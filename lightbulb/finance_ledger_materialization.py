"""Source-bound provider-neutral canonical ledger materialization.

Canonical facts are derived from completed QuickBooks or Xero discovery
results. Spring still authenticates connector receipts, creates retained
source-page evidence, and admits or persists the candidate.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal, Sequence
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.finance_journal_lifecycle import (
    DiscoveredTrialBalanceLine,
    GovernedLedgerReadReceipt,
    LedgerAccount,
    LedgerAccountDiscoveryResult,
    TrialBalanceDiscoveryResult,
)
from lightbulb.finance_source_records import (
    CanonicalLedgerAccount,
    CanonicalLedgerSnapshot,
    CanonicalTrialBalanceLine,
    FinanceLedgerScope,
    FinanceObservationEnvelope,
    OpaqueRef,
    PositiveRevision,
    Sha256Digest,
    finance_canonical_digest,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


LEDGER_SNAPSHOT_MATERIALIZATION_INPUT_SCHEMA = (
    "lightbulb.ledger_snapshot_materialization_input.v2"
)
LEDGER_SNAPSHOT_MATERIALIZATION_RESULT_SCHEMA = (
    "lightbulb.ledger_snapshot_materialization_result.v2"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
        allow_inf_nan=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class LedgerSnapshotMaterializationInput(_StrictModel):
    schema_id: Literal["lightbulb.ledger_snapshot_materialization_input.v2"] = Field(
        default=LEDGER_SNAPSHOT_MATERIALIZATION_INPUT_SCHEMA,
        alias="schema",
    )
    snapshot_ref: OpaqueRef
    snapshot_revision: PositiveRevision
    scope: FinanceLedgerScope
    materialized_at: str
    account_discovery: LedgerAccountDiscoveryResult
    trial_balance_discovery: TrialBalanceDiscoveryResult
    source_observations: tuple[FinanceObservationEnvelope, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @field_validator("materialized_at")
    @classmethod
    def _materialized_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("materialized_at must be valid ISO-8601") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("materialized_at must include a UTC offset")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_validator("source_observations", mode="before")
    @classmethod
    def _source_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class LedgerSnapshotMaterializationResult(_StrictModel):
    schema_id: Literal["lightbulb.ledger_snapshot_materialization_result.v2"] = Field(
        default=LEDGER_SNAPSHOT_MATERIALIZATION_RESULT_SCHEMA,
        alias="schema",
    )
    source_inputs: LedgerSnapshotMaterializationInput
    snapshot: CanonicalLedgerSnapshot
    source_read_binding_digest: Sha256Digest
    authority_state: Literal["governed_read_bound_structural_candidate"] = (
        "governed_read_bound_structural_candidate"
    )
    provider_neutral: Literal[True] = True
    source_observations_evidence_bound: Literal[True] = True
    governed_read_results_bound: Literal[True] = True
    connector_operation_performed: Literal[False] = False
    persistence_authorized: Literal[False] = False
    posting_authorized: Literal[False] = False

    @model_validator(mode="after")
    def _replay_source_derivation(self) -> "LedgerSnapshotMaterializationResult":
        expected_snapshot, expected_binding_digest = _derive_ledger_snapshot(
            self.source_inputs
        )
        if self.snapshot != expected_snapshot:
            raise ValueError(
                "materialized snapshot does not match its governed sources"
            )
        if self.source_read_binding_digest != expected_binding_digest:
            raise ValueError(
                "source-read binding digest does not match governed sources"
            )
        return self


def _journal_set_ref(receipts: Sequence[GovernedLedgerReadReceipt]) -> str:
    if len(receipts) == 1:
        return receipts[0].execution_journal_ref
    return "journal-set:" + finance_canonical_digest(
        tuple(receipt.execution_journal_ref for receipt in receipts)
    )


def _validate_observation_binding(
    observation: FinanceObservationEnvelope,
    *,
    dataset: Literal["chart_of_accounts", "trial_balance"],
    provider: str,
    tool: str,
    scope: FinanceLedgerScope,
    receipts: Sequence[GovernedLedgerReadReceipt],
    record_count: int,
    provider_total_count: int | None,
    provider_revision: str,
) -> None:
    source = observation.source
    checkpoint = observation.checkpoint
    first = receipts[0]
    if observation.scope != scope:
        raise ValueError(
            f"{dataset} observation scope must match materialization scope"
        )
    if (
        source.dataset != dataset
        or source.provider != provider
        or source.tool != tool
        or source.tool_version != first.tool_version
    ):
        raise ValueError(f"{dataset} observation must identify the exact governed Tool")
    if source.tenant_connector_ref != f"tenant-connector:{first.tenant_connector_id}":
        raise ValueError(f"{dataset} observation tenant connector is not source-bound")
    if source.connector_account_ref != first.connector_account_ref:
        raise ValueError(f"{dataset} observation connector account is not source-bound")
    if source.route_ref != f"route:{first.route_digest}":
        raise ValueError(f"{dataset} observation route is not source-bound")
    if source.execution_journal_ref != _journal_set_ref(receipts):
        raise ValueError(f"{dataset} observation execution journal is not source-bound")
    if observation.effective_at != scope.period_ended_at:
        raise ValueError(f"{dataset} observation must be effective at period end")
    if any(receipt.completed_at > observation.observed_at for receipt in receipts):
        raise ValueError(f"{dataset} observation predates its governed reads")
    if checkpoint.page_count != len(receipts):
        raise ValueError(f"{dataset} checkpoint page count must match governed reads")
    if checkpoint.record_count != record_count:
        raise ValueError(f"{dataset} checkpoint record count must match discovery")
    if checkpoint.provider_total_count != provider_total_count:
        raise ValueError(f"{dataset} checkpoint provider total must match discovery")
    if checkpoint.provider_revision != provider_revision:
        raise ValueError(f"{dataset} checkpoint revision must match discovery digest")
    if checkpoint.page_digests != tuple(item.source_page_digest for item in receipts):
        raise ValueError(f"{dataset} checkpoint pages must match governed reads")


def _account_class(value: str | None, *, account_ref: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in {"asset", "liability", "equity", "revenue", "expense"}:
        raise ValueError(
            f"ledger account {account_ref} has no supported canonical classification"
        )
    return normalized


def _derive_ledger_snapshot(
    inputs: LedgerSnapshotMaterializationInput,
) -> tuple[CanonicalLedgerSnapshot, str]:
    """Derive and seal a snapshot from exact governed read results and evidence."""

    accounts_result = inputs.account_discovery
    trial_result = inputs.trial_balance_discovery
    if accounts_result.provider != trial_result.provider:
        raise ValueError("account and Trial Balance reads must use one provider")

    all_receipts = (*accounts_result.read_receipts, trial_result.read_receipt)
    custody = {
        (
            receipt.project_id,
            receipt.tenant_connector_id,
            receipt.connector_account_ref,
        )
        for receipt in all_receipts
    }
    if len(custody) != 1:
        raise ValueError("governed ledger reads must use one exact project binding")
    if trial_result.start_date != inputs.scope.period_started_at[:10]:
        raise ValueError("Trial Balance start date must match the fiscal period")
    if trial_result.end_date != inputs.scope.period_ended_at[:10]:
        raise ValueError("Trial Balance end date must match the fiscal period")
    if trial_result.currency != inputs.scope.functional_currency:
        raise ValueError("Trial Balance currency must match functional currency")

    observations = {item.source.dataset: item for item in inputs.source_observations}
    if set(observations) != {"chart_of_accounts", "trial_balance"}:
        raise ValueError(
            "exact chart_of_accounts and trial_balance observations are required"
        )
    if len({item.source.provider_account_ref for item in observations.values()}) != 1:
        raise ValueError("source observations must use one exact provider account")

    _validate_observation_binding(
        observations["chart_of_accounts"],
        dataset="chart_of_accounts",
        provider=accounts_result.provider,
        tool=accounts_result.tool,
        scope=inputs.scope,
        receipts=accounts_result.read_receipts,
        record_count=accounts_result.account_count,
        provider_total_count=accounts_result.provider_total_count,
        provider_revision=accounts_result.source_digest,
    )
    _validate_observation_binding(
        observations["trial_balance"],
        dataset="trial_balance",
        provider=trial_result.provider,
        tool=trial_result.tool,
        scope=inputs.scope,
        receipts=(trial_result.read_receipt,),
        record_count=trial_result.line_count,
        provider_total_count=trial_result.line_count,
        provider_revision=trial_result.source_digest,
    )

    canonical_accounts: list[CanonicalLedgerAccount] = []
    classes: dict[str, str] = {}
    for account in accounts_result.accounts:
        if (
            account.currency is not None
            and account.currency != inputs.scope.functional_currency
        ):
            raise ValueError(
                f"ledger account {account.account_ref} currency does not match scope"
            )
        account_class = _account_class(
            account.classification,
            account_ref=account.account_ref,
        )
        classes[account.account_ref] = account_class
        canonical_accounts.append(
            CanonicalLedgerAccount(
                account_ref=account.account_ref,
                account_code=account.account_code,
                account_name=account.name,
                account_class=account_class,
                currency=inputs.scope.functional_currency,
                active=account.active,
            )
        )

    canonical_lines: list[CanonicalTrialBalanceLine] = []
    for line in trial_result.lines:
        account_class = classes.get(line.account_ref)
        if account_class is None:
            raise ValueError(
                f"Trial Balance account {line.account_ref} is absent from governed accounts"
            )
        if line.currency != inputs.scope.functional_currency:
            raise ValueError("Trial Balance line currency does not match scope")
        canonical_lines.append(
            CanonicalTrialBalanceLine(
                account_ref=line.account_ref,
                account_class=account_class,
                currency=line.currency,
                debit=line.debit,
                credit=line.credit,
            )
        )

    snapshot = CanonicalLedgerSnapshot(
        snapshot_ref=inputs.snapshot_ref,
        snapshot_revision=inputs.snapshot_revision,
        scope=inputs.scope,
        as_of=inputs.scope.period_ended_at,
        materialized_at=inputs.materialized_at,
        source_observations=inputs.source_observations,
        accounts=tuple(canonical_accounts),
        trial_balance_lines=tuple(canonical_lines),
        total_debit=trial_result.total_debit,
        total_credit=trial_result.total_credit,
    )
    binding_digest = finance_canonical_digest(
        {
            "provider": accounts_result.provider,
            "custody": tuple(
                {
                    "tool": receipt.tool,
                    "page_number": receipt.page_number,
                    "project_id": str(receipt.project_id),
                    "tenant_connector_id": str(receipt.tenant_connector_id),
                    "connector_account_ref": receipt.connector_account_ref,
                    "route_digest": receipt.route_digest,
                    "execution_journal_ref": receipt.execution_journal_ref,
                    "request_digest": receipt.request_digest,
                    "provenance_receipt_digest": receipt.provenance_receipt_digest,
                    "provider_output_digest": receipt.provider_output_digest,
                    "source_page_digest": receipt.source_page_digest,
                }
                for receipt in all_receipts
            ),
            "observations": tuple(
                observation.evidence_digest
                for observation in snapshot.source_observations
            ),
            "snapshot_artifact_digest": snapshot.artifact_digest,
        }
    )
    return snapshot, binding_digest


def materialize_ledger_snapshot(
    inputs: LedgerSnapshotMaterializationInput,
) -> LedgerSnapshotMaterializationResult:
    """Return a self-verifying result with its sanitized governed source inputs."""

    snapshot, binding_digest = _derive_ledger_snapshot(inputs)
    return LedgerSnapshotMaterializationResult(
        source_inputs=inputs,
        snapshot=snapshot,
        source_read_binding_digest=binding_digest,
    )


def _scope_example() -> dict[str, Any]:
    return {
        "tenant_ref": "tenant:example",
        "company_ref": "company:example",
        "project_ref": "project:finance-lighthouse",
        "legal_entity_ref": "legal-entity:example-us",
        "ledger_ref": "ledger:general",
        "functional_currency": "USD",
        "fiscal_period_ref": "fiscal-period:2026-08",
        "period_revision": 1,
        "period_status": "open",
        "period_started_at": "2026-08-01T00:00:00Z",
        "period_ended_at": "2026-08-31T23:59:59Z",
        "jurisdiction_ref": "US",
        "classification": "confidential",
        "retention_policy_ref": "finance-seven-years",
        "required_retained_until": "2034-09-01T00:00:00Z",
    }


def _read_receipt_example(*, tool: str, page_digest: str) -> dict[str, Any]:
    return {
        "page_number": 1,
        "tool": tool,
        "tool_version": 2,
        "project_id": UUID("00000000-0000-0000-0000-000000000401"),
        "tenant_connector_id": UUID("00000000-0000-0000-0000-000000000402"),
        "connector_account_ref": "connector-account:quickbooks-example",
        "route_digest": finance_canonical_digest(f"route:{tool}"),
        "execution_journal_ref": f"journal:{tool.replace('.', ':')}",
        "request_digest": finance_canonical_digest(f"request:{tool}"),
        "provenance_receipt_digest": finance_canonical_digest(f"receipt:{tool}"),
        "completed_at": "2026-09-01T10:55:00Z",
        "provider_output_digest": finance_canonical_digest(f"output:{tool}"),
        "source_page_digest": page_digest,
    }


def _observation_example(
    *,
    dataset: Literal["chart_of_accounts", "trial_balance"],
    receipt: dict[str, Any],
    record_count: int,
    provider_revision: str,
) -> dict[str, Any]:
    observation_ref = f"observation:quickbooks:{dataset}:2026-08"
    return {
        "observation_ref": observation_ref,
        "observation_revision": 1,
        "source": {
            "dataset": dataset,
            "provider": "quickbooks",
            "tool": receipt["tool"],
            "tool_version": receipt["tool_version"],
            "tenant_connector_ref": f"tenant-connector:{receipt['tenant_connector_id']}",
            "connector_account_ref": receipt["connector_account_ref"],
            "provider_account_ref": "quickbooks-realm:example",
            "route_ref": f"route:{receipt['route_digest']}",
            "execution_journal_ref": receipt["execution_journal_ref"],
        },
        "scope": _scope_example(),
        "checkpoint": {
            "cursor_kind": "none",
            "page_count": 1,
            "record_count": record_count,
            "provider_total_count": record_count,
            "provider_revision": provider_revision,
            "complete": True,
            "page_digests": [receipt["source_page_digest"]],
        },
        "observed_at": "2026-09-01T11:00:00Z",
        "effective_at": "2026-08-31T23:59:59Z",
        "freshness_class": "bounded",
        "fresh_until": "2026-09-02T11:00:00Z",
        "retained_until": "2034-09-01T00:00:00Z",
        "evidence_refs": [
            {
                "evidence_ref": f"evidence:quickbooks:{dataset}:2026-08",
                "kind": "finance_source_page",
                "issuer_ref": "spring-host:production",
                "subject_ref": observation_ref,
                "sha256": receipt["source_page_digest"],
                "observed_at": "2026-09-01T11:00:00Z",
                "effective_at": "2026-08-31T23:59:59Z",
                "verification_grade": "attested",
                "classification": "confidential",
                "retention_policy": "finance-seven-years",
                "jurisdiction": "US",
            }
        ],
    }


def _example_inputs() -> dict[str, Any]:
    accounts = [
        {
            "account_ref": "quickbooks-account:cash",
            "account_code": "1000",
            "name": "Cash",
            "classification": "Asset",
            "currency": "USD",
            "active": True,
        },
        {
            "account_ref": "quickbooks-account:revenue",
            "account_code": "4000",
            "name": "Revenue",
            "classification": "Revenue",
            "currency": "USD",
            "active": True,
        },
    ]
    lines = [
        {
            "account_ref": "quickbooks-account:cash",
            "account_name": "Cash",
            "currency": "USD",
            "debit": Decimal("100.00"),
            "credit": Decimal("0"),
        },
        {
            "account_ref": "quickbooks-account:revenue",
            "account_name": "Revenue",
            "currency": "USD",
            "debit": Decimal("0"),
            "credit": Decimal("100.00"),
        },
    ]
    normalized_accounts = tuple(LedgerAccount.model_validate(item) for item in accounts)
    account_digest = LedgerAccountDiscoveryResult.source_digest_for(normalized_accounts)
    trial_digest = TrialBalanceDiscoveryResult.source_digest_for(
        start_date="2026-08-01",
        end_date="2026-08-31",
        currency="USD",
        lines=tuple(DiscoveredTrialBalanceLine.model_validate(item) for item in lines),
    )
    account_page_digest = LedgerAccountDiscoveryResult.source_page_digest_for(
        provider="quickbooks",
        tool="quickbooks.list_accounts",
        page_number=1,
        accounts=normalized_accounts,
    )
    account_receipt = _read_receipt_example(
        tool="quickbooks.list_accounts",
        page_digest=account_page_digest,
    )
    trial_receipt = _read_receipt_example(
        tool="quickbooks.trial_balance_report",
        page_digest=trial_digest,
    )
    return {
        "snapshot_ref": "ledger-snapshot:2026-08",
        "snapshot_revision": 1,
        "scope": _scope_example(),
        "materialized_at": "2026-09-01T12:00:00Z",
        "account_discovery": {
            "provider": "quickbooks",
            "tool": "quickbooks.list_accounts",
            "accounts": accounts,
            "account_count": 2,
            "page_count": 1,
            "provider_total_count": 2,
            "source_digest": account_digest,
            "provenance_receipt_digests": [
                account_receipt["provenance_receipt_digest"]
            ],
            "read_receipts": [account_receipt],
        },
        "trial_balance_discovery": {
            "provider": "quickbooks",
            "tool": "quickbooks.trial_balance_report",
            "start_date": "2026-08-01",
            "end_date": "2026-08-31",
            "currency": "USD",
            "lines": lines,
            "line_count": 2,
            "total_debit": Decimal("100.00"),
            "total_credit": Decimal("100.00"),
            "source_digest": trial_digest,
            "provenance_receipt_digest": trial_receipt["provenance_receipt_digest"],
            "read_receipt": trial_receipt,
        },
        "source_observations": [
            _observation_example(
                dataset="chart_of_accounts",
                receipt=account_receipt,
                record_count=2,
                provider_revision=account_digest,
            ),
            _observation_example(
                dataset="trial_balance",
                receipt=trial_receipt,
                record_count=2,
                provider_revision=trial_digest,
            ),
        ],
    }


class MaterializeLedgerSnapshotPrimitive(
    BusinessProcessPrimitive[
        LedgerSnapshotMaterializationInput,
        LedgerSnapshotMaterializationResult,
    ]
):
    primitive_ref = "finance.materialize_ledger_snapshot"
    version = "2.0.0"
    title = "Materialize source-bound canonical ledger snapshot"
    description = (
        "Derive a provider-neutral ledger snapshot from complete QuickBooks or Xero "
        "account and Trial Balance reads plus exact Spring-attested source evidence, "
        "without persisting, posting, or granting hosted authority."
    )
    input_model = LedgerSnapshotMaterializationInput
    output_model = LedgerSnapshotMaterializationResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "ledger_writes": 0,
            "provider_authority_granted": False,
            "persistence_authorized": False,
            "posting_authorized": False,
        }
        contract["system_of_record_authority"] = "spring_host_required"
        contract["materialization_authority"] = (
            "governed_read_bound_structural_candidate"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: LedgerSnapshotMaterializationInput,
    ) -> PrimitiveExecutionResult[LedgerSnapshotMaterializationResult]:
        scope = inputs.scope
        runtime_scope = context.scope
        if (
            runtime_scope.tenant_ref != scope.tenant_ref
            or runtime_scope.company_ref != scope.company_ref
            or runtime_scope.project_ref != scope.project_ref
        ):
            blocker = PrimitiveBlocker(
                code="ledger_snapshot_scope_mismatch",
                message=(
                    "The ledger scope tenant, company, and project must exactly "
                    "match the active runtime scope."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        receipt_project_ids = {
            receipt.project_id
            for receipt in (
                *inputs.account_discovery.read_receipts,
                inputs.trial_balance_discovery.read_receipt,
            )
        }
        if runtime_scope.project_id is None or receipt_project_ids != {
            runtime_scope.project_id
        }:
            blocker = PrimitiveBlocker(
                code="ledger_snapshot_project_custody_mismatch",
                message=(
                    "The active authenticated project UUID must match every governed "
                    "ledger read receipt."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        try:
            output = materialize_ledger_snapshot(inputs)
        except ValueError as exc:
            blocker = PrimitiveBlocker(
                code="ledger_snapshot_source_binding_invalid",
                message=str(exc),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.NEEDS_INPUT,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        snapshot = output.snapshot
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Derived a source-bound provider-neutral ledger snapshot candidate "
                f"with {len(snapshot.accounts)} accounts and "
                f"{len(snapshot.trial_balance_lines)} Trial Balance lines."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.ledger_snapshot_materialized",
                    payload={
                        "snapshot_ref": snapshot.snapshot_ref,
                        "snapshot_revision": snapshot.snapshot_revision,
                        "content_digest": snapshot.content_digest,
                        "evidence_digest": snapshot.evidence_digest,
                        "materialization_idempotency_digest": (
                            snapshot.materialization_idempotency_digest
                        ),
                        "source_read_binding_digest": output.source_read_binding_digest,
                        "authority_state": output.authority_state,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="canonical_ledger_snapshot_candidate",
                    summary=(
                        "Canonical facts were derived from exact governed read results "
                        "and matching attested source pages; Spring admission and "
                        "persistence remain required."
                    ),
                    labels=[
                        "provider_neutral",
                        "governed_read_bound",
                        "structural_candidate_only",
                        "not_persisted",
                        "not_posted",
                    ],
                    refs={
                        "artifact_digest": snapshot.artifact_digest,
                        "content_digest": snapshot.content_digest,
                        "evidence_digest": snapshot.evidence_digest,
                        "source_read_binding_digest": output.source_read_binding_digest,
                    },
                )
            ],
        )


FINANCE_LEDGER_MATERIALIZATION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (MaterializeLedgerSnapshotPrimitive(),)


__all__ = [
    "FINANCE_LEDGER_MATERIALIZATION_EXECUTABLE_PRIMITIVES",
    "LEDGER_SNAPSHOT_MATERIALIZATION_INPUT_SCHEMA",
    "LEDGER_SNAPSHOT_MATERIALIZATION_RESULT_SCHEMA",
    "LedgerSnapshotMaterializationInput",
    "LedgerSnapshotMaterializationResult",
    "MaterializeLedgerSnapshotPrimitive",
    "materialize_ledger_snapshot",
]
