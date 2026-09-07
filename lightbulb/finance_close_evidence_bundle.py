"""Sealed provider evidence for the initial monthly-close lighthouse.

This module joins a self-verifying governed-read ledger materialization with
accounting transaction, period-lock, and Stripe observations. It performs no
provider read, persistence, reconciliation, or close transition. The resulting
bundle is a structural prerequisite for a close workspace, not evidence that
Spring executed or approved a close.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.finance_close_source_transactions import (
    CloseSourceTransactionResult,
)
from lightbulb.finance_ledger_materialization import (
    LedgerSnapshotMaterializationInput,
    LedgerSnapshotMaterializationResult,
    MaterializeLedgerSnapshotPrimitive,
    materialize_ledger_snapshot,
)
from lightbulb.finance_provider_period_status import ProviderPeriodStatusResult
from lightbulb.finance_source_records import (
    CanonicalLedgerSnapshot,
    finance_canonical_digest,
)
from lightbulb.finance_stripe_settlements import StripeSettlementObservationResult
from lightbulb.finance_xero_close_source_transactions import (
    XeroCloseSourceTransactionResult,
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


FINANCE_CLOSE_EVIDENCE_BUNDLE_INPUT_SCHEMA = (
    "lightbulb.finance_close_evidence_bundle_input.v2"
)
FINANCE_CLOSE_EVIDENCE_BUNDLE_SCHEMA = "lightbulb.finance_close_evidence_bundle.v2"
FINANCE_CLOSE_EVIDENCE_BUNDLE_RESULT_SCHEMA = (
    "lightbulb.finance_close_evidence_bundle_result.v2"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"

CloseEvidenceReadiness = Literal[
    "ready",
    "ready_with_provider_lock_warning",
    "blocked_by_provider_lock",
]
CloseEvidenceControlCode = Literal[
    "provider_lock_not_configured",
    "provider_period_lock_conflict",
]
CloseSourceTransactionEvidence = Annotated[
    CloseSourceTransactionResult | XeroCloseSourceTransactionResult,
    Field(discriminator="provider"),
]


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


def _strict_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("revision fields require exact integers")
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
PositiveRevision = Annotated[
    int,
    BeforeValidator(_strict_integer),
    Field(ge=1, le=9_223_372_036_854_775_807),
]


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


class FinanceCloseEvidenceBundleInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_evidence_bundle_input.v2"] = Field(
        default=FINANCE_CLOSE_EVIDENCE_BUNDLE_INPUT_SCHEMA,
        alias="schema",
    )
    bundle_ref: OpaqueRef
    bundle_revision: PositiveRevision
    prepared_at: str
    ledger_materialization: LedgerSnapshotMaterializationResult
    close_source_transactions: CloseSourceTransactionEvidence
    stripe_settlement_observation: StripeSettlementObservationResult
    provider_period_status: ProviderPeriodStatusResult

    @property
    def ledger_snapshot(self) -> CanonicalLedgerSnapshot:
        return self.ledger_materialization.snapshot

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _exact_source_alignment(self) -> "FinanceCloseEvidenceBundleInput":
        snapshot = self.ledger_snapshot
        snapshot_scope = snapshot.scope
        close_source = self.close_source_transactions
        stripe = self.stripe_settlement_observation
        period_status = self.provider_period_status
        ledger_sources = tuple(
            observation.source for observation in snapshot.source_observations
        )

        project_ids = {
            close_source.project_id,
            stripe.project_id,
            period_status.project_id,
        }
        if len(project_ids) != 1:
            raise ValueError(
                "all governed source observations must use one project UUID"
            )
        if close_source.provider != period_status.provider or any(
            source.provider != close_source.provider for source in ledger_sources
        ):
            raise ValueError(
                "ledger, close-source, and period-status evidence must use one "
                "accounting provider"
            )
        if (
            close_source.connector_account_ref != period_status.connector_account_ref
            or any(
                source.connector_account_ref != close_source.connector_account_ref
                for source in ledger_sources
            )
        ):
            raise ValueError(
                "all accounting evidence must use one exact connector account"
            )
        if (
            len(
                {
                    (
                        source.tenant_connector_ref,
                        source.provider_account_ref,
                    )
                    for source in ledger_sources
                }
            )
            != 1
        ):
            raise ValueError(
                "all ledger observations must use one exact provider account"
            )
        if close_source.tenant_connector_id != period_status.tenant_connector_id:
            raise ValueError(
                "close-source and period-status evidence must use one tenant connector"
            )

        expected_start = snapshot_scope.period_started_at[:10]
        expected_end = snapshot_scope.period_ended_at[:10]
        if (
            snapshot_scope.period_started_at != f"{expected_start}T00:00:00Z"
            or snapshot_scope.period_ended_at != f"{expected_end}T23:59:59Z"
        ):
            raise ValueError(
                "the initial close evidence scope must use exact UTC month bounds"
            )
        periods = {
            (close_source.start_date, close_source.end_date),
            (stripe.start_date, stripe.end_date),
            (period_status.start_date, period_status.end_date),
        }
        if periods != {(expected_start, expected_end)}:
            raise ValueError(
                "ledger, accounting, period-status, and Stripe evidence must cover "
                "the same complete month"
            )
        if not (
            snapshot_scope.functional_currency
            == close_source.currency
            == stripe.currency
        ):
            raise ValueError(
                "ledger, close-source, and Stripe evidence must use one currency"
            )

        prepared = _parsed_timestamp(self.prepared_at)
        source_times = [
            snapshot.materialized_at,
            close_source.observed_at,
            stripe.observed_at,
            period_status.provider_observed_at,
            period_status.execution_completed_at,
        ]
        if period_status.source_updated_at is not None:
            source_times.append(period_status.source_updated_at)
        if any(prepared < _parsed_timestamp(value) for value in source_times):
            raise ValueError("bundle preparation cannot precede any source observation")
        if _parsed_timestamp(period_status.provider_observed_at) > _parsed_timestamp(
            period_status.execution_completed_at
        ):
            raise ValueError(
                "provider period observation cannot follow execution completion"
            )
        if period_status.source_updated_at is not None and _parsed_timestamp(
            period_status.source_updated_at
        ) > _parsed_timestamp(period_status.provider_observed_at):
            raise ValueError(
                "provider source update cannot follow the provider observation"
            )
        for observation in snapshot.source_observations:
            if prepared > _parsed_timestamp(observation.fresh_until):
                raise ValueError(
                    "ledger source evidence is stale at bundle preparation"
                )
            if prepared >= _parsed_timestamp(observation.retained_until):
                raise ValueError(
                    "ledger source evidence is expired at bundle preparation"
                )
        return self


class FinanceCloseEvidenceBundle(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_evidence_bundle.v2"] = Field(
        default=FINANCE_CLOSE_EVIDENCE_BUNDLE_SCHEMA,
        alias="schema",
    )
    bundle_ref: OpaqueRef
    bundle_revision: PositiveRevision
    prepared_at: str
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    legal_entity_ref: OpaqueRef
    ledger_ref: OpaqueRef
    fiscal_period_ref: OpaqueRef
    start_date: str
    end_date: str
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    accounting_provider: Literal["quickbooks", "xero"]
    accounting_tenant_connector_ref: OpaqueRef
    accounting_tenant_connector_id: UUID
    accounting_connector_account_ref: OpaqueRef
    accounting_provider_account_ref: OpaqueRef
    stripe_tenant_connector_id: UUID
    stripe_connector_account_ref: OpaqueRef
    ledger_snapshot_ref: OpaqueRef
    ledger_snapshot_revision: PositiveRevision
    ledger_snapshot_artifact_digest: Sha256Digest
    ledger_source_read_binding_digest: Sha256Digest
    close_source_digest: Sha256Digest
    stripe_settlement_digest: Sha256Digest
    provider_period_status_digest: Sha256Digest
    provider_period_relation: Literal[
        "no_provider_lock_configured",
        "fully_at_or_before_provider_lock",
        "overlaps_provider_lock_boundary",
        "after_provider_locks",
    ]
    readiness: CloseEvidenceReadiness
    control_code: CloseEvidenceControlCode | None = None
    source_facts_complete: Literal[True] = True
    workspace_eligible: bool
    close_transition_authority: Literal[False] = False
    content_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    def content_digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"content_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _seal_readiness(self) -> "FinanceCloseEvidenceBundle":
        expected = {
            "after_provider_locks": ("ready", None, True),
            "no_provider_lock_configured": (
                "ready_with_provider_lock_warning",
                "provider_lock_not_configured",
                True,
            ),
            "fully_at_or_before_provider_lock": (
                "blocked_by_provider_lock",
                "provider_period_lock_conflict",
                False,
            ),
            "overlaps_provider_lock_boundary": (
                "blocked_by_provider_lock",
                "provider_period_lock_conflict",
                False,
            ),
        }[self.provider_period_relation]
        if (self.readiness, self.control_code, self.workspace_eligible) != expected:
            raise ValueError("bundle readiness must match the provider lock relation")
        digest = finance_canonical_digest(self.content_digest_payload())
        if self.content_digest not in {_ZERO_DIGEST, digest}:
            raise ValueError("content_digest does not match the close evidence bundle")
        object.__setattr__(self, "content_digest", digest)
        return self


class FinanceCloseEvidenceBundleResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_evidence_bundle_result.v2"] = Field(
        default=FINANCE_CLOSE_EVIDENCE_BUNDLE_RESULT_SCHEMA,
        alias="schema",
    )
    bundle: FinanceCloseEvidenceBundle
    connector_operation_performed: Literal[False] = False
    persistence_authorized: Literal[False] = False
    close_transition_authorized: Literal[False] = False


def _readiness(
    relation: str,
) -> tuple[CloseEvidenceReadiness, CloseEvidenceControlCode | None, bool]:
    if relation == "after_provider_locks":
        return "ready", None, True
    if relation == "no_provider_lock_configured":
        return "ready_with_provider_lock_warning", "provider_lock_not_configured", True
    return "blocked_by_provider_lock", "provider_period_lock_conflict", False


def prepare_close_evidence_bundle(
    inputs: FinanceCloseEvidenceBundleInput,
) -> FinanceCloseEvidenceBundleResult:
    snapshot = inputs.ledger_snapshot
    scope = snapshot.scope
    ledger_source = snapshot.source_observations[0].source
    close_source = inputs.close_source_transactions
    stripe = inputs.stripe_settlement_observation
    period_status = inputs.provider_period_status
    readiness, control_code, eligible = _readiness(period_status.period_relation)
    bundle = FinanceCloseEvidenceBundle(
        bundle_ref=inputs.bundle_ref,
        bundle_revision=inputs.bundle_revision,
        prepared_at=inputs.prepared_at,
        tenant_ref=scope.tenant_ref,
        company_ref=scope.company_ref,
        project_ref=scope.project_ref,
        project_id=close_source.project_id,
        legal_entity_ref=scope.legal_entity_ref,
        ledger_ref=scope.ledger_ref,
        fiscal_period_ref=scope.fiscal_period_ref,
        start_date=close_source.start_date,
        end_date=close_source.end_date,
        currency=scope.functional_currency,
        accounting_provider=period_status.provider,
        accounting_tenant_connector_ref=ledger_source.tenant_connector_ref,
        accounting_tenant_connector_id=close_source.tenant_connector_id,
        accounting_connector_account_ref=close_source.connector_account_ref,
        accounting_provider_account_ref=ledger_source.provider_account_ref,
        stripe_tenant_connector_id=stripe.tenant_connector_id,
        stripe_connector_account_ref=stripe.connector_account_ref,
        ledger_snapshot_ref=snapshot.snapshot_ref,
        ledger_snapshot_revision=snapshot.snapshot_revision,
        ledger_snapshot_artifact_digest=snapshot.artifact_digest,
        ledger_source_read_binding_digest=(
            inputs.ledger_materialization.source_read_binding_digest
        ),
        close_source_digest=close_source.source_digest,
        stripe_settlement_digest=stripe.source_digest,
        provider_period_status_digest=period_status.source_digest,
        provider_period_relation=period_status.period_relation,
        readiness=readiness,
        control_code=control_code,
        workspace_eligible=eligible,
    )
    return FinanceCloseEvidenceBundleResult(bundle=bundle)


def _example_inputs() -> dict[str, Any]:
    project_id = UUID("00000000-0000-0000-0000-000000000401")
    accounting_tenant_connector_id = UUID("00000000-0000-0000-0000-000000000402")
    stripe_tenant_connector_id = UUID("00000000-0000-0000-0000-000000000403")
    account_ref = "connector-account:quickbooks-example"
    checkpoint_specs = (
        ("quickbooks.list_invoices", "invoice", "12:00:00"),
        ("quickbooks.list_bills", "bill", "12:01:00"),
        ("quickbooks.list_payments", "payment", "12:02:00"),
    )
    close_source = CloseSourceTransactionResult(
        project_id=project_id,
        tenant_connector_id=accounting_tenant_connector_id,
        connector_account_ref=account_ref,
        route_digest=_digest("example-qbo-close-source-route"),
        start_date="2026-08-01",
        end_date="2026-08-31",
        currency="USD",
        transactions=(),
        transaction_count=0,
        invoice_count=0,
        bill_count=0,
        payment_count=0,
        checkpoints=[
            {
                "tool": tool,
                "transaction_type": transaction_type,
                "start_position": 1,
                "record_count": 0,
                "terminal": True,
                "page_digest": _digest(f"example-{transaction_type}-page"),
                "provenance_receipt_digest": _digest(
                    f"example-{transaction_type}-receipt"
                ),
                "execution_journal_ref": f"journal:qbo:{transaction_type}:terminal",
                "completed_at": f"2026-09-01T{clock}Z",
            }
            for tool, transaction_type, clock in checkpoint_specs
        ],
        observed_at="2026-09-01T12:02:00Z",
    )
    stripe = StripeSettlementObservationResult(
        project_id=project_id,
        tenant_connector_id=stripe_tenant_connector_id,
        connector_account_ref="connector-account:stripe-example",
        route_digest=_digest("example-stripe-settlement-route"),
        start_date="2026-08-01",
        end_date="2026-08-31",
        currency="USD",
        movements=(),
        movement_count=0,
        page_count=1,
        page_digests=[_digest("example-stripe-page")],
        provenance_receipt_digests=[_digest("example-stripe-receipt")],
        observation_completed_ats=["2026-09-01T12:03:00Z"],
        observed_at="2026-09-01T12:03:00Z",
    )
    period_status = ProviderPeriodStatusResult(
        provider="quickbooks",
        tool="quickbooks.get_period_status",
        project_id=project_id,
        tenant_connector_id=accounting_tenant_connector_id,
        connector_account_ref=account_ref,
        route_digest=_digest("example-qbo-period-status-route"),
        start_date="2026-08-01",
        end_date="2026-08-31",
        locks=(
            {
                "lock_kind": "books_closed_through",
                "through_date": "2026-07-31",
            },
        ),
        period_relation="after_provider_locks",
        source_revision_kind="sync_token",
        source_revision="7",
        source_updated_at="2026-09-01T12:04:00Z",
        provider_observed_at="2026-09-01T12:04:00Z",
        provider_response_sha256=_digest("example-qbo-period-status-response"),
        execution_journal_ref="journal:qbo:period-status:2026-08",
        provenance_receipt_digest=_digest("example-qbo-period-status-receipt"),
        execution_completed_at="2026-09-01T12:05:00Z",
    )
    return {
        "bundle_ref": "close-evidence:2026-08",
        "bundle_revision": 1,
        "prepared_at": "2026-09-01T12:10:00Z",
        "ledger_materialization": materialize_ledger_snapshot(
            LedgerSnapshotMaterializationInput.model_validate(
                deepcopy(MaterializeLedgerSnapshotPrimitive.example_inputs)
            )
        ),
        "close_source_transactions": close_source,
        "stripe_settlement_observation": stripe,
        "provider_period_status": period_status,
    }


class PrepareCloseEvidenceBundlePrimitive(
    BusinessProcessPrimitive[
        FinanceCloseEvidenceBundleInput,
        FinanceCloseEvidenceBundleResult,
    ]
):
    primitive_ref = "finance.prepare_close_evidence_bundle"
    version = "2.0.0"
    title = "Prepare monthly close evidence bundle"
    description = (
        "Join one source-bound ledger materialization, governed monthly source "
        "transactions, Stripe settlement movements, and provider period-lock status "
        "under exact project, account, month, currency, and observation-time fences."
    )
    input_model = FinanceCloseEvidenceBundleInput
    output_model = FinanceCloseEvidenceBundleResult
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
            "workspace_writes": 0,
            "ledger_writes": 0,
            "period_transitions": 0,
            "close_authorized": False,
        }
        contract["evidence_authority"] = "structural_candidate_only"
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: FinanceCloseEvidenceBundleInput,
    ) -> PrimitiveExecutionResult[FinanceCloseEvidenceBundleResult]:
        scope = inputs.ledger_snapshot.scope
        runtime_scope = context.scope
        source_project_id = inputs.close_source_transactions.project_id
        if (
            runtime_scope.tenant_ref != scope.tenant_ref
            or runtime_scope.company_ref != scope.company_ref
            or runtime_scope.project_ref != scope.project_ref
            or runtime_scope.project_id != source_project_id
        ):
            blocker = PrimitiveBlocker(
                code="close_evidence_scope_mismatch",
                message=(
                    "The ledger scope and every governed source project must exactly "
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
        output = prepare_close_evidence_bundle(inputs)
        bundle = output.bundle
        summary = (
            "Prepared a source-complete monthly close evidence bundle."
            if bundle.workspace_eligible
            else "Sealed the monthly evidence, but provider locks block workspace use."
        )
        labels = [
            bundle.accounting_provider,
            "stripe",
            "source_facts_complete",
            bundle.readiness,
            "structural_candidate_only",
        ]
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_evidence_bundle_prepared",
                    payload={
                        "bundle_ref": bundle.bundle_ref,
                        "bundle_revision": bundle.bundle_revision,
                        "accounting_provider": bundle.accounting_provider,
                        "readiness": bundle.readiness,
                        "workspace_eligible": bundle.workspace_eligible,
                        "content_digest": bundle.content_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_evidence_bundle_candidate",
                    summary=(
                        "Governed accounting and Stripe observations were joined "
                        "without granting persistence or close-transition authority."
                    ),
                    labels=labels,
                    refs={
                        "bundle_digest": bundle.content_digest,
                        "ledger_snapshot_digest": (
                            bundle.ledger_snapshot_artifact_digest
                        ),
                        "close_source_digest": bundle.close_source_digest,
                        "stripe_settlement_digest": bundle.stripe_settlement_digest,
                        "provider_period_status_digest": (
                            bundle.provider_period_status_digest
                        ),
                    },
                )
            ],
        )


FINANCE_CLOSE_EVIDENCE_BUNDLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareCloseEvidenceBundlePrimitive(),)


__all__ = [
    "FINANCE_CLOSE_EVIDENCE_BUNDLE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_EVIDENCE_BUNDLE_INPUT_SCHEMA",
    "FINANCE_CLOSE_EVIDENCE_BUNDLE_RESULT_SCHEMA",
    "FINANCE_CLOSE_EVIDENCE_BUNDLE_SCHEMA",
    "CloseEvidenceControlCode",
    "CloseEvidenceReadiness",
    "CloseSourceTransactionEvidence",
    "FinanceCloseEvidenceBundle",
    "FinanceCloseEvidenceBundleInput",
    "FinanceCloseEvidenceBundleResult",
    "PrepareCloseEvidenceBundlePrimitive",
    "prepare_close_evidence_bundle",
]
