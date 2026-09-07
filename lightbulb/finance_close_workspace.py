"""Initial monthly-close workspace construction for the finance lighthouse.

The workspace consumes a self-verifying source-bound ledger materialization
plus its exact accounting/Stripe/provider-period evidence bundle and prepares
``open_period`` and ``capture_trial_balance`` packages for the existing
period-close lifecycle. It executes no transition, provider operation,
persistence, journal, or close; those effects and all hosted evidence
verification remain Spring-owned.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

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

from lightbulb.finance_close_lifecycle import (
    OpenPeriodPackage,
    PeriodCloseScope,
    TrialBalancePackage,
)
from lightbulb.finance_close_evidence_bundle import (
    FinanceCloseEvidenceBundle,
    FinanceCloseEvidenceBundleInput,
    PrepareCloseEvidenceBundlePrimitive,
    prepare_close_evidence_bundle,
)
from lightbulb.finance_ledger_materialization import LedgerSnapshotMaterializationResult
from lightbulb.finance_source_records import (
    CanonicalLedgerSnapshot,
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


FINANCE_CLOSE_WORKSPACE_INPUT_SCHEMA = "lightbulb.finance_close_workspace_input.v3"
FINANCE_CLOSE_WORKSPACE_SCHEMA = "lightbulb.finance_close_workspace.v3"
FINANCE_CLOSE_WORKSPACE_RESULT_SCHEMA = "lightbulb.finance_close_workspace_result.v3"

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"

CloseWorkspaceStage = Literal[
    "source_facts_sealed",
    "open_period",
    "capture_trial_balance",
    "reconcile_stripe_settlements",
    "reconcile_accounts",
    "record_adjusting_entries",
    "lock_subledgers",
    "consolidate",
    "approve_close",
    "close_period",
]
CloseWorkspaceTaskStatus = Literal["complete", "ready", "blocked"]

_CHECKLIST_STAGES: tuple[str, ...] = (
    "source_facts_sealed",
    "open_period",
    "capture_trial_balance",
    "reconcile_stripe_settlements",
    "reconcile_accounts",
    "record_adjusting_entries",
    "lock_subledgers",
    "consolidate",
    "approve_close",
    "close_period",
)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


def _strict_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("revision fields require integers, not booleans")
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


class FinanceCloseWorkspaceInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_workspace_input.v3"] = Field(
        default=FINANCE_CLOSE_WORKSPACE_INPUT_SCHEMA,
        alias="schema",
    )
    workspace_ref: OpaqueRef
    workspace_revision: PositiveRevision
    prepared_at: str
    ledger_materialization: LedgerSnapshotMaterializationResult
    close_evidence_bundle: FinanceCloseEvidenceBundle
    close_scope: PeriodCloseScope
    stripe_subledger_ref: OpaqueRef
    stripe_control_account_ref: OpaqueRef
    period_open_candidate_ref: OpaqueRef
    prior_period_state: Literal["closed", "not_applicable"]
    opened_at: str
    opened_by_ref: OpaqueRef
    open_reviewed_by_ref: OpaqueRef
    period_open_evidence_use_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=20,
    )
    trial_balance_ref: OpaqueRef
    trial_balance_prepared_by_ref: OpaqueRef
    trial_balance_reviewed_by_ref: OpaqueRef
    trial_balance_evidence_use_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=20,
    )

    @property
    def ledger_snapshot(self) -> CanonicalLedgerSnapshot:
        return self.ledger_materialization.snapshot

    @field_validator("prepared_at", "opened_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "period_open_evidence_use_refs",
        "trial_balance_evidence_use_refs",
        mode="before",
    )
    @classmethod
    def _canonical_evidence_refs(cls, value: Any, info: Any) -> Any:
        values = tuple(value) if isinstance(value, list) else value
        if isinstance(values, tuple) and all(isinstance(item, str) for item in values):
            if tuple(sorted(values)) != values or len(set(values)) != len(values):
                raise ValueError(f"{info.field_name} must be unique and sorted")
        return values

    @model_validator(mode="after")
    def _exact_lighthouse_scope(self) -> "FinanceCloseWorkspaceInput":
        snapshot_scope = self.ledger_snapshot.scope
        close_scope = self.close_scope
        if close_scope.scope_kind != "entity" or len(close_scope.entity_refs) != 1:
            raise ValueError(
                "the initial close workspace supports exactly one legal entity"
            )
        expected_scope = {
            "tenant_ref": snapshot_scope.tenant_ref,
            "company_ref": snapshot_scope.company_ref,
            "project_ref": snapshot_scope.project_ref,
            "entity_ref": snapshot_scope.legal_entity_ref,
            "ledger_ref": snapshot_scope.ledger_ref,
            "functional_currency": snapshot_scope.functional_currency,
            "fiscal_period_ref": snapshot_scope.fiscal_period_ref,
            "period_started_at": snapshot_scope.period_started_at,
            "period_ended_at": snapshot_scope.period_ended_at,
            "jurisdiction_ref": snapshot_scope.jurisdiction_ref,
            "retention_policy_ref": snapshot_scope.retention_policy_ref,
            "retained_until": snapshot_scope.required_retained_until,
        }
        actual_scope = {
            "tenant_ref": close_scope.tenant_ref,
            "company_ref": close_scope.company_ref,
            "project_ref": close_scope.project_ref,
            "entity_ref": close_scope.entity_refs[0],
            "ledger_ref": close_scope.ledger_ref,
            "functional_currency": close_scope.functional_currency,
            "fiscal_period_ref": close_scope.fiscal_period_ref,
            "period_started_at": close_scope.period_started_at,
            "period_ended_at": close_scope.period_ended_at,
            "jurisdiction_ref": close_scope.jurisdiction_ref,
            "retention_policy_ref": close_scope.financial_retention_policy_ref,
            "retained_until": close_scope.evidence_retention_until,
        }
        if actual_scope != expected_scope:
            raise ValueError(
                "close scope must exactly match the canonical ledger snapshot"
            )
        if snapshot_scope.period_status != "open":
            raise ValueError(
                "the initial close workspace requires an open fiscal period"
            )
        if self.ledger_snapshot.as_of != close_scope.period_ended_at:
            raise ValueError("ledger snapshot as_of must equal the fiscal period end")
        evidence = self.close_evidence_bundle
        expected_evidence_scope = {
            "tenant_ref": snapshot_scope.tenant_ref,
            "company_ref": snapshot_scope.company_ref,
            "project_ref": snapshot_scope.project_ref,
            "project_id": close_scope.project_id,
            "legal_entity_ref": snapshot_scope.legal_entity_ref,
            "ledger_ref": snapshot_scope.ledger_ref,
            "fiscal_period_ref": snapshot_scope.fiscal_period_ref,
            "start_date": snapshot_scope.period_started_at[:10],
            "end_date": snapshot_scope.period_ended_at[:10],
            "currency": snapshot_scope.functional_currency,
        }
        actual_evidence_scope = {
            "tenant_ref": evidence.tenant_ref,
            "company_ref": evidence.company_ref,
            "project_ref": evidence.project_ref,
            "project_id": evidence.project_id,
            "legal_entity_ref": evidence.legal_entity_ref,
            "ledger_ref": evidence.ledger_ref,
            "fiscal_period_ref": evidence.fiscal_period_ref,
            "start_date": evidence.start_date,
            "end_date": evidence.end_date,
            "currency": evidence.currency,
        }
        if actual_evidence_scope != expected_evidence_scope:
            raise ValueError(
                "close evidence bundle must exactly match the close and ledger scope"
            )
        if (
            evidence.ledger_snapshot_ref != self.ledger_snapshot.snapshot_ref
            or evidence.ledger_snapshot_revision
            != self.ledger_snapshot.snapshot_revision
            or evidence.ledger_snapshot_artifact_digest
            != self.ledger_snapshot.artifact_digest
            or evidence.ledger_source_read_binding_digest
            != self.ledger_materialization.source_read_binding_digest
        ):
            raise ValueError(
                "close evidence bundle must bind the exact canonical ledger snapshot"
            )
        if not evidence.source_facts_complete or not evidence.workspace_eligible:
            raise ValueError(
                "close evidence must be source-complete and provider-lock eligible"
            )
        if self.opened_at != close_scope.period_started_at:
            raise ValueError("period opening evidence must use the exact period start")
        if self.opened_by_ref == self.open_reviewed_by_ref:
            raise ValueError("period opening and review require distinct actors")
        if self.trial_balance_prepared_by_ref == self.trial_balance_reviewed_by_ref:
            raise ValueError(
                "trial-balance preparation and review require distinct actors"
            )
        if _parsed_timestamp(self.prepared_at) < _parsed_timestamp(
            self.ledger_snapshot.materialized_at
        ):
            raise ValueError(
                "workspace preparation cannot precede ledger materialization"
            )
        if _parsed_timestamp(self.prepared_at) < _parsed_timestamp(
            evidence.prepared_at
        ):
            raise ValueError(
                "workspace preparation cannot precede the close evidence bundle"
            )
        for observation in self.ledger_snapshot.source_observations:
            if _parsed_timestamp(self.prepared_at) > _parsed_timestamp(
                observation.fresh_until
            ):
                raise ValueError("source evidence is stale at workspace preparation")
            if _parsed_timestamp(self.prepared_at) >= _parsed_timestamp(
                observation.retained_until
            ):
                raise ValueError("source evidence is expired at workspace preparation")
        stripe_bindings = [
            item
            for item in close_scope.required_subledgers
            if item.subledger_ref == self.stripe_subledger_ref
        ]
        if len(stripe_bindings) != 1 or (
            stripe_bindings[0].control_account_ref != self.stripe_control_account_ref
        ):
            raise ValueError(
                "close scope must contain the exact Stripe settlement subledger binding"
            )
        accounts_by_ref = {
            item.account_ref: item for item in self.ledger_snapshot.accounts
        }
        control_account = accounts_by_ref.get(self.stripe_control_account_ref)
        if control_account is None:
            raise ValueError(
                "Stripe control account must exist in the canonical ledger"
            )
        if not control_account.active or control_account.account_class != "asset":
            raise ValueError("Stripe control account must be an active asset account")
        return self


class FinanceCloseChecklistItem(_StrictModel):
    sequence: int = Field(ge=1, le=len(_CHECKLIST_STAGES))
    stage: CloseWorkspaceStage
    status: CloseWorkspaceTaskStatus
    blocker_code: OpaqueRef | None = None

    @model_validator(mode="after")
    def _blocker_matches_status(self) -> "FinanceCloseChecklistItem":
        if self.status == "blocked" and self.blocker_code is None:
            raise ValueError("blocked checklist items require a blocker code")
        if self.status != "blocked" and self.blocker_code is not None:
            raise ValueError("non-blocked checklist items cannot carry blocker codes")
        return self


class FinanceCloseWorkspace(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_workspace.v3"] = Field(
        default=FINANCE_CLOSE_WORKSPACE_SCHEMA,
        alias="schema",
    )
    workspace_ref: OpaqueRef
    workspace_revision: PositiveRevision
    prepared_at: str
    close_scope: PeriodCloseScope
    ledger_snapshot_ref: OpaqueRef
    ledger_snapshot_revision: PositiveRevision
    ledger_snapshot_content_digest: Sha256Digest
    ledger_snapshot_evidence_digest: Sha256Digest
    ledger_snapshot_artifact_digest: Sha256Digest
    ledger_source_read_binding_digest: Sha256Digest
    close_evidence_bundle_ref: OpaqueRef
    close_evidence_bundle_revision: PositiveRevision
    close_evidence_bundle_digest: Sha256Digest
    accounting_provider: Literal["quickbooks", "xero"]
    provider_period_readiness: Literal[
        "ready",
        "ready_with_provider_lock_warning",
    ]
    stripe_subledger_ref: OpaqueRef
    stripe_control_account_ref: OpaqueRef
    open_period_package: OpenPeriodPackage
    trial_balance_package: TrialBalancePackage
    checklist: tuple[FinanceCloseChecklistItem, ...] = Field(
        min_length=len(_CHECKLIST_STAGES),
        max_length=len(_CHECKLIST_STAGES),
    )
    next_transition: Literal["open_period"] = "open_period"
    remaining_task_count: int = Field(ge=1, le=len(_CHECKLIST_STAGES))
    authority_state: Literal["structural_candidate_only"] = "structural_candidate_only"
    persistence_authorized: Literal[False] = False
    close_authorized: Literal[False] = False
    content_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("prepared_at")
    @classmethod
    def _prepared_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @field_validator("checklist", mode="before")
    @classmethod
    def _checklist_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    def content_digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"content_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _seal_exact_initial_workspace(self) -> "FinanceCloseWorkspace":
        sequences = tuple(item.sequence for item in self.checklist)
        stages = tuple(item.stage for item in self.checklist)
        if sequences != tuple(range(1, len(_CHECKLIST_STAGES) + 1)):
            raise ValueError("close checklist sequence must be exact and contiguous")
        if stages != _CHECKLIST_STAGES:
            raise ValueError(
                "close checklist stages must use the exact lifecycle order"
            )
        if self.checklist[0].status != "complete":
            raise ValueError("sealed source facts must be the completed first task")
        if self.checklist[1].status != "ready":
            raise ValueError("open_period must be the one ready transition")
        if any(item.status != "blocked" for item in self.checklist[2:]):
            raise ValueError("later close stages must remain blocked initially")
        incomplete = sum(item.status != "complete" for item in self.checklist)
        if self.remaining_task_count != incomplete:
            raise ValueError("remaining_task_count must match the exact checklist")
        expected = finance_canonical_digest(self.content_digest_payload())
        if self.content_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("content_digest does not match the close workspace")
        object.__setattr__(self, "content_digest", expected)
        return self


class FinanceCloseWorkspaceResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_workspace_result.v3"] = Field(
        default=FINANCE_CLOSE_WORKSPACE_RESULT_SCHEMA,
        alias="schema",
    )
    workspace: FinanceCloseWorkspace
    connector_operation_performed: Literal[False] = False
    persistence_authorized: Literal[False] = False
    close_authorized: Literal[False] = False


def _initial_checklist() -> tuple[FinanceCloseChecklistItem, ...]:
    blocker_codes: dict[str, str] = {
        "capture_trial_balance": "awaiting_open_period_transition",
        "reconcile_stripe_settlements": "awaiting_trial_balance_capture",
        "reconcile_accounts": "awaiting_trial_balance_and_settlement_reconciliation",
        "record_adjusting_entries": "awaiting_reconciliation_completion",
        "lock_subledgers": "awaiting_adjustment_readback",
        "consolidate": "awaiting_subledger_locks",
        "approve_close": "awaiting_close_review_package",
        "close_period": "awaiting_independent_approval",
    }
    items: list[FinanceCloseChecklistItem] = []
    for sequence, stage in enumerate(_CHECKLIST_STAGES, start=1):
        if stage == "source_facts_sealed":
            status: CloseWorkspaceTaskStatus = "complete"
            blocker = None
        elif stage == "open_period":
            status = "ready"
            blocker = None
        else:
            status = "blocked"
            blocker = blocker_codes[stage]
        items.append(
            FinanceCloseChecklistItem(
                sequence=sequence,
                stage=stage,
                status=status,
                blocker_code=blocker,
            )
        )
    return tuple(items)


def prepare_close_workspace(
    inputs: FinanceCloseWorkspaceInput,
) -> FinanceCloseWorkspaceResult:
    snapshot = inputs.ledger_snapshot
    evidence = inputs.close_evidence_bundle
    open_package = OpenPeriodPackage(
        period_open_candidate_ref=inputs.period_open_candidate_ref,
        prior_period_state=inputs.prior_period_state,
        opened_at=inputs.opened_at,
        opened_by_ref=inputs.opened_by_ref,
        reviewed_by_ref=inputs.open_reviewed_by_ref,
        evidence_use_refs=inputs.period_open_evidence_use_refs,
    )
    trial_package = TrialBalancePackage(
        trial_balance_ref=inputs.trial_balance_ref,
        as_of=snapshot.as_of,
        currency=snapshot.scope.functional_currency,
        lines=[
            {
                "account_ref": line.account_ref,
                "account_class": line.account_class,
                "debit": line.debit,
                "credit": line.credit,
            }
            for line in snapshot.trial_balance_lines
        ],
        total_debit=snapshot.total_debit,
        total_credit=snapshot.total_credit,
        prepared_by_ref=inputs.trial_balance_prepared_by_ref,
        reviewed_by_ref=inputs.trial_balance_reviewed_by_ref,
        evidence_use_refs=inputs.trial_balance_evidence_use_refs,
    )
    checklist = _initial_checklist()
    workspace = FinanceCloseWorkspace(
        workspace_ref=inputs.workspace_ref,
        workspace_revision=inputs.workspace_revision,
        prepared_at=inputs.prepared_at,
        close_scope=inputs.close_scope,
        ledger_snapshot_ref=snapshot.snapshot_ref,
        ledger_snapshot_revision=snapshot.snapshot_revision,
        ledger_snapshot_content_digest=snapshot.content_digest,
        ledger_snapshot_evidence_digest=snapshot.evidence_digest,
        ledger_snapshot_artifact_digest=snapshot.artifact_digest,
        ledger_source_read_binding_digest=(
            inputs.ledger_materialization.source_read_binding_digest
        ),
        close_evidence_bundle_ref=evidence.bundle_ref,
        close_evidence_bundle_revision=evidence.bundle_revision,
        close_evidence_bundle_digest=evidence.content_digest,
        accounting_provider=evidence.accounting_provider,
        provider_period_readiness=evidence.readiness,
        stripe_subledger_ref=inputs.stripe_subledger_ref,
        stripe_control_account_ref=inputs.stripe_control_account_ref,
        open_period_package=open_package,
        trial_balance_package=trial_package,
        checklist=checklist,
        remaining_task_count=sum(item.status != "complete" for item in checklist),
    )
    return FinanceCloseWorkspaceResult(workspace=workspace)


def _example_inputs() -> dict[str, Any]:
    evidence_inputs = deepcopy(PrepareCloseEvidenceBundlePrimitive.example_inputs)
    parsed_evidence_inputs = FinanceCloseEvidenceBundleInput.model_validate(
        evidence_inputs
    )
    evidence = prepare_close_evidence_bundle(parsed_evidence_inputs).bundle
    materialization = deepcopy(evidence_inputs["ledger_materialization"])
    project_id = "00000000-0000-0000-0000-000000000401"
    return {
        "workspace_ref": "close-workspace:2026-08",
        "workspace_revision": 1,
        "prepared_at": "2026-09-01T12:30:00Z",
        "ledger_materialization": materialization,
        "close_evidence_bundle": evidence,
        "close_scope": {
            "tenant_ref": "tenant:example",
            "company_ref": "company:example",
            "project_ref": "project:finance-lighthouse",
            "project_id": project_id,
            "scope_kind": "entity",
            "entity_refs": ["legal-entity:example-us"],
            "ledger_ref": "ledger:general",
            "functional_currency": "USD",
            "fiscal_period_ref": "fiscal-period:2026-08",
            "period_started_at": "2026-08-01T00:00:00Z",
            "period_ended_at": "2026-08-31T23:59:59Z",
            "jurisdiction_ref": "US",
            "financial_retention_policy_ref": "finance-seven-years",
            "evidence_retention_until": "2034-09-01T00:00:00Z",
            "materiality_threshold": "1.00",
            "required_subledgers": [
                {
                    "subledger_ref": "stripe:settlements",
                    "control_account_ref": "quickbooks-account:cash",
                }
            ],
            "evidence_custody_ref": "evidence-custody:finance",
            "spring_authority_ref": "spring-authority:finance",
            "authorized_evidence_issuer_refs": [
                "controller:independent-review",
                "spring-authority:finance",
            ],
        },
        "stripe_subledger_ref": "stripe:settlements",
        "stripe_control_account_ref": "quickbooks-account:cash",
        "period_open_candidate_ref": "period-open:2026-08",
        "prior_period_state": "closed",
        "opened_at": "2026-08-01T00:00:00Z",
        "opened_by_ref": "operator:controller",
        "open_reviewed_by_ref": "reviewer:period-owner",
        "period_open_evidence_use_refs": [
            "evidence-use:period-calendar",
            "evidence-use:period-open-state",
        ],
        "trial_balance_ref": "trial-balance:2026-08",
        "trial_balance_prepared_by_ref": "operator:accountant",
        "trial_balance_reviewed_by_ref": "reviewer:controller",
        "trial_balance_evidence_use_refs": [
            "evidence-use:ledger-extract-attestation",
            "evidence-use:trial-balance-extract",
        ],
    }


class PrepareCloseWorkspacePrimitive(
    BusinessProcessPrimitive[
        FinanceCloseWorkspaceInput,
        FinanceCloseWorkspaceResult,
    ]
):
    primitive_ref = "finance.prepare_close_workspace"
    version = "3.0.0"
    title = "Prepare monthly close workspace"
    description = (
        "Build an exact-scope one-entity monthly close workspace and initial "
        "checklist from a sealed canonical ledger snapshot and governed accounting, "
        "Stripe, and provider-period evidence without executing an effect."
    )
    input_model = FinanceCloseWorkspaceInput
    output_model = FinanceCloseWorkspaceResult
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
        contract["system_of_record_authority"] = "spring_host_required"
        contract["workspace_authority"] = "structural_candidate_only"
        contract["legacy_reconciliation_route_authority"] = "excluded"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: FinanceCloseWorkspaceInput,
    ) -> PrimitiveExecutionResult[FinanceCloseWorkspaceResult]:
        runtime_scope = context.scope
        close_scope = inputs.close_scope
        if (
            runtime_scope.tenant_ref != close_scope.tenant_ref
            or runtime_scope.company_ref != close_scope.company_ref
            or runtime_scope.project_ref != close_scope.project_ref
            or runtime_scope.project_id != close_scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="close_workspace_scope_mismatch",
                message=(
                    "The close workspace tenant, company, project, and project UUID "
                    "must exactly match the active runtime scope."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = prepare_close_workspace(inputs)
        workspace = output.workspace
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared the source-complete exact-scope monthly close workspace; "
                "open_period is ready and all later stages remain fail-closed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_workspace_prepared",
                    payload={
                        "workspace_ref": workspace.workspace_ref,
                        "workspace_revision": workspace.workspace_revision,
                        "ledger_snapshot_artifact_digest": (
                            workspace.ledger_snapshot_artifact_digest
                        ),
                        "close_evidence_bundle_digest": (
                            workspace.close_evidence_bundle_digest
                        ),
                        "content_digest": workspace.content_digest,
                        "next_transition": workspace.next_transition,
                        "remaining_task_count": workspace.remaining_task_count,
                        "authority_state": workspace.authority_state,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_workspace_candidate",
                    summary=(
                        "A structurally sealed initial close checklist and transition "
                        "packages were derived from source-complete accounting and "
                        "Stripe evidence; Spring verification remains required."
                    ),
                    labels=[
                        "one_legal_entity",
                        "one_base_currency",
                        "monthly_close",
                        "governed_stripe_observation_bound",
                        "provider_period_status_bound",
                        "structural_candidate_only",
                    ],
                    refs={
                        "workspace_digest": workspace.content_digest,
                        "ledger_snapshot_digest": (
                            workspace.ledger_snapshot_artifact_digest
                        ),
                        "close_evidence_bundle_digest": (
                            workspace.close_evidence_bundle_digest
                        ),
                    },
                )
            ],
        )


FINANCE_CLOSE_WORKSPACE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareCloseWorkspacePrimitive(),)


__all__ = [
    "FINANCE_CLOSE_WORKSPACE_EXECUTABLE_PRIMITIVES",
    "FINANCE_CLOSE_WORKSPACE_INPUT_SCHEMA",
    "FINANCE_CLOSE_WORKSPACE_RESULT_SCHEMA",
    "FINANCE_CLOSE_WORKSPACE_SCHEMA",
    "CloseWorkspaceStage",
    "CloseWorkspaceTaskStatus",
    "FinanceCloseChecklistItem",
    "FinanceCloseWorkspace",
    "FinanceCloseWorkspaceInput",
    "FinanceCloseWorkspaceResult",
    "PrepareCloseWorkspacePrimitive",
    "prepare_close_workspace",
]
