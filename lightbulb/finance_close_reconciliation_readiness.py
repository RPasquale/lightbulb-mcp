"""Deterministic bridge from settlement activity to account-close readiness.

Stripe payout matching is supporting activity evidence, not an ending-balance
reconciliation. This module refuses to make that category error: it verifies
that the governed open-period and trial-balance candidates are retained, binds
the exact settlement result to the close workspace, and then marks the separate
account/subledger reconciliation stage ready. It performs no review, package
creation, persistence, lifecycle transition, or provider operation.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.finance_close_lifecycle import PeriodCloseLifecycleSnapshot
from lightbulb.finance_close_workspace import (
    FinanceCloseChecklistItem,
    FinanceCloseWorkspace,
    FinanceCloseWorkspaceInput,
    PrepareCloseWorkspacePrimitive,
    prepare_close_workspace,
)
from lightbulb.finance_settlement_reconciliation import (
    ReconcileStripeSettlementsPrimitive,
    StripeLedgerReconciliationInput,
    StripeLedgerReconciliationResult,
    reconcile_stripe_settlements,
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

CLOSE_RECONCILIATION_READINESS_INPUT_SCHEMA = (
    "lightbulb.finance_close_reconciliation_readiness_input.v1"
)
CLOSE_RECONCILIATION_READINESS_RESULT_SCHEMA = (
    "lightbulb.finance_close_reconciliation_readiness_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_CHECKLIST_STAGES = (
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
_REQUIRED_EVIDENCE_KINDS = (
    "account_subledger_reconciliations",
    "reconciliation_review_attestation",
)


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{field_name} must be a trimmed UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


ReadinessBlockerCode = Literal[
    "lifecycle_snapshot_missing",
    "lifecycle_scope_mismatch",
    "lifecycle_stage_not_ready",
    "open_period_package_mismatch",
    "trial_balance_package_mismatch",
    "settlement_workspace_mismatch",
    "settlement_scope_mismatch",
    "settlement_exact_matches_incomplete",
    "settlement_review_proposals_pending",
    "settlement_exceptions_unresolved",
    "settlement_variance_unexplained",
]


_BLOCKER_MESSAGES: dict[ReadinessBlockerCode, str] = {
    "lifecycle_snapshot_missing": (
        "Retain governed open-period and trial-balance transition candidates first."
    ),
    "lifecycle_scope_mismatch": (
        "The retained period-close lifecycle scope does not match the workspace."
    ),
    "lifecycle_stage_not_ready": (
        "The lifecycle must contain exactly open_period and capture_trial_balance."
    ),
    "open_period_package_mismatch": (
        "The retained open-period package does not match the sealed workspace."
    ),
    "trial_balance_package_mismatch": (
        "The retained trial-balance package does not match the sealed workspace."
    ),
    "settlement_workspace_mismatch": (
        "The settlement result is not bound to this exact workspace revision and digest."
    ),
    "settlement_scope_mismatch": (
        "The settlement result does not match the workspace period, currency, or Stripe binding."
    ),
    "settlement_exact_matches_incomplete": (
        "Not every Stripe payout has an exact reference, amount, and date match."
    ),
    "settlement_review_proposals_pending": (
        "Settlement amount/date proposals still require independent review."
    ),
    "settlement_exceptions_unresolved": (
        "Settlement reconciliation exceptions remain unresolved."
    ),
    "settlement_variance_unexplained": (
        "The referenced settlement activity has a non-zero unexplained variance."
    ),
}


class CloseReconciliationReadinessInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_reconciliation_readiness_input.v1"] = (
        Field(default=CLOSE_RECONCILIATION_READINESS_INPUT_SCHEMA, alias="schema")
    )
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot | None = None
    settlement_reconciliation: StripeLedgerReconciliationResult
    evaluated_at: str

    @field_validator(
        "workspace",
        "lifecycle_snapshot",
        "settlement_reconciliation",
        mode="before",
    )
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        if value is None:
            return None
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
            "settlement_reconciliation": StripeLedgerReconciliationResult,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_time(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def _causal_evaluation(self) -> "CloseReconciliationReadinessInput":
        evaluated = datetime.fromisoformat(self.evaluated_at.replace("Z", "+00:00"))
        reconciled = datetime.fromisoformat(
            self.settlement_reconciliation.reconciled_at.replace("Z", "+00:00")
        )
        if evaluated < reconciled:
            raise ValueError("readiness evaluation cannot precede reconciliation")
        if self.lifecycle_snapshot is not None:
            prepared = datetime.fromisoformat(
                self.workspace.prepared_at.replace("Z", "+00:00")
            )
            transition_times = tuple(
                datetime.fromisoformat(item.command.occurred_at.replace("Z", "+00:00"))
                for item in self.lifecycle_snapshot.transition_history
            )
            if transition_times[0] < prepared:
                raise ValueError(
                    "retained close transitions cannot precede workspace preparation"
                )
            if evaluated < transition_times[-1]:
                raise ValueError(
                    "readiness evaluation cannot precede retained close transitions"
                )
        return self


class CloseReconciliationReadinessBlocker(_StrictModel):
    code: ReadinessBlockerCode
    message: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _canonical_message(self) -> "CloseReconciliationReadinessBlocker":
        if self.message != _BLOCKER_MESSAGES[self.code]:
            raise ValueError("readiness blocker message must match its canonical code")
        return self


class CloseReconciliationReadinessResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_reconciliation_readiness_result.v1"] = (
        Field(default=CLOSE_RECONCILIATION_READINESS_RESULT_SCHEMA, alias="schema")
    )
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    settlement_result_digest: Sha256Digest
    lifecycle_version: int | None = Field(default=None, ge=1, le=8)
    lifecycle_state_digest: Sha256Digest | None = None
    trial_balance_transition_digest: Sha256Digest | None = None
    evaluated_at: str
    blockers: tuple[CloseReconciliationReadinessBlocker, ...] = Field(max_length=11)
    checklist: tuple[FinanceCloseChecklistItem, ...] = Field(
        min_length=10, max_length=10
    )
    account_reconciliation_ready: bool
    next_transition: Literal["reconcile_accounts"] | None
    required_evidence_kinds: tuple[
        Literal[
            "account_subledger_reconciliations",
            "reconciliation_review_attestation",
        ],
        Literal[
            "account_subledger_reconciliations",
            "reconciliation_review_attestation",
        ],
    ] = (
        "account_subledger_reconciliations",
        "reconciliation_review_attestation",
    )
    settlement_activity_is_balance_reconciliation: Literal[False] = False
    reconciliation_package_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False
    result_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("blockers", "checklist", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_time(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_projection(self) -> "CloseReconciliationReadinessResult":
        codes = tuple(item.code for item in self.blockers)
        if codes != tuple(sorted(codes)) or len(codes) != len(set(codes)):
            raise ValueError("readiness blockers must be unique and canonical")
        expected_ready = not self.blockers
        if self.account_reconciliation_ready != expected_ready:
            raise ValueError("account reconciliation readiness must match blockers")
        expected_next = "reconcile_accounts" if expected_ready else None
        if self.next_transition != expected_next:
            raise ValueError("next transition must match readiness")
        if tuple(item.sequence for item in self.checklist) != tuple(range(1, 11)):
            raise ValueError("readiness checklist must preserve exact sequence")
        if tuple(item.stage for item in self.checklist) != _CHECKLIST_STAGES:
            raise ValueError("readiness checklist must preserve exact close stages")
        if self.required_evidence_kinds != _REQUIRED_EVIDENCE_KINDS:
            raise ValueError("readiness must name the exact next-stage evidence")
        if (self.lifecycle_version is None) != (self.lifecycle_state_digest is None):
            raise ValueError("lifecycle version and state digest must appear together")
        if self.checklist[0].status != "complete":
            raise ValueError("source facts must remain complete")
        if any(item.status != "blocked" for item in self.checklist[5:]):
            raise ValueError("later close stages must remain blocked")
        if expected_ready:
            if any(item.status != "complete" for item in self.checklist[:4]):
                raise ValueError("ready projection requires four completed stages")
            if self.checklist[4].status != "ready":
                raise ValueError("reconcile_accounts must be the ready stage")
        elif self.checklist[4].status != "blocked":
            raise ValueError("blocked projection cannot ready reconcile_accounts")
        expected = _stable_digest(self.digest_payload())
        if self.result_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("result_digest does not match readiness evidence")
        object.__setattr__(self, "result_digest", expected)
        return self


def _blocker(code: ReadinessBlockerCode) -> CloseReconciliationReadinessBlocker:
    return CloseReconciliationReadinessBlocker(
        code=code,
        message=_BLOCKER_MESSAGES[code],
    )


def _project_checklist(
    workspace: FinanceCloseWorkspace,
    *,
    open_complete: bool,
    trial_complete: bool,
    settlement_complete: bool,
    account_ready: bool,
) -> tuple[FinanceCloseChecklistItem, ...]:
    completed = {
        "source_facts_sealed": True,
        "open_period": open_complete,
        "capture_trial_balance": trial_complete,
        "reconcile_stripe_settlements": settlement_complete,
    }
    items: list[FinanceCloseChecklistItem] = []
    for original in workspace.checklist:
        if completed.get(original.stage, False):
            status = "complete"
            blocker_code = None
        elif original.stage == "reconcile_accounts" and account_ready:
            status = "ready"
            blocker_code = None
        else:
            status = "blocked"
            blocker_code = (
                "awaiting_retained_open_period_transition"
                if original.stage == "open_period"
                else (
                    "awaiting_retained_trial_balance_transition"
                    if original.stage == "capture_trial_balance"
                    else (
                        "awaiting_exact_settlement_reconciliation"
                        if original.stage == "reconcile_stripe_settlements"
                        else (
                            "awaiting_account_reconciliation_readiness"
                            if original.stage == "reconcile_accounts"
                            else original.blocker_code or "awaiting_prior_close_stage"
                        )
                    )
                )
            )
        items.append(
            FinanceCloseChecklistItem(
                sequence=original.sequence,
                stage=original.stage,
                status=status,
                blocker_code=blocker_code,
            )
        )
    return tuple(items)


def evaluate_close_reconciliation_readiness(
    inputs: CloseReconciliationReadinessInput,
) -> CloseReconciliationReadinessResult:
    workspace = inputs.workspace
    snapshot = inputs.lifecycle_snapshot
    settlement = inputs.settlement_reconciliation
    codes: set[ReadinessBlockerCode] = set()

    open_complete = False
    trial_complete = False
    trial_transition_digest: str | None = None
    if snapshot is None:
        codes.add("lifecycle_snapshot_missing")
    else:
        if snapshot.scope != workspace.close_scope:
            codes.add("lifecycle_scope_mismatch")
        if snapshot.version != 2:
            codes.add("lifecycle_stage_not_ready")
        if snapshot.period_open != workspace.open_period_package:
            codes.add("open_period_package_mismatch")
        else:
            open_complete = True
        if snapshot.trial_balance != workspace.trial_balance_package:
            codes.add("trial_balance_package_mismatch")
        else:
            trial_complete = snapshot.version >= 2
        if snapshot.version >= 2:
            trial_transition_digest = snapshot.transition_history[1].transition_digest

    if (
        settlement.workspace_ref != workspace.workspace_ref
        or settlement.workspace_revision != workspace.workspace_revision
        or settlement.workspace_digest != workspace.content_digest
    ):
        codes.add("settlement_workspace_mismatch")
    period_start = (
        datetime.fromisoformat(
            workspace.close_scope.period_started_at.replace("Z", "+00:00")
        )
        .date()
        .isoformat()
    )
    period_end = (
        datetime.fromisoformat(
            workspace.close_scope.period_ended_at.replace("Z", "+00:00")
        )
        .date()
        .isoformat()
    )
    if (
        settlement.start_date != period_start
        or settlement.end_date != period_end
        or settlement.currency != workspace.close_scope.functional_currency
        or settlement.stripe_subledger_ref != workspace.stripe_subledger_ref
        or settlement.control_account_ref != workspace.stripe_control_account_ref
    ):
        codes.add("settlement_scope_mismatch")
    summary = settlement.summary
    if summary.matched_count != summary.payout_count:
        codes.add("settlement_exact_matches_incomplete")
    if summary.proposed_match_count:
        codes.add("settlement_review_proposals_pending")
    if summary.unresolved_exception_count:
        codes.add("settlement_exceptions_unresolved")
    if summary.unexplained_variance != 0:
        codes.add("settlement_variance_unexplained")

    settlement_complete = not any(code.startswith("settlement_") for code in codes)
    account_ready = not codes
    blockers = tuple(_blocker(code) for code in sorted(codes))
    checklist = _project_checklist(
        workspace,
        open_complete=open_complete,
        trial_complete=trial_complete,
        settlement_complete=settlement_complete,
        account_ready=account_ready,
    )
    return CloseReconciliationReadinessResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        settlement_result_digest=settlement.result_digest,
        lifecycle_version=snapshot.version if snapshot is not None else None,
        lifecycle_state_digest=(
            snapshot.state_digest if snapshot is not None else None
        ),
        trial_balance_transition_digest=trial_transition_digest,
        evaluated_at=inputs.evaluated_at,
        blockers=blockers,
        checklist=checklist,
        account_reconciliation_ready=account_ready,
        next_transition="reconcile_accounts" if account_ready else None,
    )


def _example_inputs() -> dict[str, Any]:
    workspace_input = FinanceCloseWorkspaceInput.model_validate(
        deepcopy(PrepareCloseWorkspacePrimitive.example_inputs)
    )
    workspace = prepare_close_workspace(workspace_input).workspace
    reconciliation_input = StripeLedgerReconciliationInput.model_validate(
        ReconcileStripeSettlementsPrimitive.example_inputs
    )
    reconciliation = reconcile_stripe_settlements(reconciliation_input)
    return {
        "workspace": workspace.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "lifecycle_snapshot": None,
        "settlement_reconciliation": reconciliation.model_dump(
            mode="python", by_alias=True, exclude_none=True
        ),
        "evaluated_at": "2026-09-01T12:40:00Z",
    }


class EvaluateCloseReconciliationReadinessPrimitive(
    BusinessProcessPrimitive[
        CloseReconciliationReadinessInput,
        CloseReconciliationReadinessResult,
    ]
):
    primitive_ref = "finance.evaluate_close_reconciliation_readiness"
    version = "1.0.0"
    title = "Evaluate close reconciliation readiness"
    description = (
        "Bind retained open-period and trial-balance candidates to an exact Stripe "
        "settlement activity result, then project whether full account and subledger "
        "balance reconciliation may begin without advancing the lifecycle."
    )
    input_model = CloseReconciliationReadinessInput
    output_model = CloseReconciliationReadinessResult
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
            "reconciliation_packages": 0,
            "lifecycle_transitions": 0,
        }
        contract["semantic_boundary"] = {
            "stripe_settlement_activity": "supporting_evidence_only",
            "account_and_subledger_balances": "separate_reviewed_stage_required",
        }
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CloseReconciliationReadinessInput,
    ) -> PrimitiveExecutionResult[CloseReconciliationReadinessResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="close_reconciliation_readiness_scope_mismatch",
                message=(
                    "The workspace tenant, company, project, and project UUID must "
                    "exactly match the active runtime scope."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = evaluate_close_reconciliation_readiness(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Account reconciliation is ready to be prepared."
                if output.account_reconciliation_ready
                else f"Account reconciliation remains blocked by {len(output.blockers)} condition(s)."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_reconciliation_readiness_evaluated",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "account_reconciliation_ready": (
                            output.account_reconciliation_ready
                        ),
                        "blocker_count": len(output.blockers),
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_reconciliation_readiness_candidate",
                    summary=(
                        "Settlement activity and retained close-stage prerequisites "
                        "were evaluated without treating activity as balance evidence."
                    ),
                    labels=[
                        "monthly_close",
                        "supporting_activity_only",
                        "structural_candidate_only",
                    ],
                    refs={"result_digest": output.result_digest},
                )
            ],
        )


FINANCE_CLOSE_RECONCILIATION_READINESS_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluateCloseReconciliationReadinessPrimitive(),)


__all__ = [
    "CLOSE_RECONCILIATION_READINESS_INPUT_SCHEMA",
    "CLOSE_RECONCILIATION_READINESS_RESULT_SCHEMA",
    "CloseReconciliationReadinessBlocker",
    "CloseReconciliationReadinessInput",
    "CloseReconciliationReadinessResult",
    "EvaluateCloseReconciliationReadinessPrimitive",
    "FINANCE_CLOSE_RECONCILIATION_READINESS_EXECUTABLE_PRIMITIVES",
    "ReadinessBlockerCode",
    "evaluate_close_reconciliation_readiness",
]
