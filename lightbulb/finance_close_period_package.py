"""Prepare a readiness-bound final period-close package candidate.

The primitive recomputes deterministic close controls from typed inputs and
binds their exact result, the retained version-seven approval transition, a
close request, and a Spring-reported readiness observation into the lifecycle's
``close_period`` package. Spring still owns attestation authentication, current
operator RBAC, evidence custody, hosted execution, persistence, and final
lifecycle admission. No period, connector, provider, journal, or approval
effect occurs here.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
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

from lightbulb.finance_accounting import (
    PeriodCloseReadinessEvaluation,
    PeriodCloseReadinessInput,
    evaluate_period_close_readiness,
)
from lightbulb.finance_close_approval_transition import (
    PrepareCloseApprovalTransitionCommandInput,
    PrepareCloseApprovalTransitionCommandPrimitive,
    prepare_close_approval_transition_command,
)
from lightbulb.finance_close_lifecycle import (
    CloseApprovalPackage,
    ClosePeriodPackage,
    PeriodCloseLifecycleSnapshot,
    materialize_period_close_candidate,
    period_close_scope_digest,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

CLOSE_PERIOD_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_close_period_package_candidate_input.v1"
)
CLOSE_PERIOD_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_close_period_package_candidate_result.v1"
)
CLOSE_READINESS_OBSERVATION_SCHEMA = "lightbulb.finance_close_readiness_observation.v1"

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"


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


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def close_period_request_digest(
    *,
    workspace: FinanceCloseWorkspace,
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot,
    approval_transition_digest: str,
    close_candidate_ref: str,
    close_request_ref: str,
    close_requested_at: str,
    close_operator_ref: str,
    readiness_evaluation: PeriodCloseReadinessEvaluation,
) -> str:
    """Commit the exact approved state, close request, and control result."""

    return _stable_digest(
        {
            "schema": "lightbulb.finance_close_period_request.v1",
            "workspace_ref": workspace.workspace_ref,
            "workspace_revision": workspace.workspace_revision,
            "workspace_digest": workspace.content_digest,
            "scope_digest": period_close_scope_digest(workspace.close_scope),
            "lifecycle_version": lifecycle_snapshot.version,
            "lifecycle_state_digest": lifecycle_snapshot.state_digest,
            "approval_transition_digest": approval_transition_digest,
            "close_candidate_ref": close_candidate_ref,
            "close_request_ref": close_request_ref,
            "close_requested_at": close_requested_at,
            "close_operator_ref": close_operator_ref,
            "readiness_evaluation_ref": readiness_evaluation.evaluation_ref,
            "readiness_operation_digest": readiness_evaluation.operation_digest,
            "readiness_evidence_digest": readiness_evaluation.evidence_digest,
            "readiness_evaluation_digest": readiness_evaluation.evaluation_digest,
        }
    )


class CloseReadinessObservation(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_readiness_observation.v1"] = Field(
        default=CLOSE_READINESS_OBSERVATION_SCHEMA,
        alias="schema",
    )
    readiness_attestation_ref: OpaqueRef
    readiness_policy_ref: OpaqueRef
    issuer_ref: OpaqueRef
    scope_digest: Sha256Digest
    lifecycle_state_digest: Sha256Digest
    approval_transition_digest: Sha256Digest
    close_candidate_ref: OpaqueRef
    close_request_ref: OpaqueRef
    close_request_digest: Sha256Digest
    close_operator_ref: OpaqueRef
    readiness_evaluation_ref: OpaqueRef
    readiness_operation_digest: Sha256Digest
    readiness_evidence_digest: Sha256Digest
    readiness_evaluation_digest: Sha256Digest
    decision: Literal["reported_ready"] = "reported_ready"
    observed_at: str
    expires_at: str

    @field_validator("observed_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _readiness_window_is_positive(self) -> "CloseReadinessObservation":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.observed_at):
            raise ValueError("close readiness must expire after its observation")
        return self

    def evidence_digest(self) -> str:
        return _stable_digest(self.to_dict())


class PrepareClosePeriodPackageInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_period_package_candidate_input.v1"] = (
        Field(default=CLOSE_PERIOD_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    )
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    readiness_input: PeriodCloseReadinessInput
    readiness_observation: CloseReadinessObservation
    close_candidate_ref: OpaqueRef
    close_request_ref: OpaqueRef
    close_requested_at: str
    close_operator_ref: OpaqueRef
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    prepared_at: str

    @field_validator(
        "workspace",
        "lifecycle_snapshot",
        "readiness_input",
        mode="before",
    )
    @classmethod
    def _detached_sources(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
            "readiness_input": PeriodCloseReadinessInput,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("evidence_use_refs", mode="before")
    @classmethod
    def _evidence_refs_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("close_requested_at", "prepared_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _exact_approved_sources(self) -> "PrepareClosePeriodPackageInput":
        workspace = self.workspace
        snapshot = self.lifecycle_snapshot
        scope = workspace.close_scope
        readiness_input = self.readiness_input
        observation = self.readiness_observation
        if (
            snapshot.scope != scope
            or snapshot.version != 7
            or snapshot.status != "independent_approval_evidence_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
            or snapshot.adjusting_entries is None
            or snapshot.subledger_locks is None
            or snapshot.consolidation is None
            or snapshot.close_approval is None
            or snapshot.close_candidate is not None
        ):
            raise ValueError("the exact retained approved close snapshot is required")
        if (
            tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs
            or len(set(self.evidence_use_refs)) != 2
        ):
            raise ValueError(
                "exactly two canonical close evidence use references are required"
            )
        if (
            len(
                {
                    self.close_candidate_ref,
                    self.close_request_ref,
                    observation.readiness_attestation_ref,
                }
            )
            != 3
        ):
            raise ValueError(
                "close candidate, request, and readiness attestation refs must be distinct"
            )
        approval_transition = snapshot.transition_history[6]
        approval = snapshot.close_approval
        if approval_transition.command.kind != "approve_close" or not isinstance(
            approval, CloseApprovalPackage
        ):
            raise ValueError("retained approval transition has invalid content")
        if self.close_operator_ref == approval.independent_approver_ref:
            raise ValueError("independent approver cannot operate the hosted close")

        expected_dates = (
            _parsed_timestamp(scope.period_started_at).date().isoformat(),
            _parsed_timestamp(scope.period_ended_at).date().isoformat(),
        )
        if (
            readiness_input.close_ref != self.close_candidate_ref
            or readiness_input.company.company_ref != scope.company_ref
            or readiness_input.company.functional_currency != scope.functional_currency
            or readiness_input.period.period_ref != scope.fiscal_period_ref
            or readiness_input.period.company_ref != scope.company_ref
            or readiness_input.period.functional_currency != scope.functional_currency
            or (
                readiness_input.period.start_date,
                readiness_input.period.end_date,
            )
            != expected_dates
        ):
            raise ValueError("close readiness input must bind the exact fiscal scope")
        trial = snapshot.trial_balance
        chart_refs = tuple(
            sorted(item.account_ref for item in readiness_input.chart_of_accounts)
        )
        trial_refs = tuple(item.account_ref for item in trial.lines)
        if (
            not readiness_input.chart_of_accounts_complete
            or chart_refs != trial_refs
            or readiness_input.trial_balance_debits != trial.total_debit
            or readiness_input.trial_balance_credits != trial.total_credit
        ):
            raise ValueError("close readiness must bind the exact trial balance")

        retained_reconciliations = snapshot.reconciliations.account_reconciliations
        supplied_by_account = {
            item.account_ref: item for item in readiness_input.reconciliations
        }
        if set(supplied_by_account) != {
            item.account_ref for item in retained_reconciliations
        }:
            raise ValueError("close readiness must bind every retained reconciliation")
        for retained in retained_reconciliations:
            supplied = supplied_by_account[retained.account_ref]
            if (
                supplied.reconciliation_ref != retained.reconciliation_ref
                or supplied.status != "complete"
                or supplied.unreconciled_amount != abs(retained.unexplained_variance)
                or supplied.reviewed_by_ref != retained.reviewed_by_ref
            ):
                raise ValueError(
                    "close readiness must bind every exact reconciliation result"
                )
        approval_gate = readiness_input.approval
        if (
            not approval_gate.required
            or approval_gate.status != "approved"
            or approval_gate.prepared_by_ref != approval.review_prepared_by_ref
            or approval_gate.approved_by_ref != approval.independent_approver_ref
        ):
            raise ValueError(
                "close readiness must retain the exact independent approval"
            )
        if readiness_input.consolidation.required != (
            scope.scope_kind == "consolidation_group"
        ):
            raise ValueError("close readiness consolidation mode must match scope")

        approval_time = _parsed_timestamp(approval_transition.command.occurred_at)
        evaluation_time = _parsed_timestamp(readiness_input.evaluation_as_of)
        observation_time = _parsed_timestamp(observation.observed_at)
        request_time = _parsed_timestamp(self.close_requested_at)
        prepared_time = _parsed_timestamp(self.prepared_at)
        expiry_time = _parsed_timestamp(observation.expires_at)
        if evaluation_time < approval_time:
            raise ValueError("close controls cannot precede approval transition")
        if observation_time < evaluation_time:
            raise ValueError("readiness observation cannot precede close controls")
        if request_time < observation_time:
            raise ValueError("close request cannot precede readiness observation")
        if prepared_time < request_time:
            raise ValueError("close package cannot precede its request")
        if prepared_time >= expiry_time:
            raise ValueError("close readiness is expired at package preparation")

        evaluation = evaluate_period_close_readiness(readiness_input)
        if (
            evaluation.disposition != "ready"
            or evaluation.close_authorized is not False
            or evaluation.trial_balance_imbalance != Decimal(0)
            or evaluation.required_reconciliation_count != len(retained_reconciliations)
            or evaluation.completed_reconciliation_count
            != len(retained_reconciliations)
            or evaluation.missing_entity_refs
        ):
            raise ValueError("deterministic close controls must be exactly ready")
        expected_request_digest = close_period_request_digest(
            workspace=workspace,
            lifecycle_snapshot=snapshot,
            approval_transition_digest=approval_transition.transition_digest,
            close_candidate_ref=self.close_candidate_ref,
            close_request_ref=self.close_request_ref,
            close_requested_at=self.close_requested_at,
            close_operator_ref=self.close_operator_ref,
            readiness_evaluation=evaluation,
        )
        if (
            observation.issuer_ref != scope.spring_authority_ref
            or observation.scope_digest != period_close_scope_digest(scope)
            or observation.lifecycle_state_digest != snapshot.state_digest
            or observation.approval_transition_digest
            != approval_transition.transition_digest
            or observation.close_candidate_ref != self.close_candidate_ref
            or observation.close_request_ref != self.close_request_ref
            or observation.close_request_digest != expected_request_digest
            or observation.close_operator_ref != self.close_operator_ref
            or observation.readiness_evaluation_ref != evaluation.evaluation_ref
            or observation.readiness_operation_digest != evaluation.operation_digest
            or observation.readiness_evidence_digest != evaluation.evidence_digest
            or observation.readiness_evaluation_digest != evaluation.evaluation_digest
        ):
            raise ValueError(
                "Spring readiness must bind the exact approved close request"
            )
        return self

    def readiness_evaluation(self) -> PeriodCloseReadinessEvaluation:
        return evaluate_period_close_readiness(self.readiness_input)


class ClosePeriodPackageCandidateResult(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_period_package_candidate_result.v1"] = (
        Field(default=CLOSE_PERIOD_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    )
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[7] = 7
    lifecycle_state_digest: Sha256Digest
    approval_transition_digest: Sha256Digest
    close_request_digest: Sha256Digest
    prepared_at: str
    readiness_evaluation: PeriodCloseReadinessEvaluation
    package: ClosePeriodPackage
    package_digest: Sha256Digest
    readiness_observation_digest: Sha256Digest
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    readiness_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    operator_authorization_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    hosted_close_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False
    connector_calls_authorized: Literal[False] = False

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_candidate(self) -> "ClosePeriodPackageCandidateResult":
        if self.package_digest != _stable_digest(self.package.to_dict()):
            raise ValueError("package_digest must commit the exact close package")
        if (
            self.readiness_evaluation.evaluation_digest
            != self.package.readiness_evaluation_digest
            or self.readiness_evaluation.evidence_digest
            != self.package.readiness_evidence_digest
            or self.close_request_digest != self.package.close_request_digest
            or self.readiness_observation_digest
            != self.package.readiness_observation_digest
        ):
            raise ValueError("candidate must retain exact readiness evidence")
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match close package evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_close_period_package(
    inputs: PrepareClosePeriodPackageInput,
) -> ClosePeriodPackageCandidateResult:
    workspace = inputs.workspace
    snapshot = inputs.lifecycle_snapshot
    observation = inputs.readiness_observation
    evaluation = inputs.readiness_evaluation()
    approval = snapshot.close_approval
    if approval is None:  # pragma: no cover - guarded by input validation
        raise RuntimeError("approved close snapshot lost its approval package")
    approval_transition = snapshot.transition_history[6]
    package = ClosePeriodPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        close_candidate_ref=inputs.close_candidate_ref,
        close_request_ref=inputs.close_request_ref,
        close_request_digest=observation.close_request_digest,
        readiness_attestation_ref=observation.readiness_attestation_ref,
        readiness_policy_ref=observation.readiness_policy_ref,
        readiness_evaluation_ref=evaluation.evaluation_ref,
        readiness_evaluation_digest=evaluation.evaluation_digest,
        readiness_evidence_digest=evaluation.evidence_digest,
        readiness_observation_digest=observation.evidence_digest(),
        readiness_expires_at=observation.expires_at,
        approval_candidate_ref=approval.approval_candidate_ref,
        approval_transition_digest=approval_transition.transition_digest,
        closed_through_at=workspace.close_scope.period_ended_at,
        close_requested_at=inputs.close_requested_at,
        close_operator_ref=inputs.close_operator_ref,
    )
    return ClosePeriodPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        approval_transition_digest=approval_transition.transition_digest,
        close_request_digest=observation.close_request_digest,
        prepared_at=inputs.prepared_at,
        readiness_evaluation=evaluation,
        package=package,
        package_digest=_stable_digest(package.to_dict()),
        readiness_observation_digest=observation.evidence_digest(),
    )


def _readiness_payload(
    *,
    workspace: FinanceCloseWorkspace,
    snapshot: PeriodCloseLifecycleSnapshot,
    close_candidate_ref: str,
) -> dict[str, Any]:
    scope = workspace.close_scope
    approval = snapshot.close_approval
    reconciliations = snapshot.reconciliations
    trial = snapshot.trial_balance
    if approval is None or reconciliations is None:  # pragma: no cover
        raise RuntimeError("example approved snapshot is incomplete")
    evidence = [
        {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": "evidence:close-readiness:trial-balance",
            "kind": "trial_balance",
            "issuer_ref": scope.spring_authority_ref,
            "subject_ref": scope.company_ref,
            "sha256": _stable_digest(trial.to_dict()),
            "observed_at": "2026-09-01T14:44:00Z",
            "effective_at": "2026-09-01T14:40:00Z",
            "verification_grade": "verified",
            "classification": "restricted",
        },
        {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": "evidence:close-readiness:reconciliations",
            "kind": "reconciliation",
            "issuer_ref": scope.spring_authority_ref,
            "subject_ref": scope.company_ref,
            "sha256": _stable_digest(reconciliations.to_dict()),
            "observed_at": "2026-09-01T14:44:00Z",
            "effective_at": "2026-09-01T14:40:00Z",
            "verification_grade": "verified",
            "classification": "restricted",
        },
        {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": "evidence:close-readiness:period-status",
            "kind": "period_status",
            "issuer_ref": scope.spring_authority_ref,
            "subject_ref": scope.company_ref,
            "sha256": _stable_digest(snapshot.to_dict()),
            "observed_at": "2026-09-01T14:44:00Z",
            "effective_at": "2026-09-01T14:40:00Z",
            "verification_grade": "verified",
            "classification": "restricted",
        },
    ]
    return {
        "evaluation_ref": "close-readiness-evaluation:2026-08",
        "evaluation_as_of": "2026-09-01T14:45:00Z",
        "close_ref": close_candidate_ref,
        "company": {
            "company_ref": scope.company_ref,
            "functional_currency": scope.functional_currency,
            "allowed_transaction_currencies": [scope.functional_currency],
            "amount_scale": 2,
        },
        "period": {
            "period_ref": scope.fiscal_period_ref,
            "company_ref": scope.company_ref,
            "functional_currency": scope.functional_currency,
            "start_date": _parsed_timestamp(scope.period_started_at).date().isoformat(),
            "end_date": _parsed_timestamp(scope.period_ended_at).date().isoformat(),
            "state": "soft_closed",
        },
        "chart_of_accounts_complete": True,
        "chart_of_accounts": [
            {
                "account_ref": line.account_ref,
                "company_ref": scope.company_ref,
                "allowed_currencies": [scope.functional_currency],
                "active": True,
                "posting_allowed": True,
                "reconciliation_required": True,
            }
            for line in trial.lines
        ],
        "trial_balance_debits": trial.total_debit,
        "trial_balance_credits": trial.total_credit,
        "reconciliations": [
            {
                "reconciliation_ref": item.reconciliation_ref,
                "account_ref": item.account_ref,
                "company_ref": scope.company_ref,
                "period_ref": scope.fiscal_period_ref,
                "balance_as_of": _parsed_timestamp(scope.period_ended_at)
                .date()
                .isoformat(),
                "status": "complete",
                "unreconciled_amount": abs(item.unexplained_variance),
                "reviewed_by_ref": item.reviewed_by_ref,
                "completed_at": "2026-09-01T14:42:00Z",
                "evidence_refs": ["evidence:close-readiness:reconciliations"],
            }
            for item in reconciliations.account_reconciliations
        ],
        "consolidation": {
            "required": False,
            "currency_translation_status": "not_applicable",
            "intercompany_matching_status": "not_applicable",
            "elimination_status": "not_applicable",
        },
        "approval": {
            "required": True,
            "status": "approved",
            "prepared_by_ref": approval.review_prepared_by_ref,
            "approved_by_ref": approval.independent_approver_ref,
            "evidence_refs": ["evidence:close-readiness:period-status"],
        },
        "control_gates": [
            {
                "control_ref": "control:close-checklist-complete",
                "name": "Exact close checklist complete",
                "required": True,
                "status": "passed",
                "evaluated_by_ref": "controller:close-readiness",
                "evidence_refs": ["evidence:close-readiness:trial-balance"],
            }
        ],
        "evidence_refs": evidence,
    }


def _example_inputs() -> dict[str, Any]:
    approval_inputs = PrepareCloseApprovalTransitionCommandInput.model_validate(
        deepcopy(PrepareCloseApprovalTransitionCommandPrimitive.example_inputs)
    )
    approval_command = prepare_close_approval_transition_command(approval_inputs)
    lifecycle = materialize_period_close_candidate(approval_command.lifecycle_input)
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example approval transition was not materialized")
    workspace = approval_inputs.workspace
    snapshot = lifecycle.snapshot
    close_candidate_ref = "close-candidate:2026-08"
    close_request_ref = "close-request:2026-08"
    close_requested_at = "2026-09-01T14:48:00Z"
    close_operator_ref = "operator:hosted-close"
    readiness_input = PeriodCloseReadinessInput.model_validate(
        _readiness_payload(
            workspace=workspace,
            snapshot=snapshot,
            close_candidate_ref=close_candidate_ref,
        )
    )
    readiness_evaluation = evaluate_period_close_readiness(readiness_input)
    approval_transition_digest = snapshot.transition_history[6].transition_digest
    request_digest = close_period_request_digest(
        workspace=workspace,
        lifecycle_snapshot=snapshot,
        approval_transition_digest=approval_transition_digest,
        close_candidate_ref=close_candidate_ref,
        close_request_ref=close_request_ref,
        close_requested_at=close_requested_at,
        close_operator_ref=close_operator_ref,
        readiness_evaluation=readiness_evaluation,
    )
    return {
        "workspace": workspace.to_dict(),
        "lifecycle_snapshot": snapshot.to_dict(),
        "readiness_input": readiness_input.to_dict(),
        "readiness_observation": {
            "readiness_attestation_ref": "attestation:close-readiness:2026-08",
            "readiness_policy_ref": "policy:monthly-close-readiness:v1",
            "issuer_ref": workspace.close_scope.spring_authority_ref,
            "scope_digest": period_close_scope_digest(workspace.close_scope),
            "lifecycle_state_digest": snapshot.state_digest,
            "approval_transition_digest": approval_transition_digest,
            "close_candidate_ref": close_candidate_ref,
            "close_request_ref": close_request_ref,
            "close_request_digest": request_digest,
            "close_operator_ref": close_operator_ref,
            "readiness_evaluation_ref": readiness_evaluation.evaluation_ref,
            "readiness_operation_digest": readiness_evaluation.operation_digest,
            "readiness_evidence_digest": readiness_evaluation.evidence_digest,
            "readiness_evaluation_digest": readiness_evaluation.evaluation_digest,
            "observed_at": "2026-09-01T14:46:00Z",
            "expires_at": "2026-09-01T15:16:00Z",
        },
        "close_candidate_ref": close_candidate_ref,
        "close_request_ref": close_request_ref,
        "close_requested_at": close_requested_at,
        "close_operator_ref": close_operator_ref,
        "evidence_use_refs": (
            "evidence-use:close-request",
            "evidence-use:spring-close-readiness-attestation",
        ),
        "prepared_at": "2026-09-01T14:49:00Z",
    }


class PrepareClosePeriodPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareClosePeriodPackageInput,
        ClosePeriodPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_close_period_package"
    version = "1.0.0"
    title = "Prepare readiness-bound final close package candidate"
    description = (
        "Recompute deterministic close controls and bind their exact ready result, "
        "the retained approval transition, close request, operator, and Spring "
        "readiness observation without executing or persisting a period close."
    )
    input_model = PrepareClosePeriodPackageInput
    output_model = ClosePeriodPackageCandidateResult
    connector_tools = ()
    risk_level = "critical"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "connector_operations": 0,
            "provider_calls": 0,
            "period_closes": 0,
            "journal_posts": 0,
            "approval_consumptions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["readiness_evidence"] = (
            "exact approved snapshot, deterministic control evaluation, close request, "
            "operator, Spring observation, policy, evidence, and expiry commitment"
        )
        contract["authority_boundary"] = (
            "Spring must authenticate readiness, revalidate current operator RBAC, "
            "retain evidence, execute the hosted close, persist state, and admit the "
            "final lifecycle transition"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareClosePeriodPackageInput,
    ) -> PrimitiveExecutionResult[ClosePeriodPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="close_period_package_scope_mismatch",
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
        output = prepare_close_period_package(inputs)
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural final-close package candidate; Spring "
                "readiness authentication, operator authority, evidence, execution, "
                "persistence, and lifecycle authority remain required."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_period_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "close_candidate_ref": output.package.close_candidate_ref,
                        "close_request_digest": output.close_request_digest,
                        "readiness_evaluation_digest": (
                            output.readiness_evaluation.evaluation_digest
                        ),
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_period_package_candidate",
                    summary=(
                        "The exact approved state, ready control result, close request, "
                        "and Spring observation are content-bound without close authority."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_readiness_revalidation_required",
                        "hosted_close_execution_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_CLOSE_PERIOD_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareClosePeriodPackagePrimitive(),)


__all__ = [
    "CLOSE_PERIOD_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "CLOSE_PERIOD_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "CLOSE_READINESS_OBSERVATION_SCHEMA",
    "ClosePeriodPackageCandidateResult",
    "CloseReadinessObservation",
    "FINANCE_CLOSE_PERIOD_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareClosePeriodPackageInput",
    "PrepareClosePeriodPackagePrimitive",
    "close_period_request_digest",
    "prepare_close_period_package",
]
