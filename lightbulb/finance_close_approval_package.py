"""Prepare an independently reviewed period-close approval package candidate.

The primitive binds a Spring-reported approval observation and exact review
workpaper commitment to the retained version-six close snapshot. It derives all
five prerequisite transition digests and the approval request digest instead of
accepting lifecycle fences from a caller. Spring still owns reviewer
qualification, delegation, current RBAC, approval authentication, single-use
consumption, evidence custody, persistence, and lifecycle admission. No close,
connector, provider, journal, or approval effect occurs here.
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

from lightbulb.finance_close_lifecycle import (
    CloseApprovalPackage,
    PeriodCloseLifecycleSnapshot,
    materialize_period_close_candidate,
    period_close_scope_digest,
)
from lightbulb.finance_close_workspace import FinanceCloseWorkspace
from lightbulb.finance_consolidation_transition import (
    PrepareConsolidationTransitionCommandInput,
    PrepareConsolidationTransitionCommandPrimitive,
    prepare_consolidation_transition_command,
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

CLOSE_APPROVAL_PACKAGE_CANDIDATE_INPUT_SCHEMA = (
    "lightbulb.finance_close_approval_package_candidate_input.v1"
)
CLOSE_APPROVAL_PACKAGE_CANDIDATE_RESULT_SCHEMA = (
    "lightbulb.finance_close_approval_package_candidate_result.v1"
)
CLOSE_APPROVAL_OBSERVATION_SCHEMA = "lightbulb.finance_close_approval_observation.v1"

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


def _retained_actor_refs(snapshot: PeriodCloseLifecycleSnapshot) -> set[str]:
    refs = {record.command.requested_by_ref for record in snapshot.transition_history}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and (
                    key.endswith("_by_ref")
                    or key.endswith("_approver_ref")
                    or key.endswith("_reviewer_ref")
                    or key.endswith("_owner_ref")
                    or key == "consolidator_ref"
                ):
                    refs.add(item)
                else:
                    visit(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                visit(item)

    for record in snapshot.transition_history:
        visit(record.command.package.to_dict())
    return refs


def close_approval_request_digest(
    *,
    workspace: FinanceCloseWorkspace,
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot,
    consolidation_transition_digest: str,
    approval_candidate_ref: str,
    review_workpaper_ref: str,
    review_workpaper_digest: str,
    review_prepared_by_ref: str,
    independent_approver_ref: str,
    approval_policy_ref: str,
) -> str:
    return _stable_digest(
        {
            "schema": "lightbulb.finance_close_approval_request.v1",
            "workspace_ref": workspace.workspace_ref,
            "workspace_revision": workspace.workspace_revision,
            "workspace_digest": workspace.content_digest,
            "scope_digest": period_close_scope_digest(workspace.close_scope),
            "lifecycle_version": lifecycle_snapshot.version,
            "lifecycle_state_digest": lifecycle_snapshot.state_digest,
            "consolidation_transition_digest": consolidation_transition_digest,
            "approval_candidate_ref": approval_candidate_ref,
            "review_workpaper_ref": review_workpaper_ref,
            "review_workpaper_digest": review_workpaper_digest,
            "review_prepared_by_ref": review_prepared_by_ref,
            "independent_approver_ref": independent_approver_ref,
            "approval_policy_ref": approval_policy_ref,
        }
    )


class CloseApprovalObservation(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_approval_observation.v1"] = Field(
        default=CLOSE_APPROVAL_OBSERVATION_SCHEMA,
        alias="schema",
    )
    approval_candidate_ref: OpaqueRef
    approval_decision_ref: OpaqueRef
    approval_policy_ref: OpaqueRef
    reviewer_qualification_ref: OpaqueRef
    issuer_ref: OpaqueRef
    scope_digest: Sha256Digest
    lifecycle_state_digest: Sha256Digest
    consolidation_transition_digest: Sha256Digest
    approval_request_digest: Sha256Digest
    decision: Literal["reported_approved"] = "reported_approved"
    unresolved_material_exception_count: Literal[0] = 0
    decided_at: str
    expires_at: str
    independent_approver_ref: OpaqueRef

    @field_validator("decided_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _approval_window_is_positive(self) -> "CloseApprovalObservation":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.decided_at):
            raise ValueError("close approval must expire after its decision")
        return self

    def evidence_digest(self) -> str:
        return _stable_digest(self.to_dict())


class PrepareCloseApprovalPackageInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_close_approval_package_candidate_input.v1"
    ] = Field(default=CLOSE_APPROVAL_PACKAGE_CANDIDATE_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    review_workpaper_ref: OpaqueRef
    review_workpaper_digest: Sha256Digest
    evidence_use_refs: tuple[OpaqueRef, OpaqueRef]
    review_prepared_by_ref: OpaqueRef
    approval_observation: CloseApprovalObservation
    prepared_at: str

    @field_validator("workspace", "lifecycle_snapshot", mode="before")
    @classmethod
    def _detached_sources(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
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

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at(cls, value: str) -> str:
        return _timestamp(value, field_name="prepared_at")

    @model_validator(mode="after")
    def _exact_consolidated_sources(self) -> "PrepareCloseApprovalPackageInput":
        workspace = self.workspace
        snapshot = self.lifecycle_snapshot
        observation = self.approval_observation
        scope = workspace.close_scope
        if (
            snapshot.scope != scope
            or snapshot.version != 6
            or snapshot.status != "consolidation_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
            or snapshot.adjusting_entries is None
            or snapshot.subledger_locks is None
            or snapshot.consolidation is None
            or snapshot.close_approval is not None
        ):
            raise ValueError("the exact retained consolidation snapshot is required")
        if (
            tuple(sorted(self.evidence_use_refs)) != self.evidence_use_refs
            or len(set(self.evidence_use_refs)) != 2
        ):
            raise ValueError(
                "exactly two canonical evidence use references are required"
            )
        consolidation_transition = snapshot.transition_history[5]
        if consolidation_transition.command.kind != "consolidate":
            raise ValueError("retained consolidation transition has invalid kind")
        if observation.issuer_ref != scope.spring_authority_ref:
            raise ValueError("close approval must be issued by exact Spring authority")
        if observation.scope_digest != period_close_scope_digest(scope):
            raise ValueError("close approval must bind the exact lifecycle scope")
        if observation.lifecycle_state_digest != snapshot.state_digest:
            raise ValueError("close approval must bind the exact retained state")
        if (
            observation.consolidation_transition_digest
            != consolidation_transition.transition_digest
        ):
            raise ValueError("close approval must bind exact consolidation evidence")
        expected_request_digest = close_approval_request_digest(
            workspace=workspace,
            lifecycle_snapshot=snapshot,
            consolidation_transition_digest=consolidation_transition.transition_digest,
            approval_candidate_ref=observation.approval_candidate_ref,
            review_workpaper_ref=self.review_workpaper_ref,
            review_workpaper_digest=self.review_workpaper_digest,
            review_prepared_by_ref=self.review_prepared_by_ref,
            independent_approver_ref=observation.independent_approver_ref,
            approval_policy_ref=observation.approval_policy_ref,
        )
        if observation.approval_request_digest != expected_request_digest:
            raise ValueError(
                "close approval must bind the exact review request content"
            )
        if self.review_prepared_by_ref == observation.independent_approver_ref:
            raise ValueError("close reviewer and independent approver must be distinct")
        if observation.independent_approver_ref in _retained_actor_refs(snapshot):
            raise ValueError(
                "independent close approver cannot be a retained lifecycle actor"
            )
        consolidation_time = _parsed_timestamp(snapshot.consolidation.consolidated_at)
        decision_time = _parsed_timestamp(observation.decided_at)
        prepared_time = _parsed_timestamp(self.prepared_at)
        expiry_time = _parsed_timestamp(observation.expires_at)
        if decision_time < consolidation_time:
            raise ValueError("close approval cannot precede consolidation")
        if prepared_time < decision_time:
            raise ValueError("approval package cannot precede the approval decision")
        if prepared_time >= expiry_time:
            raise ValueError("close approval is expired at package preparation")
        return self


class CloseApprovalPackageCandidateResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_close_approval_package_candidate_result.v1"
    ] = Field(default=CLOSE_APPROVAL_PACKAGE_CANDIDATE_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    lifecycle_version: Literal[6] = 6
    lifecycle_state_digest: Sha256Digest
    consolidation_transition_digest: Sha256Digest
    approval_request_digest: Sha256Digest
    prepared_at: str
    package: CloseApprovalPackage
    package_digest: Sha256Digest
    review_workpaper_digest: Sha256Digest
    approval_observation_digest: Sha256Digest
    candidate_digest: Sha256Digest = _ZERO_DIGEST
    approval_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    reviewer_qualification_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    approval_consumption_state: Literal["spring_consumption_required"] = (
        "spring_consumption_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    close_approval_package_authority: Literal[False] = False
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False

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
    def _sealed_candidate(self) -> "CloseApprovalPackageCandidateResult":
        if self.package_digest != _stable_digest(self.package.to_dict()):
            raise ValueError(
                "package_digest must commit the exact close approval package"
            )
        expected = _stable_digest(self.digest_payload())
        if self.candidate_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("candidate_digest does not match close approval evidence")
        object.__setattr__(self, "candidate_digest", expected)
        return self


def prepare_close_approval_package(
    inputs: PrepareCloseApprovalPackageInput,
) -> CloseApprovalPackageCandidateResult:
    workspace = inputs.workspace
    snapshot = inputs.lifecycle_snapshot
    observation = inputs.approval_observation
    trial_transition = snapshot.transition_history[1]
    reconciliation_transition = snapshot.transition_history[2]
    adjustment_transition = snapshot.transition_history[3]
    lock_transition = snapshot.transition_history[4]
    consolidation_transition = snapshot.transition_history[5]
    package = CloseApprovalPackage(
        evidence_use_refs=inputs.evidence_use_refs,
        approval_candidate_ref=observation.approval_candidate_ref,
        approval_decision_ref=observation.approval_decision_ref,
        approval_policy_ref=observation.approval_policy_ref,
        reviewer_qualification_ref=observation.reviewer_qualification_ref,
        approval_request_digest=observation.approval_request_digest,
        approval_observation_digest=observation.evidence_digest(),
        review_workpaper_ref=inputs.review_workpaper_ref,
        review_workpaper_digest=inputs.review_workpaper_digest,
        trial_balance_transition_digest=trial_transition.transition_digest,
        reconciliation_transition_digest=reconciliation_transition.transition_digest,
        adjustment_transition_digest=adjustment_transition.transition_digest,
        lock_transition_digest=lock_transition.transition_digest,
        consolidation_transition_digest=consolidation_transition.transition_digest,
        approved_at=observation.decided_at,
        approval_expires_at=observation.expires_at,
        review_prepared_by_ref=inputs.review_prepared_by_ref,
        independent_approver_ref=observation.independent_approver_ref,
    )
    return CloseApprovalPackageCandidateResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        lifecycle_state_digest=snapshot.state_digest,
        consolidation_transition_digest=consolidation_transition.transition_digest,
        approval_request_digest=observation.approval_request_digest,
        prepared_at=inputs.prepared_at,
        package=package,
        package_digest=_stable_digest(package.to_dict()),
        review_workpaper_digest=inputs.review_workpaper_digest,
        approval_observation_digest=observation.evidence_digest(),
    )


def _example_inputs() -> dict[str, Any]:
    consolidation_inputs = PrepareConsolidationTransitionCommandInput.model_validate(
        deepcopy(PrepareConsolidationTransitionCommandPrimitive.example_inputs)
    )
    consolidation_command = prepare_consolidation_transition_command(
        consolidation_inputs
    )
    lifecycle = materialize_period_close_candidate(
        consolidation_command.lifecycle_input
    )
    if lifecycle.snapshot is None:  # pragma: no cover - invariant guard
        raise RuntimeError("example consolidation transition was not materialized")
    workspace = consolidation_inputs.workspace
    snapshot = lifecycle.snapshot
    consolidation_digest = snapshot.transition_history[5].transition_digest
    review_workpaper_ref = "close-review-workpaper:2026-08"
    review_workpaper_digest = _stable_digest(
        {
            "workspace_digest": workspace.content_digest,
            "lifecycle_state_digest": snapshot.state_digest,
            "consolidation_transition_digest": consolidation_digest,
            "unresolved_material_exception_count": 0,
        }
    )
    review_preparer = "controller:close-review-preparer"
    independent_approver = "officer:independent-close-approver"
    approval_policy_ref = "policy:independent-monthly-close:v1"
    approval_candidate_ref = "close-approval-candidate:2026-08"
    request_digest = close_approval_request_digest(
        workspace=workspace,
        lifecycle_snapshot=snapshot,
        consolidation_transition_digest=consolidation_digest,
        approval_candidate_ref=approval_candidate_ref,
        review_workpaper_ref=review_workpaper_ref,
        review_workpaper_digest=review_workpaper_digest,
        review_prepared_by_ref=review_preparer,
        independent_approver_ref=independent_approver,
        approval_policy_ref=approval_policy_ref,
    )
    return {
        "workspace": workspace.to_dict(),
        "lifecycle_snapshot": snapshot.to_dict(),
        "review_workpaper_ref": review_workpaper_ref,
        "review_workpaper_digest": review_workpaper_digest,
        "evidence_use_refs": (
            "evidence-use:close-review-workpaper",
            "evidence-use:spring-close-approval-attestation",
        ),
        "review_prepared_by_ref": review_preparer,
        "approval_observation": {
            "approval_candidate_ref": approval_candidate_ref,
            "approval_decision_ref": "decision:close-approval:2026-08",
            "approval_policy_ref": approval_policy_ref,
            "reviewer_qualification_ref": "qualification:close-approver:2026-08",
            "issuer_ref": workspace.close_scope.spring_authority_ref,
            "scope_digest": period_close_scope_digest(workspace.close_scope),
            "lifecycle_state_digest": snapshot.state_digest,
            "consolidation_transition_digest": consolidation_digest,
            "approval_request_digest": request_digest,
            "decided_at": "2026-09-01T14:30:00Z",
            "expires_at": "2026-09-01T15:30:00Z",
            "independent_approver_ref": independent_approver,
        },
        "prepared_at": "2026-09-01T14:32:00Z",
    }


class PrepareCloseApprovalPackagePrimitive(
    BusinessProcessPrimitive[
        PrepareCloseApprovalPackageInput,
        CloseApprovalPackageCandidateResult,
    ]
):
    primitive_ref = "finance.prepare_close_approval_package"
    version = "1.0.0"
    title = "Prepare independent close-approval package candidate"
    description = (
        "Bind an exact close-review workpaper and Spring-reported independent approval "
        "to every retained prerequisite transition without authenticating or consuming "
        "the approval or advancing period close."
    )
    input_model = PrepareCloseApprovalPackageInput
    output_model = CloseApprovalPackageCandidateResult
    connector_tools = ()
    risk_level = "high"
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
            "approval_decisions": 0,
            "approval_consumptions": 0,
            "ledger_closes": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["approval_evidence"] = (
            "exact scope, state, prerequisite transitions, review workpaper, policy, "
            "reviewer qualification, decision window, and independent actor commitment; "
            "Spring authentication and single-use consumption remain required"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareCloseApprovalPackageInput,
    ) -> PrimitiveExecutionResult[CloseApprovalPackageCandidateResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
        ):
            blocker = PrimitiveBlocker(
                code="close_approval_package_scope_mismatch",
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
        output = prepare_close_approval_package(inputs)
        observation = inputs.approval_observation
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a structural close-approval package candidate; Spring "
                "qualification, authentication, consumption, evidence, and lifecycle "
                "authority remain required."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_approval_package_candidate_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "approval_candidate_ref": output.package.approval_candidate_ref,
                        "approval_policy_ref": observation.approval_policy_ref,
                        "approval_request_digest": output.approval_request_digest,
                        "package_digest": output.package_digest,
                        "candidate_digest": output.candidate_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_approval_package_candidate",
                    summary=(
                        "The exact review request and independent approval observation "
                        "are content-bound to all retained close prerequisites."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_approval_revalidation_required",
                        "spring_single_use_consumption_required",
                    ],
                    refs={"candidate_digest": output.candidate_digest},
                )
            ],
        )


FINANCE_CLOSE_APPROVAL_PACKAGE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareCloseApprovalPackagePrimitive(),)


__all__ = [
    "CLOSE_APPROVAL_OBSERVATION_SCHEMA",
    "CLOSE_APPROVAL_PACKAGE_CANDIDATE_INPUT_SCHEMA",
    "CLOSE_APPROVAL_PACKAGE_CANDIDATE_RESULT_SCHEMA",
    "CloseApprovalObservation",
    "CloseApprovalPackageCandidateResult",
    "FINANCE_CLOSE_APPROVAL_PACKAGE_EXECUTABLE_PRIMITIVES",
    "PrepareCloseApprovalPackageInput",
    "PrepareCloseApprovalPackagePrimitive",
    "close_approval_request_digest",
    "prepare_close_approval_package",
]
