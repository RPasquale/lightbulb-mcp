"""Prepare an evidence-bound ``approve_close`` transition command.

The primitive joins one close-approval package candidate to the exact retained
version-six period-close snapshot and two portable evidence claims. It derives
all lifecycle fences and command seals. Spring still owns current reviewer
qualification, approval authentication, expiry revalidation, single-use
consumption, evidence custody, persistence, and lifecycle admission. No close,
connector, provider, journal, approval, or persistence effect occurs here.
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

from lightbulb.finance_close_approval_package import (
    CloseApprovalObservation,
    CloseApprovalPackageCandidateResult,
    PrepareCloseApprovalPackageInput,
    PrepareCloseApprovalPackagePrimitive,
    prepare_close_approval_package,
)
from lightbulb.finance_close_lifecycle import (
    GENESIS_PERIOD_CLOSE_DIGEST,
    CloseApprovalPackage,
    CloseEvidenceEnvelope,
    PeriodCloseLifecycleInput,
    PeriodCloseLifecycleSnapshot,
    PeriodCloseTransitionCommand,
    period_close_command_content_digest,
    period_close_scope_digest,
    seal_period_close_command,
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

CLOSE_APPROVAL_TRANSITION_COMMAND_INPUT_SCHEMA = (
    "lightbulb.finance_close_approval_transition_command_input.v1"
)
CLOSE_APPROVAL_TRANSITION_COMMAND_RESULT_SCHEMA = (
    "lightbulb.finance_close_approval_transition_command_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_ARTIFACT_KIND = "close_review_workpaper"
_APPROVAL_KIND = "spring_close_approval_attestation"


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


class CloseReviewWorkpaperEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["close_review_workpaper"] = _ARTIFACT_KIND
    issuer_ref: OpaqueRef
    observed_at: str
    effective_at: str
    retained_until: str
    verification_grade: Literal["attested", "verified"] = "attested"
    classification: Literal["internal", "confidential", "restricted"] = "restricted"

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)


class SpringCloseApprovalEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["spring_close_approval_attestation"] = _APPROVAL_KIND
    issuer_ref: OpaqueRef
    observed_at: str
    effective_at: str
    retained_until: str
    verification_grade: Literal["verified"] = "verified"
    classification: Literal["internal", "confidential", "restricted"] = "restricted"
    approval_observation: CloseApprovalObservation

    @field_validator("approval_observation", mode="before")
    @classmethod
    def _detached_observation(cls, value: Any) -> Any:
        if isinstance(value, CloseApprovalObservation):
            return value
        if isinstance(value, dict):
            return CloseApprovalObservation.model_validate_json(
                json.dumps(value, default=str)
            )
        return value

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _observation_is_exact(self) -> "SpringCloseApprovalEvidenceClaim":
        observation = self.approval_observation
        if (
            self.issuer_ref != observation.issuer_ref
            or self.artifact_ref != observation.approval_decision_ref
            or self.artifact_digest != observation.evidence_digest()
        ):
            raise ValueError(
                "approval evidence must bind the exact typed decision observation"
            )
        return self


class PrepareCloseApprovalTransitionCommandInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_close_approval_transition_command_input.v1"
    ] = Field(default=CLOSE_APPROVAL_TRANSITION_COMMAND_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    package_candidate: CloseApprovalPackageCandidateResult
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    occurred_at: str
    requested_by_ref: OpaqueRef
    workpaper_evidence: CloseReviewWorkpaperEvidenceClaim
    approval_evidence: SpringCloseApprovalEvidenceClaim

    @field_validator(
        "workspace", "package_candidate", "lifecycle_snapshot", mode="before"
    )
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "package_candidate": CloseApprovalPackageCandidateResult,
            "lifecycle_snapshot": PeriodCloseLifecycleSnapshot,
        }[info.field_name]
        if isinstance(value, model_type):
            return value
        if isinstance(value, dict):
            return model_type.model_validate_json(json.dumps(value, default=str))
        return value

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _exact_sources_and_claims(
        self,
    ) -> "PrepareCloseApprovalTransitionCommandInput":
        workspace = self.workspace
        candidate = self.package_candidate
        snapshot = self.lifecycle_snapshot
        package = candidate.package
        scope = workspace.close_scope
        observation = self.approval_evidence.approval_observation
        if (
            candidate.workspace_ref != workspace.workspace_ref
            or candidate.workspace_revision != workspace.workspace_revision
            or candidate.workspace_digest != workspace.content_digest
        ):
            raise ValueError("package candidate must bind the exact close workspace")
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
        transition_by_field = {
            "trial_balance_transition_digest": snapshot.transition_history[1],
            "reconciliation_transition_digest": snapshot.transition_history[2],
            "adjustment_transition_digest": snapshot.transition_history[3],
            "lock_transition_digest": snapshot.transition_history[4],
            "consolidation_transition_digest": snapshot.transition_history[5],
        }
        if (
            candidate.lifecycle_state_digest != snapshot.state_digest
            or candidate.consolidation_transition_digest
            != snapshot.transition_history[5].transition_digest
            or any(
                getattr(package, field) != transition.transition_digest
                for field, transition in transition_by_field.items()
            )
            or candidate.approval_request_digest != package.approval_request_digest
            or candidate.approval_observation_digest
            != package.approval_observation_digest
        ):
            raise ValueError(
                "package candidate must bind the exact retained lifecycle state"
            )
        evidence = (self.workpaper_evidence, self.approval_evidence)
        if (
            tuple(sorted(item.use_ref for item in evidence))
            != package.evidence_use_refs
        ):
            raise ValueError("evidence claims must consume the exact package use refs")
        if (
            len({item.artifact_ref for item in evidence}) != 2
            or len({item.evidence_ref for item in evidence}) != 2
        ):
            raise ValueError(
                "artifact and portable evidence references must be distinct"
            )
        if len({item.artifact_digest for item in evidence}) != 2:
            raise ValueError("workpaper and approval evidence digests must be distinct")
        if (
            self.workpaper_evidence.artifact_ref != package.review_workpaper_ref
            or self.workpaper_evidence.artifact_digest
            != package.review_workpaper_digest
        ):
            raise ValueError(
                "close-review evidence must bind the exact retained workpaper"
            )
        if self.workpaper_evidence.issuer_ref not in (
            scope.authorized_evidence_issuer_refs
        ):
            raise ValueError("close-review workpaper issuer is not scoped")
        if (
            self.approval_evidence.artifact_ref != package.approval_decision_ref
            or self.approval_evidence.artifact_digest
            != package.approval_observation_digest
            or observation.approval_candidate_ref != package.approval_candidate_ref
            or observation.approval_decision_ref != package.approval_decision_ref
            or observation.approval_policy_ref != package.approval_policy_ref
            or observation.reviewer_qualification_ref
            != package.reviewer_qualification_ref
            or observation.approval_request_digest != package.approval_request_digest
            or observation.evidence_digest() != package.approval_observation_digest
            or observation.decided_at != package.approved_at
            or observation.expires_at != package.approval_expires_at
            or observation.independent_approver_ref != package.independent_approver_ref
        ):
            raise ValueError(
                "approval evidence must bind the exact retained decision observation"
            )
        if self.approval_evidence.issuer_ref != scope.spring_authority_ref:
            raise ValueError(
                "approval attestation must be issued by exact Spring authority"
            )
        if (
            observation.scope_digest != period_close_scope_digest(scope)
            or observation.lifecycle_state_digest != snapshot.state_digest
            or observation.consolidation_transition_digest
            != snapshot.transition_history[5].transition_digest
        ):
            raise ValueError(
                "approval observation must bind the exact retained scope and state"
            )
        if self.requested_by_ref == package.independent_approver_ref:
            raise ValueError(
                "requester must be separate from independent close approver"
            )
        occurred = _parsed_timestamp(self.occurred_at)
        if occurred < _parsed_timestamp(candidate.prepared_at):
            raise ValueError("approval transition cannot precede package preparation")
        if occurred >= _parsed_timestamp(package.approval_expires_at):
            raise ValueError("close approval is expired at transition preparation")
        return self


class CloseApprovalTransitionCommandResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_close_approval_transition_command_result.v1"
    ] = Field(default=CLOSE_APPROVAL_TRANSITION_COMMAND_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    package_candidate_digest: Sha256Digest
    lifecycle_version: Literal[6] = 6
    lifecycle_state_digest: Sha256Digest
    approval_candidate_ref: OpaqueRef
    approval_request_digest: Sha256Digest
    approval_observation_digest: Sha256Digest
    approval_expires_at: str
    lifecycle_input: PeriodCloseLifecycleInput
    command_content_digest: Sha256Digest
    command_request_digest: Sha256Digest
    evidence_lineage_tail_digest: Sha256Digest
    result_digest: Sha256Digest = _ZERO_DIGEST
    approval_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    reviewer_qualification_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    approval_consumption_state: Literal["spring_consumption_required"] = (
        "spring_consumption_required"
    )
    evidence_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False
    period_close_authorized: Literal[False] = False
    connector_calls_authorized: Literal[False] = False

    @field_validator("approval_expires_at")
    @classmethod
    def _approval_expires_at(cls, value: str) -> str:
        return _timestamp(value, field_name="approval_expires_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_result(self) -> "CloseApprovalTransitionCommandResult":
        command = self.lifecycle_input.command
        package = command.package
        if (
            self.lifecycle_input.snapshot is None
            or self.lifecycle_input.snapshot.version != self.lifecycle_version
            or self.lifecycle_input.snapshot.state_digest != self.lifecycle_state_digest
            or command.kind != "approve_close"
            or not isinstance(package, CloseApprovalPackage)
            or command.expected_version != self.lifecycle_version
            or command.expected_state_digest != self.lifecycle_state_digest
            or self.approval_candidate_ref != package.approval_candidate_ref
            or self.approval_request_digest != package.approval_request_digest
            or self.approval_observation_digest != package.approval_observation_digest
            or self.approval_expires_at != package.approval_expires_at
            or self.command_content_digest
            != period_close_command_content_digest(command)
            or self.command_request_digest != command.request_digest
            or self.evidence_lineage_tail_digest != command.evidence[-1].lineage_digest
            or command.evidence[0].artifact_ref != package.review_workpaper_ref
            or command.evidence[0].artifact_digest != package.review_workpaper_digest
            or command.evidence[1].artifact_ref != package.approval_decision_ref
            or command.evidence[1].artifact_digest
            != package.approval_observation_digest
        ):
            raise ValueError("result does not bind the exact sealed transition command")
        expected = _stable_digest(self.digest_payload())
        if self.result_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("result_digest does not match transition evidence")
        object.__setattr__(self, "result_digest", expected)
        return self


def _evidence_envelope(
    *,
    sequence: int,
    claim: CloseReviewWorkpaperEvidenceClaim | SpringCloseApprovalEvidenceClaim,
    transition_ref: str,
    workspace: FinanceCloseWorkspace,
) -> dict[str, Any]:
    scope = workspace.close_scope
    return CloseEvidenceEnvelope(
        sequence=sequence,
        use_ref=claim.use_ref,
        artifact_ref=claim.artifact_ref,
        artifact_digest=claim.artifact_digest,
        predecessor_lineage_digest=GENESIS_PERIOD_CLOSE_DIGEST,
        lineage_digest=GENESIS_PERIOD_CLOSE_DIGEST,
        custody_ref=scope.evidence_custody_ref,
        retained_until=claim.retained_until,
        reference={
            "evidence_ref": claim.evidence_ref,
            "kind": claim.kind,
            "issuer_ref": claim.issuer_ref,
            "subject_ref": transition_ref,
            "sha256": GENESIS_PERIOD_CLOSE_DIGEST,
            "observed_at": claim.observed_at,
            "effective_at": claim.effective_at,
            "verification_grade": claim.verification_grade,
            "classification": claim.classification,
            "retention_policy": scope.financial_retention_policy_ref,
            "jurisdiction": scope.jurisdiction_ref,
        },
    ).to_dict()


def prepare_close_approval_transition_command(
    inputs: PrepareCloseApprovalTransitionCommandInput,
) -> CloseApprovalTransitionCommandResult:
    workspace = inputs.workspace
    candidate = inputs.package_candidate
    snapshot = inputs.lifecycle_snapshot
    package = candidate.package
    raw_command = {
        "kind": "approve_close",
        "scope": workspace.close_scope.to_dict(),
        "transition_ref": inputs.transition_ref,
        "idempotency_key": inputs.idempotency_key,
        "expected_version": snapshot.version,
        "expected_state_digest": snapshot.state_digest,
        "expected_evidence_lineage_digest": snapshot.evidence_lineage_digest,
        "occurred_at": inputs.occurred_at,
        "host_outcome_report": "reported_certain",
        "requested_by_ref": inputs.requested_by_ref,
        "evidence_custody_ref": workspace.close_scope.evidence_custody_ref,
        "evidence": [
            _evidence_envelope(
                sequence=1,
                claim=inputs.workpaper_evidence,
                transition_ref=inputs.transition_ref,
                workspace=workspace,
            ),
            _evidence_envelope(
                sequence=2,
                claim=inputs.approval_evidence,
                transition_ref=inputs.transition_ref,
                workspace=workspace,
            ),
        ],
        "package": package.to_dict(),
    }
    command = PeriodCloseTransitionCommand.model_validate(
        seal_period_close_command(raw_command)
    )
    lifecycle_input = PeriodCloseLifecycleInput(
        scope=workspace.close_scope,
        snapshot=snapshot,
        command=command,
    )
    return CloseApprovalTransitionCommandResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        package_candidate_digest=candidate.candidate_digest,
        lifecycle_state_digest=snapshot.state_digest,
        approval_candidate_ref=package.approval_candidate_ref,
        approval_request_digest=package.approval_request_digest,
        approval_observation_digest=package.approval_observation_digest,
        approval_expires_at=package.approval_expires_at,
        lifecycle_input=lifecycle_input,
        command_content_digest=period_close_command_content_digest(command),
        command_request_digest=command.request_digest,
        evidence_lineage_tail_digest=command.evidence[-1].lineage_digest,
    )


def _example_inputs() -> dict[str, Any]:
    package_inputs = PrepareCloseApprovalPackageInput.model_validate(
        deepcopy(PrepareCloseApprovalPackagePrimitive.example_inputs)
    )
    package_candidate = prepare_close_approval_package(package_inputs)
    workspace = package_inputs.workspace
    package = package_candidate.package
    return {
        "workspace": workspace.to_dict(),
        "package_candidate": package_candidate.to_dict(),
        "lifecycle_snapshot": package_inputs.lifecycle_snapshot.to_dict(),
        "transition_ref": "transition:example:approve-close",
        "idempotency_key": "idempotency:example:approve-close",
        "occurred_at": "2026-09-01T14:40:00Z",
        "requested_by_ref": "controller:close-review-preparer",
        "workpaper_evidence": {
            "use_ref": "evidence-use:close-review-workpaper",
            "artifact_ref": package.review_workpaper_ref,
            "artifact_digest": package.review_workpaper_digest,
            "evidence_ref": "evidence:example:close-review-workpaper",
            "issuer_ref": "controller:independent-review",
            "observed_at": "2026-09-01T14:33:00Z",
            "effective_at": "2026-09-01T14:32:00Z",
            "retained_until": workspace.close_scope.evidence_retention_until,
        },
        "approval_evidence": {
            "use_ref": "evidence-use:spring-close-approval-attestation",
            "artifact_ref": package.approval_decision_ref,
            "artifact_digest": package.approval_observation_digest,
            "evidence_ref": "evidence:example:spring-close-approval-attestation",
            "issuer_ref": workspace.close_scope.spring_authority_ref,
            "observed_at": "2026-09-01T14:35:00Z",
            "effective_at": "2026-09-01T14:34:00Z",
            "retained_until": workspace.close_scope.evidence_retention_until,
            "approval_observation": package_inputs.approval_observation.to_dict(),
        },
    }


class PrepareCloseApprovalTransitionCommandPrimitive(
    BusinessProcessPrimitive[
        PrepareCloseApprovalTransitionCommandInput,
        CloseApprovalTransitionCommandResult,
    ]
):
    primitive_ref = "finance.prepare_close_approval_transition_command"
    version = "1.0.0"
    title = "Prepare evidence-bound close-approval transition command"
    description = (
        "Bind an exact independent close-approval package, retained version-six "
        "snapshot, review workpaper, and Spring approval attestation into a sealed "
        "command without consuming approval or advancing the lifecycle."
    )
    input_model = PrepareCloseApprovalTransitionCommandInput
    output_model = CloseApprovalTransitionCommandResult
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
            "journal_posts": 0,
            "approval_decisions": 0,
            "approval_consumptions": 0,
            "period_closes": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["derived_fences"] = (
            "snapshot version, state digest, evidence lineage, scope, package, "
            "approval request, observation, expiry, and command content digest"
        )
        contract["authority_boundary"] = (
            "Spring must revalidate reviewer qualification and RBAC, authenticate "
            "the unexpired approval, consume it once, retain evidence, and admit "
            "the exact lifecycle transition."
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareCloseApprovalTransitionCommandInput,
    ) -> PrimitiveExecutionResult[CloseApprovalTransitionCommandResult]:
        scope = inputs.workspace.close_scope
        if (
            context.scope.tenant_ref != scope.tenant_ref
            or context.scope.company_ref != scope.company_ref
            or context.scope.project_ref != scope.project_ref
            or context.scope.project_id != scope.project_id
            or context.scope.actor_ref != inputs.requested_by_ref
            or context.idempotency_key != inputs.idempotency_key
        ):
            blocker = PrimitiveBlocker(
                code="close_approval_transition_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, actor, and idempotency identity "
                    "must exactly match the close-approval transition request."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = prepare_close_approval_transition_command(inputs)
        command = output.lifecycle_input.command
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a sealed approve-close command candidate; Spring approval "
                "authentication, consumption, evidence, and lifecycle authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_approval_transition_command_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "transition_ref": command.transition_ref,
                        "approval_candidate_ref": output.approval_candidate_ref,
                        "approval_request_digest": output.approval_request_digest,
                        "package_candidate_digest": output.package_candidate_digest,
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_approval_transition_command_candidate",
                    summary=(
                        "The command is sealed to exact review, approval, state, and "
                        "lineage evidence; Spring retains all approval authority."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_approval_revalidation_required",
                        "spring_single_use_consumption_required",
                    ],
                    refs={
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
        )


FINANCE_CLOSE_APPROVAL_TRANSITION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareCloseApprovalTransitionCommandPrimitive(),)


__all__ = [
    "CLOSE_APPROVAL_TRANSITION_COMMAND_INPUT_SCHEMA",
    "CLOSE_APPROVAL_TRANSITION_COMMAND_RESULT_SCHEMA",
    "CloseApprovalTransitionCommandResult",
    "CloseReviewWorkpaperEvidenceClaim",
    "FINANCE_CLOSE_APPROVAL_TRANSITION_EXECUTABLE_PRIMITIVES",
    "PrepareCloseApprovalTransitionCommandInput",
    "PrepareCloseApprovalTransitionCommandPrimitive",
    "SpringCloseApprovalEvidenceClaim",
    "prepare_close_approval_transition_command",
]
