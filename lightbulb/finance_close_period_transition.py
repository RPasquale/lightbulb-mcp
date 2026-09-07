"""Prepare an evidence-bound final ``close_period`` transition command.

The primitive joins one readiness-bound close package to the exact retained
version-seven snapshot, close-request evidence, and a typed Spring readiness
observation. It derives every lifecycle fence and command seal. Spring still
owns current operator RBAC, attestation authentication and expiry revalidation,
evidence custody, hosted close execution, persistence, and lifecycle admission.
No close, connector, provider, journal, approval, or persistence effect occurs
here.
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
    GENESIS_PERIOD_CLOSE_DIGEST,
    CloseEvidenceEnvelope,
    ClosePeriodPackage,
    PeriodCloseLifecycleInput,
    PeriodCloseLifecycleSnapshot,
    PeriodCloseTransitionCommand,
    period_close_command_content_digest,
    period_close_scope_digest,
    seal_period_close_command,
)
from lightbulb.finance_close_period_package import (
    ClosePeriodPackageCandidateResult,
    CloseReadinessObservation,
    PrepareClosePeriodPackageInput,
    PrepareClosePeriodPackagePrimitive,
    prepare_close_period_package,
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

CLOSE_PERIOD_TRANSITION_COMMAND_INPUT_SCHEMA = (
    "lightbulb.finance_close_period_transition_command_input.v1"
)
CLOSE_PERIOD_TRANSITION_COMMAND_RESULT_SCHEMA = (
    "lightbulb.finance_close_period_transition_command_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_REQUEST_KIND = "close_request"
_READINESS_KIND = "spring_close_readiness_attestation"


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


class CloseRequestEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["close_request"] = _REQUEST_KIND
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


class SpringCloseReadinessEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["spring_close_readiness_attestation"] = _READINESS_KIND
    issuer_ref: OpaqueRef
    observed_at: str
    effective_at: str
    retained_until: str
    verification_grade: Literal["verified"] = "verified"
    classification: Literal["internal", "confidential", "restricted"] = "restricted"
    readiness_observation: CloseReadinessObservation

    @field_validator("readiness_observation", mode="before")
    @classmethod
    def _detached_observation(cls, value: Any) -> Any:
        if isinstance(value, CloseReadinessObservation):
            return value
        if isinstance(value, dict):
            return CloseReadinessObservation.model_validate_json(
                json.dumps(value, default=str)
            )
        return value

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _observation_is_exact(self) -> "SpringCloseReadinessEvidenceClaim":
        observation = self.readiness_observation
        if (
            self.issuer_ref != observation.issuer_ref
            or self.artifact_ref != observation.readiness_attestation_ref
            or self.artifact_digest != observation.evidence_digest()
        ):
            raise ValueError(
                "readiness evidence must bind the exact typed Spring observation"
            )
        return self


class PrepareClosePeriodTransitionCommandInput(_StrictModel):
    schema_id: Literal["lightbulb.finance_close_period_transition_command_input.v1"] = (
        Field(default=CLOSE_PERIOD_TRANSITION_COMMAND_INPUT_SCHEMA, alias="schema")
    )
    workspace: FinanceCloseWorkspace
    package_candidate: ClosePeriodPackageCandidateResult
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    occurred_at: str
    requested_by_ref: OpaqueRef
    close_request_evidence: CloseRequestEvidenceClaim
    readiness_evidence: SpringCloseReadinessEvidenceClaim

    @field_validator(
        "workspace", "package_candidate", "lifecycle_snapshot", mode="before"
    )
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "package_candidate": ClosePeriodPackageCandidateResult,
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
    ) -> "PrepareClosePeriodTransitionCommandInput":
        workspace = self.workspace
        candidate = self.package_candidate
        snapshot = self.lifecycle_snapshot
        package = candidate.package
        scope = workspace.close_scope
        observation = self.readiness_evidence.readiness_observation
        if (
            candidate.workspace_ref != workspace.workspace_ref
            or candidate.workspace_revision != workspace.workspace_revision
            or candidate.workspace_digest != workspace.content_digest
        ):
            raise ValueError("close package candidate must bind the exact workspace")
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
        approval_transition = snapshot.transition_history[6]
        if (
            candidate.lifecycle_state_digest != snapshot.state_digest
            or candidate.approval_transition_digest
            != approval_transition.transition_digest
            or package.approval_transition_digest
            != approval_transition.transition_digest
            or package.approval_candidate_ref
            != snapshot.close_approval.approval_candidate_ref
        ):
            raise ValueError(
                "close package candidate must bind the exact approved lifecycle state"
            )
        evidence = (self.close_request_evidence, self.readiness_evidence)
        if (
            tuple(sorted(item.use_ref for item in evidence))
            != package.evidence_use_refs
        ):
            raise ValueError("evidence claims must consume the exact package use refs")
        if (
            len({item.artifact_ref for item in evidence}) != 2
            or len({item.evidence_ref for item in evidence}) != 2
            or len({item.artifact_digest for item in evidence}) != 2
        ):
            raise ValueError(
                "close request and readiness evidence identities must be distinct"
            )
        if (
            self.close_request_evidence.artifact_ref != package.close_request_ref
            or self.close_request_evidence.artifact_digest
            != package.close_request_digest
        ):
            raise ValueError(
                "close-request evidence must bind the exact retained request"
            )
        if self.close_request_evidence.issuer_ref not in (
            scope.authorized_evidence_issuer_refs
        ):
            raise ValueError("close-request evidence issuer is not scoped")
        if (
            self.readiness_evidence.artifact_ref != package.readiness_attestation_ref
            or self.readiness_evidence.artifact_digest
            != package.readiness_observation_digest
            or observation.evidence_digest() != package.readiness_observation_digest
            or observation.readiness_attestation_ref
            != package.readiness_attestation_ref
            or observation.readiness_policy_ref != package.readiness_policy_ref
            or observation.readiness_evaluation_ref != package.readiness_evaluation_ref
            or observation.readiness_evaluation_digest
            != package.readiness_evaluation_digest
            or observation.readiness_operation_digest
            != candidate.readiness_evaluation.operation_digest
            or observation.readiness_evidence_digest
            != package.readiness_evidence_digest
            or observation.close_candidate_ref != package.close_candidate_ref
            or observation.close_request_ref != package.close_request_ref
            or observation.close_request_digest != package.close_request_digest
            or observation.close_operator_ref != package.close_operator_ref
            or observation.expires_at != package.readiness_expires_at
        ):
            raise ValueError(
                "readiness evidence must bind the exact retained Spring observation"
            )
        if self.readiness_evidence.issuer_ref != scope.spring_authority_ref:
            raise ValueError(
                "readiness attestation must be issued by exact Spring authority"
            )
        if (
            observation.scope_digest != period_close_scope_digest(scope)
            or observation.lifecycle_state_digest != snapshot.state_digest
            or observation.approval_transition_digest
            != approval_transition.transition_digest
        ):
            raise ValueError(
                "readiness observation must bind the exact retained scope and state"
            )
        if self.requested_by_ref != package.close_operator_ref:
            raise ValueError("final close requester must be the exact hosted operator")
        if self.requested_by_ref == snapshot.close_approval.independent_approver_ref:
            raise ValueError("independent approver cannot request the hosted close")
        occurred = _parsed_timestamp(self.occurred_at)
        if occurred < _parsed_timestamp(candidate.prepared_at):
            raise ValueError("close transition cannot precede package preparation")
        if occurred < _parsed_timestamp(package.close_requested_at):
            raise ValueError("close transition cannot precede its exact request")
        if occurred >= _parsed_timestamp(package.readiness_expires_at):
            raise ValueError("close readiness is expired at transition preparation")
        return self


class ClosePeriodTransitionCommandResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_close_period_transition_command_result.v1"
    ] = Field(default=CLOSE_PERIOD_TRANSITION_COMMAND_RESULT_SCHEMA, alias="schema")
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    package_candidate_digest: Sha256Digest
    lifecycle_version: Literal[7] = 7
    lifecycle_state_digest: Sha256Digest
    close_candidate_ref: OpaqueRef
    close_request_digest: Sha256Digest
    readiness_observation_digest: Sha256Digest
    readiness_expires_at: str
    lifecycle_input: PeriodCloseLifecycleInput
    command_content_digest: Sha256Digest
    command_request_digest: Sha256Digest
    evidence_lineage_tail_digest: Sha256Digest
    result_digest: Sha256Digest = _ZERO_DIGEST
    readiness_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    operator_authorization_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    hosted_close_execution_state: Literal["spring_execution_required"] = (
        "spring_execution_required"
    )
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False
    period_close_authorized: Literal[False] = False
    connector_calls_authorized: Literal[False] = False

    @field_validator("readiness_expires_at")
    @classmethod
    def _readiness_expires_at(cls, value: str) -> str:
        return _timestamp(value, field_name="readiness_expires_at")

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_result(self) -> "ClosePeriodTransitionCommandResult":
        command = self.lifecycle_input.command
        package = command.package
        if (
            self.lifecycle_input.snapshot is None
            or self.lifecycle_input.snapshot.version != self.lifecycle_version
            or self.lifecycle_input.snapshot.state_digest != self.lifecycle_state_digest
            or command.kind != "close_period"
            or not isinstance(package, ClosePeriodPackage)
            or command.expected_version != self.lifecycle_version
            or command.expected_state_digest != self.lifecycle_state_digest
            or self.close_candidate_ref != package.close_candidate_ref
            or self.close_request_digest != package.close_request_digest
            or self.readiness_observation_digest != package.readiness_observation_digest
            or self.readiness_expires_at != package.readiness_expires_at
            or self.command_content_digest
            != period_close_command_content_digest(command)
            or self.command_request_digest != command.request_digest
            or self.evidence_lineage_tail_digest != command.evidence[-1].lineage_digest
            or command.evidence[0].artifact_ref != package.close_request_ref
            or command.evidence[0].artifact_digest != package.close_request_digest
            or command.evidence[1].artifact_ref != package.readiness_attestation_ref
            or command.evidence[1].artifact_digest
            != package.readiness_observation_digest
        ):
            raise ValueError("result does not bind the exact sealed close command")
        expected = _stable_digest(self.digest_payload())
        if self.result_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("result_digest does not match close transition evidence")
        object.__setattr__(self, "result_digest", expected)
        return self


def _evidence_envelope(
    *,
    sequence: int,
    claim: CloseRequestEvidenceClaim | SpringCloseReadinessEvidenceClaim,
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


def prepare_close_period_transition_command(
    inputs: PrepareClosePeriodTransitionCommandInput,
) -> ClosePeriodTransitionCommandResult:
    workspace = inputs.workspace
    candidate = inputs.package_candidate
    snapshot = inputs.lifecycle_snapshot
    package = candidate.package
    raw_command = {
        "kind": "close_period",
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
                claim=inputs.close_request_evidence,
                transition_ref=inputs.transition_ref,
                workspace=workspace,
            ),
            _evidence_envelope(
                sequence=2,
                claim=inputs.readiness_evidence,
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
    return ClosePeriodTransitionCommandResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        package_candidate_digest=candidate.candidate_digest,
        lifecycle_state_digest=snapshot.state_digest,
        close_candidate_ref=package.close_candidate_ref,
        close_request_digest=package.close_request_digest,
        readiness_observation_digest=package.readiness_observation_digest,
        readiness_expires_at=package.readiness_expires_at,
        lifecycle_input=lifecycle_input,
        command_content_digest=period_close_command_content_digest(command),
        command_request_digest=command.request_digest,
        evidence_lineage_tail_digest=command.evidence[-1].lineage_digest,
    )


def _example_inputs() -> dict[str, Any]:
    package_inputs = PrepareClosePeriodPackageInput.model_validate(
        deepcopy(PrepareClosePeriodPackagePrimitive.example_inputs)
    )
    package_candidate = prepare_close_period_package(package_inputs)
    workspace = package_inputs.workspace
    package = package_candidate.package
    return {
        "workspace": workspace.to_dict(),
        "package_candidate": package_candidate.to_dict(),
        "lifecycle_snapshot": package_inputs.lifecycle_snapshot.to_dict(),
        "transition_ref": "transition:example:close-period",
        "idempotency_key": "idempotency:example:close-period",
        "occurred_at": "2026-09-01T14:55:00Z",
        "requested_by_ref": package.close_operator_ref,
        "close_request_evidence": {
            "use_ref": "evidence-use:close-request",
            "artifact_ref": package.close_request_ref,
            "artifact_digest": package.close_request_digest,
            "evidence_ref": "evidence:example:close-request",
            "issuer_ref": "controller:independent-review",
            "observed_at": "2026-09-01T14:53:00Z",
            "effective_at": package.close_requested_at,
            "retained_until": workspace.close_scope.evidence_retention_until,
        },
        "readiness_evidence": {
            "use_ref": "evidence-use:spring-close-readiness-attestation",
            "artifact_ref": package.readiness_attestation_ref,
            "artifact_digest": package.readiness_observation_digest,
            "evidence_ref": "evidence:example:spring-close-readiness-attestation",
            "issuer_ref": workspace.close_scope.spring_authority_ref,
            "observed_at": "2026-09-01T14:54:00Z",
            "effective_at": "2026-09-01T14:54:00Z",
            "retained_until": workspace.close_scope.evidence_retention_until,
            "readiness_observation": (package_inputs.readiness_observation.to_dict()),
        },
    }


class PrepareClosePeriodTransitionCommandPrimitive(
    BusinessProcessPrimitive[
        PrepareClosePeriodTransitionCommandInput,
        ClosePeriodTransitionCommandResult,
    ]
):
    primitive_ref = "finance.prepare_close_period_transition_command"
    version = "1.0.0"
    title = "Prepare evidence-bound final close transition command"
    description = (
        "Bind the exact final-close package, version-seven snapshot, close request, "
        "and Spring readiness observation into a sealed command without executing, "
        "persisting, or advancing the period close."
    )
    input_model = PrepareClosePeriodTransitionCommandInput
    output_model = ClosePeriodTransitionCommandResult
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
        contract["derived_fences"] = (
            "snapshot version, state digest, evidence lineage, scope, package, close "
            "request, readiness observation and expiry, and command content digest"
        )
        contract["authority_boundary"] = (
            "Spring must authenticate readiness, revalidate current operator RBAC, "
            "retain evidence, execute the hosted close, persist state, and admit the "
            "exact final lifecycle transition"
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareClosePeriodTransitionCommandInput,
    ) -> PrimitiveExecutionResult[ClosePeriodTransitionCommandResult]:
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
                code="close_period_transition_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, actor, and idempotency identity "
                    "must exactly match the final-close transition request."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = prepare_close_period_transition_command(inputs)
        command = output.lifecycle_input.command
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a sealed final-close command candidate; Spring readiness, "
                "operator, evidence, execution, persistence, and lifecycle authority remain."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.close_period_transition_command_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "transition_ref": command.transition_ref,
                        "close_candidate_ref": output.close_candidate_ref,
                        "close_request_digest": output.close_request_digest,
                        "package_candidate_digest": output.package_candidate_digest,
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_close_period_transition_command_candidate",
                    summary=(
                        "The command is sealed to exact close-request, readiness, state, "
                        "and lineage evidence; Spring retains all close authority."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_readiness_revalidation_required",
                        "spring_hosted_close_required",
                    ],
                    refs={
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
        )


FINANCE_CLOSE_PERIOD_TRANSITION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareClosePeriodTransitionCommandPrimitive(),)


__all__ = [
    "CLOSE_PERIOD_TRANSITION_COMMAND_INPUT_SCHEMA",
    "CLOSE_PERIOD_TRANSITION_COMMAND_RESULT_SCHEMA",
    "ClosePeriodTransitionCommandResult",
    "CloseRequestEvidenceClaim",
    "FINANCE_CLOSE_PERIOD_TRANSITION_EXECUTABLE_PRIMITIVES",
    "PrepareClosePeriodTransitionCommandInput",
    "PrepareClosePeriodTransitionCommandPrimitive",
    "SpringCloseReadinessEvidenceClaim",
    "prepare_close_period_transition_command",
]
