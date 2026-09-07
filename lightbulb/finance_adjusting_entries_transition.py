"""Prepare an evidence-bound ``record_adjusting_entries`` transition command.

The primitive joins one controlled adjusting-entries package candidate to the
exact retained version-three period-close snapshot. It derives lifecycle fences
and command seal fields rather than accepting them from a caller. Evidence and
journal-settlement metadata remain unauthenticated claims until Spring
revalidates RBAC, custody, retention, and the governed execution journals. No
lifecycle transition, persistence write, connector call, or provider call occurs
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

from lightbulb.finance_adjusting_entries_package import (
    AdjustingEntriesPackageCandidateResult,
    PrepareAdjustingEntriesPackageInput,
    PrepareAdjustingEntriesPackagePrimitive,
    prepare_adjusting_entries_package,
)
from lightbulb.finance_close_lifecycle import (
    GENESIS_PERIOD_CLOSE_DIGEST,
    CloseEvidenceEnvelope,
    PeriodCloseLifecycleInput,
    PeriodCloseLifecycleSnapshot,
    PeriodCloseTransitionCommand,
    period_close_command_content_digest,
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

ADJUSTING_ENTRIES_TRANSITION_COMMAND_INPUT_SCHEMA = (
    "lightbulb.finance_adjusting_entries_transition_command_input.v2"
)
ADJUSTING_ENTRIES_TRANSITION_COMMAND_RESULT_SCHEMA = (
    "lightbulb.finance_adjusting_entries_transition_command_result.v2"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,199}$"
_ARTIFACT_KIND = "adjusting_entry_batch"
_REVIEW_KIND = "adjustment_posting_attestation"


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


class AdjustingEntriesArtifactEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["adjusting_entry_batch"] = _ARTIFACT_KIND
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


class AdjustmentPostingReviewEvidenceClaim(_StrictModel):
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    evidence_ref: OpaqueRef
    kind: Literal["adjustment_posting_attestation"] = _REVIEW_KIND
    issuer_ref: OpaqueRef
    observed_at: str
    effective_at: str
    retained_until: str
    verification_grade: Literal["verified"] = "verified"
    classification: Literal["internal", "confidential", "restricted"] = "restricted"

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)


class PrepareAdjustingEntriesTransitionCommandInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_adjusting_entries_transition_command_input.v2"
    ] = Field(default=ADJUSTING_ENTRIES_TRANSITION_COMMAND_INPUT_SCHEMA, alias="schema")
    workspace: FinanceCloseWorkspace
    package_candidate: AdjustingEntriesPackageCandidateResult
    lifecycle_snapshot: PeriodCloseLifecycleSnapshot
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    occurred_at: str
    requested_by_ref: OpaqueRef
    artifact_evidence: AdjustingEntriesArtifactEvidenceClaim
    review_evidence: AdjustmentPostingReviewEvidenceClaim

    @field_validator(
        "workspace", "package_candidate", "lifecycle_snapshot", mode="before"
    )
    @classmethod
    def _detached_models(cls, value: Any, info: Any) -> Any:
        model_type: type[BaseModel] = {
            "workspace": FinanceCloseWorkspace,
            "package_candidate": AdjustingEntriesPackageCandidateResult,
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
    ) -> "PrepareAdjustingEntriesTransitionCommandInput":
        workspace = self.workspace
        candidate = self.package_candidate
        snapshot = self.lifecycle_snapshot
        scope = workspace.close_scope
        if (
            candidate.workspace_ref != workspace.workspace_ref
            or candidate.workspace_revision != workspace.workspace_revision
            or candidate.workspace_digest != workspace.content_digest
        ):
            raise ValueError("package candidate must bind the exact close workspace")
        if (
            snapshot.scope != scope
            or snapshot.version != 3
            or snapshot.status != "reconciliations_validated"
            or snapshot.period_open != workspace.open_period_package
            or snapshot.trial_balance != workspace.trial_balance_package
            or snapshot.reconciliations is None
        ):
            raise ValueError("the exact retained reconciliations snapshot is required")
        trial_transition = snapshot.transition_history[1]
        reconciliation_transition = snapshot.transition_history[-1]
        if (
            trial_transition.command.kind != "capture_trial_balance"
            or reconciliation_transition.command.kind != "reconcile_accounts"
            or candidate.lifecycle_state_digest != snapshot.state_digest
            or candidate.reconciliation_transition_digest
            != reconciliation_transition.transition_digest
            or candidate.package.trial_balance_transition_digest
            != trial_transition.transition_digest
            or candidate.package.reconciliation_transition_digest
            != reconciliation_transition.transition_digest
        ):
            raise ValueError(
                "package candidate must bind the exact retained lifecycle state"
            )
        evidence = (self.artifact_evidence, self.review_evidence)
        if tuple(sorted(item.use_ref for item in evidence)) != (
            candidate.package.evidence_use_refs
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
            raise ValueError("artifact and review evidence digests must be distinct")
        if self.artifact_evidence.artifact_digest != candidate.candidate_digest:
            raise ValueError(
                "adjusting-entry artifact evidence must bind the exact package candidate"
            )
        if self.artifact_evidence.issuer_ref not in (
            scope.authorized_evidence_issuer_refs
        ):
            raise ValueError("adjusting-entry artifact issuer is not scoped")
        if self.review_evidence.issuer_ref != scope.spring_authority_ref:
            raise ValueError(
                "posting attestation must be issued by exact Spring authority"
            )
        if self.requested_by_ref in {
            candidate.package.posted_by_ref,
            candidate.package.reviewed_by_ref,
        }:
            raise ValueError(
                "requester must be separate from package posting and review actors"
            )
        return self


class AdjustingEntriesTransitionCommandResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.finance_adjusting_entries_transition_command_result.v2"
    ] = Field(
        default=ADJUSTING_ENTRIES_TRANSITION_COMMAND_RESULT_SCHEMA, alias="schema"
    )
    workspace_ref: OpaqueRef
    workspace_revision: int = Field(ge=1)
    workspace_digest: Sha256Digest
    package_candidate_digest: Sha256Digest
    lifecycle_version: Literal[3] = 3
    lifecycle_state_digest: Sha256Digest
    lifecycle_input: PeriodCloseLifecycleInput
    command_content_digest: Sha256Digest
    command_request_digest: Sha256Digest
    evidence_lineage_tail_digest: Sha256Digest
    result_digest: Sha256Digest = _ZERO_DIGEST
    journal_post_settlement_state: Literal[
        "spring_revalidation_required", "not_applicable"
    ]
    evidence_authentication_state: Literal["spring_revalidation_required"] = (
        "spring_revalidation_required"
    )
    evidence_custody_state: Literal["spring_retention_required"] = (
        "spring_retention_required"
    )
    lifecycle_transition_authority: Literal[False] = False
    persistence_authorized: Literal[False] = False
    provider_calls_authorized: Literal[False] = False

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def _sealed_result(self) -> "AdjustingEntriesTransitionCommandResult":
        command = self.lifecycle_input.command
        expected_settlement = (
            "not_applicable"
            if command.package.no_adjustments_required
            else "spring_revalidation_required"
        )
        if (
            self.lifecycle_input.snapshot is None
            or self.lifecycle_input.snapshot.version != self.lifecycle_version
            or self.lifecycle_input.snapshot.state_digest != self.lifecycle_state_digest
            or command.kind != "record_adjusting_entries"
            or command.expected_version != self.lifecycle_version
            or command.expected_state_digest != self.lifecycle_state_digest
            or self.command_content_digest
            != period_close_command_content_digest(command)
            or self.command_request_digest != command.request_digest
            or self.evidence_lineage_tail_digest != command.evidence[-1].lineage_digest
            or self.journal_post_settlement_state != expected_settlement
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
    claim: AdjustingEntriesArtifactEvidenceClaim | AdjustmentPostingReviewEvidenceClaim,
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


def prepare_adjusting_entries_transition_command(
    inputs: PrepareAdjustingEntriesTransitionCommandInput,
) -> AdjustingEntriesTransitionCommandResult:
    workspace = inputs.workspace
    candidate = inputs.package_candidate
    snapshot = inputs.lifecycle_snapshot
    raw_command = {
        "kind": "record_adjusting_entries",
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
                claim=inputs.artifact_evidence,
                transition_ref=inputs.transition_ref,
                workspace=workspace,
            ),
            _evidence_envelope(
                sequence=2,
                claim=inputs.review_evidence,
                transition_ref=inputs.transition_ref,
                workspace=workspace,
            ),
        ],
        "package": candidate.package.to_dict(),
    }
    command = PeriodCloseTransitionCommand.model_validate(
        seal_period_close_command(raw_command)
    )
    lifecycle_input = PeriodCloseLifecycleInput(
        scope=workspace.close_scope,
        snapshot=snapshot,
        command=command,
    )
    return AdjustingEntriesTransitionCommandResult(
        workspace_ref=workspace.workspace_ref,
        workspace_revision=workspace.workspace_revision,
        workspace_digest=workspace.content_digest,
        package_candidate_digest=candidate.candidate_digest,
        lifecycle_state_digest=snapshot.state_digest,
        lifecycle_input=lifecycle_input,
        command_content_digest=period_close_command_content_digest(command),
        command_request_digest=command.request_digest,
        evidence_lineage_tail_digest=command.evidence[-1].lineage_digest,
        journal_post_settlement_state=(
            "not_applicable"
            if candidate.package.no_adjustments_required
            else "spring_revalidation_required"
        ),
    )


def _example_inputs() -> dict[str, Any]:
    package_inputs = PrepareAdjustingEntriesPackageInput.model_validate(
        deepcopy(PrepareAdjustingEntriesPackagePrimitive.example_inputs)
    )
    package_candidate = prepare_adjusting_entries_package(package_inputs)
    workspace = package_inputs.workspace
    review_digest = _stable_digest(
        {
            "kind": _REVIEW_KIND,
            "package_candidate_digest": package_candidate.candidate_digest,
            "issuer_ref": workspace.close_scope.spring_authority_ref,
        }
    )
    return {
        "workspace": workspace.to_dict(),
        "package_candidate": package_candidate.to_dict(),
        "lifecycle_snapshot": package_inputs.lifecycle_snapshot.to_dict(),
        "transition_ref": "transition:example:record-adjusting-entries",
        "idempotency_key": "idempotency:example:record-adjusting-entries",
        "occurred_at": "2026-09-01T13:45:00Z",
        "requested_by_ref": "requester:example:record-adjusting-entries",
        "artifact_evidence": {
            "use_ref": "evidence-use:adjusting-entry-batch",
            "artifact_ref": "artifact:example:adjusting-entry-batch",
            "artifact_digest": package_candidate.candidate_digest,
            "evidence_ref": "evidence:example:adjusting-entry-batch",
            "issuer_ref": "controller:independent-review",
            "observed_at": "2026-09-01T13:35:00Z",
            "effective_at": "2026-09-01T13:35:00Z",
            "retained_until": workspace.close_scope.evidence_retention_until,
        },
        "review_evidence": {
            "use_ref": "evidence-use:adjustment-posting-attestation",
            "artifact_ref": "artifact:example:adjustment-posting-attestation",
            "artifact_digest": review_digest,
            "evidence_ref": "evidence:example:adjustment-posting-attestation",
            "issuer_ref": workspace.close_scope.spring_authority_ref,
            "observed_at": "2026-09-01T13:40:00Z",
            "effective_at": "2026-09-01T13:40:00Z",
            "retained_until": workspace.close_scope.evidence_retention_until,
        },
    }


class PrepareAdjustingEntriesTransitionCommandPrimitive(
    BusinessProcessPrimitive[
        PrepareAdjustingEntriesTransitionCommandInput,
        AdjustingEntriesTransitionCommandResult,
    ]
):
    primitive_ref = "finance.prepare_adjusting_entries_transition_command"
    version = "2.0.0"
    title = "Prepare evidence-bound adjusting-entries transition command"
    description = (
        "Bind an exact controlled adjusting-entries package, retained version-three "
        "close snapshot, and Spring-custodied evidence claims into a sealed transition "
        "command without settling journals, authenticating evidence, or advancing the "
        "lifecycle."
    )
    input_model = PrepareAdjustingEntriesTransitionCommandInput
    output_model = AdjustingEntriesTransitionCommandResult
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
            "journal_settlements": 0,
            "review_decisions": 0,
            "evidence_writes": 0,
            "lifecycle_transitions": 0,
            "persistence_writes": 0,
        }
        contract["derived_fences"] = (
            "snapshot version, state digest, evidence lineage, scope, package, "
            "request digest, and command content digest"
        )
        contract["authority_boundary"] = (
            "Spring must settle governed journal execution, revalidate RBAC, and "
            "authenticate retained evidence before lifecycle admission."
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PrepareAdjustingEntriesTransitionCommandInput,
    ) -> PrimitiveExecutionResult[AdjustingEntriesTransitionCommandResult]:
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
                code="adjusting_entries_transition_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, actor, and idempotency identity "
                    "must exactly match the adjusting-entries transition request."
                ),
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=blocker.message,
                blockers=[blocker],
            )
        output = prepare_adjusting_entries_transition_command(inputs)
        command = output.lifecycle_input.command
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Prepared a sealed record_adjusting_entries command candidate; Spring "
                "journal settlement, evidence authentication, and lifecycle authority "
                "remain required."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="finance.adjusting_entries_transition_command_prepared",
                    payload={
                        "workspace_ref": output.workspace_ref,
                        "transition_ref": command.transition_ref,
                        "package_candidate_digest": output.package_candidate_digest,
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="finance_adjusting_entries_transition_command_candidate",
                    summary=(
                        "The command is structurally sealed to exact package, state, "
                        "and lineage fences; Spring authority remains outstanding."
                    ),
                    labels=[
                        "monthly_close",
                        "structural_candidate_only",
                        "spring_journal_settlement_required",
                        "spring_evidence_revalidation_required",
                    ],
                    refs={
                        "command_request_digest": output.command_request_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
        )


FINANCE_ADJUSTING_ENTRIES_TRANSITION_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (PrepareAdjustingEntriesTransitionCommandPrimitive(),)


__all__ = [
    "ADJUSTING_ENTRIES_TRANSITION_COMMAND_INPUT_SCHEMA",
    "ADJUSTING_ENTRIES_TRANSITION_COMMAND_RESULT_SCHEMA",
    "AdjustmentPostingReviewEvidenceClaim",
    "AdjustingEntriesArtifactEvidenceClaim",
    "AdjustingEntriesTransitionCommandResult",
    "FINANCE_ADJUSTING_ENTRIES_TRANSITION_EXECUTABLE_PRIMITIVES",
    "PrepareAdjustingEntriesTransitionCommandInput",
    "PrepareAdjustingEntriesTransitionCommandPrimitive",
    "prepare_adjusting_entries_transition_command",
]
