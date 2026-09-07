"""Typed SDK projection of Spring's Company Blueprint authority.

This module deliberately contains no deployment engine. It validates the
bounded public contracts used to register immutable Blueprint versions, offer
certification evidence, propose deployment plans, and observe Spring-owned
materialization, activation, migration, and rollback. Approval consumption,
persistence, scope checks, and every state transition remain Spring-owned.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Literal, Mapping, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.company_blueprints import (
    CertifiedEconomicSpineStageEvidence,
    CompanyBlueprint,
    CompanyBlueprintCertificationRecord,
)
from lightbulb.golden_loops import LoopOutcomeCertificationMeasurement
from lightbulb.primitive_runtime import PrimitiveEvidenceRef

COMPANY_BLUEPRINT_SPRING_VERSION_SCHEMA = (
    "lightbulb.company_blueprint_spring_version.v1"
)
COMPANY_BLUEPRINT_VALIDATION_PREVIEW_SCHEMA = (
    "lightbulb.company_blueprint_spring_validation.v1"
)
COMPANY_BLUEPRINT_SHADOW_LIFECYCLE_SCHEMA = (
    "lightbulb.company_blueprint_shadow_lifecycle.v1"
)
COMPANY_BLUEPRINT_SHADOW_HEAD_SCHEMA = "lightbulb.company_blueprint_shadow_head.v1"
COMPANY_BLUEPRINT_CERTIFICATION_CANDIDATE_SCHEMA = (
    "lightbulb.company_blueprint_certification_candidate.v1"
)
COMPANY_BLUEPRINT_CERTIFICATION_STATUS_SCHEMA = (
    "lightbulb.company_blueprint_certification_candidate_status.v1"
)
COMPANY_BLUEPRINT_CERTIFICATION_SPRING_RECORD_SCHEMA = (
    "lightbulb.company_blueprint_certification_spring_record.v1"
)
COMPANY_BLUEPRINT_DEPLOYMENT_CANDIDATE_SCHEMA = (
    "lightbulb.company_blueprint_deployment_candidate.v1"
)
COMPANY_BLUEPRINT_DEPLOYMENT_STATUS_SCHEMA = (
    "lightbulb.company_blueprint_deployment_status.v1"
)
COMPANY_BLUEPRINT_DEPLOYMENT_HEAD_SCHEMA = "lightbulb.company_blueprint_deployment_head.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$"
)
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


def _uuid(value: str, *, label: str) -> str:
    clean = str(value or "").strip().lower()
    try:
        parsed = UUID(clean)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != clean:
        raise ValueError(f"{label} must be a canonical UUID")
    return clean


def _sha256(value: str, *, label: str) -> str:
    clean = str(value or "").strip()
    if not _SHA256.fullmatch(clean):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return clean


def _timestamp(value: str, *, label: str) -> str:
    clean = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an offset")
    return clean


def company_blueprint_evaluation_timestamp(value: str | datetime) -> str:
    """Normalize a caller-supplied, offset-aware validation observation time."""

    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("evaluated_at must include an offset")
        return value.isoformat().replace("+00:00", "Z")
    return _timestamp(str(value), label="evaluated_at")


def _tuple(value: Any) -> Any:
    if value is None or isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return value


def _stable_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


class CompanyBlueprintSpringVersion(_StrictModel):
    """One immutable Blueprint version retained by Spring."""

    schema_id: Literal["lightbulb.company_blueprint_spring_version.v1"] = Field(
        alias="schema"
    )
    version_id: str
    definition_id: str
    blueprint_version: str
    blueprint_digest: str
    source_digest: str
    loop_catalog_digest: str
    declared_lifecycle: Literal["QUARANTINED"]
    source: CompanyBlueprint | None
    source_redacted: bool
    created_by: str
    created_at: str
    idempotent_replay: bool | None = None
    authority_state: Literal["QUARANTINED"]
    certification_ready: Literal[False] | None = None
    deployment_authorized: Literal[False]
    blocker_codes: tuple[str, ...]

    @field_validator("version_id", "definition_id", "created_by")
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator("blueprint_version")
    @classmethod
    def _version(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _SEMVER.fullmatch(clean):
            raise ValueError("blueprint_version must use semantic versioning")
        return clean

    @field_validator("blueprint_digest", "source_digest", "loop_catalog_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("created_at")
    @classmethod
    def _created_at(cls, value: str) -> str:
        return _timestamp(value, label="created_at")

    @field_validator("blocker_codes", mode="before")
    @classmethod
    def _blockers(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _redaction_is_coherent(self) -> "CompanyBlueprintSpringVersion":
        if self.source_redacted != (self.source is None):
            raise ValueError("source_redacted must match source availability")
        if not self.blocker_codes:
            raise ValueError("Spring Blueprint versions must disclose blocker_codes")
        return self


class CompanyBlueprintSpringValidationFinding(_StrictModel):
    severity: Literal["error", "warning"]
    code: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=1_000)
    affected_ref: str | None = Field(default=None, alias="affectedRef", max_length=300)


class CompanyBlueprintValidationPreview(_StrictModel):
    """Spring's non-authorizing validation projection for one exact version."""

    schema_id: Literal["lightbulb.company_blueprint_spring_validation.v1"] = Field(
        alias="schema"
    )
    blueprint_version_id: str
    definition_id: str
    blueprint_ref: str = Field(min_length=1, max_length=240)
    blueprint_version: str
    blueprint_digest: str
    loop_catalog_digest: str
    admission_safe: bool
    structurally_valid: bool
    certification_ready: Literal[False]
    production_eligible: Literal[False]
    deployment_authorized: Literal[False]
    blocker_codes: tuple[str, ...]
    findings: tuple[CompanyBlueprintSpringValidationFinding, ...]
    evaluated_at: str

    @field_validator("blueprint_version_id", "definition_id")
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator("blueprint_version")
    @classmethod
    def _version(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _SEMVER.fullmatch(clean):
            raise ValueError("blueprint_version must use semantic versioning")
        return clean

    @field_validator("blueprint_digest", "loop_catalog_digest")
    @classmethod
    def _digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("blocker_codes", "findings", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")


CompanyBlueprintShadowOperation = Literal["ACTIVATE", "ROLLBACK"]
CompanyBlueprintShadowState = Literal[
    "APPROVAL_PENDING",
    "APPLIED",
    "REJECTED",
    "REJECTED_SELF_APPROVAL",
    "EXPIRED",
    "CANCELLED",
    "BLOCKED_APPROVAL_MISMATCH",
    "BLOCKED_APPROVAL_NOT_CONSUMED",
    "BLOCKED_PROJECT_SCOPE_CHANGED",
    "BLOCKED_HEAD_CHANGED",
]


class CompanyBlueprintShadowIntent(_StrictModel):
    """One approval-gated, terminalizing Spring shadow transition."""

    schema_id: Literal["lightbulb.company_blueprint_shadow_lifecycle.v1"] = Field(
        alias="schema"
    )
    intent_id: str
    project_id: str
    operation: CompanyBlueprintShadowOperation
    state: CompanyBlueprintShadowState
    terminal: bool
    terminal_reason: str | None
    approval_task_id: str | None
    request_sha256: str
    expected_head_revision: int = Field(ge=0)
    from_blueprint_version_id: str | None
    from_blueprint_digest: str | None
    to_blueprint_version_id: str | None
    to_blueprint_digest: str | None
    loop_catalog_digest: str | None
    workflow_registry_digest: str | None
    runtime_artifact_digest: str | None
    rollback_plan: dict[str, Any]
    rollback_plan_sha256: str
    result_evidence_sha256: str | None
    created_at: str
    review_expires_at: str
    terminal_at: str | None
    applied_head_revision: int | None = Field(default=None, ge=1)
    authority_state: Literal["QUARANTINED_SHADOW_ONLY"]
    declared_lifecycle: Literal["QUARANTINED"]
    production_eligible: Literal[False]
    external_effects_enabled: Literal[False]
    schedules_enabled: Literal[False]
    gtm_visible: Literal[False]
    idempotent_replay: bool | None = None

    @field_validator(
        "intent_id",
        "project_id",
        "from_blueprint_version_id",
        "to_blueprint_version_id",
        "approval_task_id",
    )
    @classmethod
    def _ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator(
        "request_sha256",
        "from_blueprint_digest",
        "to_blueprint_digest",
        "loop_catalog_digest",
        "workflow_registry_digest",
        "runtime_artifact_digest",
        "rollback_plan_sha256",
        "result_evidence_sha256",
    )
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("created_at", "review_expires_at", "terminal_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _terminal_contract(self) -> "CompanyBlueprintShadowIntent":
        pending = self.state == "APPROVAL_PENDING"
        if self.terminal == pending:
            raise ValueError("terminal must be false only while approval is pending")
        if pending:
            if self.terminal_reason is not None or self.terminal_at is not None:
                raise ValueError("pending intents cannot contain terminal evidence")
            if self.result_evidence_sha256 is not None:
                raise ValueError(
                    "pending intents cannot contain a result evidence digest"
                )
        elif (
            not self.terminal_reason
            or self.terminal_at is None
            or self.result_evidence_sha256 is None
        ):
            raise ValueError(
                "terminal intents require reason, time, and result evidence"
            )
        return self


class CompanyBlueprintShadowHead(_StrictModel):
    head_revision: int = Field(ge=1)
    authority_state: Literal["EMPTY", "QUARANTINED_SHADOW"]
    blueprint_version_id: str | None
    blueprint_digest: str | None
    loop_catalog_digest: str | None
    workflow_registry_digest: str | None
    runtime_artifact_digest: str | None
    materialization_intent_id: str | None
    last_transition_intent_id: str
    external_effects_enabled: Literal[False]
    schedules_enabled: Literal[False]
    gtm_visible: Literal[False]
    updated_at: str

    @field_validator(
        "blueprint_version_id",
        "materialization_intent_id",
        "last_transition_intent_id",
    )
    @classmethod
    def _ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest",
        "loop_catalog_digest",
        "workflow_registry_digest",
        "runtime_artifact_digest",
    )
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("updated_at")
    @classmethod
    def _updated_at(cls, value: str) -> str:
        return _timestamp(value, label="updated_at")

    @model_validator(mode="after")
    def _head_tuple(self) -> "CompanyBlueprintShadowHead":
        bound = (
            self.blueprint_version_id,
            self.blueprint_digest,
            self.loop_catalog_digest,
            self.workflow_registry_digest,
            self.runtime_artifact_digest,
            self.materialization_intent_id,
        )
        if self.authority_state == "EMPTY" and any(
            value is not None for value in bound
        ):
            raise ValueError("an EMPTY shadow head cannot retain a Blueprint binding")
        if self.authority_state == "QUARANTINED_SHADOW" and any(
            value is None for value in bound
        ):
            raise ValueError("a QUARANTINED_SHADOW head requires the complete binding")
        return self


class CompanyBlueprintShadowHeadView(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint_shadow_head.v1"] = Field(
        alias="schema"
    )
    project_id: str
    head: CompanyBlueprintShadowHead | None
    authority_state: Literal["EMPTY", "QUARANTINED_SHADOW"]
    declared_lifecycle: Literal["QUARANTINED"]
    production_eligible: Literal[False]
    external_effects_enabled: Literal[False]
    schedules_enabled: Literal[False]
    gtm_visible: Literal[False]

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        return _uuid(value, label="project_id")

    @model_validator(mode="after")
    def _head_state_matches(self) -> "CompanyBlueprintShadowHeadView":
        expected = self.head.authority_state if self.head is not None else "EMPTY"
        if self.authority_state != expected:
            raise ValueError("shadow head envelope authority_state mismatch")
        return self


class CompanyBlueprintCertificationCandidate(_StrictModel):
    """Evidence offered to Spring for independent Blueprint certification."""

    schema_id: Literal[
        "lightbulb.company_blueprint_certification_candidate.v1"
    ] = Field(default=COMPANY_BLUEPRINT_CERTIFICATION_CANDIDATE_SCHEMA, alias="schema")
    blueprint_version_id: str
    blueprint_digest: str
    environment_ref: str = Field(min_length=1, max_length=300)
    runtime_artifact_digest: str
    operational_readiness_evaluation_digest: str
    loop_certification_record_ids: tuple[str, ...] = Field(
        min_length=1, max_length=500
    )
    economic_spine_stage_evidence: tuple[
        CertifiedEconomicSpineStageEvidence, ...
    ] = Field(min_length=10, max_length=10)
    company_outcome_measurements: tuple[
        LoopOutcomeCertificationMeasurement, ...
    ] = Field(min_length=1, max_length=1_000)
    rollback_rehearsal_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=500
    )
    evaluated_at: str
    candidate_digest: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")
    ready_for_operator_certification: Literal[True] = True
    deployment_authorized: Literal[False] = False
    external_effect_authorized: Literal[False] = False

    @field_validator("blueprint_version_id")
    @classmethod
    def _version_id(cls, value: str) -> str:
        return _uuid(value, label="blueprint_version_id")

    @field_validator(
        "blueprint_digest",
        "runtime_artifact_digest",
        "operational_readiness_evaluation_digest",
    )
    @classmethod
    def _candidate_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("candidate_digest")
    @classmethod
    def _candidate_digest(cls, value: str) -> str:
        clean = str(value or "").strip().lower()
        if clean and not _SHA256.fullmatch(clean):
            raise ValueError("candidate_digest must be lowercase SHA-256")
        return clean

    @field_validator("loop_certification_record_ids", mode="before")
    @classmethod
    def _record_ids(cls, value: Any) -> Any:
        values = _tuple(value)
        if not isinstance(values, tuple):
            return values
        return tuple(_uuid(item, label="loop_certification_record_id") for item in values)

    @field_validator(
        "economic_spine_stage_evidence",
        "company_outcome_measurements",
        "rollback_rehearsal_evidence_refs",
        mode="before",
    )
    @classmethod
    def _candidate_tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _candidate_time(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @model_validator(mode="after")
    def _candidate_is_canonical(self) -> "CompanyBlueprintCertificationCandidate":
        if self.loop_certification_record_ids != tuple(
            sorted(self.loop_certification_record_ids)
        ):
            raise ValueError(
                "loop certification record ids must use canonical order"
            )
        if len(set(self.loop_certification_record_ids)) != len(
            self.loop_certification_record_ids
        ):
            raise ValueError("loop certification record ids must be unique")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude={"candidate_digest"}
        )
        expected = _stable_digest(payload)
        if self.candidate_digest and self.candidate_digest != expected:
            raise ValueError(
                "candidate_digest does not match the exact certification candidate"
            )
        object.__setattr__(self, "candidate_digest", expected)
        return self


CompanyBlueprintCertificationState = Literal[
    "OPERATOR_REVIEW_PENDING",
    "CERTIFIED",
    "REJECTED",
    "REJECTED_SELF_APPROVAL",
    "EXPIRED",
    "CANCELLED",
    "BLOCKED_APPROVAL_MISMATCH",
    "BLOCKED_APPROVAL_NOT_CONSUMED",
    "BLOCKED_PROJECT_SCOPE_CHANGED",
    "BLOCKED_LOOP_CERTIFICATION_MISMATCH",
    "BLOCKED_RECORD_MISMATCH",
    "BLOCKED_EVIDENCE_TARGET_CHANGED",
]


class CompanyBlueprintCertificationStatus(_StrictModel):
    schema_id: Literal[
        "lightbulb.company_blueprint_certification_candidate_status.v1"
    ] = Field(alias="schema")
    candidate_id: str
    blueprint_version_id: str
    tenant_id: str
    company_id: str
    project_id: str
    evidence_target_id: str | None = None
    evidence_set_digest: str | None = None
    blueprint_digest: str
    environment_ref: str
    candidate_digest: str
    runtime_artifact_digest: str
    operational_readiness_evaluation_digest: str
    approval_task_id: str
    requester_user_id: str
    reviewer_user_id: str | None
    state: CompanyBlueprintCertificationState
    terminal_reason: str | None
    certification_record_id: str | None
    created_at: str
    review_expires_at: str
    terminal_at: str | None
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]
    idempotent_replay: bool | None = None

    @field_validator(
        "candidate_id",
        "blueprint_version_id",
        "tenant_id",
        "company_id",
        "project_id",
        "evidence_target_id",
        "approval_task_id",
        "requester_user_id",
        "reviewer_user_id",
        "certification_record_id",
    )
    @classmethod
    def _status_ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest",
        "candidate_digest",
        "runtime_artifact_digest",
        "operational_readiness_evaluation_digest",
        "evidence_set_digest",
    )
    @classmethod
    def _status_digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("created_at", "review_expires_at", "terminal_at")
    @classmethod
    def _status_times(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _status_target_binding(self) -> "CompanyBlueprintCertificationStatus":
        pending = self.state == "OPERATOR_REVIEW_PENDING"
        if pending and (
            self.evidence_target_id is None or self.evidence_set_digest is None
        ):
            raise ValueError("pending Blueprint certification requires sealed target custody")
        if pending and (
            self.terminal_reason is not None
            or self.terminal_at is not None
            or self.certification_record_id is not None
        ):
            raise ValueError("pending Blueprint certification cannot contain terminal evidence")
        if not pending and (not self.terminal_reason or self.terminal_at is None):
            raise ValueError("terminal Blueprint certification requires reason and time")
        if (self.state == "CERTIFIED") != (self.certification_record_id is not None):
            raise ValueError("only CERTIFIED Blueprint candidates bind a record")
        return self


class CompanyBlueprintCertificationSpringRecord(_StrictModel):
    schema_id: Literal[
        "lightbulb.company_blueprint_certification_spring_record.v1"
    ] = Field(alias="schema")
    record_id: str
    candidate_id: str
    blueprint_version_id: str
    tenant_id: str
    company_id: str
    project_id: str
    evidence_target_id: str | None = None
    evidence_set_digest: str | None = None
    blueprint_digest: str
    environment_ref: str
    candidate_digest: str
    runtime_artifact_digest: str
    record_digest: str
    record: CompanyBlueprintCertificationRecord
    operator_user_id: str
    audit_event_id: int = Field(ge=1)
    certified_at: str
    expires_at: str
    current: bool
    deployment_authorized: Literal[False]
    external_effect_authorized: Literal[False]

    @field_validator(
        "record_id",
        "candidate_id",
        "blueprint_version_id",
        "tenant_id",
        "company_id",
        "project_id",
        "evidence_target_id",
        "operator_user_id",
    )
    @classmethod
    def _record_ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest",
        "candidate_digest",
        "runtime_artifact_digest",
        "record_digest",
        "evidence_set_digest",
    )
    @classmethod
    def _record_digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _record_times(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _portable_record_binding(self) -> "CompanyBlueprintCertificationSpringRecord":
        if self.current and (
            self.evidence_target_id is None or self.evidence_set_digest is None
        ):
            raise ValueError("current Blueprint record requires sealed target custody")
        if (
            self.evidence_set_digest is not None
            and self.record.spring_evidence_custody_digest
            != self.evidence_set_digest
        ):
            raise ValueError("Blueprint record differs from sealed evidence target")
        if (
            self.record.blueprint_digest != self.blueprint_digest
            or self.record.candidate_digest != self.candidate_digest
            or self.record.runtime_artifact_digest != self.runtime_artifact_digest
            or self.record.record_digest != self.record_digest
        ):
            raise ValueError("Spring certification envelope differs from portable record")
        if self.record.operator_ref != f"user:{self.operator_user_id}":
            raise ValueError("Spring operator identity differs from portable record")
        return self


class CompanyBlueprintDeploymentCandidate(_StrictModel):
    """Immutable SDK proposal; Spring alone can authorize or materialize it."""

    schema_id: Literal["lightbulb.company_blueprint_deployment_candidate.v1"] = Field(
        default=COMPANY_BLUEPRINT_DEPLOYMENT_CANDIDATE_SCHEMA, alias="schema"
    )
    blueprint_certification_record_id: str
    blueprint_version_id: str
    blueprint_digest: str
    environment_ref: str = Field(min_length=1, max_length=300)
    runtime_artifact_digest: str
    deployment_plan: dict[str, Any]
    deployment_plan_digest: str
    expected_head_revision: int = Field(ge=0)
    required_component_refs: tuple[str, ...] = Field(min_length=1, max_length=5_000)
    migration_plan: dict[str, Any]
    rollback_plan: dict[str, Any]
    candidate_digest: str = Field(default="", pattern=r"^(?:[0-9a-f]{64})?$")
    deployment_authorized: Literal[False] = False
    external_effect_authorized: Literal[False] = False

    @field_validator("blueprint_certification_record_id", "blueprint_version_id")
    @classmethod
    def _deployment_ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest", "runtime_artifact_digest", "deployment_plan_digest"
    )
    @classmethod
    def _deployment_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("required_component_refs", mode="before")
    @classmethod
    def _components(cls, value: Any) -> Any:
        values = _tuple(value)
        if not isinstance(values, tuple):
            return values
        cleaned = tuple(str(item or "").strip() for item in values)
        if any(not item or len(item) > 300 for item in cleaned):
            raise ValueError("required component refs must be non-empty and <= 300 chars")
        return cleaned

    @model_validator(mode="after")
    def _sealed_deployment_candidate(self) -> "CompanyBlueprintDeploymentCandidate":
        if self.required_component_refs != tuple(sorted(self.required_component_refs)):
            raise ValueError("required component refs must use canonical order")
        if len(set(self.required_component_refs)) != len(self.required_component_refs):
            raise ValueError("required component refs must be unique")
        if self.deployment_plan.get("plan_digest") != self.deployment_plan_digest:
            raise ValueError("deployment_plan_digest must bind the exact SDK plan")
        if self.deployment_plan.get("blueprint_digest") != self.blueprint_digest:
            raise ValueError("deployment plan must bind the exact Blueprint")
        payload = self.model_dump(mode="json", by_alias=True, exclude={"candidate_digest"})
        expected = _stable_digest(payload)
        if self.candidate_digest and self.candidate_digest != expected:
            raise ValueError("candidate_digest does not bind the exact deployment proposal")
        object.__setattr__(self, "candidate_digest", expected)
        return self


CompanyBlueprintDeploymentState = Literal[
    "DEPLOYMENT_APPROVAL_PENDING",
    "MATERIALIZATION_PENDING",
    "ACTIVATION_APPROVAL_PENDING",
    "ROLLBACK_APPROVAL_PENDING",
    "ACTIVE",
    "SUPERSEDED",
    "FAILED",
    "ROLLED_BACK",
    "CANCELLED",
    "EXPIRED",
    "BLOCKED_CERTIFICATION_MISMATCH",
    "BLOCKED_MATERIALIZATION_MISMATCH",
    "BLOCKED_HEAD_CONFLICT",
]


class CompanyBlueprintMaterializationReceipt(_StrictModel):
    component_ref: str = Field(min_length=1, max_length=300)
    component_digest: str
    materializer_ref: str = Field(min_length=1, max_length=300)
    evidence_digest: str
    rollback_digest: str
    verified_at: str
    verified: Literal[True]

    @field_validator("component_digest", "evidence_digest", "rollback_digest")
    @classmethod
    def _receipt_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("verified_at")
    @classmethod
    def _receipt_time(cls, value: str) -> str:
        return _timestamp(value, label="verified_at")


class CompanyBlueprintProvisionedResource(_StrictModel):
    """Server-owned resource staged from one exact compiled plan component."""

    resource_id: str
    component_ref: str = Field(min_length=1, max_length=300)
    component_kind: Literal[
        "BLUEPRINT", "DEPARTMENT", "AGENT_ROLE", "GOLDEN_LOOP", "SCHEDULE",
        "PROJECT_WORKFLOW", "EXECUTION_HOST_POLICY", "PRIMITIVE_POLICY",
        "TOOL_POLICY", "CONNECTOR_BINDING", "SECRET_CUSTODY", "POLICY",
        "WORKFLOW_REGISTRY",
    ]
    component_digest: str
    resource_digest: str
    native_resource_type: Literal[
        "SPRING_CONFIGURATION", "AUTOCOMPANY_LOOP",
        "PROJECT_DYNAMIC_WORKFLOW", "TENANT_CONNECTOR",
    ]
    native_resource_id: str | None
    certification_loop_version: str | None
    execution_loop_version: str | None
    schedule_enabled_by_default: bool
    active_binding: bool
    active_head_revision: int | None = Field(default=None, ge=1)
    staged_at: str

    @field_validator("resource_id", "native_resource_id")
    @classmethod
    def _resource_ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator("component_digest", "resource_digest")
    @classmethod
    def _resource_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("staged_at")
    @classmethod
    def _resource_time(cls, value: str) -> str:
        return _timestamp(value, label="staged_at")

    @model_validator(mode="after")
    def _active_binding_is_exact(self) -> "CompanyBlueprintProvisionedResource":
        if self.active_binding != (self.active_head_revision is not None):
            raise ValueError("active binding must carry its exact head revision")
        loop_kind = self.component_kind in {"GOLDEN_LOOP", "SCHEDULE"}
        if loop_kind:
            if (
                self.certification_loop_version is None
                or self.execution_loop_version is None
            ):
                raise ValueError("Golden Loop resources require both version contracts")
        elif (
            self.certification_loop_version is not None
            or self.execution_loop_version is not None
        ):
            raise ValueError("non-Golden-Loop resources cannot carry loop versions")
        if self.native_resource_type == "SPRING_CONFIGURATION":
            if self.native_resource_id is not None:
                raise ValueError("static Spring resources cannot claim native identity")
        elif self.native_resource_id is None:
            raise ValueError("native Blueprint resources require server-owned identity")
        return self


class CompanyBlueprintDeploymentStatus(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint_deployment_status.v1"] = Field(
        alias="schema"
    )
    deployment_id: str
    tenant_id: str
    company_id: str
    project_id: str
    blueprint_certification_record_id: str
    blueprint_version_id: str
    blueprint_digest: str
    candidate_digest: str
    deployment_plan_digest: str
    environment_ref: str
    runtime_artifact_digest: str
    expected_head_revision: int = Field(ge=0)
    state: CompanyBlueprintDeploymentState
    required_component_refs: tuple[str, ...]
    materialization_receipts: tuple[CompanyBlueprintMaterializationReceipt, ...]
    provisioned_resources: tuple[CompanyBlueprintProvisionedResource, ...]
    deployment_approval_task_id: str
    activation_approval_task_id: str | None
    rollback_approval_task_id: str | None
    deployment_reviewer_user_id: str | None
    activation_reviewer_user_id: str | None
    rollback_reviewer_user_id: str | None
    terminal_reason: str | None
    created_at: str
    updated_at: str
    terminal_at: str | None
    certification_current: bool
    resources_current: bool
    deployment_authorized: bool
    external_effect_authorized: Literal[False]
    idempotent_replay: bool | None = None

    @field_validator(
        "deployment_id", "tenant_id", "company_id", "project_id",
        "blueprint_certification_record_id", "blueprint_version_id",
        "deployment_approval_task_id", "activation_approval_task_id",
        "rollback_approval_task_id", "deployment_reviewer_user_id",
        "activation_reviewer_user_id", "rollback_reviewer_user_id",
    )
    @classmethod
    def _deployment_status_ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest", "candidate_digest", "deployment_plan_digest",
        "runtime_artifact_digest",
    )
    @classmethod
    def _deployment_status_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator(
        "required_component_refs", "materialization_receipts",
        "provisioned_resources", mode="before"
    )
    @classmethod
    def _deployment_status_tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("created_at", "updated_at", "terminal_at")
    @classmethod
    def _deployment_status_times(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _authorization_matches_serving_state(self) -> "CompanyBlueprintDeploymentStatus":
        expected = self.certification_current and self.resources_current and self.state in {
            "ACTIVE", "ROLLBACK_APPROVAL_PENDING"
        }
        if self.deployment_authorized is not expected:
            raise ValueError(
                "deployment_authorized must match current certification and serving-head state"
            )
        if self.state in {"ACTIVATION_APPROVAL_PENDING", "ACTIVE", "ROLLBACK_APPROVAL_PENDING"}:
            required = set(self.required_component_refs)
            receipt_refs = {value.component_ref for value in self.materialization_receipts}
            resource_refs = {value.component_ref for value in self.provisioned_resources}
            if required != receipt_refs or required != resource_refs:
                raise ValueError("serving-capable deployment requires the exact provisioned set")
        return self


class CompanyBlueprintDeploymentHead(_StrictModel):
    schema_id: Literal["lightbulb.company_blueprint_deployment_head.v1"] = Field(alias="schema")
    project_id: str
    head_revision: int = Field(ge=1)
    deployment_id: str
    blueprint_certification_record_id: str
    blueprint_version_id: str
    blueprint_digest: str
    deployment_plan_digest: str
    runtime_artifact_digest: str
    environment_ref: str
    state: Literal["ACTIVE"]
    certification_current: bool
    resources_current: bool
    deployment_authorized: bool
    schedules_enabled: bool
    gtm_visible: bool
    external_effect_authorized: Literal[False]
    activated_at: str

    @field_validator(
        "project_id", "deployment_id", "blueprint_certification_record_id",
        "blueprint_version_id",
    )
    @classmethod
    def _head_ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator(
        "blueprint_digest", "deployment_plan_digest", "runtime_artifact_digest"
    )
    @classmethod
    def _head_digests(cls, value: str, info: Any) -> str:
        return _sha256(value, label=info.field_name)

    @field_validator("activated_at")
    @classmethod
    def _activated_at(cls, value: str) -> str:
        return _timestamp(value, label="activated_at")

    @model_validator(mode="after")
    def _effective_authority_is_current(self) -> "CompanyBlueprintDeploymentHead":
        expected = self.certification_current and self.resources_current
        if self.deployment_authorized is not expected:
            raise ValueError(
                "deployment_authorized must match certification and provisioned resources"
            )
        if not expected and (
            self.schedules_enabled or self.gtm_visible
        ):
            raise ValueError(
                "non-current certification cannot enable schedules or GTM visibility"
            )
        return self


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def public_company_contract(value: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON-compatible copy without accepting arbitrary object types."""

    if isinstance(value, BaseModel):
        result = value.model_dump(mode="json", by_alias=True)
    elif isinstance(value, Mapping):
        result = dict(value)
    else:
        raise TypeError("company contract values must be Pydantic models or mappings")
    if not all(isinstance(key, str) for key in result):
        raise ValueError("company contract object keys must be strings")
    return result


def company_blueprint_registration_payload(
    blueprint: CompanyBlueprint | Mapping[str, Any],
    *,
    loop_catalog_digest: str,
) -> dict[str, Any]:
    parsed = (
        blueprint
        if isinstance(blueprint, CompanyBlueprint)
        else CompanyBlueprint.model_validate(blueprint)
    )
    if parsed.lifecycle.value != "QUARANTINED":
        raise ValueError("only QUARANTINED Blueprint declarations may be registered")
    return {
        # CompanyBlueprint seals its declaration over Pydantic's exclude-none
        # projection. Emit that same projection so Spring/PostgreSQL hash the
        # exact declaration instead of treating optional nulls as new fields.
        "blueprint": parsed.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        ),
        "loop_catalog_digest": _sha256(
            loop_catalog_digest, label="loop_catalog_digest"
        ),
    }


def company_blueprint_shadow_activation_payload(
    *,
    blueprint_digest: str,
    loop_catalog: BaseModel | Mapping[str, Any],
    workflow_registry: BaseModel | Mapping[str, Any],
    workflow_registry_digest: str,
    runtime_artifact_digest: str,
    idempotency_key: str,
) -> dict[str, Any]:
    clean_key = str(idempotency_key or "").strip()
    if not _IDEMPOTENCY.fullmatch(clean_key):
        raise ValueError("idempotency_key must match the 1-100 character contract")
    return {
        "blueprint_digest": _sha256(blueprint_digest, label="blueprint_digest"),
        "loop_catalog": public_company_contract(loop_catalog),
        "workflow_registry": public_company_contract(workflow_registry),
        "workflow_registry_digest": _sha256(
            workflow_registry_digest, label="workflow_registry_digest"
        ),
        "runtime_artifact_digest": _sha256(
            runtime_artifact_digest, label="runtime_artifact_digest"
        ),
        "idempotency_key": clean_key,
    }


def company_blueprint_shadow_rollback_payload(
    *, idempotency_key: str
) -> dict[str, str]:
    clean_key = str(idempotency_key or "").strip()
    if not _IDEMPOTENCY.fullmatch(clean_key):
        raise ValueError("idempotency_key must match the 1-100 character contract")
    return {"idempotency_key": clean_key}


def company_blueprint_certification_payload(
    candidate: CompanyBlueprintCertificationCandidate | Mapping[str, Any],
    *,
    evidence_target_id: str,
    idempotency_key: str,
) -> dict[str, Any]:
    parsed = (
        candidate
        if isinstance(candidate, CompanyBlueprintCertificationCandidate)
        else CompanyBlueprintCertificationCandidate.model_validate(candidate)
    )
    clean_key = str(idempotency_key or "").strip()
    if not _IDEMPOTENCY.fullmatch(clean_key):
        raise ValueError("idempotency_key must match the 1-100 character contract")
    return {
        "candidate": parsed.model_dump(mode="json", by_alias=True),
        "evidence_target_id": _uuid(
            evidence_target_id, label="evidence_target_id"
        ),
        "idempotency_key": clean_key,
    }


def company_blueprint_deployment_payload(
    candidate: CompanyBlueprintDeploymentCandidate | Mapping[str, Any],
    *,
    idempotency_key: str,
) -> dict[str, Any]:
    parsed = (
        candidate
        if isinstance(candidate, CompanyBlueprintDeploymentCandidate)
        else CompanyBlueprintDeploymentCandidate.model_validate(candidate)
    )
    clean_key = str(idempotency_key or "").strip()
    if not _IDEMPOTENCY.fullmatch(clean_key):
        raise ValueError("idempotency_key must match the 1-100 character contract")
    return {
        "candidate": parsed.model_dump(mode="json", by_alias=True),
        "idempotency_key": clean_key,
    }


def parse_company_blueprint_spring_version(
    value: Mapping[str, Any],
) -> CompanyBlueprintSpringVersion:
    return CompanyBlueprintSpringVersion.model_validate(value)


def parse_company_blueprint_validation_preview(
    value: Mapping[str, Any],
) -> CompanyBlueprintValidationPreview:
    return CompanyBlueprintValidationPreview.model_validate(value)


def parse_company_blueprint_shadow_intent(
    value: Mapping[str, Any],
) -> CompanyBlueprintShadowIntent:
    return CompanyBlueprintShadowIntent.model_validate(value)


def parse_company_blueprint_shadow_head(
    value: Mapping[str, Any],
) -> CompanyBlueprintShadowHeadView:
    return CompanyBlueprintShadowHeadView.model_validate(value)


def parse_company_blueprint_certification_status(
    value: Mapping[str, Any],
) -> CompanyBlueprintCertificationStatus:
    return CompanyBlueprintCertificationStatus.model_validate(value)


def parse_company_blueprint_certification_record(
    value: Mapping[str, Any],
) -> CompanyBlueprintCertificationSpringRecord:
    return CompanyBlueprintCertificationSpringRecord.model_validate(value)


def parse_company_blueprint_deployment_status(
    value: Mapping[str, Any],
) -> CompanyBlueprintDeploymentStatus:
    return CompanyBlueprintDeploymentStatus.model_validate(value)


def parse_company_blueprint_deployment_head(
    value: Mapping[str, Any],
) -> CompanyBlueprintDeploymentHead:
    return CompanyBlueprintDeploymentHead.model_validate(value)


__all__ = [
    "COMPANY_BLUEPRINT_SHADOW_HEAD_SCHEMA",
    "COMPANY_BLUEPRINT_SHADOW_LIFECYCLE_SCHEMA",
    "COMPANY_BLUEPRINT_CERTIFICATION_CANDIDATE_SCHEMA",
    "COMPANY_BLUEPRINT_CERTIFICATION_SPRING_RECORD_SCHEMA",
    "COMPANY_BLUEPRINT_CERTIFICATION_STATUS_SCHEMA",
    "COMPANY_BLUEPRINT_DEPLOYMENT_CANDIDATE_SCHEMA",
    "COMPANY_BLUEPRINT_DEPLOYMENT_HEAD_SCHEMA",
    "COMPANY_BLUEPRINT_DEPLOYMENT_STATUS_SCHEMA",
    "COMPANY_BLUEPRINT_SPRING_VERSION_SCHEMA",
    "COMPANY_BLUEPRINT_VALIDATION_PREVIEW_SCHEMA",
    "CompanyBlueprintShadowHead",
    "CompanyBlueprintShadowHeadView",
    "CompanyBlueprintShadowIntent",
    "CompanyBlueprintShadowOperation",
    "CompanyBlueprintShadowState",
    "CompanyBlueprintSpringVersion",
    "CompanyBlueprintSpringValidationFinding",
    "CompanyBlueprintValidationPreview",
    "CompanyBlueprintCertificationCandidate",
    "CompanyBlueprintCertificationSpringRecord",
    "CompanyBlueprintCertificationState",
    "CompanyBlueprintCertificationStatus",
    "CompanyBlueprintDeploymentCandidate",
    "CompanyBlueprintDeploymentHead",
    "CompanyBlueprintDeploymentState",
    "CompanyBlueprintDeploymentStatus",
    "CompanyBlueprintMaterializationReceipt",
    "CompanyBlueprintProvisionedResource",
    "company_blueprint_certification_payload",
    "company_blueprint_deployment_payload",
    "company_blueprint_registration_payload",
    "company_blueprint_evaluation_timestamp",
    "company_blueprint_shadow_activation_payload",
    "company_blueprint_shadow_rollback_payload",
    "parse_company_blueprint_shadow_head",
    "parse_company_blueprint_shadow_intent",
    "parse_company_blueprint_spring_version",
    "parse_company_blueprint_validation_preview",
    "parse_company_blueprint_certification_record",
    "parse_company_blueprint_certification_status",
    "parse_company_blueprint_deployment_head",
    "parse_company_blueprint_deployment_status",
    "public_company_contract",
]
