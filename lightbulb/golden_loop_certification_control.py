"""Typed SDK projection of Spring's Golden Loop certification authority.

The SDK can assemble and submit an evidence-sealed candidate, but it cannot
self-certify. Spring resolves exact scope and RBAC, binds an independent
ApprovalTask, issues an expiring record, and retains the audit authority. A
record from this module never grants deployment or provider-effect authority.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.golden_loops import LoopCertificationCandidate, LoopCertificationRecord
from lightbulb.operational_readiness import (
    OperationalReadinessInput,
    OperationalReadinessResult,
)

GOLDEN_LOOP_CERTIFICATION_STATUS_SCHEMA = (
    "lightbulb.golden_loop_certification_candidate_status.v1"
)
GOLDEN_LOOP_CERTIFICATION_SPRING_RECORD_SCHEMA = (
    "lightbulb.golden_loop_certification_spring_record.v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
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


class GoldenLoopCertificationProposalRequest(_StrictModel):
    candidate: LoopCertificationCandidate
    catalog_version_id: str
    declaration_version_id: str
    evidence_target_id: str
    readiness_input: OperationalReadinessInput
    readiness_result: OperationalReadinessResult
    runtime_artifact_digest: str
    idempotency_key: str = Field(min_length=1, max_length=100)

    @field_validator(
        "catalog_version_id", "declaration_version_id", "evidence_target_id"
    )
    @classmethod
    def _registry_ids(cls, value: str, info: Any) -> str:
        return _uuid(value, label=info.field_name)

    @field_validator("runtime_artifact_digest")
    @classmethod
    def _artifact_digest(cls, value: str) -> str:
        return _sha256(value, label="runtime_artifact_digest")

    @field_validator("idempotency_key")
    @classmethod
    def _idempotency(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _IDEMPOTENCY.fullmatch(clean):
            raise ValueError("idempotency_key has an invalid format")
        return clean

    @model_validator(mode="after")
    def _candidate_is_exactly_bound(self) -> "GoldenLoopCertificationProposalRequest":
        if self.readiness_result.input_digest != self.candidate.operational_readiness_input_digest:
            raise ValueError("candidate readiness input digest differs")
        if self.readiness_result.evidence_digest != self.candidate.operational_readiness_evidence_digest:
            raise ValueError("candidate readiness evidence digest differs")
        if self.readiness_result.evaluation_digest != self.candidate.operational_readiness_evaluation_digest:
            raise ValueError("candidate readiness evaluation digest differs")
        if self.readiness_result.environment_ref != self.candidate.environment_ref:
            raise ValueError("candidate readiness environment differs")
        if self.readiness_result.evaluated_at != self.candidate.evaluated_at:
            raise ValueError("candidate readiness timestamp differs")
        return self

    def to_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


GoldenLoopCertificationState = Literal[
    "OPERATOR_REVIEW_PENDING",
    "CERTIFIED",
    "REJECTED",
    "REJECTED_SELF_APPROVAL",
    "EXPIRED",
    "CANCELLED",
    "BLOCKED_APPROVAL_MISMATCH",
    "BLOCKED_APPROVAL_NOT_CONSUMED",
    "BLOCKED_PROJECT_SCOPE_CHANGED",
    "BLOCKED_RECORD_MISMATCH",
    "BLOCKED_EVIDENCE_TARGET_CHANGED",
]


class GoldenLoopCertificationCandidateStatus(_StrictModel):
    schema_id: Literal[
        "lightbulb.golden_loop_certification_candidate_status.v1"
    ] = Field(alias="schema")
    candidate_id: str
    tenant_id: str
    company_id: str
    project_id: str
    catalog_version_id: str | None = None
    declaration_version_id: str | None = None
    evidence_target_id: str | None = None
    evidence_set_digest: str | None = None
    loop_ref: str = Field(min_length=1, max_length=200)
    loop_version: str
    declaration_digest: str
    environment_ref: str = Field(min_length=1, max_length=300)
    candidate_digest: str
    loop_catalog_digest: str
    runtime_artifact_digest: str
    readiness_input_digest: str
    readiness_evidence_digest: str
    readiness_evaluation_digest: str
    approval_task_id: str
    requester_user_id: str
    reviewer_user_id: str | None
    state: GoldenLoopCertificationState
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
        "tenant_id",
        "company_id",
        "project_id",
        "catalog_version_id",
        "declaration_version_id",
        "evidence_target_id",
        "approval_task_id",
        "requester_user_id",
        "reviewer_user_id",
        "certification_record_id",
    )
    @classmethod
    def _ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator("loop_version")
    @classmethod
    def _version(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _SEMVER.fullmatch(clean):
            raise ValueError("loop_version must use semantic versioning")
        return clean

    @field_validator(
        "declaration_digest",
        "candidate_digest",
        "loop_catalog_digest",
        "runtime_artifact_digest",
        "readiness_input_digest",
        "readiness_evidence_digest",
        "readiness_evaluation_digest",
        "evidence_set_digest",
    )
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("created_at", "review_expires_at", "terminal_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _terminal_shape(self) -> "GoldenLoopCertificationCandidateStatus":
        if (self.catalog_version_id is None) != (self.declaration_version_id is None):
            raise ValueError("catalog and declaration registry IDs must be bound together")
        pending = self.state == "OPERATOR_REVIEW_PENDING"
        if pending and self.catalog_version_id is None:
            raise ValueError("pending certification candidates require registry custody")
        if pending and (
            self.evidence_target_id is None or self.evidence_set_digest is None
        ):
            raise ValueError("pending certification candidates require sealed target custody")
        if pending and (
            self.terminal_reason is not None
            or self.terminal_at is not None
            or self.certification_record_id is not None
        ):
            raise ValueError("pending certification candidates cannot contain terminal evidence")
        if not pending and (not self.terminal_reason or self.terminal_at is None):
            raise ValueError("terminal certification candidates require reason and time")
        if (self.state == "CERTIFIED") != (self.certification_record_id is not None):
            raise ValueError("only CERTIFIED candidates bind a certification record")
        return self

    @property
    def terminal(self) -> bool:
        return self.state != "OPERATOR_REVIEW_PENDING"


class GoldenLoopCertificationSpringRecord(_StrictModel):
    schema_id: Literal[
        "lightbulb.golden_loop_certification_spring_record.v1"
    ] = Field(alias="schema")
    record_id: str
    candidate_id: str
    tenant_id: str
    company_id: str
    project_id: str
    catalog_version_id: str | None = None
    declaration_version_id: str | None = None
    evidence_target_id: str | None = None
    evidence_set_digest: str | None = None
    loop_ref: str = Field(min_length=1, max_length=200)
    loop_version: str
    declaration_digest: str
    environment_ref: str = Field(min_length=1, max_length=300)
    candidate_digest: str
    loop_catalog_digest: str
    runtime_artifact_digest: str
    record_digest: str
    record: LoopCertificationRecord
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
        "tenant_id",
        "company_id",
        "project_id",
        "catalog_version_id",
        "declaration_version_id",
        "evidence_target_id",
        "operator_user_id",
    )
    @classmethod
    def _ids(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _uuid(value, label=info.field_name)

    @field_validator("loop_version")
    @classmethod
    def _version(cls, value: str) -> str:
        clean = str(value or "").strip()
        if not _SEMVER.fullmatch(clean):
            raise ValueError("loop_version must use semantic versioning")
        return clean

    @field_validator(
        "declaration_digest",
        "candidate_digest",
        "loop_catalog_digest",
        "runtime_artifact_digest",
        "record_digest",
        "evidence_set_digest",
    )
    @classmethod
    def _digests(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _sha256(value, label=info.field_name)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _record_binding(self) -> "GoldenLoopCertificationSpringRecord":
        if (self.catalog_version_id is None) != (self.declaration_version_id is None):
            raise ValueError("catalog and declaration registry IDs must be bound together")
        if self.current and self.catalog_version_id is None:
            raise ValueError("current certification records require registry custody")
        if self.current and (
            self.evidence_target_id is None or self.evidence_set_digest is None
        ):
            raise ValueError("current certification records require sealed target custody")
        if (
            self.evidence_set_digest is not None
            and self.record.spring_evidence_custody_digest != self.evidence_set_digest
        ):
            raise ValueError("Spring record differs from sealed evidence target")
        if (
            self.record.loop_ref != self.loop_ref
            or self.record.loop_version != self.loop_version
            or self.record.declaration_digest != self.declaration_digest
            or self.record.candidate_digest != self.candidate_digest
            or self.record.runtime_artifact_digest != self.runtime_artifact_digest
            or self.record.record_digest != self.record_digest
        ):
            raise ValueError("Spring certification envelope differs from portable record")
        if self.record.operator_ref != f"user:{self.operator_user_id}":
            raise ValueError("Spring operator identity differs from portable record")
        return self


def parse_golden_loop_certification_candidate_status(
    value: Mapping[str, Any],
) -> GoldenLoopCertificationCandidateStatus:
    return GoldenLoopCertificationCandidateStatus.model_validate(value)


def parse_golden_loop_certification_spring_record(
    value: Mapping[str, Any],
) -> GoldenLoopCertificationSpringRecord:
    return GoldenLoopCertificationSpringRecord.model_validate(value)


__all__ = [
    "GOLDEN_LOOP_CERTIFICATION_SPRING_RECORD_SCHEMA",
    "GOLDEN_LOOP_CERTIFICATION_STATUS_SCHEMA",
    "GoldenLoopCertificationCandidateStatus",
    "GoldenLoopCertificationProposalRequest",
    "GoldenLoopCertificationSpringRecord",
    "GoldenLoopCertificationState",
    "parse_golden_loop_certification_candidate_status",
    "parse_golden_loop_certification_spring_record",
]
