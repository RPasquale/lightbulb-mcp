"""Typed, fail-closed semantic feedback for project-creation preflights.

Feedback is an explicit user preference/usefulness signal attached to the
trusted neutral episode in a project-preflight receipt. It is not a project
approval, business-outcome proof, reward, rubric result, or training command.
Tenant, company, user, project, execution, and episode authority are never
accepted as free-form request fields.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.project_creation import (
    ProjectCreationPreflightReceipt,
    normalize_project_uuid,
)


PROJECT_PREFLIGHT_FEEDBACK_RECEIPT_SCHEMA = (
    "project_preflight_semantic_feedback_receipt.v1"
)
SemanticFeedbackValue = Literal["pass", "fail", "not_assessed"]

CanonicalEpisodeId = Annotated[
    str,
    StringConstraints(pattern=r"^ep_[0-9a-f]{32}$"),
]
CanonicalFeedbackId = Annotated[
    str,
    StringConstraints(pattern=r"^semfb_[0-9a-f]{64}$"),
]
CanonicalSha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=False,
    )


class ProjectPreflightFeedbackDimensions(_StrictModel):
    """The only human judgments accepted by the semantic gate."""

    helpfulness: SemanticFeedbackValue
    calibrated_criticality: SemanticFeedbackValue
    factual_grounding: SemanticFeedbackValue

    @field_validator(
        "helpfulness",
        "calibrated_criticality",
        "factual_grounding",
        mode="before",
    )
    @classmethod
    def _exact_value(cls, value: Any, info: Any) -> str:
        if not isinstance(value, str) or value not in {
            "pass",
            "fail",
            "not_assessed",
        }:
            raise ValueError(
                f"{info.field_name} must be pass, fail, or not_assessed"
            )
        return value

    @property
    def positive_gate_passed(self) -> bool:
        return all(value == "pass" for value in self.model_dump().values())


def _canonical_uuid(value: Any, label: str) -> str:
    normalized = normalize_project_uuid(value, label)
    if value != normalized:
        raise ValueError(f"{label} must be a canonical lowercase UUID")
    return normalized


def _aware_datetime(value: Any, label: str) -> datetime:
    if isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            value = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if not isinstance(value, datetime):
        raise ValueError(f"{label} must be a timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class ProjectPreflightSemanticFeedbackReceipt(_StrictModel):
    """Server-authored receipt for one exact, append-only feedback decision."""

    feedback_id: CanonicalFeedbackId
    episode_id: CanonicalEpisodeId
    execution_id: str
    tenant_id: str
    company_id: str
    project_id: None
    user_id: str
    dimensions: ProjectPreflightFeedbackDimensions
    semantic_gate_passed: bool
    base_canonical_sha256: CanonicalSha256
    structural_evidence_sha256: CanonicalSha256
    receipt_sha256: CanonicalSha256
    retain_until: datetime
    created_at: datetime

    @field_validator(
        "execution_id", "tenant_id", "company_id", "user_id", mode="before"
    )
    @classmethod
    def _uuid_fields(cls, value: Any, info: Any) -> str:
        return _canonical_uuid(value, info.field_name)

    @field_validator("retain_until", "created_at", mode="before")
    @classmethod
    def _timestamps(cls, value: Any, info: Any) -> datetime:
        return _aware_datetime(value, info.field_name)

    @model_validator(mode="after")
    def _validate_semantics(self) -> "ProjectPreflightSemanticFeedbackReceipt":
        if self.semantic_gate_passed != self.dimensions.positive_gate_passed:
            raise ValueError(
                "semantic_gate_passed does not match the explicit dimensions"
            )
        if self.retain_until <= self.created_at:
            raise ValueError("retain_until must be later than created_at")
        return self


def normalize_project_preflight_feedback_idempotency_key(value: Any) -> str:
    """Match the endpoint's exact caller-owned one-shot retry-key contract."""
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not 8 <= len(value) <= 128
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(
            "idempotency_key must be 8-128 characters without surrounding "
            "whitespace or control characters"
        )
    return value


def build_project_preflight_feedback_request(
    *,
    helpfulness: SemanticFeedbackValue,
    calibrated_criticality: SemanticFeedbackValue,
    factual_grounding: SemanticFeedbackValue,
    idempotency_key: str,
) -> tuple[dict[str, Any], ProjectPreflightFeedbackDimensions]:
    """Build the exact body; no scope, reward, rubric, or training keys exist."""
    key = normalize_project_preflight_feedback_idempotency_key(idempotency_key)
    dimensions = ProjectPreflightFeedbackDimensions(
        helpfulness=helpfulness,
        calibrated_criticality=calibrated_criticality,
        factual_grounding=factual_grounding,
    )
    return {
        "idempotency_key": key,
        "dimensions": dimensions.model_dump(),
    }, dimensions


def bind_project_preflight_feedback_receipt(
    response: Any,
    *,
    preflight_receipt: ProjectCreationPreflightReceipt,
    dimensions: ProjectPreflightFeedbackDimensions,
    expected_tenant_id: str,
    expected_company_id: str,
) -> ProjectPreflightSemanticFeedbackReceipt:
    """Strictly parse and cross-bind a response to request and auth context."""
    if not isinstance(preflight_receipt, ProjectCreationPreflightReceipt):
        raise TypeError("preflight_receipt must be a ProjectCreationPreflightReceipt")
    parsed = ProjectPreflightSemanticFeedbackReceipt.model_validate(response)
    if parsed.episode_id != preflight_receipt.episode_id:
        raise ValueError("Semantic feedback receipt episode binding mismatch")
    if parsed.execution_id != preflight_receipt.preflight_execution_id:
        raise ValueError("Semantic feedback receipt execution binding mismatch")
    if parsed.dimensions != dimensions:
        raise ValueError("Semantic feedback receipt dimensions mismatch")
    if parsed.tenant_id != _canonical_uuid(expected_tenant_id, "tenant_id"):
        raise ValueError("Semantic feedback receipt tenant binding mismatch")
    if parsed.company_id != _canonical_uuid(expected_company_id, "company_id"):
        raise ValueError("Semantic feedback receipt company binding mismatch")
    return parsed


def project_preflight_feedback_mcp_projection(
    receipt: ProjectPreflightSemanticFeedbackReceipt,
) -> dict[str, Any]:
    """Privacy-minimized success projection for an agent's MCP context."""
    if not isinstance(receipt, ProjectPreflightSemanticFeedbackReceipt):
        raise TypeError("receipt must be a ProjectPreflightSemanticFeedbackReceipt")
    return {
        "schema": PROJECT_PREFLIGHT_FEEDBACK_RECEIPT_SCHEMA,
        "feedback_id": receipt.feedback_id,
        "episode_id": receipt.episode_id,
        "dimensions": receipt.dimensions.model_dump(),
        "semantic_gate_passed": receipt.semantic_gate_passed,
        "receipt_sha256": receipt.receipt_sha256,
        "retain_until": receipt.retain_until.isoformat(),
        "created_at": receipt.created_at.isoformat(),
    }


__all__ = [
    "PROJECT_PREFLIGHT_FEEDBACK_RECEIPT_SCHEMA",
    "ProjectPreflightFeedbackDimensions",
    "ProjectPreflightSemanticFeedbackReceipt",
    "SemanticFeedbackValue",
    "bind_project_preflight_feedback_receipt",
    "build_project_preflight_feedback_request",
    "normalize_project_preflight_feedback_idempotency_key",
    "project_preflight_feedback_mcp_projection",
]
