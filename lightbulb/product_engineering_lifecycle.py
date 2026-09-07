"""Deterministic product-engineering lifecycle candidate materialization.

This module retains a bounded, immutable SDK projection from requirements to
roadmap/release targeting, an engineering baseline, design review, engineering
change, verification and validation, a release candidate, telemetry, and a
proposed vulnerability/defect disposition.  It validates portable contracts;
it does not approve, persist, release, close, accept risk, or call a provider.

Spring remains authoritative for authenticated tenant/company/project scope,
identity, certification, RBAC, approvals, durable idempotency, persistence,
audit, release and risk-acceptance decisions.  PLM/ALM/telemetry systems retain
source custody and provider effects.  Actor and evidence assertions here are
structural inputs which those authorities must authenticate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, TypeAlias
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceClassification,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
    PrimitiveRecoveryDisposition,
    PrimitiveRecoveryPlan,
    revalidate_model_boundary,
)


PRODUCT_ENGINEERING_LIFECYCLE_SNAPSHOT_SCHEMA = (
    "lightbulb.product_engineering_lifecycle_snapshot.v1"
)
PRODUCT_ENGINEERING_LIFECYCLE_INPUT_SCHEMA = (
    "lightbulb.product_engineering_lifecycle_input.v1"
)
PRODUCT_ENGINEERING_TRANSITION_RECEIPT_SCHEMA = (
    "lightbulb.product_engineering_transition_receipt.v1"
)
PRODUCT_ENGINEERING_LIFECYCLE_RESULT_SCHEMA = (
    "lightbulb.product_engineering_lifecycle_result.v1"
)
PRODUCT_ENGINEERING_COMMAND_SCHEMA = (
    "lightbulb.product_engineering_transition_command.v1"
)

GENESIS_SNAPSHOT_DIGEST = "0" * 64
MAX_PRODUCT_ENGINEERING_TRANSITIONS = 9
MAX_REQUIREMENTS = 2_000
MAX_TRACE_RECORDS = 5_000
MAX_ISSUES = 5_000
EVIDENCE_FRESHNESS = timedelta(days=7)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_UNORDERED_COLLECTION_KEYS = {
    "acceptance_criteria_refs",
    "actions",
    "actors",
    "artifacts",
    "bom_components",
    "configuration_item_refs",
    "configuration_items",
    "covered_component_refs",
    "covered_configuration_item_refs",
    "covered_requirement_refs",
    "covered_specification_refs",
    "evidence_refs",
    "impacted_component_refs",
    "impacted_configuration_item_refs",
    "impacted_requirement_refs",
    "impacted_specification_refs",
    "issues",
    "known_blocker_refs",
    "linked_requirement_refs",
    "requirement_refs",
    "requirements",
    "roadmap_item_refs",
    "signals",
    "specification_refs",
    "specifications",
    "telemetry_signal_refs",
    "tests",
    "traced_requirement_refs",
    "traced_specification_refs",
}
_TIMESTAMP_KEYS = {
    "change_cutoff_at",
    "effective_at",
    "observed_at",
    "occurred_at",
    "planned_release_at",
    "valid_from",
    "valid_until",
    "window_ended_at",
    "window_started_at",
}


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError(
            "references must contain visible characters without whitespace"
        )
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _as_tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _sort_records(value: Any, key: str) -> Any:
    candidate = _as_tuple(value)
    if not isinstance(candidate, tuple):
        return candidate

    def record_key(item: Any) -> str:
        if isinstance(item, BaseModel):
            return str(getattr(item, key, ""))
        if isinstance(item, Mapping):
            return str(item.get(key) or "")
        return ""

    return tuple(sorted(candidate, key=record_key))


def _sort_strings(value: Any) -> Any:
    candidate = _as_tuple(value)
    if isinstance(candidate, tuple) and all(
        isinstance(item, str) for item in candidate
    ):
        return tuple(sorted(candidate))
    return candidate


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _normalize_timestamp_fields(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_timestamp_fields(item, parent_key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_timestamp_fields(item) for item in value]
    if parent_key in _TIMESTAMP_KEYS and value is not None:
        if not isinstance(value, str):
            raise ValueError(f"{parent_key} must be an ISO-8601 string")
        return _timestamp(value, field_name=parent_key)
    return value


def _normalize_unordered(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_unordered(item, parent_key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        items = [_normalize_unordered(item) for item in value]
        if parent_key in _UNORDERED_COLLECTION_KEYS:
            items.sort(
                key=lambda item: json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
        return items
    return value


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        _normalize_unordered(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _require_unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} references must be unique")


class ProductEngineeringLifecycleScope(_StrictModel):
    """Exact business scope plus the expected external evidence custodians."""

    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    product_ref: OpaqueRef
    configuration_ref: OpaqueRef
    release_ref: OpaqueRef
    spring_authority_ref: OpaqueRef
    plm_system_ref: OpaqueRef
    alm_system_ref: OpaqueRef
    telemetry_system_ref: OpaqueRef

    @field_validator("project_id", mode="before")
    @classmethod
    def _canonical_project_id(cls, value: Any) -> UUID:
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("project_id must be a canonical UUID")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return parsed

    @model_validator(mode="after")
    def _custodians_are_unambiguous(self) -> "ProductEngineeringLifecycleScope":
        custody_refs = (
            self.spring_authority_ref,
            self.plm_system_ref,
            self.alm_system_ref,
            self.telemetry_system_ref,
        )
        _require_unique(custody_refs, label="custody-system")
        return self


def product_engineering_scope_digest(
    scope: ProductEngineeringLifecycleScope | Mapping[str, Any],
) -> str:
    parsed = (
        ProductEngineeringLifecycleScope.model_validate(scope)
        if not isinstance(scope, ProductEngineeringLifecycleScope)
        else ProductEngineeringLifecycleScope.model_validate(scope.to_dict())
    )
    return _stable_digest(parsed.to_dict())


ActorRole = Literal[
    "requirement_author",
    "requirement_reviewer",
    "product_owner",
    "release_approver",
    "design_author",
    "configuration_manager",
    "baseline_approver",
    "design_owner",
    "independent_reviewer",
    "review_approver",
    "change_requester",
    "impact_assessor",
    "change_approver",
    "change_implementer",
    "test_author",
    "test_executor",
    "independent_validator",
    "release_manager",
    "quality_approver",
    "security_approver",
    "telemetry_analyst",
    "telemetry_reviewer",
    "issue_owner",
    "disposition_reviewer",
    "risk_reviewer",
]


class CertifiedLifecycleActor(_StrictModel):
    actor_ref: OpaqueRef
    role: ActorRole
    certification_ref: OpaqueRef
    valid_from: str
    valid_until: str
    certification_evidence: PrimitiveEvidenceRef

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _valid_timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _certification_is_content_bound(self) -> "CertifiedLifecycleActor":
        if _parsed_timestamp(self.valid_from) >= _parsed_timestamp(self.valid_until):
            raise ValueError("actor certification validity must be a positive window")
        evidence = self.certification_evidence
        if evidence.subject_ref != self.actor_ref:
            raise ValueError("actor certification evidence must name the exact actor")
        if evidence.kind != "actor_certification":
            raise ValueError("actor certification evidence has the wrong kind")
        if evidence.verification_grade != PrimitiveEvidenceVerificationGrade.VERIFIED:
            raise ValueError("actor certification evidence must be verified")
        if evidence.classification == PrimitiveEvidenceClassification.PUBLIC:
            raise ValueError("actor certification evidence cannot be public")
        if evidence.retention_policy is None:
            raise ValueError("actor certification evidence requires retention custody")
        payload = self.to_dict()
        payload.pop("certification_evidence")
        if evidence.sha256 != _stable_digest(payload):
            raise ValueError("actor certification evidence must commit exact content")
        return self


class _ContentBoundCandidate(_StrictModel):
    scope_digest: Sha256Digest
    content_digest: Sha256Digest

    @model_validator(mode="after")
    def _content_is_sealed(self) -> "_ContentBoundCandidate":
        payload = self.to_dict()
        payload.pop("content_digest")
        if self.content_digest != _stable_digest(payload):
            raise ValueError("candidate content_digest does not match exact content")
        return self


RequirementKind = Literal[
    "functional",
    "performance",
    "security",
    "safety",
    "regulatory",
    "usability",
    "operational",
]


class RequirementRecord(_StrictModel):
    requirement_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    kind: RequirementKind
    statement_digest: Sha256Digest
    acceptance_criteria_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=1_000,
    )

    @field_validator("acceptance_criteria_refs", mode="before")
    @classmethod
    def _criteria_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _criteria_are_unique(self) -> "RequirementRecord":
        _require_unique(self.acceptance_criteria_refs, label="acceptance-criteria")
        return self


class RequirementsBaselineCandidate(_ContentBoundCandidate):
    baseline_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    requirements: tuple[RequirementRecord, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENTS,
    )

    @field_validator("requirements", mode="before")
    @classmethod
    def _requirements_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "requirement_ref")

    @model_validator(mode="after")
    def _requirement_refs_are_unique(self) -> "RequirementsBaselineCandidate":
        _require_unique(
            tuple(item.requirement_ref for item in self.requirements),
            label="requirement",
        )
        return self


class ReleaseTargetCandidate(_ContentBoundCandidate):
    release_target_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    requirements_baseline_digest: Sha256Digest
    roadmap_item_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=2_000)
    requirement_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENTS,
    )
    planned_release_at: str
    change_cutoff_at: str

    @field_validator("roadmap_item_refs", "requirement_refs", mode="before")
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @field_validator("planned_release_at", "change_cutoff_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _target_is_bounded(self) -> "ReleaseTargetCandidate":
        _require_unique(self.roadmap_item_refs, label="roadmap-item")
        _require_unique(self.requirement_refs, label="requirement")
        if _parsed_timestamp(self.change_cutoff_at) > _parsed_timestamp(
            self.planned_release_at
        ):
            raise ValueError("change cutoff cannot follow planned release")
        return self


class SpecificationRecord(_StrictModel):
    specification_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    content_sha256: Sha256Digest
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=2_000)
    configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator("requirement_refs", "configuration_item_refs", mode="before")
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _links_are_unique(self) -> "SpecificationRecord":
        _require_unique(self.requirement_refs, label="requirement")
        _require_unique(self.configuration_item_refs, label="configuration-item")
        return self


class ConfigurationItemRecord(_StrictModel):
    configuration_item_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    content_sha256: Sha256Digest
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator("specification_refs", mode="before")
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _links_are_unique(self) -> "ConfigurationItemRecord":
        _require_unique(self.specification_refs, label="specification")
        return self


class BomComponentRecord(_StrictModel):
    component_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    quantity: int = Field(ge=1, le=1_000_000_000)
    configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator("configuration_item_refs", mode="before")
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _links_are_unique(self) -> "BomComponentRecord":
        _require_unique(self.configuration_item_refs, label="configuration-item")
        return self


class EngineeringBaselineCandidate(_ContentBoundCandidate):
    baseline_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    configuration_ref: OpaqueRef
    requirements_baseline_digest: Sha256Digest
    release_target_digest: Sha256Digest
    specifications: tuple[SpecificationRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    configuration_items: tuple[ConfigurationItemRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    bom_components: tuple[BomComponentRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator("specifications", mode="before")
    @classmethod
    def _specifications_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "specification_ref")

    @field_validator("configuration_items", mode="before")
    @classmethod
    def _items_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "configuration_item_ref")

    @field_validator("bom_components", mode="before")
    @classmethod
    def _components_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "component_ref")

    @model_validator(mode="after")
    def _baseline_refs_are_unique(self) -> "EngineeringBaselineCandidate":
        _require_unique(
            tuple(item.specification_ref for item in self.specifications),
            label="specification",
        )
        _require_unique(
            tuple(item.configuration_item_ref for item in self.configuration_items),
            label="configuration-item",
        )
        _require_unique(
            tuple(item.component_ref for item in self.bom_components),
            label="BOM-component",
        )
        return self


class DesignActionRecord(_StrictModel):
    action_ref: OpaqueRef
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["closed", "open"]
    closure_ref: OpaqueRef | None = None

    @model_validator(mode="after")
    def _closure_is_exact(self) -> "DesignActionRecord":
        if (self.status == "closed") != (self.closure_ref is not None):
            raise ValueError("closed design actions require one closure reference")
        return self


class DesignReviewCandidate(_ContentBoundCandidate):
    review_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    engineering_baseline_digest: Sha256Digest
    covered_requirement_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENTS,
    )
    covered_specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    covered_configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    covered_component_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    actions: tuple[DesignActionRecord, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACE_RECORDS,
    )
    recommendation: Literal["candidate_ready", "changes_required"]

    @field_validator(
        "covered_requirement_refs",
        "covered_specification_refs",
        "covered_configuration_item_refs",
        "covered_component_refs",
        mode="before",
    )
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @field_validator("actions", mode="before")
    @classmethod
    def _actions_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "action_ref")

    @model_validator(mode="after")
    def _review_is_consistent(self) -> "DesignReviewCandidate":
        for label, values in (
            ("requirement", self.covered_requirement_refs),
            ("specification", self.covered_specification_refs),
            ("configuration-item", self.covered_configuration_item_refs),
            ("component", self.covered_component_refs),
        ):
            _require_unique(values, label=label)
        _require_unique(tuple(item.action_ref for item in self.actions), label="action")
        if self.recommendation == "candidate_ready" and any(
            item.status != "closed" for item in self.actions
        ):
            raise ValueError("candidate-ready design review cannot retain open actions")
        return self


class EngineeringChangeCandidate(_ContentBoundCandidate):
    change_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    from_baseline_digest: Sha256Digest
    proposed_baseline_digest: Sha256Digest
    proposed_baseline: EngineeringBaselineCandidate
    risk_tier: Literal["low", "medium", "high", "critical"]
    implementation_plan_ref: OpaqueRef
    impacted_requirement_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENTS,
    )
    impacted_specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    impacted_configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    impacted_component_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator(
        "impacted_requirement_refs",
        "impacted_specification_refs",
        "impacted_configuration_item_refs",
        "impacted_component_refs",
        mode="before",
    )
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _change_is_bounded(self) -> "EngineeringChangeCandidate":
        if self.from_baseline_digest == self.proposed_baseline_digest:
            raise ValueError("engineering change must propose a distinct baseline")
        if self.proposed_baseline.content_digest != self.proposed_baseline_digest:
            raise ValueError(
                "engineering change must carry the exact proposed baseline"
            )
        if self.proposed_baseline.scope_digest != self.scope_digest:
            raise ValueError("proposed baseline must retain exact lifecycle scope")
        for label, values in (
            ("requirement", self.impacted_requirement_refs),
            ("specification", self.impacted_specification_refs),
            ("configuration-item", self.impacted_configuration_item_refs),
            ("component", self.impacted_component_refs),
        ):
            _require_unique(values, label=label)
        return self


class TestRecord(_StrictModel):
    test_ref: OpaqueRef
    kind: Literal["verification", "validation"]
    method: Literal[
        "test",
        "analysis",
        "inspection",
        "demonstration",
        "simulation",
    ]
    result: Literal["passed", "failed", "not_run"]
    result_sha256: Sha256Digest
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=2_000)
    acceptance_criteria_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator(
        "requirement_refs",
        "acceptance_criteria_refs",
        "specification_refs",
        mode="before",
    )
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _trace_refs_are_unique(self) -> "TestRecord":
        _require_unique(self.requirement_refs, label="requirement")
        _require_unique(self.acceptance_criteria_refs, label="acceptance-criteria")
        _require_unique(self.specification_refs, label="specification")
        return self


class VerificationValidationCandidate(_ContentBoundCandidate):
    campaign_ref: OpaqueRef
    revision: int = Field(ge=1, le=1_000_000)
    engineering_change_digest: Sha256Digest
    target_baseline_digest: Sha256Digest
    tests: tuple[TestRecord, ...] = Field(min_length=1, max_length=MAX_TRACE_RECORDS)

    @field_validator("tests", mode="before")
    @classmethod
    def _tests_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "test_ref")

    @model_validator(mode="after")
    def _tests_are_unique(self) -> "VerificationValidationCandidate":
        _require_unique(tuple(item.test_ref for item in self.tests), label="test")
        return self


class ReleaseArtifactRecord(_StrictModel):
    artifact_ref: OpaqueRef
    kind: Literal[
        "software",
        "firmware",
        "hardware",
        "documentation",
        "configuration",
        "sbom",
    ]
    content_sha256: Sha256Digest


class ReleaseCandidateRecord(_ContentBoundCandidate):
    candidate_ref: OpaqueRef
    candidate_version: ShortText
    target_baseline_digest: Sha256Digest
    design_review_digest: Sha256Digest
    engineering_change_digest: Sha256Digest
    verification_validation_digest: Sha256Digest
    traced_requirement_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_REQUIREMENTS,
    )
    traced_specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    artifacts: tuple[ReleaseArtifactRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    known_blocker_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator(
        "traced_requirement_refs",
        "traced_specification_refs",
        "known_blocker_refs",
        mode="before",
    )
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @field_validator("artifacts", mode="before")
    @classmethod
    def _artifacts_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "artifact_ref")

    @model_validator(mode="after")
    def _release_artifacts_are_unique(self) -> "ReleaseCandidateRecord":
        _require_unique(self.traced_requirement_refs, label="requirement")
        _require_unique(self.traced_specification_refs, label="specification")
        _require_unique(
            tuple(item.artifact_ref for item in self.artifacts), label="artifact"
        )
        _require_unique(
            tuple(item.content_sha256 for item in self.artifacts),
            label="artifact-content",
        )
        _require_unique(self.known_blocker_refs, label="blocker")
        return self


class TelemetrySignalRecord(_StrictModel):
    signal_ref: OpaqueRef
    metric_ref: OpaqueRef
    source_sha256: Sha256Digest
    sample_count: int = Field(ge=1, le=10_000_000_000)
    threshold_status: Literal["within_threshold", "warning", "breached"]
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=2_000)

    @field_validator("requirement_refs", mode="before")
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _requirement_refs_are_unique(self) -> "TelemetrySignalRecord":
        _require_unique(self.requirement_refs, label="requirement")
        return self


class ProductTelemetryCandidate(_ContentBoundCandidate):
    observation_ref: OpaqueRef
    release_candidate_digest: Sha256Digest
    environment: Literal["test", "staging", "pilot", "production", "field"]
    window_started_at: str
    window_ended_at: str
    signals: tuple[TelemetrySignalRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )

    @field_validator("window_started_at", "window_ended_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("signals", mode="before")
    @classmethod
    def _signals_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "signal_ref")

    @model_validator(mode="after")
    def _window_and_signals_are_bounded(self) -> "ProductTelemetryCandidate":
        if _parsed_timestamp(self.window_started_at) >= _parsed_timestamp(
            self.window_ended_at
        ):
            raise ValueError("telemetry window must be positive")
        _require_unique(tuple(item.signal_ref for item in self.signals), label="signal")
        _require_unique(
            tuple(item.source_sha256 for item in self.signals),
            label="telemetry-source",
        )
        return self


IssueDisposition = Literal[
    "release_block",
    "remediation_required",
    "risk_review_required",
    "false_positive_review",
]


class ProductIssueRecord(_StrictModel):
    issue_ref: OpaqueRef
    kind: Literal["vulnerability", "defect"]
    severity: Literal["low", "medium", "high", "critical"]
    source_ref: OpaqueRef
    linked_requirement_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=2_000,
    )
    telemetry_signal_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=MAX_TRACE_RECORDS,
    )
    proposed_disposition: IssueDisposition
    remediation_ref: OpaqueRef | None = None

    @field_validator(
        "linked_requirement_refs",
        "telemetry_signal_refs",
        mode="before",
    )
    @classmethod
    def _references_tuple(cls, value: Any) -> Any:
        return _sort_strings(value)

    @model_validator(mode="after")
    def _disposition_is_fail_closed(self) -> "ProductIssueRecord":
        _require_unique(self.linked_requirement_refs, label="requirement")
        _require_unique(self.telemetry_signal_refs, label="telemetry-signal")
        if (self.proposed_disposition == "remediation_required") != (
            self.remediation_ref is not None
        ):
            raise ValueError(
                "remediation disposition requires one remediation reference"
            )
        if self.severity in {"high", "critical"} and self.proposed_disposition not in {
            "release_block",
            "remediation_required",
        }:
            raise ValueError(
                "high and critical issues must block or require remediation"
            )
        return self


class IssueDispositionCandidate(_ContentBoundCandidate):
    disposition_ref: OpaqueRef
    release_candidate_digest: Sha256Digest
    telemetry_digest: Sha256Digest
    no_known_issues: bool
    issues: tuple[ProductIssueRecord, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ISSUES,
    )

    @field_validator("issues", mode="before")
    @classmethod
    def _issues_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "issue_ref")

    @model_validator(mode="after")
    def _issue_assertion_is_exact(self) -> "IssueDispositionCandidate":
        if self.no_known_issues == bool(self.issues):
            raise ValueError(
                "no_known_issues must be true exactly when the issue list is empty"
            )
        _require_unique(tuple(item.issue_ref for item in self.issues), label="issue")
        _require_unique(
            tuple(item.source_ref for item in self.issues), label="issue-source"
        )
        return self


TransitionKind = Literal[
    "requirements",
    "release_target",
    "engineering_baseline",
    "design_review",
    "engineering_change",
    "verification_validation",
    "release_candidate",
    "product_telemetry",
    "issue_disposition",
]
TransitionOutcome = Literal["candidate", "rejected", "in_doubt"]


def _actor_content_digest(actor: Mapping[str, Any]) -> str:
    payload = dict(actor)
    payload.pop("certification_evidence", None)
    return _stable_digest(payload)


def _command_content_payload(command: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    payload = (
        command.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(command, BaseModel)
        else deepcopy(dict(command))
    )
    payload = _normalize_timestamp_fields(payload)
    payload.pop("request_digest", None)
    payload.pop("evidence_refs", None)
    return payload


def _command_request_payload(command: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    payload = (
        command.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(command, BaseModel)
        else deepcopy(dict(command))
    )
    payload = _normalize_timestamp_fields(payload)
    payload.pop("request_digest", None)
    return payload


class _TransitionCommandBase(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_transition_command.v1"] = Field(
        default=PRODUCT_ENGINEERING_COMMAND_SCHEMA,
        alias="schema",
    )
    kind: TransitionKind
    command_ref: OpaqueRef
    scope_digest: Sha256Digest
    requested_by_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_revision: int = Field(ge=0, lt=MAX_PRODUCT_ENGINEERING_TRANSITIONS)
    expected_snapshot_digest: Sha256Digest
    occurred_at: str
    transition_outcome: TransitionOutcome = "candidate"
    artifact_evidence_ref: OpaqueRef
    governance_evidence_ref: OpaqueRef
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=2,
        max_length=2,
    )
    actors: tuple[CertifiedLifecycleActor, ...] = Field(min_length=2, max_length=4)
    request_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def _valid_occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "evidence_ref")

    @field_validator("actors", mode="before")
    @classmethod
    def _actors_tuple(cls, value: Any) -> Any:
        return _sort_records(value, "role")

    @model_validator(mode="after")
    def _header_is_content_bound(self) -> "_TransitionCommandBase":
        evidence_refs = tuple(item.evidence_ref for item in self.evidence_refs)
        if set(evidence_refs) != {
            self.artifact_evidence_ref,
            self.governance_evidence_ref,
        }:
            raise ValueError("selected evidence references must equal the evidence set")
        _require_unique(evidence_refs, label="transition-evidence")
        _require_unique(
            tuple(item.actor_ref for item in self.actors),
            label="actor",
        )
        _require_unique(
            tuple(item.role for item in self.actors),
            label="actor-role",
        )
        _require_unique(
            tuple(item.certification_ref for item in self.actors),
            label="actor-certification",
        )
        if self.requested_by_ref not in {actor.actor_ref for actor in self.actors}:
            raise ValueError(
                "requested_by_ref must name an exact certified command actor"
            )

        occurred_at = _parsed_timestamp(self.occurred_at)
        content_digest = _stable_digest(_command_content_payload(self))
        for evidence in self.evidence_refs:
            if evidence.subject_ref != self.command_ref:
                raise ValueError("transition evidence must name the exact command")
            if evidence.sha256 != content_digest:
                raise ValueError(
                    "transition evidence must commit exact command content"
                )
            _validate_fresh_evidence(evidence, occurred_at=occurred_at)

        all_evidence_refs = list(evidence_refs)
        for actor in self.actors:
            valid_from = _parsed_timestamp(actor.valid_from)
            valid_until = _parsed_timestamp(actor.valid_until)
            if not valid_from <= occurred_at < valid_until:
                raise ValueError("actor certification must be valid at transition time")
            certification = actor.certification_evidence
            _validate_fresh_evidence(certification, occurred_at=occurred_at)
            all_evidence_refs.append(certification.evidence_ref)
        _require_unique(tuple(all_evidence_refs), label="all command evidence")

        if self.request_digest != _stable_digest(_command_request_payload(self)):
            raise ValueError("request_digest does not match exact command envelope")
        return self


def _validate_fresh_evidence(
    evidence: PrimitiveEvidenceRef,
    *,
    occurred_at: datetime,
) -> None:
    observed_at = _parsed_timestamp(evidence.observed_at)
    if observed_at > occurred_at:
        raise ValueError("evidence cannot be observed after the transition")
    if observed_at < occurred_at - EVIDENCE_FRESHNESS:
        raise ValueError("transition evidence exceeds the seven-day freshness bound")
    if evidence.effective_at is None:
        raise ValueError("transition evidence requires an effective timestamp")
    if _parsed_timestamp(evidence.effective_at) > occurred_at:
        raise ValueError("evidence cannot become effective after the transition")
    if evidence.classification == PrimitiveEvidenceClassification.PUBLIC:
        raise ValueError("product-engineering evidence cannot be public")
    if evidence.retention_policy is None:
        raise ValueError("product-engineering evidence requires retention custody")


def _validate_roles(
    command: _TransitionCommandBase,
    expected: frozenset[ActorRole],
) -> None:
    actual = frozenset(actor.role for actor in command.actors)
    if actual != expected:
        raise ValueError(f"{command.kind} requires the exact certified actor roles")


class BaselineRequirementsCommand(_TransitionCommandBase):
    kind: Literal["requirements"] = "requirements"
    candidate: RequirementsBaselineCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "BaselineRequirementsCommand":
        _validate_roles(
            self,
            frozenset({"requirement_author", "requirement_reviewer"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("requirements candidate scope digest is not exact")
        return self


class TargetReleaseCommand(_TransitionCommandBase):
    kind: Literal["release_target"] = "release_target"
    candidate: ReleaseTargetCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "TargetReleaseCommand":
        _validate_roles(self, frozenset({"product_owner", "release_approver"}))
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("release-target candidate scope digest is not exact")
        return self


class BaselineEngineeringCommand(_TransitionCommandBase):
    kind: Literal["engineering_baseline"] = "engineering_baseline"
    candidate: EngineeringBaselineCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "BaselineEngineeringCommand":
        _validate_roles(
            self,
            frozenset({"design_author", "configuration_manager", "baseline_approver"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("engineering-baseline candidate scope digest is not exact")
        return self


class ReviewDesignCommand(_TransitionCommandBase):
    kind: Literal["design_review"] = "design_review"
    candidate: DesignReviewCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ReviewDesignCommand":
        _validate_roles(
            self,
            frozenset({"design_owner", "independent_reviewer", "review_approver"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("design-review candidate scope digest is not exact")
        return self


class ValidateEngineeringChangeCommand(_TransitionCommandBase):
    kind: Literal["engineering_change"] = "engineering_change"
    candidate: EngineeringChangeCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ValidateEngineeringChangeCommand":
        _validate_roles(
            self,
            frozenset(
                {
                    "change_requester",
                    "impact_assessor",
                    "change_approver",
                    "change_implementer",
                }
            ),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("engineering-change candidate scope digest is not exact")
        return self


class ValidateVerificationCommand(_TransitionCommandBase):
    kind: Literal["verification_validation"] = "verification_validation"
    candidate: VerificationValidationCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ValidateVerificationCommand":
        _validate_roles(
            self,
            frozenset({"test_author", "test_executor", "independent_validator"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("verification candidate scope digest is not exact")
        return self


class ValidateReleaseCandidateCommand(_TransitionCommandBase):
    kind: Literal["release_candidate"] = "release_candidate"
    candidate: ReleaseCandidateRecord

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ValidateReleaseCandidateCommand":
        _validate_roles(
            self,
            frozenset({"release_manager", "quality_approver", "security_approver"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("release candidate scope digest is not exact")
        return self


class ObserveProductTelemetryCommand(_TransitionCommandBase):
    kind: Literal["product_telemetry"] = "product_telemetry"
    candidate: ProductTelemetryCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ObserveProductTelemetryCommand":
        _validate_roles(
            self,
            frozenset({"telemetry_analyst", "telemetry_reviewer"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("telemetry candidate scope digest is not exact")
        return self


class ProposeIssueDispositionCommand(_TransitionCommandBase):
    kind: Literal["issue_disposition"] = "issue_disposition"
    candidate: IssueDispositionCandidate

    @model_validator(mode="after")
    def _roles_and_scope_are_exact(self) -> "ProposeIssueDispositionCommand":
        _validate_roles(
            self,
            frozenset({"issue_owner", "disposition_reviewer", "risk_reviewer"}),
        )
        if self.candidate.scope_digest != self.scope_digest:
            raise ValueError("issue-disposition candidate scope digest is not exact")
        return self


ProductEngineeringTransitionCommand: TypeAlias = Annotated[
    BaselineRequirementsCommand
    | TargetReleaseCommand
    | BaselineEngineeringCommand
    | ReviewDesignCommand
    | ValidateEngineeringChangeCommand
    | ValidateVerificationCommand
    | ValidateReleaseCandidateCommand
    | ObserveProductTelemetryCommand
    | ProposeIssueDispositionCommand,
    Field(discriminator="kind"),
]

_COMMAND_ADAPTER = TypeAdapter(ProductEngineeringTransitionCommand)


def seal_product_engineering_command(
    command: BaseModel | Mapping[str, Any],
) -> ProductEngineeringTransitionCommand:
    """Canonically seal a command; this does not authenticate its assertions."""

    payload = (
        command.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(command, BaseModel)
        else deepcopy(dict(command))
    )
    payload = _normalize_timestamp_fields(payload)
    candidate = dict(payload["candidate"])
    if payload.get("kind") == "engineering_change":
        proposed_baseline = deepcopy(dict(candidate["proposed_baseline"]))
        proposed_baseline.pop("content_digest", None)
        proposed_baseline["content_digest"] = _stable_digest(proposed_baseline)
        candidate["proposed_baseline"] = proposed_baseline
        candidate["proposed_baseline_digest"] = proposed_baseline["content_digest"]
    candidate.pop("content_digest", None)
    candidate["content_digest"] = _stable_digest(candidate)
    payload["candidate"] = candidate

    actors: list[dict[str, Any]] = []
    for raw_actor in payload["actors"]:
        actor = deepcopy(dict(raw_actor))
        certification = deepcopy(dict(actor["certification_evidence"]))
        certification["sha256"] = _actor_content_digest(actor)
        actor["certification_evidence"] = certification
        actors.append(actor)
    payload["actors"] = actors

    content_digest = _stable_digest(_command_content_payload(payload))
    evidence_refs: list[dict[str, Any]] = []
    for raw_evidence in payload["evidence_refs"]:
        evidence = deepcopy(dict(raw_evidence))
        evidence["sha256"] = content_digest
        evidence_refs.append(evidence)
    payload["evidence_refs"] = evidence_refs
    payload.pop("request_digest", None)
    payload["request_digest"] = _stable_digest(_command_request_payload(payload))
    return _COMMAND_ADAPTER.validate_python(payload)


_STAGE_ORDER: tuple[TransitionKind, ...] = (
    "requirements",
    "release_target",
    "engineering_baseline",
    "design_review",
    "engineering_change",
    "verification_validation",
    "release_candidate",
    "product_telemetry",
    "issue_disposition",
)
LifecyclePhase = Literal[
    "requirements_baselined",
    "release_targeted",
    "engineering_baselined",
    "design_reviewed",
    "change_candidate_validated",
    "verification_validation_passed",
    "release_candidate_validated",
    "telemetry_observed",
    "issue_dispositions_proposed",
]
_PHASE_BY_KIND: dict[TransitionKind, LifecyclePhase] = {
    "requirements": "requirements_baselined",
    "release_target": "release_targeted",
    "engineering_baseline": "engineering_baselined",
    "design_review": "design_reviewed",
    "engineering_change": "change_candidate_validated",
    "verification_validation": "verification_validation_passed",
    "release_candidate": "release_candidate_validated",
    "product_telemetry": "telemetry_observed",
    "issue_disposition": "issue_dispositions_proposed",
}
_FIELD_BY_KIND: dict[TransitionKind, str] = {
    "requirements": "requirements_baseline",
    "release_target": "release_target",
    "engineering_baseline": "engineering_baseline",
    "design_review": "design_review",
    "engineering_change": "engineering_change",
    "verification_validation": "verification_validation",
    "release_candidate": "release_candidate",
    "product_telemetry": "product_telemetry",
    "issue_disposition": "issue_disposition",
}
_EVIDENCE_CONTRACT: dict[TransitionKind, tuple[str, str, str]] = {
    "requirements": ("requirements_baseline", "requirements_review", "plm"),
    "release_target": ("release_target", "release_target_review", "plm"),
    "engineering_baseline": (
        "engineering_baseline",
        "baseline_review",
        "plm",
    ),
    "design_review": ("design_review_record", "design_review_attestation", "plm"),
    "engineering_change": (
        "engineering_change_record",
        "change_review_attestation",
        "plm",
    ),
    "verification_validation": (
        "verification_validation_results",
        "independent_validation_attestation",
        "alm",
    ),
    "release_candidate": (
        "release_candidate_record",
        "release_readiness_attestation",
        "plm",
    ),
    "product_telemetry": (
        "product_telemetry_observation",
        "telemetry_admission_attestation",
        "telemetry",
    ),
    "issue_disposition": (
        "issue_disposition_record",
        "issue_disposition_review",
        "plm",
    ),
}


def _command_all_evidence(
    command: _TransitionCommandBase,
) -> tuple[PrimitiveEvidenceRef, ...]:
    return (
        *command.evidence_refs,
        *(actor.certification_evidence for actor in command.actors),
    )


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest(
        [
            item.to_dict()
            for item in sorted(
                evidence_refs, key=lambda evidence: evidence.evidence_ref
            )
        ]
    )


def _validate_command_custody(
    scope: ProductEngineeringLifecycleScope,
    command: _TransitionCommandBase,
    *,
    prior_occurred_at: str | None,
) -> None:
    exact_scope_digest = product_engineering_scope_digest(scope)
    if command.scope_digest != exact_scope_digest:
        raise ValueError(
            "command scope digest does not match the exact lifecycle scope"
        )

    artifact_kind, governance_kind, source = _EVIDENCE_CONTRACT[command.kind]
    evidence_by_ref = {item.evidence_ref: item for item in command.evidence_refs}
    artifact_evidence = evidence_by_ref[command.artifact_evidence_ref]
    governance_evidence = evidence_by_ref[command.governance_evidence_ref]
    source_issuer = {
        "plm": scope.plm_system_ref,
        "alm": scope.alm_system_ref,
        "telemetry": scope.telemetry_system_ref,
    }[source]
    if (
        artifact_evidence.kind != artifact_kind
        or artifact_evidence.issuer_ref != source_issuer
    ):
        raise ValueError("artifact evidence lacks exact kind and source custody")
    if (
        _GRADE_RANK[artifact_evidence.verification_grade]
        < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
    ):
        raise ValueError("artifact evidence must be at least attested")
    if (
        governance_evidence.kind != governance_kind
        or governance_evidence.issuer_ref != scope.spring_authority_ref
        or governance_evidence.verification_grade
        != PrimitiveEvidenceVerificationGrade.VERIFIED
    ):
        raise ValueError("governance evidence lacks exact Spring custody and grade")

    for actor in command.actors:
        certification = actor.certification_evidence
        if certification.issuer_ref != scope.spring_authority_ref:
            raise ValueError("actor certification must remain in Spring custody")

    if prior_occurred_at is not None:
        lower_bound = _parsed_timestamp(prior_occurred_at)
        if any(
            _parsed_timestamp(evidence.observed_at) < lower_bound
            for evidence in _command_all_evidence(command)
        ):
            raise ValueError("new transition evidence cannot predate retained state")


def _actor_ref_for_role(
    command: _TransitionCommandBase,
    role: ActorRole,
) -> str | None:
    return next(
        (actor.actor_ref for actor in command.actors if actor.role == role),
        None,
    )


def _validate_cross_stage_actor_separation(
    command: _TransitionCommandBase,
    history: Sequence[ProductEngineeringTransitionRecord],
) -> None:
    """Enforce independence that necessarily spans two lifecycle commands."""

    prior_actor_by_role = {
        actor.role: actor.actor_ref
        for record in history
        for actor in record.command.actors
    }
    if command.kind == "design_review":
        design_author = prior_actor_by_role.get("design_author")
        independent_reviewer = _actor_ref_for_role(command, "independent_reviewer")
        if design_author is not None and independent_reviewer == design_author:
            raise ValueError(
                "independent design reviewer cannot be the retained design author"
            )
    if command.kind == "verification_validation":
        change_implementer = prior_actor_by_role.get("change_implementer")
        independent_validator = _actor_ref_for_role(command, "independent_validator")
        if (
            change_implementer is not None
            and independent_validator == change_implementer
        ):
            raise ValueError(
                "independent validator cannot be the retained change implementer"
            )


class ProductEngineeringTransitionRecord(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_transition_record.v1"] = Field(
        default="lightbulb.product_engineering_transition_record.v1",
        alias="schema",
    )
    command: ProductEngineeringTransitionCommand
    candidate_digest: Sha256Digest
    record_digest: Sha256Digest

    @model_validator(mode="after")
    def _record_is_sealed(self) -> "ProductEngineeringTransitionRecord":
        if self.command.transition_outcome != "candidate":
            raise ValueError("retained history may contain only validated candidates")
        if self.candidate_digest != self.command.candidate.content_digest:
            raise ValueError("transition record candidate digest is not exact")
        payload = self.to_dict()
        payload.pop("record_digest")
        if self.record_digest != _stable_digest(payload):
            raise ValueError("transition record digest does not match exact content")
        return self


def _make_transition_record(
    command: ProductEngineeringTransitionCommand,
) -> ProductEngineeringTransitionRecord:
    payload = {
        "schema": "lightbulb.product_engineering_transition_record.v1",
        "command": command.to_dict(),
        "candidate_digest": command.candidate.content_digest,
    }
    payload["record_digest"] = _stable_digest(payload)
    return ProductEngineeringTransitionRecord.model_validate(payload)


def _require_exact_set(
    actual: Sequence[str],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(actual) != expected or len(actual) != len(expected):
        raise ValueError(f"{label} traceability must be exact and complete")


def _requirements_trace(
    candidate: RequirementsBaselineCandidate,
) -> tuple[set[str], set[str], dict[str, set[str]]]:
    requirement_refs = {item.requirement_ref for item in candidate.requirements}
    criteria_by_requirement = {
        item.requirement_ref: set(item.acceptance_criteria_refs)
        for item in candidate.requirements
    }
    acceptance_refs = set().union(*criteria_by_requirement.values())
    if sum(len(values) for values in criteria_by_requirement.values()) != len(
        acceptance_refs
    ):
        raise ValueError(
            "acceptance criteria cannot be assigned to multiple requirements"
        )
    return requirement_refs, acceptance_refs, criteria_by_requirement


def _validate_baseline_trace(
    candidate: EngineeringBaselineCandidate,
    requirement_refs: set[str],
) -> tuple[set[str], set[str], set[str]]:
    spec_refs = {item.specification_ref for item in candidate.specifications}
    item_refs = {item.configuration_item_ref for item in candidate.configuration_items}
    component_refs = {item.component_ref for item in candidate.bom_components}
    traced_requirements: set[str] = set()
    for specification in candidate.specifications:
        if not set(specification.requirement_refs) <= requirement_refs:
            raise ValueError("specification references an unknown requirement")
        if not set(specification.configuration_item_refs) <= item_refs:
            raise ValueError("specification references an unknown configuration item")
        traced_requirements.update(specification.requirement_refs)
    if traced_requirements != requirement_refs:
        raise ValueError("specifications must cover every exact requirement")
    traced_specifications: set[str] = set()
    specifications_by_ref = {
        item.specification_ref: item for item in candidate.specifications
    }
    items_by_ref = {
        item.configuration_item_ref: item for item in candidate.configuration_items
    }
    for specification in candidate.specifications:
        for item_ref in specification.configuration_item_refs:
            if (
                specification.specification_ref
                not in items_by_ref[item_ref].specification_refs
            ):
                raise ValueError("specification/configuration links must be reciprocal")
    for item in candidate.configuration_items:
        if not set(item.specification_refs) <= spec_refs:
            raise ValueError("configuration item references an unknown specification")
        traced_specifications.update(item.specification_refs)
        for specification_ref in item.specification_refs:
            specification = specifications_by_ref[specification_ref]
            if item.configuration_item_ref not in specification.configuration_item_refs:
                raise ValueError("specification/configuration links must be reciprocal")
    if traced_specifications != spec_refs:
        raise ValueError("configuration must implement every exact specification")
    traced_items: set[str] = set()
    for component in candidate.bom_components:
        if not set(component.configuration_item_refs) <= item_refs:
            raise ValueError("BOM component references an unknown configuration item")
        traced_items.update(component.configuration_item_refs)
    if traced_items != item_refs:
        raise ValueError("BOM must cover every exact configuration item")
    return spec_refs, item_refs, component_refs


def _validate_stage_semantics(
    scope: ProductEngineeringLifecycleScope,
    command: ProductEngineeringTransitionCommand,
    artifacts: Mapping[str, _ContentBoundCandidate],
    *,
    prior_occurred_at: str | None,
) -> None:
    candidate = command.candidate
    occurred_at = _parsed_timestamp(command.occurred_at)

    if command.kind == "requirements":
        if not isinstance(candidate, RequirementsBaselineCandidate):
            raise ValueError("requirements command carries the wrong candidate type")
        _requirements_trace(candidate)
        return

    requirements = artifacts.get("requirements_baseline")
    if not isinstance(requirements, RequirementsBaselineCandidate):
        raise ValueError("requirements baseline is missing from retained state")
    requirement_refs, acceptance_refs, criteria_by_requirement = _requirements_trace(
        requirements
    )

    if command.kind == "release_target":
        if not isinstance(candidate, ReleaseTargetCandidate):
            raise ValueError("release-target command carries the wrong candidate type")
        if candidate.requirements_baseline_digest != requirements.content_digest:
            raise ValueError(
                "release target does not bind the exact requirements baseline"
            )
        _require_exact_set(
            candidate.requirement_refs,
            requirement_refs,
            label="release-target requirement",
        )
        if _parsed_timestamp(candidate.change_cutoff_at) < occurred_at:
            raise ValueError("release change cutoff cannot predate targeting")
        if _parsed_timestamp(candidate.planned_release_at) <= occurred_at:
            raise ValueError("planned release must follow release targeting")
        return

    release_target = artifacts.get("release_target")
    if not isinstance(release_target, ReleaseTargetCandidate):
        raise ValueError("release target is missing from retained state")

    if command.kind == "engineering_baseline":
        if not isinstance(candidate, EngineeringBaselineCandidate):
            raise ValueError("baseline command carries the wrong candidate type")
        if candidate.configuration_ref != scope.configuration_ref:
            raise ValueError("engineering baseline uses the wrong configuration")
        if (
            candidate.requirements_baseline_digest != requirements.content_digest
            or candidate.release_target_digest != release_target.content_digest
        ):
            raise ValueError(
                "engineering baseline does not bind its exact predecessors"
            )
        _validate_baseline_trace(candidate, requirement_refs)
        return

    baseline = artifacts.get("engineering_baseline")
    if not isinstance(baseline, EngineeringBaselineCandidate):
        raise ValueError("engineering baseline is missing from retained state")
    spec_refs = {item.specification_ref for item in baseline.specifications}
    item_refs = {item.configuration_item_ref for item in baseline.configuration_items}
    component_refs = {item.component_ref for item in baseline.bom_components}

    if command.kind == "design_review":
        if not isinstance(candidate, DesignReviewCandidate):
            raise ValueError("design-review command carries the wrong candidate type")
        if candidate.engineering_baseline_digest != baseline.content_digest:
            raise ValueError("design review does not bind the exact baseline")
        _require_exact_set(
            candidate.covered_requirement_refs,
            requirement_refs,
            label="design-review requirement",
        )
        _require_exact_set(
            candidate.covered_specification_refs,
            spec_refs,
            label="design-review specification",
        )
        _require_exact_set(
            candidate.covered_configuration_item_refs,
            item_refs,
            label="design-review configuration-item",
        )
        _require_exact_set(
            candidate.covered_component_refs,
            component_refs,
            label="design-review component",
        )
        if candidate.recommendation != "candidate_ready":
            raise ValueError(
                "design review must recommend a candidate before advancing"
            )
        return

    design_review = artifacts.get("design_review")
    if not isinstance(design_review, DesignReviewCandidate):
        raise ValueError("design review is missing from retained state")

    if command.kind == "engineering_change":
        if not isinstance(candidate, EngineeringChangeCandidate):
            raise ValueError(
                "engineering-change command carries the wrong candidate type"
            )
        if candidate.from_baseline_digest != baseline.content_digest:
            raise ValueError("engineering change does not bind the immutable baseline")
        proposed = candidate.proposed_baseline
        if (
            proposed.configuration_ref != scope.configuration_ref
            or proposed.requirements_baseline_digest != requirements.content_digest
            or proposed.release_target_digest != release_target.content_digest
        ):
            raise ValueError("proposed baseline does not retain exact governed scope")
        if proposed.baseline_ref == baseline.baseline_ref:
            raise ValueError("proposed baseline requires a new immutable reference")
        if proposed.baseline_ref in {
            requirements.baseline_ref,
            release_target.release_target_ref,
            design_review.review_ref,
        }:
            raise ValueError(
                "proposed baseline reference collides with retained history"
            )
        if proposed.revision <= baseline.revision:
            raise ValueError("proposed baseline revision must advance monotonically")
        if proposed.content_digest in {
            requirements.content_digest,
            release_target.content_digest,
            baseline.content_digest,
            design_review.content_digest,
        }:
            raise ValueError("proposed baseline content collides with retained history")
        proposed_spec_refs, proposed_item_refs, proposed_component_refs = (
            _validate_baseline_trace(proposed, requirement_refs)
        )
        if (
            proposed_spec_refs != spec_refs
            or proposed_item_refs != item_refs
            or proposed_component_refs != component_refs
        ):
            raise ValueError("v1 engineering change must retain exact trace identities")

        old_specs = {item.specification_ref: item for item in baseline.specifications}
        new_specs = {item.specification_ref: item for item in proposed.specifications}
        old_items = {
            item.configuration_item_ref: item for item in baseline.configuration_items
        }
        new_items = {
            item.configuration_item_ref: item for item in proposed.configuration_items
        }
        old_components = {item.component_ref: item for item in baseline.bom_components}
        new_components = {item.component_ref: item for item in proposed.bom_components}
        changed_specs = {ref for ref in spec_refs if old_specs[ref] != new_specs[ref]}
        changed_items = {ref for ref in item_refs if old_items[ref] != new_items[ref]}
        changed_components = {
            ref for ref in component_refs if old_components[ref] != new_components[ref]
        }
        if any(
            new_specs[ref].revision <= old_specs[ref].revision for ref in changed_specs
        ):
            raise ValueError("changed specification revisions must advance")
        if any(
            new_items[ref].revision <= old_items[ref].revision for ref in changed_items
        ):
            raise ValueError("changed configuration-item revisions must advance")
        if any(
            new_components[ref].revision <= old_components[ref].revision
            for ref in changed_components
        ):
            raise ValueError("changed BOM-component revisions must advance")
        if set(candidate.impacted_specification_refs) != changed_specs:
            raise ValueError("change impact must equal changed specifications")
        if set(candidate.impacted_configuration_item_refs) != changed_items:
            raise ValueError("change impact must equal changed configuration items")
        if set(candidate.impacted_component_refs) != changed_components:
            raise ValueError("change impact must equal changed BOM components")

        impacted_specs = set(changed_specs)
        for item_ref in changed_items:
            impacted_specs.update(new_items[item_ref].specification_refs)
        for component_ref in changed_components:
            for item_ref in new_components[component_ref].configuration_item_refs:
                impacted_specs.update(new_items[item_ref].specification_refs)
        impacted_requirements = {
            requirement_ref
            for specification_ref in impacted_specs
            for requirement_ref in new_specs[specification_ref].requirement_refs
        }
        if set(candidate.impacted_requirement_refs) != impacted_requirements:
            raise ValueError("change impact must equal traced impacted requirements")
        if not set(candidate.impacted_requirement_refs) <= requirement_refs:
            raise ValueError("engineering change references an unknown requirement")
        if not set(candidate.impacted_specification_refs) <= spec_refs:
            raise ValueError("engineering change references an unknown specification")
        if not set(candidate.impacted_configuration_item_refs) <= item_refs:
            raise ValueError(
                "engineering change references an unknown configuration item"
            )
        if not set(candidate.impacted_component_refs) <= component_refs:
            raise ValueError("engineering change references an unknown BOM component")
        return

    engineering_change = artifacts.get("engineering_change")
    if not isinstance(engineering_change, EngineeringChangeCandidate):
        raise ValueError("engineering change is missing from retained state")

    if command.kind == "verification_validation":
        if not isinstance(candidate, VerificationValidationCandidate):
            raise ValueError("V&V command carries the wrong candidate type")
        if (
            candidate.engineering_change_digest != engineering_change.content_digest
            or candidate.target_baseline_digest
            != engineering_change.proposed_baseline_digest
        ):
            raise ValueError("V&V does not bind the exact change and proposed baseline")
        if any(test.result != "passed" for test in candidate.tests):
            raise ValueError("every verification and validation test must pass")
        if {test.kind for test in candidate.tests} != {"verification", "validation"}:
            raise ValueError("both verification and validation evidence are required")
        tested_requirements: set[str] = set()
        tested_acceptance: set[str] = set()
        tested_specifications: set[str] = set()
        coverage_by_kind = {
            "verification": {
                "requirements": set(),
                "acceptance": set(),
                "specifications": set(),
            },
            "validation": {
                "requirements": set(),
                "acceptance": set(),
                "specifications": set(),
            },
        }
        for test in candidate.tests:
            test_requirements = set(test.requirement_refs)
            if not test_requirements <= requirement_refs:
                raise ValueError("test references an unknown requirement")
            allowed_criteria = set().union(
                *(criteria_by_requirement[ref] for ref in test_requirements)
            )
            if not set(test.acceptance_criteria_refs) <= allowed_criteria:
                raise ValueError(
                    "test acceptance criteria do not match its requirements"
                )
            if not set(test.specification_refs) <= spec_refs:
                raise ValueError("test references an unknown specification")
            requirements_from_specifications = {
                requirement_ref
                for specification in engineering_change.proposed_baseline.specifications
                if specification.specification_ref in test.specification_refs
                for requirement_ref in specification.requirement_refs
            }
            if requirements_from_specifications != test_requirements:
                raise ValueError("test requirement/specification trace must be exact")
            tested_requirements.update(test_requirements)
            tested_acceptance.update(test.acceptance_criteria_refs)
            tested_specifications.update(test.specification_refs)
            kind_coverage = coverage_by_kind[test.kind]
            kind_coverage["requirements"].update(test_requirements)
            kind_coverage["acceptance"].update(test.acceptance_criteria_refs)
            kind_coverage["specifications"].update(test.specification_refs)
        if tested_requirements != requirement_refs:
            raise ValueError("V&V must cover every exact requirement")
        if tested_acceptance != acceptance_refs:
            raise ValueError("V&V must cover every exact acceptance criterion")
        if tested_specifications != spec_refs:
            raise ValueError("V&V must cover every exact specification")
        for activity_kind, coverage in coverage_by_kind.items():
            if coverage["requirements"] != requirement_refs:
                raise ValueError(f"{activity_kind} must cover every exact requirement")
            if coverage["acceptance"] != acceptance_refs:
                raise ValueError(
                    f"{activity_kind} must cover every exact acceptance criterion"
                )
            if coverage["specifications"] != spec_refs:
                raise ValueError(
                    f"{activity_kind} must cover every exact specification"
                )
        return

    verification_validation = artifacts.get("verification_validation")
    if not isinstance(verification_validation, VerificationValidationCandidate):
        raise ValueError("V&V is missing from retained state")

    if command.kind == "release_candidate":
        if not isinstance(candidate, ReleaseCandidateRecord):
            raise ValueError("release command carries the wrong candidate type")
        if (
            candidate.target_baseline_digest
            != engineering_change.proposed_baseline_digest
            or candidate.design_review_digest != design_review.content_digest
            or candidate.engineering_change_digest != engineering_change.content_digest
            or candidate.verification_validation_digest
            != verification_validation.content_digest
        ):
            raise ValueError("release candidate does not bind its exact governed chain")
        _require_exact_set(
            candidate.traced_requirement_refs,
            requirement_refs,
            label="release-candidate requirement",
        )
        _require_exact_set(
            candidate.traced_specification_refs,
            spec_refs,
            label="release-candidate specification",
        )
        if candidate.known_blocker_refs:
            raise ValueError("release candidate cannot retain known blockers")
        return

    release_candidate = artifacts.get("release_candidate")
    if not isinstance(release_candidate, ReleaseCandidateRecord):
        raise ValueError("release candidate is missing from retained state")

    if command.kind == "product_telemetry":
        if not isinstance(candidate, ProductTelemetryCandidate):
            raise ValueError("telemetry command carries the wrong candidate type")
        if candidate.release_candidate_digest != release_candidate.content_digest:
            raise ValueError("telemetry does not bind the exact release candidate")
        if prior_occurred_at is None or _parsed_timestamp(
            candidate.window_started_at
        ) < _parsed_timestamp(prior_occurred_at):
            raise ValueError("telemetry window cannot predate the release candidate")
        if _parsed_timestamp(candidate.window_ended_at) > occurred_at:
            raise ValueError("telemetry window cannot end after observation")
        if any(signal.threshold_status == "breached" for signal in candidate.signals):
            raise ValueError("breached telemetry must block candidate advancement")
        observed_requirements = {
            requirement_ref
            for signal in candidate.signals
            for requirement_ref in signal.requirement_refs
        }
        if observed_requirements != requirement_refs:
            raise ValueError("telemetry must cover every exact requirement")
        return

    telemetry = artifacts.get("product_telemetry")
    if not isinstance(telemetry, ProductTelemetryCandidate):
        raise ValueError("product telemetry is missing from retained state")

    if command.kind == "issue_disposition":
        if not isinstance(candidate, IssueDispositionCandidate):
            raise ValueError("issue command carries the wrong candidate type")
        if (
            candidate.release_candidate_digest != release_candidate.content_digest
            or candidate.telemetry_digest != telemetry.content_digest
        ):
            raise ValueError("issue disposition does not bind release and telemetry")
        signal_refs = {item.signal_ref for item in telemetry.signals}
        warning_refs = {
            item.signal_ref
            for item in telemetry.signals
            if item.threshold_status == "warning"
        }
        disposition_signal_refs: set[str] = set()
        for issue in candidate.issues:
            if not set(issue.linked_requirement_refs) <= requirement_refs:
                raise ValueError("issue references an unknown requirement")
            if not set(issue.telemetry_signal_refs) <= signal_refs:
                raise ValueError("issue references an unknown telemetry signal")
            signal_requirements = {
                requirement_ref
                for signal in telemetry.signals
                if signal.signal_ref in issue.telemetry_signal_refs
                for requirement_ref in signal.requirement_refs
            }
            if signal_requirements != set(issue.linked_requirement_refs):
                raise ValueError("issue requirement/telemetry trace must be exact")
            disposition_signal_refs.update(issue.telemetry_signal_refs)
        if not warning_refs <= disposition_signal_refs:
            raise ValueError("every warning telemetry signal requires a disposition")
        return

    raise ValueError("unsupported lifecycle transition kind")


def _snapshot_payload(
    scope: ProductEngineeringLifecycleScope,
    history: Sequence[ProductEngineeringTransitionRecord],
    artifacts: Mapping[str, _ContentBoundCandidate],
) -> dict[str, Any]:
    if not history:
        raise ValueError("a lifecycle snapshot requires retained history")
    payload: dict[str, Any] = {
        "schema": PRODUCT_ENGINEERING_LIFECYCLE_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "revision": len(history),
        "phase": _PHASE_BY_KIND[history[-1].command.kind],
        "transition_history": [item.to_dict() for item in history],
    }
    for field_name in _FIELD_BY_KIND.values():
        artifact = artifacts.get(field_name)
        if artifact is not None:
            payload[field_name] = artifact.to_dict()
    return payload


def _prefix_snapshot_digest(
    scope: ProductEngineeringLifecycleScope,
    history: Sequence[ProductEngineeringTransitionRecord],
    artifacts: Mapping[str, _ContentBoundCandidate],
) -> str:
    return _stable_digest(_snapshot_payload(scope, history, artifacts))


class ProductEngineeringLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_lifecycle_snapshot.v1"] = Field(
        default=PRODUCT_ENGINEERING_LIFECYCLE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: ProductEngineeringLifecycleScope
    revision: int = Field(ge=1, le=MAX_PRODUCT_ENGINEERING_TRANSITIONS)
    phase: LifecyclePhase
    transition_history: tuple[ProductEngineeringTransitionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_PRODUCT_ENGINEERING_TRANSITIONS,
    )
    requirements_baseline: RequirementsBaselineCandidate | None = None
    release_target: ReleaseTargetCandidate | None = None
    engineering_baseline: EngineeringBaselineCandidate | None = None
    design_review: DesignReviewCandidate | None = None
    engineering_change: EngineeringChangeCandidate | None = None
    verification_validation: VerificationValidationCandidate | None = None
    release_candidate: ReleaseCandidateRecord | None = None
    product_telemetry: ProductTelemetryCandidate | None = None
    issue_disposition: IssueDispositionCandidate | None = None
    state_digest: Sha256Digest

    @field_validator("transition_history", mode="before")
    @classmethod
    def _history_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _history_replays_to_exact_state(self) -> "ProductEngineeringLifecycleSnapshot":
        if self.revision != len(self.transition_history):
            raise ValueError("snapshot revision must equal retained transition count")

        artifacts: dict[str, _ContentBoundCandidate] = {}
        prefix: list[ProductEngineeringTransitionRecord] = []
        prior_digest = GENESIS_SNAPSHOT_DIGEST
        prior_occurred_at: str | None = None
        seen_commands: set[str] = set()
        seen_idempotency: set[str] = set()
        seen_evidence_refs: set[str] = set()
        seen_evidence_envelopes: set[str] = set()
        seen_evidence_content: set[str] = set()
        primary_refs: set[str] = set()
        artifact_digests: set[str] = set()

        for index, record in enumerate(self.transition_history):
            command = record.command
            if command.kind != _STAGE_ORDER[index]:
                raise ValueError("transition history is out of lifecycle sequence")
            if command.expected_revision != index:
                raise ValueError("retained command has the wrong expected revision")
            if command.expected_snapshot_digest != prior_digest:
                raise ValueError("retained command has a stale predecessor digest")
            if command.command_ref in seen_commands:
                raise ValueError("command reference cannot be reused")
            if command.idempotency_key in seen_idempotency:
                raise ValueError("idempotency key cannot be reused in retained history")
            if prior_occurred_at is not None and _parsed_timestamp(
                command.occurred_at
            ) <= _parsed_timestamp(prior_occurred_at):
                raise ValueError("transition time must increase monotonically")

            _validate_command_custody(
                self.scope,
                command,
                prior_occurred_at=prior_occurred_at,
            )
            current_evidence = _command_all_evidence(command)
            current_refs = {item.evidence_ref for item in current_evidence}
            current_envelopes = {
                _stable_digest(item.to_dict()) for item in current_evidence
            }
            current_content = {item.sha256 for item in current_evidence}
            if current_refs & seen_evidence_refs:
                raise ValueError(
                    "evidence reference cannot be reused across transitions"
                )
            if current_envelopes & seen_evidence_envelopes:
                raise ValueError("evidence envelope cannot be replayed")
            if current_content & seen_evidence_content:
                raise ValueError("evidence content cannot be reused across transitions")

            _validate_cross_stage_actor_separation(command, prefix)
            _validate_stage_semantics(
                self.scope,
                command,
                artifacts,
                prior_occurred_at=prior_occurred_at,
            )
            candidate = command.candidate
            primary_ref = _candidate_primary_ref(candidate)
            if primary_ref in primary_refs:
                raise ValueError(
                    "primary artifact reference cannot collide across stages"
                )
            if candidate.content_digest in artifact_digests:
                raise ValueError(
                    "candidate content digest cannot be reused across stages"
                )
            artifacts[_FIELD_BY_KIND[command.kind]] = candidate
            prefix.append(record)
            prior_digest = _prefix_snapshot_digest(self.scope, prefix, artifacts)
            prior_occurred_at = command.occurred_at
            seen_commands.add(command.command_ref)
            seen_idempotency.add(command.idempotency_key)
            seen_evidence_refs.update(current_refs)
            seen_evidence_envelopes.update(current_envelopes)
            seen_evidence_content.update(current_content)
            primary_refs.add(primary_ref)
            artifact_digests.add(candidate.content_digest)

        if self.phase != _PHASE_BY_KIND[self.transition_history[-1].command.kind]:
            raise ValueError("snapshot phase does not match retained history")
        for field_name in _FIELD_BY_KIND.values():
            if getattr(self, field_name) != artifacts.get(field_name):
                raise ValueError(
                    f"snapshot {field_name} does not match retained history"
                )
        if self.state_digest != prior_digest:
            raise ValueError("state_digest does not match semantically replayed state")
        return self


def _candidate_primary_ref(candidate: _ContentBoundCandidate) -> str:
    for field_name in (
        "baseline_ref",
        "release_target_ref",
        "review_ref",
        "change_ref",
        "campaign_ref",
        "candidate_ref",
        "observation_ref",
        "disposition_ref",
    ):
        value = getattr(candidate, field_name, None)
        if value is not None:
            return str(value)
    raise ValueError("candidate lacks a primary artifact reference")


def product_engineering_snapshot_digest(
    snapshot: ProductEngineeringLifecycleSnapshot | Mapping[str, Any],
    *,
    validate: bool = True,
) -> str:
    payload = (
        snapshot.to_dict()
        if isinstance(snapshot, ProductEngineeringLifecycleSnapshot)
        else deepcopy(dict(snapshot))
    )
    if validate:
        parsed = ProductEngineeringLifecycleSnapshot.model_validate(payload)
        payload = parsed.to_dict()
    payload.pop("state_digest", None)
    return _stable_digest(payload)


class ProductEngineeringLifecycleInput(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_lifecycle_input.v1"] = Field(
        default=PRODUCT_ENGINEERING_LIFECYCLE_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ProductEngineeringLifecycleScope
    command: ProductEngineeringTransitionCommand
    snapshot: ProductEngineeringLifecycleSnapshot | None = None

    @model_validator(mode="after")
    def _snapshot_scope_is_exact(self) -> "ProductEngineeringLifecycleInput":
        if self.snapshot is not None and self.snapshot.scope != self.scope:
            raise ValueError("snapshot scope must exactly equal lifecycle input scope")
        return self


TransitionReceiptStatus = Literal[
    "candidate_materialized",
    "duplicate",
    "rejected",
    "in_doubt",
]
TransitionRecovery = Literal[
    "none",
    "do_not_replay",
    "correct_input",
    "refresh_snapshot",
    "manual_reconcile",
]


class ProductEngineeringTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_transition_receipt.v1"] = Field(
        default=PRODUCT_ENGINEERING_TRANSITION_RECEIPT_SCHEMA,
        alias="schema",
    )
    command_ref: OpaqueRef
    kind: TransitionKind
    status: TransitionReceiptStatus
    request_digest: Sha256Digest
    evidence_digest: Sha256Digest
    from_revision: int = Field(ge=0, le=MAX_PRODUCT_ENGINEERING_TRANSITIONS)
    to_revision: int = Field(ge=0, le=MAX_PRODUCT_ENGINEERING_TRANSITIONS)
    from_snapshot_digest: Sha256Digest
    to_snapshot_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=500)
    recovery: TransitionRecovery

    @model_validator(mode="after")
    def _receipt_is_honest(self) -> "ProductEngineeringTransitionReceipt":
        if self.status == "candidate_materialized":
            if (
                self.to_revision != self.from_revision + 1
                or self.to_snapshot_digest == self.from_snapshot_digest
                or self.rejection_code is not None
                or self.recovery != "none"
            ):
                raise ValueError("candidate receipt must prove one bounded projection")
        else:
            if (
                self.to_revision != self.from_revision
                or self.to_snapshot_digest != self.from_snapshot_digest
                or self.rejection_code is None
                or self.recovery == "none"
            ):
                raise ValueError(
                    "non-materialized receipt must retain exact prior state"
                )
        if self.status == "in_doubt" and self.recovery != "manual_reconcile":
            raise ValueError("in-doubt transition must require manual reconciliation")
        return self


class ProductEngineeringLifecycleResult(_StrictModel):
    schema_id: Literal["lightbulb.product_engineering_lifecycle_result.v1"] = Field(
        default=PRODUCT_ENGINEERING_LIFECYCLE_RESULT_SCHEMA,
        alias="schema",
    )
    candidate_validated: bool
    live_systems_changed: Literal[False] = False
    authoritative_persistence_claimed: Literal[False] = False
    authoritative_release_claimed: Literal[False] = False
    risk_acceptance_or_issue_closure_claimed: Literal[False] = False
    snapshot: ProductEngineeringLifecycleSnapshot | None = None
    transition_receipt: ProductEngineeringTransitionReceipt

    @model_validator(mode="after")
    def _result_matches_receipt(self) -> "ProductEngineeringLifecycleResult":
        materialized = self.transition_receipt.status == "candidate_materialized"
        if self.candidate_validated != materialized:
            raise ValueError("candidate_validated must match receipt status")
        if materialized:
            if (
                self.snapshot is None
                or self.snapshot.revision != self.transition_receipt.to_revision
                or self.snapshot.state_digest
                != self.transition_receipt.to_snapshot_digest
            ):
                raise ValueError(
                    "materialized result must carry the exact new snapshot"
                )
        elif self.snapshot is not None and (
            self.snapshot.revision != self.transition_receipt.to_revision
            or self.snapshot.state_digest != self.transition_receipt.to_snapshot_digest
        ):
            raise ValueError("blocked result may carry only the unchanged snapshot")
        return self


PRODUCT_ENGINEERING_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="product_engineering_candidate_materialization",
    tool="sdk.product_engineering.propose_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)


class _TransitionRejected(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        recovery: TransitionRecovery,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recovery = recovery


def _prior_coordinates(
    snapshot: ProductEngineeringLifecycleSnapshot | None,
) -> tuple[int, str]:
    if snapshot is None:
        return 0, GENESIS_SNAPSHOT_DIGEST
    return snapshot.revision, snapshot.state_digest


def _unchanged_result(
    scope: ProductEngineeringLifecycleScope,
    command: ProductEngineeringTransitionCommand,
    snapshot: ProductEngineeringLifecycleSnapshot | None,
    *,
    status: Literal["duplicate", "rejected", "in_doubt"],
    code: str,
    message: str,
    recovery: TransitionRecovery,
) -> ProductEngineeringLifecycleResult:
    del scope
    revision, digest = _prior_coordinates(snapshot)
    receipt = ProductEngineeringTransitionReceipt(
        command_ref=command.command_ref,
        kind=command.kind,
        status=status,
        request_digest=command.request_digest,
        evidence_digest=_evidence_digest(_command_all_evidence(command)),
        from_revision=revision,
        to_revision=revision,
        from_snapshot_digest=digest,
        to_snapshot_digest=digest,
        rejection_code=code,
        message=message,
        recovery=recovery,
    )
    return ProductEngineeringLifecycleResult(
        candidate_validated=False,
        snapshot=snapshot,
        transition_receipt=receipt,
    )


def _check_new_command_fences(
    scope: ProductEngineeringLifecycleScope,
    command: ProductEngineeringTransitionCommand,
    snapshot: ProductEngineeringLifecycleSnapshot | None,
) -> None:
    revision, digest = _prior_coordinates(snapshot)
    if snapshot is not None:
        for record in snapshot.transition_history:
            retained = record.command
            if retained.idempotency_key == command.idempotency_key:
                if retained.request_digest == command.request_digest:
                    raise _TransitionRejected(
                        "DUPLICATE_REQUEST",
                        "The exact idempotent request is already retained.",
                        "do_not_replay",
                    )
                raise _TransitionRejected(
                    "IDEMPOTENCY_CONFLICT",
                    "Idempotency key was reused for different command content.",
                    "do_not_replay",
                )
            if retained.command_ref == command.command_ref:
                raise _TransitionRejected(
                    "COMMAND_REF_CONFLICT",
                    "Command reference is already retained with different content.",
                    "do_not_replay",
                )
    if revision >= MAX_PRODUCT_ENGINEERING_TRANSITIONS:
        raise _TransitionRejected(
            "LIFECYCLE_COMPLETE",
            "The bounded product-engineering lifecycle is already complete.",
            "do_not_replay",
        )
    expected_kind = _STAGE_ORDER[revision]
    if command.kind != expected_kind:
        raise _TransitionRejected(
            "OUT_OF_SEQUENCE_TRANSITION",
            f"Revision {revision} requires transition {expected_kind}.",
            "refresh_snapshot",
        )
    if command.expected_revision != revision:
        raise _TransitionRejected(
            "STALE_REVISION",
            "Command expected_revision does not match retained state.",
            "refresh_snapshot",
        )
    if command.expected_snapshot_digest != digest:
        raise _TransitionRejected(
            "STALE_SNAPSHOT_DIGEST",
            "Command predecessor digest does not match retained state.",
            "refresh_snapshot",
        )

    prior_occurred_at = (
        snapshot.transition_history[-1].command.occurred_at
        if snapshot is not None
        else None
    )
    _validate_command_custody(
        scope,
        command,
        prior_occurred_at=prior_occurred_at,
    )
    if prior_occurred_at is not None and _parsed_timestamp(
        command.occurred_at
    ) <= _parsed_timestamp(prior_occurred_at):
        raise _TransitionRejected(
            "NON_MONOTONIC_TRANSITION_TIME",
            "Transition time must be later than retained state.",
            "correct_input",
        )

    if snapshot is None:
        return

    try:
        _validate_cross_stage_actor_separation(
            command,
            snapshot.transition_history,
        )
    except ValueError as exc:
        raise _TransitionRejected(
            "STRUCTURAL_SOD_VIOLATION",
            str(exc),
            "correct_input",
        ) from exc

    retained_evidence = {
        evidence.evidence_ref
        for record in snapshot.transition_history
        for evidence in _command_all_evidence(record.command)
    }
    retained_envelopes = {
        _stable_digest(evidence.to_dict())
        for record in snapshot.transition_history
        for evidence in _command_all_evidence(record.command)
    }
    retained_content = {
        evidence.sha256
        for record in snapshot.transition_history
        for evidence in _command_all_evidence(record.command)
    }
    current_evidence = _command_all_evidence(command)
    if retained_evidence & {item.evidence_ref for item in current_evidence}:
        raise _TransitionRejected(
            "EVIDENCE_REF_REUSED",
            "Transition evidence reference was already consumed.",
            "correct_input",
        )
    if retained_envelopes & {
        _stable_digest(item.to_dict()) for item in current_evidence
    }:
        raise _TransitionRejected(
            "EVIDENCE_ENVELOPE_REPLAYED",
            "Transition evidence envelope was already consumed.",
            "correct_input",
        )
    if retained_content & {item.sha256 for item in current_evidence}:
        raise _TransitionRejected(
            "EVIDENCE_CONTENT_REUSED",
            "Transition evidence content was already consumed.",
            "correct_input",
        )

    prior_primary_refs = {
        _candidate_primary_ref(record.command.candidate)
        for record in snapshot.transition_history
    }
    if _candidate_primary_ref(command.candidate) in prior_primary_refs:
        raise _TransitionRejected(
            "ARTIFACT_REF_COLLISION",
            "Primary artifact reference collides with retained history.",
            "correct_input",
        )
    if command.candidate.content_digest in {
        record.command.candidate.content_digest
        for record in snapshot.transition_history
    }:
        raise _TransitionRejected(
            "ARTIFACT_CONTENT_REUSED",
            "Candidate content digest collides with retained history.",
            "correct_input",
        )


def _materialize_snapshot(
    scope: ProductEngineeringLifecycleScope,
    command: ProductEngineeringTransitionCommand,
    snapshot: ProductEngineeringLifecycleSnapshot | None,
) -> ProductEngineeringLifecycleSnapshot:
    history = list(snapshot.transition_history) if snapshot is not None else []
    artifacts: dict[str, _ContentBoundCandidate] = {}
    if snapshot is not None:
        for field_name in _FIELD_BY_KIND.values():
            artifact = getattr(snapshot, field_name)
            if artifact is not None:
                artifacts[field_name] = artifact

    prior_occurred_at = history[-1].command.occurred_at if history else None
    try:
        _validate_stage_semantics(
            scope,
            command,
            artifacts,
            prior_occurred_at=prior_occurred_at,
        )
    except ValueError as exc:
        raise _TransitionRejected(
            "INVALID_TRANSITION_SEMANTICS",
            str(exc),
            "correct_input",
        ) from exc

    record = _make_transition_record(command)
    history.append(record)
    artifacts[_FIELD_BY_KIND[command.kind]] = command.candidate
    payload = _snapshot_payload(scope, history, artifacts)
    payload["state_digest"] = _stable_digest(payload)
    return ProductEngineeringLifecycleSnapshot.model_validate(payload)


def materialize_product_engineering_candidate(
    inputs: ProductEngineeringLifecycleInput | Mapping[str, Any],
) -> ProductEngineeringLifecycleResult:
    """Validate and retain one SDK candidate without authoritative effects."""

    parsed = revalidate_model_boundary(
        ProductEngineeringLifecycleInput,
        inputs,
    )
    scope = parsed.scope
    command = parsed.command
    snapshot = parsed.snapshot

    try:
        _validate_command_custody(
            scope,
            command,
            prior_occurred_at=None,
        )
    except ValueError as exc:
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status="rejected",
            code="INVALID_EVIDENCE_CUSTODY",
            message=str(exc),
            recovery="correct_input",
        )

    if command.transition_outcome == "in_doubt":
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status="in_doubt",
            code="AMBIGUOUS_EXTERNAL_OUTCOME",
            message=(
                "Upstream PLM/ALM outcome is ambiguous; reconcile Spring's durable "
                "journal before any continuation."
            ),
            recovery="manual_reconcile",
        )

    try:
        _check_new_command_fences(scope, command, snapshot)
    except _TransitionRejected as exc:
        status: Literal["duplicate", "rejected"] = (
            "duplicate" if exc.code == "DUPLICATE_REQUEST" else "rejected"
        )
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status=status,
            code=exc.code,
            message=exc.message,
            recovery=exc.recovery,
        )
    except ValueError as exc:
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status="rejected",
            code="INVALID_TRANSITION_HEADER",
            message=str(exc),
            recovery="correct_input",
        )

    if command.transition_outcome == "rejected":
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status="rejected",
            code="UPSTREAM_REJECTED",
            message="Upstream source reported rejection; retained state was not advanced.",
            recovery="do_not_replay",
        )

    try:
        new_snapshot = _materialize_snapshot(scope, command, snapshot)
    except _TransitionRejected as exc:
        return _unchanged_result(
            scope,
            command,
            snapshot,
            status="rejected",
            code=exc.code,
            message=exc.message,
            recovery=exc.recovery,
        )

    from_revision, from_digest = _prior_coordinates(snapshot)
    receipt = ProductEngineeringTransitionReceipt(
        command_ref=command.command_ref,
        kind=command.kind,
        status="candidate_materialized",
        request_digest=command.request_digest,
        evidence_digest=_evidence_digest(_command_all_evidence(command)),
        from_revision=from_revision,
        to_revision=new_snapshot.revision,
        from_snapshot_digest=from_digest,
        to_snapshot_digest=new_snapshot.state_digest,
        message=(
            "Deterministic SDK candidate materialized; no approval, persistence, "
            "release, closure, or provider effect is claimed."
        ),
        recovery="none",
    )
    return ProductEngineeringLifecycleResult(
        candidate_validated=True,
        snapshot=new_snapshot,
        transition_receipt=receipt,
    )


def _example_evidence(
    evidence_ref: str,
    *,
    kind: str,
    issuer_ref: str,
    subject_ref: str,
    occurred_at: str,
    grade: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": issuer_ref,
        "subject_ref": subject_ref,
        "sha256": "0" * 64,
        "observed_at": occurred_at,
        "effective_at": occurred_at,
        "verification_grade": grade,
        "classification": "confidential",
        "retention_policy": "product-lifecycle-7y",
    }


def _example_actor(
    actor_ref: str,
    role: ActorRole,
    *,
    suffix: str,
    occurred_at: str,
) -> dict[str, Any]:
    return {
        "actor_ref": actor_ref,
        "role": role,
        "certification_ref": f"cert-{suffix}",
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2027-08-01T00:00:00Z",
        "certification_evidence": _example_evidence(
            f"evidence-cert-{suffix}",
            kind="actor_certification",
            issuer_ref="spring-product-authority-example",
            subject_ref=actor_ref,
            occurred_at=occurred_at,
            grade="verified",
        ),
    }


def _product_engineering_example_inputs() -> dict[str, Any]:
    scope = ProductEngineeringLifecycleScope(
        tenant_ref="authenticated",
        company_ref="selected",
        project_ref="workflow-improvement",
        project_id="11111111-1111-4111-8111-111111111111",
        product_ref="product-example",
        configuration_ref="configuration-example",
        release_ref="release-example",
        spring_authority_ref="spring-product-authority-example",
        plm_system_ref="plm-example",
        alm_system_ref="alm-example",
        telemetry_system_ref="telemetry-example",
    )
    occurred_at = "2026-08-25T12:00:00Z"
    command_ref = "requirements-command-example"
    command = seal_product_engineering_command(
        {
            "schema": PRODUCT_ENGINEERING_COMMAND_SCHEMA,
            "kind": "requirements",
            "command_ref": command_ref,
            "scope_digest": product_engineering_scope_digest(scope),
            "requested_by_ref": "requirement-author-example",
            "idempotency_key": "requirements-idempotency-example",
            "expected_revision": 0,
            "expected_snapshot_digest": GENESIS_SNAPSHOT_DIGEST,
            "occurred_at": occurred_at,
            "transition_outcome": "candidate",
            "artifact_evidence_ref": "evidence-requirements-example",
            "governance_evidence_ref": "evidence-requirements-review-example",
            "evidence_refs": [
                _example_evidence(
                    "evidence-requirements-example",
                    kind="requirements_baseline",
                    issuer_ref=scope.plm_system_ref,
                    subject_ref=command_ref,
                    occurred_at=occurred_at,
                    grade="attested",
                ),
                _example_evidence(
                    "evidence-requirements-review-example",
                    kind="requirements_review",
                    issuer_ref=scope.spring_authority_ref,
                    subject_ref=command_ref,
                    occurred_at=occurred_at,
                    grade="verified",
                ),
            ],
            "actors": [
                _example_actor(
                    "requirement-author-example",
                    "requirement_author",
                    suffix="requirement-author-example",
                    occurred_at=occurred_at,
                ),
                _example_actor(
                    "requirement-reviewer-example",
                    "requirement_reviewer",
                    suffix="requirement-reviewer-example",
                    occurred_at=occurred_at,
                ),
            ],
            "candidate": {
                "scope_digest": product_engineering_scope_digest(scope),
                "content_digest": "0" * 64,
                "baseline_ref": "requirements-baseline-example",
                "revision": 1,
                "requirements": [
                    {
                        "requirement_ref": "requirement-example",
                        "revision": 1,
                        "kind": "functional",
                        "statement_digest": "1" * 64,
                        "acceptance_criteria_refs": ["criterion-example"],
                    }
                ],
            },
            "request_digest": "0" * 64,
        }
    )
    return {"scope": scope.to_dict(), "command": command.to_dict()}


def _scope_matches_context(
    inputs: ProductEngineeringLifecycleInput,
    context: PrimitiveExecutionContext,
) -> bool:
    scope = inputs.scope
    command = inputs.command
    return (
        scope.tenant_ref == context.scope.tenant_ref
        and scope.company_ref == context.scope.company_ref
        and scope.project_ref == context.scope.project_ref
        and context.scope.project_id is not None
        and scope.project_id == context.scope.project_id
        and context.scope.actor_ref is not None
        and command.requested_by_ref == context.scope.actor_ref
        and context.idempotency_key is not None
        and command.idempotency_key == context.idempotency_key
    )


class ProposeProductEngineeringTransitionPrimitive(
    BusinessProcessPrimitive[
        ProductEngineeringLifecycleInput,
        ProductEngineeringLifecycleResult,
    ]
):
    primitive_ref = "product_engineering.propose_lifecycle_transition"
    version = "1.0.0"
    title = "Propose a bounded product-engineering lifecycle transition"
    description = (
        "Validate and materialize one exact-scope product-engineering SDK "
        "candidate without PLM, ALM, telemetry, release, or system-of-record effects."
    )
    input_model = ProductEngineeringLifecycleInput
    output_model = ProductEngineeringLifecycleResult
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _product_engineering_example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = (
            PRODUCT_ENGINEERING_TRANSITION_OPERATION.to_dict()
        )
        contract["effect_boundary"] = {
            "sdk_candidate_projection_only": True,
            "live_systems_changed": False,
            "authoritative_persistence_claimed": False,
            "authoritative_release_claimed": False,
            "risk_acceptance_or_issue_closure_claimed": False,
            "connector_or_provider_calls": False,
        }
        contract["authority_boundary"] = {
            "spring": (
                "authenticated scope, identity, certification, RBAC, approvals, "
                "durable idempotency, persistence, audit, release and risk decisions"
            ),
            "plm_alm_telemetry": "source custody and provider effects",
            "sdk": "deterministic candidate validation and immutable projection only",
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_PRODUCT_ENGINEERING_TRANSITIONS,
            "exact_scope": (
                "tenant, company, project reference and UUID, product, configuration, "
                "and release"
            ),
            "runtime_attribution": (
                "runtime project UUID, authenticated actor, and idempotency key must be "
                "present and exactly match the validated transition command"
            ),
            "history_validation": "semantic replay from genesis with canonical digests",
            "evidence": "fresh, content-bound, custody-bound, and single-use",
            "genesis_replay": "durable Spring idempotency ledger remains required",
            "ambiguous_outcome": "manual reconciliation; never automatic continuation",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProductEngineeringLifecycleInput,
    ) -> PrimitiveExecutionResult[ProductEngineeringLifecycleResult]:
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project UUID, actor, and idempotency key must "
                    "be present and exactly match the product-engineering lifecycle input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[ProductEngineeringLifecycleResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Product-engineering candidate rejected at scope boundary.",
                blockers=[blocker],
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=PRODUCT_ENGINEERING_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.command.request_digest,
                        evidence_refs=list(_command_all_evidence(inputs.command)),
                        error=blocker,
                    )
                ],
            )

        output = materialize_product_engineering_candidate(inputs)
        receipt = output.transition_receipt
        recovery_plan: PrimitiveRecoveryPlan | None = None
        recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
        blockers: list[PrimitiveBlocker] = []
        if output.candidate_validated:
            execution_status = PrimitiveExecutionStatus.PREVIEW
            operation_status = PrimitiveOperationStatus.PREVIEW
            summary = "Product-engineering lifecycle candidate validated in preview."
        elif receipt.status == "in_doubt":
            execution_status = PrimitiveExecutionStatus.BLOCKED
            operation_status = PrimitiveOperationStatus.IN_DOUBT
            recovery_disposition = (
                PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            )
            recovery_plan = PrimitiveRecoveryPlan(
                policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                disposition=recovery_disposition,
                instructions=(
                    "Reconcile the exact request digest against Spring's durable "
                    "PLM/ALM journal before submitting any new transition."
                ),
            )
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "AMBIGUOUS_EXTERNAL_OUTCOME",
                message=receipt.message,
                retryable=False,
            )
            blockers.append(blocker)
            summary = "Product-engineering lifecycle remains unchanged pending reconciliation."
        else:
            execution_status = PrimitiveExecutionStatus.BLOCKED
            operation_status = PrimitiveOperationStatus.BLOCKED
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "TRANSITION_REJECTED",
                message=receipt.message,
                retryable=False,
            )
            blockers.append(blocker)
            summary = "Product-engineering lifecycle candidate was not materialized."

        operation_receipt = PrimitiveOperationReceipt(
            spec=PRODUCT_ENGINEERING_TRANSITION_OPERATION,
            status=operation_status,
            request_digest=receipt.request_digest,
            external_refs=(
                {
                    "candidate_snapshot_digest": receipt.to_snapshot_digest,
                    "candidate_revision": str(receipt.to_revision),
                }
                if output.candidate_validated
                else {}
            ),
            evidence_refs=list(_command_all_evidence(inputs.command)),
            recovery_disposition=recovery_disposition,
            recovery_plan=recovery_plan,
            error=blockers[0] if blockers else None,
        )
        events = [
            PrimitiveEvent(
                type=(
                    "product_engineering.candidate_validated"
                    if output.candidate_validated
                    else "product_engineering.candidate_blocked"
                ),
                payload={
                    "kind": inputs.command.kind,
                    "request_digest": receipt.request_digest,
                    "candidate_validated": output.candidate_validated,
                    "live_systems_changed": False,
                },
            )
        ]
        return PrimitiveExecutionResult[ProductEngineeringLifecycleResult](
            status=execution_status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=events,
            evidence=[
                PrimitiveEvidence(
                    kind="product_engineering_candidate",
                    summary=(
                        "SDK-only product-engineering projection; Spring and source "
                        "systems retain all authority."
                    ),
                    labels=[inputs.command.kind, receipt.status],
                    refs={
                        "command_ref": inputs.command.command_ref,
                        "request_digest": receipt.request_digest,
                    },
                )
            ],
            evidence_refs=list(_command_all_evidence(inputs.command)),
            operation_receipts=[operation_receipt],
            recovery_plan=recovery_plan,
            blockers=blockers,
            retryable=False,
        )


PRODUCT_ENGINEERING_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeProductEngineeringTransitionPrimitive(),)


__all__ = [
    "BaselineEngineeringCommand",
    "BaselineRequirementsCommand",
    "BomComponentRecord",
    "CertifiedLifecycleActor",
    "DesignActionRecord",
    "DesignReviewCandidate",
    "EngineeringBaselineCandidate",
    "EngineeringChangeCandidate",
    "GENESIS_SNAPSHOT_DIGEST",
    "IssueDispositionCandidate",
    "MAX_PRODUCT_ENGINEERING_TRANSITIONS",
    "ObserveProductTelemetryCommand",
    "PRODUCT_ENGINEERING_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "PRODUCT_ENGINEERING_TRANSITION_OPERATION",
    "ProductEngineeringLifecycleInput",
    "ProductEngineeringLifecycleResult",
    "ProductEngineeringLifecycleScope",
    "ProductEngineeringLifecycleSnapshot",
    "ProductEngineeringTransitionReceipt",
    "ProductIssueRecord",
    "ProductTelemetryCandidate",
    "ProposeIssueDispositionCommand",
    "ProposeProductEngineeringTransitionPrimitive",
    "ReleaseArtifactRecord",
    "ReleaseCandidateRecord",
    "ReleaseTargetCandidate",
    "RequirementRecord",
    "RequirementsBaselineCandidate",
    "ReviewDesignCommand",
    "SpecificationRecord",
    "TargetReleaseCommand",
    "TelemetrySignalRecord",
    "TestRecord",
    "ValidateEngineeringChangeCommand",
    "ValidateReleaseCandidateCommand",
    "ValidateVerificationCommand",
    "VerificationValidationCandidate",
    "materialize_product_engineering_candidate",
    "product_engineering_scope_digest",
    "product_engineering_snapshot_digest",
    "seal_product_engineering_command",
]
