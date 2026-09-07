"""Deterministic, evidence-bound product release governance controls.

The module evaluates normalized product-lifecycle evidence only. It does not
resolve scope, read a connector, approve or publish a release, update a
configuration baseline or BOM, execute an engineering change, or mutate a
vulnerability or defect. A trusted host, normally the Spring Control Plane,
owns those authorities and supplies the exact-scope snapshots evaluated here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
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
    revalidate_model_boundary,
)


PRODUCT_GOVERNANCE_EVIDENCE_COVERAGE_SCHEMA = (
    "lightbulb.product_governance_evidence_coverage.v1"
)
PRODUCT_ROADMAP_RELEASE_SCOPE_SCHEMA = "lightbulb.product_roadmap_release_scope.v1"
PRODUCT_REQUIREMENT_SNAPSHOT_SCHEMA = "lightbulb.product_requirement_snapshot.v1"
PRODUCT_SPECIFICATION_SNAPSHOT_SCHEMA = "lightbulb.product_specification_snapshot.v1"
PRODUCT_CONFIGURATION_SNAPSHOT_SCHEMA = "lightbulb.product_configuration_snapshot.v1"
PRODUCT_BOM_SNAPSHOT_SCHEMA = "lightbulb.product_bom_snapshot.v1"
PRODUCT_ENGINEERING_CHANGE_SNAPSHOT_SCHEMA = (
    "lightbulb.product_engineering_change_snapshot.v1"
)
PRODUCT_DESIGN_REVIEW_SNAPSHOT_SCHEMA = "lightbulb.product_design_review_snapshot.v1"
PRODUCT_VERIFICATION_VALIDATION_RECORD_SCHEMA = (
    "lightbulb.product_verification_validation_record.v1"
)
PRODUCT_TELEMETRY_SNAPSHOT_SCHEMA = "lightbulb.product_telemetry_snapshot.v1"
PRODUCT_ISSUE_SNAPSHOT_SCHEMA = "lightbulb.product_issue_snapshot.v1"
RELEASE_GOVERNANCE_INPUT_SCHEMA = "lightbulb.release_governance_input.v1"
RELEASE_GOVERNANCE_RESULT_SCHEMA = "lightbulb.release_governance_result.v1"

_ZERO_DIGEST = "0" * 64
_METRIC_QUANTUM = Decimal("0.000001")

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
MetricUnit = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=40,
        pattern=r"^[A-Za-z%][A-Za-z0-9%._/-]{0,39}$",
    ),
]

ReleaseKind = Literal[
    "initial",
    "major",
    "minor",
    "patch",
    "hotfix",
    "hardware",
    "regulated",
]
ReleaseStatus = Literal[
    "planning",
    "candidate",
    "frozen",
    "approved",
    "released",
    "cancelled",
]
RequirementKind = Literal[
    "functional",
    "performance",
    "security",
    "safety",
    "regulatory",
    "usability",
    "operational",
]
RequirementStatus = Literal[
    "draft",
    "in_review",
    "approved",
    "implemented",
    "verified",
    "validated",
    "retired",
    "rejected",
]
SpecificationStatus = Literal[
    "draft",
    "in_review",
    "approved",
    "superseded",
    "withdrawn",
]
ConfigurationStatus = Literal["draft", "frozen", "released", "superseded"]
BomStatus = Literal["draft", "approved", "released", "superseded"]
EngineeringChangeStatus = Literal[
    "draft",
    "awaiting_approval",
    "approved",
    "execution_ready",
    "in_progress",
    "completed",
    "closed",
    "rejected",
    "cancelled",
]
EngineeringApprovalStatus = Literal[
    "not_started",
    "pending",
    "approved",
    "rejected",
]
EngineeringExecutionStatus = Literal[
    "not_started",
    "planned",
    "in_progress",
    "completed",
    "failed",
    "cancelled",
]
RiskTier = Literal["low", "medium", "high", "critical"]
DesignReviewType = Literal[
    "concept",
    "requirements",
    "architecture",
    "detailed_design",
    "security",
    "safety",
    "manufacturability",
    "release",
]
DesignReviewStatus = Literal[
    "planned",
    "in_progress",
    "approved",
    "approved_with_actions",
    "rejected",
    "cancelled",
]
VerificationValidationKind = Literal["verification", "validation"]
VerificationValidationMethod = Literal[
    "test",
    "analysis",
    "inspection",
    "demonstration",
    "simulation",
]
VerificationValidationStatus = Literal[
    "planned",
    "in_progress",
    "passed",
    "failed",
    "waived",
    "not_applicable",
]
TelemetryEnvironment = Literal["test", "staging", "pilot", "production", "field"]
TelemetrySignalStatus = Literal[
    "within_threshold",
    "warning",
    "breached",
    "insufficient_data",
]
ProductIssueKind = Literal["vulnerability", "defect"]
ProductIssueSeverity = Literal["low", "medium", "high", "critical"]
ProductIssueStatus = Literal[
    "open",
    "triaged",
    "in_remediation",
    "remediated_pending_verification",
    "resolved",
    "accepted_risk",
    "deferred",
    "false_positive",
]
ReleaseGovernanceGate = Literal[
    "evidence",
    "release_scope",
    "requirements",
    "specifications_configuration",
    "engineering_changes",
    "design_reviews",
    "verification_validation",
    "telemetry",
    "issues",
]
ReleaseGovernanceSeverity = Literal["info", "review", "blocking"]
ReleaseGovernanceGateStatus = Literal["pass", "review", "fail", "indeterminate"]
ReleaseGovernanceDisposition = Literal[
    "ready",
    "manual_review",
    "blocked",
    "indeterminate",
]


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
        return self.model_dump(mode="json", by_alias=True)


def _as_tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _sorted_string_tuple(value: Any) -> Any:
    candidate = _as_tuple(value)
    if isinstance(candidate, tuple) and all(
        isinstance(item, str) for item in candidate
    ):
        return tuple(sorted(candidate))
    return candidate


def _sorted_evidence_tuple(value: Any) -> Any:
    candidate = _as_tuple(value)
    if not isinstance(candidate, tuple):
        return candidate

    def evidence_ref(item: Any) -> str:
        if isinstance(item, PrimitiveEvidenceRef):
            return item.evidence_ref
        if isinstance(item, Mapping):
            return str(item.get("evidence_ref") or "")
        return ""

    return tuple(sorted(candidate, key=evidence_ref))


def _sorted_records(value: Any, key: str) -> Any:
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


def _normalized_timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _metric(value: Any, *, ratio: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("metric values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("metric values must use bounded notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("metric values must be finite") from exc
    if not parsed.is_finite():
        raise ValueError("metric values must be finite")
    try:
        normalized = parsed.quantize(_METRIC_QUANTUM)
    except InvalidOperation as exc:
        raise ValueError("metric value exceeds the supported precision") from exc
    if parsed != normalized:
        raise ValueError("metric values support at most 6 decimal places")
    if ratio and not Decimal("0") <= normalized <= Decimal("1"):
        raise ValueError("ratio values must be between zero and one")
    return normalized


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def product_governance_snapshot_digest(
    snapshot: BaseModel | Mapping[str, Any],
) -> str:
    """Return the canonical digest of one normalized product snapshot."""

    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


def _require_unique_refs(values: Sequence[Any], *, field: str, label: str) -> None:
    refs = [str(getattr(item, field)) for item in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{label} references must be unique")


def _require_unique_strings(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} references must be unique")


class _EvidenceBoundModel(_StrictModel):
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _sorted_evidence_tuple(value)

    @model_validator(mode="after")
    def _unique_evidence(self) -> "_EvidenceBoundModel":
        _require_unique_refs(
            self.evidence_refs,
            field="evidence_ref",
            label="evidence",
        )
        return self


class ProductGovernanceEvidenceCoverage(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_governance_evidence_coverage.v1"] = Field(
        default=PRODUCT_GOVERNANCE_EVIDENCE_COVERAGE_SCHEMA,
        alias="schema",
    )
    coverage_ref: OpaqueRef
    release_ref: OpaqueRef
    captured_at: str
    requirements_complete: bool
    specifications_complete: bool
    bom_complete: bool
    engineering_changes_complete: bool
    design_reviews_complete: bool
    verification_validation_complete: bool
    telemetry_complete: bool
    issues_complete: bool

    @field_validator("captured_at")
    @classmethod
    def _valid_captured_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="captured_at")


class ProductRoadmapReleaseScope(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_roadmap_release_scope.v1"] = Field(
        default=PRODUCT_ROADMAP_RELEASE_SCOPE_SCHEMA,
        alias="schema",
    )
    release_ref: OpaqueRef
    product_ref: OpaqueRef
    release_version: ShortText
    release_kind: ReleaseKind
    status: ReleaseStatus
    roadmap_item_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=1_000)
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=5_000)
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    configuration_baseline_ref: OpaqueRef
    bom_revision_ref: OpaqueRef | None = None
    owner_ref: OpaqueRef
    planned_release_at: str
    change_cutoff_at: str | None = None
    approval_ref: OpaqueRef | None = None

    @field_validator(
        "roadmap_item_refs",
        "requirement_refs",
        "specification_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @field_validator("planned_release_at", "change_cutoff_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_scope(self) -> "ProductRoadmapReleaseScope":
        _require_unique_strings(self.roadmap_item_refs, label="roadmap-item")
        _require_unique_strings(self.requirement_refs, label="requirement")
        _require_unique_strings(self.specification_refs, label="specification")
        if self.change_cutoff_at is not None and _parse_timestamp(
            self.change_cutoff_at
        ) > _parse_timestamp(self.planned_release_at):
            raise ValueError("change_cutoff_at must not be after planned_release_at")
        return self


class ProductRequirementSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_requirement_snapshot.v1"] = Field(
        default=PRODUCT_REQUIREMENT_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    requirement_ref: OpaqueRef
    revision: int = Field(ge=1)
    kind: RequirementKind
    status: RequirementStatus
    roadmap_item_ref: OpaqueRef
    acceptance_criteria_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    approval_ref: OpaqueRef | None = None

    @field_validator(
        "acceptance_criteria_refs",
        "specification_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductRequirementSnapshot":
        _require_unique_strings(
            self.acceptance_criteria_refs,
            label="acceptance-criteria",
        )
        _require_unique_strings(self.specification_refs, label="specification")
        return self


class ProductSpecificationSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_specification_snapshot.v1"] = Field(
        default=PRODUCT_SPECIFICATION_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    specification_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: SpecificationStatus
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=5_000)
    configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    approval_ref: OpaqueRef | None = None

    @field_validator(
        "requirement_refs",
        "configuration_item_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductSpecificationSnapshot":
        _require_unique_strings(self.requirement_refs, label="requirement")
        _require_unique_strings(
            self.configuration_item_refs,
            label="configuration-item",
        )
        return self


class ProductConfigurationSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_configuration_snapshot.v1"] = Field(
        default=PRODUCT_CONFIGURATION_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    configuration_baseline_ref: OpaqueRef
    revision: int = Field(ge=1)
    product_ref: OpaqueRef
    status: ConfigurationStatus
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    configuration_item_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=20_000,
    )
    bom_revision_ref: OpaqueRef | None = None
    engineering_change_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_ref: OpaqueRef | None = None

    @field_validator(
        "specification_refs",
        "configuration_item_refs",
        "engineering_change_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductConfigurationSnapshot":
        _require_unique_strings(self.specification_refs, label="specification")
        _require_unique_strings(
            self.configuration_item_refs,
            label="configuration-item",
        )
        _require_unique_strings(
            self.engineering_change_refs,
            label="engineering-change",
        )
        return self


class ProductBomSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_bom_snapshot.v1"] = Field(
        default=PRODUCT_BOM_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    bom_revision_ref: OpaqueRef
    revision: int = Field(ge=1)
    product_ref: OpaqueRef
    configuration_baseline_ref: OpaqueRef
    status: BomStatus
    component_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20_000)
    engineering_change_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    approval_ref: OpaqueRef | None = None

    @field_validator("component_refs", "engineering_change_refs", mode="before")
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductBomSnapshot":
        _require_unique_strings(self.component_refs, label="component")
        _require_unique_strings(
            self.engineering_change_refs,
            label="engineering-change",
        )
        return self


class ProductEngineeringChangeSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_engineering_change_snapshot.v1"] = Field(
        default=PRODUCT_ENGINEERING_CHANGE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    change_ref: OpaqueRef
    product_ref: OpaqueRef
    status: EngineeringChangeStatus
    risk_tier: RiskTier
    approval_status: EngineeringApprovalStatus
    execution_status: EngineeringExecutionStatus
    impacted_requirement_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    impacted_specification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    impacted_configuration_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    impacted_bom_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    target_configuration_baseline_ref: OpaqueRef | None = None
    target_bom_revision_ref: OpaqueRef | None = None
    evidence_gap_count: int = Field(default=0, ge=0, le=100_000)
    requested_at: str
    completed_at: str | None = None
    decision_ref: OpaqueRef | None = None

    @field_validator(
        "impacted_requirement_refs",
        "impacted_specification_refs",
        "impacted_configuration_refs",
        "impacted_bom_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @field_validator("requested_at", "completed_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductEngineeringChangeSnapshot":
        for values, label in (
            (self.impacted_requirement_refs, "impacted requirement"),
            (self.impacted_specification_refs, "impacted specification"),
            (self.impacted_configuration_refs, "impacted configuration"),
            (self.impacted_bom_refs, "impacted BOM"),
        ):
            _require_unique_strings(values, label=label)
        if self.completed_at is not None and _parse_timestamp(
            self.completed_at
        ) < _parse_timestamp(self.requested_at):
            raise ValueError("completed_at must not be before requested_at")
        return self


class ProductDesignReviewSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_design_review_snapshot.v1"] = Field(
        default=PRODUCT_DESIGN_REVIEW_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    review_ref: OpaqueRef
    review_type: DesignReviewType
    status: DesignReviewStatus
    reviewed_requirement_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    reviewed_specification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    reviewed_configuration_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    reviewed_bom_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    reviewed_change_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    open_action_count: int = Field(default=0, ge=0, le=100_000)
    blocking_action_count: int = Field(default=0, ge=0, le=100_000)
    decision_ref: OpaqueRef | None = None
    completed_at: str | None = None

    @field_validator(
        "reviewed_requirement_refs",
        "reviewed_specification_refs",
        "reviewed_configuration_refs",
        "reviewed_bom_refs",
        "reviewed_change_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @field_validator("completed_at")
    @classmethod
    def _valid_completed_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name="completed_at")

    @model_validator(mode="after")
    def _valid_review(self) -> "ProductDesignReviewSnapshot":
        reference_sets = (
            self.reviewed_requirement_refs,
            self.reviewed_specification_refs,
            self.reviewed_configuration_refs,
            self.reviewed_bom_refs,
            self.reviewed_change_refs,
        )
        if not any(reference_sets):
            raise ValueError(
                "a design review must identify at least one reviewed artifact"
            )
        for values, label in (
            (self.reviewed_requirement_refs, "reviewed requirement"),
            (self.reviewed_specification_refs, "reviewed specification"),
            (self.reviewed_configuration_refs, "reviewed configuration"),
            (self.reviewed_bom_refs, "reviewed BOM"),
            (self.reviewed_change_refs, "reviewed change"),
        ):
            _require_unique_strings(values, label=label)
        if self.blocking_action_count > self.open_action_count:
            raise ValueError("blocking_action_count cannot exceed open_action_count")
        return self


class ProductVerificationValidationRecord(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_verification_validation_record.v1"] = Field(
        default=PRODUCT_VERIFICATION_VALIDATION_RECORD_SCHEMA,
        alias="schema",
    )
    record_ref: OpaqueRef
    activity_kind: VerificationValidationKind
    method: VerificationValidationMethod
    status: VerificationValidationStatus
    requirement_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=5_000)
    specification_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    configuration_baseline_ref: OpaqueRef
    protocol_ref: OpaqueRef | None = None
    result_ref: OpaqueRef | None = None
    waiver_ref: OpaqueRef | None = None
    executed_at: str | None = None

    @field_validator("requirement_refs", "specification_refs", mode="before")
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @field_validator("executed_at")
    @classmethod
    def _valid_executed_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name="executed_at")

    @model_validator(mode="after")
    def _unique_links(self) -> "ProductVerificationValidationRecord":
        _require_unique_strings(self.requirement_refs, label="requirement")
        _require_unique_strings(self.specification_refs, label="specification")
        return self


class ProductTelemetrySignal(_StrictModel):
    signal_ref: OpaqueRef
    metric_name: ShortText
    status: TelemetrySignalStatus
    observed_value: Decimal | None = None
    threshold_value: Decimal | None = None
    unit: MetricUnit

    @field_validator("observed_value", "threshold_value", mode="before")
    @classmethod
    def _valid_metrics(cls, value: Any) -> Decimal | None:
        return None if value is None else _metric(value)

    @model_validator(mode="after")
    def _measured_status_has_values(self) -> "ProductTelemetrySignal":
        if self.status in {"within_threshold", "warning", "breached"} and (
            self.observed_value is None or self.threshold_value is None
        ):
            raise ValueError(
                "measured telemetry statuses require observed and threshold values"
            )
        return self


class ProductTelemetrySnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_telemetry_snapshot.v1"] = Field(
        default=PRODUCT_TELEMETRY_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    telemetry_ref: OpaqueRef
    product_ref: OpaqueRef
    subject_release_ref: OpaqueRef | None = None
    configuration_baseline_ref: OpaqueRef
    environment: TelemetryEnvironment
    window_start: str
    window_end: str
    sample_size: int = Field(ge=0, le=10_000_000_000)
    signals: tuple[ProductTelemetrySignal, ...] = Field(
        min_length=1,
        max_length=1_000,
    )

    @field_validator("window_start", "window_end")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, field_name=info.field_name)

    @field_validator("signals", mode="before")
    @classmethod
    def _signal_tuple(cls, value: Any) -> Any:
        return _sorted_records(value, "signal_ref")

    @model_validator(mode="after")
    def _valid_telemetry(self) -> "ProductTelemetrySnapshot":
        _require_unique_refs(self.signals, field="signal_ref", label="telemetry signal")
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("window_end must not be before window_start")
        return self


class ProductIssueSnapshot(_EvidenceBoundModel):
    schema_id: Literal["lightbulb.product_issue_snapshot.v1"] = Field(
        default=PRODUCT_ISSUE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    issue_ref: OpaqueRef
    product_ref: OpaqueRef
    kind: ProductIssueKind
    severity: ProductIssueSeverity
    status: ProductIssueStatus
    affected_release_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    affected_configuration_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    affected_specification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    detected_at: str
    due_at: str | None = None
    disposition_ref: OpaqueRef | None = None
    remediation_verification_ref: OpaqueRef | None = None

    @field_validator(
        "affected_release_refs",
        "affected_configuration_refs",
        "affected_specification_refs",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @field_validator("detected_at", "due_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_issue(self) -> "ProductIssueSnapshot":
        for values, label in (
            (self.affected_release_refs, "affected release"),
            (self.affected_configuration_refs, "affected configuration"),
            (self.affected_specification_refs, "affected specification"),
        ):
            _require_unique_strings(values, label=label)
        if self.due_at is not None and _parse_timestamp(self.due_at) < _parse_timestamp(
            self.detected_at
        ):
            raise ValueError("due_at must not be before detected_at")
        return self


class ReleaseGovernancePolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8_760)
    max_telemetry_evidence_age_hours: int = Field(default=48, ge=1, le=8_760)
    require_bom: bool = False
    require_validation: bool = True
    require_telemetry: bool = True
    minimum_telemetry_sample_size: int = Field(default=100, ge=1, le=10_000_000_000)
    required_design_review_types: tuple[DesignReviewType, ...] = Field(
        default=("release",),
        min_length=1,
        max_length=8,
    )
    blocking_issue_severities: tuple[ProductIssueSeverity, ...] = Field(
        default=("critical", "high"),
        min_length=1,
        max_length=4,
    )
    require_high_risk_change_review: bool = True
    allow_verification_validation_waivers: bool = False

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _valid_evidence_grade(
        cls,
        value: Any,
    ) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @field_validator(
        "required_design_review_types",
        "blocking_issue_severities",
        mode="before",
    )
    @classmethod
    def _reference_tuples(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)

    @model_validator(mode="after")
    def _unique_policy_values(self) -> "ReleaseGovernancePolicy":
        _require_unique_strings(
            self.required_design_review_types,
            label="required design-review type",
        )
        _require_unique_strings(
            self.blocking_issue_severities,
            label="blocking issue severity",
        )
        return self


class ReleaseGovernanceInput(_StrictModel):
    schema_id: Literal["lightbulb.release_governance_input.v1"] = Field(
        default=RELEASE_GOVERNANCE_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    evidence_coverage: ProductGovernanceEvidenceCoverage
    release_scope: ProductRoadmapReleaseScope
    requirements: tuple[ProductRequirementSnapshot, ...] = Field(max_length=5_000)
    specifications: tuple[ProductSpecificationSnapshot, ...] = Field(max_length=5_000)
    configuration: ProductConfigurationSnapshot
    bom: ProductBomSnapshot | None = None
    engineering_changes: tuple[ProductEngineeringChangeSnapshot, ...] = Field(
        max_length=5_000
    )
    design_reviews: tuple[ProductDesignReviewSnapshot, ...] = Field(max_length=5_000)
    verification_validation_records: tuple[
        ProductVerificationValidationRecord,
        ...,
    ] = Field(max_length=20_000)
    telemetry: tuple[ProductTelemetrySnapshot, ...] = Field(max_length=1_000)
    issues: tuple[ProductIssueSnapshot, ...] = Field(max_length=20_000)
    policy: ReleaseGovernancePolicy = Field(default_factory=ReleaseGovernancePolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="analysis_as_of")

    @field_validator(
        "requirements",
        "specifications",
        "engineering_changes",
        "design_reviews",
        "verification_validation_records",
        "telemetry",
        "issues",
        mode="before",
    )
    @classmethod
    def _sorted_snapshot_tuples(cls, value: Any, info: Any) -> Any:
        keys = {
            "requirements": "requirement_ref",
            "specifications": "specification_ref",
            "engineering_changes": "change_ref",
            "design_reviews": "review_ref",
            "verification_validation_records": "record_ref",
            "telemetry": "telemetry_ref",
            "issues": "issue_ref",
        }
        return _sorted_records(value, keys[info.field_name])

    @model_validator(mode="after")
    def _snapshot_graph_is_exact(self) -> "ReleaseGovernanceInput":
        for values, field, label in (
            (self.requirements, "requirement_ref", "requirement"),
            (self.specifications, "specification_ref", "specification"),
            (self.engineering_changes, "change_ref", "engineering-change"),
            (self.design_reviews, "review_ref", "design-review"),
            (
                self.verification_validation_records,
                "record_ref",
                "verification-validation record",
            ),
            (self.telemetry, "telemetry_ref", "telemetry"),
            (self.issues, "issue_ref", "issue"),
        ):
            _require_unique_refs(values, field=field, label=label)

        evidence_groups: list[tuple[PrimitiveEvidenceRef, ...]] = [
            self.evidence_coverage.evidence_refs,
            self.release_scope.evidence_refs,
            self.configuration.evidence_refs,
            *(item.evidence_refs for item in self.requirements),
            *(item.evidence_refs for item in self.specifications),
            *(item.evidence_refs for item in self.engineering_changes),
            *(item.evidence_refs for item in self.design_reviews),
            *(item.evidence_refs for item in self.verification_validation_records),
            *(item.evidence_refs for item in self.telemetry),
            *(item.evidence_refs for item in self.issues),
        ]
        if self.bom is not None:
            evidence_groups.append(self.bom.evidence_refs)
        evidence_by_ref: dict[str, PrimitiveEvidenceRef] = {}
        for group in evidence_groups:
            for evidence in group:
                previous = evidence_by_ref.setdefault(evidence.evidence_ref, evidence)
                if previous != evidence:
                    raise ValueError(
                        "one evidence_ref cannot identify conflicting evidence"
                    )
        _validate_release_business_graph(self)
        return self


def _validate_release_business_graph(inputs: ReleaseGovernanceInput) -> None:
    analysis_as_of = _parse_timestamp(inputs.analysis_as_of)
    actual_events: list[tuple[str, str]] = [
        ("evidence coverage captured_at", inputs.evidence_coverage.captured_at)
    ]
    for change in inputs.engineering_changes:
        actual_events.append(
            (
                f"engineering change {change.change_ref} requested_at",
                change.requested_at,
            )
        )
        if change.completed_at is not None:
            actual_events.append(
                (
                    f"engineering change {change.change_ref} completed_at",
                    change.completed_at,
                )
            )
    actual_events.extend(
        (f"design review {review.review_ref} completed_at", review.completed_at)
        for review in inputs.design_reviews
        if review.completed_at is not None
    )
    actual_events.extend(
        (f"verification/validation {record.record_ref} executed_at", record.executed_at)
        for record in inputs.verification_validation_records
        if record.executed_at is not None
    )
    actual_events.extend(
        (f"telemetry {snapshot.telemetry_ref} window_end", snapshot.window_end)
        for snapshot in inputs.telemetry
    )
    actual_events.extend(
        (f"issue {issue.issue_ref} detected_at", issue.detected_at)
        for issue in inputs.issues
    )
    for label, occurred_at in actual_events:
        if _parse_timestamp(occurred_at) > analysis_as_of:
            raise ValueError(f"{label} cannot follow analysis_as_of")

    release = inputs.release_scope
    expected_specification_refs = set(release.specification_refs)
    expected_configuration_refs = {release.configuration_baseline_ref}
    expected_bom_refs = (
        {release.bom_revision_ref} if release.bom_revision_ref is not None else set()
    )
    changes_by_ref = {
        change.change_ref: change for change in inputs.engineering_changes
    }
    approved_review_statuses = {"approved", "approved_with_actions"}

    for review in inputs.design_reviews:
        review_specification_refs = set(review.reviewed_specification_refs)
        review_configuration_refs = set(review.reviewed_configuration_refs)
        review_bom_refs = set(review.reviewed_bom_refs)
        missing_change_refs = set(review.reviewed_change_refs) - set(changes_by_ref)
        if missing_change_refs:
            raise ValueError(
                "design review must bind engineering changes present in the exact packet"
            )
        if review_specification_refs - expected_specification_refs:
            raise ValueError(
                "design review specification identities must remain in release scope"
            )
        if review_configuration_refs - expected_configuration_refs:
            raise ValueError(
                "design review configuration identities must match the release baseline"
            )
        if review_bom_refs - expected_bom_refs:
            raise ValueError("design review BOM identities must match the release BOM")

        if (
            review.review_type == "release"
            and review.status in approved_review_statuses
        ):
            if review_specification_refs != expected_specification_refs:
                raise ValueError(
                    "approved release review must bind the exact release specifications"
                )
            if review_configuration_refs != expected_configuration_refs:
                raise ValueError(
                    "approved release review must bind the exact release baseline"
                )
            if review_bom_refs != expected_bom_refs:
                raise ValueError(
                    "approved release review must bind the exact release BOM"
                )

        if review.completed_at is None:
            continue
        review_completed_at = _parse_timestamp(review.completed_at)
        for change_ref in review.reviewed_change_refs:
            change = changes_by_ref[change_ref]
            if change.completed_at is None:
                raise ValueError(
                    "completed design review cannot bind an incomplete engineering change"
                )
            if review_completed_at < _parse_timestamp(change.requested_at):
                raise ValueError(
                    "design review completed_at cannot precede reviewed change requested_at"
                )
            if review_completed_at < _parse_timestamp(change.completed_at):
                raise ValueError(
                    "design review completed_at cannot precede reviewed change completed_at"
                )
            if not set(change.impacted_specification_refs) <= review_specification_refs:
                raise ValueError(
                    "design review must bind every specification impacted by its exact change"
                )
            required_configuration_refs = set(change.impacted_configuration_refs)
            if change.target_configuration_baseline_ref is not None:
                required_configuration_refs.add(
                    change.target_configuration_baseline_ref
                )
            if not required_configuration_refs <= review_configuration_refs:
                raise ValueError(
                    "design review must bind the exact change configuration baseline"
                )
            required_bom_refs = set(change.impacted_bom_refs)
            if change.target_bom_revision_ref is not None:
                required_bom_refs.add(change.target_bom_revision_ref)
            if not required_bom_refs <= review_bom_refs:
                raise ValueError(
                    "design review must bind the exact change BOM baseline"
                )

    required_review_types = set(inputs.policy.required_design_review_types)
    for record in inputs.verification_validation_records:
        if record.executed_at is None:
            continue
        executed_at = _parse_timestamp(record.executed_at)
        record_specification_refs = set(record.specification_refs)
        applicable_change_completions = [
            _parse_timestamp(change.completed_at)
            for change in inputs.engineering_changes
            if change.completed_at is not None
            and change.target_configuration_baseline_ref
            == record.configuration_baseline_ref
            and record_specification_refs.intersection(
                change.impacted_specification_refs
            )
        ]
        if applicable_change_completions and executed_at < max(
            applicable_change_completions
        ):
            raise ValueError(
                "verification/validation executed_at cannot precede its latest applicable "
                "engineering change completion"
            )

        applicable_review_completions = [
            _parse_timestamp(review.completed_at)
            for review in inputs.design_reviews
            if review.completed_at is not None
            and review.status in approved_review_statuses
            and review.review_type in required_review_types
            and record.configuration_baseline_ref in review.reviewed_configuration_refs
            and record_specification_refs <= set(review.reviewed_specification_refs)
        ]
        if applicable_review_completions and executed_at < max(
            applicable_review_completions
        ):
            raise ValueError(
                "verification/validation executed_at cannot precede its latest applicable "
                "required design review completion"
            )


class ReleaseGovernanceFinding(_StrictModel):
    code: OpaqueRef
    gate: ReleaseGovernanceGate
    severity: ReleaseGovernanceSeverity
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    artifact_ref: OpaqueRef | None = None
    requirement_ref: OpaqueRef | None = None


class ReleaseGovernanceGateResult(_StrictModel):
    gate: ReleaseGovernanceGate
    status: ReleaseGovernanceGateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _sorted_string_tuple(value)


class ReleaseGovernanceCoverageSummary(_StrictModel):
    scoped_requirement_count: int = Field(ge=0)
    requirement_snapshot_count: int = Field(ge=0)
    scoped_specification_count: int = Field(ge=0)
    specification_snapshot_count: int = Field(ge=0)
    verified_requirement_count: int = Field(ge=0)
    validated_requirement_count: int = Field(ge=0)
    approved_design_review_count: int = Field(ge=0)
    open_engineering_change_count: int = Field(ge=0)
    telemetry_signal_count: int = Field(ge=0)
    breached_telemetry_signal_count: int = Field(ge=0)
    unresolved_vulnerability_count: int = Field(ge=0)
    unresolved_defect_count: int = Field(ge=0)


class ProductGovernanceEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    release_authorized: Literal[False] = False
    configuration_change_authorized: Literal[False] = False
    engineering_change_authorized: Literal[False] = False
    vulnerability_disposition_authorized: Literal[False] = False
    defect_disposition_authorized: Literal[False] = False
    release_state_changed: Literal[False] = False
    configuration_changed: Literal[False] = False
    engineering_changes_changed: Literal[False] = False
    vulnerabilities_changed: Literal[False] = False
    defects_changed: Literal[False] = False
    external_systems_changed: Literal[False] = False


PRODUCT_GOVERNANCE_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="product-release-governance-controls.evaluate",
    tool="product.evaluate_release_governance_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class ReleaseGovernanceResult(_StrictModel):
    schema_id: Literal["lightbulb.release_governance_result.v1"] = Field(
        default=RELEASE_GOVERNANCE_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    release_ref: OpaqueRef
    release_version: ShortText
    assurance_grade: PrimitiveEvidenceVerificationGrade
    disposition: ReleaseGovernanceDisposition
    release_authorized: Literal[False] = False
    gates: tuple[ReleaseGovernanceGateResult, ...] = Field(
        min_length=9,
        max_length=9,
    )
    findings: tuple[ReleaseGovernanceFinding, ...] = Field(max_length=200_000)
    coverage: ReleaseGovernanceCoverageSummary
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[OpaqueRef, ...] = Field(max_length=1_220_100)
    effect_boundary: ProductGovernanceEffectBoundary = Field(
        default_factory=ProductGovernanceEffectBoundary
    )
    result_digest: str = Field(default=_ZERO_DIGEST, pattern=r"^[0-9a-f]{64}$")

    @field_validator("gates", "findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("source_snapshot_digests")
    @classmethod
    def _valid_snapshot_digests(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or len(value) > 61_005:
            raise ValueError("source_snapshot_digests must contain 1 to 61005 entries")
        if any(
            not key
            or len(key) > 220
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for key, digest in value.items()
        ):
            raise ValueError("source snapshot digests must be lowercase SHA-256 values")
        return value

    @model_validator(mode="after")
    def _complete_gate_set_and_unique_evidence(self) -> "ReleaseGovernanceResult":
        expected_findings = tuple(
            sorted(
                self.findings,
                key=lambda item: (
                    _GATE_ORDER.index(item.gate),
                    item.artifact_ref or "",
                    item.requirement_ref or "",
                    item.code,
                ),
            )
        )
        if self.findings != expected_findings:
            raise ValueError("findings must be in canonical order")
        expected_gates: list[ReleaseGovernanceGateResult] = []
        for gate_name in _GATE_ORDER:
            gate_findings = [item for item in self.findings if item.gate == gate_name]
            if any(
                item.severity == "blocking" and item.code not in _INDETERMINATE_CODES
                for item in gate_findings
            ):
                status: ReleaseGovernanceGateStatus = "fail"
            elif any(item.code in _INDETERMINATE_CODES for item in gate_findings):
                status = "indeterminate"
            elif any(item.severity == "review" for item in gate_findings):
                status = "review"
            else:
                status = "pass"
            expected_gates.append(
                ReleaseGovernanceGateResult(
                    gate=gate_name,
                    status=status,
                    finding_codes=tuple(sorted({item.code for item in gate_findings})),
                )
            )
        if self.gates != tuple(expected_gates):
            raise ValueError("gates must be the canonical projection of findings")
        expected_disposition: ReleaseGovernanceDisposition = (
            "blocked"
            if any(item.status == "fail" for item in self.gates)
            else "indeterminate"
            if any(item.status == "indeterminate" for item in self.gates)
            else "manual_review"
            if any(item.status == "review" for item in self.gates)
            else "ready"
        )
        if self.disposition != expected_disposition:
            raise ValueError("disposition must match gate results")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("result evidence references must be canonical and unique")
        required_sources = {
            "evidence_coverage",
            "release_scope",
            "configuration",
            "policy",
        }
        allowed_prefixes = (
            "requirement:",
            "specification:",
            "engineering_change:",
            "design_review:",
            "verification_validation:",
            "telemetry:",
            "issue:",
        )
        if not required_sources.issubset(self.source_snapshot_digests) or any(
            key not in required_sources
            and key != "bom"
            and not key.startswith(allowed_prefixes)
            for key in self.source_snapshot_digests
        ):
            raise ValueError("source_snapshot_digests contains an invalid source set")
        if self.coverage.requirement_snapshot_count != sum(
            key.startswith("requirement:") for key in self.source_snapshot_digests
        ):
            raise ValueError("requirement snapshot count must match source digests")
        if self.coverage.specification_snapshot_count != sum(
            key.startswith("specification:") for key in self.source_snapshot_digests
        ):
            raise ValueError("specification snapshot count must match source digests")
        expected_digest = _stable_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"result_digest"},
                exclude_none=True,
            )
        )
        if self.result_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("result_digest does not match result")
        object.__setattr__(self, "result_digest", expected_digest)
        return self


_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

_GATE_ORDER: tuple[ReleaseGovernanceGate, ...] = (
    "evidence",
    "release_scope",
    "requirements",
    "specifications_configuration",
    "engineering_changes",
    "design_reviews",
    "verification_validation",
    "telemetry",
    "issues",
)

_INDETERMINATE_CODES = {
    "evidence_missing",
    "evidence_stale",
    "evidence_not_yet_effective",
    "evidence_below_required_grade",
    "evidence_coverage_after_analysis_cutoff",
    "requirements_population_incomplete",
    "specifications_population_incomplete",
    "bom_population_incomplete",
    "engineering_changes_population_incomplete",
    "design_reviews_population_incomplete",
    "verification_validation_population_incomplete",
    "telemetry_population_incomplete",
    "issues_population_incomplete",
    "scoped_requirement_not_observed",
    "scoped_specification_not_observed",
    "requirement_specification_trace_not_observed",
    "bom_snapshot_not_observed",
    "baseline_change_not_observed",
    "engineering_change_after_analysis_cutoff",
    "required_design_review_not_observed",
    "high_risk_change_review_not_observed",
    "design_review_after_analysis_cutoff",
    "verification_not_observed",
    "validation_not_observed",
    "verification_validation_after_analysis_cutoff",
    "telemetry_not_observed",
    "telemetry_after_analysis_cutoff",
    "telemetry_below_minimum_sample",
    "telemetry_signal_insufficient",
}


def _model_digest(model: BaseModel) -> str:
    return _stable_digest(model.model_dump(mode="json", by_alias=True))


def evaluate_release_governance_controls(
    value: ReleaseGovernanceInput | Mapping[str, Any],
) -> ReleaseGovernanceResult:
    """Evaluate one normalized release packet without reading or mutating state."""

    inputs = revalidate_model_boundary(ReleaseGovernanceInput, value)
    findings: list[ReleaseGovernanceFinding] = []

    def add(
        code: str,
        gate: ReleaseGovernanceGate,
        severity: ReleaseGovernanceSeverity,
        message: str,
        *,
        artifact_ref: str | None = None,
        requirement_ref: str | None = None,
    ) -> None:
        findings.append(
            ReleaseGovernanceFinding(
                code=code,
                gate=gate,
                severity=severity,
                message=message,
                artifact_ref=artifact_ref,
                requirement_ref=requirement_ref,
            )
        )

    analysis_at = _parse_timestamp(inputs.analysis_as_of)
    coverage = inputs.evidence_coverage
    release = inputs.release_scope
    configuration = inputs.configuration
    bom = inputs.bom
    minimum_grade = inputs.policy.minimum_evidence_grade

    evidence_sets: list[tuple[str, str, tuple[PrimitiveEvidenceRef, ...], int]] = [
        (
            "evidence_coverage",
            coverage.coverage_ref,
            coverage.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        ),
        (
            "release_scope",
            release.release_ref,
            release.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        ),
        (
            "configuration",
            configuration.configuration_baseline_ref,
            configuration.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        ),
    ]
    if bom is not None:
        evidence_sets.append(
            (
                "bom",
                bom.bom_revision_ref,
                bom.evidence_refs,
                inputs.policy.max_evidence_age_hours,
            )
        )
    evidence_sets.extend(
        (
            "requirement",
            item.requirement_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.requirements
    )
    evidence_sets.extend(
        (
            "specification",
            item.specification_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.specifications
    )
    evidence_sets.extend(
        (
            "engineering_change",
            item.change_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.engineering_changes
    )
    evidence_sets.extend(
        (
            "design_review",
            item.review_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.design_reviews
    )
    evidence_sets.extend(
        (
            "verification_validation",
            item.record_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.verification_validation_records
    )
    evidence_sets.extend(
        (
            "telemetry",
            item.telemetry_ref,
            item.evidence_refs,
            inputs.policy.max_telemetry_evidence_age_hours,
        )
        for item in inputs.telemetry
    )
    evidence_sets.extend(
        (
            item.kind,
            item.issue_ref,
            item.evidence_refs,
            inputs.policy.max_evidence_age_hours,
        )
        for item in inputs.issues
    )

    document_grades: list[PrimitiveEvidenceVerificationGrade] = []
    for kind, artifact_ref, evidence_refs, max_age_hours in evidence_sets:
        eligible_evidence: list[PrimitiveEvidenceRef] = []
        future_effective = False
        stale = False
        for evidence in evidence_refs:
            observed_at = _parse_timestamp(evidence.observed_at)
            if observed_at > analysis_at:
                future_effective = True
                continue
            if evidence.effective_at is not None and (
                _parse_timestamp(evidence.effective_at) > analysis_at
            ):
                future_effective = True
                continue
            if analysis_at - observed_at > timedelta(hours=max_age_hours):
                stale = True
                continue
            eligible_evidence.append(evidence)

        if not eligible_evidence:
            code = (
                "evidence_not_yet_effective"
                if future_effective and not stale
                else "evidence_stale"
                if stale
                else "evidence_missing"
            )
            add(
                code,
                "evidence",
                "blocking",
                f"{kind} has no current effective evidence.",
                artifact_ref=artifact_ref,
            )
            document_grades.append(PrimitiveEvidenceVerificationGrade.UNVERIFIED)
            continue

        best_grade = max(
            (item.verification_grade for item in eligible_evidence),
            key=_GRADE_RANK.__getitem__,
        )
        document_grades.append(best_grade)
        if _GRADE_RANK[best_grade] < _GRADE_RANK[minimum_grade]:
            add(
                "evidence_below_required_grade",
                "evidence",
                "blocking",
                f"{kind} evidence is below the required verification grade.",
                artifact_ref=artifact_ref,
            )

    coverage_effective = _parse_timestamp(coverage.captured_at) <= analysis_at
    if not coverage_effective:
        add(
            "evidence_coverage_after_analysis_cutoff",
            "evidence",
            "blocking",
            "Evidence population coverage was captured after the analysis cutoff.",
            artifact_ref=coverage.coverage_ref,
        )
        document_grades.append(PrimitiveEvidenceVerificationGrade.UNVERIFIED)

    def population_complete(field_name: str) -> bool:
        return coverage_effective and bool(getattr(coverage, field_name))

    population_checks: list[tuple[str, str, ReleaseGovernanceGate, str, bool]] = [
        (
            "requirements_complete",
            "requirements_population_incomplete",
            "requirements",
            "Requirement population coverage is incomplete.",
            True,
        ),
        (
            "specifications_complete",
            "specifications_population_incomplete",
            "specifications_configuration",
            "Specification population coverage is incomplete.",
            True,
        ),
        (
            "bom_complete",
            "bom_population_incomplete",
            "specifications_configuration",
            "BOM population coverage is incomplete.",
            bool(release.bom_revision_ref or bom or inputs.policy.require_bom),
        ),
        (
            "engineering_changes_complete",
            "engineering_changes_population_incomplete",
            "engineering_changes",
            "Engineering-change population coverage is incomplete.",
            True,
        ),
        (
            "design_reviews_complete",
            "design_reviews_population_incomplete",
            "design_reviews",
            "Design-review population coverage is incomplete.",
            True,
        ),
        (
            "verification_validation_complete",
            "verification_validation_population_incomplete",
            "verification_validation",
            "Verification and validation population coverage is incomplete.",
            True,
        ),
        (
            "telemetry_complete",
            "telemetry_population_incomplete",
            "telemetry",
            "Product-telemetry population coverage is incomplete.",
            bool(inputs.telemetry or inputs.policy.require_telemetry),
        ),
        (
            "issues_complete",
            "issues_population_incomplete",
            "issues",
            "Vulnerability and defect population coverage is incomplete.",
            True,
        ),
    ]
    for field_name, code, gate, message, required in population_checks:
        if required and not population_complete(field_name):
            add(
                code,
                gate,
                "blocking",
                message,
                artifact_ref=coverage.coverage_ref,
            )
            document_grades.append(PrimitiveEvidenceVerificationGrade.UNVERIFIED)

    assurance_grade = (
        min(document_grades, key=_GRADE_RANK.__getitem__)
        if document_grades
        else PrimitiveEvidenceVerificationGrade.UNVERIFIED
    )

    if coverage.release_ref != release.release_ref:
        add(
            "coverage_release_mismatch",
            "release_scope",
            "blocking",
            "Evidence coverage references a different release.",
            artifact_ref=coverage.coverage_ref,
        )

    if release.status in {"planning", "cancelled"}:
        add(
            "release_not_candidate",
            "release_scope",
            "blocking",
            "Release is not in a state eligible for governance readiness.",
            artifact_ref=release.release_ref,
        )
    elif release.status == "released":
        add(
            "release_already_released",
            "release_scope",
            "review",
            "Release is already released; this result cannot authorize it again.",
            artifact_ref=release.release_ref,
        )
    if release.status in {"approved", "released"} and release.approval_ref is None:
        add(
            "release_approval_missing",
            "release_scope",
            "blocking",
            "Approved or released scope lacks an authoritative approval reference.",
            artifact_ref=release.release_ref,
        )
    if _parse_timestamp(release.planned_release_at) < analysis_at:
        add(
            "planned_release_date_elapsed",
            "release_scope",
            "review",
            "Planned release time elapsed before the analysis cutoff.",
            artifact_ref=release.release_ref,
        )
    if configuration.configuration_baseline_ref != release.configuration_baseline_ref:
        add(
            "release_configuration_mismatch",
            "release_scope",
            "blocking",
            "Release scope references a different configuration baseline.",
            artifact_ref=configuration.configuration_baseline_ref,
        )
    if configuration.product_ref != release.product_ref:
        add(
            "configuration_product_mismatch",
            "release_scope",
            "blocking",
            "Configuration baseline belongs to a different product.",
            artifact_ref=configuration.configuration_baseline_ref,
        )

    expected_requirement_refs = set(release.requirement_refs)
    expected_specification_refs = set(release.specification_refs)
    roadmap_refs = set(release.roadmap_item_refs)
    requirements_by_ref = {item.requirement_ref: item for item in inputs.requirements}
    specifications_by_ref = {
        item.specification_ref: item for item in inputs.specifications
    }

    for requirement_ref in sorted(expected_requirement_refs - set(requirements_by_ref)):
        complete = population_complete("requirements_complete")
        add(
            "scoped_requirement_missing"
            if complete
            else "scoped_requirement_not_observed",
            "requirements",
            "blocking",
            "A release-scoped requirement snapshot is missing."
            if complete
            else "A release-scoped requirement was not observed in an incomplete population.",
            artifact_ref=release.release_ref,
            requirement_ref=requirement_ref,
        )

    allowed_requirement_statuses = {
        "approved",
        "implemented",
        "verified",
        "validated",
    }
    for requirement in inputs.requirements:
        if requirement.requirement_ref not in expected_requirement_refs:
            add(
                "requirement_outside_release_scope",
                "requirements",
                "info",
                "Requirement snapshot is outside the declared release scope.",
                artifact_ref=requirement.requirement_ref,
                requirement_ref=requirement.requirement_ref,
            )
            continue
        if requirement.status not in allowed_requirement_statuses:
            add(
                "requirement_not_approved",
                "requirements",
                "blocking",
                "Release-scoped requirement is not approved for implementation.",
                artifact_ref=requirement.requirement_ref,
                requirement_ref=requirement.requirement_ref,
            )
        if requirement.approval_ref is None:
            add(
                "requirement_approval_missing",
                "requirements",
                "blocking",
                "Release-scoped requirement has no authoritative approval reference.",
                artifact_ref=requirement.requirement_ref,
                requirement_ref=requirement.requirement_ref,
            )
        if requirement.roadmap_item_ref not in roadmap_refs:
            add(
                "requirement_roadmap_mismatch",
                "requirements",
                "blocking",
                "Requirement does not trace to a roadmap item in release scope.",
                artifact_ref=requirement.requirement_ref,
                requirement_ref=requirement.requirement_ref,
            )
        for specification_ref in requirement.specification_refs:
            if specification_ref not in expected_specification_refs:
                add(
                    "requirement_specification_outside_release_scope",
                    "requirements",
                    "blocking",
                    "Requirement traces to a specification outside release scope.",
                    artifact_ref=specification_ref,
                    requirement_ref=requirement.requirement_ref,
                )

    for specification_ref in sorted(
        expected_specification_refs - set(specifications_by_ref)
    ):
        complete = population_complete("specifications_complete")
        add(
            "scoped_specification_missing"
            if complete
            else "scoped_specification_not_observed",
            "specifications_configuration",
            "blocking",
            "A release-scoped specification snapshot is missing."
            if complete
            else "A release-scoped specification was not observed in an incomplete population.",
            artifact_ref=specification_ref,
        )

    approved_specification_refs: set[str] = set()
    requirement_specification_coverage: dict[str, set[str]] = {}
    for specification in inputs.specifications:
        if specification.specification_ref not in expected_specification_refs:
            add(
                "specification_outside_release_scope",
                "specifications_configuration",
                "info",
                "Specification snapshot is outside the declared release scope.",
                artifact_ref=specification.specification_ref,
            )
            continue
        if specification.status != "approved":
            add(
                "specification_not_approved",
                "specifications_configuration",
                "blocking",
                "Release-scoped specification is not approved.",
                artifact_ref=specification.specification_ref,
            )
        elif specification.approval_ref is None:
            add(
                "specification_approval_missing",
                "specifications_configuration",
                "blocking",
                "Approved specification has no authoritative approval reference.",
                artifact_ref=specification.specification_ref,
            )
        else:
            approved_specification_refs.add(specification.specification_ref)
        for requirement_ref in specification.requirement_refs:
            if requirement_ref not in expected_requirement_refs:
                add(
                    "specification_requirement_outside_release_scope",
                    "specifications_configuration",
                    "blocking",
                    "Specification traces to a requirement outside release scope.",
                    artifact_ref=specification.specification_ref,
                    requirement_ref=requirement_ref,
                )
                continue
            requirement_specification_coverage.setdefault(
                requirement_ref,
                set(),
            ).add(specification.specification_ref)

    for requirement_ref in sorted(expected_requirement_refs):
        requirement = requirements_by_ref.get(requirement_ref)
        if requirement is None:
            continue
        covered_specs = requirement_specification_coverage.get(
            requirement_ref,
            set(),
        )
        declared_specs = set(requirement.specification_refs)
        if not (covered_specs & declared_specs & approved_specification_refs):
            complete = population_complete("specifications_complete")
            add(
                "requirement_missing_approved_specification_trace"
                if complete
                else "requirement_specification_trace_not_observed",
                "specifications_configuration",
                "blocking",
                "Requirement lacks a reciprocal trace to an approved release specification."
                if complete
                else "Approved specification trace was not observed in an incomplete population.",
                artifact_ref=release.release_ref,
                requirement_ref=requirement_ref,
            )

    if configuration.status not in {"frozen", "released"}:
        add(
            "configuration_not_frozen",
            "specifications_configuration",
            "blocking",
            "Configuration baseline is not frozen for release evaluation.",
            artifact_ref=configuration.configuration_baseline_ref,
        )
    if configuration.approval_ref is None:
        add(
            "configuration_approval_missing",
            "specifications_configuration",
            "blocking",
            "Configuration baseline has no authoritative approval reference.",
            artifact_ref=configuration.configuration_baseline_ref,
        )
    for specification_ref in sorted(
        expected_specification_refs - set(configuration.specification_refs)
    ):
        add(
            "configuration_missing_release_specification",
            "specifications_configuration",
            "blocking",
            "Configuration baseline omits a release-scoped specification.",
            artifact_ref=specification_ref,
        )
    configuration_items = set(configuration.configuration_item_refs)
    for specification in inputs.specifications:
        if specification.specification_ref not in expected_specification_refs:
            continue
        for item_ref in sorted(
            set(specification.configuration_item_refs) - configuration_items
        ):
            add(
                "configuration_missing_specification_item",
                "specifications_configuration",
                "blocking",
                "Configuration baseline omits an item required by a release specification.",
                artifact_ref=item_ref,
            )

    expected_bom_ref = release.bom_revision_ref
    if expected_bom_ref is None and inputs.policy.require_bom:
        if population_complete("bom_complete"):
            add(
                "bom_required_for_release",
                "specifications_configuration",
                "blocking",
                "Policy requires a BOM revision for this release.",
                artifact_ref=release.release_ref,
            )
        else:
            add(
                "bom_snapshot_not_observed",
                "specifications_configuration",
                "blocking",
                "Required BOM evidence was not observed in an incomplete population.",
                artifact_ref=release.release_ref,
            )
    if expected_bom_ref is not None and bom is None:
        complete = population_complete("bom_complete")
        add(
            "bom_snapshot_missing" if complete else "bom_snapshot_not_observed",
            "specifications_configuration",
            "blocking",
            "Release-scoped BOM snapshot is missing."
            if complete
            else "Release-scoped BOM was not observed in an incomplete population.",
            artifact_ref=expected_bom_ref,
        )
    if bom is not None:
        if expected_bom_ref is None:
            add(
                "bom_outside_release_scope",
                "specifications_configuration",
                "info",
                "BOM snapshot is not declared by the release scope.",
                artifact_ref=bom.bom_revision_ref,
            )
        elif bom.bom_revision_ref != expected_bom_ref:
            add(
                "release_bom_mismatch",
                "specifications_configuration",
                "blocking",
                "BOM snapshot does not match the release-scoped revision.",
                artifact_ref=bom.bom_revision_ref,
            )
        if bom.product_ref != release.product_ref:
            add(
                "bom_product_mismatch",
                "specifications_configuration",
                "blocking",
                "BOM belongs to a different product.",
                artifact_ref=bom.bom_revision_ref,
            )
        if bom.configuration_baseline_ref != release.configuration_baseline_ref:
            add(
                "bom_configuration_mismatch",
                "specifications_configuration",
                "blocking",
                "BOM is not bound to the release configuration baseline.",
                artifact_ref=bom.bom_revision_ref,
            )
        if configuration.bom_revision_ref != bom.bom_revision_ref:
            add(
                "configuration_bom_mismatch",
                "specifications_configuration",
                "blocking",
                "Configuration baseline does not bind the supplied BOM revision.",
                artifact_ref=configuration.configuration_baseline_ref,
            )
        if bom.status not in {"approved", "released"}:
            add(
                "bom_not_approved",
                "specifications_configuration",
                "blocking",
                "BOM revision is not approved for release.",
                artifact_ref=bom.bom_revision_ref,
            )
        if bom.approval_ref is None:
            add(
                "bom_approval_missing",
                "specifications_configuration",
                "blocking",
                "BOM revision has no authoritative approval reference.",
                artifact_ref=bom.bom_revision_ref,
            )

    changes_by_ref = {item.change_ref: item for item in inputs.engineering_changes}
    for change_ref in sorted(
        set(configuration.engineering_change_refs) - set(changes_by_ref)
    ):
        complete = population_complete("engineering_changes_complete")
        add(
            "baseline_change_snapshot_missing"
            if complete
            else "baseline_change_not_observed",
            "engineering_changes",
            "blocking",
            "Configuration-declared engineering change snapshot is missing."
            if complete
            else "Configuration-declared engineering change was not observed in an incomplete population.",
            artifact_ref=change_ref,
        )

    open_change_count = 0
    high_risk_change_refs: set[str] = set()
    for change in inputs.engineering_changes:
        if change.product_ref != release.product_ref:
            add(
                "engineering_change_product_mismatch",
                "engineering_changes",
                "blocking",
                "Engineering change belongs to a different product.",
                artifact_ref=change.change_ref,
            )
            continue
        if _parse_timestamp(change.requested_at) > analysis_at or (
            change.completed_at is not None
            and _parse_timestamp(change.completed_at) > analysis_at
        ):
            add(
                "engineering_change_after_analysis_cutoff",
                "engineering_changes",
                "blocking",
                "Engineering change state is not effective at the analysis cutoff.",
                artifact_ref=change.change_ref,
            )
            continue
        for requirement_ref in sorted(
            set(change.impacted_requirement_refs) - expected_requirement_refs
        ):
            add(
                "engineering_change_requirement_outside_scope",
                "engineering_changes",
                "blocking",
                "Engineering change impacts a requirement outside release scope.",
                artifact_ref=change.change_ref,
                requirement_ref=requirement_ref,
            )
        if set(change.impacted_specification_refs) - expected_specification_refs:
            add(
                "engineering_change_specification_outside_scope",
                "engineering_changes",
                "blocking",
                "Engineering change impacts a specification outside release scope.",
                artifact_ref=change.change_ref,
            )
        if any(
            ref != release.configuration_baseline_ref
            for ref in change.impacted_configuration_refs
        ):
            add(
                "engineering_change_configuration_outside_scope",
                "engineering_changes",
                "blocking",
                "Engineering change impacts a configuration outside release scope.",
                artifact_ref=change.change_ref,
            )
        if expected_bom_ref is None and change.impacted_bom_refs:
            add(
                "engineering_change_bom_outside_scope",
                "engineering_changes",
                "blocking",
                "Engineering change impacts a BOM outside release scope.",
                artifact_ref=change.change_ref,
            )
        elif expected_bom_ref is not None and any(
            ref != expected_bom_ref for ref in change.impacted_bom_refs
        ):
            add(
                "engineering_change_bom_outside_scope",
                "engineering_changes",
                "blocking",
                "Engineering change impacts a BOM outside release scope.",
                artifact_ref=change.change_ref,
            )
        if change.status in {"rejected", "cancelled"}:
            if change.change_ref in configuration.engineering_change_refs:
                add(
                    "rejected_change_in_configuration",
                    "engineering_changes",
                    "blocking",
                    "Rejected or cancelled change is included in the release baseline.",
                    artifact_ref=change.change_ref,
                )
            else:
                add(
                    "nonexecuted_change_excluded",
                    "engineering_changes",
                    "info",
                    "Rejected or cancelled change was excluded from release controls.",
                    artifact_ref=change.change_ref,
                )
            continue
        if change.risk_tier in {"high", "critical"}:
            high_risk_change_refs.add(change.change_ref)
        if change.status not in {"completed", "closed"}:
            open_change_count += 1
            add(
                "engineering_change_not_complete",
                "engineering_changes",
                "blocking",
                "Release-relevant engineering change is not complete.",
                artifact_ref=change.change_ref,
            )
        if change.approval_status != "approved" or change.decision_ref is None:
            add(
                "engineering_change_approval_missing",
                "engineering_changes",
                "blocking",
                "Engineering change lacks an authoritative approval decision.",
                artifact_ref=change.change_ref,
            )
        if change.execution_status != "completed" or change.completed_at is None:
            add(
                "engineering_change_execution_incomplete",
                "engineering_changes",
                "blocking",
                "Engineering change execution is incomplete or unproven.",
                artifact_ref=change.change_ref,
            )
        if change.evidence_gap_count > 0:
            add(
                "engineering_change_evidence_gaps",
                "engineering_changes",
                "blocking",
                "Engineering change retains unresolved evidence gaps.",
                artifact_ref=change.change_ref,
            )
        if (
            change.target_configuration_baseline_ref
            != release.configuration_baseline_ref
        ):
            add(
                "engineering_change_not_bound_to_configuration",
                "engineering_changes",
                "blocking",
                "Engineering change is not bound to the release configuration baseline.",
                artifact_ref=change.change_ref,
            )
        if change.change_ref not in configuration.engineering_change_refs:
            add(
                "engineering_change_not_in_configuration",
                "engineering_changes",
                "blocking",
                "Completed engineering change is absent from the configuration baseline.",
                artifact_ref=change.change_ref,
            )
        if change.impacted_bom_refs and expected_bom_ref is not None:
            if change.target_bom_revision_ref != expected_bom_ref:
                add(
                    "engineering_change_not_bound_to_bom",
                    "engineering_changes",
                    "blocking",
                    "BOM-impacting engineering change is not bound to the release BOM.",
                    artifact_ref=change.change_ref,
                )
            if bom is not None and change.change_ref not in bom.engineering_change_refs:
                add(
                    "engineering_change_not_in_bom",
                    "engineering_changes",
                    "blocking",
                    "BOM-impacting engineering change is absent from the BOM revision.",
                    artifact_ref=change.change_ref,
                )
        if (
            release.change_cutoff_at is not None
            and change.completed_at is not None
            and _parse_timestamp(change.completed_at)
            > _parse_timestamp(release.change_cutoff_at)
        ):
            add(
                "post_cutoff_engineering_change",
                "engineering_changes",
                "review",
                "Engineering change completed after the declared release cutoff.",
                artifact_ref=change.change_ref,
            )

    valid_reviews: list[ProductDesignReviewSnapshot] = []
    future_review_types: set[DesignReviewType] = set()
    future_review_change_refs: set[str] = set()
    for review in inputs.design_reviews:
        completed_in_time = (
            review.completed_at is not None
            and _parse_timestamp(review.completed_at) <= analysis_at
        )
        if review.completed_at is not None and not completed_in_time:
            future_review_types.add(review.review_type)
            future_review_change_refs.update(review.reviewed_change_refs)
            add(
                "design_review_after_analysis_cutoff",
                "design_reviews",
                "blocking",
                "Design review completed after the analysis cutoff.",
                artifact_ref=review.review_ref,
            )
        for requirement_ref in sorted(
            set(review.reviewed_requirement_refs) - expected_requirement_refs
        ):
            add(
                "design_review_requirement_outside_scope",
                "design_reviews",
                "blocking",
                "Design review references a requirement outside release scope.",
                artifact_ref=review.review_ref,
                requirement_ref=requirement_ref,
            )
        if set(review.reviewed_specification_refs) - expected_specification_refs:
            add(
                "design_review_specification_outside_scope",
                "design_reviews",
                "blocking",
                "Design review references a specification outside release scope.",
                artifact_ref=review.review_ref,
            )
        if any(
            ref != release.configuration_baseline_ref
            for ref in review.reviewed_configuration_refs
        ):
            add(
                "design_review_configuration_outside_scope",
                "design_reviews",
                "blocking",
                "Design review references a configuration outside release scope.",
                artifact_ref=review.review_ref,
            )
        if expected_bom_ref is None and review.reviewed_bom_refs:
            add(
                "design_review_bom_outside_scope",
                "design_reviews",
                "blocking",
                "Design review references a BOM outside release scope.",
                artifact_ref=review.review_ref,
            )
        elif expected_bom_ref is not None and any(
            ref != expected_bom_ref for ref in review.reviewed_bom_refs
        ):
            add(
                "design_review_bom_outside_scope",
                "design_reviews",
                "blocking",
                "Design review references a BOM outside release scope.",
                artifact_ref=review.review_ref,
            )
        if set(review.reviewed_change_refs) - set(changes_by_ref):
            add(
                "design_review_change_snapshot_missing",
                "design_reviews",
                "blocking",
                "Design review references an engineering change absent from the packet.",
                artifact_ref=review.review_ref,
            )
        if review.status in {"planned", "in_progress", "rejected"}:
            add(
                "design_review_not_approved",
                "design_reviews",
                "blocking",
                "Release-relevant design review is not approved.",
                artifact_ref=review.review_ref,
            )
        elif review.status == "cancelled":
            add(
                "cancelled_design_review_excluded",
                "design_reviews",
                "info",
                "Cancelled design review was excluded.",
                artifact_ref=review.review_ref,
            )
        else:
            if review.decision_ref is None or review.completed_at is None:
                add(
                    "design_review_decision_missing",
                    "design_reviews",
                    "blocking",
                    "Approved design review lacks a completed decision reference.",
                    artifact_ref=review.review_ref,
                )
            if review.blocking_action_count > 0:
                add(
                    "design_review_blocking_actions_open",
                    "design_reviews",
                    "blocking",
                    "Design review retains blocking open actions.",
                    artifact_ref=review.review_ref,
                )
            elif (
                review.open_action_count > 0 or review.status == "approved_with_actions"
            ):
                add(
                    "design_review_actions_open",
                    "design_reviews",
                    "review",
                    "Design review is approved with open nonblocking actions.",
                    artifact_ref=review.review_ref,
                )
            if (
                review.decision_ref is not None
                and completed_in_time
                and review.blocking_action_count == 0
            ):
                valid_reviews.append(review)

    for review_type in inputs.policy.required_design_review_types:
        candidates = [
            review
            for review in valid_reviews
            if review.review_type == review_type
            and (
                review_type != "release"
                or release.configuration_baseline_ref
                in review.reviewed_configuration_refs
            )
        ]
        if not candidates:
            complete = population_complete("design_reviews_complete")
            future_candidate = review_type in future_review_types
            add(
                "required_design_review_missing"
                if complete and not future_candidate
                else "required_design_review_not_observed",
                "design_reviews",
                "blocking",
                f"Required {review_type} design review is missing or not approved."
                if complete and not future_candidate
                else f"Required {review_type} design review was not effective at the analysis cutoff.",
                artifact_ref=release.release_ref,
            )

    if inputs.policy.require_high_risk_change_review:
        for change_ref in sorted(high_risk_change_refs):
            if not any(
                change_ref in review.reviewed_change_refs for review in valid_reviews
            ):
                complete = population_complete("design_reviews_complete")
                future_candidate = change_ref in future_review_change_refs
                add(
                    "high_risk_change_review_missing"
                    if complete and not future_candidate
                    else "high_risk_change_review_not_observed",
                    "design_reviews",
                    "blocking",
                    "High-risk engineering change lacks an approved design review."
                    if complete and not future_candidate
                    else "High-risk change review was not effective at the analysis cutoff.",
                    artifact_ref=change_ref,
                )

    verified_requirements: set[str] = set()
    validated_requirements: set[str] = set()
    future_verified_requirements: set[str] = set()
    future_validated_requirements: set[str] = set()
    for record in inputs.verification_validation_records:
        if record.executed_at is not None and (
            _parse_timestamp(record.executed_at) > analysis_at
        ):
            future_target = (
                future_verified_requirements
                if record.activity_kind == "verification"
                else future_validated_requirements
            )
            future_target.update(record.requirement_refs)
            add(
                "verification_validation_after_analysis_cutoff",
                "verification_validation",
                "blocking",
                "Verification or validation record executed after the analysis cutoff.",
                artifact_ref=record.record_ref,
            )
            continue
        if record.configuration_baseline_ref != release.configuration_baseline_ref:
            add(
                "verification_validation_configuration_mismatch",
                "verification_validation",
                "blocking",
                "Verification or validation record targets a different configuration.",
                artifact_ref=record.record_ref,
            )
            continue
        invalid_requirements = set(record.requirement_refs) - expected_requirement_refs
        invalid_specifications = (
            set(record.specification_refs) - expected_specification_refs
        )
        if invalid_requirements:
            add(
                "verification_validation_requirement_outside_scope",
                "verification_validation",
                "blocking",
                "Verification or validation traces to a requirement outside release scope.",
                artifact_ref=record.record_ref,
                requirement_ref=sorted(invalid_requirements)[0],
            )
        if invalid_specifications:
            add(
                "verification_validation_specification_outside_scope",
                "verification_validation",
                "blocking",
                "Verification or validation traces to a specification outside release scope.",
                artifact_ref=record.record_ref,
            )
        if invalid_requirements or invalid_specifications:
            continue

        covered = False
        if record.status == "passed":
            if (
                record.protocol_ref is None
                or record.result_ref is None
                or record.executed_at is None
            ):
                add(
                    "verification_validation_result_missing",
                    "verification_validation",
                    "blocking",
                    "Passed verification or validation lacks protocol, result, or execution evidence.",
                    artifact_ref=record.record_ref,
                )
            else:
                covered = True
        elif record.status == "failed":
            add(
                "verification_validation_failed",
                "verification_validation",
                "blocking",
                "Verification or validation has a failed result.",
                artifact_ref=record.record_ref,
            )
        elif record.status in {"waived", "not_applicable"}:
            if record.waiver_ref is None:
                add(
                    "verification_validation_waiver_missing",
                    "verification_validation",
                    "blocking",
                    "Waived or not-applicable activity lacks a waiver reference.",
                    artifact_ref=record.record_ref,
                )
            elif not inputs.policy.allow_verification_validation_waivers:
                add(
                    "verification_validation_waiver_not_allowed",
                    "verification_validation",
                    "blocking",
                    "Active policy does not allow verification or validation waivers.",
                    artifact_ref=record.record_ref,
                )
            else:
                covered = True
                add(
                    "verification_validation_waiver_requires_review",
                    "verification_validation",
                    "review",
                    "Verification or validation waiver requires authoritative human review.",
                    artifact_ref=record.record_ref,
                )
        else:
            add(
                "verification_validation_incomplete",
                "verification_validation",
                "info",
                "Verification or validation activity is not complete.",
                artifact_ref=record.record_ref,
            )

        if covered:
            target = (
                verified_requirements
                if record.activity_kind == "verification"
                else validated_requirements
            )
            target.update(record.requirement_refs)

    for requirement_ref in sorted(expected_requirement_refs):
        if requirement_ref not in verified_requirements:
            complete = population_complete("verification_validation_complete")
            future_candidate = requirement_ref in future_verified_requirements
            add(
                "verification_missing"
                if complete and not future_candidate
                else "verification_not_observed",
                "verification_validation",
                "blocking",
                "Requirement lacks passing verification traceability."
                if complete and not future_candidate
                else "Requirement verification was not effective at the analysis cutoff.",
                artifact_ref=release.release_ref,
                requirement_ref=requirement_ref,
            )
        if (
            inputs.policy.require_validation
            and requirement_ref not in validated_requirements
        ):
            complete = population_complete("verification_validation_complete")
            future_candidate = requirement_ref in future_validated_requirements
            add(
                "validation_missing"
                if complete and not future_candidate
                else "validation_not_observed",
                "verification_validation",
                "blocking",
                "Requirement lacks passing validation traceability."
                if complete and not future_candidate
                else "Requirement validation was not effective at the analysis cutoff.",
                artifact_ref=release.release_ref,
                requirement_ref=requirement_ref,
            )

    applicable_telemetry_count = 0
    future_telemetry_count = 0
    telemetry_signal_count = 0
    breached_telemetry_signal_count = 0
    for snapshot in inputs.telemetry:
        if snapshot.product_ref != release.product_ref:
            add(
                "telemetry_product_mismatch",
                "telemetry",
                "blocking",
                "Telemetry snapshot belongs to a different product.",
                artifact_ref=snapshot.telemetry_ref,
            )
            continue
        if snapshot.configuration_baseline_ref != release.configuration_baseline_ref:
            add(
                "telemetry_configuration_mismatch",
                "telemetry",
                "blocking",
                "Telemetry snapshot targets a different configuration baseline.",
                artifact_ref=snapshot.telemetry_ref,
            )
            continue
        if (
            snapshot.subject_release_ref is not None
            and snapshot.subject_release_ref != release.release_ref
        ):
            add(
                "telemetry_outside_release_scope",
                "telemetry",
                "info",
                "Telemetry snapshot targets a different release and was excluded.",
                artifact_ref=snapshot.telemetry_ref,
            )
            continue
        if _parse_timestamp(snapshot.window_end) > analysis_at:
            future_telemetry_count += 1
            add(
                "telemetry_after_analysis_cutoff",
                "telemetry",
                "blocking",
                "Telemetry window ends after the analysis cutoff and was excluded.",
                artifact_ref=snapshot.telemetry_ref,
            )
            continue
        applicable_telemetry_count += 1
        telemetry_signal_count += len(snapshot.signals)
        if snapshot.sample_size < inputs.policy.minimum_telemetry_sample_size:
            add(
                "telemetry_below_minimum_sample",
                "telemetry",
                "blocking",
                "Telemetry sample size is below the active policy minimum.",
                artifact_ref=snapshot.telemetry_ref,
            )
        for signal in snapshot.signals:
            if signal.status == "breached":
                breached_telemetry_signal_count += 1
                add(
                    "telemetry_threshold_breached",
                    "telemetry",
                    "blocking",
                    "Product telemetry breaches a release threshold.",
                    artifact_ref=signal.signal_ref,
                )
            elif signal.status == "warning":
                add(
                    "telemetry_warning",
                    "telemetry",
                    "review",
                    "Product telemetry is within a warning band.",
                    artifact_ref=signal.signal_ref,
                )
            elif signal.status == "insufficient_data":
                add(
                    "telemetry_signal_insufficient",
                    "telemetry",
                    "blocking",
                    "Telemetry signal has insufficient data for a release decision.",
                    artifact_ref=signal.signal_ref,
                )

    if inputs.policy.require_telemetry and applicable_telemetry_count == 0:
        if future_telemetry_count == 0:
            complete = population_complete("telemetry_complete")
            add(
                "required_telemetry_missing" if complete else "telemetry_not_observed",
                "telemetry",
                "blocking",
                "Required release telemetry is missing."
                if complete
                else "Required release telemetry was not observed in an incomplete population.",
                artifact_ref=release.release_ref,
            )

    unresolved_vulnerability_count = 0
    unresolved_defect_count = 0
    unresolved_statuses = {
        "open",
        "triaged",
        "in_remediation",
        "remediated_pending_verification",
        "accepted_risk",
        "deferred",
    }
    for issue in inputs.issues:
        if issue.product_ref != release.product_ref:
            add(
                "issue_product_mismatch",
                "issues",
                "blocking",
                "Vulnerability or defect belongs to a different product.",
                artifact_ref=issue.issue_ref,
            )
            continue
        has_scope = bool(
            issue.affected_release_refs
            or issue.affected_configuration_refs
            or issue.affected_specification_refs
        )
        relevant = not has_scope or bool(
            release.release_ref in issue.affected_release_refs
            or release.configuration_baseline_ref in issue.affected_configuration_refs
            or expected_specification_refs.intersection(
                issue.affected_specification_refs
            )
        )
        if not relevant:
            add(
                "issue_outside_release_scope",
                "issues",
                "info",
                "Vulnerability or defect does not affect the release scope.",
                artifact_ref=issue.issue_ref,
            )
            continue
        if issue.status in unresolved_statuses:
            if issue.kind == "vulnerability":
                unresolved_vulnerability_count += 1
            else:
                unresolved_defect_count += 1
        if (
            issue.status in unresolved_statuses
            and issue.due_at is not None
            and _parse_timestamp(issue.due_at) < analysis_at
        ):
            add(
                "issue_disposition_overdue",
                "issues",
                "blocking",
                "Vulnerability or defect disposition is overdue.",
                artifact_ref=issue.issue_ref,
            )
        if issue.status == "resolved":
            if (
                issue.disposition_ref is None
                or issue.remediation_verification_ref is None
            ):
                add(
                    "issue_resolution_unverified",
                    "issues",
                    "blocking",
                    "Resolved vulnerability or defect lacks disposition and verification references.",
                    artifact_ref=issue.issue_ref,
                )
        elif issue.status == "false_positive":
            if issue.disposition_ref is None:
                add(
                    "false_positive_disposition_missing",
                    "issues",
                    "blocking",
                    "False-positive disposition lacks an authoritative reference.",
                    artifact_ref=issue.issue_ref,
                )
            else:
                add(
                    "false_positive_issue_excluded",
                    "issues",
                    "info",
                    "Authoritatively dispositioned false-positive issue was excluded.",
                    artifact_ref=issue.issue_ref,
                )
        elif issue.status in {"accepted_risk", "deferred"}:
            if issue.disposition_ref is None:
                add(
                    "issue_disposition_missing",
                    "issues",
                    "blocking",
                    "Accepted or deferred issue lacks an authoritative disposition.",
                    artifact_ref=issue.issue_ref,
                )
            else:
                add(
                    "issue_disposition_requires_review",
                    "issues",
                    "review",
                    "Accepted-risk or deferred issue requires authoritative release review.",
                    artifact_ref=issue.issue_ref,
                )
        elif issue.status in unresolved_statuses:
            if issue.severity in inputs.policy.blocking_issue_severities:
                add(
                    "blocking_issue_unresolved",
                    "issues",
                    "blocking",
                    "High-severity vulnerability or defect remains unresolved.",
                    artifact_ref=issue.issue_ref,
                )
            else:
                add(
                    "nonblocking_issue_unresolved",
                    "issues",
                    "review",
                    "Lower-severity vulnerability or defect remains unresolved.",
                    artifact_ref=issue.issue_ref,
                )

    gates: list[ReleaseGovernanceGateResult] = []
    for gate in _GATE_ORDER:
        gate_findings = [item for item in findings if item.gate == gate]
        codes = tuple(sorted({item.code for item in gate_findings}))
        if any(
            item.severity == "blocking" and item.code not in _INDETERMINATE_CODES
            for item in gate_findings
        ):
            status: ReleaseGovernanceGateStatus = "fail"
        elif any(item.code in _INDETERMINATE_CODES for item in gate_findings):
            status = "indeterminate"
        elif any(item.severity == "review" for item in gate_findings):
            status = "review"
        else:
            status = "pass"
        gates.append(
            ReleaseGovernanceGateResult(
                gate=gate,
                status=status,
                finding_codes=codes,
            )
        )

    if any(item.status == "fail" for item in gates):
        disposition: ReleaseGovernanceDisposition = "blocked"
    elif any(item.status == "indeterminate" for item in gates):
        disposition = "indeterminate"
    elif any(item.status == "review" for item in gates):
        disposition = "manual_review"
    else:
        disposition = "ready"

    source_snapshot_digests: dict[str, str] = {
        "evidence_coverage": _model_digest(coverage),
        "release_scope": _model_digest(release),
        "configuration": _model_digest(configuration),
        "policy": _model_digest(inputs.policy),
    }
    if bom is not None:
        source_snapshot_digests["bom"] = _model_digest(bom)
    source_snapshot_digests.update(
        {
            f"requirement:{item.requirement_ref}": _model_digest(item)
            for item in inputs.requirements
        }
    )
    source_snapshot_digests.update(
        {
            f"specification:{item.specification_ref}": _model_digest(item)
            for item in inputs.specifications
        }
    )
    source_snapshot_digests.update(
        {
            f"engineering_change:{item.change_ref}": _model_digest(item)
            for item in inputs.engineering_changes
        }
    )
    source_snapshot_digests.update(
        {
            f"design_review:{item.review_ref}": _model_digest(item)
            for item in inputs.design_reviews
        }
    )
    source_snapshot_digests.update(
        {
            f"verification_validation:{item.record_ref}": _model_digest(item)
            for item in inputs.verification_validation_records
        }
    )
    source_snapshot_digests.update(
        {
            f"telemetry:{item.telemetry_ref}": _model_digest(item)
            for item in inputs.telemetry
        }
    )
    source_snapshot_digests.update(
        {f"issue:{item.issue_ref}": _model_digest(item) for item in inputs.issues}
    )

    all_evidence = [
        evidence
        for _, _, evidence_refs, _ in evidence_sets
        for evidence in evidence_refs
    ]
    evidence_ref_names = tuple(sorted({item.evidence_ref for item in all_evidence}))
    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                _GATE_ORDER.index(item.gate),
                item.artifact_ref or "",
                item.requirement_ref or "",
                item.code,
            ),
        )
    )
    approved_design_review_count = sum(
        1
        for review in inputs.design_reviews
        if review.status in {"approved", "approved_with_actions"}
        and review.decision_ref is not None
        and review.completed_at is not None
        and _parse_timestamp(review.completed_at) <= analysis_at
    )
    result = ReleaseGovernanceResult(
        evaluation_ref=inputs.evaluation_ref,
        analysis_as_of=inputs.analysis_as_of,
        release_ref=release.release_ref,
        release_version=release.release_version,
        assurance_grade=assurance_grade,
        disposition=disposition,
        gates=tuple(gates),
        findings=ordered_findings,
        coverage=ReleaseGovernanceCoverageSummary(
            scoped_requirement_count=len(expected_requirement_refs),
            requirement_snapshot_count=len(inputs.requirements),
            scoped_specification_count=len(expected_specification_refs),
            specification_snapshot_count=len(inputs.specifications),
            verified_requirement_count=len(
                verified_requirements.intersection(expected_requirement_refs)
            ),
            validated_requirement_count=len(
                validated_requirements.intersection(expected_requirement_refs)
            ),
            approved_design_review_count=approved_design_review_count,
            open_engineering_change_count=open_change_count,
            telemetry_signal_count=telemetry_signal_count,
            breached_telemetry_signal_count=breached_telemetry_signal_count,
            unresolved_vulnerability_count=unresolved_vulnerability_count,
            unresolved_defect_count=unresolved_defect_count,
        ),
        source_snapshot_digests=source_snapshot_digests,
        evidence_refs=evidence_ref_names,
    )
    return result


def _example_evidence(evidence_ref: str, digest_character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": "normalized_product_governance_snapshot",
        "issuer_ref": "spring-product-governance-authority",
        "sha256": digest_character * 64,
        "observed_at": "2026-08-24T10:00:00Z",
        "verification_grade": "attested",
        "classification": "confidential",
        "retention_policy": "product-lifecycle-seven-years",
        "jurisdiction": "US",
    }


class EvaluateReleaseGovernanceControlsPrimitive(
    BusinessProcessPrimitive[ReleaseGovernanceInput, ReleaseGovernanceResult]
):
    primitive_ref = "product.evaluate_release_governance_controls"
    version = "1.0.0"
    title = "Evaluate product release governance controls"
    description = (
        "Evaluate evidence-bound requirements, release scope, specifications, "
        "configuration, BOM, changes, reviews, V&V, telemetry, vulnerabilities, "
        "and defects without authorizing or mutating lifecycle systems."
    )
    input_model = ReleaseGovernanceInput
    output_model = ReleaseGovernanceResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "evaluation_ref": "release-governance-example-1",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "evidence_coverage": {
            "coverage_ref": "coverage-release-1-4-0",
            "release_ref": "release-1-4-0",
            "captured_at": "2026-08-24T10:00:00Z",
            "requirements_complete": True,
            "specifications_complete": True,
            "bom_complete": True,
            "engineering_changes_complete": True,
            "design_reviews_complete": True,
            "verification_validation_complete": True,
            "telemetry_complete": True,
            "issues_complete": True,
            "evidence_refs": [_example_evidence("coverage-evidence", "a")],
        },
        "release_scope": {
            "release_ref": "release-1-4-0",
            "product_ref": "product-lightbulb",
            "release_version": "1.4.0",
            "release_kind": "minor",
            "status": "candidate",
            "roadmap_item_refs": ["roadmap-item-secure-export"],
            "requirement_refs": ["requirement-secure-export"],
            "specification_refs": ["specification-secure-export"],
            "configuration_baseline_ref": "configuration-1-4-0-rc1",
            "bom_revision_ref": "bom-1-4-0-rc1",
            "owner_ref": "product-owner-lightbulb",
            "planned_release_at": "2026-08-30T12:00:00Z",
            "change_cutoff_at": "2026-08-23T12:00:00Z",
            "evidence_refs": [_example_evidence("release-evidence", "b")],
        },
        "requirements": [
            {
                "requirement_ref": "requirement-secure-export",
                "revision": 3,
                "kind": "security",
                "status": "validated",
                "roadmap_item_ref": "roadmap-item-secure-export",
                "acceptance_criteria_refs": ["criterion-export-encrypted"],
                "specification_refs": ["specification-secure-export"],
                "approval_ref": "requirement-approval-3",
                "evidence_refs": [_example_evidence("requirement-evidence", "c")],
            }
        ],
        "specifications": [
            {
                "specification_ref": "specification-secure-export",
                "revision": 2,
                "status": "approved",
                "requirement_refs": ["requirement-secure-export"],
                "configuration_item_refs": ["component-export-service"],
                "approval_ref": "specification-approval-2",
                "evidence_refs": [_example_evidence("specification-evidence", "d")],
            }
        ],
        "configuration": {
            "configuration_baseline_ref": "configuration-1-4-0-rc1",
            "revision": 1,
            "product_ref": "product-lightbulb",
            "status": "frozen",
            "specification_refs": ["specification-secure-export"],
            "configuration_item_refs": ["component-export-service"],
            "bom_revision_ref": "bom-1-4-0-rc1",
            "engineering_change_refs": ["change-secure-export"],
            "content_sha256": "7" * 64,
            "approval_ref": "configuration-approval-1",
            "evidence_refs": [_example_evidence("configuration-evidence", "e")],
        },
        "bom": {
            "bom_revision_ref": "bom-1-4-0-rc1",
            "revision": 1,
            "product_ref": "product-lightbulb",
            "configuration_baseline_ref": "configuration-1-4-0-rc1",
            "status": "approved",
            "component_refs": ["component-export-service"],
            "engineering_change_refs": ["change-secure-export"],
            "approval_ref": "bom-approval-1",
            "evidence_refs": [_example_evidence("bom-evidence", "f")],
        },
        "engineering_changes": [
            {
                "change_ref": "change-secure-export",
                "product_ref": "product-lightbulb",
                "status": "completed",
                "risk_tier": "high",
                "approval_status": "approved",
                "execution_status": "completed",
                "impacted_requirement_refs": ["requirement-secure-export"],
                "impacted_specification_refs": ["specification-secure-export"],
                "impacted_configuration_refs": ["configuration-1-4-0-rc1"],
                "impacted_bom_refs": ["bom-1-4-0-rc1"],
                "target_configuration_baseline_ref": "configuration-1-4-0-rc1",
                "target_bom_revision_ref": "bom-1-4-0-rc1",
                "evidence_gap_count": 0,
                "requested_at": "2026-08-01T12:00:00Z",
                "completed_at": "2026-08-22T12:00:00Z",
                "decision_ref": "change-decision-secure-export",
                "evidence_refs": [_example_evidence("change-evidence", "1")],
            }
        ],
        "design_reviews": [
            {
                "review_ref": "review-release-1-4-0",
                "review_type": "release",
                "status": "approved",
                "reviewed_requirement_refs": ["requirement-secure-export"],
                "reviewed_specification_refs": ["specification-secure-export"],
                "reviewed_configuration_refs": ["configuration-1-4-0-rc1"],
                "reviewed_bom_refs": ["bom-1-4-0-rc1"],
                "reviewed_change_refs": ["change-secure-export"],
                "open_action_count": 0,
                "blocking_action_count": 0,
                "decision_ref": "review-decision-release-1-4-0",
                "completed_at": "2026-08-23T10:00:00Z",
                "evidence_refs": [_example_evidence("review-evidence", "2")],
            }
        ],
        "verification_validation_records": [
            {
                "record_ref": "verification-secure-export",
                "activity_kind": "verification",
                "method": "test",
                "status": "passed",
                "requirement_refs": ["requirement-secure-export"],
                "specification_refs": ["specification-secure-export"],
                "configuration_baseline_ref": "configuration-1-4-0-rc1",
                "protocol_ref": "protocol-secure-export-verification",
                "result_ref": "result-secure-export-verification",
                "executed_at": "2026-08-23T10:30:00Z",
                "evidence_refs": [_example_evidence("verification-evidence", "3")],
            },
            {
                "record_ref": "validation-secure-export",
                "activity_kind": "validation",
                "method": "demonstration",
                "status": "passed",
                "requirement_refs": ["requirement-secure-export"],
                "specification_refs": ["specification-secure-export"],
                "configuration_baseline_ref": "configuration-1-4-0-rc1",
                "protocol_ref": "protocol-secure-export-validation",
                "result_ref": "result-secure-export-validation",
                "executed_at": "2026-08-23T11:00:00Z",
                "evidence_refs": [_example_evidence("validation-evidence", "4")],
            },
        ],
        "telemetry": [
            {
                "telemetry_ref": "telemetry-secure-export-pilot",
                "product_ref": "product-lightbulb",
                "subject_release_ref": "release-1-4-0",
                "configuration_baseline_ref": "configuration-1-4-0-rc1",
                "environment": "pilot",
                "window_start": "2026-08-20T09:00:00Z",
                "window_end": "2026-08-24T09:00:00Z",
                "sample_size": 5_000,
                "signals": [
                    {
                        "signal_ref": "signal-crash-free-sessions",
                        "metric_name": "crash_free_sessions_ratio",
                        "status": "within_threshold",
                        "observed_value": "0.999000",
                        "threshold_value": "0.995000",
                        "unit": "ratio",
                    }
                ],
                "evidence_refs": [_example_evidence("telemetry-evidence", "5")],
            }
        ],
        "issues": [
            {
                "issue_ref": "vulnerability-export-library",
                "product_ref": "product-lightbulb",
                "kind": "vulnerability",
                "severity": "critical",
                "status": "resolved",
                "affected_release_refs": ["release-1-4-0"],
                "affected_configuration_refs": ["configuration-1-4-0-rc1"],
                "affected_specification_refs": ["specification-secure-export"],
                "detected_at": "2026-08-01T12:00:00Z",
                "due_at": "2026-08-20T12:00:00Z",
                "disposition_ref": "disposition-vulnerability-remediated",
                "remediation_verification_ref": "verification-vulnerability-fixed",
                "evidence_refs": [_example_evidence("issue-evidence", "6")],
            }
        ],
        "policy": {
            "minimum_evidence_grade": "attested",
            "max_evidence_age_hours": 168,
            "max_telemetry_evidence_age_hours": 48,
            "require_bom": True,
            "require_validation": True,
            "require_telemetry": True,
            "minimum_telemetry_sample_size": 100,
            "required_design_review_types": ["release"],
            "blocking_issue_severities": ["high", "critical"],
            "require_high_risk_change_review": True,
            "allow_verification_validation_waivers": False,
        },
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PRODUCT_GOVERNANCE_CONTROL_OPERATION.to_dict()
        contract["effect_boundary"] = ProductGovernanceEffectBoundary().to_dict()
        contract["source_snapshot_authority"] = "trusted_host_required"
        contract["authority_boundary"] = {
            "sdk": "deterministic_release_control_evaluation_only",
            "spring": [
                "tenant_and_company_scope",
                "rbac",
                "source_normalization",
                "release_and_change_approval",
                "persistence_and_audit",
            ],
            "connectors": "not_invoked_by_this_primitive",
            "release_authority": "never_granted_by_this_primitive",
            "configuration_authority": "never_granted_by_this_primitive",
            "engineering_change_authority": "never_granted_by_this_primitive",
            "issue_disposition_authority": "never_granted_by_this_primitive",
        }
        contract["recovery_semantics"] = {
            "external_operations": 0,
            "replay_class": "safe",
            "crash_recovery": "not_required",
            "same_input_same_result_digest": True,
            "source_refresh_owned_by": "trusted_host",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReleaseGovernanceInput,
    ) -> PrimitiveExecutionResult[ReleaseGovernanceResult]:
        del context
        output = evaluate_release_governance_controls(inputs)
        evidence_groups: list[tuple[PrimitiveEvidenceRef, ...]] = [
            inputs.evidence_coverage.evidence_refs,
            inputs.release_scope.evidence_refs,
            inputs.configuration.evidence_refs,
            *(item.evidence_refs for item in inputs.requirements),
            *(item.evidence_refs for item in inputs.specifications),
            *(item.evidence_refs for item in inputs.engineering_changes),
            *(item.evidence_refs for item in inputs.design_reviews),
            *(item.evidence_refs for item in inputs.verification_validation_records),
            *(item.evidence_refs for item in inputs.telemetry),
            *(item.evidence_refs for item in inputs.issues),
        ]
        if inputs.bom is not None:
            evidence_groups.append(inputs.bom.evidence_refs)
        evidence_by_ref = {
            evidence.evidence_ref: evidence
            for evidence_group in evidence_groups
            for evidence in evidence_group
        }
        evidence_refs = [
            evidence_by_ref[evidence_ref] for evidence_ref in sorted(evidence_by_ref)
        ]
        receipt = PrimitiveOperationReceipt(
            spec=PRODUCT_GOVERNANCE_CONTROL_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=product_governance_snapshot_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[ReleaseGovernanceResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Product release governance controls evaluated; the result is a "
                f"non-authorizing readiness proposal with disposition {output.disposition}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="product.release_governance_controls_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "release_ref": output.release_ref,
                        "disposition": output.disposition,
                        "assurance_grade": output.assurance_grade.value,
                        "finding_count": len(output.findings),
                        "release_authorized": False,
                        "live_systems_changed": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="product_release_governance_result",
                    summary=(
                        "The SDK evaluated normalized product-lifecycle evidence "
                        "without approving a release or changing lifecycle systems."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "PRODUCT_BOM_SNAPSHOT_SCHEMA",
    "PRODUCT_CONFIGURATION_SNAPSHOT_SCHEMA",
    "PRODUCT_DESIGN_REVIEW_SNAPSHOT_SCHEMA",
    "PRODUCT_ENGINEERING_CHANGE_SNAPSHOT_SCHEMA",
    "PRODUCT_GOVERNANCE_EVIDENCE_COVERAGE_SCHEMA",
    "PRODUCT_GOVERNANCE_CONTROL_OPERATION",
    "PRODUCT_ISSUE_SNAPSHOT_SCHEMA",
    "PRODUCT_REQUIREMENT_SNAPSHOT_SCHEMA",
    "PRODUCT_ROADMAP_RELEASE_SCOPE_SCHEMA",
    "PRODUCT_SPECIFICATION_SNAPSHOT_SCHEMA",
    "PRODUCT_TELEMETRY_SNAPSHOT_SCHEMA",
    "PRODUCT_VERIFICATION_VALIDATION_RECORD_SCHEMA",
    "RELEASE_GOVERNANCE_INPUT_SCHEMA",
    "RELEASE_GOVERNANCE_RESULT_SCHEMA",
    "EvaluateReleaseGovernanceControlsPrimitive",
    "ProductBomSnapshot",
    "ProductConfigurationSnapshot",
    "ProductDesignReviewSnapshot",
    "ProductEngineeringChangeSnapshot",
    "ProductGovernanceEffectBoundary",
    "ProductGovernanceEvidenceCoverage",
    "ProductIssueSnapshot",
    "ProductRequirementSnapshot",
    "ProductRoadmapReleaseScope",
    "ProductSpecificationSnapshot",
    "ProductTelemetrySignal",
    "ProductTelemetrySnapshot",
    "ProductVerificationValidationRecord",
    "ReleaseGovernanceCoverageSummary",
    "ReleaseGovernanceFinding",
    "ReleaseGovernanceGateResult",
    "ReleaseGovernanceInput",
    "ReleaseGovernancePolicy",
    "ReleaseGovernanceResult",
    "evaluate_release_governance_controls",
    "product_governance_snapshot_digest",
]
