"""Evidence-bound manufacturing release and completion control evaluation.

This module owns deterministic SDK mechanics only. It evaluates normalized BOM,
routing, production-order, inventory, execution, quality, nonconformance, and
maintenance evidence. It never releases or completes an order, moves inventory,
dispositions quality, closes CAPA, or changes a physical system of record.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
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


BILL_OF_MATERIAL_SNAPSHOT_SCHEMA = "lightbulb.bill_of_material_snapshot.v1"
MANUFACTURING_ROUTING_SNAPSHOT_SCHEMA = "lightbulb.manufacturing_routing_snapshot.v1"
PRODUCTION_ORDER_SNAPSHOT_SCHEMA = "lightbulb.production_order_snapshot.v1"
MANUFACTURING_CONTROL_INPUT_SCHEMA = "lightbulb.manufacturing_control_input.v1"
MANUFACTURING_CONTROL_RESULT_SCHEMA = "lightbulb.manufacturing_control_result.v1"

_QUANTITY_QUANTUM = Decimal("0.000001")
_ZERO_DIGEST = "0" * 64
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
UnitCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9._/-]{0,31}$",
    ),
]

EvaluationTarget = Literal["release", "completion"]
GateName = Literal[
    "evidence",
    "configuration",
    "order",
    "material",
    "work_center",
    "execution",
    "quality",
    "nonconformance",
]
GateStatus = Literal["pass", "review", "fail", "indeterminate"]
_GATE_ORDER: tuple[GateName, ...] = (
    "evidence",
    "configuration",
    "order",
    "material",
    "work_center",
    "execution",
    "quality",
    "nonconformance",
)
FindingSeverity = Literal["info", "review", "blocking"]
Disposition = Literal[
    "eligible_for_release_approval",
    "eligible_for_completion_approval",
    "manual_review_required",
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
    return tuple(value) if isinstance(value, list) else value


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


def _quantity(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("quantities must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("quantities must use bounded notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(_QUANTITY_QUANTUM)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(
            "quantities must be finite and within supported precision"
        ) from exc
    if not parsed.is_finite() or parsed != normalized:
        raise ValueError("quantities support at most six decimal places")
    if parsed < 0:
        raise ValueError("quantities must be non-negative")
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


def manufacturing_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    """Return a stable digest for one normalized manufacturing snapshot."""

    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


def _unique(values: Sequence[Any], *, field: str, label: str) -> None:
    refs = [str(getattr(value, field)) for value in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{label} references must be unique")


class MaterialTraceRef(_StrictModel):
    kind: Literal["batch", "lot", "serial"]
    trace_ref: OpaqueRef


class BillOfMaterialComponent(_StrictModel):
    component_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_per_unit: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    lot_controlled: bool = False
    serial_controlled: bool = False
    approved_alternate_item_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )

    @field_validator("quantity_per_unit", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("approved_alternate_item_refs", mode="before")
    @classmethod
    def _alternate_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_alternates(self) -> "BillOfMaterialComponent":
        if len(self.approved_alternate_item_refs) != len(
            set(self.approved_alternate_item_refs)
        ):
            raise ValueError("approved alternate item references must be unique")
        if self.item_ref in self.approved_alternate_item_refs:
            raise ValueError("the primary item cannot also be an alternate")
        return self


class BillOfMaterialSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.bill_of_material_snapshot.v1"] = Field(
        default=BILL_OF_MATERIAL_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    bom_ref: OpaqueRef
    product_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: Literal["draft", "pending_approval", "approved", "obsolete"]
    effective_from: str
    effective_until: str | None = None
    components: tuple[BillOfMaterialComponent, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("effective_from")
    @classmethod
    def _valid_effective_from(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_from")

    @field_validator("effective_until")
    @classmethod
    def _valid_effective_until(cls, value: str | None) -> str | None:
        return (
            None if value is None else _timestamp(value, field_name="effective_until")
        )

    @field_validator("components", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_bom(self) -> "BillOfMaterialSnapshot":
        _unique(self.components, field="component_ref", label="BOM component")
        if self.effective_until is not None and _parsed_timestamp(
            self.effective_until
        ) <= _parsed_timestamp(self.effective_from):
            raise ValueError("effective_until must be after effective_from")
        return self


class RoutingStep(_StrictModel):
    sequence: int = Field(ge=1)
    operation_ref: OpaqueRef
    work_center_ref: OpaqueRef
    work_instruction_ref: OpaqueRef
    work_instruction_revision: int = Field(ge=1)
    required_certification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )

    @field_validator("required_certification_refs", mode="before")
    @classmethod
    def _certification_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ManufacturingRoutingSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_routing_snapshot.v1"] = Field(
        default=MANUFACTURING_ROUTING_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    routing_ref: OpaqueRef
    product_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: Literal["draft", "pending_approval", "approved", "obsolete"]
    steps: tuple[RoutingStep, ...] = Field(min_length=1, max_length=1_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("steps", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_routing(self) -> "ManufacturingRoutingSnapshot":
        _unique(self.steps, field="sequence", label="routing step sequence")
        _unique(self.steps, field="operation_ref", label="routing operation")
        return self


class ProductionOrderSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.production_order_snapshot.v1"] = Field(
        default=PRODUCTION_ORDER_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    production_order_ref: OpaqueRef
    product_ref: OpaqueRef
    site_ref: OpaqueRef
    planned_quantity: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    bom_ref: OpaqueRef
    bom_revision: int = Field(ge=1)
    routing_ref: OpaqueRef
    routing_revision: int = Field(ge=1)
    status: Literal[
        "planned",
        "approved",
        "released",
        "in_process",
        "completed",
        "on_hold",
        "cancelled",
    ]
    approval_ref: OpaqueRef | None = None
    scheduled_start: str
    scheduled_end: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("planned_quantity", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("scheduled_start", "scheduled_end")
    @classmethod
    def _valid_timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_schedule(self) -> "ProductionOrderSnapshot":
        if _parsed_timestamp(self.scheduled_end) <= _parsed_timestamp(
            self.scheduled_start
        ):
            raise ValueError("scheduled_end must be after scheduled_start")
        return self


class MaterialAllocation(_StrictModel):
    allocation_ref: OpaqueRef
    component_ref: OpaqueRef
    item_ref: OpaqueRef
    allocated_quantity: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    availability: Literal["available", "quarantined", "expired", "unknown"]
    trace_refs: tuple[MaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=5_000,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("allocated_quantity", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("trace_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_trace(self) -> "MaterialAllocation":
        _unique(self.trace_refs, field="trace_ref", label="material trace")
        return self


class WorkCenterReadiness(_StrictModel):
    work_center_ref: OpaqueRef
    availability: Literal["ready", "maintenance_due", "out_of_service", "unknown"]
    calibration_current: bool | None = None
    maintenance_work_order_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class WorkExecutionRecord(_StrictModel):
    execution_ref: OpaqueRef
    production_order_ref: OpaqueRef
    bom_ref: OpaqueRef
    bom_revision: int = Field(ge=1)
    routing_ref: OpaqueRef
    routing_revision: int = Field(ge=1)
    routing_step_sequence: int = Field(ge=1)
    status: Literal["not_started", "in_process", "completed", "failed", "skipped"]
    quantity_completed: Decimal = Field(ge=0)
    operator_ref: OpaqueRef | None = None
    certification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    output_trace_refs: tuple[MaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    started_at: str | None = None
    completed_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("quantity_completed", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator(
        "certification_refs",
        "output_trace_refs",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _valid_execution_time(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_execution(self) -> "WorkExecutionRecord":
        if self.status == "completed" and (
            self.operator_ref is None
            or self.started_at is None
            or self.completed_at is None
        ):
            raise ValueError(
                "completed execution requires operator_ref, started_at, and completed_at"
            )
        if self.status == "in_process" and self.started_at is None:
            raise ValueError("in-process execution requires started_at")
        if self.status == "not_started" and (
            self.started_at is not None or self.completed_at is not None
        ):
            raise ValueError("not-started execution cannot carry business timestamps")
        if self.completed_at is not None and self.started_at is None:
            raise ValueError("completed_at requires started_at")
        if self.completed_at is not None and _parsed_timestamp(
            self.completed_at
        ) < _parsed_timestamp(self.started_at):
            raise ValueError("execution completion cannot precede execution start")
        _unique(self.output_trace_refs, field="trace_ref", label="output trace")
        return self


class QualityInspection(_StrictModel):
    inspection_ref: OpaqueRef
    production_order_ref: OpaqueRef
    bom_ref: OpaqueRef
    bom_revision: int = Field(ge=1)
    routing_ref: OpaqueRef
    routing_revision: int = Field(ge=1)
    stage: Literal["incoming", "in_process", "final"]
    status: Literal["pending", "passed", "failed", "waived"]
    quantity_inspected: Decimal = Field(ge=0)
    quantity_accepted: Decimal = Field(ge=0)
    quantity_rejected: Decimal = Field(ge=0)
    trace_refs: tuple[MaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    waiver_ref: OpaqueRef | None = None
    started_at: str
    inspected_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator(
        "quantity_inspected",
        "quantity_accepted",
        "quantity_rejected",
        mode="before",
    )
    @classmethod
    def _valid_quantities(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("trace_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("started_at", "inspected_at")
    @classmethod
    def _valid_inspection_time(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_inspection(self) -> "QualityInspection":
        if self.quantity_accepted + self.quantity_rejected != self.quantity_inspected:
            raise ValueError(
                "quantity_accepted plus quantity_rejected must equal quantity_inspected"
            )
        if self.status == "waived" and self.waiver_ref is None:
            raise ValueError("waived inspections require waiver_ref")
        if self.status == "pending" and self.inspected_at is not None:
            raise ValueError("pending inspection cannot carry inspected_at")
        if self.status != "pending" and self.inspected_at is None:
            raise ValueError("completed inspection requires inspected_at")
        if self.inspected_at is not None and _parsed_timestamp(
            self.inspected_at
        ) < _parsed_timestamp(self.started_at):
            raise ValueError("inspection completion cannot precede inspection start")
        _unique(self.trace_refs, field="trace_ref", label="inspection trace")
        return self


class NonconformanceRecord(_StrictModel):
    nonconformance_ref: OpaqueRef
    production_order_ref: OpaqueRef
    bom_ref: OpaqueRef
    bom_revision: int = Field(ge=1)
    routing_ref: OpaqueRef
    routing_revision: int = Field(ge=1)
    severity: Literal["minor", "major", "critical"]
    status: Literal["open", "contained", "dispositioned", "closed"]
    related_trace_refs: tuple[MaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    capa_required: bool = False
    capa_ref: OpaqueRef | None = None
    capa_status: Literal["open", "verified", "closed"] | None = None
    opened_at: str
    closed_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("related_trace_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("opened_at", "closed_at")
    @classmethod
    def _valid_nonconformance_time(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_capa(self) -> "NonconformanceRecord":
        if self.capa_required and (self.capa_ref is None or self.capa_status is None):
            raise ValueError(
                "CAPA-required nonconformance needs capa_ref and capa_status"
            )
        if not self.capa_required and (
            self.capa_ref is not None or self.capa_status is not None
        ):
            raise ValueError("CAPA fields require capa_required=true")
        if self.status == "closed" and self.closed_at is None:
            raise ValueError("closed nonconformance requires closed_at")
        if self.status != "closed" and self.closed_at is not None:
            raise ValueError("unclosed nonconformance cannot carry closed_at")
        if self.closed_at is not None and _parsed_timestamp(
            self.closed_at
        ) < _parsed_timestamp(self.opened_at):
            raise ValueError("nonconformance closure cannot precede opening")
        _unique(
            self.related_trace_refs, field="trace_ref", label="nonconformance trace"
        )
        return self


class ManufacturingControlPolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8_760)
    quantity_tolerance: Decimal = Field(default=Decimal("0"), ge=0)
    require_incoming_inspection_for_release: bool = False
    require_final_inspection_for_completion: bool = True
    allow_quality_waiver: bool = False
    require_output_traceability: bool = True
    require_current_calibration: bool = True

    @field_validator("quantity_tolerance", mode="before")
    @classmethod
    def _valid_tolerance(cls, value: Any) -> Decimal:
        return _quantity(value)


class ManufacturingControlInput(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_control_input.v1"] = Field(
        default=MANUFACTURING_CONTROL_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: EvaluationTarget
    analysis_as_of: str
    bill_of_material: BillOfMaterialSnapshot
    routing: ManufacturingRoutingSnapshot
    production_order: ProductionOrderSnapshot
    material_allocations: tuple[MaterialAllocation, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    work_centers: tuple[WorkCenterReadiness, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    execution_records: tuple[WorkExecutionRecord, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    quality_inspections: tuple[QualityInspection, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    nonconformances: tuple[NonconformanceRecord, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    policy: ManufacturingControlPolicy = Field(
        default_factory=ManufacturingControlPolicy
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator(
        "material_allocations",
        "work_centers",
        "execution_records",
        "quality_inspections",
        "nonconformances",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_packet_refs(self) -> "ManufacturingControlInput":
        _unique(self.material_allocations, field="allocation_ref", label="allocation")
        _unique(self.work_centers, field="work_center_ref", label="work center")
        _unique(self.execution_records, field="execution_ref", label="execution")
        _unique(self.quality_inspections, field="inspection_ref", label="inspection")
        _unique(
            self.nonconformances,
            field="nonconformance_ref",
            label="nonconformance",
        )
        return self


class ManufacturingFinding(_StrictModel):
    code: OpaqueRef
    gate: GateName
    status: Literal["review", "fail", "indeterminate"]
    severity: FindingSeverity
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    subject_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ManufacturingGateResult(_StrictModel):
    gate: GateName
    status: GateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=1_000
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ComponentCoverage(_StrictModel):
    component_ref: OpaqueRef
    required_quantity: Decimal = Field(ge=0)
    allocated_quantity: Decimal = Field(ge=0)
    traceability_required: bool
    traceability_present: bool
    covered: bool


class ManufacturingEffectBoundary(_StrictModel):
    production_order_released: Literal[False] = False
    production_order_completed: Literal[False] = False
    inventory_mutated: Literal[False] = False
    quality_dispositioned: Literal[False] = False
    nonconformance_or_capa_closed: Literal[False] = False
    maintenance_work_order_changed: Literal[False] = False
    trusted_host_authority_required: Literal[True] = True


MANUFACTURING_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="bom-inventory-traceability-controls.evaluate",
    tool="operations.verify_bom_inventory_traceability",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class ManufacturingControlResult(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_control_result.v1"] = Field(
        default=MANUFACTURING_CONTROL_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: EvaluationTarget
    analysis_as_of: str
    proposed_disposition: Disposition
    assurance_grade: PrimitiveEvidenceVerificationGrade
    gates: tuple[ManufacturingGateResult, ...]
    findings: tuple[ManufacturingFinding, ...]
    component_coverage: tuple[ComponentCoverage, ...]
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[OpaqueRef, ...]
    effect_boundary: ManufacturingEffectBoundary = Field(
        default_factory=ManufacturingEffectBoundary
    )
    result_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator(
        "gates", "findings", "component_coverage", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _result_is_coherent_and_content_bound(self) -> "ManufacturingControlResult":
        for finding in self.findings:
            expected_severity: FindingSeverity = (
                "blocking" if finding.status == "fail" else "review"
            )
            if finding.severity != expected_severity:
                raise ValueError("finding severity must match finding status")
        for coverage in self.component_coverage:
            if not coverage.traceability_required and not coverage.traceability_present:
                raise ValueError(
                    "non-traceable components must report traceability as satisfied"
                )
            if (
                coverage.allocated_quantity >= coverage.required_quantity
                and not coverage.covered
            ):
                raise ValueError("fully allocated components must be covered")
        expected_findings = tuple(
            sorted(
                self.findings,
                key=lambda item: (
                    _GATE_ORDER.index(item.gate),
                    item.subject_ref or "",
                    item.code,
                ),
            )
        )
        if self.findings != expected_findings:
            raise ValueError("findings must be in canonical order")
        expected_gates = tuple(
            ManufacturingGateResult(
                gate=gate,
                status=_gate_status(
                    [item for item in self.findings if item.gate == gate]
                ),
                finding_codes=tuple(
                    item.code for item in self.findings if item.gate == gate
                ),
            )
            for gate in _GATE_ORDER
        )
        if self.gates != expected_gates:
            raise ValueError("gates must be the canonical projection of findings")
        statuses = {gate.status for gate in self.gates}
        expected_disposition: Disposition = (
            "blocked"
            if "fail" in statuses
            else "indeterminate"
            if "indeterminate" in statuses
            else "manual_review_required"
            if "review" in statuses
            else "eligible_for_release_approval"
            if self.target == "release"
            else "eligible_for_completion_approval"
        )
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match gate results and target")
        if set(self.source_snapshot_digests) != {
            "bill_of_material",
            "policy",
            "routing",
            "production_order",
            "material_allocations",
            "work_centers",
            "execution_records",
            "quality_inspections",
            "nonconformances",
        }:
            raise ValueError(
                "source_snapshot_digests must contain the exact source set"
            )
        if any(
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in self.source_snapshot_digests.values()
        ):
            raise ValueError("source snapshot digests must be lowercase SHA-256 values")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("evidence_refs must be unique and in canonical order")
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


def _all_evidence(
    inputs: ManufacturingControlInput,
) -> tuple[PrimitiveEvidenceRef, ...]:
    groups: list[tuple[PrimitiveEvidenceRef, ...]] = [
        inputs.bill_of_material.evidence_refs,
        inputs.routing.evidence_refs,
        inputs.production_order.evidence_refs,
    ]
    for collection in (
        inputs.material_allocations,
        inputs.work_centers,
        inputs.execution_records,
        inputs.quality_inspections,
        inputs.nonconformances,
    ):
        groups.extend(item.evidence_refs for item in collection)
    return tuple(evidence for group in groups for evidence in group)


def _finding(
    findings: list[ManufacturingFinding],
    *,
    code: str,
    gate: GateName,
    status: Literal["review", "fail", "indeterminate"],
    message: str,
    subject_ref: str | None = None,
    evidence_refs: Sequence[str] = (),
) -> None:
    findings.append(
        ManufacturingFinding(
            code=code,
            gate=gate,
            status=status,
            severity="blocking" if status == "fail" else "review",
            message=message,
            subject_ref=subject_ref,
            evidence_refs=tuple(evidence_refs),
        )
    )


def _gate_status(findings: Sequence[ManufacturingFinding]) -> GateStatus:
    statuses = {finding.status for finding in findings}
    if "fail" in statuses:
        return "fail"
    if "indeterminate" in statuses:
        return "indeterminate"
    if "review" in statuses:
        return "review"
    return "pass"


def evaluate_manufacturing_controls(
    value: ManufacturingControlInput | Mapping[str, Any],
) -> ManufacturingControlResult:
    """Evaluate release/completion controls without performing a physical write."""

    inputs = revalidate_model_boundary(ManufacturingControlInput, value)
    findings: list[ManufacturingFinding] = []
    evidence = _all_evidence(inputs)
    evidence_names = [item.evidence_ref for item in evidence]
    if len(evidence_names) != len(set(evidence_names)):
        _finding(
            findings,
            code="evidence_ref_reused",
            gate="evidence",
            status="indeterminate",
            message="Evidence references must identify one unique retained artifact.",
        )

    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    minimum_rank = _GRADE_RANK[inputs.policy.minimum_evidence_grade]
    order = inputs.production_order
    for item in evidence:
        observed_at = _parsed_timestamp(item.observed_at)
        if item.subject_ref != order.production_order_ref:
            _finding(
                findings,
                code=f"evidence_subject_mismatch:{item.evidence_ref}",
                gate="evidence",
                status="fail",
                message=(
                    "Every evidence artifact must be attributed to the exact "
                    "production order under evaluation."
                ),
                subject_ref=item.evidence_ref,
                evidence_refs=(item.evidence_ref,),
            )
        if observed_at > analysis_at:
            _finding(
                findings,
                code=f"future_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence was observed after the analysis cutoff.",
                subject_ref=item.evidence_ref,
                evidence_refs=(item.evidence_ref,),
            )
        elif (analysis_at - observed_at).total_seconds() > (
            inputs.policy.max_evidence_age_hours * 3_600
        ):
            _finding(
                findings,
                code=f"stale_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence exceeds the configured freshness window.",
                subject_ref=item.evidence_ref,
                evidence_refs=(item.evidence_ref,),
            )
        if _GRADE_RANK[item.verification_grade] < minimum_rank:
            _finding(
                findings,
                code=f"weak_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence verification grade is below policy.",
                subject_ref=item.evidence_ref,
                evidence_refs=(item.evidence_ref,),
            )

    bom = inputs.bill_of_material
    routing = inputs.routing
    if bom.status != "approved":
        _finding(
            findings,
            code="bom_not_approved",
            gate="configuration",
            status="fail",
            message="The production BOM revision is not approved.",
            subject_ref=bom.bom_ref,
        )
    if routing.status != "approved":
        _finding(
            findings,
            code="routing_not_approved",
            gate="configuration",
            status="fail",
            message="The production routing revision is not approved.",
            subject_ref=routing.routing_ref,
        )
    if len({bom.product_ref, routing.product_ref, order.product_ref}) != 1:
        _finding(
            findings,
            code="product_configuration_mismatch",
            gate="configuration",
            status="fail",
            message="BOM, routing, and production order must reference the same product.",
            subject_ref=order.production_order_ref,
        )
    if (order.bom_ref, order.bom_revision) != (bom.bom_ref, bom.revision):
        _finding(
            findings,
            code="bom_revision_mismatch",
            gate="configuration",
            status="fail",
            message="The production order is not pinned to the supplied BOM revision.",
            subject_ref=order.production_order_ref,
        )
    if (order.routing_ref, order.routing_revision) != (
        routing.routing_ref,
        routing.revision,
    ):
        _finding(
            findings,
            code="routing_revision_mismatch",
            gate="configuration",
            status="fail",
            message="The production order is not pinned to the supplied routing revision.",
            subject_ref=order.production_order_ref,
        )

    record_groups: tuple[
        tuple[
            str,
            GateName,
            str,
            Sequence[WorkExecutionRecord | QualityInspection | NonconformanceRecord],
        ],
        ...,
    ] = (
        ("execution", "execution", "execution_ref", inputs.execution_records),
        ("inspection", "quality", "inspection_ref", inputs.quality_inspections),
        (
            "nonconformance",
            "nonconformance",
            "nonconformance_ref",
            inputs.nonconformances,
        ),
    )
    for label, gate, ref_field, records in record_groups:
        for record in records:
            record_ref = getattr(record, ref_field)
            if record.production_order_ref != order.production_order_ref:
                _finding(
                    findings,
                    code=f"{label}_production_order_mismatch:{record_ref}",
                    gate=gate,
                    status="fail",
                    message=(
                        "The record must reference the exact production order "
                        "under evaluation."
                    ),
                    subject_ref=record_ref,
                )
            if (record.bom_ref, record.bom_revision) != (
                bom.bom_ref,
                bom.revision,
            ):
                _finding(
                    findings,
                    code=f"{label}_bom_revision_mismatch:{record_ref}",
                    gate=gate,
                    status="fail",
                    message="The record must bind the evaluated released BOM revision.",
                    subject_ref=record_ref,
                )
            if (record.routing_ref, record.routing_revision) != (
                routing.routing_ref,
                routing.revision,
            ):
                _finding(
                    findings,
                    code=f"{label}_routing_revision_mismatch:{record_ref}",
                    gate=gate,
                    status="fail",
                    message=(
                        "The record must bind the evaluated released routing revision."
                    ),
                    subject_ref=record_ref,
                )

    business_timestamps: list[tuple[GateName, str, str, str | None]] = []
    business_timestamps.extend(
        ("execution", record.execution_ref, field_name, timestamp)
        for record in inputs.execution_records
        for field_name, timestamp in (
            ("started_at", record.started_at),
            ("completed_at", record.completed_at),
        )
    )
    business_timestamps.extend(
        ("quality", record.inspection_ref, field_name, timestamp)
        for record in inputs.quality_inspections
        for field_name, timestamp in (
            ("started_at", record.started_at),
            ("inspected_at", record.inspected_at),
        )
    )
    business_timestamps.extend(
        ("nonconformance", record.nonconformance_ref, field_name, timestamp)
        for record in inputs.nonconformances
        for field_name, timestamp in (
            ("opened_at", record.opened_at),
            ("closed_at", record.closed_at),
        )
    )
    for gate, record_ref, field_name, timestamp in business_timestamps:
        if timestamp is not None and _parsed_timestamp(timestamp) > analysis_at:
            _finding(
                findings,
                code=f"future_business_timestamp:{record_ref}:{field_name}",
                gate=gate,
                status="fail",
                message="Business timestamps cannot occur after the analysis cutoff.",
                subject_ref=record_ref,
            )

    order_start = _parsed_timestamp(order.scheduled_start)
    for execution in inputs.execution_records:
        if (
            execution.started_at is not None
            and _parsed_timestamp(execution.started_at) < order_start
        ):
            _finding(
                findings,
                code=f"execution_precedes_order_start:{execution.execution_ref}",
                gate="execution",
                status="fail",
                message="Execution cannot start before the production order schedule.",
                subject_ref=execution.execution_ref,
            )
    ordered_executions = sorted(
        inputs.execution_records,
        key=lambda record: record.routing_step_sequence,
    )
    for previous, current in zip(ordered_executions, ordered_executions[1:]):
        if (
            previous.completed_at is not None
            and current.started_at is not None
            and _parsed_timestamp(current.started_at)
            < _parsed_timestamp(previous.completed_at)
        ):
            _finding(
                findings,
                code=f"execution_sequence_chronology_invalid:{current.execution_ref}",
                gate="execution",
                status="fail",
                message=(
                    "A later routing step cannot start before the prior step completes."
                ),
                subject_ref=current.execution_ref,
            )
    completed_execution_times = [
        _parsed_timestamp(record.completed_at)
        for record in inputs.execution_records
        if record.completed_at is not None
    ]
    if completed_execution_times:
        latest_execution_completion = max(completed_execution_times)
        for inspection in inputs.quality_inspections:
            if (
                inspection.stage == "final"
                and _parsed_timestamp(inspection.started_at)
                < latest_execution_completion
            ):
                _finding(
                    findings,
                    code=f"final_inspection_precedes_execution:{inspection.inspection_ref}",
                    gate="quality",
                    status="fail",
                    message=(
                        "Final inspection cannot start before execution is complete."
                    ),
                    subject_ref=inspection.inspection_ref,
                )
    effective_at = _parsed_timestamp(order.scheduled_start)
    if effective_at < _parsed_timestamp(bom.effective_from) or (
        bom.effective_until is not None
        and effective_at >= _parsed_timestamp(bom.effective_until)
    ):
        _finding(
            findings,
            code="bom_outside_effective_window",
            gate="configuration",
            status="fail",
            message="The BOM revision is not effective at scheduled production start.",
            subject_ref=bom.bom_ref,
        )

    valid_statuses = (
        {"planned", "approved"}
        if inputs.target == "release"
        else {"released", "in_process"}
    )
    if order.status not in valid_statuses:
        _finding(
            findings,
            code="production_order_state_invalid",
            gate="order",
            status="fail",
            message=f"Order state {order.status!r} cannot be evaluated for {inputs.target}.",
            subject_ref=order.production_order_ref,
        )
    if order.approval_ref is None:
        _finding(
            findings,
            code="production_order_approval_missing",
            gate="order",
            status="fail",
            message="The host-supplied production-order approval reference is missing.",
            subject_ref=order.production_order_ref,
        )

    allocations_by_component: dict[str, list[MaterialAllocation]] = {}
    for allocation in inputs.material_allocations:
        allocations_by_component.setdefault(allocation.component_ref, []).append(
            allocation
        )
    component_coverage: list[ComponentCoverage] = []
    for component in bom.components:
        allocations = allocations_by_component.get(component.component_ref, [])
        required = component.quantity_per_unit * order.planned_quantity
        accepted_items = {component.item_ref, *component.approved_alternate_item_refs}
        eligible = [
            item
            for item in allocations
            if item.item_ref in accepted_items
            and item.unit_of_measure == component.unit_of_measure
        ]
        allocated = sum(
            (item.allocated_quantity for item in eligible),
            start=Decimal("0"),
        )
        trace_required = component.lot_controlled or component.serial_controlled
        trace_present = bool(eligible) and all(item.trace_refs for item in eligible)
        covered = allocated + inputs.policy.quantity_tolerance >= required
        component_coverage.append(
            ComponentCoverage(
                component_ref=component.component_ref,
                required_quantity=required,
                allocated_quantity=allocated,
                traceability_required=trace_required,
                traceability_present=(not trace_required or trace_present),
                covered=covered,
            )
        )
        if not eligible:
            _finding(
                findings,
                code=f"material_allocation_missing:{component.component_ref}",
                gate="material",
                status="indeterminate",
                message="No matching material allocation was supplied.",
                subject_ref=component.component_ref,
            )
        elif any(item.availability in {"quarantined", "expired"} for item in eligible):
            _finding(
                findings,
                code=f"material_unavailable:{component.component_ref}",
                gate="material",
                status="fail",
                message="Allocated material is quarantined or expired.",
                subject_ref=component.component_ref,
            )
        elif any(item.availability == "unknown" for item in eligible):
            _finding(
                findings,
                code=f"material_availability_unknown:{component.component_ref}",
                gate="material",
                status="indeterminate",
                message="Allocated material availability is unknown.",
                subject_ref=component.component_ref,
            )
        if not covered:
            _finding(
                findings,
                code=f"material_quantity_short:{component.component_ref}",
                gate="material",
                status="fail",
                message="Allocated material does not cover planned production quantity.",
                subject_ref=component.component_ref,
            )
        if trace_required and not trace_present:
            _finding(
                findings,
                code=f"input_traceability_missing:{component.component_ref}",
                gate="material",
                status="fail",
                message="Lot/serial-controlled input material lacks trace references.",
                subject_ref=component.component_ref,
            )

    work_centers = {item.work_center_ref: item for item in inputs.work_centers}
    for work_center_ref in sorted({step.work_center_ref for step in routing.steps}):
        readiness = work_centers.get(work_center_ref)
        if readiness is None:
            _finding(
                findings,
                code=f"work_center_readiness_missing:{work_center_ref}",
                gate="work_center",
                status="indeterminate",
                message="No readiness evidence was supplied for a routed work center.",
                subject_ref=work_center_ref,
            )
            continue
        if readiness.availability in {"maintenance_due", "out_of_service"}:
            _finding(
                findings,
                code=f"work_center_unavailable:{work_center_ref}",
                gate="work_center",
                status="fail",
                message="A routed work center is due for maintenance or out of service.",
                subject_ref=work_center_ref,
            )
        elif readiness.availability == "unknown":
            _finding(
                findings,
                code=f"work_center_unknown:{work_center_ref}",
                gate="work_center",
                status="indeterminate",
                message="A routed work center has unknown availability.",
                subject_ref=work_center_ref,
            )
        if (
            inputs.policy.require_current_calibration
            and readiness.calibration_current is not True
        ):
            _finding(
                findings,
                code=f"calibration_not_current:{work_center_ref}",
                gate="work_center",
                status=(
                    "fail"
                    if readiness.calibration_current is False
                    else "indeterminate"
                ),
                message="Current calibration evidence is required for the work center.",
                subject_ref=work_center_ref,
            )

    executions_by_step = {
        item.routing_step_sequence: item for item in inputs.execution_records
    }
    if inputs.target == "completion":
        for step in routing.steps:
            execution = executions_by_step.get(step.sequence)
            if execution is None:
                _finding(
                    findings,
                    code=f"execution_missing:{step.sequence}",
                    gate="execution",
                    status="indeterminate",
                    message="No execution evidence was supplied for a routing step.",
                    subject_ref=step.operation_ref,
                )
                continue
            if execution.status != "completed":
                _finding(
                    findings,
                    code=f"execution_incomplete:{step.sequence}",
                    gate="execution",
                    status="fail",
                    message="Every routing step must be completed before order completion.",
                    subject_ref=execution.execution_ref,
                )
            if (
                execution.quantity_completed + inputs.policy.quantity_tolerance
                < order.planned_quantity
            ):
                _finding(
                    findings,
                    code=f"execution_quantity_short:{step.sequence}",
                    gate="execution",
                    status="fail",
                    message="Routing-step completed quantity is below the order quantity.",
                    subject_ref=execution.execution_ref,
                )
            missing_certifications = set(step.required_certification_refs) - set(
                execution.certification_refs
            )
            if missing_certifications:
                _finding(
                    findings,
                    code=f"operator_certification_missing:{step.sequence}",
                    gate="execution",
                    status="fail",
                    message="The execution record lacks required operator certifications.",
                    subject_ref=execution.execution_ref,
                )
            if (
                inputs.policy.require_output_traceability
                and not execution.output_trace_refs
            ):
                _finding(
                    findings,
                    code=f"output_traceability_missing:{step.sequence}",
                    gate="execution",
                    status="fail",
                    message="Completed execution lacks batch/lot/serial output traceability.",
                    subject_ref=execution.execution_ref,
                )

    required_stage = (
        "incoming"
        if inputs.target == "release"
        and inputs.policy.require_incoming_inspection_for_release
        else "final"
        if inputs.target == "completion"
        and inputs.policy.require_final_inspection_for_completion
        else None
    )
    if required_stage is not None:
        inspections = [
            inspection
            for inspection in inputs.quality_inspections
            if inspection.stage == required_stage
        ]
        if not inspections:
            _finding(
                findings,
                code=f"{required_stage}_inspection_missing",
                gate="quality",
                status="indeterminate",
                message=f"A {required_stage} inspection is required by policy.",
                subject_ref=order.production_order_ref,
            )
        elif any(inspection.status == "failed" for inspection in inspections):
            _finding(
                findings,
                code=f"{required_stage}_inspection_failed",
                gate="quality",
                status="fail",
                message=f"A {required_stage} inspection failed.",
                subject_ref=order.production_order_ref,
            )
        elif any(inspection.status == "pending" for inspection in inspections):
            _finding(
                findings,
                code=f"{required_stage}_inspection_pending",
                gate="quality",
                status="indeterminate",
                message=f"A {required_stage} inspection is still pending.",
                subject_ref=order.production_order_ref,
            )
        elif any(inspection.status == "waived" for inspection in inspections):
            _finding(
                findings,
                code=f"{required_stage}_inspection_waived",
                gate="quality",
                status=("review" if inputs.policy.allow_quality_waiver else "fail"),
                message=f"A {required_stage} inspection was waived.",
                subject_ref=order.production_order_ref,
            )

    for nonconformance in inputs.nonconformances:
        if nonconformance.status != "closed":
            _finding(
                findings,
                code=f"nonconformance_open:{nonconformance.nonconformance_ref}",
                gate="nonconformance",
                status=(
                    "fail"
                    if nonconformance.severity in {"major", "critical"}
                    else "review"
                ),
                message="An unresolved nonconformance remains in the packet.",
                subject_ref=nonconformance.nonconformance_ref,
            )
        if nonconformance.capa_required and nonconformance.capa_status != "closed":
            _finding(
                findings,
                code=f"capa_open:{nonconformance.nonconformance_ref}",
                gate="nonconformance",
                status="fail",
                message="Required CAPA is not closed.",
                subject_ref=nonconformance.capa_ref,
            )

    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                _GATE_ORDER.index(item.gate),
                item.subject_ref or "",
                item.code,
            ),
        )
    )
    gates = tuple(
        ManufacturingGateResult(
            gate=gate,
            status=_gate_status(
                [finding for finding in ordered_findings if finding.gate == gate]
            ),
            finding_codes=tuple(
                finding.code for finding in ordered_findings if finding.gate == gate
            ),
        )
        for gate in _GATE_ORDER
    )
    statuses = {gate.status for gate in gates}
    if "fail" in statuses:
        disposition: Disposition = "blocked"
    elif "indeterminate" in statuses:
        disposition = "indeterminate"
    elif "review" in statuses:
        disposition = "manual_review_required"
    elif inputs.target == "release":
        disposition = "eligible_for_release_approval"
    else:
        disposition = "eligible_for_completion_approval"

    assurance_grade = min(
        (item.verification_grade for item in evidence),
        key=lambda grade: _GRADE_RANK[grade],
    )
    source_digests = {
        "bill_of_material": manufacturing_snapshot_digest(bom),
        "policy": manufacturing_snapshot_digest(inputs.policy),
        "routing": manufacturing_snapshot_digest(routing),
        "production_order": manufacturing_snapshot_digest(order),
        "material_allocations": _stable_digest(
            [item.to_dict() for item in inputs.material_allocations]
        ),
        "work_centers": _stable_digest(
            [item.to_dict() for item in inputs.work_centers]
        ),
        "execution_records": _stable_digest(
            [item.to_dict() for item in inputs.execution_records]
        ),
        "quality_inspections": _stable_digest(
            [item.to_dict() for item in inputs.quality_inspections]
        ),
        "nonconformances": _stable_digest(
            [item.to_dict() for item in inputs.nonconformances]
        ),
    }
    result = ManufacturingControlResult(
        evaluation_ref=inputs.evaluation_ref,
        target=inputs.target,
        analysis_as_of=inputs.analysis_as_of,
        proposed_disposition=disposition,
        assurance_grade=assurance_grade,
        gates=gates,
        findings=ordered_findings,
        component_coverage=tuple(component_coverage),
        source_snapshot_digests=source_digests,
        evidence_refs=tuple(sorted(evidence_names)),
    )
    return result


def _example_evidence(ref: str, character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": "normalized_manufacturing_snapshot",
        "issuer_ref": "spring-manufacturing-authority",
        "subject_ref": "prod-1042",
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "confidential",
        "retention_policy": "quality-ten-years",
        "jurisdiction": "US",
    }


class VerifyBomInventoryTraceabilityPrimitive(
    BusinessProcessPrimitive[ManufacturingControlInput, ManufacturingControlResult]
):
    primitive_ref = "operations.verify_bom_inventory_traceability"
    version = "1.0.0"
    title = "Verify BOM, inventory, and manufacturing traceability"
    description = (
        "Evaluate evidence-bound production release or completion controls without "
        "releasing an order, moving stock, or changing quality/CAPA records."
    )
    input_model = ManufacturingControlInput
    output_model = ManufacturingControlResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "evaluation_ref": "mfg-evaluation-1042",
        "target": "release",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "bill_of_material": {
            "bom_ref": "bom-widget",
            "product_ref": "widget",
            "revision": 3,
            "status": "approved",
            "effective_from": "2026-01-01T00:00:00Z",
            "components": [
                {
                    "component_ref": "component-steel",
                    "item_ref": "steel-sheet",
                    "quantity_per_unit": "2.000000",
                    "unit_of_measure": "EA",
                    "lot_controlled": True,
                }
            ],
            "evidence_refs": [_example_evidence("bom-evidence", "a")],
        },
        "routing": {
            "routing_ref": "routing-widget",
            "product_ref": "widget",
            "revision": 2,
            "status": "approved",
            "steps": [
                {
                    "sequence": 10,
                    "operation_ref": "cut-steel",
                    "work_center_ref": "laser-cell-1",
                    "work_instruction_ref": "wi-cut-steel",
                    "work_instruction_revision": 4,
                }
            ],
            "evidence_refs": [_example_evidence("routing-evidence", "b")],
        },
        "production_order": {
            "production_order_ref": "prod-1042",
            "product_ref": "widget",
            "site_ref": "plant-east",
            "planned_quantity": "10.000000",
            "unit_of_measure": "EA",
            "bom_ref": "bom-widget",
            "bom_revision": 3,
            "routing_ref": "routing-widget",
            "routing_revision": 2,
            "status": "approved",
            "approval_ref": "approval-prod-1042",
            "scheduled_start": "2026-08-25T12:00:00Z",
            "scheduled_end": "2026-08-25T18:00:00Z",
            "evidence_refs": [_example_evidence("order-evidence", "c")],
        },
        "material_allocations": [
            {
                "allocation_ref": "allocation-steel",
                "component_ref": "component-steel",
                "item_ref": "steel-sheet",
                "allocated_quantity": "20.000000",
                "unit_of_measure": "EA",
                "availability": "available",
                "trace_refs": [{"kind": "lot", "trace_ref": "lot-steel-42"}],
                "evidence_refs": [_example_evidence("allocation-evidence", "d")],
            }
        ],
        "work_centers": [
            {
                "work_center_ref": "laser-cell-1",
                "availability": "ready",
                "calibration_current": True,
                "evidence_refs": [_example_evidence("work-center-evidence", "e")],
            }
        ],
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = MANUFACTURING_CONTROL_OPERATION.to_dict()
        contract["capability_hints"] = [
            "erp.read_bom",
            "erp.read_production_order",
            "mes.read_execution",
            "qms.read_inspections",
            "cmms.read_asset_status",
        ]
        contract["capability_hints_are_dispatch_authority"] = False
        contract["effect_boundary"] = ManufacturingEffectBoundary().to_dict()
        contract["system_of_record_authority"] = "trusted_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ManufacturingControlInput,
    ) -> PrimitiveExecutionResult[ManufacturingControlResult]:
        del context
        output = evaluate_manufacturing_controls(inputs)
        evidence_refs = sorted(
            _all_evidence(inputs),
            key=lambda item: item.evidence_ref,
        )
        receipt = PrimitiveOperationReceipt(
            spec=MANUFACTURING_CONTROL_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=manufacturing_snapshot_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[ManufacturingControlResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Manufacturing controls evaluated; the result proposes "
                f"{output.proposed_disposition} and grants no execution authority."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="operations.manufacturing_controls_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "target": output.target,
                        "proposed_disposition": output.proposed_disposition,
                        "finding_count": len(output.findings),
                        "live_systems_changed": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="manufacturing_control_result",
                    summary=(
                        "The SDK evaluated normalized manufacturing evidence without "
                        "releasing an order or mutating inventory, quality, or CAPA."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "BILL_OF_MATERIAL_SNAPSHOT_SCHEMA",
    "MANUFACTURING_CONTROL_INPUT_SCHEMA",
    "MANUFACTURING_CONTROL_RESULT_SCHEMA",
    "MANUFACTURING_CONTROL_OPERATION",
    "MANUFACTURING_ROUTING_SNAPSHOT_SCHEMA",
    "PRODUCTION_ORDER_SNAPSHOT_SCHEMA",
    "BillOfMaterialComponent",
    "BillOfMaterialSnapshot",
    "ComponentCoverage",
    "ManufacturingControlInput",
    "ManufacturingControlPolicy",
    "ManufacturingControlResult",
    "ManufacturingEffectBoundary",
    "ManufacturingFinding",
    "ManufacturingGateResult",
    "ManufacturingRoutingSnapshot",
    "MaterialAllocation",
    "MaterialTraceRef",
    "NonconformanceRecord",
    "ProductionOrderSnapshot",
    "QualityInspection",
    "RoutingStep",
    "VerifyBomInventoryTraceabilityPrimitive",
    "WorkCenterReadiness",
    "WorkExecutionRecord",
    "evaluate_manufacturing_controls",
    "manufacturing_snapshot_digest",
]
