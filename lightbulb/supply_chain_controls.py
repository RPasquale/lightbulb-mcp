"""Deterministic supply-chain planning and fulfillment control evaluation.

The SDK evaluates normalized, evidence-bound snapshots only.  It does not read
a connector, reserve stock, create an order, commit an allocation, modify a
shipment, or assert delivery.  Spring remains authoritative for tenant and
company scope, RBAC, source normalization, persistence, approval, and audit;
provider systems remain authoritative for their operational records.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
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


SUPPLIER_PERFORMANCE_SNAPSHOT_SCHEMA = (
    "lightbulb.supply_chain_supplier_performance_snapshot.v1"
)
DEMAND_FORECAST_SNAPSHOT_SCHEMA = "lightbulb.supply_chain_demand_forecast_snapshot.v1"
PLANNING_CYCLE_SNAPSHOT_SCHEMA = "lightbulb.supply_chain_planning_cycle_snapshot.v1"
SUPPLY_DEMAND_PLAN_LINE_SCHEMA = "lightbulb.supply_chain_plan_line.v1"
ALLOCATION_PLAN_LINE_SCHEMA = "lightbulb.supply_chain_allocation_plan_line.v1"
REPLENISHMENT_PLAN_LINE_SCHEMA = "lightbulb.supply_chain_replenishment_plan_line.v1"
WAREHOUSE_SNAPSHOT_SCHEMA = "lightbulb.supply_chain_warehouse_snapshot.v1"
SHIPMENT_SNAPSHOT_SCHEMA = "lightbulb.supply_chain_shipment_snapshot.v1"
PLAN_FULFILLMENT_CONTROLS_INPUT_SCHEMA = (
    "lightbulb.supply_chain_plan_fulfillment_controls_input.v1"
)
PLAN_FULFILLMENT_CONTROLS_RESULT_SCHEMA = (
    "lightbulb.supply_chain_plan_fulfillment_controls_result.v1"
)

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_QUANTITY_QUANTUM = Decimal("0.000001")
_RATIO_QUANTUM = Decimal("0.000001")
_MAX_QUANTITY = Decimal("1e15")
_MAX_ACCUMULATED_QUANTITY = Decimal("2e18")
_MAX_FINDINGS = 30_000
_MAX_EVIDENCE_REFS = 5_000


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("text must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("text contains an unsupported control character")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
FindingMessage = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
    AfterValidator(_bounded_text),
]
UnitCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9._/-]{0,31}$",
    ),
]
HandlingCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_.-]{0,63}$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]

SupplierQualificationStatus = Literal[
    "qualified", "conditional", "pending", "blocked", "expired", "unknown"
]
SupplierRiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
PlanningStatus = Literal["approved", "pending", "conflicted", "rejected", "unknown"]
MrpRunStatus = Literal["complete", "running", "failed", "unknown"]
AllocationStatus = Literal[
    "proposed", "pending_approval", "approved", "committed", "cancelled", "unknown"
]
ReplenishmentStatus = Literal[
    "proposed",
    "pending_approval",
    "approved",
    "not_required",
    "cancelled",
    "unknown",
]
WarehouseStatus = Literal["operational", "constrained", "closed", "unknown"]
ShipmentStatus = Literal[
    "planned",
    "ready",
    "in_transit",
    "delivered",
    "exception",
    "cancelled",
    "unknown",
]
ShipmentExceptionCategory = Literal[
    "delay",
    "damage",
    "loss",
    "customs",
    "temperature",
    "capacity",
    "address",
    "other",
]
ShipmentExceptionSeverity = Literal["review", "blocking"]
ShipmentExceptionStatus = Literal["open", "mitigated", "resolved"]
SupplyChainGate = Literal[
    "evidence",
    "supplier",
    "forecast",
    "planning",
    "allocation",
    "replenishment",
    "warehouse",
    "shipment",
    "custody",
    "exception",
]
SupplyChainFindingSeverity = Literal["review", "blocking", "indeterminate"]
SupplyChainGateStatus = Literal["pass", "review", "fail", "indeterminate"]
PlanLineControlStatus = Literal["ready", "review", "blocked", "indeterminate"]
ShipmentControlStatus = Literal["ready", "review", "blocked", "indeterminate"]
PlanFulfillmentDisposition = Literal[
    "ready_for_governed_execution",
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
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _as_tuple(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


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


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(
    value: Any,
    *,
    quantum: Decimal,
    non_negative: bool = True,
    maximum: Decimal = _MAX_QUANTITY,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError("decimal values must use bounded notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("decimal values must be finite") from exc
    if not parsed.is_finite() or abs(parsed) > maximum:
        raise ValueError("decimal values must be bounded and finite")
    if non_negative and parsed < 0:
        raise ValueError("decimal values must be non-negative")
    try:
        normalized = parsed.quantize(quantum)
    except InvalidOperation as exc:
        raise ValueError("decimal value exceeds supported precision") from exc
    if normalized != parsed:
        raise ValueError(
            f"decimal values support at most {-quantum.as_tuple().exponent} places"
        )
    return normalized


def _quantity(value: Any) -> Decimal:
    return _decimal(value, quantum=_QUANTITY_QUANTUM)


def _signed_quantity(value: Any) -> Decimal:
    return _decimal(
        value,
        quantum=_QUANTITY_QUANTUM,
        non_negative=False,
        maximum=_MAX_ACCUMULATED_QUANTITY,
    )


def _accumulated_quantity(value: Any) -> Decimal:
    return _decimal(
        value,
        quantum=_QUANTITY_QUANTUM,
        maximum=_MAX_ACCUMULATED_QUANTITY,
    )


def _ratio(value: Any) -> Decimal:
    parsed = _decimal(value, quantum=_RATIO_QUANTUM)
    if parsed > 1:
        raise ValueError("ratio values must be between zero and one")
    return parsed


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def supply_chain_snapshot_digest(
    snapshot: BaseModel | Mapping[str, Any],
) -> str:
    """Return a canonical SHA-256 digest for one normalized snapshot."""

    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


def _require_unique_refs(
    values: Sequence[Any],
    *,
    field: str,
    label: str,
) -> None:
    refs = [str(getattr(value, field)) for value in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{label} references must be unique")


class SupplyChainSnapshotCoverage(_StrictModel):
    suppliers_complete: bool
    forecasts_complete: bool
    plan_lines_complete: bool
    allocations_complete: bool
    replenishments_complete: bool
    warehouses_complete: bool
    shipments_complete: bool


class SupplyChainControlPolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8_760)
    max_forecast_age_hours: int = Field(default=168, ge=1, le=8_760)
    minimum_forecast_confidence: Decimal = Field(
        default=Decimal("0.700000"), ge=0, le=1
    )
    forecast_plan_tolerance_ratio: Decimal = Field(
        default=Decimal("0.100000"), ge=0, le=1
    )
    minimum_supplier_on_time_ratio: Decimal = Field(
        default=Decimal("0.900000"), ge=0, le=1
    )
    maximum_supplier_defect_ratio: Decimal = Field(
        default=Decimal("0.050000"), ge=0, le=1
    )
    maximum_supplier_lead_time_days: int = Field(default=180, ge=1, le=3_650)
    maximum_warehouse_utilization_ratio: Decimal = Field(
        default=Decimal("0.950000"), gt=0, le=1
    )
    minimum_inventory_accuracy_ratio: Decimal = Field(
        default=Decimal("0.980000"), ge=0, le=1
    )

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _evidence_grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @field_validator(
        "minimum_forecast_confidence",
        "forecast_plan_tolerance_ratio",
        "minimum_supplier_on_time_ratio",
        "maximum_supplier_defect_ratio",
        "maximum_warehouse_utilization_ratio",
        "minimum_inventory_accuracy_ratio",
        mode="before",
    )
    @classmethod
    def _ratios(cls, value: Any) -> Decimal:
        return _ratio(value)


class SupplierPerformanceSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_supplier_performance_snapshot.v1"] = (
        Field(default=SUPPLIER_PERFORMANCE_SNAPSHOT_SCHEMA, alias="schema")
    )
    supplier_ref: OpaqueRef
    company_ref: OpaqueRef
    qualification_status: SupplierQualificationStatus
    risk_level: SupplierRiskLevel
    on_time_delivery_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    defect_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    lead_time_days: int | None = Field(default=None, ge=0, le=3_650)
    qualified_until: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("on_time_delivery_ratio", "defect_ratio", mode="before")
    @classmethod
    def _optional_ratios(cls, value: Any) -> Decimal | None:
        return None if value is None else _ratio(value)

    @field_validator("qualified_until")
    @classmethod
    def _qualified_until(cls, value: str | None) -> str | None:
        return (
            None if value is None else _timestamp(value, field_name="qualified_until")
        )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class DemandForecastSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_demand_forecast_snapshot.v1"] = Field(
        default=DEMAND_FORECAST_SNAPSHOT_SCHEMA, alias="schema"
    )
    forecast_ref: OpaqueRef
    company_ref: OpaqueRef
    item_ref: OpaqueRef
    warehouse_ref: OpaqueRef
    unit_of_measure: UnitCode
    horizon_start: str
    horizon_end: str
    generated_at: str
    forecast_quantity: Decimal = Field(ge=0)
    confidence_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    model_version_ref: OpaqueRef
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("horizon_start", "horizon_end", "generated_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("forecast_quantity", mode="before")
    @classmethod
    def _forecast_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("confidence_ratio", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal | None:
        return None if value is None else _ratio(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _ordered_horizon(self) -> "DemandForecastSnapshot":
        if self.horizon_start >= self.horizon_end:
            raise ValueError("forecast horizon_start must precede horizon_end")
        return self


class PlanningCycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_planning_cycle_snapshot.v1"] = Field(
        default=PLANNING_CYCLE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    cycle_ref: OpaqueRef
    company_ref: OpaqueRef
    horizon_start: str
    horizon_end: str
    sop_status: PlanningStatus
    mrp_status: MrpRunStatus
    approved_by_ref: OpaqueRef | None = None
    mrp_run_ref: OpaqueRef | None = None
    mrp_completed_at: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator(
        "horizon_start",
        "horizon_end",
        "mrp_completed_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _ordered_horizon(self) -> "PlanningCycleSnapshot":
        if self.horizon_start >= self.horizon_end:
            raise ValueError("planning horizon_start must precede horizon_end")
        return self


class SupplyDemandPlanLine(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_plan_line.v1"] = Field(
        default=SUPPLY_DEMAND_PLAN_LINE_SCHEMA,
        alias="schema",
    )
    plan_line_ref: OpaqueRef
    company_ref: OpaqueRef
    forecast_ref: OpaqueRef
    item_ref: OpaqueRef
    warehouse_ref: OpaqueRef
    unit_of_measure: UnitCode
    opening_on_hand_quantity: Decimal = Field(ge=0)
    confirmed_inbound_quantity: Decimal = Field(ge=0)
    planned_production_quantity: Decimal = Field(ge=0)
    uncommitted_demand_quantity: Decimal = Field(ge=0)
    committed_demand_quantity: Decimal = Field(ge=0)
    safety_stock_quantity: Decimal = Field(ge=0)
    required_handling_codes: tuple[HandlingCode, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator(
        "opening_on_hand_quantity",
        "confirmed_inbound_quantity",
        "planned_production_quantity",
        "uncommitted_demand_quantity",
        "committed_demand_quantity",
        "safety_stock_quantity",
        mode="before",
    )
    @classmethod
    def _quantities(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("required_handling_codes", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_handling_codes(self) -> "SupplyDemandPlanLine":
        if len(self.required_handling_codes) != len(set(self.required_handling_codes)):
            raise ValueError("required handling codes must be unique")
        return self


class AllocationPlanLine(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_allocation_plan_line.v1"] = Field(
        default=ALLOCATION_PLAN_LINE_SCHEMA,
        alias="schema",
    )
    allocation_ref: OpaqueRef
    company_ref: OpaqueRef
    plan_line_ref: OpaqueRef
    item_ref: OpaqueRef
    warehouse_ref: OpaqueRef
    destination_ref: OpaqueRef
    unit_of_measure: UnitCode
    quantity: Decimal = Field(gt=0)
    priority: int = Field(ge=1, le=10_000)
    status: AllocationStatus
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ReplenishmentPlanLine(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_replenishment_plan_line.v1"] = Field(
        default=REPLENISHMENT_PLAN_LINE_SCHEMA, alias="schema"
    )
    replenishment_ref: OpaqueRef
    company_ref: OpaqueRef
    plan_line_ref: OpaqueRef
    supplier_ref: OpaqueRef
    item_ref: OpaqueRef
    warehouse_ref: OpaqueRef
    unit_of_measure: UnitCode
    quantity: Decimal = Field(gt=0)
    handling_units: Decimal = Field(gt=0)
    status: ReplenishmentStatus
    order_by_at: str
    expected_receipt_at: str
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("quantity", "handling_units", mode="before")
    @classmethod
    def _quantities(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("order_by_at", "expected_receipt_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _ordered_dates(self) -> "ReplenishmentPlanLine":
        if self.order_by_at > self.expected_receipt_at:
            raise ValueError("order_by_at cannot follow expected_receipt_at")
        return self


class WarehouseSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_warehouse_snapshot.v1"] = Field(
        default=WAREHOUSE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    warehouse_ref: OpaqueRef
    company_ref: OpaqueRef
    status: WarehouseStatus
    capacity_handling_units: Decimal = Field(gt=0)
    occupied_handling_units: Decimal = Field(ge=0)
    reserved_inbound_handling_units: Decimal = Field(ge=0)
    planned_inbound_handling_units: Decimal = Field(ge=0)
    planned_outbound_handling_units: Decimal = Field(ge=0)
    inventory_accuracy_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    handling_codes: tuple[HandlingCode, ...] = Field(max_length=100)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator(
        "capacity_handling_units",
        "occupied_handling_units",
        "reserved_inbound_handling_units",
        "planned_inbound_handling_units",
        "planned_outbound_handling_units",
        mode="before",
    )
    @classmethod
    def _quantities(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("inventory_accuracy_ratio", mode="before")
    @classmethod
    def _accuracy(cls, value: Any) -> Decimal | None:
        return None if value is None else _ratio(value)

    @field_validator("handling_codes", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_handling_codes(self) -> "WarehouseSnapshot":
        if len(self.handling_codes) != len(set(self.handling_codes)):
            raise ValueError("warehouse handling codes must be unique")
        return self


class ShipmentCustodyEvent(_StrictModel):
    custody_event_ref: OpaqueRef
    sequence: int = Field(ge=1, le=10_000)
    from_party_ref: OpaqueRef
    to_party_ref: OpaqueRef
    occurred_at: str
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ShipmentExceptionSnapshot(_StrictModel):
    exception_ref: OpaqueRef
    category: ShipmentExceptionCategory
    severity: ShipmentExceptionSeverity
    status: ShipmentExceptionStatus
    opened_at: str
    resolved_at: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("opened_at", "resolved_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _resolution_follows_opening(self) -> "ShipmentExceptionSnapshot":
        if self.resolved_at is not None and _parse_timestamp(
            self.resolved_at
        ) < _parse_timestamp(self.opened_at):
            raise ValueError("shipment exception resolved_at cannot precede opened_at")
        return self


class ShipmentSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_shipment_snapshot.v1"] = Field(
        default=SHIPMENT_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    shipment_ref: OpaqueRef
    company_ref: OpaqueRef
    allocation_ref: OpaqueRef
    plan_line_ref: OpaqueRef
    item_ref: OpaqueRef
    warehouse_ref: OpaqueRef
    destination_ref: OpaqueRef
    unit_of_measure: UnitCode
    quantity: Decimal = Field(gt=0)
    status: ShipmentStatus
    carrier_ref: OpaqueRef | None = None
    tracking_ref: OpaqueRef | None = None
    custody_holder_ref: OpaqueRef | None = None
    ship_by_at: str
    promised_delivery_at: str
    shipped_at: str | None = None
    delivered_at: str | None = None
    delivery_receipt_ref: OpaqueRef | None = None
    required_handling_codes: tuple[HandlingCode, ...] = Field(
        default_factory=tuple,
        max_length=20,
    )
    custody_events: tuple[ShipmentCustodyEvent, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    exceptions: tuple[ShipmentExceptionSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator(
        "ship_by_at",
        "promised_delivery_at",
        "shipped_at",
        "delivered_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator(
        "required_handling_codes",
        "custody_events",
        "exceptions",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _nested_graph_is_chronological(self) -> "ShipmentSnapshot":
        _require_unique_refs(
            self.custody_events,
            field="custody_event_ref",
            label="custody-event",
        )
        _require_unique_refs(
            self.exceptions,
            field="exception_ref",
            label="shipment-exception",
        )
        sequences = [event.sequence for event in self.custody_events]
        if len(sequences) != len(set(sequences)):
            raise ValueError("custody-event sequences must be unique")
        if len(self.required_handling_codes) != len(set(self.required_handling_codes)):
            raise ValueError("shipment required handling codes must be unique")
        if self.ship_by_at > self.promised_delivery_at:
            raise ValueError("ship_by_at cannot follow promised_delivery_at")
        shipped_at = (
            _parse_timestamp(self.shipped_at) if self.shipped_at is not None else None
        )
        delivered_at = (
            _parse_timestamp(self.delivered_at)
            if self.delivered_at is not None
            else None
        )
        if delivered_at is not None and shipped_at is None:
            raise ValueError("shipment delivered_at requires shipped_at")
        if (
            delivered_at is not None
            and shipped_at is not None
            and delivered_at < shipped_at
        ):
            raise ValueError("shipment delivered_at cannot precede shipped_at")

        custody_events = sorted(self.custody_events, key=lambda event: event.sequence)
        if custody_events and shipped_at is None:
            raise ValueError("shipment custody events require shipped_at")
        previous_custody_at: datetime | None = None
        for event in custody_events:
            occurred_at = _parse_timestamp(event.occurred_at)
            if shipped_at is not None and occurred_at < shipped_at:
                raise ValueError("custody event occurred_at cannot precede shipped_at")
            if previous_custody_at is not None and occurred_at < previous_custody_at:
                raise ValueError("custody events must be chronological by sequence")
            if delivered_at is not None and occurred_at > delivered_at:
                raise ValueError("custody event occurred_at cannot follow delivered_at")
            previous_custody_at = occurred_at

        if shipped_at is not None:
            for exception in self.exceptions:
                if _parse_timestamp(exception.opened_at) < shipped_at:
                    raise ValueError(
                        "shipment exception opened_at cannot precede shipped_at"
                    )
        return self


class PlanFulfillmentControlsInput(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_plan_fulfillment_controls_input.v1"] = (
        Field(default=PLAN_FULFILLMENT_CONTROLS_INPUT_SCHEMA, alias="schema")
    )
    control_ref: OpaqueRef
    company_ref: OpaqueRef
    analysis_as_of: str
    coverage: SupplyChainSnapshotCoverage
    planning_cycle: PlanningCycleSnapshot
    suppliers: tuple[SupplierPerformanceSnapshot, ...] = Field(max_length=200)
    demand_forecasts: tuple[DemandForecastSnapshot, ...] = Field(max_length=1_000)
    plan_lines: tuple[SupplyDemandPlanLine, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    allocations: tuple[AllocationPlanLine, ...] = Field(max_length=2_000)
    replenishments: tuple[ReplenishmentPlanLine, ...] = Field(max_length=1_000)
    warehouses: tuple[WarehouseSnapshot, ...] = Field(max_length=200)
    shipments: tuple[ShipmentSnapshot, ...] = Field(max_length=2_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        max_length=_MAX_EVIDENCE_REFS
    )
    policy: SupplyChainControlPolicy = Field(default_factory=SupplyChainControlPolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator(
        "suppliers",
        "demand_forecasts",
        "plan_lines",
        "allocations",
        "replenishments",
        "warehouses",
        "shipments",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_graph_is_exact(self) -> "PlanFulfillmentControlsInput":
        for values, field, label in (
            (self.suppliers, "supplier_ref", "supplier"),
            (self.demand_forecasts, "forecast_ref", "forecast"),
            (self.plan_lines, "plan_line_ref", "plan-line"),
            (self.allocations, "allocation_ref", "allocation"),
            (self.replenishments, "replenishment_ref", "replenishment"),
            (self.warehouses, "warehouse_ref", "warehouse"),
            (self.shipments, "shipment_ref", "shipment"),
            (self.evidence_refs, "evidence_ref", "evidence"),
        ):
            _require_unique_refs(values, field=field, label=label)
        analysis_as_of = _parse_timestamp(self.analysis_as_of)
        for shipment in self.shipments:
            operational_events: list[tuple[str, str]] = []
            for field_name in ("shipped_at", "delivered_at"):
                value = getattr(shipment, field_name)
                if value is not None:
                    operational_events.append((field_name, value))
            operational_events.extend(
                ("custody occurred_at", event.occurred_at)
                for event in shipment.custody_events
            )
            for exception in shipment.exceptions:
                operational_events.append(("exception opened_at", exception.opened_at))
                if exception.resolved_at is not None:
                    operational_events.append(
                        ("exception resolved_at", exception.resolved_at)
                    )
            for label, value in operational_events:
                if _parse_timestamp(value) > analysis_as_of:
                    raise ValueError(f"shipment {label} cannot follow analysis_as_of")
        return self


class SupplyChainFinding(_StrictModel):
    code: OpaqueRef
    gate: SupplyChainGate
    severity: SupplyChainFindingSeverity
    message: FindingMessage
    subject_ref: OpaqueRef | None = None
    related_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("related_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)


class SupplyChainGateResult(_StrictModel):
    gate: SupplyChainGate
    status: SupplyChainGateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=_MAX_FINDINGS
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_codes(cls, value: Any) -> Any:
        return _as_tuple(value)


class PlanLineControlResult(_StrictModel):
    plan_line_ref: OpaqueRef
    projected_ending_quantity: Decimal
    available_to_allocate_quantity: Decimal = Field(ge=0)
    safety_stock_gap_quantity: Decimal = Field(ge=0)
    committed_demand_quantity: Decimal = Field(ge=0)
    allocated_quantity: Decimal = Field(ge=0)
    replenishment_required_quantity: Decimal = Field(ge=0)
    replenishment_planned_quantity: Decimal = Field(ge=0)
    status: PlanLineControlStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=_MAX_FINDINGS
    )

    @field_validator("projected_ending_quantity", mode="before")
    @classmethod
    def _signed_quantity(cls, value: Any) -> Decimal:
        return _signed_quantity(value)

    @field_validator(
        "available_to_allocate_quantity",
        "safety_stock_gap_quantity",
        "committed_demand_quantity",
        "allocated_quantity",
        "replenishment_required_quantity",
        "replenishment_planned_quantity",
        mode="before",
    )
    @classmethod
    def _quantities(cls, value: Any) -> Decimal:
        return _accumulated_quantity(value)

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_codes(cls, value: Any) -> Any:
        return _as_tuple(value)


class ShipmentControlResult(_StrictModel):
    shipment_ref: OpaqueRef
    status: ShipmentControlStatus
    custody_complete: bool
    open_exception_count: int = Field(ge=0, le=100)
    delivered_on_time: bool | None = None
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=_MAX_FINDINGS
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_codes(cls, value: Any) -> Any:
        return _as_tuple(value)


class SupplyChainEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    inventory_changed: Literal[False] = False
    orders_created: Literal[False] = False
    allocations_committed: Literal[False] = False
    replenishments_committed: Literal[False] = False
    shipments_changed: Literal[False] = False
    fulfillment_authorized: Literal[False] = False
    external_systems_changed: Literal[False] = False


class PlanFulfillmentControlsResult(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_plan_fulfillment_controls_result.v1"] = (
        Field(default=PLAN_FULFILLMENT_CONTROLS_RESULT_SCHEMA, alias="schema")
    )
    control_ref: OpaqueRef
    company_ref: OpaqueRef
    analysis_as_of: str
    assurance_grade: PrimitiveEvidenceVerificationGrade
    proposed_disposition: PlanFulfillmentDisposition
    fulfillment_authorized: Literal[False] = False
    gates: tuple[SupplyChainGateResult, ...]
    plan_line_results: tuple[PlanLineControlResult, ...]
    shipment_results: tuple[ShipmentControlResult, ...]
    findings: tuple[SupplyChainFinding, ...] = Field(max_length=_MAX_FINDINGS)
    source_snapshot_digests: dict[str, Sha256Digest]
    evidence_refs: tuple[OpaqueRef, ...] = Field(max_length=_MAX_EVIDENCE_REFS)
    operation_spec: PrimitiveOperationSpec
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    effect_boundary: SupplyChainEffectBoundary = Field(
        default_factory=SupplyChainEffectBoundary
    )
    result_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator(
        "gates",
        "plan_line_results",
        "shipment_results",
        "findings",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("assurance_grade", mode="before")
    @classmethod
    def _assurance_grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @model_validator(mode="after")
    def _sound_result(self) -> "PlanFulfillmentControlsResult":
        if self.operation_spec != SUPPLY_CHAIN_EVALUATION_OPERATION:
            raise ValueError("operation_spec must identify the supply-chain evaluator")
        if self.operation_spec.effect != ConnectorEffect.READ:
            raise ValueError("supply-chain evaluation must remain read-only")
        expected_disposition: PlanFulfillmentDisposition
        statuses = {gate.status for gate in self.gates}
        if "fail" in statuses:
            expected_disposition = "blocked"
        elif "indeterminate" in statuses:
            expected_disposition = "indeterminate"
        elif "review" in statuses:
            expected_disposition = "manual_review_required"
        else:
            expected_disposition = "ready_for_governed_execution"
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match gate results")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("result evidence references must be unique")
        if (
            not self.source_snapshot_digests
            or len(self.source_snapshot_digests) > 7_500
        ):
            raise ValueError("source_snapshot_digests must contain 1 to 7500 entries")
        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(digest_payload)
        if self.result_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("result_digest does not match result")
        object.__setattr__(self, "result_digest", expected_digest)
        return self


SUPPLY_CHAIN_EVALUATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="plan-fulfillment-controls.evaluate",
    tool="supply_chain.evaluate_plan_fulfillment_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

_GATE_ORDER: tuple[SupplyChainGate, ...] = (
    "evidence",
    "supplier",
    "forecast",
    "planning",
    "allocation",
    "replenishment",
    "warehouse",
    "shipment",
    "custody",
    "exception",
)


def _finding_code(base: str, subject_ref: str | None = None) -> str:
    if subject_ref is None:
        return base[:160]
    prefix = f"{base}:"
    return f"{prefix}{subject_ref[: 160 - len(prefix)]}"


def _add_finding(
    findings: list[SupplyChainFinding],
    *,
    code: str,
    gate: SupplyChainGate,
    severity: SupplyChainFindingSeverity,
    message: str,
    subject_ref: str | None = None,
    related_refs: Sequence[str] = (),
    evidence_refs: Sequence[str] = (),
) -> None:
    if len(findings) >= _MAX_FINDINGS:
        return
    if len(findings) == _MAX_FINDINGS - 1:
        findings.append(
            SupplyChainFinding(
                code="evaluation.findings_truncated",
                gate="evidence",
                severity="blocking",
                message=(
                    "The bounded evaluator reached its finding limit; the proposal "
                    "fails closed."
                ),
            )
        )
        return
    findings.append(
        SupplyChainFinding(
            code=_finding_code(code, subject_ref),
            gate=gate,
            severity=severity,
            message=message[:500],
            subject_ref=subject_ref,
            related_refs=tuple(dict.fromkeys(related_refs))[:100],
            evidence_refs=tuple(dict.fromkeys(evidence_refs))[:20],
        )
    )


def _coverage_findings(
    findings: list[SupplyChainFinding],
    coverage: SupplyChainSnapshotCoverage,
) -> None:
    for field_name, gate in (
        ("suppliers_complete", "supplier"),
        ("forecasts_complete", "forecast"),
        ("plan_lines_complete", "planning"),
        ("allocations_complete", "allocation"),
        ("replenishments_complete", "replenishment"),
        ("warehouses_complete", "warehouse"),
        ("shipments_complete", "shipment"),
    ):
        if not getattr(coverage, field_name):
            _add_finding(
                findings,
                code=f"snapshot.{field_name}",
                gate=gate,
                severity="indeterminate",
                message=(
                    f"The trusted host did not declare {field_name.removesuffix('_complete').replace('_', ' ')} "
                    "snapshot coverage complete."
                ),
            )


def _assess_owner_evidence(
    findings: list[SupplyChainFinding],
    *,
    owner_ref: str,
    owner_label: str,
    expected_kind: str,
    refs: tuple[str, ...],
    evidence_by_ref: dict[str, PrimitiveEvidenceRef],
    analysis_as_of: datetime,
    policy: SupplyChainControlPolicy,
    evidence_state: dict[str, Any],
) -> None:
    if not refs:
        evidence_state["invalid"] = True
        _add_finding(
            findings,
            code=f"evidence.{owner_label}.missing",
            gate="evidence",
            severity="indeterminate",
            message=f"{owner_label.replace('_', ' ').title()} lacks evidence references.",
            subject_ref=owner_ref,
        )
        return

    missing_refs = [ref for ref in refs if ref not in evidence_by_ref]
    if missing_refs:
        evidence_state["invalid"] = True
        _add_finding(
            findings,
            code=f"evidence.{owner_label}.unresolved",
            gate="evidence",
            severity="indeterminate",
            message="One or more referenced evidence records were not supplied.",
            subject_ref=owner_ref,
            evidence_refs=missing_refs,
        )

    supplied = [evidence_by_ref[ref] for ref in refs if ref in evidence_by_ref]
    expected = [evidence for evidence in supplied if evidence.kind == expected_kind]
    if not expected:
        evidence_state["invalid"] = True
        _add_finding(
            findings,
            code=f"evidence.{owner_label}.kind_missing",
            gate="evidence",
            severity="indeterminate",
            message=f"Evidence kind {expected_kind} was not supplied for this snapshot.",
            subject_ref=owner_ref,
            evidence_refs=[evidence.evidence_ref for evidence in supplied],
        )

    stale_refs: list[str] = []
    future_refs: list[str] = []
    future_effective_refs: list[str] = []
    low_grade_refs: list[str] = []
    eligible_grades: list[PrimitiveEvidenceVerificationGrade] = []
    for evidence in supplied:
        observed_at = _parse_timestamp(evidence.observed_at)
        if observed_at > analysis_as_of:
            future_refs.append(evidence.evidence_ref)
            continue
        age_hours = (analysis_as_of - observed_at).total_seconds() / 3_600
        if age_hours > policy.max_evidence_age_hours:
            stale_refs.append(evidence.evidence_ref)
            continue
        if (
            evidence.effective_at is not None
            and _parse_timestamp(evidence.effective_at) > analysis_as_of
        ):
            future_effective_refs.append(evidence.evidence_ref)
            continue
        if (
            _GRADE_RANK[evidence.verification_grade]
            < _GRADE_RANK[policy.minimum_evidence_grade]
        ):
            low_grade_refs.append(evidence.evidence_ref)
            continue
        eligible_grades.append(evidence.verification_grade)

    if future_refs:
        evidence_state["invalid"] = True
        _add_finding(
            findings,
            code=f"evidence.{owner_label}.future",
            gate="evidence",
            severity="blocking",
            message="Evidence observation time is after the analysis cutoff.",
            subject_ref=owner_ref,
            evidence_refs=future_refs,
        )
    for code_suffix, problem_refs, message in (
        ("stale", stale_refs, "Evidence is older than the allowed freshness window."),
        (
            "not_effective",
            future_effective_refs,
            "Evidence is not yet effective at the analysis cutoff.",
        ),
        (
            "grade_low",
            low_grade_refs,
            "Evidence verification grade is below policy.",
        ),
    ):
        if problem_refs:
            evidence_state["invalid"] = True
            _add_finding(
                findings,
                code=f"evidence.{owner_label}.{code_suffix}",
                gate="evidence",
                severity="indeterminate",
                message=message,
                subject_ref=owner_ref,
                evidence_refs=problem_refs,
            )
    evidence_state["eligible_grades"].extend(eligible_grades)


def _evidence_precedes_claim(
    refs: Sequence[str],
    *,
    expected_kind: str,
    claimed_at: datetime,
    evidence_by_ref: Mapping[str, PrimitiveEvidenceRef],
) -> bool:
    matching = [
        evidence_by_ref[ref]
        for ref in refs
        if ref in evidence_by_ref and evidence_by_ref[ref].kind == expected_kind
    ]
    return (
        bool(matching)
        and max(_parse_timestamp(evidence.observed_at) for evidence in matching)
        < claimed_at
    )


def _relative_difference(actual: Decimal, expected: Decimal) -> Decimal | None:
    difference = abs(actual - expected)
    if expected == 0:
        return Decimal("0") if difference == 0 else None
    ratio = difference / expected
    if ratio > 1:
        return Decimal("1.000000")
    return ratio.quantize(_RATIO_QUANTUM)


def _status_from_findings(
    findings: Sequence[SupplyChainFinding],
) -> PlanLineControlStatus:
    severities = {finding.severity for finding in findings}
    if "blocking" in severities:
        return "blocked"
    if "indeterminate" in severities:
        return "indeterminate"
    if "review" in severities:
        return "review"
    return "ready"


def _gate_results(
    findings: Sequence[SupplyChainFinding],
) -> tuple[SupplyChainGateResult, ...]:
    results: list[SupplyChainGateResult] = []
    for gate in _GATE_ORDER:
        gate_findings = [finding for finding in findings if finding.gate == gate]
        severities = {finding.severity for finding in gate_findings}
        status: SupplyChainGateStatus = (
            "fail"
            if "blocking" in severities
            else "indeterminate"
            if "indeterminate" in severities
            else "review"
            if "review" in severities
            else "pass"
        )
        results.append(
            SupplyChainGateResult(
                gate=gate,
                status=status,
                finding_codes=tuple(
                    dict.fromkeys(finding.code for finding in gate_findings)
                ),
            )
        )
    return tuple(results)


def _source_snapshot_digests(
    inputs: PlanFulfillmentControlsInput,
) -> dict[str, str]:
    digests = {
        "coverage": supply_chain_snapshot_digest(inputs.coverage),
        "planning_cycle": supply_chain_snapshot_digest(inputs.planning_cycle),
        "policy": supply_chain_snapshot_digest(inputs.policy),
    }
    groups: tuple[tuple[str, Sequence[BaseModel], str], ...] = (
        ("supplier", inputs.suppliers, "supplier_ref"),
        ("forecast", inputs.demand_forecasts, "forecast_ref"),
        ("plan_line", inputs.plan_lines, "plan_line_ref"),
        ("allocation", inputs.allocations, "allocation_ref"),
        ("replenishment", inputs.replenishments, "replenishment_ref"),
        ("warehouse", inputs.warehouses, "warehouse_ref"),
        ("shipment", inputs.shipments, "shipment_ref"),
    )
    for prefix, values, field in groups:
        for value in sorted(values, key=lambda item: str(getattr(item, field))):
            ref = str(getattr(value, field))
            digests[f"{prefix}:{ref}"] = supply_chain_snapshot_digest(value)
    return digests


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest(
        [
            evidence.to_dict()
            for evidence in sorted(evidence_refs, key=lambda item: item.evidence_ref)
        ]
    )


def _operation_digest(
    inputs: PlanFulfillmentControlsInput,
    evidence_digest: str,
) -> str:
    payload = inputs.model_dump(
        mode="json",
        by_alias=True,
        exclude={"evidence_refs"},
        exclude_none=True,
    )
    payload["evidence_digest"] = evidence_digest
    return _stable_digest(payload)


def evaluate_plan_fulfillment_controls(
    inputs: PlanFulfillmentControlsInput | Mapping[str, Any],
) -> PlanFulfillmentControlsResult:
    """Evaluate planning and fulfillment controls without changing operations."""

    parsed = revalidate_model_boundary(PlanFulfillmentControlsInput, inputs)
    findings: list[SupplyChainFinding] = []
    analysis_as_of = _parse_timestamp(parsed.analysis_as_of)
    policy = parsed.policy
    evidence_by_ref = {
        evidence.evidence_ref: evidence for evidence in parsed.evidence_refs
    }
    evidence_state: dict[str, Any] = {
        "invalid": False,
        "eligible_grades": [],
    }

    _coverage_findings(findings, parsed.coverage)

    cycle = parsed.planning_cycle
    _assess_owner_evidence(
        findings,
        owner_ref=cycle.cycle_ref,
        owner_label="planning_cycle",
        expected_kind="planning_cycle_snapshot",
        refs=cycle.evidence_refs,
        evidence_by_ref=evidence_by_ref,
        analysis_as_of=analysis_as_of,
        policy=policy,
        evidence_state=evidence_state,
    )
    if cycle.company_ref != parsed.company_ref:
        _add_finding(
            findings,
            code="planning.company_scope_mismatch",
            gate="planning",
            severity="blocking",
            message="Planning cycle company does not match the evaluation scope.",
            subject_ref=cycle.cycle_ref,
        )
    if cycle.sop_status in {"conflicted", "rejected"}:
        _add_finding(
            findings,
            code="planning.sop_not_approved",
            gate="planning",
            severity="blocking",
            message=f"S&OP status {cycle.sop_status} blocks a fulfillment proposal.",
            subject_ref=cycle.cycle_ref,
        )
    elif cycle.sop_status != "approved":
        _add_finding(
            findings,
            code="planning.sop_indeterminate",
            gate="planning",
            severity="indeterminate",
            message="S&OP consensus is not conclusively approved.",
            subject_ref=cycle.cycle_ref,
        )
    elif cycle.approved_by_ref is None:
        _add_finding(
            findings,
            code="planning.sop_approver_missing",
            gate="planning",
            severity="indeterminate",
            message="Approved S&OP cycle lacks an approver reference.",
            subject_ref=cycle.cycle_ref,
        )
    if cycle.mrp_status == "failed":
        _add_finding(
            findings,
            code="planning.mrp_failed",
            gate="planning",
            severity="blocking",
            message="The supplied MRP run failed.",
            subject_ref=cycle.cycle_ref,
        )
    elif cycle.mrp_status != "complete":
        _add_finding(
            findings,
            code="planning.mrp_incomplete",
            gate="planning",
            severity="indeterminate",
            message="The MRP run is not conclusively complete.",
            subject_ref=cycle.cycle_ref,
        )
    elif cycle.mrp_run_ref is None or cycle.mrp_completed_at is None:
        _add_finding(
            findings,
            code="planning.mrp_receipt_missing",
            gate="planning",
            severity="indeterminate",
            message="Completed MRP cycle lacks run or completion lineage.",
            subject_ref=cycle.cycle_ref,
        )
    elif _parse_timestamp(cycle.mrp_completed_at) > analysis_as_of:
        _add_finding(
            findings,
            code="planning.mrp_completion_future",
            gate="planning",
            severity="blocking",
            message="MRP completion time is after the analysis cutoff.",
            subject_ref=cycle.cycle_ref,
        )
    if (
        cycle.mrp_status == "complete"
        and cycle.mrp_completed_at is not None
        and _evidence_precedes_claim(
            cycle.evidence_refs,
            expected_kind="planning_cycle_snapshot",
            claimed_at=_parse_timestamp(cycle.mrp_completed_at),
            evidence_by_ref=evidence_by_ref,
        )
    ):
        evidence_state["invalid"] = True
        _add_finding(
            findings,
            code="evidence.planning_cycle.precedes_claim",
            gate="evidence",
            severity="blocking",
            message="Planning-cycle evidence predates the claimed MRP completion.",
            subject_ref=cycle.cycle_ref,
            evidence_refs=cycle.evidence_refs,
        )

    suppliers_by_ref = {
        supplier.supplier_ref: supplier for supplier in parsed.suppliers
    }
    for supplier in sorted(parsed.suppliers, key=lambda item: item.supplier_ref):
        _assess_owner_evidence(
            findings,
            owner_ref=supplier.supplier_ref,
            owner_label="supplier",
            expected_kind="supplier_performance_snapshot",
            refs=supplier.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if supplier.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="supplier.company_scope_mismatch",
                gate="supplier",
                severity="blocking",
                message="Supplier snapshot company does not match evaluation scope.",
                subject_ref=supplier.supplier_ref,
            )
        if supplier.qualification_status in {"blocked", "expired"}:
            _add_finding(
                findings,
                code="supplier.qualification_blocked",
                gate="supplier",
                severity="blocking",
                message=(
                    f"Supplier qualification status {supplier.qualification_status} "
                    "blocks replenishment."
                ),
                subject_ref=supplier.supplier_ref,
            )
        elif supplier.qualification_status == "conditional":
            _add_finding(
                findings,
                code="supplier.qualification_conditional",
                gate="supplier",
                severity="review",
                message="Supplier qualification is conditional and needs review.",
                subject_ref=supplier.supplier_ref,
            )
        elif supplier.qualification_status != "qualified":
            _add_finding(
                findings,
                code="supplier.qualification_indeterminate",
                gate="supplier",
                severity="indeterminate",
                message="Supplier qualification is not conclusively valid.",
                subject_ref=supplier.supplier_ref,
            )
        if supplier.qualified_until is None:
            _add_finding(
                findings,
                code="supplier.qualification_expiry_missing",
                gate="supplier",
                severity="indeterminate",
                message="Supplier qualification expiry is not supplied.",
                subject_ref=supplier.supplier_ref,
            )
        elif _parse_timestamp(supplier.qualified_until) < analysis_as_of:
            _add_finding(
                findings,
                code="supplier.qualification_expired",
                gate="supplier",
                severity="blocking",
                message="Supplier qualification expired before the analysis cutoff.",
                subject_ref=supplier.supplier_ref,
            )
        if supplier.risk_level == "critical":
            _add_finding(
                findings,
                code="supplier.risk_critical",
                gate="supplier",
                severity="blocking",
                message="Supplier risk is critical.",
                subject_ref=supplier.supplier_ref,
            )
        elif supplier.risk_level == "high":
            _add_finding(
                findings,
                code="supplier.risk_high",
                gate="supplier",
                severity="review",
                message="Supplier risk is high and needs review.",
                subject_ref=supplier.supplier_ref,
            )
        elif supplier.risk_level == "unknown":
            _add_finding(
                findings,
                code="supplier.risk_unknown",
                gate="supplier",
                severity="indeterminate",
                message="Supplier risk is unknown.",
                subject_ref=supplier.supplier_ref,
            )
        for value, threshold, code, message in (
            (
                supplier.on_time_delivery_ratio,
                policy.minimum_supplier_on_time_ratio,
                "supplier.on_time_performance_low",
                "Supplier on-time delivery performance is below policy.",
            ),
            (
                supplier.defect_ratio,
                policy.maximum_supplier_defect_ratio,
                "supplier.defect_rate_high",
                "Supplier defect rate exceeds policy.",
            ),
        ):
            if value is None:
                _add_finding(
                    findings,
                    code=f"{code}.missing",
                    gate="supplier",
                    severity="indeterminate",
                    message="A required supplier performance metric is missing.",
                    subject_ref=supplier.supplier_ref,
                )
            elif (code == "supplier.on_time_performance_low" and value < threshold) or (
                code == "supplier.defect_rate_high" and value > threshold
            ):
                _add_finding(
                    findings,
                    code=code,
                    gate="supplier",
                    severity="review",
                    message=message,
                    subject_ref=supplier.supplier_ref,
                )
        if supplier.lead_time_days is None:
            _add_finding(
                findings,
                code="supplier.lead_time_missing",
                gate="supplier",
                severity="indeterminate",
                message="Supplier lead-time performance is missing.",
                subject_ref=supplier.supplier_ref,
            )
        elif supplier.lead_time_days > policy.maximum_supplier_lead_time_days:
            _add_finding(
                findings,
                code="supplier.lead_time_high",
                gate="supplier",
                severity="review",
                message="Supplier lead time exceeds policy.",
                subject_ref=supplier.supplier_ref,
            )

    forecasts_by_ref = {
        forecast.forecast_ref: forecast for forecast in parsed.demand_forecasts
    }
    for forecast in sorted(
        parsed.demand_forecasts,
        key=lambda item: item.forecast_ref,
    ):
        _assess_owner_evidence(
            findings,
            owner_ref=forecast.forecast_ref,
            owner_label="forecast",
            expected_kind="demand_forecast_snapshot",
            refs=forecast.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if forecast.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="forecast.company_scope_mismatch",
                gate="forecast",
                severity="blocking",
                message="Forecast company does not match evaluation scope.",
                subject_ref=forecast.forecast_ref,
            )
        generated_at = _parse_timestamp(forecast.generated_at)
        if generated_at > analysis_as_of:
            _add_finding(
                findings,
                code="forecast.generated_future",
                gate="forecast",
                severity="blocking",
                message="Forecast generation time is after the analysis cutoff.",
                subject_ref=forecast.forecast_ref,
            )
        elif (
            analysis_as_of - generated_at
        ).total_seconds() / 3_600 > policy.max_forecast_age_hours:
            _add_finding(
                findings,
                code="forecast.stale",
                gate="forecast",
                severity="indeterminate",
                message="Demand forecast is older than the policy window.",
                subject_ref=forecast.forecast_ref,
            )
        if _evidence_precedes_claim(
            forecast.evidence_refs,
            expected_kind="demand_forecast_snapshot",
            claimed_at=generated_at,
            evidence_by_ref=evidence_by_ref,
        ):
            evidence_state["invalid"] = True
            _add_finding(
                findings,
                code="evidence.forecast.precedes_claim",
                gate="evidence",
                severity="blocking",
                message="Forecast evidence predates the claimed generation time.",
                subject_ref=forecast.forecast_ref,
                evidence_refs=forecast.evidence_refs,
            )
        if forecast.confidence_ratio is None:
            _add_finding(
                findings,
                code="forecast.confidence_missing",
                gate="forecast",
                severity="indeterminate",
                message="Forecast confidence is not supplied.",
                subject_ref=forecast.forecast_ref,
            )
        elif forecast.confidence_ratio < policy.minimum_forecast_confidence:
            _add_finding(
                findings,
                code="forecast.confidence_low",
                gate="forecast",
                severity="review",
                message="Forecast confidence is below policy.",
                subject_ref=forecast.forecast_ref,
            )
        if (
            forecast.horizon_start > cycle.horizon_start
            or forecast.horizon_end < cycle.horizon_end
        ):
            _add_finding(
                findings,
                code="forecast.horizon_incomplete",
                gate="forecast",
                severity="indeterminate",
                message="Forecast does not cover the complete S&OP/MRP horizon.",
                subject_ref=forecast.forecast_ref,
            )

    plan_lines_by_ref = {
        plan_line.plan_line_ref: plan_line for plan_line in parsed.plan_lines
    }
    warehouses_by_ref = {
        warehouse.warehouse_ref: warehouse for warehouse in parsed.warehouses
    }
    allocations_by_ref = {
        allocation.allocation_ref: allocation for allocation in parsed.allocations
    }

    allocations_by_plan_line: dict[str, list[AllocationPlanLine]] = {}
    for allocation in sorted(parsed.allocations, key=lambda item: item.allocation_ref):
        allocations_by_plan_line.setdefault(allocation.plan_line_ref, []).append(
            allocation
        )
        _assess_owner_evidence(
            findings,
            owner_ref=allocation.allocation_ref,
            owner_label="allocation",
            expected_kind="allocation_plan",
            refs=allocation.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if allocation.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="allocation.company_scope_mismatch",
                gate="allocation",
                severity="blocking",
                message="Allocation company does not match evaluation scope.",
                subject_ref=allocation.allocation_ref,
                related_refs=(allocation.plan_line_ref,),
            )
        plan_line = plan_lines_by_ref.get(allocation.plan_line_ref)
        if plan_line is None:
            _add_finding(
                findings,
                code="allocation.plan_line_missing",
                gate="allocation",
                severity=(
                    "blocking"
                    if parsed.coverage.plan_lines_complete
                    else "indeterminate"
                ),
                message="Allocation references a plan line that was not supplied.",
                subject_ref=allocation.allocation_ref,
                related_refs=(allocation.plan_line_ref,),
            )
        elif (
            allocation.item_ref != plan_line.item_ref
            or allocation.warehouse_ref != plan_line.warehouse_ref
            or allocation.unit_of_measure != plan_line.unit_of_measure
        ):
            _add_finding(
                findings,
                code="allocation.plan_line_mismatch",
                gate="allocation",
                severity="blocking",
                message="Allocation item, warehouse, or unit mismatches its plan line.",
                subject_ref=allocation.allocation_ref,
                related_refs=(allocation.plan_line_ref,),
            )
        if allocation.status == "unknown":
            _add_finding(
                findings,
                code="allocation.status_unknown",
                gate="allocation",
                severity="indeterminate",
                message="Allocation status is unknown.",
                subject_ref=allocation.allocation_ref,
                related_refs=(allocation.plan_line_ref,),
            )
        elif allocation.status == "pending_approval":
            _add_finding(
                findings,
                code="allocation.approval_pending",
                gate="allocation",
                severity="review",
                message="Allocation proposal is awaiting governed approval.",
                subject_ref=allocation.allocation_ref,
                related_refs=(allocation.plan_line_ref,),
            )

    replenishments_by_plan_line: dict[str, list[ReplenishmentPlanLine]] = {}
    replenishment_handling_by_warehouse: dict[str, Decimal] = {}
    for replenishment in sorted(
        parsed.replenishments,
        key=lambda item: item.replenishment_ref,
    ):
        replenishments_by_plan_line.setdefault(replenishment.plan_line_ref, []).append(
            replenishment
        )
        _assess_owner_evidence(
            findings,
            owner_ref=replenishment.replenishment_ref,
            owner_label="replenishment",
            expected_kind="replenishment_plan",
            refs=replenishment.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if replenishment.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="replenishment.company_scope_mismatch",
                gate="replenishment",
                severity="blocking",
                message="Replenishment company does not match evaluation scope.",
                subject_ref=replenishment.replenishment_ref,
                related_refs=(replenishment.plan_line_ref,),
            )
        plan_line = plan_lines_by_ref.get(replenishment.plan_line_ref)
        if plan_line is None:
            _add_finding(
                findings,
                code="replenishment.plan_line_missing",
                gate="replenishment",
                severity=(
                    "blocking"
                    if parsed.coverage.plan_lines_complete
                    else "indeterminate"
                ),
                message="Replenishment references a plan line that was not supplied.",
                subject_ref=replenishment.replenishment_ref,
                related_refs=(replenishment.plan_line_ref,),
            )
        elif (
            replenishment.item_ref != plan_line.item_ref
            or replenishment.warehouse_ref != plan_line.warehouse_ref
            or replenishment.unit_of_measure != plan_line.unit_of_measure
        ):
            _add_finding(
                findings,
                code="replenishment.plan_line_mismatch",
                gate="replenishment",
                severity="blocking",
                message=(
                    "Replenishment item, warehouse, or unit mismatches its plan line."
                ),
                subject_ref=replenishment.replenishment_ref,
                related_refs=(replenishment.plan_line_ref,),
            )
        supplier = suppliers_by_ref.get(replenishment.supplier_ref)
        if supplier is None:
            _add_finding(
                findings,
                code="replenishment.supplier_missing",
                gate="replenishment",
                severity=(
                    "blocking"
                    if parsed.coverage.suppliers_complete
                    else "indeterminate"
                ),
                message="Replenishment supplier snapshot was not supplied.",
                subject_ref=replenishment.replenishment_ref,
                related_refs=(
                    replenishment.plan_line_ref,
                    replenishment.supplier_ref,
                ),
            )
        if replenishment.status == "unknown":
            _add_finding(
                findings,
                code="replenishment.status_unknown",
                gate="replenishment",
                severity="indeterminate",
                message="Replenishment status is unknown.",
                subject_ref=replenishment.replenishment_ref,
                related_refs=(replenishment.plan_line_ref,),
            )
        elif replenishment.status == "pending_approval":
            _add_finding(
                findings,
                code="replenishment.approval_pending",
                gate="replenishment",
                severity="review",
                message="Replenishment proposal awaits governed approval.",
                subject_ref=replenishment.replenishment_ref,
                related_refs=(replenishment.plan_line_ref,),
            )
        if replenishment.status not in {"cancelled", "not_required"}:
            if _parse_timestamp(
                replenishment.order_by_at
            ) < analysis_as_of and replenishment.status in {
                "proposed",
                "pending_approval",
            }:
                _add_finding(
                    findings,
                    code="replenishment.order_window_missed",
                    gate="replenishment",
                    severity="blocking",
                    message="Replenishment order-by time has passed without approval.",
                    subject_ref=replenishment.replenishment_ref,
                    related_refs=(replenishment.plan_line_ref,),
                )
            if replenishment.expected_receipt_at > cycle.horizon_end:
                _add_finding(
                    findings,
                    code="replenishment.receipt_after_horizon",
                    gate="replenishment",
                    severity="blocking",
                    message="Expected replenishment receipt falls after the plan horizon.",
                    subject_ref=replenishment.replenishment_ref,
                    related_refs=(replenishment.plan_line_ref,),
                )
            replenishment_handling_by_warehouse[replenishment.warehouse_ref] = (
                replenishment_handling_by_warehouse.get(
                    replenishment.warehouse_ref, Decimal("0")
                )
                + replenishment.handling_units
            )

    for warehouse in sorted(parsed.warehouses, key=lambda item: item.warehouse_ref):
        _assess_owner_evidence(
            findings,
            owner_ref=warehouse.warehouse_ref,
            owner_label="warehouse",
            expected_kind="warehouse_snapshot",
            refs=warehouse.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if warehouse.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="warehouse.company_scope_mismatch",
                gate="warehouse",
                severity="blocking",
                message="Warehouse company does not match evaluation scope.",
                subject_ref=warehouse.warehouse_ref,
            )
        if warehouse.status == "closed":
            _add_finding(
                findings,
                code="warehouse.closed",
                gate="warehouse",
                severity="blocking",
                message="Warehouse is closed.",
                subject_ref=warehouse.warehouse_ref,
            )
        elif warehouse.status == "constrained":
            _add_finding(
                findings,
                code="warehouse.constrained",
                gate="warehouse",
                severity="review",
                message="Warehouse is operating under a constraint.",
                subject_ref=warehouse.warehouse_ref,
            )
        elif warehouse.status == "unknown":
            _add_finding(
                findings,
                code="warehouse.status_unknown",
                gate="warehouse",
                severity="indeterminate",
                message="Warehouse operating status is unknown.",
                subject_ref=warehouse.warehouse_ref,
            )
        projected_load = max(
            Decimal("0"),
            warehouse.occupied_handling_units
            + warehouse.reserved_inbound_handling_units
            + warehouse.planned_inbound_handling_units
            - warehouse.planned_outbound_handling_units,
        )
        utilization = projected_load / warehouse.capacity_handling_units
        if projected_load > warehouse.capacity_handling_units:
            _add_finding(
                findings,
                code="warehouse.capacity_exceeded",
                gate="warehouse",
                severity="blocking",
                message="Projected warehouse load exceeds handling-unit capacity.",
                subject_ref=warehouse.warehouse_ref,
            )
        elif utilization > policy.maximum_warehouse_utilization_ratio:
            _add_finding(
                findings,
                code="warehouse.capacity_near_limit",
                gate="warehouse",
                severity="review",
                message="Projected warehouse utilization exceeds the policy threshold.",
                subject_ref=warehouse.warehouse_ref,
            )
        planned_replenishment_handling = replenishment_handling_by_warehouse.get(
            warehouse.warehouse_ref,
            Decimal("0"),
        )
        if planned_replenishment_handling > warehouse.planned_inbound_handling_units:
            _add_finding(
                findings,
                code="warehouse.replenishment_capacity_unreserved",
                gate="warehouse",
                severity="blocking",
                message=(
                    "Replenishment handling units exceed the warehouse's planned "
                    "inbound capacity reservation."
                ),
                subject_ref=warehouse.warehouse_ref,
            )
        if warehouse.inventory_accuracy_ratio is None:
            _add_finding(
                findings,
                code="warehouse.inventory_accuracy_missing",
                gate="warehouse",
                severity="indeterminate",
                message="Warehouse inventory accuracy is not supplied.",
                subject_ref=warehouse.warehouse_ref,
            )
        elif (
            warehouse.inventory_accuracy_ratio < policy.minimum_inventory_accuracy_ratio
        ):
            _add_finding(
                findings,
                code="warehouse.inventory_accuracy_low",
                gate="warehouse",
                severity="review",
                message="Warehouse inventory accuracy is below policy.",
                subject_ref=warehouse.warehouse_ref,
            )

    plan_metrics: dict[str, dict[str, Decimal]] = {}
    for plan_line in sorted(parsed.plan_lines, key=lambda item: item.plan_line_ref):
        _assess_owner_evidence(
            findings,
            owner_ref=plan_line.plan_line_ref,
            owner_label="plan_line",
            expected_kind="supply_demand_plan",
            refs=plan_line.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if plan_line.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="planning.plan_line_company_mismatch",
                gate="planning",
                severity="blocking",
                message="Plan-line company does not match evaluation scope.",
                subject_ref=plan_line.plan_line_ref,
            )
        forecast = forecasts_by_ref.get(plan_line.forecast_ref)
        if forecast is None:
            _add_finding(
                findings,
                code="forecast.plan_line_forecast_missing",
                gate="forecast",
                severity=(
                    "blocking"
                    if parsed.coverage.forecasts_complete
                    else "indeterminate"
                ),
                message="Plan line references a forecast that was not supplied.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=(plan_line.forecast_ref,),
            )
        elif (
            forecast.item_ref != plan_line.item_ref
            or forecast.warehouse_ref != plan_line.warehouse_ref
            or forecast.unit_of_measure != plan_line.unit_of_measure
        ):
            _add_finding(
                findings,
                code="forecast.plan_line_mismatch",
                gate="forecast",
                severity="blocking",
                message="Forecast item, warehouse, or unit mismatches the plan line.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=(forecast.forecast_ref,),
            )
        else:
            planned_demand = (
                plan_line.uncommitted_demand_quantity
                + plan_line.committed_demand_quantity
            )
            variance = _relative_difference(
                planned_demand,
                forecast.forecast_quantity,
            )
            if variance is None or variance > policy.forecast_plan_tolerance_ratio:
                _add_finding(
                    findings,
                    code="planning.forecast_demand_misaligned",
                    gate="planning",
                    severity="review",
                    message="S&OP/MRP demand differs from the referenced forecast beyond policy.",
                    subject_ref=plan_line.plan_line_ref,
                    related_refs=(forecast.forecast_ref,),
                )

        warehouse = warehouses_by_ref.get(plan_line.warehouse_ref)
        if warehouse is None:
            _add_finding(
                findings,
                code="warehouse.plan_line_warehouse_missing",
                gate="warehouse",
                severity=(
                    "blocking"
                    if parsed.coverage.warehouses_complete
                    else "indeterminate"
                ),
                message="Plan-line warehouse snapshot was not supplied.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=(plan_line.warehouse_ref,),
            )
        else:
            missing_handling = sorted(
                set(plan_line.required_handling_codes) - set(warehouse.handling_codes)
            )
            if missing_handling:
                _add_finding(
                    findings,
                    code="warehouse.plan_line_handling_unsupported",
                    gate="warehouse",
                    severity="blocking",
                    message="Warehouse lacks handling capabilities required by the plan line.",
                    subject_ref=plan_line.plan_line_ref,
                    related_refs=(warehouse.warehouse_ref,),
                )

        active_replenishments = [
            item
            for item in replenishments_by_plan_line.get(plan_line.plan_line_ref, [])
            if item.status not in {"cancelled", "not_required", "unknown"}
        ]
        replenishment_planned = sum(
            (item.quantity for item in active_replenishments),
            Decimal("0"),
        )
        base_supply = (
            plan_line.opening_on_hand_quantity
            + plan_line.confirmed_inbound_quantity
            + plan_line.planned_production_quantity
        )
        projected_ending = (
            base_supply
            - plan_line.uncommitted_demand_quantity
            - plan_line.committed_demand_quantity
        )
        safety_gap = max(
            Decimal("0"),
            plan_line.safety_stock_quantity - projected_ending,
        )
        if safety_gap > 0 and replenishment_planned < safety_gap:
            _add_finding(
                findings,
                code="replenishment.safety_stock_gap_uncovered",
                gate="replenishment",
                severity="blocking",
                message="Proposed replenishment does not cover the projected safety-stock gap.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=tuple(
                    item.replenishment_ref for item in active_replenishments
                ),
            )
        elif safety_gap == 0 and replenishment_planned > 0:
            _add_finding(
                findings,
                code="replenishment.no_gap_but_planned",
                gate="replenishment",
                severity="review",
                message="Replenishment is proposed even though no safety-stock gap is projected.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=tuple(
                    item.replenishment_ref for item in active_replenishments
                ),
            )

        active_allocations = [
            item
            for item in allocations_by_plan_line.get(plan_line.plan_line_ref, [])
            if item.status not in {"cancelled", "unknown"}
        ]
        allocated_quantity = sum(
            (item.quantity for item in active_allocations),
            Decimal("0"),
        )
        available_to_allocate = max(
            Decimal("0"),
            base_supply
            + replenishment_planned
            - plan_line.uncommitted_demand_quantity
            - plan_line.safety_stock_quantity,
        )
        if allocated_quantity > available_to_allocate:
            _add_finding(
                findings,
                code="allocation.available_supply_exceeded",
                gate="allocation",
                severity="blocking",
                message="Planned allocations exceed available-to-allocate supply.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=tuple(item.allocation_ref for item in active_allocations),
            )
        if allocated_quantity < plan_line.committed_demand_quantity:
            _add_finding(
                findings,
                code="allocation.committed_demand_uncovered",
                gate="allocation",
                severity="blocking",
                message="Planned allocations do not cover committed demand.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=tuple(item.allocation_ref for item in active_allocations),
            )
        elif plan_line.committed_demand_quantity == 0 and allocated_quantity > 0:
            _add_finding(
                findings,
                code="allocation.no_commitment_but_planned",
                gate="allocation",
                severity="review",
                message="Allocation is proposed without committed demand.",
                subject_ref=plan_line.plan_line_ref,
                related_refs=tuple(item.allocation_ref for item in active_allocations),
            )
        plan_metrics[plan_line.plan_line_ref] = {
            "projected_ending": projected_ending,
            "available_to_allocate": available_to_allocate,
            "safety_gap": safety_gap,
            "allocated": allocated_quantity,
            "replenishment_planned": replenishment_planned,
        }

    shipment_state: dict[str, dict[str, Any]] = {}
    shipment_quantity_by_allocation: dict[str, Decimal] = {}
    shipment_refs_by_allocation: dict[str, list[str]] = {}
    for shipment in sorted(parsed.shipments, key=lambda item: item.shipment_ref):
        _assess_owner_evidence(
            findings,
            owner_ref=shipment.shipment_ref,
            owner_label="shipment",
            expected_kind="shipment_snapshot",
            refs=shipment.evidence_refs,
            evidence_by_ref=evidence_by_ref,
            analysis_as_of=analysis_as_of,
            policy=policy,
            evidence_state=evidence_state,
        )
        if shipment.company_ref != parsed.company_ref:
            _add_finding(
                findings,
                code="shipment.company_scope_mismatch",
                gate="shipment",
                severity="blocking",
                message="Shipment company does not match evaluation scope.",
                subject_ref=shipment.shipment_ref,
                related_refs=(shipment.plan_line_ref,),
            )
        allocation = allocations_by_ref.get(shipment.allocation_ref)
        if allocation is None:
            _add_finding(
                findings,
                code="shipment.allocation_missing",
                gate="shipment",
                severity=(
                    "blocking"
                    if parsed.coverage.allocations_complete
                    else "indeterminate"
                ),
                message="Shipment allocation snapshot was not supplied.",
                subject_ref=shipment.shipment_ref,
                related_refs=(shipment.allocation_ref, shipment.plan_line_ref),
            )
        elif (
            shipment.plan_line_ref != allocation.plan_line_ref
            or shipment.item_ref != allocation.item_ref
            or shipment.warehouse_ref != allocation.warehouse_ref
            or shipment.destination_ref != allocation.destination_ref
            or shipment.unit_of_measure != allocation.unit_of_measure
        ):
            _add_finding(
                findings,
                code="shipment.allocation_mismatch",
                gate="shipment",
                severity="blocking",
                message="Shipment scope does not match its allocation.",
                subject_ref=shipment.shipment_ref,
                related_refs=(shipment.allocation_ref, shipment.plan_line_ref),
            )
        if (
            allocation is not None
            and shipment.status in {"in_transit", "delivered", "exception"}
            and allocation.status != "committed"
        ):
            _add_finding(
                findings,
                code="shipment.allocation_not_committed",
                gate="shipment",
                severity="blocking",
                message="Dispatched shipment does not have a committed allocation.",
                subject_ref=shipment.shipment_ref,
                related_refs=(shipment.allocation_ref, shipment.plan_line_ref),
            )
        if shipment.status not in {"cancelled", "unknown"}:
            shipment_quantity_by_allocation[shipment.allocation_ref] = (
                shipment_quantity_by_allocation.get(
                    shipment.allocation_ref, Decimal("0")
                )
                + shipment.quantity
            )
            shipment_refs_by_allocation.setdefault(shipment.allocation_ref, []).append(
                shipment.shipment_ref
            )

        warehouse = warehouses_by_ref.get(shipment.warehouse_ref)
        if warehouse is None:
            _add_finding(
                findings,
                code="shipment.warehouse_missing",
                gate="shipment",
                severity=(
                    "blocking"
                    if parsed.coverage.warehouses_complete
                    else "indeterminate"
                ),
                message="Shipment warehouse snapshot was not supplied.",
                subject_ref=shipment.shipment_ref,
                related_refs=(shipment.warehouse_ref,),
            )
        else:
            missing_handling = sorted(
                set(shipment.required_handling_codes) - set(warehouse.handling_codes)
            )
            if missing_handling:
                _add_finding(
                    findings,
                    code="shipment.handling_unsupported",
                    gate="shipment",
                    severity="blocking",
                    message="Warehouse lacks handling capabilities required by shipment.",
                    subject_ref=shipment.shipment_ref,
                    related_refs=(shipment.warehouse_ref,),
                )

        if shipment.status == "unknown":
            _add_finding(
                findings,
                code="shipment.status_unknown",
                gate="shipment",
                severity="indeterminate",
                message="Shipment status is unknown.",
                subject_ref=shipment.shipment_ref,
            )
        active_transport = shipment.status in {
            "ready",
            "in_transit",
            "delivered",
            "exception",
        }
        if active_transport and (
            shipment.carrier_ref is None or shipment.tracking_ref is None
        ):
            _add_finding(
                findings,
                code="shipment.carrier_tracking_missing",
                gate="shipment",
                severity="indeterminate",
                message="Active shipment lacks carrier or tracking lineage.",
                subject_ref=shipment.shipment_ref,
            )
        if shipment.status in {"in_transit", "delivered", "exception"}:
            if shipment.shipped_at is None:
                _add_finding(
                    findings,
                    code="shipment.shipped_at_missing",
                    gate="shipment",
                    severity="indeterminate",
                    message="Dispatched shipment lacks a shipped-at time.",
                    subject_ref=shipment.shipment_ref,
                )
            elif _parse_timestamp(shipment.shipped_at) > analysis_as_of:
                _add_finding(
                    findings,
                    code="shipment.shipped_at_future",
                    gate="shipment",
                    severity="blocking",
                    message="Shipment departure time is after the analysis cutoff.",
                    subject_ref=shipment.shipment_ref,
                )
        shipment_claim_times = [
            _parse_timestamp(timestamp)
            for timestamp in (shipment.shipped_at, shipment.delivered_at)
            if timestamp is not None
        ]
        if shipment_claim_times and _evidence_precedes_claim(
            shipment.evidence_refs,
            expected_kind="shipment_snapshot",
            claimed_at=max(shipment_claim_times),
            evidence_by_ref=evidence_by_ref,
        ):
            evidence_state["invalid"] = True
            _add_finding(
                findings,
                code="evidence.shipment.precedes_claim",
                gate="evidence",
                severity="blocking",
                message="Shipment evidence predates its latest claimed movement.",
                subject_ref=shipment.shipment_ref,
                evidence_refs=shipment.evidence_refs,
            )
        delivered_on_time: bool | None = None
        if shipment.status == "delivered":
            if shipment.delivered_at is None or shipment.delivery_receipt_ref is None:
                _add_finding(
                    findings,
                    code="shipment.delivery_receipt_missing",
                    gate="shipment",
                    severity="indeterminate",
                    message="Delivered shipment lacks delivery time or receipt lineage.",
                    subject_ref=shipment.shipment_ref,
                )
            else:
                delivered_at = _parse_timestamp(shipment.delivered_at)
                delivered_on_time = delivered_at <= _parse_timestamp(
                    shipment.promised_delivery_at
                )
                if delivered_at > analysis_as_of:
                    _add_finding(
                        findings,
                        code="shipment.delivered_at_future",
                        gate="shipment",
                        severity="blocking",
                        message="Delivery time is after the analysis cutoff.",
                        subject_ref=shipment.shipment_ref,
                    )
                if shipment.shipped_at is not None and delivered_at < _parse_timestamp(
                    shipment.shipped_at
                ):
                    _add_finding(
                        findings,
                        code="shipment.delivery_before_departure",
                        gate="shipment",
                        severity="blocking",
                        message="Delivery time precedes shipment departure.",
                        subject_ref=shipment.shipment_ref,
                    )
                if not delivered_on_time:
                    _add_finding(
                        findings,
                        code="shipment.delivered_late",
                        gate="shipment",
                        severity="review",
                        message="Shipment was delivered after the promised time.",
                        subject_ref=shipment.shipment_ref,
                    )
        elif (
            shipment.status in {"planned", "ready"}
            and _parse_timestamp(shipment.ship_by_at) < analysis_as_of
        ):
            _add_finding(
                findings,
                code="shipment.ship_window_missed",
                gate="shipment",
                severity="review",
                message="Shipment has not departed by its ship-by time.",
                subject_ref=shipment.shipment_ref,
            )
        elif (
            shipment.status in {"in_transit", "exception"}
            and _parse_timestamp(shipment.promised_delivery_at) < analysis_as_of
        ):
            _add_finding(
                findings,
                code="shipment.delivery_overdue",
                gate="shipment",
                severity="review",
                message="Shipment is not delivered by its promised time.",
                subject_ref=shipment.shipment_ref,
            )

        custody_events = sorted(
            shipment.custody_events,
            key=lambda event: event.sequence,
        )
        custody_complete = shipment.status in {"planned", "ready", "cancelled"}
        if shipment.status in {"in_transit", "delivered", "exception"}:
            if not custody_events:
                _add_finding(
                    findings,
                    code="custody.events_missing",
                    gate="custody",
                    severity="indeterminate",
                    message="Active shipment lacks custody events.",
                    subject_ref=shipment.shipment_ref,
                )
            else:
                custody_complete = True
        if custody_events:
            expected_sequences = list(range(1, len(custody_events) + 1))
            actual_sequences = [event.sequence for event in custody_events]
            if actual_sequences != expected_sequences:
                custody_complete = False
                _add_finding(
                    findings,
                    code="custody.sequence_incomplete",
                    gate="custody",
                    severity="indeterminate",
                    message="Custody-event sequence is incomplete.",
                    subject_ref=shipment.shipment_ref,
                )
            if custody_events[0].from_party_ref != shipment.warehouse_ref:
                custody_complete = False
                _add_finding(
                    findings,
                    code="custody.origin_mismatch",
                    gate="custody",
                    severity="blocking",
                    message="First custody event does not originate at the warehouse.",
                    subject_ref=shipment.shipment_ref,
                    related_refs=(custody_events[0].custody_event_ref,),
                )
            previous: ShipmentCustodyEvent | None = None
            for event in custody_events:
                _assess_owner_evidence(
                    findings,
                    owner_ref=event.custody_event_ref,
                    owner_label="custody_event",
                    expected_kind="shipment_custody_event",
                    refs=event.evidence_refs,
                    evidence_by_ref=evidence_by_ref,
                    analysis_as_of=analysis_as_of,
                    policy=policy,
                    evidence_state=evidence_state,
                )
                occurred_at = _parse_timestamp(event.occurred_at)
                if _evidence_precedes_claim(
                    event.evidence_refs,
                    expected_kind="shipment_custody_event",
                    claimed_at=occurred_at,
                    evidence_by_ref=evidence_by_ref,
                ):
                    custody_complete = False
                    evidence_state["invalid"] = True
                    _add_finding(
                        findings,
                        code="evidence.custody_event.precedes_claim",
                        gate="evidence",
                        severity="blocking",
                        message="Custody evidence predates the claimed handoff.",
                        subject_ref=event.custody_event_ref,
                        related_refs=(shipment.shipment_ref,),
                        evidence_refs=event.evidence_refs,
                    )
                if occurred_at > analysis_as_of:
                    custody_complete = False
                    _add_finding(
                        findings,
                        code="custody.event_future",
                        gate="custody",
                        severity="blocking",
                        message="Custody event occurs after the analysis cutoff.",
                        subject_ref=event.custody_event_ref,
                        related_refs=(shipment.shipment_ref,),
                    )
                if previous is not None:
                    if previous.to_party_ref != event.from_party_ref:
                        custody_complete = False
                        _add_finding(
                            findings,
                            code="custody.chain_broken",
                            gate="custody",
                            severity="blocking",
                            message="Custody handoff parties do not form a continuous chain.",
                            subject_ref=event.custody_event_ref,
                            related_refs=(
                                shipment.shipment_ref,
                                previous.custody_event_ref,
                            ),
                        )
                    if occurred_at < _parse_timestamp(previous.occurred_at):
                        custody_complete = False
                        _add_finding(
                            findings,
                            code="custody.time_reversed",
                            gate="custody",
                            severity="blocking",
                            message="Custody events are not chronological.",
                            subject_ref=event.custody_event_ref,
                            related_refs=(shipment.shipment_ref,),
                        )
                previous = event
            last_holder = custody_events[-1].to_party_ref
            if shipment.custody_holder_ref is None:
                custody_complete = False
                _add_finding(
                    findings,
                    code="custody.holder_missing",
                    gate="custody",
                    severity="indeterminate",
                    message="Shipment lacks a current custody-holder reference.",
                    subject_ref=shipment.shipment_ref,
                )
            elif shipment.custody_holder_ref != last_holder:
                custody_complete = False
                _add_finding(
                    findings,
                    code="custody.holder_mismatch",
                    gate="custody",
                    severity="blocking",
                    message="Current custody holder conflicts with the latest handoff.",
                    subject_ref=shipment.shipment_ref,
                )
            if (
                shipment.status == "delivered"
                and last_holder != shipment.destination_ref
            ):
                custody_complete = False
                _add_finding(
                    findings,
                    code="custody.delivery_destination_mismatch",
                    gate="custody",
                    severity="blocking",
                    message="Delivered shipment custody does not end at its destination.",
                    subject_ref=shipment.shipment_ref,
                )

        open_exception_count = 0
        for exception in sorted(
            shipment.exceptions,
            key=lambda item: item.exception_ref,
        ):
            _assess_owner_evidence(
                findings,
                owner_ref=exception.exception_ref,
                owner_label="shipment_exception",
                expected_kind="shipment_exception",
                refs=exception.evidence_refs,
                evidence_by_ref=evidence_by_ref,
                analysis_as_of=analysis_as_of,
                policy=policy,
                evidence_state=evidence_state,
            )
            opened_at = _parse_timestamp(exception.opened_at)
            exception_claimed_at = (
                _parse_timestamp(exception.resolved_at)
                if exception.resolved_at is not None
                else opened_at
            )
            if _evidence_precedes_claim(
                exception.evidence_refs,
                expected_kind="shipment_exception",
                claimed_at=exception_claimed_at,
                evidence_by_ref=evidence_by_ref,
            ):
                evidence_state["invalid"] = True
                _add_finding(
                    findings,
                    code="evidence.shipment_exception.precedes_claim",
                    gate="evidence",
                    severity="blocking",
                    message="Exception evidence predates the latest claimed event.",
                    subject_ref=exception.exception_ref,
                    related_refs=(shipment.shipment_ref,),
                    evidence_refs=exception.evidence_refs,
                )
            if opened_at > analysis_as_of:
                _add_finding(
                    findings,
                    code="exception.opened_future",
                    gate="exception",
                    severity="blocking",
                    message="Shipment exception opens after the analysis cutoff.",
                    subject_ref=exception.exception_ref,
                    related_refs=(shipment.shipment_ref,),
                )
            if exception.status == "open":
                open_exception_count += 1
                _add_finding(
                    findings,
                    code=f"exception.open_{exception.category}",
                    gate="exception",
                    severity=exception.severity,
                    message=f"Shipment has an open {exception.category} exception.",
                    subject_ref=exception.exception_ref,
                    related_refs=(shipment.shipment_ref,),
                )
                if exception.resolved_at is not None:
                    _add_finding(
                        findings,
                        code="exception.open_with_resolution_time",
                        gate="exception",
                        severity="blocking",
                        message="Open exception unexpectedly carries a resolution time.",
                        subject_ref=exception.exception_ref,
                        related_refs=(shipment.shipment_ref,),
                    )
            elif exception.status == "mitigated":
                open_exception_count += 1
                _add_finding(
                    findings,
                    code=f"exception.mitigated_{exception.category}",
                    gate="exception",
                    severity="review",
                    message=f"Shipment {exception.category} exception is mitigated but unresolved.",
                    subject_ref=exception.exception_ref,
                    related_refs=(shipment.shipment_ref,),
                )
            elif exception.resolved_at is None:
                _add_finding(
                    findings,
                    code="exception.resolution_time_missing",
                    gate="exception",
                    severity="indeterminate",
                    message="Resolved exception lacks a resolution time.",
                    subject_ref=exception.exception_ref,
                    related_refs=(shipment.shipment_ref,),
                )
            else:
                resolved_at = _parse_timestamp(exception.resolved_at)
                if resolved_at < opened_at or resolved_at > analysis_as_of:
                    _add_finding(
                        findings,
                        code="exception.resolution_time_invalid",
                        gate="exception",
                        severity="blocking",
                        message="Exception resolution time is temporally invalid.",
                        subject_ref=exception.exception_ref,
                        related_refs=(shipment.shipment_ref,),
                    )
        if shipment.status == "exception" and open_exception_count == 0:
            _add_finding(
                findings,
                code="exception.status_without_open_record",
                gate="exception",
                severity="indeterminate",
                message="Shipment exception status lacks an open exception record.",
                subject_ref=shipment.shipment_ref,
            )
        shipment_state[shipment.shipment_ref] = {
            "custody_complete": custody_complete,
            "open_exception_count": open_exception_count,
            "delivered_on_time": delivered_on_time,
        }

    for allocation_ref, shipment_quantity in sorted(
        shipment_quantity_by_allocation.items()
    ):
        allocation = allocations_by_ref.get(allocation_ref)
        if allocation is not None and shipment_quantity > allocation.quantity:
            shipment_refs = shipment_refs_by_allocation[allocation_ref]
            _add_finding(
                findings,
                code="shipment.allocation_quantity_exceeded",
                gate="shipment",
                severity="blocking",
                message="Shipment quantity exceeds its allocation quantity.",
                subject_ref=allocation_ref,
                related_refs=shipment_refs,
            )

    for allocation in sorted(parsed.allocations, key=lambda item: item.allocation_ref):
        if allocation.status in {"cancelled", "unknown"}:
            continue
        shipment_quantity = shipment_quantity_by_allocation.get(
            allocation.allocation_ref,
            Decimal("0"),
        )
        if shipment_quantity < allocation.quantity:
            _add_finding(
                findings,
                code="shipment.allocation_quantity_uncovered",
                gate="shipment",
                severity=(
                    "blocking"
                    if parsed.coverage.shipments_complete
                    else "indeterminate"
                ),
                message="Active shipment plans do not cover the allocation quantity.",
                subject_ref=allocation.allocation_ref,
                related_refs=(
                    allocation.plan_line_ref,
                    *shipment_refs_by_allocation.get(allocation.allocation_ref, ()),
                ),
            )

    plan_line_results: list[PlanLineControlResult] = []
    for plan_line in sorted(parsed.plan_lines, key=lambda item: item.plan_line_ref):
        related_findings = [
            finding
            for finding in findings
            if finding.subject_ref == plan_line.plan_line_ref
            or plan_line.plan_line_ref in finding.related_refs
        ]
        metrics = plan_metrics[plan_line.plan_line_ref]
        plan_line_results.append(
            PlanLineControlResult(
                plan_line_ref=plan_line.plan_line_ref,
                projected_ending_quantity=metrics["projected_ending"],
                available_to_allocate_quantity=metrics["available_to_allocate"],
                safety_stock_gap_quantity=metrics["safety_gap"],
                committed_demand_quantity=plan_line.committed_demand_quantity,
                allocated_quantity=metrics["allocated"],
                replenishment_required_quantity=metrics["safety_gap"],
                replenishment_planned_quantity=metrics["replenishment_planned"],
                status=_status_from_findings(related_findings),
                finding_codes=tuple(
                    dict.fromkeys(finding.code for finding in related_findings)
                ),
            )
        )

    shipment_results: list[ShipmentControlResult] = []
    for shipment in sorted(parsed.shipments, key=lambda item: item.shipment_ref):
        related_findings = [
            finding
            for finding in findings
            if finding.subject_ref == shipment.shipment_ref
            or shipment.shipment_ref in finding.related_refs
        ]
        state = shipment_state[shipment.shipment_ref]
        shipment_results.append(
            ShipmentControlResult(
                shipment_ref=shipment.shipment_ref,
                status=_status_from_findings(related_findings),
                custody_complete=state["custody_complete"],
                open_exception_count=state["open_exception_count"],
                delivered_on_time=state["delivered_on_time"],
                finding_codes=tuple(
                    dict.fromkeys(finding.code for finding in related_findings)
                ),
            )
        )

    gates = _gate_results(findings)
    gate_statuses = {gate.status for gate in gates}
    disposition: PlanFulfillmentDisposition = (
        "blocked"
        if "fail" in gate_statuses
        else "indeterminate"
        if "indeterminate" in gate_statuses
        else "manual_review_required"
        if "review" in gate_statuses
        else "ready_for_governed_execution"
    )
    eligible_grades: list[PrimitiveEvidenceVerificationGrade] = evidence_state[
        "eligible_grades"
    ]
    assurance_grade = (
        PrimitiveEvidenceVerificationGrade.UNVERIFIED
        if evidence_state["invalid"] or not eligible_grades
        else min(eligible_grades, key=lambda grade: _GRADE_RANK[grade])
    )
    evidence_digest = _evidence_digest(parsed.evidence_refs)
    operation_digest = _operation_digest(parsed, evidence_digest)
    return PlanFulfillmentControlsResult(
        control_ref=parsed.control_ref,
        company_ref=parsed.company_ref,
        analysis_as_of=parsed.analysis_as_of,
        assurance_grade=assurance_grade,
        proposed_disposition=disposition,
        fulfillment_authorized=False,
        gates=gates,
        plan_line_results=tuple(plan_line_results),
        shipment_results=tuple(shipment_results),
        findings=tuple(findings),
        source_snapshot_digests=_source_snapshot_digests(parsed),
        evidence_refs=tuple(
            evidence.evidence_ref
            for evidence in sorted(
                parsed.evidence_refs,
                key=lambda item: item.evidence_ref,
            )
        ),
        operation_spec=SUPPLY_CHAIN_EVALUATION_OPERATION,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
        effect_boundary=SupplyChainEffectBoundary(),
    )


def _example_evidence(
    evidence_ref: str,
    kind: str,
    digest_character: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": "spring-supply-chain-authority",
        "subject_ref": "company-example",
        "sha256": digest_character * 64,
        "observed_at": "2026-08-24T11:00:00Z",
        "effective_at": "2026-08-24T10:00:00Z",
        "verification_grade": "attested",
        "classification": "confidential",
        "retention_policy": "operations-seven-years",
        "jurisdiction": "US",
    }


def _example_inputs() -> dict[str, Any]:
    return {
        "schema": PLAN_FULFILLMENT_CONTROLS_INPUT_SCHEMA,
        "control_ref": "plan-fulfillment-example",
        "company_ref": "company-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "coverage": {
            "suppliers_complete": True,
            "forecasts_complete": True,
            "plan_lines_complete": True,
            "allocations_complete": True,
            "replenishments_complete": True,
            "warehouses_complete": True,
            "shipments_complete": True,
        },
        "planning_cycle": {
            "cycle_ref": "planning-cycle-example",
            "company_ref": "company-example",
            "horizon_start": "2026-08-24T00:00:00Z",
            "horizon_end": "2026-09-30T23:59:59Z",
            "sop_status": "approved",
            "mrp_status": "complete",
            "approved_by_ref": "planner-approver",
            "mrp_run_ref": "mrp-run-example",
            "mrp_completed_at": "2026-08-24T11:00:00Z",
            "evidence_refs": ["evidence-planning-cycle"],
        },
        "suppliers": [
            {
                "supplier_ref": "supplier-example",
                "company_ref": "company-example",
                "qualification_status": "qualified",
                "risk_level": "low",
                "on_time_delivery_ratio": "0.980000",
                "defect_ratio": "0.010000",
                "lead_time_days": 14,
                "qualified_until": "2027-08-24T00:00:00Z",
                "evidence_refs": ["evidence-supplier"],
            }
        ],
        "demand_forecasts": [
            {
                "forecast_ref": "forecast-widget-east",
                "company_ref": "company-example",
                "item_ref": "item-widget",
                "warehouse_ref": "warehouse-east",
                "unit_of_measure": "EA",
                "horizon_start": "2026-08-24T00:00:00Z",
                "horizon_end": "2026-09-30T23:59:59Z",
                "generated_at": "2026-08-24T11:00:00Z",
                "forecast_quantity": "60.000000",
                "confidence_ratio": "0.900000",
                "model_version_ref": "forecast-model-v1",
                "evidence_refs": ["evidence-forecast"],
            }
        ],
        "plan_lines": [
            {
                "plan_line_ref": "plan-line-widget-east",
                "company_ref": "company-example",
                "forecast_ref": "forecast-widget-east",
                "item_ref": "item-widget",
                "warehouse_ref": "warehouse-east",
                "unit_of_measure": "EA",
                "opening_on_hand_quantity": "50.000000",
                "confirmed_inbound_quantity": "10.000000",
                "planned_production_quantity": "0.000000",
                "uncommitted_demand_quantity": "40.000000",
                "committed_demand_quantity": "20.000000",
                "safety_stock_quantity": "20.000000",
                "required_handling_codes": ["ambient"],
                "evidence_refs": ["evidence-plan-line"],
            }
        ],
        "allocations": [
            {
                "allocation_ref": "allocation-customer-a",
                "company_ref": "company-example",
                "plan_line_ref": "plan-line-widget-east",
                "item_ref": "item-widget",
                "warehouse_ref": "warehouse-east",
                "destination_ref": "customer-a",
                "unit_of_measure": "EA",
                "quantity": "20.000000",
                "priority": 10,
                "status": "committed",
                "evidence_refs": ["evidence-allocation"],
            }
        ],
        "replenishments": [
            {
                "replenishment_ref": "replenishment-widget-east",
                "company_ref": "company-example",
                "plan_line_ref": "plan-line-widget-east",
                "supplier_ref": "supplier-example",
                "item_ref": "item-widget",
                "warehouse_ref": "warehouse-east",
                "unit_of_measure": "EA",
                "quantity": "40.000000",
                "handling_units": "10.000000",
                "status": "proposed",
                "order_by_at": "2026-08-25T12:00:00Z",
                "expected_receipt_at": "2026-09-01T12:00:00Z",
                "evidence_refs": ["evidence-replenishment"],
            }
        ],
        "warehouses": [
            {
                "warehouse_ref": "warehouse-east",
                "company_ref": "company-example",
                "status": "operational",
                "capacity_handling_units": "1000.000000",
                "occupied_handling_units": "400.000000",
                "reserved_inbound_handling_units": "100.000000",
                "planned_inbound_handling_units": "10.000000",
                "planned_outbound_handling_units": "50.000000",
                "inventory_accuracy_ratio": "0.995000",
                "handling_codes": ["ambient"],
                "evidence_refs": ["evidence-warehouse"],
            }
        ],
        "shipments": [
            {
                "shipment_ref": "shipment-customer-a",
                "company_ref": "company-example",
                "allocation_ref": "allocation-customer-a",
                "plan_line_ref": "plan-line-widget-east",
                "item_ref": "item-widget",
                "warehouse_ref": "warehouse-east",
                "destination_ref": "customer-a",
                "unit_of_measure": "EA",
                "quantity": "20.000000",
                "status": "in_transit",
                "carrier_ref": "carrier-example",
                "tracking_ref": "tracking-example",
                "custody_holder_ref": "carrier-example",
                "ship_by_at": "2026-08-24T10:00:00Z",
                "promised_delivery_at": "2026-08-27T12:00:00Z",
                "shipped_at": "2026-08-24T11:00:00Z",
                "required_handling_codes": ["ambient"],
                "custody_events": [
                    {
                        "custody_event_ref": "custody-event-carrier",
                        "sequence": 1,
                        "from_party_ref": "warehouse-east",
                        "to_party_ref": "carrier-example",
                        "occurred_at": "2026-08-24T11:00:00Z",
                        "evidence_refs": ["evidence-custody"],
                    }
                ],
                "exceptions": [],
                "evidence_refs": ["evidence-shipment"],
            }
        ],
        "evidence_refs": [
            _example_evidence(
                "evidence-planning-cycle", "planning_cycle_snapshot", "a"
            ),
            _example_evidence(
                "evidence-supplier", "supplier_performance_snapshot", "b"
            ),
            _example_evidence("evidence-forecast", "demand_forecast_snapshot", "c"),
            _example_evidence("evidence-plan-line", "supply_demand_plan", "d"),
            _example_evidence("evidence-allocation", "allocation_plan", "e"),
            _example_evidence("evidence-replenishment", "replenishment_plan", "f"),
            _example_evidence("evidence-warehouse", "warehouse_snapshot", "1"),
            _example_evidence("evidence-shipment", "shipment_snapshot", "2"),
            _example_evidence("evidence-custody", "shipment_custody_event", "3"),
        ],
    }


class EvaluatePlanFulfillmentControlsPrimitive(
    BusinessProcessPrimitive[
        PlanFulfillmentControlsInput,
        PlanFulfillmentControlsResult,
    ]
):
    primitive_ref = "supply_chain.evaluate_plan_fulfillment_controls"
    version = "1.0.0"
    title = "Evaluate supply-chain plan and fulfillment controls"
    description = (
        "Evaluate supplier, forecast, S&OP/MRP, allocation, replenishment, "
        "warehouse, shipment, custody, delivery, and exception evidence without "
        "changing operational systems."
    )
    input_model = PlanFulfillmentControlsInput
    output_model = PlanFulfillmentControlsResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = _example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = SUPPLY_CHAIN_EVALUATION_OPERATION.to_dict()
        contract["effect_boundary"] = SupplyChainEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "sdk": "deterministic_control_evaluation_and_proposal_only",
            "spring": [
                "tenant_and_company_scope",
                "rbac",
                "source_normalization",
                "persistence_and_audit",
                "approval_and_write_authorization",
            ],
            "connectors": "provider_reads_and_writes_via_trusted_host_only",
            "inventory_authority": "never_granted_by_this_primitive",
            "order_authority": "never_granted_by_this_primitive",
            "allocation_authority": "never_granted_by_this_primitive",
            "shipment_authority": "never_granted_by_this_primitive",
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
        inputs: PlanFulfillmentControlsInput,
    ) -> PrimitiveExecutionResult[PlanFulfillmentControlsResult]:
        del context
        output = evaluate_plan_fulfillment_controls(inputs)
        evidence_refs = sorted(
            inputs.evidence_refs,
            key=lambda evidence: evidence.evidence_ref,
        )
        receipt = PrimitiveOperationReceipt(
            spec=SUPPLY_CHAIN_EVALUATION_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.operation_digest,
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[PlanFulfillmentControlsResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Supply-chain controls evaluated; the read-only proposal disposition "
                f"is {output.proposed_disposition}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="supply_chain.plan_fulfillment_controls_evaluated",
                    payload={
                        "control_ref": output.control_ref,
                        "proposed_disposition": output.proposed_disposition,
                        "assurance_grade": output.assurance_grade.value,
                        "finding_count": len(output.findings),
                        "fulfillment_authorized": False,
                        "inventory_changed": False,
                        "orders_created": False,
                        "allocations_committed": False,
                        "shipments_changed": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="supply_chain_control_result",
                    summary=(
                        "The SDK evaluated normalized supply-chain evidence without "
                        "connector calls or operational mutations."
                    ),
                    labels=[
                        output.proposed_disposition,
                        "read_only",
                        "spring_authority_required",
                    ],
                    refs={
                        "operation_sha256": output.operation_digest,
                        "evidence_sha256": output.evidence_digest,
                        "result_sha256": output.result_digest,
                    },
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


SUPPLY_CHAIN_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    EvaluatePlanFulfillmentControlsPrimitive(),
)


__all__ = [
    "ALLOCATION_PLAN_LINE_SCHEMA",
    "DEMAND_FORECAST_SNAPSHOT_SCHEMA",
    "PLAN_FULFILLMENT_CONTROLS_INPUT_SCHEMA",
    "PLAN_FULFILLMENT_CONTROLS_RESULT_SCHEMA",
    "PLANNING_CYCLE_SNAPSHOT_SCHEMA",
    "REPLENISHMENT_PLAN_LINE_SCHEMA",
    "SHIPMENT_SNAPSHOT_SCHEMA",
    "SUPPLIER_PERFORMANCE_SNAPSHOT_SCHEMA",
    "SUPPLY_CHAIN_EVALUATION_OPERATION",
    "SUPPLY_CHAIN_EXECUTABLE_PRIMITIVES",
    "SUPPLY_DEMAND_PLAN_LINE_SCHEMA",
    "WAREHOUSE_SNAPSHOT_SCHEMA",
    "AllocationPlanLine",
    "AllocationStatus",
    "DemandForecastSnapshot",
    "EvaluatePlanFulfillmentControlsPrimitive",
    "MrpRunStatus",
    "PlanFulfillmentControlsInput",
    "PlanFulfillmentControlsResult",
    "PlanFulfillmentDisposition",
    "PlanLineControlResult",
    "PlanLineControlStatus",
    "PlanningCycleSnapshot",
    "PlanningStatus",
    "ReplenishmentPlanLine",
    "ReplenishmentStatus",
    "ShipmentControlResult",
    "ShipmentControlStatus",
    "ShipmentCustodyEvent",
    "ShipmentExceptionCategory",
    "ShipmentExceptionSeverity",
    "ShipmentExceptionSnapshot",
    "ShipmentExceptionStatus",
    "ShipmentSnapshot",
    "ShipmentStatus",
    "SupplierPerformanceSnapshot",
    "SupplierQualificationStatus",
    "SupplierRiskLevel",
    "SupplyChainControlPolicy",
    "SupplyChainEffectBoundary",
    "SupplyChainFinding",
    "SupplyChainFindingSeverity",
    "SupplyChainGate",
    "SupplyChainGateResult",
    "SupplyChainGateStatus",
    "SupplyChainSnapshotCoverage",
    "SupplyDemandPlanLine",
    "WarehouseSnapshot",
    "WarehouseStatus",
    "evaluate_plan_fulfillment_controls",
    "supply_chain_snapshot_digest",
]
