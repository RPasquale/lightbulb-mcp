"""Deterministic, non-authoritative supply-chain execution projections.

This module deliberately stops at a content-bound candidate snapshot.  Spring
remains authoritative for identity, RBAC, approval, idempotency, persistence,
and audit.  ERP, WMS, and TMS systems remain authoritative for optimization,
inventory, warehouse, shipment, custody, and delivery facts and writes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Mapping, Sequence, Union
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
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
)


SUPPLY_CHAIN_SCOPE_SCHEMA = "lightbulb.supply_chain_execution_scope.v1"
SUPPLY_CHAIN_EVIDENCE_SCHEMA = "lightbulb.supply_chain_execution_evidence.v1"
SUPPLY_CHAIN_APPROVAL_SCHEMA = "lightbulb.supply_chain_execution_approval.v1"
SUPPLY_CHAIN_TRANSITION_RECORD_SCHEMA = (
    "lightbulb.supply_chain_execution_transition_record.v1"
)
SUPPLY_CHAIN_SNAPSHOT_SCHEMA = "lightbulb.supply_chain_execution_snapshot.v1"
SUPPLY_CHAIN_REQUEST_SCHEMA = "lightbulb.supply_chain_execution_request.v1"
SUPPLY_CHAIN_PROPOSAL_SCHEMA = "lightbulb.supply_chain_execution_proposal.v1"
SUPPLY_CHAIN_RESULT_SCHEMA = "lightbulb.supply_chain_execution_result.v1"
SPRING_SUPPLY_CHAIN_EVIDENCE_ISSUER = "spring:supply-chain-authority"
SPRING_SUPPLY_CHAIN_EVIDENCE_CUSTODIAN = "spring:supply-chain-evidence-vault"
ZERO_DIGEST = "0" * 64
MAX_TRANSITIONS = 32
MAX_EVIDENCE_PER_TRANSITION = 8
MAX_CUSTODY_EVENTS = 12
MAX_QUANTITY = Decimal("1000000000000")
MAX_EVIDENCE_AGE = timedelta(days=7)
MAX_APPROVAL_WINDOW = timedelta(hours=24)
MAX_EXCEPTION_WINDOW = timedelta(days=7)
MAX_AMBIGUITY_WINDOW = timedelta(hours=72)


SupplyChainState = Literal[
    "forecast_projected",
    "sop_approved",
    "mrp_planned",
    "allocated",
    "replenishment_planned",
    "warehouse_released",
    "in_transit",
    "delivered",
    "exception_open",
    "exception_resolved",
    "in_doubt",
    "closed",
]
ApprovalRole = Literal[
    "sop_authorizer",
    "allocation_authorizer",
    "replenishment_authorizer",
    "warehouse_authorizer",
    "transport_authorizer",
    "exception_authorizer",
    "recovery_authorizer",
    "closure_authorizer",
]


class SupplyChainExecutionError(ValueError):
    """Stable, fail-closed lifecycle error returned by the primitive wrapper."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        str_strip_whitespace=False,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _stable_digest(value: Any) -> str:
    encoded = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _visible(value: Any, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError(
            f"{name} must contain visible ASCII characters without whitespace"
        )
    return value


def _quantity(value: Any, *, allow_zero: bool = True) -> Decimal:
    if isinstance(value, float):
        raise ValueError("quantity must not be supplied as a binary float")
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError("quantity must be a decimal string, integer, or Decimal")
    try:
        lexical = str(value)
    except ValueError as exc:
        raise ValueError("quantity must use bounded decimal notation") from exc
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("quantity must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("quantity must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("quantity must be a finite decimal")
    if parsed < 0 or (not allow_zero and parsed == 0):
        raise ValueError(
            "quantity must be positive"
            if not allow_zero
            else "quantity cannot be negative"
        )
    if parsed > MAX_QUANTITY:
        raise ValueError("quantity exceeds the supported bound")
    if max(0, -parsed.as_tuple().exponent) > 6:
        raise ValueError("quantity supports at most six fractional digits")
    return Decimal("0") if parsed == 0 else parsed.normalize()


def _canonical_date(value: Any, *, name: str) -> date:
    if isinstance(value, datetime):
        raise ValueError(f"{name} must be an ISO-8601 calendar date")
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{name} must be an ISO-8601 calendar date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 calendar date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{name} must use canonical YYYY-MM-DD form")
    return parsed


class SupplyChainExecutionScope(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_scope.v1"] = Field(
        default=SUPPLY_CHAIN_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: str = Field(min_length=1, max_length=160)
    company_ref: str = Field(min_length=1, max_length=160)
    project_ref: str = Field(min_length=1, max_length=160)
    project_id: UUID
    planning_cycle_ref: str = Field(min_length=1, max_length=160)
    item_ref: str = Field(min_length=1, max_length=160)
    source_location_ref: str = Field(min_length=1, max_length=160)
    destination_location_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)

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
        if str(parsed) != value.lower():
            raise ValueError("project_id must be a canonical UUID")
        return parsed

    @field_validator(
        "tenant_ref",
        "company_ref",
        "project_ref",
        "planning_cycle_ref",
        "item_ref",
        "source_location_ref",
        "destination_location_ref",
        "unit_of_measure",
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @model_validator(mode="after")
    def _locations_differ(self) -> "SupplyChainExecutionScope":
        if self.source_location_ref == self.destination_location_ref:
            raise ValueError("source and destination locations must differ")
        return self


def supply_chain_scope_digest(
    scope: SupplyChainExecutionScope | Mapping[str, Any],
) -> str:
    parsed = SupplyChainExecutionScope.model_validate(scope)
    return _stable_digest(parsed)


class SupplyChainExecutionEvidence(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_evidence.v1"] = Field(
        default=SUPPLY_CHAIN_EVIDENCE_SCHEMA,
        alias="schema",
    )
    evidence_ref: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=80)
    issuer_ref: Literal["spring:supply-chain-authority"]
    custodian_ref: Literal["spring:supply-chain-evidence-vault"]
    subject_ref: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    effective_at: str
    verification_grade: Literal["attested", "verified"]
    classification: Literal["confidential", "restricted"] = "restricted"
    retention_policy: Literal["supply-chain-seven-years"]
    single_use: Literal[True]
    causal_revision: int = Field(ge=0, le=MAX_TRANSITIONS)
    causal_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_ref", "subject_ref", "retention_policy")
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("observed_at", "effective_at")
    @classmethod
    def _timestamps_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _chronology(self) -> "SupplyChainExecutionEvidence":
        if _dt(self.effective_at) > _dt(self.observed_at):
            raise ValueError("evidence cannot be observed before it becomes effective")
        return self

    def portable_ref(self) -> PrimitiveEvidenceRef:
        return PrimitiveEvidenceRef(
            evidence_ref=self.evidence_ref,
            kind=self.kind,
            issuer_ref=self.issuer_ref,
            subject_ref=self.subject_ref,
            sha256=self.sha256,
            observed_at=self.observed_at,
            effective_at=self.effective_at,
            verification_grade=PrimitiveEvidenceVerificationGrade(
                self.verification_grade
            ),
            classification=PrimitiveEvidenceClassification(self.classification),
            retention_policy=self.retention_policy,
        )


class SupplyChainApprovalEvidence(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_approval.v1"] = Field(
        default=SUPPLY_CHAIN_APPROVAL_SCHEMA,
        alias="schema",
    )
    approval_ref: str = Field(min_length=1, max_length=200)
    approval_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    transition_ref: str = Field(min_length=1, max_length=160)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_by_ref: str = Field(min_length=1, max_length=160)
    approver_role: ApprovalRole
    approved_at: str
    expires_at: str
    decision: Literal["approved"]
    single_use: Literal[True]
    sdk_execution_authority_granted: Literal[False]
    approval_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: SupplyChainExecutionEvidence

    @field_validator(
        "approval_ref",
        "lifecycle_ref",
        "transition_ref",
        "approved_by_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def _timestamps_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("approval_receipt_digest")
    @classmethod
    def _receipt_is_not_a_sentinel(cls, value: str) -> str:
        if value == ZERO_DIGEST:
            raise ValueError("approval_receipt_digest must identify a Spring receipt")
        return value

    @model_validator(mode="after")
    def _content_bound(self) -> "SupplyChainApprovalEvidence":
        approved_at = _dt(self.approved_at)
        expires_at = _dt(self.expires_at)
        if expires_at <= approved_at or expires_at - approved_at > MAX_APPROVAL_WINDOW:
            raise ValueError(
                "approval validity must be positive and no longer than 24 hours"
            )
        if self.approval_digest != supply_chain_approval_digest(self):
            raise ValueError("approval_digest does not match approval content")
        evidence = self.evidence
        if (
            evidence.kind != "supply_chain_approval_decision"
            or evidence.subject_ref != self.approval_ref
            or evidence.sha256 != self.approval_digest
            or evidence.verification_grade != "verified"
            or evidence.observed_at != self.approved_at
            or evidence.effective_at != self.approved_at
        ):
            raise ValueError(
                "approval evidence must verify the exact approval decision"
            )
        return self


def supply_chain_approval_digest(
    approval: SupplyChainApprovalEvidence | Mapping[str, Any],
) -> str:
    payload = (
        approval.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(approval, SupplyChainApprovalEvidence)
        else dict(approval)
    )
    payload.pop("approval_digest", None)
    payload.pop("evidence", None)
    return _stable_digest(payload)


class _Command(_StrictModel):
    approval: SupplyChainApprovalEvidence | None = None

    @model_validator(mode="after")
    def _command_refs_are_exact(self) -> "_Command":
        for field_name in type(self).model_fields:
            value = getattr(self, field_name, None)
            if isinstance(value, str) and (
                field_name.endswith("_ref")
                or field_name in {"unit_of_measure", "model_version"}
            ):
                _visible(value, name=field_name)
        return self


class ProjectDemandForecastCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_project_demand_forecast_command.v1"] = (
        Field(
            default="lightbulb.supply_chain_project_demand_forecast_command.v1",
            alias="schema",
        )
    )
    kind: Literal["project_demand_forecast"]
    forecast_ref: str = Field(min_length=1, max_length=160)
    planning_cycle_ref: str = Field(min_length=1, max_length=160)
    item_ref: str = Field(min_length=1, max_length=160)
    source_location_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    horizon_start: date
    horizon_end: date
    generated_at: str
    forecast_quantity: Decimal
    model_version: str = Field(min_length=1, max_length=80)
    planner_ref: str = Field(min_length=1, max_length=160)

    @field_validator("forecast_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)

    @field_validator("generated_at")
    @classmethod
    def _generated_at(cls, value: str) -> str:
        return _utc(value, name="generated_at")

    @field_validator("horizon_start", "horizon_end", mode="before")
    @classmethod
    def _canonical_horizon_date(cls, value: Any, info: Any) -> date:
        return _canonical_date(value, name=info.field_name)

    @model_validator(mode="after")
    def _horizon(self) -> "ProjectDemandForecastCommand":
        if self.horizon_end < self.horizon_start:
            raise ValueError("forecast horizon end cannot precede its start")
        if _dt(self.generated_at).date() > self.horizon_start:
            raise ValueError("forecast horizon cannot begin before forecast generation")
        if self.approval is not None:
            raise ValueError(
                "forecast projection does not accept portable approval authority"
            )
        return self


class ApproveSopCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_approve_sop_command.v1"] = Field(
        default="lightbulb.supply_chain_approve_sop_command.v1", alias="schema"
    )
    kind: Literal["approve_sop"]
    sop_plan_ref: str = Field(min_length=1, max_length=160)
    forecast_ref: str = Field(min_length=1, max_length=160)
    approved_quantity: Decimal
    unit_of_measure: str = Field(min_length=1, max_length=32)
    submitted_by_ref: str = Field(min_length=1, max_length=160)

    @field_validator("approved_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)


class RecordMrpSupplyPlanCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_record_mrp_supply_plan_command.v1"] = (
        Field(
            default="lightbulb.supply_chain_record_mrp_supply_plan_command.v1",
            alias="schema",
        )
    )
    kind: Literal["record_mrp_supply_plan"]
    mrp_run_ref: str = Field(min_length=1, max_length=160)
    sop_plan_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    approved_demand_quantity: Decimal
    opening_on_hand_quantity: Decimal
    confirmed_inbound_quantity: Decimal
    planned_production_quantity: Decimal
    safety_stock_quantity: Decimal
    required_replenishment_quantity: Decimal
    planned_at: str
    planner_ref: str = Field(min_length=1, max_length=160)

    @field_validator(
        "approved_demand_quantity",
        "opening_on_hand_quantity",
        "confirmed_inbound_quantity",
        "planned_production_quantity",
        "safety_stock_quantity",
        "required_replenishment_quantity",
        mode="before",
    )
    @classmethod
    def _valid_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value)

    @field_validator("planned_at")
    @classmethod
    def _planned_at(cls, value: str) -> str:
        return _utc(value, name="planned_at")

    @model_validator(mode="after")
    def _no_approval(self) -> "RecordMrpSupplyPlanCommand":
        if self.approval is not None:
            raise ValueError(
                "MRP fact projection does not accept portable approval authority"
            )
        required = max(
            Decimal("0"),
            self.approved_demand_quantity
            + self.safety_stock_quantity
            - self.opening_on_hand_quantity
            - self.confirmed_inbound_quantity
            - self.planned_production_quantity,
        )
        if self.required_replenishment_quantity != required:
            raise ValueError(
                "required replenishment must match the deterministic MRP shortfall"
            )
        return self


class AllocateSupplyCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_allocate_supply_command.v1"] = Field(
        default="lightbulb.supply_chain_allocate_supply_command.v1", alias="schema"
    )
    kind: Literal["allocate_supply"]
    allocation_ref: str = Field(min_length=1, max_length=160)
    mrp_run_ref: str = Field(min_length=1, max_length=160)
    destination_location_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    allocation_quantity: Decimal
    allocator_ref: str = Field(min_length=1, max_length=160)

    @field_validator("allocation_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)


class PlanReplenishmentCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_plan_replenishment_command.v1"] = Field(
        default="lightbulb.supply_chain_plan_replenishment_command.v1", alias="schema"
    )
    kind: Literal["plan_replenishment"]
    replenishment_ref: str = Field(min_length=1, max_length=160)
    mrp_run_ref: str = Field(min_length=1, max_length=160)
    allocation_ref: str = Field(min_length=1, max_length=160)
    status: Literal["planned", "not_required"]
    supplier_ref: str | None = Field(default=None, min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    replenishment_quantity: Decimal
    order_by: str
    expected_receipt_at: str
    planner_ref: str = Field(min_length=1, max_length=160)

    @field_validator("replenishment_quantity", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value)

    @field_validator("order_by", "expected_receipt_at")
    @classmethod
    def _timestamps_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _status_matches_quantity(self) -> "PlanReplenishmentCommand":
        if _dt(self.expected_receipt_at) < _dt(self.order_by):
            raise ValueError("expected receipt cannot precede order-by time")
        if self.replenishment_quantity == 0:
            if self.status != "not_required" or self.supplier_ref is not None:
                raise ValueError("zero replenishment must be explicitly not_required")
        elif self.status != "planned" or self.supplier_ref is None:
            raise ValueError(
                "positive replenishment requires a supplier and planned status"
            )
        return self


class ReleaseWarehouseCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_release_warehouse_command.v1"] = Field(
        default="lightbulb.supply_chain_release_warehouse_command.v1", alias="schema"
    )
    kind: Literal["release_warehouse"]
    warehouse_release_ref: str = Field(min_length=1, max_length=160)
    allocation_ref: str = Field(min_length=1, max_length=160)
    source_location_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    release_quantity: Decimal
    released_at: str
    warehouse_operator_ref: str = Field(min_length=1, max_length=160)

    @field_validator("release_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)

    @field_validator("released_at")
    @classmethod
    def _released_at(cls, value: str) -> str:
        return _utc(value, name="released_at")


class DispatchShipmentCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_dispatch_shipment_command.v1"] = Field(
        default="lightbulb.supply_chain_dispatch_shipment_command.v1", alias="schema"
    )
    kind: Literal["dispatch_shipment"]
    shipment_ref: str = Field(min_length=1, max_length=160)
    warehouse_release_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    shipment_quantity: Decimal
    carrier_ref: str = Field(min_length=1, max_length=160)
    custody_event_ref: str = Field(min_length=1, max_length=160)
    from_custodian_ref: str = Field(min_length=1, max_length=160)
    to_custodian_ref: str = Field(min_length=1, max_length=160)
    dispatched_at: str
    dispatcher_ref: str = Field(min_length=1, max_length=160)

    @field_validator("shipment_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)

    @field_validator("dispatched_at")
    @classmethod
    def _dispatched_at(cls, value: str) -> str:
        return _utc(value, name="dispatched_at")

    @model_validator(mode="after")
    def _custody_changes(self) -> "DispatchShipmentCommand":
        if self.from_custodian_ref == self.to_custodian_ref:
            raise ValueError("shipment dispatch must transfer custody")
        return self


class RecordCustodyTransferCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_record_custody_transfer_command.v1"] = (
        Field(
            default="lightbulb.supply_chain_record_custody_transfer_command.v1",
            alias="schema",
        )
    )
    kind: Literal["record_custody_transfer"]
    shipment_ref: str = Field(min_length=1, max_length=160)
    custody_event_ref: str = Field(min_length=1, max_length=160)
    sequence: int = Field(ge=2, le=MAX_CUSTODY_EVENTS)
    from_custodian_ref: str = Field(min_length=1, max_length=160)
    to_custodian_ref: str = Field(min_length=1, max_length=160)
    transferred_at: str
    recorder_ref: str = Field(min_length=1, max_length=160)

    @field_validator("transferred_at")
    @classmethod
    def _transferred_at(cls, value: str) -> str:
        return _utc(value, name="transferred_at")

    @model_validator(mode="after")
    def _custody_changes(self) -> "RecordCustodyTransferCommand":
        if self.from_custodian_ref == self.to_custodian_ref:
            raise ValueError("custody transfer must change custodian")
        if self.approval is not None:
            raise ValueError(
                "custody fact projection does not accept portable approval authority"
            )
        return self


class RecordDeliveryCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_record_delivery_command.v1"] = Field(
        default="lightbulb.supply_chain_record_delivery_command.v1", alias="schema"
    )
    kind: Literal["record_delivery"]
    delivery_ref: str = Field(min_length=1, max_length=160)
    shipment_ref: str = Field(min_length=1, max_length=160)
    destination_location_ref: str = Field(min_length=1, max_length=160)
    unit_of_measure: str = Field(min_length=1, max_length=32)
    delivered_quantity: Decimal
    delivered_at: str
    receiving_custodian_ref: str = Field(min_length=1, max_length=160)
    recorder_ref: str = Field(min_length=1, max_length=160)

    @field_validator("delivered_quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Decimal) -> Decimal:
        return _quantity(value, allow_zero=False)

    @field_validator("delivered_at")
    @classmethod
    def _delivered_at(cls, value: str) -> str:
        return _utc(value, name="delivered_at")

    @model_validator(mode="after")
    def _no_approval(self) -> "RecordDeliveryCommand":
        if self.approval is not None:
            raise ValueError(
                "delivery fact projection does not accept portable approval authority"
            )
        return self


class OpenShipmentExceptionCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_open_shipment_exception_command.v1"] = (
        Field(
            default="lightbulb.supply_chain_open_shipment_exception_command.v1",
            alias="schema",
        )
    )
    kind: Literal["open_shipment_exception"]
    exception_ref: str = Field(min_length=1, max_length=160)
    shipment_ref: str = Field(min_length=1, max_length=160)
    category: Literal[
        "delay",
        "damage",
        "loss",
        "customs",
        "temperature",
        "capacity",
        "address",
        "other",
    ]
    severity: Literal["review", "blocking"]
    detected_at: str
    response_deadline_at: str
    reporter_ref: str = Field(min_length=1, max_length=160)

    @field_validator("detected_at", "response_deadline_at")
    @classmethod
    def _timestamps_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _bounded_deadline(self) -> "OpenShipmentExceptionCommand":
        detected = _dt(self.detected_at)
        deadline = _dt(self.response_deadline_at)
        if deadline <= detected or deadline - detected > MAX_EXCEPTION_WINDOW:
            raise ValueError(
                "exception deadline must be positive and within seven days"
            )
        if self.approval is not None:
            raise ValueError(
                "exception fact projection does not accept portable approval authority"
            )
        return self


class ResolveShipmentExceptionCommand(_Command):
    schema_id: Literal[
        "lightbulb.supply_chain_resolve_shipment_exception_command.v1"
    ] = Field(
        default="lightbulb.supply_chain_resolve_shipment_exception_command.v1",
        alias="schema",
    )
    kind: Literal["resolve_shipment_exception"]
    resolution_ref: str = Field(min_length=1, max_length=160)
    exception_ref: str = Field(min_length=1, max_length=160)
    outcome: Literal[
        "redelivery_planned",
        "return_planned",
        "carrier_claim_planned",
        "closed_no_provider_write",
    ]
    resolved_at: str
    resolver_ref: str = Field(min_length=1, max_length=160)

    @field_validator("resolved_at")
    @classmethod
    def _resolved_at(cls, value: str) -> str:
        return _utc(value, name="resolved_at")


class MarkExecutionInDoubtCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_mark_execution_in_doubt_command.v1"] = (
        Field(
            default="lightbulb.supply_chain_mark_execution_in_doubt_command.v1",
            alias="schema",
        )
    )
    kind: Literal["mark_execution_in_doubt"]
    ambiguity_ref: str = Field(min_length=1, max_length=160)
    ambiguous_operation_ref: str = Field(min_length=1, max_length=160)
    detected_at: str
    resolution_deadline_at: str
    detector_ref: str = Field(min_length=1, max_length=160)

    @field_validator("detected_at", "resolution_deadline_at")
    @classmethod
    def _timestamps_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _bounded_deadline(self) -> "MarkExecutionInDoubtCommand":
        detected = _dt(self.detected_at)
        deadline = _dt(self.resolution_deadline_at)
        if deadline <= detected or deadline - detected > MAX_AMBIGUITY_WINDOW:
            raise ValueError("ambiguity resolution deadline must be within 72 hours")
        if self.approval is not None:
            raise ValueError(
                "ambiguity fact projection does not accept portable approval authority"
            )
        return self


class ResolveExecutionInDoubtCommand(_Command):
    schema_id: Literal[
        "lightbulb.supply_chain_resolve_execution_in_doubt_command.v1"
    ] = Field(
        default="lightbulb.supply_chain_resolve_execution_in_doubt_command.v1",
        alias="schema",
    )
    kind: Literal["resolve_execution_in_doubt"]
    recovery_ref: str = Field(min_length=1, max_length=160)
    ambiguity_ref: str = Field(min_length=1, max_length=160)
    outcome: Literal["effect_not_applied"]
    resolved_at: str
    reconciler_ref: str = Field(min_length=1, max_length=160)

    @field_validator("resolved_at")
    @classmethod
    def _resolved_at(cls, value: str) -> str:
        return _utc(value, name="resolved_at")


class CloseExecutionCommand(_Command):
    schema_id: Literal["lightbulb.supply_chain_close_execution_command.v1"] = Field(
        default="lightbulb.supply_chain_close_execution_command.v1", alias="schema"
    )
    kind: Literal["close_execution"]
    closure_ref: str = Field(min_length=1, max_length=160)
    closed_at: str
    closer_ref: str = Field(min_length=1, max_length=160)

    @field_validator("closed_at")
    @classmethod
    def _closed_at(cls, value: str) -> str:
        return _utc(value, name="closed_at")


SupplyChainCommand = Annotated[
    Union[
        ProjectDemandForecastCommand,
        ApproveSopCommand,
        RecordMrpSupplyPlanCommand,
        AllocateSupplyCommand,
        PlanReplenishmentCommand,
        ReleaseWarehouseCommand,
        DispatchShipmentCommand,
        RecordCustodyTransferCommand,
        RecordDeliveryCommand,
        OpenShipmentExceptionCommand,
        ResolveShipmentExceptionCommand,
        MarkExecutionInDoubtCommand,
        ResolveExecutionInDoubtCommand,
        CloseExecutionCommand,
    ],
    Field(discriminator="kind"),
]

_SUPPLY_CHAIN_COMMAND_ADAPTER = TypeAdapter(SupplyChainCommand)


def supply_chain_command_digest(command: SupplyChainCommand | Mapping[str, Any]) -> str:
    parsed = _SUPPLY_CHAIN_COMMAND_ADAPTER.validate_python(command)
    payload = parsed.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload.pop("approval", None)
    return _stable_digest(payload)


def supply_chain_idempotency_digest(
    scope: SupplyChainExecutionScope | Mapping[str, Any],
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    lifecycle_ref = _visible(lifecycle_ref, name="lifecycle_ref")
    idempotency_key = _visible(idempotency_key, name="idempotency_key")
    return _stable_digest(
        {
            "scope_digest": supply_chain_scope_digest(scope),
            "lifecycle_ref": lifecycle_ref,
            "idempotency_key": idempotency_key,
        }
    )


def supply_chain_fact_evidence_digest(
    scope: SupplyChainExecutionScope | Mapping[str, Any],
    lifecycle_ref: str,
    transition_ref: str,
    command: SupplyChainCommand | Mapping[str, Any],
) -> str:
    parsed_command = _SUPPLY_CHAIN_COMMAND_ADAPTER.validate_python(command)
    return _stable_digest(
        {
            "scope_digest": supply_chain_scope_digest(scope),
            "lifecycle_ref": lifecycle_ref,
            "transition_ref": transition_ref,
            "command_digest": supply_chain_command_digest(parsed_command),
            "fact_subject_ref": _fact_subject(parsed_command),
        }
    )


def _actor_for(command: SupplyChainCommand) -> str:
    for name in (
        "planner_ref",
        "submitted_by_ref",
        "allocator_ref",
        "warehouse_operator_ref",
        "dispatcher_ref",
        "recorder_ref",
        "reporter_ref",
        "resolver_ref",
        "detector_ref",
        "reconciler_ref",
        "closer_ref",
    ):
        value = getattr(command, name, None)
        if value is not None:
            return str(value)
    raise AssertionError("command actor is missing")


_REQUIRED_APPROVAL: dict[str, ApprovalRole] = {
    "approve_sop": "sop_authorizer",
    "allocate_supply": "allocation_authorizer",
    "plan_replenishment": "replenishment_authorizer",
    "release_warehouse": "warehouse_authorizer",
    "dispatch_shipment": "transport_authorizer",
    "resolve_shipment_exception": "exception_authorizer",
    "resolve_execution_in_doubt": "recovery_authorizer",
    "close_execution": "closure_authorizer",
}

_CAUSAL_SOD_COMMAND_KINDS: dict[str, frozenset[str]] = {
    "approve_sop": frozenset({"project_demand_forecast"}),
    "allocate_supply": frozenset({"record_mrp_supply_plan"}),
    "plan_replenishment": frozenset({"record_mrp_supply_plan", "allocate_supply"}),
    "release_warehouse": frozenset({"allocate_supply", "plan_replenishment"}),
    "dispatch_shipment": frozenset({"release_warehouse"}),
    "resolve_shipment_exception": frozenset({"open_shipment_exception"}),
    "resolve_execution_in_doubt": frozenset({"mark_execution_in_doubt"}),
    "close_execution": frozenset({"record_delivery", "resolve_shipment_exception"}),
}


_FACT_EVIDENCE_KIND: dict[str, str] = {
    "project_demand_forecast": "demand_forecast_attestation",
    "record_mrp_supply_plan": "mrp_supply_plan_attestation",
    "release_warehouse": "warehouse_release_attestation",
    "dispatch_shipment": "shipment_dispatch_attestation",
    "record_custody_transfer": "custody_transfer_attestation",
    "record_delivery": "delivery_attestation",
    "open_shipment_exception": "shipment_exception_attestation",
    "resolve_shipment_exception": "exception_resolution_attestation",
    "mark_execution_in_doubt": "execution_ambiguity_attestation",
    "resolve_execution_in_doubt": "execution_recovery_attestation",
}


def _fact_subject(command: SupplyChainCommand) -> str:
    field_by_kind = {
        "project_demand_forecast": "forecast_ref",
        "record_mrp_supply_plan": "mrp_run_ref",
        "release_warehouse": "warehouse_release_ref",
        "dispatch_shipment": "shipment_ref",
        "record_custody_transfer": "custody_event_ref",
        "record_delivery": "delivery_ref",
        "open_shipment_exception": "exception_ref",
        "resolve_shipment_exception": "resolution_ref",
        "mark_execution_in_doubt": "ambiguity_ref",
        "resolve_execution_in_doubt": "recovery_ref",
    }
    return str(getattr(command, field_by_kind[command.kind]))


def _event_time(command: SupplyChainCommand) -> str | None:
    for name in (
        "generated_at",
        "planned_at",
        "order_by",
        "released_at",
        "dispatched_at",
        "transferred_at",
        "delivered_at",
        "detected_at",
        "resolved_at",
        "closed_at",
    ):
        value = getattr(command, name, None)
        if value is not None:
            return str(value)
    return None


class SupplyChainCustodyProjection(_StrictModel):
    custody_event_ref: str = Field(min_length=1, max_length=160)
    sequence: int = Field(ge=1, le=MAX_CUSTODY_EVENTS)
    from_custodian_ref: str = Field(min_length=1, max_length=160)
    to_custodian_ref: str = Field(min_length=1, max_length=160)
    transferred_at: str

    @field_validator("transferred_at")
    @classmethod
    def _transferred_at(cls, value: str) -> str:
        return _utc(value, name="transferred_at")


def _content_payload(
    *,
    scope_digest: str,
    lifecycle_ref: str,
    revision: int,
    prior_state: str | None,
    prior_state_digest: str,
    transition_ref: str,
    command_digest: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
) -> dict[str, Any]:
    return {
        "scope_digest": scope_digest,
        "lifecycle_ref": lifecycle_ref,
        "revision": revision,
        "prior_state": prior_state,
        "prior_state_digest": prior_state_digest,
        "transition_ref": transition_ref,
        "command_digest": command_digest,
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": requested_by_ref,
        "proposed_at": proposed_at,
    }


class SupplyChainTransitionRecord(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_transition_record.v1"] = Field(
        default=SUPPLY_CHAIN_TRANSITION_RECORD_SCHEMA, alias="schema"
    )
    revision: int = Field(ge=1, le=MAX_TRANSITIONS)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    transition_ref: str = Field(min_length=1, max_length=160)
    prior_state: SupplyChainState | None = None
    prior_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    command: SupplyChainCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    evidence_refs: list[SupplyChainExecutionEvidence] = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_PER_TRANSITION,
    )
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_approver_role: ApprovalRole | None = None
    approval_ref: str | None = Field(default=None, min_length=1, max_length=200)
    approval_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    authoritative_state_changed: Literal[False]
    optimizer_executed: Literal[False]
    inventory_write_executed: Literal[False]
    warehouse_write_executed: Literal[False]
    carrier_write_executed: Literal[False]
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "lifecycle_ref",
        "transition_ref",
        "idempotency_key",
        "requested_by_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _proposed_at(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @model_validator(mode="after")
    def _digests_match(self) -> "SupplyChainTransitionRecord":
        if self.command_digest != supply_chain_command_digest(self.command):
            raise ValueError("record command_digest does not match command")
        expected_idempotency = _stable_digest(
            {
                "scope_digest": self.scope_digest,
                "lifecycle_ref": self.lifecycle_ref,
                "idempotency_key": self.idempotency_key,
            }
        )
        if self.idempotency_digest != expected_idempotency:
            raise ValueError("record idempotency_digest does not match its fence")
        expected_content = _stable_digest(
            _content_payload(
                scope_digest=self.scope_digest,
                lifecycle_ref=self.lifecycle_ref,
                revision=self.revision,
                prior_state=self.prior_state,
                prior_state_digest=self.prior_state_digest,
                transition_ref=self.transition_ref,
                command_digest=self.command_digest,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("record content_digest does not match transition content")
        if self.evidence_digest != _stable_digest(self.evidence_refs):
            raise ValueError("record evidence_digest does not match evidence")
        required = _REQUIRED_APPROVAL.get(self.command.kind)
        if self.required_approver_role != required:
            raise ValueError("record required_approver_role is inconsistent")
        approval = self.command.approval
        if required is None:
            if (
                approval is not None
                or self.approval_ref is not None
                or self.approval_digest is not None
            ):
                raise ValueError(
                    "non-approved transition cannot contain approval metadata"
                )
        elif (
            approval is None
            or self.approval_ref != approval.approval_ref
            or self.approval_digest != approval.approval_digest
        ):
            raise ValueError("record approval metadata must match command approval")
        payload = self.model_dump(
            mode="json", by_alias=True, exclude_none=True, exclude={"transition_digest"}
        )
        if self.transition_digest != _stable_digest(payload):
            raise ValueError("record transition_digest does not match transition")
        return self


class SupplyChainExecutionSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_snapshot.v1"] = Field(
        default=SUPPLY_CHAIN_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: SupplyChainExecutionScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    revision: int = Field(ge=1, le=MAX_TRANSITIONS)
    state: SupplyChainState
    forecast_ref: str | None = None
    forecast_quantity: Decimal | None = None
    forecast_generated_at: str | None = None
    sop_plan_ref: str | None = None
    approved_quantity: Decimal | None = None
    mrp_run_ref: str | None = None
    opening_on_hand_quantity: Decimal | None = None
    confirmed_inbound_quantity: Decimal | None = None
    planned_production_quantity: Decimal | None = None
    safety_stock_quantity: Decimal | None = None
    required_replenishment_quantity: Decimal | None = None
    allocation_ref: str | None = None
    allocation_quantity: Decimal | None = None
    replenishment_ref: str | None = None
    replenishment_quantity: Decimal | None = None
    replenishment_status: Literal["planned", "not_required"] | None = None
    replenishment_expected_receipt_at: str | None = None
    supplier_ref: str | None = None
    warehouse_release_ref: str | None = None
    release_quantity: Decimal | None = None
    released_at: str | None = None
    shipment_ref: str | None = None
    shipment_quantity: Decimal | None = None
    carrier_ref: str | None = None
    dispatched_at: str | None = None
    current_custodian_ref: str | None = None
    custody_events: list[SupplyChainCustodyProjection] = Field(
        default_factory=list, max_length=MAX_CUSTODY_EVENTS
    )
    delivery_ref: str | None = None
    delivered_quantity: Decimal | None = None
    delivered_at: str | None = None
    exception_ref: str | None = None
    exception_deadline_at: str | None = None
    exception_detected_at: str | None = None
    exception_category: str | None = None
    exception_severity: str | None = None
    resolution_ref: str | None = None
    resolved_at: str | None = None
    resolution_outcome: str | None = None
    in_doubt_from_state: SupplyChainState | None = None
    ambiguity_ref: str | None = None
    ambiguous_operation_ref: str | None = None
    ambiguity_detected_at: str | None = None
    ambiguity_deadline_at: str | None = None
    recovery_ref: str | None = None
    recovery_outcome: str | None = None
    closure_ref: str | None = None
    closed_at: str | None = None
    transition_history: list[SupplyChainTransitionRecord] = Field(
        min_length=1, max_length=MAX_TRANSITIONS
    )
    state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref")
    @classmethod
    def _exact_lifecycle_ref(cls, value: str) -> str:
        return _visible(value, name="lifecycle_ref")

    @field_validator(
        "forecast_quantity",
        "approved_quantity",
        "opening_on_hand_quantity",
        "confirmed_inbound_quantity",
        "planned_production_quantity",
        "safety_stock_quantity",
        "required_replenishment_quantity",
        "allocation_quantity",
        "replenishment_quantity",
        "release_quantity",
        "shipment_quantity",
        "delivered_quantity",
        mode="before",
    )
    @classmethod
    def _canonical_snapshot_quantity(cls, value: Any) -> Decimal | None:
        return None if value is None else _quantity(value)

    @model_validator(mode="after")
    def _semantic_replay_matches(self) -> "SupplyChainExecutionSnapshot":
        if self.scope_digest != supply_chain_scope_digest(self.scope):
            raise ValueError("snapshot scope_digest does not match scope")
        projection = _replay_history(
            self.scope,
            self.lifecycle_ref,
            self.transition_history,
        )
        expected_payload = _snapshot_payload(
            self.scope,
            self.lifecycle_ref,
            self.transition_history,
            projection,
        )
        expected_digest = _stable_digest(expected_payload)
        if self.state_digest != expected_digest:
            raise ValueError("snapshot state_digest does not match replayed state")
        expected_payload["state_digest"] = expected_digest
        actual = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        expected = SupplyChainExecutionSnapshot.model_construct(
            **expected_payload
        ).model_dump(mode="json", by_alias=True, exclude_none=True)
        if actual != expected:
            raise ValueError("snapshot fields do not match semantic history replay")
        return self


def _empty_projection() -> dict[str, Any]:
    return {
        "state": None,
        "forecast_ref": None,
        "forecast_quantity": None,
        "forecast_generated_at": None,
        "sop_plan_ref": None,
        "approved_quantity": None,
        "mrp_run_ref": None,
        "opening_on_hand_quantity": None,
        "confirmed_inbound_quantity": None,
        "planned_production_quantity": None,
        "safety_stock_quantity": None,
        "required_replenishment_quantity": None,
        "allocation_ref": None,
        "allocation_quantity": None,
        "replenishment_ref": None,
        "replenishment_quantity": None,
        "replenishment_status": None,
        "replenishment_expected_receipt_at": None,
        "supplier_ref": None,
        "warehouse_release_ref": None,
        "release_quantity": None,
        "released_at": None,
        "shipment_ref": None,
        "shipment_quantity": None,
        "carrier_ref": None,
        "dispatched_at": None,
        "current_custodian_ref": None,
        "custody_events": [],
        "delivery_ref": None,
        "delivered_quantity": None,
        "delivered_at": None,
        "exception_ref": None,
        "exception_deadline_at": None,
        "exception_detected_at": None,
        "exception_category": None,
        "exception_severity": None,
        "resolution_ref": None,
        "resolved_at": None,
        "resolution_outcome": None,
        "in_doubt_from_state": None,
        "ambiguity_ref": None,
        "ambiguous_operation_ref": None,
        "ambiguity_detected_at": None,
        "ambiguity_deadline_at": None,
        "recovery_ref": None,
        "recovery_outcome": None,
        "closure_ref": None,
        "closed_at": None,
    }


def _fail(code: str, message: str) -> None:
    raise SupplyChainExecutionError(code, message)


def _assert_scope(
    command: SupplyChainCommand, scope: SupplyChainExecutionScope
) -> None:
    for name, expected in (
        ("planning_cycle_ref", scope.planning_cycle_ref),
        ("item_ref", scope.item_ref),
        ("source_location_ref", scope.source_location_ref),
        ("destination_location_ref", scope.destination_location_ref),
        ("unit_of_measure", scope.unit_of_measure),
    ):
        value = getattr(command, name, None)
        if value is not None and value != expected:
            _fail(
                "scope_mismatch", f"command {name} does not match exact lifecycle scope"
            )


def _at_or_before(value: str, cutoff: str, *, field: str) -> None:
    if _dt(value) > _dt(cutoff):
        _fail("future_event", f"{field} cannot be after proposed_at")


def _after(value: str, lower: str | None, *, field: str) -> None:
    if lower is not None and _dt(value) < _dt(lower):
        _fail("stale_event", f"{field} cannot precede its causal predecessor")


def _apply_command(
    scope: SupplyChainExecutionScope,
    projection: Mapping[str, Any],
    command: SupplyChainCommand,
    proposed_at: str,
    causal_not_before: str | None = None,
) -> dict[str, Any]:
    result = dict(projection)
    result["custody_events"] = list(projection.get("custody_events") or [])
    _assert_scope(command, scope)
    event_time = _event_time(command)
    if event_time is not None:
        _after(event_time, causal_not_before, field="command event time")
    state = projection.get("state")

    if isinstance(command, ProjectDemandForecastCommand):
        if state is not None:
            _fail(
                "forecast_already_projected",
                "demand forecast may be projected only once",
            )
        _at_or_before(command.generated_at, proposed_at, field="generated_at")
        result.update(
            state="forecast_projected",
            forecast_ref=command.forecast_ref,
            forecast_quantity=command.forecast_quantity,
            forecast_generated_at=command.generated_at,
        )
    elif isinstance(command, ApproveSopCommand):
        if state != "forecast_projected":
            _fail("invalid_transition", "S&OP approval requires a projected forecast")
        if command.forecast_ref != projection["forecast_ref"]:
            _fail("artifact_mismatch", "S&OP approval must bind the exact forecast")
        if command.approved_quantity != projection["forecast_quantity"]:
            _fail(
                "quantity_mismatch",
                "S&OP approval must bind the exact forecast quantity",
            )
        result.update(
            state="sop_approved",
            sop_plan_ref=command.sop_plan_ref,
            approved_quantity=command.approved_quantity,
        )
    elif isinstance(command, RecordMrpSupplyPlanCommand):
        if state != "sop_approved":
            _fail("invalid_transition", "MRP plan requires S&OP approval")
        if command.sop_plan_ref != projection["sop_plan_ref"]:
            _fail("artifact_mismatch", "MRP plan must bind the exact S&OP plan")
        if command.approved_demand_quantity != projection["approved_quantity"]:
            _fail("quantity_mismatch", "MRP demand must equal approved S&OP quantity")
        _at_or_before(command.planned_at, proposed_at, field="planned_at")
        _after(
            command.planned_at, projection["forecast_generated_at"], field="planned_at"
        )
        result.update(
            state="mrp_planned",
            mrp_run_ref=command.mrp_run_ref,
            opening_on_hand_quantity=command.opening_on_hand_quantity,
            confirmed_inbound_quantity=command.confirmed_inbound_quantity,
            planned_production_quantity=command.planned_production_quantity,
            safety_stock_quantity=command.safety_stock_quantity,
            required_replenishment_quantity=command.required_replenishment_quantity,
        )
    elif isinstance(command, AllocateSupplyCommand):
        if state != "mrp_planned":
            _fail("invalid_transition", "allocation requires an MRP supply plan")
        if command.mrp_run_ref != projection["mrp_run_ref"]:
            _fail("artifact_mismatch", "allocation must bind the exact MRP run")
        available = (
            projection["opening_on_hand_quantity"]
            + projection["confirmed_inbound_quantity"]
            + projection["planned_production_quantity"]
            + projection["required_replenishment_quantity"]
            - projection["safety_stock_quantity"]
        )
        if (
            command.allocation_quantity != projection["approved_quantity"]
            or command.allocation_quantity > available
        ):
            _fail(
                "allocation_quantity_mismatch",
                "allocation must exactly cover approved demand within supply",
            )
        result.update(
            state="allocated",
            allocation_ref=command.allocation_ref,
            allocation_quantity=command.allocation_quantity,
        )
    elif isinstance(command, PlanReplenishmentCommand):
        if state != "allocated":
            _fail("invalid_transition", "replenishment planning requires allocation")
        if (
            command.mrp_run_ref != projection["mrp_run_ref"]
            or command.allocation_ref != projection["allocation_ref"]
        ):
            _fail(
                "artifact_mismatch",
                "replenishment must bind exact MRP and allocation artifacts",
            )
        if (
            command.replenishment_quantity
            != projection["required_replenishment_quantity"]
        ):
            _fail(
                "replenishment_quantity_mismatch",
                "replenishment must equal deterministic MRP shortfall",
            )
        _at_or_before(command.order_by, proposed_at, field="order_by")
        result.update(
            state="replenishment_planned",
            replenishment_ref=command.replenishment_ref,
            replenishment_quantity=command.replenishment_quantity,
            replenishment_status=command.status,
            replenishment_expected_receipt_at=command.expected_receipt_at,
            supplier_ref=command.supplier_ref,
        )
    elif isinstance(command, ReleaseWarehouseCommand):
        if state != "replenishment_planned":
            _fail(
                "invalid_transition",
                "warehouse release requires replenishment disposition",
            )
        if command.allocation_ref != projection["allocation_ref"]:
            _fail("artifact_mismatch", "warehouse release must bind exact allocation")
        if command.release_quantity != projection["allocation_quantity"]:
            _fail(
                "release_quantity_mismatch",
                "warehouse release must equal allocated quantity",
            )
        _at_or_before(command.released_at, proposed_at, field="released_at")
        if projection["replenishment_quantity"] > 0 and _dt(command.released_at) < _dt(
            projection["replenishment_expected_receipt_at"]
        ):
            _fail(
                "replenishment_not_receivable",
                "warehouse release cannot precede the planned replenishment receipt",
            )
        result.update(
            state="warehouse_released",
            warehouse_release_ref=command.warehouse_release_ref,
            release_quantity=command.release_quantity,
            released_at=command.released_at,
        )
    elif isinstance(command, DispatchShipmentCommand):
        if state != "warehouse_released":
            _fail(
                "duplicate_or_invalid_shipment",
                "shipment dispatch requires one unreconciled warehouse release",
            )
        if command.warehouse_release_ref != projection["warehouse_release_ref"]:
            _fail("artifact_mismatch", "shipment must bind exact warehouse release")
        if command.shipment_quantity != projection["release_quantity"]:
            _fail(
                "shipment_quantity_mismatch",
                "shipment quantity must equal warehouse release",
            )
        if (
            command.from_custodian_ref != scope.source_location_ref
            or command.to_custodian_ref != command.carrier_ref
        ):
            _fail(
                "custody_mismatch",
                "dispatch custody must transfer from source location to carrier",
            )
        _at_or_before(command.dispatched_at, proposed_at, field="dispatched_at")
        _after(command.dispatched_at, projection["released_at"], field="dispatched_at")
        event = SupplyChainCustodyProjection(
            custody_event_ref=command.custody_event_ref,
            sequence=1,
            from_custodian_ref=command.from_custodian_ref,
            to_custodian_ref=command.to_custodian_ref,
            transferred_at=command.dispatched_at,
        )
        result.update(
            state="in_transit",
            shipment_ref=command.shipment_ref,
            shipment_quantity=command.shipment_quantity,
            carrier_ref=command.carrier_ref,
            dispatched_at=command.dispatched_at,
            current_custodian_ref=command.to_custodian_ref,
            custody_events=[event],
        )
    elif isinstance(command, RecordCustodyTransferCommand):
        if state != "in_transit":
            _fail(
                "invalid_transition", "custody transfer requires an in-transit shipment"
            )
        events = list(projection["custody_events"])
        if command.shipment_ref != projection["shipment_ref"]:
            _fail("artifact_mismatch", "custody transfer must bind exact shipment")
        if (
            command.sequence != len(events) + 1
            or command.from_custodian_ref != projection["current_custodian_ref"]
            or any(
                event.custody_event_ref == command.custody_event_ref for event in events
            )
        ):
            _fail(
                "custody_chain_mismatch",
                "custody sequence, holder, and event reference must extend the exact chain",
            )
        _at_or_before(command.transferred_at, proposed_at, field="transferred_at")
        _after(
            command.transferred_at, events[-1].transferred_at, field="transferred_at"
        )
        events.append(
            SupplyChainCustodyProjection(
                custody_event_ref=command.custody_event_ref,
                sequence=command.sequence,
                from_custodian_ref=command.from_custodian_ref,
                to_custodian_ref=command.to_custodian_ref,
                transferred_at=command.transferred_at,
            )
        )
        result.update(
            current_custodian_ref=command.to_custodian_ref, custody_events=events
        )
    elif isinstance(command, RecordDeliveryCommand):
        if state != "in_transit":
            _fail(
                "duplicate_or_invalid_delivery",
                "delivery requires one in-transit shipment",
            )
        if command.shipment_ref != projection["shipment_ref"]:
            _fail("artifact_mismatch", "delivery must bind exact shipment")
        if command.delivered_quantity != projection["shipment_quantity"]:
            _fail(
                "delivery_quantity_mismatch",
                "delivery quantity must equal shipment quantity",
            )
        if command.receiving_custodian_ref != scope.destination_location_ref:
            _fail(
                "custody_mismatch",
                "delivery custody must end at exact destination location",
            )
        _at_or_before(command.delivered_at, proposed_at, field="delivered_at")
        _after(
            command.delivered_at,
            projection["custody_events"][-1].transferred_at,
            field="delivered_at",
        )
        events = list(projection["custody_events"])
        if projection["current_custodian_ref"] != command.receiving_custodian_ref:
            if len(events) >= MAX_CUSTODY_EVENTS:
                _fail(
                    "custody_chain_limit_reached",
                    "delivery cannot extend a custody chain at its bounded limit",
                )
            events.append(
                SupplyChainCustodyProjection(
                    custody_event_ref=command.delivery_ref,
                    sequence=len(events) + 1,
                    from_custodian_ref=projection["current_custodian_ref"],
                    to_custodian_ref=command.receiving_custodian_ref,
                    transferred_at=command.delivered_at,
                )
            )
        result.update(
            state="delivered",
            delivery_ref=command.delivery_ref,
            delivered_quantity=command.delivered_quantity,
            delivered_at=command.delivered_at,
            current_custodian_ref=command.receiving_custodian_ref,
            custody_events=events,
        )
    elif isinstance(command, OpenShipmentExceptionCommand):
        if state != "in_transit":
            _fail(
                "invalid_transition",
                "shipment exception requires an in-transit shipment",
            )
        if command.shipment_ref != projection["shipment_ref"]:
            _fail("artifact_mismatch", "exception must bind exact shipment")
        _at_or_before(command.detected_at, proposed_at, field="detected_at")
        _after(
            command.detected_at,
            projection["custody_events"][-1].transferred_at,
            field="detected_at",
        )
        if _dt(proposed_at) > _dt(command.response_deadline_at):
            _fail(
                "exception_deadline_missed",
                "an already-expired shipment exception cannot be projected as open",
            )
        result.update(
            state="exception_open",
            exception_ref=command.exception_ref,
            exception_detected_at=command.detected_at,
            exception_deadline_at=command.response_deadline_at,
            exception_category=command.category,
            exception_severity=command.severity,
            resolution_ref=None,
            resolved_at=None,
            resolution_outcome=None,
        )
    elif isinstance(command, ResolveShipmentExceptionCommand):
        if state != "exception_open":
            _fail(
                "invalid_transition", "exception resolution requires one open exception"
            )
        if command.exception_ref != projection["exception_ref"]:
            _fail("artifact_mismatch", "resolution must bind exact exception")
        _at_or_before(command.resolved_at, proposed_at, field="resolved_at")
        _after(
            command.resolved_at,
            projection["exception_detected_at"],
            field="resolved_at",
        )
        if _dt(command.resolved_at) > _dt(projection["exception_deadline_at"]):
            _fail(
                "exception_deadline_missed",
                "exception resolution cannot assert timely closure after its deadline",
            )
        result.update(
            state=(
                "in_transit"
                if command.outcome == "redelivery_planned"
                else "exception_resolved"
            ),
            resolution_ref=command.resolution_ref,
            resolved_at=command.resolved_at,
            resolution_outcome=command.outcome,
        )
    elif isinstance(command, MarkExecutionInDoubtCommand):
        if state not in {"warehouse_released", "in_transit", "exception_open"}:
            _fail(
                "invalid_transition",
                "in-doubt recovery is bounded to released, transit, or exception execution",
            )
        _at_or_before(command.detected_at, proposed_at, field="detected_at")
        if _dt(proposed_at) > _dt(command.resolution_deadline_at):
            _fail(
                "recovery_deadline_missed",
                "an already-expired execution ambiguity cannot be projected as in doubt",
            )
        result.update(
            state="in_doubt",
            in_doubt_from_state=state,
            ambiguity_ref=command.ambiguity_ref,
            ambiguous_operation_ref=command.ambiguous_operation_ref,
            ambiguity_detected_at=command.detected_at,
            ambiguity_deadline_at=command.resolution_deadline_at,
            recovery_ref=None,
            recovery_outcome=None,
        )
    elif isinstance(command, ResolveExecutionInDoubtCommand):
        if state != "in_doubt":
            _fail(
                "invalid_transition",
                "recovery resolution requires an in-doubt projection",
            )
        if command.ambiguity_ref != projection["ambiguity_ref"]:
            _fail("artifact_mismatch", "recovery must bind the exact ambiguity")
        _at_or_before(command.resolved_at, proposed_at, field="resolved_at")
        _after(
            command.resolved_at,
            projection["ambiguity_detected_at"],
            field="resolved_at",
        )
        if _dt(command.resolved_at) > _dt(projection["ambiguity_deadline_at"]):
            _fail("recovery_deadline_missed", "in-doubt recovery deadline was missed")
        result.update(
            state=projection["in_doubt_from_state"],
            in_doubt_from_state=None,
            ambiguity_ref=None,
            ambiguous_operation_ref=None,
            ambiguity_detected_at=None,
            ambiguity_deadline_at=None,
            recovery_ref=command.recovery_ref,
            recovery_outcome=command.outcome,
        )
    elif isinstance(command, CloseExecutionCommand):
        if state not in {"delivered", "exception_resolved"}:
            _fail(
                "invalid_transition",
                "closure requires verified delivery or exception resolution",
            )
        causal_time = (
            projection["delivered_at"]
            if state == "delivered"
            else projection["resolved_at"]
        )
        _at_or_before(command.closed_at, proposed_at, field="closed_at")
        _after(command.closed_at, causal_time, field="closed_at")
        result.update(
            state="closed",
            closure_ref=command.closure_ref,
            closed_at=command.closed_at,
        )
    else:  # pragma: no cover - discriminated union is exhaustive
        raise AssertionError("unsupported command")
    return result


def _snapshot_payload(
    scope: SupplyChainExecutionScope,
    lifecycle_ref: str,
    history: Sequence[SupplyChainTransitionRecord],
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": SUPPLY_CHAIN_SNAPSHOT_SCHEMA,
        "scope": scope,
        "scope_digest": supply_chain_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        "revision": len(history),
        **{key: value for key, value in projection.items() if value is not None},
        "transition_history": list(history),
    }


def _partial_snapshot_digest(
    scope: SupplyChainExecutionScope,
    lifecycle_ref: str,
    history: Sequence[SupplyChainTransitionRecord],
    projection: Mapping[str, Any],
) -> str:
    if not history:
        return ZERO_DIGEST
    return _stable_digest(_snapshot_payload(scope, lifecycle_ref, history, projection))


def supply_chain_snapshot_digest(snapshot: SupplyChainExecutionSnapshot) -> str:
    projection = _replay_history(
        snapshot.scope,
        snapshot.lifecycle_ref,
        snapshot.transition_history,
    )
    return _stable_digest(
        _snapshot_payload(
            snapshot.scope,
            snapshot.lifecycle_ref,
            snapshot.transition_history,
            projection,
        )
    )


def _approval_and_evidence_valid(
    *,
    scope: SupplyChainExecutionScope,
    lifecycle_ref: str,
    revision: int,
    prior_state_digest: str,
    transition_ref: str,
    idempotency_digest: str,
    command: SupplyChainCommand,
    requested_by_ref: str,
    proposed_at: str,
    evidence_refs: Sequence[SupplyChainExecutionEvidence],
    expected_commitment_digest: str,
    causal_not_before: str | None,
    prior_history: Sequence[SupplyChainTransitionRecord],
) -> None:
    refs = [evidence.evidence_ref for evidence in evidence_refs]
    if len(refs) != len(set(refs)):
        _fail("duplicate_evidence", "transition evidence references must be unique")
    cutoff = _dt(proposed_at)
    for evidence in evidence_refs:
        if (
            evidence.causal_revision != revision - 1
            or evidence.causal_state_digest != prior_state_digest
        ):
            _fail(
                "stale_evidence",
                "evidence causal revision and state digest must match the exact fence",
            )
        observed = _dt(evidence.observed_at)
        if observed > cutoff or cutoff - observed > MAX_EVIDENCE_AGE:
            _fail(
                "stale_evidence",
                "evidence must be observed no later than proposed_at and within seven days",
            )
        if causal_not_before is not None and observed < _dt(causal_not_before):
            _fail(
                "evidence_causality_mismatch",
                "evidence observation cannot predate the prior transition",
            )
    commitments = [
        evidence
        for evidence in evidence_refs
        if evidence.kind == "supply_chain_transition_commitment"
    ]
    if len(commitments) != 1:
        _fail(
            "missing_transition_commitment",
            "exactly one transition commitment is required",
        )
    commitment = commitments[0]
    if (
        commitment.subject_ref != transition_ref
        or commitment.sha256 != expected_commitment_digest
        or commitment.effective_at != commitment.observed_at
    ):
        _fail(
            "transition_commitment_mismatch",
            "transition commitment must bind exact request content",
        )

    fact_kind = _FACT_EVIDENCE_KIND.get(command.kind)
    allowed_kinds = {"supply_chain_transition_commitment"}
    if fact_kind is not None:
        allowed_kinds.add(fact_kind)
        facts = [evidence for evidence in evidence_refs if evidence.kind == fact_kind]
        if len(facts) != 1:
            _fail("missing_fact_evidence", f"exactly one {fact_kind} is required")
        fact = facts[0]
        minimum_grade = (
            "attested"
            if command.kind
            in {
                "project_demand_forecast",
                "record_mrp_supply_plan",
            }
            else "verified"
        )
        grade_rank = {"attested": 1, "verified": 2}
        if (
            fact.subject_ref != _fact_subject(command)
            or fact.sha256
            != supply_chain_fact_evidence_digest(
                scope,
                lifecycle_ref,
                transition_ref,
                command,
            )
            or grade_rank[fact.verification_grade] < grade_rank[minimum_grade]
        ):
            _fail(
                "fact_evidence_mismatch",
                "fact evidence must bind the exact artifact, command, and grade",
            )
        event_time = _event_time(command)
        if event_time is not None and (
            fact.effective_at != event_time or _dt(fact.observed_at) < _dt(event_time)
        ):
            _fail(
                "evidence_chronology_mismatch",
                "fact evidence must become effective at, and cannot predate, the exact event",
            )
    if {evidence.kind for evidence in evidence_refs} != allowed_kinds:
        _fail(
            "unexpected_evidence",
            "transition contains an unexpected or duplicate evidence purpose",
        )

    required_role = _REQUIRED_APPROVAL.get(command.kind)
    approval = command.approval
    if required_role is None:
        if approval is not None:
            _fail(
                "unexpected_approval",
                "this observational transition cannot consume approval",
            )
        return
    if approval is None:
        _fail("approval_required", f"{required_role} approval is required")
    assert approval is not None
    if (
        approval.scope_digest != supply_chain_scope_digest(scope)
        or approval.lifecycle_ref != lifecycle_ref
        or approval.transition_ref != transition_ref
        or approval.command_digest != supply_chain_command_digest(command)
        or approval.idempotency_digest != idempotency_digest
        or approval.approver_role != required_role
    ):
        _fail(
            "approval_binding_mismatch",
            "approval does not bind exact scope, transition, command, role, and idempotency fence",
        )
    causal_kinds = _CAUSAL_SOD_COMMAND_KINDS.get(command.kind, frozenset())
    causal_actors = {
        actor_ref
        for record in prior_history
        if record.command.kind in causal_kinds
        for actor_ref in (record.requested_by_ref, _actor_for(record.command))
    }
    forbidden_approvers = {
        requested_by_ref,
        _actor_for(command),
    } | causal_actors
    if approval.approved_by_ref in forbidden_approvers:
        _fail(
            "segregation_of_duties_violation",
            "approver must be independent from requester, command actor, and causal artifact actors",
        )
    if not (_dt(approval.approved_at) <= cutoff <= _dt(approval.expires_at)):
        _fail(
            "approval_stale", "approval must be effective and unexpired at proposed_at"
        )
    if causal_not_before is not None and _dt(approval.approved_at) < _dt(
        causal_not_before
    ):
        _fail(
            "approval_causality_mismatch",
            "approval cannot predate the state it authorizes",
        )
    command_event_time = _event_time(command)
    if command_event_time is not None and not (
        _dt(approval.approved_at) <= _dt(command_event_time) <= _dt(approval.expires_at)
    ):
        _fail(
            "approval_event_fence_mismatch",
            "consequential event must occur within its approval window",
        )
    approval_evidence = approval.evidence
    if (
        approval_evidence.causal_revision != revision - 1
        or approval_evidence.causal_state_digest != prior_state_digest
        or _dt(approval_evidence.observed_at) > cutoff
    ):
        _fail(
            "approval_evidence_stale",
            "approval evidence must bind the exact prior fence and chronology",
        )


def _replay_history(
    scope: SupplyChainExecutionScope,
    lifecycle_ref: str,
    history: Sequence[SupplyChainTransitionRecord],
) -> dict[str, Any]:
    projection = _empty_projection()
    prior: list[SupplyChainTransitionRecord] = []
    transition_refs: set[str] = set()
    idempotency_digests: set[str] = set()
    evidence_refs: set[str] = set()
    approval_refs: set[str] = set()
    artifact_refs: set[str] = set()
    last_proposed_at: str | None = None
    for expected_revision, record in enumerate(history, start=1):
        prior_digest = _partial_snapshot_digest(scope, lifecycle_ref, prior, projection)
        if (
            record.revision != expected_revision
            or record.scope_digest != supply_chain_scope_digest(scope)
            or record.lifecycle_ref != lifecycle_ref
            or record.prior_state != projection["state"]
            or record.prior_state_digest != prior_digest
        ):
            _fail(
                "history_fence_mismatch",
                "history revision, scope, lifecycle, prior state, and digest must replay exactly",
            )
        if last_proposed_at is not None and _dt(record.proposed_at) < _dt(
            last_proposed_at
        ):
            _fail(
                "history_chronology_mismatch",
                "history proposed_at values must be monotonic",
            )
        if (
            record.transition_ref in transition_refs
            or record.idempotency_digest in idempotency_digests
        ):
            _fail(
                "duplicate_history_fence",
                "history transition and idempotency fences must be unique",
            )
        current_artifacts = _created_artifact_refs(record.command)
        if (
            len(current_artifacts) != len(set(current_artifacts))
            or set(current_artifacts) & artifact_refs
        ):
            _fail(
                "duplicate_artifact",
                "history lifecycle artifacts must be globally unique",
            )
        current_evidence = {evidence.evidence_ref for evidence in record.evidence_refs}
        if current_evidence & evidence_refs:
            _fail(
                "evidence_reuse", "single-use transition evidence cannot appear twice"
            )
        approval = record.command.approval
        if approval is not None:
            if (
                approval.approval_ref in approval_refs
                or approval.evidence.evidence_ref in evidence_refs
                or approval.evidence.evidence_ref in current_evidence
            ):
                _fail(
                    "approval_reuse", "single-use approval evidence cannot appear twice"
                )
            approval_refs.add(approval.approval_ref)
            evidence_refs.add(approval.evidence.evidence_ref)
        expected_commitment = _stable_digest(
            {
                "content_digest": record.content_digest,
                "approval_digest": record.approval_digest,
            }
        )
        _approval_and_evidence_valid(
            scope=scope,
            lifecycle_ref=lifecycle_ref,
            revision=expected_revision,
            prior_state_digest=prior_digest,
            transition_ref=record.transition_ref,
            idempotency_digest=record.idempotency_digest,
            command=record.command,
            requested_by_ref=record.requested_by_ref,
            proposed_at=record.proposed_at,
            evidence_refs=record.evidence_refs,
            expected_commitment_digest=expected_commitment,
            causal_not_before=last_proposed_at,
            prior_history=prior,
        )
        projection = _apply_command(
            scope,
            projection,
            record.command,
            record.proposed_at,
            causal_not_before=last_proposed_at,
        )
        transition_refs.add(record.transition_ref)
        idempotency_digests.add(record.idempotency_digest)
        artifact_refs.update(current_artifacts)
        evidence_refs.update(current_evidence)
        prior.append(record)
        last_proposed_at = record.proposed_at
    return projection


class SupplyChainTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_request.v1"] = Field(
        default=SUPPLY_CHAIN_REQUEST_SCHEMA,
        alias="schema",
    )
    scope: SupplyChainExecutionScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    expected_revision: int = Field(ge=0, lt=MAX_TRANSITIONS)
    expected_state: SupplyChainState | None = None
    expected_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_snapshot: SupplyChainExecutionSnapshot | None = None
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: SupplyChainCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_refs: list[SupplyChainExecutionEvidence] = Field(
        min_length=1,
        max_length=MAX_EVIDENCE_PER_TRANSITION,
    )

    @field_validator(
        "lifecycle_ref",
        "transition_ref",
        "idempotency_key",
        "requested_by_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _proposed_at(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @model_validator(mode="after")
    def _exact_fences_and_digests(self) -> "SupplyChainTransitionRequest":
        if self.scope_digest != supply_chain_scope_digest(self.scope):
            raise ValueError("request scope_digest does not match scope")
        if self.command_digest != supply_chain_command_digest(self.command):
            raise ValueError("request command_digest does not match command")
        if self.idempotency_digest != supply_chain_idempotency_digest(
            self.scope, self.lifecycle_ref, self.idempotency_key
        ):
            raise ValueError(
                "request idempotency_digest does not match its exact fence"
            )
        expected_content = _stable_digest(
            _content_payload(
                scope_digest=self.scope_digest,
                lifecycle_ref=self.lifecycle_ref,
                revision=self.expected_revision + 1,
                prior_state=self.expected_state,
                prior_state_digest=self.expected_state_digest,
                transition_ref=self.transition_ref,
                command_digest=self.command_digest,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("request content_digest does not match transition content")
        if self.expected_revision == 0:
            if (
                self.expected_snapshot is not None
                or self.expected_state is not None
                or self.expected_state_digest != ZERO_DIGEST
            ):
                raise ValueError(
                    "revision zero must use an empty state and zero digest"
                )
        else:
            snapshot = self.expected_snapshot
            if snapshot is None:
                raise ValueError("nonzero revision requires the exact prior snapshot")
            if (
                snapshot.scope != self.scope
                or snapshot.lifecycle_ref != self.lifecycle_ref
                or snapshot.revision != self.expected_revision
                or snapshot.state != self.expected_state
                or snapshot.state_digest != self.expected_state_digest
            ):
                raise ValueError(
                    "expected snapshot does not match exact scope and revision fence"
                )
        return self


def supply_chain_transition_content_digest(
    request: SupplyChainTransitionRequest | Mapping[str, Any],
) -> str:
    if isinstance(request, SupplyChainTransitionRequest):
        scope = request.scope
        lifecycle_ref = request.lifecycle_ref
        revision = request.expected_revision + 1
        prior_state = request.expected_state
        prior_state_digest = request.expected_state_digest
        transition_ref = request.transition_ref
        command_digest = supply_chain_command_digest(request.command)
        idempotency_digest = supply_chain_idempotency_digest(
            scope,
            lifecycle_ref,
            request.idempotency_key,
        )
        requested_by_ref = request.requested_by_ref
        proposed_at = request.proposed_at
    else:
        payload = dict(request)
        scope = SupplyChainExecutionScope.model_validate(payload["scope"])
        lifecycle_ref = _visible(payload["lifecycle_ref"], name="lifecycle_ref")
        raw_revision = payload["expected_revision"]
        if isinstance(raw_revision, bool) or not isinstance(raw_revision, int):
            raise ValueError("expected_revision must be an integer")
        revision = raw_revision + 1
        prior_state = payload.get("expected_state")
        prior_state_digest = payload["expected_state_digest"]
        if not isinstance(prior_state_digest, str):
            raise ValueError("expected_state_digest must be a string")
        transition_ref = _visible(payload["transition_ref"], name="transition_ref")
        command_digest = supply_chain_command_digest(payload["command"])
        idempotency_digest = supply_chain_idempotency_digest(
            scope,
            lifecycle_ref,
            _visible(payload["idempotency_key"], name="idempotency_key"),
        )
        requested_by_ref = _visible(
            payload["requested_by_ref"], name="requested_by_ref"
        )
        proposed_at = _utc(payload["proposed_at"], name="proposed_at")
    return _stable_digest(
        _content_payload(
            scope_digest=supply_chain_scope_digest(scope),
            lifecycle_ref=lifecycle_ref,
            revision=revision,
            prior_state=prior_state,
            prior_state_digest=prior_state_digest,
            transition_ref=transition_ref,
            command_digest=command_digest,
            idempotency_digest=idempotency_digest,
            requested_by_ref=requested_by_ref,
            proposed_at=proposed_at,
        )
    )


def supply_chain_transition_evidence_digest(
    request: SupplyChainTransitionRequest | Mapping[str, Any],
) -> str:
    if isinstance(request, SupplyChainTransitionRequest):
        content_digest = request.content_digest
        approval = request.command.approval
    else:
        payload = dict(request)
        content_digest = payload["content_digest"]
        if not isinstance(content_digest, str):
            raise ValueError("content_digest must be a string")
        command = payload.get("command") or {}
        approval = command.get("approval") if isinstance(command, Mapping) else None
    approval_digest = (
        approval.approval_digest
        if isinstance(approval, SupplyChainApprovalEvidence)
        else approval.get("approval_digest")
        if isinstance(approval, Mapping)
        else None
    )
    return _stable_digest(
        {"content_digest": content_digest, "approval_digest": approval_digest}
    )


class SupplyChainTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_proposal.v1"] = Field(
        default=SUPPLY_CHAIN_PROPOSAL_SCHEMA,
        alias="schema",
    )
    scope: SupplyChainExecutionScope
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    source_revision: int = Field(ge=0, lt=MAX_TRANSITIONS)
    source_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_revision: int = Field(ge=1, le=MAX_TRANSITIONS)
    target_state: SupplyChainState
    transition_ref: str = Field(min_length=1, max_length=160)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_approver_role: ApprovalRole | None = None
    business_approval_evidence_present: bool
    authoritative_state_changed: Literal[False]
    optimizer_executed: Literal[False]
    inventory_or_provider_write_executed: Literal[False]
    spring_submission_executed: Literal[False]
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref", "transition_ref")
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @model_validator(mode="after")
    def _proposal_digest_matches(self) -> "SupplyChainTransitionProposal":
        payload = self.model_dump(
            mode="json", by_alias=True, exclude_none=True, exclude={"proposal_digest"}
        )
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("proposal_digest does not match proposal")
        return self


class SupplyChainTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.supply_chain_execution_result.v1"] = Field(
        default=SUPPLY_CHAIN_RESULT_SCHEMA,
        alias="schema",
    )
    proposal: SupplyChainTransitionProposal
    candidate_snapshot: SupplyChainExecutionSnapshot
    authority_boundary: Literal[
        "sdk_candidate_only_spring_erp_wms_tms_authoritative"
    ] = "sdk_candidate_only_spring_erp_wms_tms_authoritative"
    recovery_semantics: Literal[
        "no_sdk_effect_manual_spring_reconciliation_for_in_doubt_provider_execution"
    ] = "no_sdk_effect_manual_spring_reconciliation_for_in_doubt_provider_execution"

    @model_validator(mode="after")
    def _candidate_matches_proposal(self) -> "SupplyChainTransitionResult":
        last_transition = self.candidate_snapshot.transition_history[-1]
        if (
            self.candidate_snapshot.scope != self.proposal.scope
            or self.candidate_snapshot.lifecycle_ref != self.proposal.lifecycle_ref
            or self.candidate_snapshot.revision != self.proposal.target_revision
            or self.candidate_snapshot.state != self.proposal.target_state
            or self.candidate_snapshot.state_digest
            != self.proposal.candidate_state_digest
        ):
            raise ValueError("proposal must identify its exact candidate snapshot")
        if (
            self.proposal.source_revision != last_transition.revision - 1
            or self.proposal.source_state_digest != last_transition.prior_state_digest
            or self.proposal.target_revision != last_transition.revision
            or self.proposal.transition_ref != last_transition.transition_ref
            or self.proposal.command_digest != last_transition.command_digest
            or self.proposal.content_digest != last_transition.content_digest
            or self.proposal.idempotency_digest != last_transition.idempotency_digest
            or self.proposal.transition_digest != last_transition.transition_digest
            or self.proposal.required_approver_role
            != last_transition.required_approver_role
            or self.proposal.business_approval_evidence_present
            is not (last_transition.command.approval is not None)
        ):
            raise ValueError(
                "proposal must bind every field of the last candidate transition"
            )
        return self


def _created_artifact_refs(command: SupplyChainCommand) -> tuple[str, ...]:
    fields_by_kind: dict[str, tuple[str, ...]] = {
        "project_demand_forecast": ("forecast_ref",),
        "approve_sop": ("sop_plan_ref",),
        "record_mrp_supply_plan": ("mrp_run_ref",),
        "allocate_supply": ("allocation_ref",),
        "plan_replenishment": ("replenishment_ref",),
        "release_warehouse": ("warehouse_release_ref",),
        "dispatch_shipment": ("shipment_ref", "custody_event_ref"),
        "record_custody_transfer": ("custody_event_ref",),
        "record_delivery": ("delivery_ref",),
        "open_shipment_exception": ("exception_ref",),
        "resolve_shipment_exception": ("resolution_ref",),
        "mark_execution_in_doubt": ("ambiguity_ref",),
        "resolve_execution_in_doubt": ("recovery_ref",),
        "close_execution": ("closure_ref",),
    }
    return tuple(str(getattr(command, field)) for field in fields_by_kind[command.kind])


def propose_supply_chain_execution_transition(
    request: SupplyChainTransitionRequest | Mapping[str, Any],
) -> SupplyChainTransitionResult:
    parsed = SupplyChainTransitionRequest.model_validate(request)
    history: list[SupplyChainTransitionRecord]
    projection: dict[str, Any]
    if parsed.expected_snapshot is None:
        history = []
        projection = _empty_projection()
    else:
        history = list(parsed.expected_snapshot.transition_history)
        projection = _replay_history(parsed.scope, parsed.lifecycle_ref, history)
    if len(history) >= MAX_TRANSITIONS:
        _fail(
            "transition_limit_reached", "lifecycle reached its bounded transition limit"
        )
    if history and _dt(parsed.proposed_at) < _dt(history[-1].proposed_at):
        _fail("stale_transition", "proposed_at cannot precede prior transition")

    prior_transition_refs = {record.transition_ref for record in history}
    prior_idempotency = {record.idempotency_digest for record in history}
    prior_evidence = {
        evidence.evidence_ref for record in history for evidence in record.evidence_refs
    }
    prior_approval_refs = {
        record.command.approval.approval_ref
        for record in history
        if record.command.approval is not None
    }
    prior_evidence.update(
        record.command.approval.evidence.evidence_ref
        for record in history
        if record.command.approval is not None
    )
    prior_artifacts = {
        artifact
        for record in history
        for artifact in _created_artifact_refs(record.command)
    }
    current_artifacts = _created_artifact_refs(parsed.command)
    if (
        len(current_artifacts) != len(set(current_artifacts))
        or set(current_artifacts) & prior_artifacts
    ):
        _fail("duplicate_artifact", "new lifecycle artifacts must be globally unique")
    if parsed.transition_ref in prior_transition_refs:
        _fail("duplicate_transition", "transition_ref has already been consumed")
    if parsed.idempotency_digest in prior_idempotency:
        _fail("duplicate_idempotency", "idempotency fence has already been consumed")
    current_evidence_refs = {evidence.evidence_ref for evidence in parsed.evidence_refs}
    if current_evidence_refs & prior_evidence:
        _fail("evidence_reuse", "single-use evidence has already been consumed")
    approval = parsed.command.approval
    if approval is not None and (
        approval.approval_ref in prior_approval_refs
        or approval.evidence.evidence_ref in prior_evidence
        or approval.evidence.evidence_ref in current_evidence_refs
    ):
        _fail(
            "approval_reuse",
            "single-use approval or approval evidence has already been consumed",
        )

    _approval_and_evidence_valid(
        scope=parsed.scope,
        lifecycle_ref=parsed.lifecycle_ref,
        revision=parsed.expected_revision + 1,
        prior_state_digest=parsed.expected_state_digest,
        transition_ref=parsed.transition_ref,
        idempotency_digest=parsed.idempotency_digest,
        command=parsed.command,
        requested_by_ref=parsed.requested_by_ref,
        proposed_at=parsed.proposed_at,
        evidence_refs=parsed.evidence_refs,
        expected_commitment_digest=supply_chain_transition_evidence_digest(parsed),
        causal_not_before=history[-1].proposed_at if history else None,
        prior_history=history,
    )
    next_projection = _apply_command(
        parsed.scope,
        projection,
        parsed.command,
        parsed.proposed_at,
        causal_not_before=history[-1].proposed_at if history else None,
    )
    required_role = _REQUIRED_APPROVAL.get(parsed.command.kind)
    record_payload: dict[str, Any] = {
        "schema": SUPPLY_CHAIN_TRANSITION_RECORD_SCHEMA,
        "revision": parsed.expected_revision + 1,
        "scope_digest": parsed.scope_digest,
        "lifecycle_ref": parsed.lifecycle_ref,
        "transition_ref": parsed.transition_ref,
        "prior_state": parsed.expected_state,
        "prior_state_digest": parsed.expected_state_digest,
        "command": parsed.command,
        "command_digest": parsed.command_digest,
        "content_digest": parsed.content_digest,
        "idempotency_key": parsed.idempotency_key,
        "idempotency_digest": parsed.idempotency_digest,
        "requested_by_ref": parsed.requested_by_ref,
        "proposed_at": parsed.proposed_at,
        "evidence_refs": parsed.evidence_refs,
        "evidence_digest": _stable_digest(parsed.evidence_refs),
        "required_approver_role": required_role,
        "approval_ref": approval.approval_ref if approval is not None else None,
        "approval_digest": approval.approval_digest if approval is not None else None,
        "authoritative_state_changed": False,
        "optimizer_executed": False,
        "inventory_write_executed": False,
        "warehouse_write_executed": False,
        "carrier_write_executed": False,
    }
    record_payload["transition_digest"] = _stable_digest(
        {key: value for key, value in record_payload.items() if value is not None}
    )
    record = SupplyChainTransitionRecord.model_validate(record_payload)
    next_history = [*history, record]
    snapshot_payload = _snapshot_payload(
        parsed.scope,
        parsed.lifecycle_ref,
        next_history,
        next_projection,
    )
    snapshot_payload["state_digest"] = _stable_digest(snapshot_payload)
    snapshot = SupplyChainExecutionSnapshot.model_validate(snapshot_payload)
    proposal_payload: dict[str, Any] = {
        "schema": SUPPLY_CHAIN_PROPOSAL_SCHEMA,
        "scope": parsed.scope,
        "lifecycle_ref": parsed.lifecycle_ref,
        "source_revision": parsed.expected_revision,
        "source_state_digest": parsed.expected_state_digest,
        "target_revision": snapshot.revision,
        "target_state": snapshot.state,
        "transition_ref": parsed.transition_ref,
        "command_digest": parsed.command_digest,
        "content_digest": parsed.content_digest,
        "idempotency_digest": parsed.idempotency_digest,
        "transition_digest": record.transition_digest,
        "candidate_state_digest": snapshot.state_digest,
        "required_approver_role": required_role,
        "business_approval_evidence_present": approval is not None,
        "authoritative_state_changed": False,
        "optimizer_executed": False,
        "inventory_or_provider_write_executed": False,
        "spring_submission_executed": False,
    }
    proposal_payload["proposal_digest"] = _stable_digest(
        {key: value for key, value in proposal_payload.items() if value is not None}
    )
    proposal = SupplyChainTransitionProposal.model_validate(proposal_payload)
    return SupplyChainTransitionResult(
        proposal=proposal,
        candidate_snapshot=snapshot,
    )


SUPPLY_CHAIN_EXECUTION_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="supply-chain.execution-transition-proposal",
    tool="supply_chain.propose_execution_transition",
    effect=ConnectorEffect.DRAFT,
    approval_required=True,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _no_effect_recovery() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.NONE,
        disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
    )


def _receipt(
    *,
    status: PrimitiveOperationStatus,
    request_digest: str,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    error: PrimitiveBlocker | None = None,
    external_refs: Mapping[str, str] | None = None,
) -> PrimitiveOperationReceipt:
    return PrimitiveOperationReceipt(
        spec=SUPPLY_CHAIN_EXECUTION_TRANSITION_OPERATION,
        status=status,
        request_digest=request_digest,
        external_refs=dict(external_refs or {}),
        evidence_refs=list(evidence_refs),
        replayed=False,
        recovery_disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
        recovery_plan=_no_effect_recovery(),
        error=error,
    )


def _request_matches_context(
    request: SupplyChainTransitionRequest,
    context: PrimitiveExecutionContext,
) -> bool:
    context_scope = context.scope
    return (
        request.scope.tenant_ref == context_scope.tenant_ref
        and request.scope.company_ref == context_scope.company_ref
        and request.scope.project_ref == context_scope.project_ref
        and context_scope.project_id is not None
        and request.scope.project_id == context_scope.project_id
        and context_scope.actor_ref is not None
        and request.requested_by_ref == context_scope.actor_ref
        and context.idempotency_key is not None
        and request.idempotency_key == context.idempotency_key
    )


def _example_evidence(
    *,
    evidence_ref: str,
    kind: str,
    subject_ref: str,
    sha256: str,
    observed_at: str,
    effective_at: str,
    grade: Literal["attested", "verified"],
) -> dict[str, Any]:
    return {
        "schema": SUPPLY_CHAIN_EVIDENCE_SCHEMA,
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": SPRING_SUPPLY_CHAIN_EVIDENCE_ISSUER,
        "custodian_ref": SPRING_SUPPLY_CHAIN_EVIDENCE_CUSTODIAN,
        "subject_ref": subject_ref,
        "sha256": sha256,
        "observed_at": observed_at,
        "effective_at": effective_at,
        "verification_grade": grade,
        "classification": "restricted",
        "retention_policy": "supply-chain-seven-years",
        "single_use": True,
        "causal_revision": 0,
        "causal_state_digest": ZERO_DIGEST,
    }


def _example_inputs() -> dict[str, Any]:
    scope: dict[str, Any] = {
        "schema": SUPPLY_CHAIN_SCOPE_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000841",
        "planning_cycle_ref": "planning-cycle-example",
        "item_ref": "item-example",
        "source_location_ref": "warehouse-example",
        "destination_location_ref": "destination-example",
        "unit_of_measure": "each",
    }
    command: dict[str, Any] = {
        "schema": "lightbulb.supply_chain_project_demand_forecast_command.v1",
        "kind": "project_demand_forecast",
        "forecast_ref": "forecast-example",
        "planning_cycle_ref": scope["planning_cycle_ref"],
        "item_ref": scope["item_ref"],
        "source_location_ref": scope["source_location_ref"],
        "unit_of_measure": scope["unit_of_measure"],
        "horizon_start": "2026-08-26",
        "horizon_end": "2026-09-25",
        "generated_at": "2026-08-25T12:00:00Z",
        "forecast_quantity": "100",
        "model_version": "forecast-model-v7",
        "planner_ref": "planner-example",
    }
    lifecycle_ref = "supply-chain-lifecycle-example"
    transition_ref = "transition-forecast-example"
    idempotency_key = "idempotency-forecast-example"
    proposed_at = "2026-08-25T14:00:00Z"
    scope_digest = supply_chain_scope_digest(scope)
    command_digest = supply_chain_command_digest(command)
    idempotency_digest = supply_chain_idempotency_digest(
        scope, lifecycle_ref, idempotency_key
    )
    content_digest = _stable_digest(
        _content_payload(
            scope_digest=scope_digest,
            lifecycle_ref=lifecycle_ref,
            revision=1,
            prior_state=None,
            prior_state_digest=ZERO_DIGEST,
            transition_ref=transition_ref,
            command_digest=command_digest,
            idempotency_digest=idempotency_digest,
            requested_by_ref="planner-example",
            proposed_at=proposed_at,
        )
    )
    transition_evidence_digest = _stable_digest(
        {"content_digest": content_digest, "approval_digest": None}
    )
    payload: dict[str, Any] = {
        "schema": SUPPLY_CHAIN_REQUEST_SCHEMA,
        "scope": scope,
        "scope_digest": scope_digest,
        "lifecycle_ref": lifecycle_ref,
        "expected_revision": 0,
        "expected_state": None,
        "expected_state_digest": ZERO_DIGEST,
        "transition_ref": transition_ref,
        "idempotency_key": idempotency_key,
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": "planner-example",
        "proposed_at": proposed_at,
        "command": command,
        "command_digest": command_digest,
        "content_digest": content_digest,
        "evidence_refs": [
            _example_evidence(
                evidence_ref="evidence-forecast-commitment-example",
                kind="supply_chain_transition_commitment",
                subject_ref=transition_ref,
                sha256=transition_evidence_digest,
                observed_at="2026-08-25T13:58:00Z",
                effective_at="2026-08-25T13:58:00Z",
                grade="attested",
            ),
            _example_evidence(
                evidence_ref="evidence-forecast-fact-example",
                kind="demand_forecast_attestation",
                subject_ref="forecast-example",
                sha256=supply_chain_fact_evidence_digest(
                    scope,
                    lifecycle_ref,
                    transition_ref,
                    command,
                ),
                observed_at="2026-08-25T13:57:00Z",
                effective_at="2026-08-25T12:00:00Z",
                grade="attested",
            ),
        ],
    }
    return SupplyChainTransitionRequest.model_validate(payload).to_dict()


class ProposeSupplyChainExecutionTransitionPrimitive(
    BusinessProcessPrimitive[SupplyChainTransitionRequest, SupplyChainTransitionResult]
):
    primitive_ref = "supply_chain.propose_execution_transition"
    version = "1.0.0"
    title = "Propose a governed supply-chain execution transition"
    description = (
        "Validate and replay one evidence-bound supply-chain execution candidate "
        "without optimizing or changing Spring, ERP, WMS, TMS, inventory, or carrier state."
    )
    input_model = SupplyChainTransitionRequest
    output_model = SupplyChainTransitionResult
    connector_tools = ()
    risk_level = "high"
    approval_required = True
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "sdk_projection_or_proposal_only": True,
            "authoritative_state_changed": False,
            "optimizer_executed": False,
            "inventory_write_executed": False,
            "erp_wms_tms_or_carrier_write_executed": False,
            "spring_submission_executed": False,
            "hosted_approval_task_created": False,
            "connector_calls": False,
            "spring_identity_rbac_approval_persistence_audit_required": True,
            "erp_wms_tms_fact_and_write_authority_required": True,
        }
        contract["portable_evidence_is_execution_authority"] = False
        contract["non_preview_result_is_still_preview"] = True
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: SupplyChainTransitionRequest,
    ) -> PrimitiveExecutionResult[SupplyChainTransitionResult]:
        domain_evidence = list(inputs.evidence_refs)
        if inputs.command.approval is not None:
            domain_evidence.append(inputs.command.approval.evidence)
        portable_evidence = [evidence.portable_ref() for evidence in domain_evidence]
        if not _request_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="supply_chain_runtime_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, project-id, actor, and "
                    "idempotency scope are required and must match the exact supply-chain request."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Supply-chain transition rejected at the runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs),
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        try:
            output = propose_supply_chain_execution_transition(inputs)
        except SupplyChainExecutionError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code, message=exc.message, retryable=False
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Supply-chain transition failed deterministic lifecycle validation.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs),
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        proposal = output.proposal
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.PREVIEW,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Supply-chain candidate passed deterministic validation. It was not "
                "submitted to Spring, and no optimizer, ERP, WMS, TMS, inventory, "
                "warehouse, carrier, custody, or delivery state changed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="supply_chain.execution_transition_candidate_validated",
                    payload={
                        "lifecycle_ref": proposal.lifecycle_ref,
                        "transition_ref": proposal.transition_ref,
                        "target_state": proposal.target_state,
                        "proposal_digest": proposal.proposal_digest,
                        "authoritative_state_changed": False,
                        "optimizer_executed": False,
                        "provider_write_executed": False,
                        "spring_submission_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="supply_chain_execution_transition_proposal",
                    summary=(
                        "Content-bound SDK candidate; Spring and ERP/WMS/TMS retain "
                        "approval, persistence, optimization, fact, and write authority."
                    ),
                    labels=[
                        inputs.command.kind,
                        proposal.target_state,
                        "preview_only",
                        "no_live_effect",
                    ],
                    refs={"proposal_digest": proposal.proposal_digest},
                )
            ],
            evidence_refs=portable_evidence,
            operation_receipts=[
                _receipt(
                    status=PrimitiveOperationStatus.PREVIEW,
                    request_digest=_stable_digest(inputs),
                    evidence_refs=portable_evidence,
                    external_refs={
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "proposal_digest": proposal.proposal_digest,
                        "transition_digest": proposal.transition_digest,
                    },
                )
            ],
            retryable=False,
        )


SUPPLY_CHAIN_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeSupplyChainExecutionTransitionPrimitive(),)


__all__ = [
    "SPRING_SUPPLY_CHAIN_EVIDENCE_CUSTODIAN",
    "SPRING_SUPPLY_CHAIN_EVIDENCE_ISSUER",
    "SUPPLY_CHAIN_APPROVAL_SCHEMA",
    "SUPPLY_CHAIN_EVIDENCE_SCHEMA",
    "SUPPLY_CHAIN_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "SUPPLY_CHAIN_EXECUTION_TRANSITION_OPERATION",
    "SUPPLY_CHAIN_PROPOSAL_SCHEMA",
    "SUPPLY_CHAIN_REQUEST_SCHEMA",
    "SUPPLY_CHAIN_RESULT_SCHEMA",
    "SUPPLY_CHAIN_SCOPE_SCHEMA",
    "SUPPLY_CHAIN_SNAPSHOT_SCHEMA",
    "SUPPLY_CHAIN_TRANSITION_RECORD_SCHEMA",
    "ZERO_DIGEST",
    "AllocateSupplyCommand",
    "ApproveSopCommand",
    "CloseExecutionCommand",
    "DispatchShipmentCommand",
    "MarkExecutionInDoubtCommand",
    "OpenShipmentExceptionCommand",
    "PlanReplenishmentCommand",
    "ProjectDemandForecastCommand",
    "ProposeSupplyChainExecutionTransitionPrimitive",
    "RecordCustodyTransferCommand",
    "RecordDeliveryCommand",
    "RecordMrpSupplyPlanCommand",
    "ReleaseWarehouseCommand",
    "ResolveExecutionInDoubtCommand",
    "ResolveShipmentExceptionCommand",
    "SupplyChainApprovalEvidence",
    "SupplyChainCommand",
    "SupplyChainCustodyProjection",
    "SupplyChainExecutionError",
    "SupplyChainExecutionEvidence",
    "SupplyChainExecutionScope",
    "SupplyChainExecutionSnapshot",
    "SupplyChainTransitionProposal",
    "SupplyChainTransitionRecord",
    "SupplyChainTransitionRequest",
    "SupplyChainTransitionResult",
    "propose_supply_chain_execution_transition",
    "supply_chain_approval_digest",
    "supply_chain_command_digest",
    "supply_chain_fact_evidence_digest",
    "supply_chain_idempotency_digest",
    "supply_chain_scope_digest",
    "supply_chain_snapshot_digest",
    "supply_chain_transition_evidence_digest",
    "supply_chain_transition_content_digest",
]
