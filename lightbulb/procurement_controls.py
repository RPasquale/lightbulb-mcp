"""Deterministic, evidence-bound purchase-to-pay control evaluation.

The module owns reusable procurement mechanics only.  It does not resolve a
tenant, read a connector, approve a purchase, create a provider object, release
payment, or mutate inventory.  A trusted host normalizes authoritative vendor,
requisition, purchase-order, receipt, and invoice evidence into these contracts;
the primitive then evaluates the packet deterministically.
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


VENDOR_QUALIFICATION_SNAPSHOT_SCHEMA = "lightbulb.vendor_qualification_snapshot.v1"
PURCHASE_REQUISITION_SNAPSHOT_SCHEMA = "lightbulb.purchase_requisition_snapshot.v1"
PURCHASE_ORDER_SNAPSHOT_SCHEMA = "lightbulb.purchase_order_snapshot.v1"
GOODS_RECEIPT_SNAPSHOT_SCHEMA = "lightbulb.goods_receipt_snapshot.v1"
SUPPLIER_INVOICE_SNAPSHOT_SCHEMA = "lightbulb.supplier_invoice_snapshot.v1"
PURCHASE_TO_PAY_CONTROLS_INPUT_SCHEMA = "lightbulb.purchase_to_pay_controls_input.v1"
PURCHASE_TO_PAY_CONTROLS_RESULT_SCHEMA = "lightbulb.purchase_to_pay_controls_result.v1"

_ZERO_DIGEST = "0" * 64
_QUANTITY_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.0001")
_RATIO_QUANTUM = Decimal("0.000001")

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
UnitCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9._/-]{0,31}$",
    ),
]

VendorQualificationStatus = Literal[
    "pending", "qualified", "conditional", "blocked", "expired"
]
PurchaseRequisitionStatus = Literal[
    "draft", "pending_approval", "approved", "rejected", "cancelled", "closed"
]
PurchaseOrderStatus = Literal[
    "draft",
    "pending_approval",
    "approved",
    "issued",
    "partially_received",
    "received",
    "closed",
    "cancelled",
]
GoodsReceiptStatus = Literal["posted", "quarantined", "reversed"]
SupplierInvoiceStatus = Literal["received", "validated", "on_hold", "paid", "cancelled"]
InvoiceDuplicateCheck = Literal[
    "clear", "not_performed", "possible_duplicate", "confirmed_duplicate"
]
TraceKind = Literal["lot", "serial"]
ControlGate = Literal[
    "evidence",
    "vendor",
    "requisition",
    "purchase_order",
    "receiving",
    "invoice",
    "three_way_match",
]
ControlSeverity = Literal["info", "review", "blocking"]
ControlGateStatus = Literal["pass", "review", "fail", "indeterminate"]
PurchaseToPayLineStatus = Literal[
    "matched", "not_invoiced", "exception", "indeterminate"
]
PurchaseToPayDisposition = Literal[
    "eligible_for_payment_approval",
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
    if isinstance(value, list):
        return tuple(value)
    return value


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


def _decimal(
    value: Any,
    *,
    quantum: Decimal,
    non_negative: bool = True,
) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("decimal values must use bounded notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("decimal values must be finite") from exc
    if not parsed.is_finite():
        raise ValueError("decimal values must be finite")
    if non_negative and parsed < 0:
        raise ValueError("decimal values must be non-negative")
    try:
        normalized = parsed.quantize(quantum)
    except InvalidOperation as exc:
        raise ValueError("decimal value exceeds the supported precision") from exc
    if parsed != normalized:
        raise ValueError(
            f"decimal values support at most {-quantum.as_tuple().exponent} places"
        )
    return normalized


def _quantity(value: Any) -> Decimal:
    return _decimal(value, quantum=_QUANTITY_QUANTUM)


def _money(value: Any) -> Decimal:
    return _decimal(value, quantum=_MONEY_QUANTUM)


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


def procurement_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    """Return the canonical digest of one normalized procurement snapshot."""

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


class ProcurementMaterialTraceRef(_StrictModel):
    kind: TraceKind
    trace_ref: OpaqueRef


class VendorQualificationSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.vendor_qualification_snapshot.v1"] = Field(
        default=VENDOR_QUALIFICATION_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    vendor_ref: OpaqueRef
    status: VendorQualificationStatus
    policy_ref: OpaqueRef
    qualified_at: str | None = None
    valid_until: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("qualified_at", "valid_until")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _qualified_status_has_window(self) -> "VendorQualificationSnapshot":
        if self.status in {"qualified", "conditional"} and (
            self.qualified_at is None or self.valid_until is None
        ):
            raise ValueError(
                "qualified and conditional vendors require qualified_at and valid_until"
            )
        if (
            self.qualified_at is not None
            and self.valid_until is not None
            and _parse_timestamp(self.qualified_at) > _parse_timestamp(self.valid_until)
        ):
            raise ValueError("qualified_at must not be after valid_until")
        return self


class PurchaseRequisitionLine(_StrictModel):
    line_ref: OpaqueRef
    item_ref: OpaqueRef
    description: ShortText | None = None
    quantity_requested: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    estimated_unit_price: Decimal | None = Field(default=None, ge=0)

    @field_validator("quantity_requested", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("estimated_unit_price", mode="before")
    @classmethod
    def _valid_optional_money(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)


class PurchaseRequisitionSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.purchase_requisition_snapshot.v1"] = Field(
        default=PURCHASE_REQUISITION_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    requisition_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: PurchaseRequisitionStatus
    currency: CurrencyCode
    approved_budget_amount: Decimal = Field(gt=0)
    vendor_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    approved_at: str | None = None
    lines: tuple[PurchaseRequisitionLine, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("approved_budget_amount", mode="before")
    @classmethod
    def _valid_budget(cls, value: Any) -> Decimal:
        return _money(value)

    @field_validator("approved_at")
    @classmethod
    def _valid_approved_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name="approved_at")

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_requisition(self) -> "PurchaseRequisitionSnapshot":
        _require_unique_refs(self.lines, field="line_ref", label="requisition line")
        if self.status in {"approved", "closed"} and (
            self.approval_ref is None or self.approved_at is None
        ):
            raise ValueError(
                "approved requisitions require approval_ref and approved_at"
            )
        return self


class PurchaseOrderLine(_StrictModel):
    line_ref: OpaqueRef
    requisition_line_ref: OpaqueRef
    item_ref: OpaqueRef
    description: ShortText | None = None
    quantity_ordered: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    unit_price: Decimal = Field(ge=0)

    @field_validator("quantity_ordered", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("unit_price", mode="before")
    @classmethod
    def _valid_money(cls, value: Any) -> Decimal:
        return _money(value)


class PurchaseOrderSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.purchase_order_snapshot.v1"] = Field(
        default=PURCHASE_ORDER_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    purchase_order_ref: OpaqueRef
    revision: int = Field(ge=1)
    requisition_ref: OpaqueRef
    vendor_ref: OpaqueRef
    status: PurchaseOrderStatus
    currency: CurrencyCode
    issued_at: str | None = None
    approval_ref: OpaqueRef | None = None
    lines: tuple[PurchaseOrderLine, ...] = Field(min_length=1, max_length=1_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("issued_at")
    @classmethod
    def _valid_issued_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name="issued_at")

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_purchase_order(self) -> "PurchaseOrderSnapshot":
        _require_unique_refs(self.lines, field="line_ref", label="purchase-order line")
        authorized_statuses = {
            "approved",
            "issued",
            "partially_received",
            "received",
            "closed",
        }
        if self.status in authorized_statuses and self.approval_ref is None:
            raise ValueError("authorized purchase orders require approval_ref")
        if self.status in authorized_statuses - {"approved"} and self.issued_at is None:
            raise ValueError("issued purchase orders require issued_at")
        return self


class GoodsReceiptLine(_StrictModel):
    line_ref: OpaqueRef
    purchase_order_line_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_received: Decimal = Field(gt=0)
    quantity_accepted: Decimal = Field(ge=0)
    quantity_rejected: Decimal = Field(default=Decimal("0"), ge=0)
    unit_of_measure: UnitCode
    trace_refs: tuple[ProcurementMaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )

    @field_validator(
        "quantity_received",
        "quantity_accepted",
        "quantity_rejected",
        mode="before",
    )
    @classmethod
    def _valid_quantities(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("trace_refs", mode="before")
    @classmethod
    def _trace_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _quantities_reconcile(self) -> "GoodsReceiptLine":
        if self.quantity_accepted + self.quantity_rejected != self.quantity_received:
            raise ValueError(
                "quantity_accepted plus quantity_rejected must equal quantity_received"
            )
        _require_unique_refs(self.trace_refs, field="trace_ref", label="trace")
        return self


class GoodsReceiptSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.goods_receipt_snapshot.v1"] = Field(
        default=GOODS_RECEIPT_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    goods_receipt_ref: OpaqueRef
    revision: int = Field(ge=1)
    purchase_order_ref: OpaqueRef
    vendor_ref: OpaqueRef
    status: GoodsReceiptStatus
    received_at: str
    receiving_location_ref: OpaqueRef
    lines: tuple[GoodsReceiptLine, ...] = Field(min_length=1, max_length=1_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("received_at")
    @classmethod
    def _valid_received_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="received_at")

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_receipt(self) -> "GoodsReceiptSnapshot":
        _require_unique_refs(self.lines, field="line_ref", label="goods-receipt line")
        return self


class SupplierInvoiceLine(_StrictModel):
    line_ref: OpaqueRef
    purchase_order_line_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_invoiced: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    unit_price: Decimal = Field(ge=0)
    line_total: Decimal = Field(ge=0)

    @field_validator("quantity_invoiced", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("unit_price", "line_total", mode="before")
    @classmethod
    def _valid_money(cls, value: Any) -> Decimal:
        return _money(value)


class SupplierInvoiceSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.supplier_invoice_snapshot.v1"] = Field(
        default=SUPPLIER_INVOICE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    supplier_invoice_ref: OpaqueRef
    revision: int = Field(ge=1)
    invoice_number: ShortText
    vendor_ref: OpaqueRef
    purchase_order_ref: OpaqueRef
    status: SupplierInvoiceStatus
    duplicate_check: InvoiceDuplicateCheck
    currency: CurrencyCode
    invoice_date: str
    due_at: str | None = None
    subtotal: Decimal = Field(ge=0)
    tax_total: Decimal = Field(default=Decimal("0"), ge=0)
    total: Decimal = Field(ge=0)
    lines: tuple[SupplierInvoiceLine, ...] = Field(min_length=1, max_length=1_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )

    @field_validator("invoice_date", "due_at")
    @classmethod
    def _valid_timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, field_name=info.field_name)

    @field_validator("subtotal", "tax_total", "total", mode="before")
    @classmethod
    def _valid_money(cls, value: Any) -> Decimal:
        return _money(value)

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_invoice(self) -> "SupplierInvoiceSnapshot":
        _require_unique_refs(self.lines, field="line_ref", label="invoice line")
        if self.due_at is not None and _parse_timestamp(self.due_at) < _parse_timestamp(
            self.invoice_date
        ):
            raise ValueError("invoice due_at cannot precede invoice_date")
        return self


class PurchaseToPayControlPolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8_760)
    quantity_tolerance_ratio: Decimal = Field(default=Decimal("0"), ge=0, le=1)
    unit_price_tolerance_ratio: Decimal = Field(default=Decimal("0.02"), ge=0, le=1)
    line_total_tolerance_ratio: Decimal = Field(default=Decimal("0.02"), ge=0, le=1)
    document_total_tolerance_ratio: Decimal = Field(default=Decimal("0.02"), ge=0, le=1)
    absolute_amount_tolerance: Decimal = Field(default=Decimal("0.01"), ge=0)
    allowed_over_receipt_ratio: Decimal = Field(default=Decimal("0"), ge=0, le=1)
    require_full_order_receipt: bool = False

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _valid_evidence_grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @field_validator(
        "quantity_tolerance_ratio",
        "unit_price_tolerance_ratio",
        "line_total_tolerance_ratio",
        "document_total_tolerance_ratio",
        "allowed_over_receipt_ratio",
        mode="before",
    )
    @classmethod
    def _valid_ratios(cls, value: Any) -> Decimal:
        return _ratio(value)

    @field_validator("absolute_amount_tolerance", mode="before")
    @classmethod
    def _valid_tolerance(cls, value: Any) -> Decimal:
        return _money(value)


class PurchaseToPayControlsInput(_StrictModel):
    schema_id: Literal["lightbulb.purchase_to_pay_controls_input.v1"] = Field(
        default=PURCHASE_TO_PAY_CONTROLS_INPUT_SCHEMA,
        alias="schema",
    )
    control_ref: OpaqueRef
    analysis_as_of: str
    vendor: VendorQualificationSnapshot
    requisition: PurchaseRequisitionSnapshot
    purchase_order: PurchaseOrderSnapshot
    goods_receipts: tuple[GoodsReceiptSnapshot, ...] = Field(max_length=100)
    supplier_invoice: SupplierInvoiceSnapshot
    policy: PurchaseToPayControlPolicy = Field(
        default_factory=PurchaseToPayControlPolicy
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="analysis_as_of")

    @field_validator("goods_receipts", mode="before")
    @classmethod
    def _receipt_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _document_graph_is_exact(self) -> "PurchaseToPayControlsInput":
        _require_unique_refs(
            self.goods_receipts,
            field="goods_receipt_ref",
            label="goods-receipt",
        )
        evidence_by_ref: dict[str, PrimitiveEvidenceRef] = {}
        evidence_groups = (
            self.vendor.evidence_refs,
            self.requisition.evidence_refs,
            self.purchase_order.evidence_refs,
            self.supplier_invoice.evidence_refs,
            *(receipt.evidence_refs for receipt in self.goods_receipts),
        )
        for evidence_group in evidence_groups:
            for evidence in evidence_group:
                previous = evidence_by_ref.setdefault(
                    evidence.evidence_ref,
                    evidence,
                )
                if previous != evidence:
                    raise ValueError(
                        "one evidence_ref cannot identify conflicting evidence"
                    )
        requisition_approved_at = self.requisition.approved_at
        purchase_order_issued_at = self.purchase_order.issued_at
        if (
            requisition_approved_at is not None
            and purchase_order_issued_at is not None
            and _parse_timestamp(requisition_approved_at)
            > _parse_timestamp(purchase_order_issued_at)
        ):
            raise ValueError(
                "requisition approved_at cannot follow purchase-order issued_at"
            )
        if purchase_order_issued_at is not None:
            issued_at = _parse_timestamp(purchase_order_issued_at)
            if any(
                _parse_timestamp(receipt.received_at) < issued_at
                for receipt in self.goods_receipts
            ):
                raise ValueError(
                    "goods-receipt received_at cannot precede purchase-order issued_at"
                )
            if _parse_timestamp(self.supplier_invoice.invoice_date) < issued_at:
                raise ValueError(
                    "supplier invoice_date cannot precede purchase-order issued_at"
                )
        return self


class PurchaseToPayFinding(_StrictModel):
    code: OpaqueRef
    gate: ControlGate
    severity: ControlSeverity
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    document_ref: OpaqueRef | None = None
    line_ref: OpaqueRef | None = None


class PurchaseToPayGateResult(_StrictModel):
    gate: ControlGate
    status: ControlGateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class PurchaseToPayLineResult(_StrictModel):
    purchase_order_line_ref: OpaqueRef
    requisition_line_ref: OpaqueRef
    item_ref: OpaqueRef
    unit_of_measure: UnitCode
    quantity_ordered: Decimal = Field(ge=0)
    quantity_accepted: Decimal = Field(ge=0)
    quantity_invoiced: Decimal = Field(ge=0)
    receipt_evidence_present: bool
    purchase_order_unit_price: Decimal = Field(ge=0)
    invoice_unit_price: Decimal | None = Field(default=None, ge=0)
    expected_invoice_line_total: Decimal = Field(ge=0)
    actual_invoice_line_total: Decimal = Field(ge=0)
    price_variance_ratio: Decimal | None = Field(default=None, ge=0)
    total_variance_ratio: Decimal | None = Field(default=None, ge=0)
    accepted_goods_receipt_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    trace_refs: tuple[ProcurementMaterialTraceRef, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    status: PurchaseToPayLineStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator(
        "accepted_goods_receipt_refs",
        "trace_refs",
        "finding_codes",
        mode="before",
    )
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_lineage(self) -> "PurchaseToPayLineResult":
        if len(self.accepted_goods_receipt_refs) != len(
            set(self.accepted_goods_receipt_refs)
        ):
            raise ValueError("accepted goods-receipt references must be unique")
        trace_keys = {(item.kind, item.trace_ref) for item in self.trace_refs}
        if len(trace_keys) != len(self.trace_refs):
            raise ValueError("trace references must be unique by kind and reference")
        return self


class ProcurementEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    payment_authorized: Literal[False] = False
    inventory_changed: Literal[False] = False
    external_systems_changed: Literal[False] = False


PURCHASE_TO_PAY_CONTROLS_OPERATION = PrimitiveOperationSpec(
    operation_ref="purchase-to-pay-controls.evaluate",
    tool="procurement.evaluate_purchase_to_pay_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class PurchaseToPayControlsResult(_StrictModel):
    schema_id: Literal["lightbulb.purchase_to_pay_controls_result.v1"] = Field(
        default=PURCHASE_TO_PAY_CONTROLS_RESULT_SCHEMA,
        alias="schema",
    )
    control_ref: OpaqueRef
    analysis_as_of: str
    assurance_grade: PrimitiveEvidenceVerificationGrade
    proposed_disposition: PurchaseToPayDisposition
    payment_authorized: Literal[False] = False
    gates: tuple[PurchaseToPayGateResult, ...]
    line_results: tuple[PurchaseToPayLineResult, ...]
    findings: tuple[PurchaseToPayFinding, ...]
    purchase_order_total: Decimal = Field(ge=0)
    accepted_value_at_purchase_order_price: Decimal = Field(ge=0)
    expected_invoice_subtotal: Decimal = Field(ge=0)
    actual_invoice_subtotal: Decimal = Field(ge=0)
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[str, ...]
    effect_boundary: ProcurementEffectBoundary = Field(
        default_factory=ProcurementEffectBoundary
    )
    result_digest: str = Field(default=_ZERO_DIGEST, pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "gates", "line_results", "findings", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("source_snapshot_digests")
    @classmethod
    def _valid_snapshot_digests(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or len(value) > 104:
            raise ValueError("source_snapshot_digests must contain 1 to 104 entries")
        if any(
            not key
            or len(key) > 200
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for key, digest in value.items()
        ):
            raise ValueError("source snapshot digests must be lowercase SHA-256 values")
        return value

    @model_validator(mode="after")
    def _result_is_coherent_and_content_bound(self) -> "PurchaseToPayControlsResult":
        expected_findings = tuple(
            sorted(
                self.findings,
                key=lambda item: (
                    _GATE_ORDER.index(item.gate),
                    item.document_ref or "",
                    item.line_ref or "",
                    item.code,
                ),
            )
        )
        if self.findings != expected_findings:
            raise ValueError("findings must be in canonical order")
        expected_gates: list[PurchaseToPayGateResult] = []
        for gate_name in _GATE_ORDER:
            gate_findings = [item for item in self.findings if item.gate == gate_name]
            if any(
                item.severity == "blocking" and item.code not in _INDETERMINATE_CODES
                for item in gate_findings
            ):
                status: ControlGateStatus = "fail"
            elif any(item.code in _INDETERMINATE_CODES for item in gate_findings):
                status = "indeterminate"
            elif any(item.severity == "review" for item in gate_findings):
                status = "review"
            else:
                status = "pass"
            expected_gates.append(
                PurchaseToPayGateResult(
                    gate=gate_name,
                    status=status,
                    finding_codes=tuple(sorted({item.code for item in gate_findings})),
                )
            )
        if self.gates != tuple(expected_gates):
            raise ValueError("gates must be the canonical projection of findings")
        expected_disposition: PurchaseToPayDisposition = (
            "blocked"
            if any(item.status == "fail" for item in self.gates)
            else "indeterminate"
            if any(item.status == "indeterminate" for item in self.gates)
            else "manual_review_required"
            if any(item.status == "review" for item in self.gates)
            else "eligible_for_payment_approval"
        )
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match gate results")

        line_findings = {
            line.purchase_order_line_ref: tuple(
                item
                for item in self.findings
                if item.line_ref == line.purchase_order_line_ref
            )
            for line in self.line_results
        }
        for line in self.line_results:
            related = line_findings[line.purchase_order_line_ref]
            expected_codes = tuple(sorted({item.code for item in related}))
            expected_status: PurchaseToPayLineStatus = (
                "not_invoiced"
                if line.quantity_invoiced == 0
                else "exception"
                if any(
                    item.severity == "blocking"
                    and item.code not in _INDETERMINATE_CODES
                    for item in related
                )
                else "indeterminate"
                if any(item.code in _INDETERMINATE_CODES for item in related)
                else "exception"
                if related
                else "matched"
            )
            if line.finding_codes != expected_codes or line.status != expected_status:
                raise ValueError("line status and finding_codes must match findings")
            if line.expected_invoice_line_total != (
                line.quantity_invoiced * line.purchase_order_unit_price
            ):
                raise ValueError(
                    "expected invoice line total must match line quantities"
                )
        if self.purchase_order_total != sum(
            (
                line.quantity_ordered * line.purchase_order_unit_price
                for line in self.line_results
            ),
            Decimal("0"),
        ):
            raise ValueError("purchase_order_total must match line results")
        if self.accepted_value_at_purchase_order_price != sum(
            (
                line.quantity_accepted * line.purchase_order_unit_price
                for line in self.line_results
            ),
            Decimal("0"),
        ):
            raise ValueError(
                "accepted_value_at_purchase_order_price must match line results"
            )
        if self.expected_invoice_subtotal != sum(
            (line.expected_invoice_line_total for line in self.line_results),
            Decimal("0"),
        ):
            raise ValueError("expected_invoice_subtotal must match line results")
        required_source_keys = {
            "invoice",
            "policy",
            "purchase_order",
            "requisition",
            "vendor",
        }
        if not required_source_keys.issubset(self.source_snapshot_digests) or any(
            key not in required_source_keys and not key.startswith("goods_receipt:")
            for key in self.source_snapshot_digests
        ):
            raise ValueError("source_snapshot_digests contains an invalid source set")
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


_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

_GATE_ORDER: tuple[ControlGate, ...] = (
    "evidence",
    "vendor",
    "requisition",
    "purchase_order",
    "receiving",
    "invoice",
    "three_way_match",
)

_INDETERMINATE_CODES = {
    "evidence_missing",
    "evidence_stale",
    "evidence_not_yet_effective",
    "evidence_below_required_grade",
    "missing_goods_receipt",
    "missing_goods_receipt_for_purchase_order_line",
    "invoice_duplicate_check_not_performed",
    "goods_receipt_after_analysis_cutoff",
    "invoice_after_analysis_cutoff",
    "purchase_order_after_analysis_cutoff",
    "vendor_qualification_after_analysis_cutoff",
}


def _difference_ratio(actual: Decimal, expected: Decimal) -> Decimal | None:
    difference = abs(actual - expected)
    if expected == 0:
        return Decimal("0") if difference == 0 else None
    return (difference / abs(expected)).quantize(_RATIO_QUANTUM)


def _within_tolerance(
    actual: Decimal,
    expected: Decimal,
    *,
    ratio: Decimal,
    absolute: Decimal = Decimal("0"),
) -> bool:
    difference = abs(actual - expected)
    if difference <= absolute:
        return True
    if expected == 0:
        return False
    return difference / abs(expected) <= ratio


def _model_digest(model: BaseModel) -> str:
    return _stable_digest(model.model_dump(mode="json", by_alias=True))


def evaluate_purchase_to_pay_controls(
    value: PurchaseToPayControlsInput | Mapping[str, Any],
) -> PurchaseToPayControlsResult:
    """Evaluate one normalized packet without reading or mutating external state."""

    inputs = revalidate_model_boundary(PurchaseToPayControlsInput, value)
    findings: list[PurchaseToPayFinding] = []

    def add(
        code: str,
        gate: ControlGate,
        severity: ControlSeverity,
        message: str,
        *,
        document_ref: str | None = None,
        line_ref: str | None = None,
    ) -> None:
        findings.append(
            PurchaseToPayFinding(
                code=code,
                gate=gate,
                severity=severity,
                message=message,
                document_ref=document_ref,
                line_ref=line_ref,
            )
        )

    analysis_at = _parse_timestamp(inputs.analysis_as_of)
    minimum_grade = inputs.policy.minimum_evidence_grade
    document_grades: list[PrimitiveEvidenceVerificationGrade] = []

    evidence_sets: list[tuple[str, str, tuple[PrimitiveEvidenceRef, ...]]] = [
        ("vendor", inputs.vendor.vendor_ref, inputs.vendor.evidence_refs),
        (
            "requisition",
            inputs.requisition.requisition_ref,
            inputs.requisition.evidence_refs,
        ),
        (
            "purchase_order",
            inputs.purchase_order.purchase_order_ref,
            inputs.purchase_order.evidence_refs,
        ),
        (
            "invoice",
            inputs.supplier_invoice.supplier_invoice_ref,
            inputs.supplier_invoice.evidence_refs,
        ),
    ]
    evidence_sets.extend(
        ("goods_receipt", receipt.goods_receipt_ref, receipt.evidence_refs)
        for receipt in sorted(
            inputs.goods_receipts,
            key=lambda item: item.goods_receipt_ref,
        )
    )

    for kind, document_ref, evidence_refs in evidence_sets:
        eligible_evidence: list[PrimitiveEvidenceRef] = []
        future_effective = False
        stale = False
        for evidence in sorted(evidence_refs, key=lambda item: item.evidence_ref):
            observed_at = _parse_timestamp(evidence.observed_at)
            if observed_at > analysis_at:
                future_effective = True
                continue
            if evidence.effective_at is not None and (
                _parse_timestamp(evidence.effective_at) > analysis_at
            ):
                future_effective = True
                continue
            if analysis_at - observed_at > timedelta(
                hours=inputs.policy.max_evidence_age_hours
            ):
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
                document_ref=document_ref,
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
                document_ref=document_ref,
            )

    if not inputs.goods_receipts:
        document_grades.append(PrimitiveEvidenceVerificationGrade.UNVERIFIED)

    assurance_grade = (
        min(document_grades, key=_GRADE_RANK.__getitem__)
        if document_grades
        else PrimitiveEvidenceVerificationGrade.UNVERIFIED
    )

    vendor = inputs.vendor
    requisition = inputs.requisition
    purchase_order = inputs.purchase_order
    invoice = inputs.supplier_invoice

    if vendor.status == "conditional":
        add(
            "vendor_conditionally_qualified",
            "vendor",
            "review",
            "Vendor qualification is conditional and requires human review.",
            document_ref=vendor.vendor_ref,
        )
    elif vendor.status != "qualified":
        add(
            "vendor_not_qualified",
            "vendor",
            "blocking",
            "Vendor is not currently qualified for purchase-to-pay processing.",
            document_ref=vendor.vendor_ref,
        )
    if (
        vendor.valid_until is not None
        and _parse_timestamp(vendor.valid_until) < analysis_at
    ):
        add(
            "vendor_qualification_expired",
            "vendor",
            "blocking",
            "Vendor qualification expired before the analysis cutoff.",
            document_ref=vendor.vendor_ref,
        )
    if (
        vendor.qualified_at is not None
        and _parse_timestamp(vendor.qualified_at) > analysis_at
    ):
        add(
            "vendor_qualification_after_analysis_cutoff",
            "vendor",
            "blocking",
            "Vendor qualification is not effective at the analysis cutoff.",
            document_ref=vendor.vendor_ref,
        )

    if requisition.status not in {"approved", "closed"}:
        add(
            "requisition_not_approved",
            "requisition",
            "blocking",
            "Purchase requisition is not approved.",
            document_ref=requisition.requisition_ref,
        )
    if (
        requisition.vendor_ref is not None
        and requisition.vendor_ref != vendor.vendor_ref
    ):
        add(
            "requisition_vendor_mismatch",
            "requisition",
            "blocking",
            "Purchase requisition vendor does not match the qualified vendor.",
            document_ref=requisition.requisition_ref,
        )

    authorized_po_statuses = {
        "issued",
        "partially_received",
        "received",
        "closed",
    }
    if purchase_order.status not in authorized_po_statuses:
        add(
            "purchase_order_not_authorized",
            "purchase_order",
            "blocking",
            "Purchase order is not in an authorized state.",
            document_ref=purchase_order.purchase_order_ref,
        )
    if purchase_order.requisition_ref != requisition.requisition_ref:
        add(
            "purchase_order_requisition_mismatch",
            "purchase_order",
            "blocking",
            "Purchase order does not reference the supplied requisition.",
            document_ref=purchase_order.purchase_order_ref,
        )
    if purchase_order.vendor_ref != vendor.vendor_ref:
        add(
            "purchase_order_vendor_mismatch",
            "purchase_order",
            "blocking",
            "Purchase order vendor does not match the qualified vendor.",
            document_ref=purchase_order.purchase_order_ref,
        )
    if purchase_order.currency != requisition.currency:
        add(
            "purchase_order_currency_mismatch",
            "purchase_order",
            "blocking",
            "Purchase order currency does not match the requisition currency.",
            document_ref=purchase_order.purchase_order_ref,
        )
    if (
        purchase_order.issued_at is not None
        and _parse_timestamp(purchase_order.issued_at) > analysis_at
    ):
        add(
            "purchase_order_after_analysis_cutoff",
            "purchase_order",
            "blocking",
            "Purchase order was issued after the analysis cutoff.",
            document_ref=purchase_order.purchase_order_ref,
        )

    requisition_lines = {item.line_ref: item for item in requisition.lines}
    purchase_order_lines = {item.line_ref: item for item in purchase_order.lines}
    purchase_order_total = sum(
        (item.quantity_ordered * item.unit_price for item in purchase_order.lines),
        Decimal("0"),
    )
    if purchase_order_total > requisition.approved_budget_amount:
        add(
            "purchase_order_exceeds_approved_budget",
            "purchase_order",
            "blocking",
            "Purchase order total exceeds the approved requisition budget.",
            document_ref=purchase_order.purchase_order_ref,
        )

    for po_line in sorted(purchase_order.lines, key=lambda item: item.line_ref):
        req_line = requisition_lines.get(po_line.requisition_line_ref)
        if req_line is None:
            add(
                "purchase_order_line_missing_requisition_link",
                "purchase_order",
                "blocking",
                "Purchase-order line does not resolve to a requisition line.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
            continue
        if po_line.item_ref != req_line.item_ref:
            add(
                "purchase_order_item_mismatch",
                "purchase_order",
                "blocking",
                "Purchase-order item does not match the requisition line.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
        if po_line.unit_of_measure != req_line.unit_of_measure:
            add(
                "purchase_order_unit_mismatch",
                "purchase_order",
                "blocking",
                "Purchase-order unit does not match the requisition line.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
        if (
            po_line.quantity_ordered > req_line.quantity_requested
            and not _within_tolerance(
                po_line.quantity_ordered,
                req_line.quantity_requested,
                ratio=inputs.policy.quantity_tolerance_ratio,
            )
        ):
            add(
                "ordered_quantity_exceeds_requisition",
                "purchase_order",
                "blocking",
                "Ordered quantity exceeds the approved requisition quantity.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
        if (
            req_line.estimated_unit_price is not None
            and po_line.unit_price > req_line.estimated_unit_price
            and not _within_tolerance(
                po_line.unit_price,
                req_line.estimated_unit_price,
                ratio=inputs.policy.unit_price_tolerance_ratio,
                absolute=inputs.policy.absolute_amount_tolerance,
            )
        ):
            add(
                "purchase_order_price_exceeds_requisition",
                "purchase_order",
                "blocking",
                "Purchase-order unit price exceeds the approved estimate.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )

    accepted_by_po_line: dict[str, Decimal] = {}
    receipt_observed_po_lines: set[str] = set()
    accepted_receipt_refs_by_po_line: dict[str, set[str]] = {}
    trace_refs_by_po_line: dict[
        str,
        dict[tuple[TraceKind, str], ProcurementMaterialTraceRef],
    ] = {}
    if not inputs.goods_receipts:
        add(
            "missing_goods_receipt",
            "receiving",
            "blocking",
            "No goods-receipt evidence was supplied; receipt cannot be inferred.",
            document_ref=purchase_order.purchase_order_ref,
        )

    posted_receipt_count = 0
    for receipt in sorted(
        inputs.goods_receipts,
        key=lambda item: item.goods_receipt_ref,
    ):
        receipt_header_matches = True
        if receipt.purchase_order_ref != purchase_order.purchase_order_ref:
            receipt_header_matches = False
            add(
                "goods_receipt_purchase_order_mismatch",
                "receiving",
                "blocking",
                "Goods receipt references a different purchase order.",
                document_ref=receipt.goods_receipt_ref,
            )
        if receipt.vendor_ref != vendor.vendor_ref:
            receipt_header_matches = False
            add(
                "goods_receipt_vendor_mismatch",
                "receiving",
                "blocking",
                "Goods receipt vendor does not match the qualified vendor.",
                document_ref=receipt.goods_receipt_ref,
            )
        if _parse_timestamp(receipt.received_at) > analysis_at:
            add(
                "goods_receipt_after_analysis_cutoff",
                "receiving",
                "blocking",
                "Goods receipt occurred after the analysis cutoff and was excluded.",
                document_ref=receipt.goods_receipt_ref,
            )
            continue
        if receipt.status == "reversed":
            add(
                "reversed_goods_receipt_excluded",
                "receiving",
                "info",
                "Reversed goods receipt was excluded from accepted quantities.",
                document_ref=receipt.goods_receipt_ref,
            )
            continue
        if receipt.status == "quarantined":
            add(
                "quarantined_goods_receipt_excluded",
                "receiving",
                "review",
                "Quarantined goods receipt was excluded from accepted quantities.",
                document_ref=receipt.goods_receipt_ref,
            )
            continue
        posted_receipt_count += 1
        for receipt_line in sorted(receipt.lines, key=lambda item: item.line_ref):
            po_line = purchase_order_lines.get(receipt_line.purchase_order_line_ref)
            if po_line is None:
                add(
                    "goods_receipt_line_missing_purchase_order_link",
                    "receiving",
                    "blocking",
                    "Goods-receipt line does not resolve to a purchase-order line.",
                    document_ref=receipt.goods_receipt_ref,
                    line_ref=receipt_line.purchase_order_line_ref,
                )
                continue
            receipt_line_matches = True
            if receipt_line.item_ref != po_line.item_ref:
                receipt_line_matches = False
                add(
                    "goods_receipt_item_mismatch",
                    "receiving",
                    "blocking",
                    "Goods-receipt item does not match the purchase-order line.",
                    document_ref=receipt.goods_receipt_ref,
                    line_ref=po_line.line_ref,
                )
            if receipt_line.unit_of_measure != po_line.unit_of_measure:
                receipt_line_matches = False
                add(
                    "goods_receipt_unit_mismatch",
                    "receiving",
                    "blocking",
                    "Goods-receipt unit does not match the purchase-order line.",
                    document_ref=receipt.goods_receipt_ref,
                    line_ref=po_line.line_ref,
                )
            if not receipt_header_matches or not receipt_line_matches:
                continue
            receipt_observed_po_lines.add(po_line.line_ref)
            accepted_by_po_line[po_line.line_ref] = (
                accepted_by_po_line.get(po_line.line_ref, Decimal("0"))
                + receipt_line.quantity_accepted
            )
            if receipt_line.quantity_accepted > 0:
                accepted_receipt_refs_by_po_line.setdefault(
                    po_line.line_ref,
                    set(),
                ).add(receipt.goods_receipt_ref)
                line_trace_refs = trace_refs_by_po_line.setdefault(
                    po_line.line_ref,
                    {},
                )
                for trace_ref in receipt_line.trace_refs:
                    line_trace_refs[(trace_ref.kind, trace_ref.trace_ref)] = trace_ref

    if inputs.goods_receipts and posted_receipt_count == 0:
        add(
            "missing_goods_receipt",
            "receiving",
            "blocking",
            "No posted goods receipt remains after reversals and quarantine.",
            document_ref=purchase_order.purchase_order_ref,
        )

    if invoice.purchase_order_ref != purchase_order.purchase_order_ref:
        add(
            "invoice_purchase_order_mismatch",
            "invoice",
            "blocking",
            "Supplier invoice references a different purchase order.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if invoice.vendor_ref != vendor.vendor_ref:
        add(
            "invoice_vendor_mismatch",
            "invoice",
            "blocking",
            "Supplier invoice vendor does not match the qualified vendor.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if invoice.currency != purchase_order.currency:
        add(
            "invoice_currency_mismatch",
            "invoice",
            "blocking",
            "Supplier invoice currency does not match the purchase order.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if _parse_timestamp(invoice.invoice_date) > analysis_at:
        add(
            "invoice_after_analysis_cutoff",
            "invoice",
            "blocking",
            "Supplier invoice is dated after the analysis cutoff.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if invoice.status == "received":
        add(
            "invoice_not_validated",
            "invoice",
            "blocking",
            "Supplier invoice has not reached a validated state.",
            document_ref=invoice.supplier_invoice_ref,
        )
    elif invoice.status == "on_hold":
        add(
            "invoice_on_hold",
            "invoice",
            "review",
            "Supplier invoice is on hold.",
            document_ref=invoice.supplier_invoice_ref,
        )
    elif invoice.status == "paid":
        add(
            "invoice_already_paid",
            "invoice",
            "blocking",
            "Supplier invoice is already paid and cannot be proposed again.",
            document_ref=invoice.supplier_invoice_ref,
        )
    elif invoice.status == "cancelled":
        add(
            "invoice_cancelled",
            "invoice",
            "blocking",
            "Cancelled supplier invoice cannot proceed to payment approval.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if invoice.duplicate_check == "not_performed":
        add(
            "invoice_duplicate_check_not_performed",
            "invoice",
            "blocking",
            "Duplicate-invoice screening has not been performed.",
            document_ref=invoice.supplier_invoice_ref,
        )
    elif invoice.duplicate_check in {
        "possible_duplicate",
        "confirmed_duplicate",
    }:
        add(
            "invoice_duplicate_detected",
            "invoice",
            "blocking",
            "Supplier invoice failed duplicate screening.",
            document_ref=invoice.supplier_invoice_ref,
        )

    invoiced_quantity_by_po_line: dict[str, Decimal] = {}
    invoiced_total_by_po_line: dict[str, Decimal] = {}
    for invoice_line in sorted(invoice.lines, key=lambda item: item.line_ref):
        po_line = purchase_order_lines.get(invoice_line.purchase_order_line_ref)
        if po_line is None:
            add(
                "invoice_line_missing_purchase_order_link",
                "invoice",
                "blocking",
                "Invoice line does not resolve to a purchase-order line.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=invoice_line.purchase_order_line_ref,
            )
            continue
        if invoice_line.item_ref != po_line.item_ref:
            add(
                "invoice_item_mismatch",
                "invoice",
                "blocking",
                "Invoice item does not match the purchase-order line.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        if invoice_line.unit_of_measure != po_line.unit_of_measure:
            add(
                "invoice_unit_mismatch",
                "invoice",
                "blocking",
                "Invoice unit does not match the purchase-order line.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        arithmetic_total = invoice_line.quantity_invoiced * invoice_line.unit_price
        if not _within_tolerance(
            invoice_line.line_total,
            arithmetic_total,
            ratio=inputs.policy.line_total_tolerance_ratio,
            absolute=inputs.policy.absolute_amount_tolerance,
        ):
            add(
                "invoice_line_arithmetic_mismatch",
                "invoice",
                "blocking",
                "Invoice line total does not reconcile to quantity and unit price.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        invoiced_quantity_by_po_line[po_line.line_ref] = (
            invoiced_quantity_by_po_line.get(po_line.line_ref, Decimal("0"))
            + invoice_line.quantity_invoiced
        )
        invoiced_total_by_po_line[po_line.line_ref] = (
            invoiced_total_by_po_line.get(po_line.line_ref, Decimal("0"))
            + invoice_line.line_total
        )

    invoice_line_sum = sum(
        (item.line_total for item in invoice.lines),
        Decimal("0"),
    )
    if not _within_tolerance(
        invoice.subtotal,
        invoice_line_sum,
        ratio=inputs.policy.document_total_tolerance_ratio,
        absolute=inputs.policy.absolute_amount_tolerance,
    ):
        add(
            "invoice_subtotal_line_sum_mismatch",
            "invoice",
            "blocking",
            "Invoice subtotal does not reconcile to its line totals.",
            document_ref=invoice.supplier_invoice_ref,
        )
    if not _within_tolerance(
        invoice.total,
        invoice.subtotal + invoice.tax_total,
        ratio=inputs.policy.document_total_tolerance_ratio,
        absolute=inputs.policy.absolute_amount_tolerance,
    ):
        add(
            "invoice_total_arithmetic_mismatch",
            "invoice",
            "blocking",
            "Invoice total does not reconcile to subtotal plus tax.",
            document_ref=invoice.supplier_invoice_ref,
        )

    line_results: list[PurchaseToPayLineResult] = []
    accepted_value = Decimal("0")
    expected_invoice_subtotal = Decimal("0")
    for po_line in sorted(purchase_order.lines, key=lambda item: item.line_ref):
        accepted = accepted_by_po_line.get(po_line.line_ref, Decimal("0"))
        invoiced = invoiced_quantity_by_po_line.get(
            po_line.line_ref,
            Decimal("0"),
        )
        actual_line_total = invoiced_total_by_po_line.get(
            po_line.line_ref,
            Decimal("0"),
        )
        expected_line_total = invoiced * po_line.unit_price
        accepted_value += accepted * po_line.unit_price
        expected_invoice_subtotal += expected_line_total
        invoice_unit_price = actual_line_total / invoiced if invoiced > 0 else None
        receipt_evidence_present = po_line.line_ref in receipt_observed_po_lines

        if not receipt_evidence_present and (
            invoiced > 0 or inputs.policy.require_full_order_receipt
        ):
            add(
                "missing_goods_receipt_for_purchase_order_line",
                "three_way_match",
                "blocking",
                "No eligible goods-receipt line supports this purchase-order line; "
                "accepted quantity was not inferred.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )

        if (
            receipt_evidence_present
            and accepted > po_line.quantity_ordered
            and not _within_tolerance(
                accepted,
                po_line.quantity_ordered,
                ratio=inputs.policy.allowed_over_receipt_ratio,
            )
        ):
            add(
                "accepted_quantity_exceeds_purchase_order",
                "three_way_match",
                "blocking",
                "Accepted receipt quantity exceeds the purchase-order quantity.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
        if (
            inputs.policy.require_full_order_receipt
            and receipt_evidence_present
            and accepted < po_line.quantity_ordered
            and not _within_tolerance(
                accepted,
                po_line.quantity_ordered,
                ratio=inputs.policy.quantity_tolerance_ratio,
            )
        ):
            add(
                "purchase_order_not_fully_received",
                "three_way_match",
                "blocking",
                "Purchase-order line is not fully received under the active policy.",
                document_ref=purchase_order.purchase_order_ref,
                line_ref=po_line.line_ref,
            )
        if (
            receipt_evidence_present
            and invoiced > accepted
            and not _within_tolerance(
                invoiced,
                accepted,
                ratio=inputs.policy.quantity_tolerance_ratio,
            )
        ):
            add(
                "invoice_quantity_exceeds_accepted_receipt",
                "three_way_match",
                "blocking",
                "Invoiced quantity exceeds accepted goods-receipt quantity.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        if invoiced > po_line.quantity_ordered and not _within_tolerance(
            invoiced,
            po_line.quantity_ordered,
            ratio=inputs.policy.quantity_tolerance_ratio,
        ):
            add(
                "invoice_quantity_exceeds_purchase_order",
                "three_way_match",
                "blocking",
                "Invoiced quantity exceeds the purchase-order quantity.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        if invoice_unit_price is not None and not _within_tolerance(
            invoice_unit_price,
            po_line.unit_price,
            ratio=inputs.policy.unit_price_tolerance_ratio,
            absolute=inputs.policy.absolute_amount_tolerance,
        ):
            add(
                "invoice_unit_price_variance",
                "three_way_match",
                "blocking",
                "Invoice unit price is outside the purchase-order tolerance.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )
        if invoiced > 0 and not _within_tolerance(
            actual_line_total,
            expected_line_total,
            ratio=inputs.policy.line_total_tolerance_ratio,
            absolute=inputs.policy.absolute_amount_tolerance,
        ):
            add(
                "invoice_line_total_variance",
                "three_way_match",
                "blocking",
                "Invoice line total is outside the purchase-order tolerance.",
                document_ref=invoice.supplier_invoice_ref,
                line_ref=po_line.line_ref,
            )

        line_findings = [
            finding for finding in findings if finding.line_ref == po_line.line_ref
        ]
        line_codes = tuple(sorted({item.code for item in line_findings}))
        if invoiced == 0:
            line_status: PurchaseToPayLineStatus = "not_invoiced"
        elif any(
            item.severity == "blocking" and item.code not in _INDETERMINATE_CODES
            for item in line_findings
        ):
            line_status = "exception"
        elif any(item.code in _INDETERMINATE_CODES for item in line_findings):
            line_status = "indeterminate"
        elif line_findings:
            line_status = "exception"
        else:
            line_status = "matched"
        line_results.append(
            PurchaseToPayLineResult(
                purchase_order_line_ref=po_line.line_ref,
                requisition_line_ref=po_line.requisition_line_ref,
                item_ref=po_line.item_ref,
                unit_of_measure=po_line.unit_of_measure,
                quantity_ordered=po_line.quantity_ordered,
                quantity_accepted=accepted,
                quantity_invoiced=invoiced,
                receipt_evidence_present=receipt_evidence_present,
                purchase_order_unit_price=po_line.unit_price,
                invoice_unit_price=invoice_unit_price,
                expected_invoice_line_total=expected_line_total,
                actual_invoice_line_total=actual_line_total,
                price_variance_ratio=(
                    _difference_ratio(invoice_unit_price, po_line.unit_price)
                    if invoice_unit_price is not None
                    else None
                ),
                total_variance_ratio=(
                    _difference_ratio(actual_line_total, expected_line_total)
                    if invoiced > 0
                    else None
                ),
                accepted_goods_receipt_refs=tuple(
                    sorted(
                        accepted_receipt_refs_by_po_line.get(
                            po_line.line_ref,
                            set(),
                        )
                    )
                ),
                trace_refs=tuple(
                    trace_ref
                    for _, trace_ref in sorted(
                        trace_refs_by_po_line.get(
                            po_line.line_ref,
                            {},
                        ).items()
                    )
                ),
                status=line_status,
                finding_codes=line_codes,
            )
        )

    if not _within_tolerance(
        invoice.subtotal,
        expected_invoice_subtotal,
        ratio=inputs.policy.document_total_tolerance_ratio,
        absolute=inputs.policy.absolute_amount_tolerance,
    ):
        add(
            "invoice_subtotal_purchase_order_variance",
            "three_way_match",
            "blocking",
            "Invoice subtotal is outside the purchase-order price tolerance.",
            document_ref=invoice.supplier_invoice_ref,
        )

    gates: list[PurchaseToPayGateResult] = []
    for gate in _GATE_ORDER:
        gate_findings = [item for item in findings if item.gate == gate]
        codes = tuple(sorted({item.code for item in gate_findings}))
        if any(
            item.severity == "blocking" and item.code not in _INDETERMINATE_CODES
            for item in gate_findings
        ):
            status = "fail"
        elif any(item.code in _INDETERMINATE_CODES for item in gate_findings):
            status: ControlGateStatus = "indeterminate"
        elif any(item.severity == "review" for item in gate_findings):
            status = "review"
        else:
            status = "pass"
        gates.append(
            PurchaseToPayGateResult(
                gate=gate,
                status=status,
                finding_codes=codes,
            )
        )

    if any(item.status == "fail" for item in gates):
        disposition: PurchaseToPayDisposition = "blocked"
    elif any(item.status == "indeterminate" for item in gates):
        disposition = "indeterminate"
    elif any(item.status == "review" for item in gates):
        disposition = "manual_review_required"
    else:
        disposition = "eligible_for_payment_approval"

    source_snapshot_digests = {
        "invoice": _model_digest(invoice),
        "policy": _model_digest(inputs.policy),
        "purchase_order": _model_digest(purchase_order),
        "requisition": _model_digest(requisition),
        "vendor": _model_digest(vendor),
    }
    source_snapshot_digests.update(
        {
            f"goods_receipt:{receipt.goods_receipt_ref}": _model_digest(receipt)
            for receipt in sorted(
                inputs.goods_receipts,
                key=lambda item: item.goods_receipt_ref,
            )
        }
    )
    all_evidence = [
        evidence for _, _, evidence_refs in evidence_sets for evidence in evidence_refs
    ]
    evidence_ref_names = tuple(sorted({item.evidence_ref for item in all_evidence}))
    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                _GATE_ORDER.index(item.gate),
                item.document_ref or "",
                item.line_ref or "",
                item.code,
            ),
        )
    )
    result = PurchaseToPayControlsResult(
        control_ref=inputs.control_ref,
        analysis_as_of=inputs.analysis_as_of,
        assurance_grade=assurance_grade,
        proposed_disposition=disposition,
        gates=tuple(gates),
        line_results=tuple(line_results),
        findings=ordered_findings,
        purchase_order_total=purchase_order_total,
        accepted_value_at_purchase_order_price=accepted_value,
        expected_invoice_subtotal=expected_invoice_subtotal,
        actual_invoice_subtotal=invoice.subtotal,
        source_snapshot_digests=source_snapshot_digests,
        evidence_refs=evidence_ref_names,
    )
    return result


def _example_evidence(evidence_ref: str, digest_character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": "normalized_procurement_snapshot",
        "issuer_ref": "spring-procurement-authority",
        "sha256": digest_character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "confidential",
        "retention_policy": "finance-seven-years",
        "jurisdiction": "US",
    }


class EvaluatePurchaseToPayControlsPrimitive(
    BusinessProcessPrimitive[PurchaseToPayControlsInput, PurchaseToPayControlsResult]
):
    primitive_ref = "procurement.evaluate_purchase_to_pay_controls"
    version = "1.0.0"
    title = "Evaluate purchase-to-pay controls"
    description = (
        "Evaluate evidence-bound vendor, requisition, purchase-order, goods-receipt, "
        "and supplier-invoice controls without authorizing payment or changing stock."
    )
    input_model = PurchaseToPayControlsInput
    output_model = PurchaseToPayControlsResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "control_ref": "p2p-control-1042",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "vendor": {
            "vendor_ref": "vendor-example",
            "status": "qualified",
            "policy_ref": "vendor-policy-v1",
            "qualified_at": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "evidence_refs": [_example_evidence("vendor-evidence", "a")],
        },
        "requisition": {
            "requisition_ref": "req-1042",
            "revision": 1,
            "status": "approved",
            "currency": "USD",
            "approved_budget_amount": "1000.0000",
            "vendor_ref": "vendor-example",
            "approval_ref": "approval-req-1042",
            "approved_at": "2026-08-19T00:00:00Z",
            "lines": [
                {
                    "line_ref": "req-line-1",
                    "item_ref": "item-widget",
                    "quantity_requested": "10.000000",
                    "unit_of_measure": "EA",
                    "estimated_unit_price": "100.0000",
                }
            ],
            "evidence_refs": [_example_evidence("requisition-evidence", "b")],
        },
        "purchase_order": {
            "purchase_order_ref": "po-1042",
            "revision": 1,
            "requisition_ref": "req-1042",
            "vendor_ref": "vendor-example",
            "status": "issued",
            "currency": "USD",
            "issued_at": "2026-08-20T00:00:00Z",
            "approval_ref": "approval-po-1042",
            "lines": [
                {
                    "line_ref": "po-line-1",
                    "requisition_line_ref": "req-line-1",
                    "item_ref": "item-widget",
                    "quantity_ordered": "10.000000",
                    "unit_of_measure": "EA",
                    "unit_price": "100.0000",
                }
            ],
            "evidence_refs": [_example_evidence("purchase-order-evidence", "c")],
        },
        "goods_receipts": [
            {
                "goods_receipt_ref": "gr-1042",
                "revision": 1,
                "purchase_order_ref": "po-1042",
                "vendor_ref": "vendor-example",
                "status": "posted",
                "received_at": "2026-08-23T00:00:00Z",
                "receiving_location_ref": "warehouse-east",
                "lines": [
                    {
                        "line_ref": "gr-line-1",
                        "purchase_order_line_ref": "po-line-1",
                        "item_ref": "item-widget",
                        "quantity_received": "10.000000",
                        "quantity_accepted": "10.000000",
                        "quantity_rejected": "0.000000",
                        "unit_of_measure": "EA",
                        "trace_refs": [{"kind": "lot", "trace_ref": "lot-2026-08-a"}],
                    }
                ],
                "evidence_refs": [_example_evidence("receipt-evidence", "d")],
            }
        ],
        "supplier_invoice": {
            "supplier_invoice_ref": "invoice-1042",
            "revision": 1,
            "invoice_number": "INV-1042",
            "vendor_ref": "vendor-example",
            "purchase_order_ref": "po-1042",
            "status": "validated",
            "duplicate_check": "clear",
            "currency": "USD",
            "invoice_date": "2026-08-23T00:00:00Z",
            "subtotal": "1000.0000",
            "tax_total": "0.0000",
            "total": "1000.0000",
            "lines": [
                {
                    "line_ref": "invoice-line-1",
                    "purchase_order_line_ref": "po-line-1",
                    "item_ref": "item-widget",
                    "quantity_invoiced": "10.000000",
                    "unit_of_measure": "EA",
                    "unit_price": "100.0000",
                    "line_total": "1000.0000",
                }
            ],
            "evidence_refs": [_example_evidence("invoice-evidence", "e")],
        },
        "policy": {
            "minimum_evidence_grade": "attested",
            "max_evidence_age_hours": 168,
        },
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PURCHASE_TO_PAY_CONTROLS_OPERATION.to_dict()
        contract["capability_hints"] = [
            "quickbooks.list_vendors",
            "quickbooks.list_purchase_orders",
            "quickbooks.list_bills",
            "xero.list_contacts",
            "xero.list_purchase_orders",
            "xero.list_invoices",
        ]
        contract["capability_hints_are_dispatch_authority"] = False
        contract["effect_boundary"] = ProcurementEffectBoundary().to_dict()
        contract["goods_receipt_authority"] = "trusted_host_required"
        contract["authority_boundary"] = {
            "sdk": "deterministic_control_evaluation_only",
            "spring": [
                "tenant_and_company_scope",
                "rbac",
                "source_normalization",
                "approval_authority",
                "persistence_and_audit",
            ],
            "connectors": "provider_reads_and_writes_via_trusted_host_only",
            "payment_authority": "never_granted_by_this_primitive",
            "inventory_authority": "never_granted_by_this_primitive",
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
        inputs: PurchaseToPayControlsInput,
    ) -> PrimitiveExecutionResult[PurchaseToPayControlsResult]:
        del context
        output = evaluate_purchase_to_pay_controls(inputs)
        evidence_by_ref = {
            evidence.evidence_ref: evidence
            for evidence_group in (
                inputs.vendor.evidence_refs,
                inputs.requisition.evidence_refs,
                inputs.purchase_order.evidence_refs,
                inputs.supplier_invoice.evidence_refs,
                *(receipt.evidence_refs for receipt in inputs.goods_receipts),
            )
            for evidence in evidence_group
        }
        evidence_refs = [
            evidence_by_ref[evidence_ref] for evidence_ref in sorted(evidence_by_ref)
        ]
        receipt = PrimitiveOperationReceipt(
            spec=PURCHASE_TO_PAY_CONTROLS_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=_model_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[PurchaseToPayControlsResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Purchase-to-pay controls evaluated; the result is a payment "
                f"approval proposal with disposition {output.proposed_disposition}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="procurement.purchase_to_pay_controls_evaluated",
                    payload={
                        "control_ref": output.control_ref,
                        "proposed_disposition": output.proposed_disposition,
                        "assurance_grade": output.assurance_grade.value,
                        "finding_count": len(output.findings),
                        "payment_authorized": False,
                        "live_systems_changed": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="purchase_to_pay_control_result",
                    summary=(
                        "The SDK evaluated normalized procurement evidence without "
                        "calling a connector, approving payment, or changing inventory."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "GOODS_RECEIPT_SNAPSHOT_SCHEMA",
    "PURCHASE_ORDER_SNAPSHOT_SCHEMA",
    "PURCHASE_REQUISITION_SNAPSHOT_SCHEMA",
    "PURCHASE_TO_PAY_CONTROLS_INPUT_SCHEMA",
    "PURCHASE_TO_PAY_CONTROLS_RESULT_SCHEMA",
    "PURCHASE_TO_PAY_CONTROLS_OPERATION",
    "SUPPLIER_INVOICE_SNAPSHOT_SCHEMA",
    "VENDOR_QUALIFICATION_SNAPSHOT_SCHEMA",
    "EvaluatePurchaseToPayControlsPrimitive",
    "GoodsReceiptLine",
    "GoodsReceiptSnapshot",
    "ProcurementMaterialTraceRef",
    "ProcurementEffectBoundary",
    "PurchaseOrderLine",
    "PurchaseOrderSnapshot",
    "PurchaseRequisitionLine",
    "PurchaseRequisitionSnapshot",
    "PurchaseToPayControlPolicy",
    "PurchaseToPayControlsInput",
    "PurchaseToPayControlsResult",
    "PurchaseToPayFinding",
    "PurchaseToPayGateResult",
    "PurchaseToPayLineResult",
    "SupplierInvoiceLine",
    "SupplierInvoiceSnapshot",
    "VendorQualificationSnapshot",
    "evaluate_purchase_to_pay_controls",
    "procurement_snapshot_digest",
]
