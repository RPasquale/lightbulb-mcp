"""Deterministic, Spring-authoritative procure-to-pay lifecycle contracts.

The SDK validates and content-binds the lifecycle from requisition through
closure.  It never persists a transition and never calls a connector.  Every
state change is first emitted as an approval-gated proposal.  Only a caller at
the Spring Control Plane's locked, authenticated boundary may supply the live
aggregate and verified authority evidence to :func:`validate_transition_evidence`.

``validate_transition_evidence`` produces only a locally validated candidate;
it does not make caller-authored evidence authoritative or persist that
candidate.  Spring remains responsible for RBAC, approval custody, idempotency
persistence, audit, and any later provider execution.  The semantic operation
name below describes that boundary and is not a claim that a provider Connector
Tool exists.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Mapping, Union
from uuid import UUID

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
    PrimitiveBlocker,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveEvent,
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


PROCURE_TO_PAY_SCOPE_SCHEMA = "lightbulb.procure_to_pay_scope.v1"
PROCURE_TO_PAY_LIFECYCLE_SCHEMA = "lightbulb.procure_to_pay_lifecycle.v1"
PROCURE_TO_PAY_TRANSITION_REQUEST_SCHEMA = (
    "lightbulb.procure_to_pay_transition_request.v1"
)
PROCURE_TO_PAY_TRANSITION_PROPOSAL_SCHEMA = (
    "lightbulb.procure_to_pay_transition_proposal.v1"
)
PROCURE_TO_PAY_PROPOSAL_RESULT_SCHEMA = "lightbulb.procure_to_pay_proposal_result.v1"
SPRING_TRANSITION_EVIDENCE_SCHEMA = (
    "lightbulb.spring_procure_to_pay_transition_evidence.v1"
)
PROCURE_TO_PAY_TRANSITION_VALIDATION_RESULT_SCHEMA = (
    "lightbulb.procure_to_pay_transition_validation_result.v1"
)

SPRING_PROCUREMENT_TRANSITION_OPERATION = "procurement.lifecycle_transition"
ZERO_DIGEST = "0" * 64

_MAX_LINES = 250
_MAX_RECEIPTS = 100
_MAX_EVIDENCE_REFS = 20
_MAX_FINDINGS = 500
_MAX_TRANSITIONS = 128
_MONEY_QUANTUM = Decimal("0.01")
_QUANTITY_QUANTUM = Decimal("0.000001")
_MAX_MONEY = Decimal("999999999999.99")
_MAX_QUANTITY = Decimal("999999999999.999999")
_MAX_AGGREGATE_QUANTITY = _MAX_QUANTITY * _MAX_LINES
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError(
            "references must contain visible characters without whitespace"
        )
    return value


def _bounded_text(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("text must be trimmed and contain no control characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
    AfterValidator(_bounded_text),
]
UnitCode = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,31}$"),
]


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
    return tuple(value) if isinstance(value, list) else value


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(
    value: Any,
    *,
    quantum: Decimal,
    maximum: Decimal,
    field_name: str,
) -> Decimal:
    if isinstance(value, (bool, float)) or not isinstance(value, (str, int, Decimal)):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError(f"{field_name} must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a finite bounded decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed > maximum:
        raise ValueError(f"{field_name} is outside the supported range")
    if parsed != normalized:
        places = -quantum.as_tuple().exponent
        raise ValueError(f"{field_name} supports at most {places} decimal places")
    return normalized


def _money(value: Any, *, field_name: str = "money") -> Decimal:
    return _decimal(
        value,
        quantum=_MONEY_QUANTUM,
        maximum=_MAX_MONEY,
        field_name=field_name,
    )


def _quantity(value: Any, *, field_name: str = "quantity") -> Decimal:
    return _decimal(
        value,
        quantum=_QUANTITY_QUANTUM,
        maximum=_MAX_QUANTITY,
        field_name=field_name,
    )


def _aggregate_quantity(value: Any, *, field_name: str) -> Decimal:
    return _decimal(
        value,
        quantum=_QUANTITY_QUANTUM,
        maximum=_MAX_AGGREGATE_QUANTITY,
        field_name=field_name,
    )


def _exact_line_total(quantity: Decimal, unit_price: Decimal) -> Decimal:
    return _money(quantity * unit_price, field_name="calculated line total")


def _unique_refs(values: tuple[Any, ...], *, field_name: str) -> None:
    refs = [str(getattr(item, field_name)) for item in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{field_name} values must be unique")


def _evidence_set_digest(values: tuple[PrimitiveEvidenceRef, ...]) -> str:
    return _stable_digest(
        [
            item.model_dump(mode="json", by_alias=True, exclude_none=True)
            for item in sorted(values, key=lambda evidence: evidence.evidence_ref)
        ]
    )


def _validate_unique_evidence(values: tuple[PrimitiveEvidenceRef, ...]) -> None:
    refs = [item.evidence_ref for item in values]
    if len(refs) != len(set(refs)):
        raise ValueError("evidence_ref values must be unique")


class ProcureToPayScope(_StrictModel):
    """Exact authenticated scope that Spring must derive, never a policy grant."""

    schema_id: Literal["lightbulb.procure_to_pay_scope.v1"] = Field(
        default=PROCURE_TO_PAY_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    account_ref: OpaqueRef

    @field_validator("project_id", mode="before")
    @classmethod
    def _project_id(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                return UUID(value)
            except ValueError as exc:
                raise ValueError("project_id must be a valid UUID") from exc
        return value

    @property
    def scope_digest(self) -> str:
        return _stable_digest(self.to_dict())


class RequisitionLine(_StrictModel):
    line_ref: OpaqueRef
    item_ref: OpaqueRef
    description: ShortText
    quantity_requested: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    estimated_unit_price: Decimal = Field(ge=0)
    line_total: Decimal = Field(ge=0)
    cost_center_ref: OpaqueRef

    @field_validator("quantity_requested", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, field_name="quantity_requested")

    @field_validator("estimated_unit_price", "line_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _total_is_exact(self) -> "RequisitionLine":
        if self.line_total != _exact_line_total(
            self.quantity_requested, self.estimated_unit_price
        ):
            raise ValueError(
                "requisition line_total must equal quantity times unit price"
            )
        return self


class PurchaseRequisition(_StrictModel):
    requisition_ref: OpaqueRef
    status: Literal["draft", "submitted", "approved"]
    currency: CurrencyCode
    vendor_ref: OpaqueRef
    budget_ref: OpaqueRef
    budget_amount: Decimal = Field(gt=0)
    total_amount: Decimal = Field(gt=0)
    lines: tuple[RequisitionLine, ...] = Field(
        min_length=1,
        max_length=_MAX_LINES,
    )

    @field_validator("budget_amount", "total_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _totals_and_refs_are_exact(self) -> "PurchaseRequisition":
        _unique_refs(self.lines, field_name="line_ref")
        calculated = sum((line.line_total for line in self.lines), Decimal("0.00"))
        if calculated != self.total_amount:
            raise ValueError("requisition total_amount must equal its line totals")
        if self.total_amount > self.budget_amount:
            raise ValueError("requisition total_amount exceeds the bound budget")
        return self


class PurchaseOrderLine(_StrictModel):
    line_ref: OpaqueRef
    requisition_line_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_ordered: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    unit_price: Decimal = Field(ge=0)
    line_total: Decimal = Field(ge=0)

    @field_validator("quantity_ordered", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, field_name="quantity_ordered")

    @field_validator("unit_price", "line_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _total_is_exact(self) -> "PurchaseOrderLine":
        if self.line_total != _exact_line_total(self.quantity_ordered, self.unit_price):
            raise ValueError(
                "purchase-order line_total must equal quantity times unit price"
            )
        return self


class PurchaseOrder(_StrictModel):
    purchase_order_ref: OpaqueRef
    requisition_ref: OpaqueRef
    vendor_ref: OpaqueRef
    status: Literal[
        "draft",
        "issued",
        "partially_received",
        "received",
        "matched",
        "match_exception",
        "closed",
    ]
    currency: CurrencyCode
    total_amount: Decimal = Field(gt=0)
    issued_at: str | None = None
    lines: tuple[PurchaseOrderLine, ...] = Field(
        min_length=1,
        max_length=_MAX_LINES,
    )

    @field_validator("total_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _money(value, field_name="total_amount")

    @field_validator("issued_at")
    @classmethod
    def _issued_at(cls, value: str | None) -> str | None:
        return (
            None
            if value is None
            else _normalized_timestamp(value, field_name="issued_at")
        )

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _totals_and_status_are_exact(self) -> "PurchaseOrder":
        _unique_refs(self.lines, field_name="line_ref")
        _unique_refs(self.lines, field_name="requisition_line_ref")
        calculated = sum((line.line_total for line in self.lines), Decimal("0.00"))
        if calculated != self.total_amount:
            raise ValueError("purchase-order total_amount must equal its line totals")
        if self.status == "draft" and self.issued_at is not None:
            raise ValueError("a draft purchase order cannot have issued_at")
        if self.status != "draft" and self.issued_at is None:
            raise ValueError("an issued purchase order requires issued_at")
        return self


class GoodsReceiptLine(_StrictModel):
    line_ref: OpaqueRef
    purchase_order_line_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_received: Decimal = Field(gt=0)
    quantity_accepted: Decimal = Field(ge=0)
    quantity_rejected: Decimal = Field(ge=0)
    unit_of_measure: UnitCode

    @field_validator(
        "quantity_received",
        "quantity_accepted",
        "quantity_rejected",
        mode="before",
    )
    @classmethod
    def _quantities(cls, value: Any, info: Any) -> Decimal:
        return _quantity(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _quantities_reconcile(self) -> "GoodsReceiptLine":
        if self.quantity_accepted + self.quantity_rejected != self.quantity_received:
            raise ValueError(
                "accepted plus rejected quantity must equal received quantity"
            )
        return self


class GoodsReceipt(_StrictModel):
    goods_receipt_ref: OpaqueRef
    purchase_order_ref: OpaqueRef
    vendor_ref: OpaqueRef
    receiving_location_ref: OpaqueRef
    received_at: str
    lines: tuple[GoodsReceiptLine, ...] = Field(
        min_length=1,
        max_length=_MAX_LINES,
    )

    @field_validator("received_at")
    @classmethod
    def _received_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="received_at")

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _line_refs_are_unique(self) -> "GoodsReceipt":
        _unique_refs(self.lines, field_name="line_ref")
        _unique_refs(self.lines, field_name="purchase_order_line_ref")
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
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, field_name="quantity_invoiced")

    @field_validator("unit_price", "line_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _total_is_exact(self) -> "SupplierInvoiceLine":
        if self.line_total != _exact_line_total(
            self.quantity_invoiced, self.unit_price
        ):
            raise ValueError("invoice line_total must equal quantity times unit price")
        return self


class SupplierInvoice(_StrictModel):
    supplier_invoice_ref: OpaqueRef
    invoice_number: ShortText
    purchase_order_ref: OpaqueRef
    vendor_ref: OpaqueRef
    currency: CurrencyCode
    invoice_date: str
    duplicate_check: Literal["clear", "possible_duplicate", "confirmed_duplicate"]
    subtotal: Decimal = Field(ge=0)
    tax_total: Decimal = Field(ge=0)
    total: Decimal = Field(gt=0)
    lines: tuple[SupplierInvoiceLine, ...] = Field(
        min_length=1,
        max_length=_MAX_LINES,
    )

    @field_validator("invoice_date")
    @classmethod
    def _invoice_date(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="invoice_date")

    @field_validator("subtotal", "tax_total", "total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @field_validator("lines", mode="before")
    @classmethod
    def _lines(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _totals_are_exact(self) -> "SupplierInvoice":
        _unique_refs(self.lines, field_name="line_ref")
        _unique_refs(self.lines, field_name="purchase_order_line_ref")
        subtotal = sum((line.line_total for line in self.lines), Decimal("0.00"))
        if subtotal != self.subtotal:
            raise ValueError("invoice subtotal must equal its line totals")
        if self.subtotal + self.tax_total != self.total:
            raise ValueError("invoice total must equal subtotal plus tax")
        return self


class ThreeWayMatchPolicy(_StrictModel):
    quantity_tolerance: Decimal = Decimal("0.000000")
    unit_price_tolerance: Decimal = Decimal("0.00")
    subtotal_tolerance: Decimal = Decimal("0.00")

    @field_validator("quantity_tolerance", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, field_name="quantity_tolerance")

    @field_validator("unit_price_tolerance", "subtotal_tolerance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)


class ThreeWayMatchFinding(_StrictModel):
    code: OpaqueRef
    message: ShortText
    purchase_order_line_ref: OpaqueRef | None = None


class ThreeWayMatchResult(_StrictModel):
    match_ref: OpaqueRef
    disposition: Literal["matched", "exception"]
    purchase_order_ref: OpaqueRef
    supplier_invoice_ref: OpaqueRef
    evaluated_at: str
    accepted_quantity_total: Decimal = Field(ge=0)
    invoiced_quantity_total: Decimal = Field(ge=0)
    expected_subtotal: Decimal = Field(ge=0)
    invoice_subtotal: Decimal = Field(ge=0)
    policy: ThreeWayMatchPolicy
    findings: tuple[ThreeWayMatchFinding, ...] = Field(max_length=_MAX_FINDINGS)
    evaluation_digest: Sha256Digest

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="evaluated_at")

    @field_validator(
        "accepted_quantity_total", "invoiced_quantity_total", mode="before"
    )
    @classmethod
    def _quantity(cls, value: Any, info: Any) -> Decimal:
        return _aggregate_quantity(value, field_name=info.field_name)

    @field_validator("expected_subtotal", "invoice_subtotal", mode="before")
    @classmethod
    def _money(cls, value: Any, info: Any) -> Decimal:
        return _money(value, field_name=info.field_name)

    @field_validator("findings", mode="before")
    @classmethod
    def _findings(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _disposition_matches_findings(self) -> "ThreeWayMatchResult":
        if (self.disposition == "matched") != (not self.findings):
            raise ValueError("three-way match disposition must match its findings")
        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_digest"},
        )
        if self.evaluation_digest != _stable_digest(digest_payload):
            raise ValueError("three-way match evaluation_digest does not match")
        return self


class ExceptionResolution(_StrictModel):
    resolution_ref: OpaqueRef
    disposition: Literal["approve_override", "cancel_and_close"]
    rationale: ShortText
    resolved_at: str

    @field_validator("resolved_at")
    @classmethod
    def _resolved_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="resolved_at")


class ProcureToPayClosure(_StrictModel):
    closure_ref: OpaqueRef
    closed_at: str

    @field_validator("closed_at")
    @classmethod
    def _closed_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="closed_at")


ProcureToPayState = Literal[
    "requisition_draft",
    "requisition_pending_approval",
    "requisition_approved",
    "purchase_order_pending_approval",
    "purchase_order_issued",
    "partially_received",
    "fully_received",
    "matched",
    "exception",
    "closed",
]


class ProcureToPayTransitionRecord(_StrictModel):
    transition_index: int = Field(ge=1, le=_MAX_TRANSITIONS)
    operation: OpaqueRef
    idempotency_key: OpaqueRef
    intent_digest: Sha256Digest
    proposal_digest: Sha256Digest
    requested_by_ref: OpaqueRef
    authority_ref: OpaqueRef
    approved_by_ref: OpaqueRef
    approval_ref: OpaqueRef
    approval_receipt_digest: Sha256Digest
    authority_receipt_digest: Sha256Digest
    supporting_evidence_digest: Sha256Digest
    authority_evidence_digest: Sha256Digest
    committed_at: str

    @field_validator("committed_at")
    @classmethod
    def _committed_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="committed_at")


class ProcureToPayLifecycle(_StrictModel):
    schema_id: Literal["lightbulb.procure_to_pay_lifecycle.v1"] = Field(
        default=PROCURE_TO_PAY_LIFECYCLE_SCHEMA,
        alias="schema",
    )
    lifecycle_ref: OpaqueRef
    revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    scope: ProcureToPayScope
    state: ProcureToPayState
    requisition: PurchaseRequisition
    purchase_order: PurchaseOrder | None = None
    goods_receipts: tuple[GoodsReceipt, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_RECEIPTS,
    )
    supplier_invoice: SupplierInvoice | None = None
    three_way_match: ThreeWayMatchResult | None = None
    exception_resolution: ExceptionResolution | None = None
    closure: ProcureToPayClosure | None = None
    updated_at: str
    transition_history: tuple[ProcureToPayTransitionRecord, ...] = Field(
        min_length=1,
        max_length=_MAX_TRANSITIONS,
    )
    domain_digest: Sha256Digest
    state_digest: Sha256Digest

    @field_validator("updated_at")
    @classmethod
    def _updated_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="updated_at")

    @field_validator("goods_receipts", "transition_history", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _aggregate_is_consistent(self) -> "ProcureToPayLifecycle":
        if self.revision != len(self.transition_history):
            raise ValueError(
                "revision must equal the number of authoritative transitions"
            )
        if tuple(
            record.transition_index for record in self.transition_history
        ) != tuple(range(1, self.revision + 1)):
            raise ValueError("transition indexes must be contiguous")
        authority_identity_fields = (
            "idempotency_key",
            "proposal_digest",
            "approval_ref",
            "approval_receipt_digest",
            "authority_receipt_digest",
            "authority_evidence_digest",
        )
        for field_name in authority_identity_fields:
            values = [getattr(record, field_name) for record in self.transition_history]
            if len(values) != len(set(values)):
                raise ValueError(
                    "transition history cannot reuse idempotency, proposal, approval, "
                    "or authority evidence identifiers"
                )
        committed_times = [
            _parsed_timestamp(record.committed_at) for record in self.transition_history
        ]
        if committed_times != sorted(committed_times):
            raise ValueError("transition commit times must be monotonic")
        if _parsed_timestamp(self.updated_at) > committed_times[-1]:
            raise ValueError("lifecycle update time cannot exceed its latest commit")
        receipt_refs = [receipt.goods_receipt_ref for receipt in self.goods_receipts]
        if len(receipt_refs) != len(set(receipt_refs)):
            raise ValueError("goods receipt references must be unique")
        self._validate_state_documents()
        self._validate_operation_history()

        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        domain_payload = dict(payload)
        for key in ("transition_history", "domain_digest", "state_digest"):
            domain_payload.pop(key, None)
        expected_domain = _stable_digest(domain_payload)
        if self.domain_digest != expected_domain:
            raise ValueError("domain_digest does not match the lifecycle snapshot")
        state_payload = dict(payload)
        state_payload.pop("state_digest", None)
        if self.state_digest != _stable_digest(state_payload):
            raise ValueError(
                "state_digest does not match lifecycle and authority history"
            )
        return self

    def _validate_operation_history(self) -> None:
        operations = [record.operation for record in self.transition_history]
        expected = ["create_requisition"]
        if self.state != "requisition_draft":
            expected.append("submit_requisition")
        if self.state not in {
            "requisition_draft",
            "requisition_pending_approval",
        }:
            expected.append("approve_requisition")
        if self.state not in {
            "requisition_draft",
            "requisition_pending_approval",
            "requisition_approved",
        }:
            expected.append("create_purchase_order")
        downstream_states = {
            "purchase_order_issued",
            "partially_received",
            "fully_received",
            "matched",
            "exception",
            "closed",
        }
        if self.state in downstream_states:
            expected.append("issue_purchase_order")
        receipt_states = {
            "partially_received",
            "fully_received",
            "matched",
            "exception",
            "closed",
        }
        if self.state in receipt_states:
            expected.extend("record_goods_receipt" for _ in self.goods_receipts)
        if self.state in {"matched", "exception", "closed"}:
            expected.append("evaluate_three_way_match")
        if self.exception_resolution is not None:
            expected.append("resolve_match_exception")
        if self.closure is not None:
            expected.append("close")
        if operations != expected:
            raise ValueError(
                "transition history operations do not match the lifecycle state and documents"
            )

    def _validate_state_documents(self) -> None:
        req_status = {
            "requisition_draft": "draft",
            "requisition_pending_approval": "submitted",
        }.get(self.state, "approved")
        if self.requisition.status != req_status:
            raise ValueError("requisition status does not match lifecycle state")
        pre_po_states = {
            "requisition_draft",
            "requisition_pending_approval",
            "requisition_approved",
        }
        if self.exception_resolution is not None:
            override_state = (
                self.state in {"matched", "closed"}
                and self.exception_resolution.disposition == "approve_override"
            )
            cancelled_state = (
                self.state == "closed"
                and self.exception_resolution.disposition == "cancel_and_close"
            )
            if (
                self.three_way_match is None
                or self.three_way_match.disposition != "exception"
                or not (override_state or cancelled_state)
            ):
                raise ValueError(
                    "exception resolution does not match the resolved lifecycle state"
                )
        if self.state != "closed" and self.closure is not None:
            raise ValueError("closure evidence is allowed only in the closed state")
        if (self.state in pre_po_states) != (self.purchase_order is None):
            raise ValueError("purchase-order presence does not match lifecycle state")
        if self.purchase_order is None:
            if self.goods_receipts or self.supplier_invoice or self.three_way_match:
                raise ValueError("downstream documents require a purchase order")
            return
        expected_po_status = {
            "purchase_order_pending_approval": "draft",
            "purchase_order_issued": "issued",
            "partially_received": "partially_received",
            "fully_received": "received",
            "matched": "matched",
            "exception": "match_exception",
            "closed": "closed",
        }.get(self.state)
        if self.purchase_order.status != expected_po_status:
            raise ValueError("purchase-order status does not match lifecycle state")
        _validate_purchase_order(self.requisition, self.purchase_order)
        received, _ = _receipt_totals(self.purchase_order, self.goods_receipts)
        receipts_complete = all(
            received[line.line_ref] == line.quantity_ordered
            for line in self.purchase_order.lines
        )
        if (
            self.state
            in {
                "purchase_order_pending_approval",
                "purchase_order_issued",
            }
            and self.goods_receipts
        ):
            raise ValueError("goods receipts appear before the receiving state")
        if self.state == "partially_received" and (
            not self.goods_receipts or receipts_complete
        ):
            raise ValueError(
                "partially received state requires incomplete recorded receipts"
            )
        if self.state in {"fully_received", "matched", "exception", "closed"} and (
            not self.goods_receipts or not receipts_complete
        ):
            raise ValueError(
                "fully received and downstream states require complete receipts"
            )
        if self.goods_receipts:
            if self.purchase_order.issued_at is None or any(
                _parsed_timestamp(receipt.received_at)
                < _parsed_timestamp(self.purchase_order.issued_at)
                or _parsed_timestamp(receipt.received_at)
                > _parsed_timestamp(self.updated_at)
                for receipt in self.goods_receipts
            ):
                raise ValueError(
                    "goods receipts must follow order issue and not exceed lifecycle time"
                )
        if self.state in {"matched", "exception", "closed"}:
            if self.supplier_invoice is None or self.three_way_match is None:
                raise ValueError(
                    "matched, exception, and closed states require match evidence"
                )
        elif self.supplier_invoice is not None or self.three_way_match is not None:
            raise ValueError(
                "invoice and match result appear before three-way matching"
            )
        if self.supplier_invoice is not None and self.three_way_match is not None:
            recomputed_match = _three_way_match(
                match_ref=self.three_way_match.match_ref,
                evaluated_at=self.three_way_match.evaluated_at,
                purchase_order=self.purchase_order,
                receipts=self.goods_receipts,
                invoice=self.supplier_invoice,
                policy=self.three_way_match.policy,
            )
            if recomputed_match != self.three_way_match:
                raise ValueError(
                    "three-way match result does not match its bound documents and policy"
                )
            if any(
                _parsed_timestamp(receipt.received_at)
                > _parsed_timestamp(self.three_way_match.evaluated_at)
                for receipt in self.goods_receipts
            ) or _parsed_timestamp(
                self.three_way_match.evaluated_at
            ) > _parsed_timestamp(self.updated_at):
                raise ValueError(
                    "three-way match time must follow receipts and not exceed lifecycle time"
                )
        if self.exception_resolution is not None:
            if self.three_way_match is None or not (
                _parsed_timestamp(self.three_way_match.evaluated_at)
                <= _parsed_timestamp(self.exception_resolution.resolved_at)
                <= _parsed_timestamp(self.updated_at)
            ):
                raise ValueError(
                    "exception resolution time must follow matching and not exceed lifecycle time"
                )
            if (
                self.exception_resolution.disposition == "approve_override"
                and self.supplier_invoice is not None
                and self.supplier_invoice.duplicate_check == "confirmed_duplicate"
            ):
                raise ValueError(
                    "a confirmed duplicate supplier invoice cannot be overridden"
                )
        if self.closure is not None:
            prior_time = (
                self.exception_resolution.resolved_at
                if self.exception_resolution is not None
                else self.three_way_match.evaluated_at
                if self.three_way_match is not None
                else self.updated_at
            )
            if (
                _parsed_timestamp(self.closure.closed_at)
                < _parsed_timestamp(prior_time)
                or self.closure.closed_at != self.updated_at
            ):
                raise ValueError(
                    "closure time must follow resolution and equal lifecycle update time"
                )
        if self.state == "matched":
            override = (
                self.three_way_match is not None
                and self.three_way_match.disposition == "exception"
                and self.exception_resolution is not None
                and self.exception_resolution.disposition == "approve_override"
            )
            if self.three_way_match is not None and not (
                self.three_way_match.disposition == "matched" or override
            ):
                raise ValueError("matched state requires a passing or approved match")
        if self.state == "exception" and (
            self.three_way_match is None
            or self.three_way_match.disposition != "exception"
            or self.exception_resolution is not None
        ):
            raise ValueError("open exception state requires an unresolved failed match")
        if self.state == "closed" and self.three_way_match is not None:
            passed = self.three_way_match.disposition == "matched"
            override = (
                self.three_way_match.disposition == "exception"
                and self.exception_resolution is not None
                and self.exception_resolution.disposition == "approve_override"
            )
            cancelled = (
                self.three_way_match.disposition == "exception"
                and self.exception_resolution is not None
                and self.exception_resolution.disposition == "cancel_and_close"
            )
            if not (passed or override or cancelled):
                raise ValueError(
                    "closed state requires a passing match, approved override, or cancellation"
                )
            if (cancelled and self.closure is not None) or (
                (passed or override) and self.closure is None
            ):
                raise ValueError(
                    "normal closure requires closure evidence; cancellation uses its resolution"
                )


class CreateRequisitionCommand(_StrictModel):
    kind: Literal["create_requisition"] = "create_requisition"
    requisition: PurchaseRequisition

    @model_validator(mode="after")
    def _draft_only(self) -> "CreateRequisitionCommand":
        if self.requisition.status != "draft":
            raise ValueError("new requisitions must start as draft")
        return self


class SubmitRequisitionCommand(_StrictModel):
    kind: Literal["submit_requisition"] = "submit_requisition"


class ApproveRequisitionCommand(_StrictModel):
    kind: Literal["approve_requisition"] = "approve_requisition"


class CreatePurchaseOrderCommand(_StrictModel):
    kind: Literal["create_purchase_order"] = "create_purchase_order"
    purchase_order: PurchaseOrder

    @model_validator(mode="after")
    def _draft_only(self) -> "CreatePurchaseOrderCommand":
        if self.purchase_order.status != "draft":
            raise ValueError("new purchase orders must start as draft")
        return self


class IssuePurchaseOrderCommand(_StrictModel):
    kind: Literal["issue_purchase_order"] = "issue_purchase_order"
    issued_at: str

    @field_validator("issued_at")
    @classmethod
    def _issued_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="issued_at")


class RecordGoodsReceiptCommand(_StrictModel):
    kind: Literal["record_goods_receipt"] = "record_goods_receipt"
    goods_receipt: GoodsReceipt


class EvaluateThreeWayMatchCommand(_StrictModel):
    kind: Literal["evaluate_three_way_match"] = "evaluate_three_way_match"
    match_ref: OpaqueRef
    supplier_invoice: SupplierInvoice
    policy: ThreeWayMatchPolicy = Field(default_factory=ThreeWayMatchPolicy)


class ResolveMatchExceptionCommand(_StrictModel):
    kind: Literal["resolve_match_exception"] = "resolve_match_exception"
    resolution: ExceptionResolution


class CloseProcureToPayCommand(_StrictModel):
    kind: Literal["close"] = "close"
    closed_at: str
    closure_ref: OpaqueRef

    @field_validator("closed_at")
    @classmethod
    def _closed_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="closed_at")


TransitionCommand = Annotated[
    Union[
        CreateRequisitionCommand,
        SubmitRequisitionCommand,
        ApproveRequisitionCommand,
        CreatePurchaseOrderCommand,
        IssuePurchaseOrderCommand,
        RecordGoodsReceiptCommand,
        EvaluateThreeWayMatchCommand,
        ResolveMatchExceptionCommand,
        CloseProcureToPayCommand,
    ],
    Field(discriminator="kind"),
]


class ProcureToPayTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.procure_to_pay_transition_request.v1"] = Field(
        default=PROCURE_TO_PAY_TRANSITION_REQUEST_SCHEMA,
        alias="schema",
    )
    scope: ProcureToPayScope
    lifecycle_ref: OpaqueRef
    expected_revision: int = Field(ge=0, le=_MAX_TRANSITIONS - 1)
    expected_state_digest: Sha256Digest
    idempotency_key: OpaqueRef
    requested_by_ref: OpaqueRef
    proposed_at: str
    command: TransitionCommand
    current: ProcureToPayLifecycle | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_REFS,
    )

    @field_validator("proposed_at")
    @classmethod
    def _proposed_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="proposed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _request_is_exactly_bound(self) -> "ProcureToPayTransitionRequest":
        _validate_unique_evidence(self.evidence_refs)
        if any(
            evidence.verification_grade
            not in {
                PrimitiveEvidenceVerificationGrade.ATTESTED,
                PrimitiveEvidenceVerificationGrade.VERIFIED,
            }
            for evidence in self.evidence_refs
        ):
            raise ValueError("transition evidence must be attested or verified")
        if any(
            _parsed_timestamp(evidence.observed_at)
            > _parsed_timestamp(self.proposed_at)
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "transition evidence cannot be observed after proposal time"
            )
        required_subject = _command_evidence_subject(self.command, self.current)
        subject_evidence = tuple(
            evidence
            for evidence in self.evidence_refs
            if evidence.subject_ref == required_subject
        )
        if not subject_evidence:
            raise ValueError(
                "transition evidence must bind the exact command document subject"
            )
        creating = self.command.kind == "create_requisition"
        if creating:
            if self.current is not None or self.expected_revision != 0:
                raise ValueError(
                    "create_requisition requires revision zero and no current state"
                )
            if self.expected_state_digest != ZERO_DIGEST:
                raise ValueError(
                    "create_requisition requires the zero prior-state digest"
                )
        else:
            if self.current is None:
                raise ValueError("existing lifecycle transitions require current state")
            if (
                self.current.scope != self.scope
                or self.current.lifecycle_ref != self.lifecycle_ref
                or self.current.revision != self.expected_revision
                or self.current.state_digest != self.expected_state_digest
            ):
                raise ValueError(
                    "current lifecycle does not match exact request binding"
                )
            if _parsed_timestamp(self.proposed_at) < _parsed_timestamp(
                self.current.updated_at
            ):
                raise ValueError("proposal time predates the current lifecycle state")
            if _parsed_timestamp(self.proposed_at) < _parsed_timestamp(
                self.current.transition_history[-1].committed_at
            ):
                raise ValueError(
                    "proposal time predates the latest authoritative commit"
                )
            latest_commit = _parsed_timestamp(
                self.current.transition_history[-1].committed_at
            )
            if not any(
                _parsed_timestamp(evidence.observed_at) >= latest_commit
                for evidence in subject_evidence
            ):
                raise ValueError(
                    "transition evidence for the command document predates the "
                    "latest authoritative commit"
                )
            if self.idempotency_key in {
                record.idempotency_key for record in self.current.transition_history
            }:
                raise ValueError("idempotency key has already been consumed")
        return self


class ProcureToPayTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.procure_to_pay_transition_proposal.v1"] = Field(
        default=PROCURE_TO_PAY_TRANSITION_PROPOSAL_SCHEMA,
        alias="schema",
    )
    request: ProcureToPayTransitionRequest
    operation_spec: PrimitiveOperationSpec
    scope_digest: Sha256Digest
    intent_digest: Sha256Digest
    supporting_evidence_digest: Sha256Digest
    target_revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    target_state: ProcureToPayState
    target_domain_digest: Sha256Digest
    execution_boundary: Literal["spring_control_plane"] = "spring_control_plane"
    approval_required: Literal[True] = True
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    provider_execution_claimed: Literal[False] = False
    proposal_digest: Sha256Digest

    @model_validator(mode="after")
    def _proposal_is_content_bound(self) -> "ProcureToPayTransitionProposal":
        if self.operation_spec != _operation_spec(self.request.command.kind):
            raise ValueError("operation_spec does not match transition command")
        if self.scope_digest != self.request.scope.scope_digest:
            raise ValueError("scope_digest does not match exact transition scope")
        if self.intent_digest != _stable_digest(self.request.to_dict()):
            raise ValueError("intent_digest does not match transition request")
        if self.supporting_evidence_digest != _evidence_set_digest(
            self.request.evidence_refs
        ):
            raise ValueError("supporting_evidence_digest does not match evidence")
        if self.target_revision != self.request.expected_revision + 1:
            raise ValueError("target revision must advance exactly once")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_digest"},
        )
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("proposal_digest does not match proposal content")
        return self


class ProcureToPayProposalResult(_StrictModel):
    schema_id: Literal["lightbulb.procure_to_pay_proposal_result.v1"] = Field(
        default=PROCURE_TO_PAY_PROPOSAL_RESULT_SCHEMA,
        alias="schema",
    )
    proposal: ProcureToPayTransitionProposal
    operation_receipt: PrimitiveOperationReceipt
    state_changed: Literal[False] = False

    @model_validator(mode="after")
    def _receipt_is_exact(self) -> "ProcureToPayProposalResult":
        receipt = self.operation_receipt
        if (
            receipt.spec != self.proposal.operation_spec
            or receipt.status != PrimitiveOperationStatus.PENDING_APPROVAL
            or receipt.request_digest != self.proposal.proposal_digest
            or receipt.external_refs.get("scope_digest") != self.proposal.scope_digest
            or receipt.external_refs.get("lifecycle_ref")
            != self.proposal.request.lifecycle_ref
            or receipt.external_refs.get("idempotency_key")
            != self.proposal.request.idempotency_key
            or receipt.external_refs.get("target_domain_digest")
            != self.proposal.target_domain_digest
            or receipt.external_refs.get("intent_digest") != self.proposal.intent_digest
            or receipt.external_refs.get("tenant_ref")
            != self.proposal.request.scope.tenant_ref
            or receipt.external_refs.get("company_ref")
            != self.proposal.request.scope.company_ref
            or receipt.external_refs.get("project_ref")
            != self.proposal.request.scope.project_ref
            or receipt.external_refs.get("project_id")
            != str(self.proposal.request.scope.project_id)
            or receipt.external_refs.get("account_ref")
            != self.proposal.request.scope.account_ref
            or tuple(receipt.evidence_refs) != self.proposal.request.evidence_refs
        ):
            raise ValueError("proposal operation receipt is not exactly bound")
        return self


AuthorityOutcome = Literal["completed", "in_doubt", "rejected"]


def spring_authority_binding_digest(
    *,
    proposal: ProcureToPayTransitionProposal,
    outcome: AuthorityOutcome,
    authority_ref: str,
    committed_at: str,
    approval_ref: str | None,
    approved_by_ref: str | None,
    approval_receipt_digest: str | None,
    reason_code: str | None,
) -> str:
    """Digest the exact Spring decision fields carried by commit evidence."""

    return _stable_digest(
        {
            "schema": "lightbulb.spring_procure_to_pay_authority_binding.v1",
            "proposal_digest": proposal.proposal_digest,
            "outcome": outcome,
            "authority_ref": authority_ref,
            "lifecycle_ref": proposal.request.lifecycle_ref,
            "scope_digest": proposal.scope_digest,
            "current_state_digest": proposal.request.expected_state_digest,
            "idempotency_key": proposal.request.idempotency_key,
            "target_domain_digest": proposal.target_domain_digest,
            "committed_at": _normalized_timestamp(
                committed_at,
                field_name="committed_at",
            ),
            "approval_ref": approval_ref,
            "approved_by_ref": approved_by_ref,
            "approval_receipt_digest": approval_receipt_digest,
            "reason_code": reason_code,
        }
    )


class SpringProcureToPayTransitionEvidence(_StrictModel):
    schema_id: Literal["lightbulb.spring_procure_to_pay_transition_evidence.v1"] = (
        Field(default=SPRING_TRANSITION_EVIDENCE_SCHEMA, alias="schema")
    )
    proposal: ProcureToPayTransitionProposal
    outcome: AuthorityOutcome
    authority_ref: OpaqueRef
    lifecycle_ref: OpaqueRef
    scope_digest: Sha256Digest
    current_state_digest: Sha256Digest
    idempotency_key: OpaqueRef
    target_domain_digest: Sha256Digest
    authority_receipt_digest: Sha256Digest
    authority_evidence_digest: Sha256Digest
    committed_at: str
    approval_ref: OpaqueRef | None = None
    approved_by_ref: OpaqueRef | None = None
    approval_receipt_digest: Sha256Digest | None = None
    reason_code: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_REFS,
    )

    @field_validator("committed_at")
    @classmethod
    def _committed_at(cls, value: str) -> str:
        return _normalized_timestamp(value, field_name="committed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _authority_evidence_is_exact(self) -> "SpringProcureToPayTransitionEvidence":
        proposal = self.proposal
        request = proposal.request
        if (
            self.lifecycle_ref != request.lifecycle_ref
            or self.scope_digest != proposal.scope_digest
            or self.current_state_digest != request.expected_state_digest
            or self.idempotency_key != request.idempotency_key
            or self.target_domain_digest != proposal.target_domain_digest
        ):
            raise ValueError(
                "Spring evidence does not match the exact proposal binding"
            )
        if _parsed_timestamp(self.committed_at) < _parsed_timestamp(
            request.proposed_at
        ):
            raise ValueError("authority evidence predates the transition proposal")
        _validate_unique_evidence(self.evidence_refs)
        if any(
            evidence.verification_grade != PrimitiveEvidenceVerificationGrade.VERIFIED
            or evidence.issuer_ref != self.authority_ref
            or evidence.subject_ref != proposal.proposal_digest
            or _parsed_timestamp(evidence.observed_at)
            < _parsed_timestamp(request.proposed_at)
            or _parsed_timestamp(evidence.observed_at)
            > _parsed_timestamp(self.committed_at)
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "authority evidence must be fresh, verified, and proposal-bound"
            )
        if self.authority_evidence_digest != _evidence_set_digest(self.evidence_refs):
            raise ValueError("authority_evidence_digest does not match evidence")
        expected_authority_receipt = spring_authority_binding_digest(
            proposal=proposal,
            outcome=self.outcome,
            authority_ref=self.authority_ref,
            committed_at=self.committed_at,
            approval_ref=self.approval_ref,
            approved_by_ref=self.approved_by_ref,
            approval_receipt_digest=self.approval_receipt_digest,
            reason_code=self.reason_code,
        )
        if self.authority_receipt_digest != expected_authority_receipt:
            raise ValueError(
                "authority receipt digest does not bind the exact decision"
            )
        authority_receipts = [
            evidence
            for evidence in self.evidence_refs
            if evidence.kind == "procurement_transition_commit"
            and evidence.sha256 == self.authority_receipt_digest
        ]
        if len(authority_receipts) != 1:
            raise ValueError(
                "one exact authority commit receipt must be present in verified evidence"
            )
        completed = self.outcome == "completed"
        if completed != (self.approval_ref is not None):
            raise ValueError(
                "completed transitions require one exact approval reference"
            )
        if completed != (self.approved_by_ref is not None):
            raise ValueError(
                "completed transitions require one exact approver reference"
            )
        if completed != (self.approval_receipt_digest is not None):
            raise ValueError("completed transitions require an approval receipt digest")
        approval_evidence = [
            evidence
            for evidence in self.evidence_refs
            if evidence.kind == "procurement_transition_approval"
        ]
        if completed and (
            len(approval_evidence) != 1
            or approval_evidence[0].sha256 != self.approval_receipt_digest
        ):
            raise ValueError(
                "one exact approval receipt must be present in verified evidence"
            )
        if not completed and approval_evidence:
            raise ValueError(
                "non-completed authority evidence cannot carry an approval receipt"
            )
        if completed and self.approved_by_ref == request.requested_by_ref:
            raise ValueError(
                "transition approver must be independent of the transition requester"
            )
        if completed and request.current is not None:
            separated_prior_operations = {
                "approve_requisition": {"create_requisition"},
                "issue_purchase_order": {"create_purchase_order"},
                "resolve_match_exception": {"evaluate_three_way_match"},
            }.get(request.command.kind, set())
            forbidden_prior_actors = {
                record.requested_by_ref
                for record in request.current.transition_history
                if record.operation in separated_prior_operations
            }
            if self.approved_by_ref in forbidden_prior_actors:
                raise ValueError(
                    "transition approver must be independent of the originating "
                    "procurement actor"
                )
            prior_values = {
                "approval_ref": {
                    record.approval_ref for record in request.current.transition_history
                },
                "approval_receipt_digest": {
                    record.approval_receipt_digest
                    for record in request.current.transition_history
                },
                "authority_receipt_digest": {
                    record.authority_receipt_digest
                    for record in request.current.transition_history
                },
                "authority_evidence_digest": {
                    record.authority_evidence_digest
                    for record in request.current.transition_history
                },
            }
            for field_name, consumed in prior_values.items():
                if getattr(self, field_name) in consumed:
                    raise ValueError(
                        "Spring authority and approval evidence must be single-use "
                        "within a lifecycle"
                    )
        if completed and self.reason_code is not None:
            raise ValueError(
                "completed authority evidence cannot carry a failure reason"
            )
        if not completed and self.reason_code is None:
            raise ValueError("non-completed authority evidence requires a reason code")
        return self


class ProcureToPayTransitionValidationResult(_StrictModel):
    """Structural validation output; never proof that Spring persisted a change."""

    schema_id: Literal["lightbulb.procure_to_pay_transition_validation_result.v1"] = (
        Field(
            default=PROCURE_TO_PAY_TRANSITION_VALIDATION_RESULT_SCHEMA,
            alias="schema",
        )
    )
    status: Literal["candidate_validated", "in_doubt", "rejected"]
    proposal_digest: Sha256Digest
    operation_spec: PrimitiveOperationSpec
    current_lifecycle: ProcureToPayLifecycle | None = None
    candidate_lifecycle: ProcureToPayLifecycle | None = None
    operation_receipt: PrimitiveOperationReceipt
    recovery_plan: PrimitiveRecoveryPlan | None = None
    state_changed: Literal[False] = False
    authoritative_persistence_claimed: Literal[False] = False
    automatic_retry_allowed: Literal[False] = False
    connector_writes: Literal[0] = 0
    provider_execution_claimed: Literal[False] = False

    @model_validator(mode="after")
    def _result_matches_receipt(self) -> "ProcureToPayTransitionValidationResult":
        expected_status = {
            "candidate_validated": PrimitiveOperationStatus.PREVIEW,
            "in_doubt": PrimitiveOperationStatus.IN_DOUBT,
            "rejected": PrimitiveOperationStatus.BLOCKED,
        }[self.status]
        if (
            self.operation_receipt.spec != self.operation_spec
            or self.operation_receipt.status != expected_status
            or self.operation_receipt.request_digest != self.proposal_digest
        ):
            raise ValueError("transition result does not match its operation receipt")
        if (self.status == "candidate_validated") != (
            self.candidate_lifecycle is not None
        ):
            raise ValueError(
                "only validated completed evidence may expose a candidate lifecycle"
            )
        if (self.status == "in_doubt") != (self.recovery_plan is not None):
            raise ValueError("only an in-doubt transition carries unresolved recovery")
        return self


class ProcureToPayLifecycleError(ValueError):
    """Fail-closed lifecycle error with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise ProcureToPayLifecycleError(code, message)


def _operation_spec(command_kind: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(
        operation_ref=f"procure-to-pay.{command_kind.replace('_', '-')}",
        tool=SPRING_PROCUREMENT_TRANSITION_OPERATION,
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        atomicity_group="procure-to-pay-lifecycle",
        replay_class=PrimitiveOperationReplayClass.PROBE_BEFORE_RETRY,
        freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
        recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
    )


def _command_evidence_subject(
    command: TransitionCommand,
    current: ProcureToPayLifecycle | None,
) -> str:
    if command.kind == "create_requisition":
        return command.requisition.requisition_ref
    if command.kind in {"submit_requisition", "approve_requisition"}:
        if current is None:  # caught by the request's state validator
            return "current-requisition-required"
        return current.requisition.requisition_ref
    if command.kind == "create_purchase_order":
        return command.purchase_order.purchase_order_ref
    if command.kind == "issue_purchase_order":
        if current is None or current.purchase_order is None:
            return "current-purchase-order-required"
        return current.purchase_order.purchase_order_ref
    if command.kind == "record_goods_receipt":
        return command.goods_receipt.goods_receipt_ref
    if command.kind == "evaluate_three_way_match":
        return command.supplier_invoice.supplier_invoice_ref
    if command.kind == "resolve_match_exception":
        return command.resolution.resolution_ref
    return command.closure_ref


def _manual_recovery_plan() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
        disposition=PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
        instructions=(
            "Lock the exact lifecycle scope in Spring, inspect the authoritative "
            "idempotency and transition journal, then settle the proposal. Do not "
            "apply or retry the transition from SDK evidence alone."
        ),
    )


def _copy_model(model: BaseModel, model_type: type[BaseModel], **updates: Any) -> Any:
    payload = model.model_dump(mode="python", by_alias=False)
    payload.update(updates)
    return model_type.model_validate(payload)


def _build_lifecycle(**fields: Any) -> ProcureToPayLifecycle:
    payload: dict[str, Any] = {
        "schema": PROCURE_TO_PAY_LIFECYCLE_SCHEMA,
        **fields,
    }
    provisional = ProcureToPayLifecycle.model_construct(
        schema_id=PROCURE_TO_PAY_LIFECYCLE_SCHEMA,
        domain_digest=ZERO_DIGEST,
        state_digest=ZERO_DIGEST,
        **fields,
    )
    canonical = provisional.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
    )
    domain_payload = dict(canonical)
    for key in ("transition_history", "domain_digest", "state_digest"):
        domain_payload.pop(key, None)
    domain_digest = _stable_digest(domain_payload)
    state_payload = dict(canonical)
    state_payload["domain_digest"] = domain_digest
    state_payload.pop("state_digest", None)
    payload["domain_digest"] = domain_digest
    payload["state_digest"] = _stable_digest(state_payload)
    return ProcureToPayLifecycle.model_validate(payload)


def _lifecycle_fields(lifecycle: ProcureToPayLifecycle) -> dict[str, Any]:
    return {
        "lifecycle_ref": lifecycle.lifecycle_ref,
        "revision": lifecycle.revision,
        "scope": lifecycle.scope,
        "state": lifecycle.state,
        "requisition": lifecycle.requisition,
        "purchase_order": lifecycle.purchase_order,
        "goods_receipts": lifecycle.goods_receipts,
        "supplier_invoice": lifecycle.supplier_invoice,
        "three_way_match": lifecycle.three_way_match,
        "exception_resolution": lifecycle.exception_resolution,
        "closure": lifecycle.closure,
        "updated_at": lifecycle.updated_at,
        "transition_history": lifecycle.transition_history,
    }


def _validate_purchase_order(
    requisition: PurchaseRequisition,
    purchase_order: PurchaseOrder,
) -> None:
    if (
        purchase_order.requisition_ref != requisition.requisition_ref
        or purchase_order.vendor_ref != requisition.vendor_ref
        or purchase_order.currency != requisition.currency
    ):
        _fail(
            "purchase_order_document_mismatch",
            "purchase order does not match the approved requisition",
        )
    if purchase_order.total_amount > requisition.budget_amount:
        _fail(
            "purchase_order_budget_exceeded",
            "purchase order exceeds the bound requisition budget",
        )
    requisition_lines = {line.line_ref: line for line in requisition.lines}
    for line in purchase_order.lines:
        requested = requisition_lines.get(line.requisition_line_ref)
        if requested is None:
            _fail(
                "purchase_order_line_unbound",
                "purchase-order line does not reference an exact requisition line",
            )
        if (
            line.item_ref != requested.item_ref
            or line.unit_of_measure != requested.unit_of_measure
            or line.quantity_ordered > requested.quantity_requested
        ):
            _fail(
                "purchase_order_line_mismatch",
                "purchase-order line exceeds or conflicts with its requisition line",
            )


def _receipt_totals(
    purchase_order: PurchaseOrder,
    receipts: tuple[GoodsReceipt, ...],
) -> tuple[dict[str, Decimal], dict[str, Decimal]]:
    received = {line.line_ref: Decimal("0.000000") for line in purchase_order.lines}
    accepted = {line.line_ref: Decimal("0.000000") for line in purchase_order.lines}
    po_lines = {line.line_ref: line for line in purchase_order.lines}
    for receipt in receipts:
        if (
            receipt.purchase_order_ref != purchase_order.purchase_order_ref
            or receipt.vendor_ref != purchase_order.vendor_ref
        ):
            _fail(
                "goods_receipt_document_mismatch",
                "goods receipt does not match the exact purchase order and vendor",
            )
        for line in receipt.lines:
            ordered = po_lines.get(line.purchase_order_line_ref)
            if ordered is None or (
                line.item_ref != ordered.item_ref
                or line.unit_of_measure != ordered.unit_of_measure
            ):
                _fail(
                    "goods_receipt_line_mismatch",
                    "goods-receipt line does not match an exact purchase-order line",
                )
            received[ordered.line_ref] += line.quantity_received
            accepted[ordered.line_ref] += line.quantity_accepted
            if received[ordered.line_ref] > ordered.quantity_ordered:
                _fail(
                    "purchase_order_over_received",
                    "cumulative received quantity exceeds the purchase order",
                )
    return received, accepted


def _three_way_match(
    *,
    match_ref: str,
    evaluated_at: str,
    purchase_order: PurchaseOrder,
    receipts: tuple[GoodsReceipt, ...],
    invoice: SupplierInvoice,
    policy: ThreeWayMatchPolicy,
) -> ThreeWayMatchResult:
    if (
        invoice.purchase_order_ref != purchase_order.purchase_order_ref
        or invoice.vendor_ref != purchase_order.vendor_ref
        or invoice.currency != purchase_order.currency
    ):
        _fail(
            "supplier_invoice_document_mismatch",
            "supplier invoice does not match the exact purchase order, vendor, and currency",
        )
    if _parsed_timestamp(invoice.invoice_date) > _parsed_timestamp(evaluated_at):
        _fail(
            "future_supplier_invoice",
            "supplier invoice date exceeds the match evaluation time",
        )
    _, accepted = _receipt_totals(purchase_order, receipts)
    po_lines = {line.line_ref: line for line in purchase_order.lines}
    invoice_lines = {line.purchase_order_line_ref: line for line in invoice.lines}
    findings: list[ThreeWayMatchFinding] = []
    if invoice.duplicate_check != "clear":
        findings.append(
            ThreeWayMatchFinding(
                code="invoice-duplicate-check-not-clear",
                message="Supplier invoice duplicate check is not clear.",
            )
        )
    expected_subtotal = Decimal("0.00")
    accepted_total = Decimal("0.000000")
    invoiced_total = sum(
        (line.quantity_invoiced for line in invoice.lines),
        Decimal("0.000000"),
    )
    for po_line in purchase_order.lines:
        invoice_line = invoice_lines.get(po_line.line_ref)
        accepted_quantity = accepted[po_line.line_ref]
        accepted_total += accepted_quantity
        if invoice_line is None:
            findings.append(
                ThreeWayMatchFinding(
                    code="invoice-line-missing",
                    message="Purchase-order line is absent from the supplier invoice.",
                    purchase_order_line_ref=po_line.line_ref,
                )
            )
            continue
        expected_subtotal += _exact_line_total(
            invoice_line.quantity_invoiced, po_line.unit_price
        )
        if (
            invoice_line.item_ref != po_line.item_ref
            or invoice_line.unit_of_measure != po_line.unit_of_measure
        ):
            findings.append(
                ThreeWayMatchFinding(
                    code="invoice-line-identity-mismatch",
                    message="Invoice line identity does not match purchase-order line.",
                    purchase_order_line_ref=po_line.line_ref,
                )
            )
        if (
            abs(invoice_line.quantity_invoiced - accepted_quantity)
            > policy.quantity_tolerance
        ):
            findings.append(
                ThreeWayMatchFinding(
                    code="invoice-receipt-quantity-mismatch",
                    message="Invoiced quantity differs from accepted receipt quantity.",
                    purchase_order_line_ref=po_line.line_ref,
                )
            )
        if (
            abs(invoice_line.unit_price - po_line.unit_price)
            > policy.unit_price_tolerance
        ):
            findings.append(
                ThreeWayMatchFinding(
                    code="invoice-purchase-order-price-mismatch",
                    message="Invoice unit price differs from purchase-order unit price.",
                    purchase_order_line_ref=po_line.line_ref,
                )
            )
    unknown_lines = set(invoice_lines) - set(po_lines)
    for line_ref in sorted(unknown_lines):
        findings.append(
            ThreeWayMatchFinding(
                code="invoice-line-unbound",
                message="Invoice line has no purchase-order line.",
                purchase_order_line_ref=line_ref,
            )
        )
    if abs(invoice.subtotal - expected_subtotal) > policy.subtotal_tolerance:
        findings.append(
            ThreeWayMatchFinding(
                code="invoice-subtotal-mismatch",
                message="Invoice subtotal differs from purchase-order pricing.",
            )
        )
    payload = {
        "match_ref": match_ref,
        "disposition": "matched" if not findings else "exception",
        "purchase_order_ref": purchase_order.purchase_order_ref,
        "supplier_invoice_ref": invoice.supplier_invoice_ref,
        "evaluated_at": evaluated_at,
        "accepted_quantity_total": accepted_total,
        "invoiced_quantity_total": invoiced_total,
        "expected_subtotal": expected_subtotal,
        "invoice_subtotal": invoice.subtotal,
        "policy": policy,
        "findings": tuple(findings),
    }
    provisional = ThreeWayMatchResult.model_construct(
        **payload,
        evaluation_digest=ZERO_DIGEST,
    )
    digest_payload = provisional.model_dump(
        mode="json",
        by_alias=True,
        exclude={"evaluation_digest"},
    )
    return ThreeWayMatchResult(
        **payload,
        evaluation_digest=_stable_digest(digest_payload),
    )


def _pending_transition_record(
    request: ProcureToPayTransitionRequest,
    *,
    transition_index: int,
) -> ProcureToPayTransitionRecord:
    """Create collision-resistant placeholders excluded from proposal meaning."""

    intent_digest = _stable_digest(request.to_dict())

    def pending_digest(field_name: str) -> str:
        return _stable_digest(
            {
                "schema": "lightbulb.procure_to_pay_pending_authority_field.v1",
                "field": field_name,
                "intent_digest": intent_digest,
            }
        )

    return ProcureToPayTransitionRecord(
        transition_index=transition_index,
        operation=request.command.kind,
        idempotency_key=request.idempotency_key,
        intent_digest=intent_digest,
        proposal_digest=pending_digest("proposal_digest"),
        requested_by_ref=request.requested_by_ref,
        authority_ref="spring-pending",
        approved_by_ref=f"approver-pending-{intent_digest[:24]}",
        approval_ref=f"approval-pending-{intent_digest[:24]}",
        approval_receipt_digest=pending_digest("approval_receipt_digest"),
        authority_receipt_digest=pending_digest("authority_receipt_digest"),
        supporting_evidence_digest=_evidence_set_digest(request.evidence_refs),
        authority_evidence_digest=pending_digest("authority_evidence_digest"),
        committed_at=request.proposed_at,
    )


def _candidate_lifecycle(
    request: ProcureToPayTransitionRequest,
    current: ProcureToPayLifecycle | None,
) -> ProcureToPayLifecycle:
    command = request.command
    if command.kind == "create_requisition":
        if current is not None:
            _fail("lifecycle_already_exists", "cannot create an existing lifecycle")
        # A proposal candidate has no authority record. Use a temporary record only
        # to calculate its domain digest; it is replaced by verified Spring evidence.
        temporary_record = _pending_transition_record(request, transition_index=1)
        return _build_lifecycle(
            lifecycle_ref=request.lifecycle_ref,
            revision=1,
            scope=request.scope,
            state="requisition_draft",
            requisition=command.requisition,
            updated_at=request.proposed_at,
            transition_history=(temporary_record,),
        )
    if current is None:
        _fail("current_lifecycle_required", "transition requires current lifecycle")
    fields = _lifecycle_fields(current)
    fields["revision"] = current.revision + 1
    fields["updated_at"] = request.proposed_at
    # Temporary history preserves the candidate revision invariant. Domain digest
    # excludes history, so authority placeholders cannot enter proposal meaning.
    fields["transition_history"] = current.transition_history + (
        _pending_transition_record(
            request,
            transition_index=current.revision + 1,
        ),
    )
    requisition = current.requisition
    purchase_order = current.purchase_order
    latest_authoritative_time = max(
        _parsed_timestamp(current.updated_at),
        _parsed_timestamp(current.transition_history[-1].committed_at),
    )

    if command.kind == "submit_requisition":
        if current.state != "requisition_draft":
            _fail("invalid_transition", "only a draft requisition may be submitted")
        fields["state"] = "requisition_pending_approval"
        fields["requisition"] = _copy_model(
            requisition, PurchaseRequisition, status="submitted"
        )
    elif command.kind == "approve_requisition":
        if current.state != "requisition_pending_approval":
            _fail("invalid_transition", "only a submitted requisition may be approved")
        fields["state"] = "requisition_approved"
        fields["requisition"] = _copy_model(
            requisition, PurchaseRequisition, status="approved"
        )
    elif command.kind == "create_purchase_order":
        if current.state != "requisition_approved":
            _fail(
                "invalid_transition", "purchase order requires an approved requisition"
            )
        _validate_purchase_order(requisition, command.purchase_order)
        fields["state"] = "purchase_order_pending_approval"
        fields["purchase_order"] = command.purchase_order
    elif command.kind == "issue_purchase_order":
        if current.state != "purchase_order_pending_approval" or purchase_order is None:
            _fail(
                "invalid_transition", "only an approved draft purchase order may issue"
            )
        if not (
            latest_authoritative_time
            <= _parsed_timestamp(command.issued_at)
            <= _parsed_timestamp(request.proposed_at)
        ):
            _fail(
                "invalid_issue_time",
                "purchase-order issue time must follow current state and not exceed proposal time",
            )
        fields["state"] = "purchase_order_issued"
        fields["purchase_order"] = _copy_model(
            purchase_order,
            PurchaseOrder,
            status="issued",
            issued_at=command.issued_at,
        )
    elif command.kind == "record_goods_receipt":
        if (
            current.state not in {"purchase_order_issued", "partially_received"}
            or purchase_order is None
        ):
            _fail(
                "invalid_transition",
                "goods receipt requires an open issued purchase order",
            )
        if command.goods_receipt.goods_receipt_ref in {
            receipt.goods_receipt_ref for receipt in current.goods_receipts
        }:
            _fail("duplicate_goods_receipt", "goods receipt was already recorded")
        if len(current.goods_receipts) >= _MAX_RECEIPTS:
            _fail("goods_receipt_limit_reached", "lifecycle receipt bound is exhausted")
        if _parsed_timestamp(command.goods_receipt.received_at) > _parsed_timestamp(
            request.proposed_at
        ):
            _fail("future_receipt", "goods receipt time exceeds proposal time")
        if purchase_order.issued_at is None or _parsed_timestamp(
            command.goods_receipt.received_at
        ) < _parsed_timestamp(purchase_order.issued_at):
            _fail(
                "receipt_predates_order", "goods receipt predates purchase-order issue"
            )
        receipts = current.goods_receipts + (command.goods_receipt,)
        received, _ = _receipt_totals(purchase_order, receipts)
        complete = all(
            received[line.line_ref] == line.quantity_ordered
            for line in purchase_order.lines
        )
        state = "fully_received" if complete else "partially_received"
        fields["state"] = state
        fields["goods_receipts"] = receipts
        fields["purchase_order"] = _copy_model(
            purchase_order,
            PurchaseOrder,
            status="received" if complete else "partially_received",
        )
    elif command.kind == "evaluate_three_way_match":
        if current.state != "fully_received" or purchase_order is None:
            _fail(
                "invalid_transition", "three-way match requires a fully received order"
            )
        match = _three_way_match(
            match_ref=command.match_ref,
            evaluated_at=request.proposed_at,
            purchase_order=purchase_order,
            receipts=current.goods_receipts,
            invoice=command.supplier_invoice,
            policy=command.policy,
        )
        state = "matched" if match.disposition == "matched" else "exception"
        fields["state"] = state
        fields["supplier_invoice"] = command.supplier_invoice
        fields["three_way_match"] = match
        fields["purchase_order"] = _copy_model(
            purchase_order,
            PurchaseOrder,
            status="matched" if state == "matched" else "match_exception",
        )
    elif command.kind == "resolve_match_exception":
        if current.state != "exception" or purchase_order is None:
            _fail("invalid_transition", "only an open match exception may be resolved")
        if not (
            latest_authoritative_time
            <= _parsed_timestamp(command.resolution.resolved_at)
            <= _parsed_timestamp(request.proposed_at)
        ):
            _fail(
                "invalid_resolution_time",
                "exception resolution must follow current state and not exceed proposal time",
            )
        if (
            command.resolution.disposition == "approve_override"
            and current.supplier_invoice is not None
            and current.supplier_invoice.duplicate_check == "confirmed_duplicate"
        ):
            _fail(
                "confirmed_duplicate_cannot_be_overridden",
                "a confirmed duplicate supplier invoice must be cancelled, not approved",
            )
        close = command.resolution.disposition == "cancel_and_close"
        fields["state"] = "closed" if close else "matched"
        fields["exception_resolution"] = command.resolution
        fields["purchase_order"] = _copy_model(
            purchase_order,
            PurchaseOrder,
            status="closed" if close else "matched",
        )
    elif command.kind == "close":
        if current.state != "matched" or purchase_order is None:
            _fail("invalid_transition", "only a matched lifecycle may close")
        if not (
            latest_authoritative_time
            <= _parsed_timestamp(command.closed_at)
            <= _parsed_timestamp(request.proposed_at)
        ):
            _fail(
                "invalid_closure_time",
                "closure must follow current state and not exceed proposal time",
            )
        fields["state"] = "closed"
        fields["updated_at"] = command.closed_at
        fields["closure"] = ProcureToPayClosure(
            closure_ref=command.closure_ref,
            closed_at=command.closed_at,
        )
        fields["purchase_order"] = _copy_model(
            purchase_order,
            PurchaseOrder,
            status="closed",
        )
    else:  # pragma: no cover - discriminated contract makes this unreachable
        _fail("unsupported_transition", "unsupported procure-to-pay transition")
    return _build_lifecycle(**fields)


def propose_transition(
    request: ProcureToPayTransitionRequest | dict[str, Any],
) -> ProcureToPayProposalResult:
    """Build a deterministic approval proposal without changing state or connectors."""

    parsed = revalidate_model_boundary(ProcureToPayTransitionRequest, request)
    candidate = _candidate_lifecycle(parsed, parsed.current)
    spec = _operation_spec(parsed.command.kind)
    proposal_fields = {
        "request": parsed,
        "operation_spec": spec,
        "scope_digest": parsed.scope.scope_digest,
        "intent_digest": _stable_digest(parsed.to_dict()),
        "supporting_evidence_digest": _evidence_set_digest(parsed.evidence_refs),
        "target_revision": candidate.revision,
        "target_state": candidate.state,
        "target_domain_digest": candidate.domain_digest,
    }
    provisional = ProcureToPayTransitionProposal.model_construct(
        schema_id=PROCURE_TO_PAY_TRANSITION_PROPOSAL_SCHEMA,
        proposal_digest=ZERO_DIGEST,
        **proposal_fields,
    )
    proposal_payload = provisional.model_dump(
        mode="json",
        by_alias=True,
        exclude={"proposal_digest"},
    )
    proposal = ProcureToPayTransitionProposal(
        **proposal_fields,
        proposal_digest=_stable_digest(proposal_payload),
    )
    receipt = PrimitiveOperationReceipt(
        spec=spec,
        status=PrimitiveOperationStatus.PENDING_APPROVAL,
        request_digest=proposal.proposal_digest,
        external_refs={
            "lifecycle_ref": parsed.lifecycle_ref,
            "scope_digest": proposal.scope_digest,
            "tenant_ref": parsed.scope.tenant_ref,
            "company_ref": parsed.scope.company_ref,
            "project_ref": parsed.scope.project_ref,
            "project_id": str(parsed.scope.project_id),
            "account_ref": parsed.scope.account_ref,
            "idempotency_key": parsed.idempotency_key,
            "intent_digest": proposal.intent_digest,
            "target_domain_digest": proposal.target_domain_digest,
        },
        evidence_refs=list(parsed.evidence_refs),
    )
    return ProcureToPayProposalResult(
        proposal=proposal,
        operation_receipt=receipt,
    )


def _verify_live_state(
    proposal: ProcureToPayTransitionProposal,
    live_current: ProcureToPayLifecycle | None,
) -> None:
    request = proposal.request
    if live_current is not None and request.idempotency_key in {
        record.idempotency_key for record in live_current.transition_history
    }:
        _fail(
            "duplicate_idempotency_key",
            "the authoritative lifecycle already consumed this idempotency key",
        )
    if request.current is None:
        if live_current is not None:
            _fail(
                "stale_transition_evidence", "lifecycle was created after this proposal"
            )
        return
    if live_current is None or (
        live_current.scope != request.scope
        or live_current.lifecycle_ref != request.lifecycle_ref
        or live_current.revision != request.expected_revision
        or live_current.state_digest != request.expected_state_digest
        or live_current.state_digest != request.current.state_digest
    ):
        _fail(
            "stale_transition_evidence",
            "locked authoritative lifecycle no longer matches the proposal",
        )


def validate_transition_evidence(
    evidence: SpringProcureToPayTransitionEvidence | dict[str, Any],
    *,
    live_current: ProcureToPayLifecycle | None,
) -> ProcureToPayTransitionValidationResult:
    """Validate evidence and return a non-authoritative lifecycle candidate.

    This function performs no persistence and grants no authority. A caller can
    construct structurally valid evidence, so only Spring may authenticate it,
    persist the candidate, and record the authoritative transition.
    """

    parsed = SpringProcureToPayTransitionEvidence.model_validate(
        evidence.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(evidence, SpringProcureToPayTransitionEvidence)
        else evidence
    )
    if live_current is not None:
        live_current = ProcureToPayLifecycle.model_validate(
            live_current.model_dump(mode="python", by_alias=True, exclude_none=True)
        )
    proposal = parsed.proposal
    _verify_live_state(proposal, live_current)
    candidate = _candidate_lifecycle(proposal.request, live_current)
    if (
        candidate.revision != proposal.target_revision
        or candidate.state != proposal.target_state
        or candidate.domain_digest != proposal.target_domain_digest
    ):
        _fail(
            "proposal_candidate_mismatch",
            "recomputed lifecycle candidate does not match the reviewed proposal",
        )

    if parsed.outcome == "in_doubt":
        recovery = _manual_recovery_plan()
        blocker = PrimitiveBlocker(
            code=str(parsed.reason_code),
            message="Spring could not settle the authoritative lifecycle transition.",
            retryable=False,
        )
        receipt = PrimitiveOperationReceipt(
            spec=proposal.operation_spec,
            status=PrimitiveOperationStatus.IN_DOUBT,
            request_digest=proposal.proposal_digest,
            provenance_receipt_digest=parsed.authority_receipt_digest,
            external_refs={
                "lifecycle_ref": parsed.lifecycle_ref,
                "scope_digest": parsed.scope_digest,
                "idempotency_key": parsed.idempotency_key,
                "target_domain_digest": parsed.target_domain_digest,
            },
            evidence_refs=list(parsed.evidence_refs),
            recovery_disposition=PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED,
            recovery_plan=recovery,
            error=blocker,
        )
        return ProcureToPayTransitionValidationResult(
            status="in_doubt",
            proposal_digest=proposal.proposal_digest,
            operation_spec=proposal.operation_spec,
            current_lifecycle=live_current,
            operation_receipt=receipt,
            recovery_plan=recovery,
        )

    if parsed.outcome == "rejected":
        blocker = PrimitiveBlocker(
            code=str(parsed.reason_code),
            message="Spring rejected the authoritative lifecycle transition.",
            retryable=False,
        )
        receipt = PrimitiveOperationReceipt(
            spec=proposal.operation_spec,
            status=PrimitiveOperationStatus.BLOCKED,
            request_digest=proposal.proposal_digest,
            provenance_receipt_digest=parsed.authority_receipt_digest,
            external_refs={
                "lifecycle_ref": parsed.lifecycle_ref,
                "scope_digest": parsed.scope_digest,
                "idempotency_key": parsed.idempotency_key,
            },
            evidence_refs=list(parsed.evidence_refs),
            error=blocker,
        )
        return ProcureToPayTransitionValidationResult(
            status="rejected",
            proposal_digest=proposal.proposal_digest,
            operation_spec=proposal.operation_spec,
            current_lifecycle=live_current,
            operation_receipt=receipt,
        )

    if (
        parsed.approval_ref is None
        or parsed.approved_by_ref is None
        or parsed.approval_receipt_digest is None
    ):
        _fail(
            "incomplete_completed_authority_evidence",
            "completed evidence requires exact approval and approver fields",
        )
    authority_record = ProcureToPayTransitionRecord(
        transition_index=candidate.revision,
        operation=proposal.request.command.kind,
        idempotency_key=parsed.idempotency_key,
        intent_digest=proposal.intent_digest,
        proposal_digest=proposal.proposal_digest,
        requested_by_ref=proposal.request.requested_by_ref,
        authority_ref=parsed.authority_ref,
        approved_by_ref=parsed.approved_by_ref,
        approval_ref=parsed.approval_ref,
        approval_receipt_digest=parsed.approval_receipt_digest,
        authority_receipt_digest=parsed.authority_receipt_digest,
        supporting_evidence_digest=proposal.supporting_evidence_digest,
        authority_evidence_digest=parsed.authority_evidence_digest,
        committed_at=parsed.committed_at,
    )
    candidate_fields = _lifecycle_fields(candidate)
    candidate_fields["transition_history"] = (
        () if live_current is None else live_current.transition_history
    ) + (authority_record,)
    candidate_lifecycle = _build_lifecycle(**candidate_fields)
    receipt = PrimitiveOperationReceipt(
        spec=proposal.operation_spec,
        status=PrimitiveOperationStatus.PREVIEW,
        request_digest=proposal.proposal_digest,
        external_refs={
            "lifecycle_ref": candidate_lifecycle.lifecycle_ref,
            "scope_digest": parsed.scope_digest,
            "account_ref": candidate_lifecycle.scope.account_ref,
            "idempotency_key": parsed.idempotency_key,
            "intent_digest": proposal.intent_digest,
            "candidate_domain_digest": candidate_lifecycle.domain_digest,
            "candidate_state_digest": candidate_lifecycle.state_digest,
            "validated_approval_receipt_digest": parsed.approval_receipt_digest,
            "validated_authority_receipt_digest": parsed.authority_receipt_digest,
            "requested_by_ref": proposal.request.requested_by_ref,
            "approved_by_ref": parsed.approved_by_ref,
        },
        evidence_refs=list(parsed.evidence_refs),
    )
    return ProcureToPayTransitionValidationResult(
        status="candidate_validated",
        proposal_digest=proposal.proposal_digest,
        operation_spec=proposal.operation_spec,
        current_lifecycle=live_current,
        candidate_lifecycle=candidate_lifecycle,
        operation_receipt=receipt,
    )


def _request_matches_context(
    request: ProcureToPayTransitionRequest,
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


def _procure_to_pay_example_inputs() -> dict[str, Any]:
    return {
        "schema": PROCURE_TO_PAY_TRANSITION_REQUEST_SCHEMA,
        "scope": {
            "schema": PROCURE_TO_PAY_SCOPE_SCHEMA,
            "tenant_ref": "authenticated",
            "company_ref": "selected",
            "project_ref": "workflow-improvement",
            "project_id": "00000000-0000-0000-0000-000000000401",
            "account_ref": "procurement-example-account",
        },
        "lifecycle_ref": "p2p-example",
        "expected_revision": 0,
        "expected_state_digest": ZERO_DIGEST,
        "idempotency_key": "p2p-create-example",
        "requested_by_ref": "procurement-requester-example",
        "proposed_at": "2026-08-25T10:00:00Z",
        "command": {
            "kind": "create_requisition",
            "requisition": {
                "requisition_ref": "requisition-example",
                "status": "draft",
                "currency": "USD",
                "vendor_ref": "vendor-example",
                "budget_ref": "budget-example",
                "budget_amount": "100.00",
                "total_amount": "20.00",
                "lines": [
                    {
                        "line_ref": "requisition-line-example",
                        "item_ref": "item-example",
                        "description": "Two example components",
                        "quantity_requested": "2.000000",
                        "unit_of_measure": "EA",
                        "estimated_unit_price": "10.00",
                        "line_total": "20.00",
                        "cost_center_ref": "cost-center-example",
                    }
                ],
            },
        },
        "evidence_refs": [
            {
                "schema": "lightbulb.primitive_evidence_ref.v1",
                "evidence_ref": "p2p-create-evidence-example",
                "kind": "procurement_document_snapshot",
                "issuer_ref": "spring-procurement-read-authority",
                "subject_ref": "requisition-example",
                "sha256": _stable_digest("p2p-create-evidence-example"),
                "observed_at": "2026-08-25T09:59:00Z",
                "verification_grade": "attested",
                "classification": "confidential",
                "retention_policy": "procurement-seven-years",
                "jurisdiction": "US",
            }
        ],
    }


class ProposeProcureToPayTransitionPrimitive(
    BusinessProcessPrimitive[
        ProcureToPayTransitionRequest,
        ProcureToPayProposalResult,
    ]
):
    """Executable proposal wrapper with no connector or persistence authority."""

    primitive_ref = "procurement.propose_procure_to_pay_transition"
    version = "1.0.0"
    title = "Propose a governed procure-to-pay lifecycle transition"
    description = (
        "Build an exact-scope, evidence-bound transition proposal without changing "
        "the lifecycle, calling a connector, or claiming Spring approval."
    )
    input_model = ProcureToPayTransitionRequest
    output_model = ProcureToPayProposalResult
    connector_tools = ()
    risk_level = "high"
    approval_required = True
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _procure_to_pay_example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "sdk_proposal_only": True,
            "lifecycle_state_changed": False,
            "connector_calls": False,
            "approval_granted": False,
            "authoritative_persistence_claimed": False,
            "spring_approval_and_persistence_required": True,
        }
        contract["authority_guarantees"] = {
            "runtime_scope_binding": (
                "tenant_company_project_project_id_actor_and_idempotency_required"
            ),
            "durable_idempotency_authority": "spring_control_plane",
            "approval_custody": "spring_control_plane",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProcureToPayTransitionRequest,
    ) -> PrimitiveExecutionResult[ProcureToPayProposalResult]:
        spec = _operation_spec(inputs.command.kind)
        if not _request_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="procure_to_pay_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, project-id, actor, and "
                    "idempotency scope are required and must match the transition request."
                ),
                field="scope",
                retryable=False,
            )
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.BLOCKED,
                request_digest=_stable_digest(inputs.to_dict()),
                evidence_refs=list(inputs.evidence_refs),
                error=blocker,
            )
            return PrimitiveExecutionResult[ProcureToPayProposalResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Procure-to-pay proposal rejected at the runtime scope boundary.",
                operation_receipts=[receipt],
                blockers=[blocker],
                retryable=False,
            )

        try:
            output = propose_transition(inputs)
        except ProcureToPayLifecycleError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=False,
            )
            receipt = PrimitiveOperationReceipt(
                spec=spec,
                status=PrimitiveOperationStatus.BLOCKED,
                request_digest=_stable_digest(inputs.to_dict()),
                evidence_refs=list(inputs.evidence_refs),
                error=blocker,
            )
            return PrimitiveExecutionResult[ProcureToPayProposalResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Procure-to-pay transition proposal failed deterministic "
                    "lifecycle validation."
                ),
                operation_receipts=[receipt],
                blockers=[blocker],
                retryable=False,
            )
        receipt = output.operation_receipt
        status = PrimitiveExecutionStatus.PENDING_APPROVAL
        summary = (
            "Transition proposal is pending Spring approval and persistence; no "
            "lifecycle or provider state changed."
        )
        if context.preview_only:
            status = PrimitiveExecutionStatus.PREVIEW
            summary = (
                "Preview planned an approval-gated transition proposal; no lifecycle "
                "or provider state changed."
            )
            receipt = PrimitiveOperationReceipt(
                spec=output.proposal.operation_spec,
                status=PrimitiveOperationStatus.PREVIEW,
                request_digest=output.proposal.proposal_digest,
                external_refs=dict(output.operation_receipt.external_refs),
                evidence_refs=list(inputs.evidence_refs),
            )

        return PrimitiveExecutionResult[ProcureToPayProposalResult](
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type="procurement.procure_to_pay_transition_proposed",
                    payload={
                        "lifecycle_ref": inputs.lifecycle_ref,
                        "command_kind": inputs.command.kind,
                        "proposal_digest": output.proposal.proposal_digest,
                        "target_state": output.proposal.target_state,
                        "approval_granted": False,
                        "authoritative_persistence_claimed": False,
                        "connector_calls": 0,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="procure_to_pay_transition_proposal",
                    summary=(
                        "Content-bound SDK proposal; Spring approval, durable "
                        "idempotency, persistence, and audit custody remain required."
                    ),
                    labels=[inputs.command.kind, "pending_spring_authority"],
                    refs={
                        "lifecycle_ref": inputs.lifecycle_ref,
                        "proposal_digest": output.proposal.proposal_digest,
                    },
                )
            ],
            evidence_refs=list(inputs.evidence_refs),
            operation_receipts=[receipt],
            retryable=False,
        )


PROCURE_TO_PAY_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeProcureToPayTransitionPrimitive(),)


__all__ = [
    "PROCURE_TO_PAY_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "PROCURE_TO_PAY_LIFECYCLE_SCHEMA",
    "PROCURE_TO_PAY_PROPOSAL_RESULT_SCHEMA",
    "PROCURE_TO_PAY_SCOPE_SCHEMA",
    "PROCURE_TO_PAY_TRANSITION_PROPOSAL_SCHEMA",
    "PROCURE_TO_PAY_TRANSITION_REQUEST_SCHEMA",
    "PROCURE_TO_PAY_TRANSITION_VALIDATION_RESULT_SCHEMA",
    "SPRING_PROCUREMENT_TRANSITION_OPERATION",
    "SPRING_TRANSITION_EVIDENCE_SCHEMA",
    "ZERO_DIGEST",
    "ApproveRequisitionCommand",
    "AuthorityOutcome",
    "CloseProcureToPayCommand",
    "CreatePurchaseOrderCommand",
    "CreateRequisitionCommand",
    "EvaluateThreeWayMatchCommand",
    "ExceptionResolution",
    "GoodsReceipt",
    "GoodsReceiptLine",
    "IssuePurchaseOrderCommand",
    "ProcureToPayLifecycle",
    "ProcureToPayClosure",
    "ProcureToPayLifecycleError",
    "ProcureToPayProposalResult",
    "ProcureToPayScope",
    "ProcureToPayState",
    "ProcureToPayTransitionProposal",
    "ProcureToPayTransitionRecord",
    "ProcureToPayTransitionRequest",
    "ProcureToPayTransitionValidationResult",
    "ProposeProcureToPayTransitionPrimitive",
    "PurchaseOrder",
    "PurchaseOrderLine",
    "PurchaseRequisition",
    "RecordGoodsReceiptCommand",
    "RequisitionLine",
    "ResolveMatchExceptionCommand",
    "SpringProcureToPayTransitionEvidence",
    "SubmitRequisitionCommand",
    "SupplierInvoice",
    "SupplierInvoiceLine",
    "ThreeWayMatchFinding",
    "ThreeWayMatchPolicy",
    "ThreeWayMatchResult",
    "TransitionCommand",
    "propose_transition",
    "spring_authority_binding_digest",
    "validate_transition_evidence",
]
