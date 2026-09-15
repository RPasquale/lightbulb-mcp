"""The fulfilment chain: one replay-fenced lifecycle per paid order, from capture to the customer holding the goods.

The storefront settlement chain proved the money a window of orders produced
and the inventory chain proved what the units cost, but nothing followed the
goods: whether the order was fulfilled inside the promise, shipped with
tracking, delivered, lost, damaged, or returned, and what came back to
stock.  ``FULFILMENT_LIFECYCLE`` does:

    captured -> fulfilment_created -> shipped -> delivered -> closed     (terminal)
    shipped | delivered -> exception -> shipped (reshipped) | returned | cancelled
    delivered -> returned -> closed
    captured | fulfilment_created -> cancelled                          (terminal, with a reason)

* ``order_receipt`` opens the case from a paid order row of a storefront
  order read with provenance; the SKU units and the total are the row's.
* ``fulfilment_receipt`` and ``shipment_receipt`` consume fulfilment-order
  and carrier reads; days to ship and the late flag are computed against
  the plan's promise.
* ``delivery_receipt`` consumes the carrier's delivered read; days to
  deliver and the late flag are computed.
* ``exception_receipt`` names a typed exception; ``return_receipt``
  consumes a returns read and never returns more units than were ordered.

``restock_receipt`` hands the inventory chain the resaleable units that
came back; ``refund_expectation`` tells the refund chain what a refund for
this order must look like; ``late_shipments_signal`` gives the operating
system its signal.  Nothing here ships anything, refunds anyone, or
persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

FULFILMENT_KIND = "fulfilment_chain"
FULFILMENT_GOLDEN_LOOP = "commerce.paid_order_to_delivered_customer@0.1.0"
FULFILMENT_PLAN_SCHEMA = "lightbulb.fulfilment_plan.v1"
REFUND_EXPECTATION_SCHEMA = "lightbulb.fulfilment_refund_expectation.v1"
MAX_FULFILMENT_TRANSITIONS = 24
ORDER_TOOLS: frozenset[str] = frozenset({"ecommerce.search_orders", "ecommerce.get_order", "shopify.list_orders", "square.search_orders", "square.list_orders"})
FULFILMENT_TOOLS: frozenset[str] = frozenset({"shopify.list_fulfillment_orders", "host.fulfilment_orders", "host.warehouse_pick"})
CARRIER_TOOLS: frozenset[str] = frozenset({"host.carrier_tracking", "shopify.list_fulfillment_orders", "host.shipment_events"})
RETURN_TOOLS: frozenset[str] = frozenset({"host.returns", "shopify.list_refunds", "host.goods_receipt"})
PAID_STATUSES: frozenset[str] = frozenset({"paid", "partially_refunded", "refunded", "completed"})
ExceptionKind = Literal["lost", "damaged", "delayed", "returned_to_sender", "address_failure"]
ReturnCondition = Literal["resaleable", "damaged", "unknown"]
_HUNDRED = Decimal("100")
_QTY = Decimal("0.001")

FULFILMENT_STATUSES: tuple[str, ...] = ("captured", "fulfilment_created", "shipped", "delivered", "exception", "returned", "closed", "cancelled")
TERMINAL_FULFILMENT_STATUSES: frozenset[str] = frozenset({"closed", "cancelled"})
FULFILMENT_EVENTS: tuple[str, ...] = ("capture", "create_fulfilment", "ship", "deliver", "raise_exception", "reship", "receive_return", "close", "cancel")
_FULFILMENT_TABLE: dict[tuple[str, str], str] = {
    ("new", "capture"): "captured",
    ("captured", "create_fulfilment"): "fulfilment_created",
    ("fulfilment_created", "ship"): "shipped",
    ("shipped", "deliver"): "delivered",
    ("shipped", "raise_exception"): "exception",
    ("delivered", "raise_exception"): "exception",
    ("exception", "reship"): "shipped",
    ("exception", "receive_return"): "returned",
    ("delivered", "receive_return"): "returned",
    ("delivered", "close"): "closed",
    ("returned", "close"): "closed",
    ("captured", "cancel"): "cancelled",
    ("fulfilment_created", "cancel"): "cancelled",
    ("exception", "cancel"): "cancelled",
}


class FulfilmentChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise FulfilmentChainError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM)


def _units(value: Mapping[str, Any]) -> dict[str, Decimal]:
    return {str(key): Decimal(str(item)).quantize(_QTY) for key, item in dict(value or {}).items()}


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class FulfilmentPlan(StrictModel):
    """What the chain enforces: the store, the promise in days, the carriers allowed, and the return window."""

    schema_id: str = Field(default=FULFILMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    store_ref: OpaqueRef
    promised_ship_days: int = Field(default=2, ge=0, le=60)
    promised_delivery_days: int = Field(default=7, ge=1, le=120)
    carriers: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    require_tracking: bool = True
    return_window_days: int = Field(default=30, ge=0, le=365)
    storefront_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("carriers", mode="before")
    @classmethod
    def _carriers(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "FulfilmentPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(FulfilmentPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_fulfilment_chain(company_ref: str, *, currency: str, store_ref: str, storefront_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> FulfilmentPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "store_ref": store_ref, **dict(overrides or {})}
    if storefront_plan is not None:
        raw["storefront_plan_digest"] = str(dict(detached(storefront_plan)).get("plan_digest") or stable_digest(detached(storefront_plan)))
    return seal(FulfilmentPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class FulfilmentReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    order_ref: OpaqueRef | None = None
    order_created_at: str | None = None
    financial_status: ShortText | None = None
    order_total: Decimal | None = None
    order_currency: ShortText | None = None
    units: dict[str, Decimal] = Field(default_factory=dict)
    order_provenance: dict[str, Any] | None = None
    order_digest: Sha256Digest | None = None
    customer_ref: OpaqueRef | None = None
    fulfilment_ref: OpaqueRef | None = None
    location_ref: OpaqueRef | None = None
    fulfilment_provenance: dict[str, Any] | None = None
    fulfilment_digest: Sha256Digest | None = None
    tracking_ref: OpaqueRef | None = None
    carrier: ShortText | None = None
    shipped_at: str | None = None
    shipment_provenance: dict[str, Any] | None = None
    shipment_digest: Sha256Digest | None = None
    delivered_at: str | None = None
    delivery_provenance: dict[str, Any] | None = None
    delivery_digest: Sha256Digest | None = None
    exception_kind: ExceptionKind | None = None
    exception_at: str | None = None
    returned_units: dict[str, Decimal] = Field(default_factory=dict)
    return_condition: ReturnCondition | None = None
    received_at: str | None = None
    return_provenance: dict[str, Any] | None = None
    return_digest: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("order_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="order_total")

    @field_validator("units", "returned_units", mode="before")
    @classmethod
    def _unit_maps(cls, value: Any) -> dict[str, Decimal]:
        return _units(value)

    @field_validator("order_created_at", "shipped_at", "delivered_at", "exception_at", "received_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class FulfilmentLedger(StrictModel):
    order_ref: str | None = None
    order_created_at: str | None = None
    order_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    units: dict[str, Decimal] = Field(default_factory=dict)
    order_digest: str | None = None
    customer_ref: str | None = None
    fulfilment_ref: str | None = None
    location_ref: str | None = None
    fulfilment_created_at: str | None = None
    tracking_ref: str | None = None
    carrier: str | None = None
    shipped_at: str | None = None
    days_to_ship: int | None = None
    shipped_late: bool = False
    shipments: int = Field(default=0, ge=0)
    delivered_at: str | None = None
    days_to_deliver: int | None = None
    delivered_late: bool = False
    exceptions: tuple[str, ...] = Field(default_factory=tuple, max_length=24)
    last_exception_at: str | None = None
    returned_units: dict[str, Decimal] = Field(default_factory=dict)
    return_condition: str | None = None
    returned_at: str | None = None
    return_digest: str | None = None
    closed_at: str | None = None
    cancel_reason: str | None = None
    outcome: Literal["open", "closed", "cancelled"] = "open"

    @field_validator("exceptions", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("order_total", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="order_total")

    @field_validator("units", "returned_units", mode="before")
    @classmethod
    def _unit_maps(cls, value: Any) -> dict[str, Decimal]:
        return _units(value)


class FulfilmentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    shipment_created: Literal[False] = False
    refund_issued: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_fulfilment(plan: FulfilmentPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "capture":
        require(r.order_ref is not None and r.order_created_at is not None and r.financial_status is not None and r.order_total is not None and r.order_provenance is not None and r.order_digest is not None, "ORDER_MISSING", "a capture names the order, when it was placed, its financial status, its total, the read provenance, and its digest")
        require(str(dict(r.order_provenance or {}).get("output_digest")) == r.order_digest, "ORDER_NOT_BOUND", "the provenance does not seal this order read")
        require(str(r.financial_status).lower() in PAID_STATUSES, "ORDER_NOT_PAID", f"the order is {r.financial_status}; only paid orders are fulfilled")
        require(str(r.order_currency or plan.currency).upper() == plan.currency, "ORDER_CURRENCY_MISMATCH", f"the order is in {r.order_currency}; the chain runs in {plan.currency}")
        require(bool(r.units) and all(value > 0 for value in r.units.values()), "ORDER_UNITS_MISSING", "a paid order carries at least one SKU line with units")
        require(parsed(str(r.order_created_at)) <= parsed(at), "ORDER_FROM_FUTURE", "an order cannot be placed after it is captured")
        data.update({"order_ref": r.order_ref, "order_created_at": r.order_created_at, "order_total": str(_money(r.order_total)), "units": {key: str(value) for key, value in r.units.items()}, "order_digest": r.order_digest, "customer_ref": r.customer_ref})
    elif event == "create_fulfilment":
        require(r.fulfilment_ref is not None and r.fulfilment_provenance is not None and r.fulfilment_digest is not None, "FULFILMENT_MISSING", "a fulfilment names itself, the read provenance, and its digest")
        require(str(dict(r.fulfilment_provenance or {}).get("output_digest")) == r.fulfilment_digest, "FULFILMENT_NOT_BOUND", "the provenance does not seal this fulfilment read")
        data.update({"fulfilment_ref": r.fulfilment_ref, "location_ref": r.location_ref, "fulfilment_created_at": at})
    elif event in ("ship", "reship"):
        require(r.shipped_at is not None and r.shipment_provenance is not None and r.shipment_digest is not None, "SHIPMENT_MISSING", "a shipment names the time, the carrier read provenance, and its digest")
        require(str(dict(r.shipment_provenance or {}).get("output_digest")) == r.shipment_digest, "SHIPMENT_NOT_BOUND", "the provenance does not seal this shipment read")
        require(not plan.require_tracking or r.tracking_ref is not None, "TRACKING_MISSING", "this plan ships with tracking")
        require(not plan.carriers or (r.carrier is not None and r.carrier in plan.carriers), "CARRIER_NOT_ALLOWED", f"{r.carrier} is not a carrier this plan ships with")
        floor = data.get("fulfilment_created_at") or data["order_created_at"]
        require(parsed(str(floor)) <= parsed(str(r.shipped_at)) <= parsed(at), "SHIPMENT_TIME_INVALID", "a shipment follows the fulfilment and precedes its recording")
        days = (parsed(str(r.shipped_at)) - parsed(str(data["order_created_at"]))).days
        updates = {"tracking_ref": r.tracking_ref, "carrier": r.carrier, "shipped_at": r.shipped_at, "shipments": int(data.get("shipments", 0)) + 1}
        if event == "ship":
            updates.update({"days_to_ship": days, "shipped_late": days > plan.promised_ship_days})
        data.update(updates)
    elif event == "deliver":
        require(r.delivered_at is not None and r.delivery_provenance is not None and r.delivery_digest is not None, "DELIVERY_MISSING", "a delivery names the time, the carrier read provenance, and its digest")
        require(str(dict(r.delivery_provenance or {}).get("output_digest")) == r.delivery_digest, "DELIVERY_NOT_BOUND", "the provenance does not seal this delivery read")
        require(parsed(str(data["shipped_at"])) <= parsed(str(r.delivered_at)) <= parsed(at), "DELIVERY_TIME_INVALID", "a delivery follows the shipment and precedes its recording")
        days = (parsed(str(r.delivered_at)) - parsed(str(data["order_created_at"]))).days
        data.update({"delivered_at": r.delivered_at, "days_to_deliver": days, "delivered_late": days > plan.promised_delivery_days})
    elif event == "raise_exception":
        require(r.exception_kind is not None and r.exception_at is not None, "EXCEPTION_MISSING", "an exception names its kind and when it was observed")
        require(parsed(str(r.exception_at)) <= parsed(at), "EXCEPTION_FROM_FUTURE", "an exception cannot be observed in the future")
        data.update({"exceptions": [*data.get("exceptions", ()), str(r.exception_kind)], "last_exception_at": r.exception_at})
    elif event == "receive_return":
        require(bool(r.returned_units) and r.return_condition is not None and r.received_at is not None and r.return_provenance is not None and r.return_digest is not None, "RETURN_MISSING", "a return names the units by SKU, their condition, the time, the read provenance, and its digest")
        require(str(dict(r.return_provenance or {}).get("output_digest")) == r.return_digest, "RETURN_NOT_BOUND", "the provenance does not seal this return read")
        ordered = _units(data.get("units", {}))
        for sku, units in r.returned_units.items():
            require(sku in ordered and 0 < units <= ordered[sku], "RETURN_EXCEEDS_ORDER", f"{units} of {sku} returned against {ordered.get(sku, Decimal('0'))} ordered")
        delivered_at = data.get("delivered_at")
        if delivered_at is not None:
            window = (parsed(str(r.received_at)) - parsed(str(delivered_at))).days
            require(window <= plan.return_window_days, "RETURN_OUTSIDE_WINDOW", f"the return arrived {window} days after delivery; the window is {plan.return_window_days} days", "manual_reconciliation")
        require(parsed(str(r.received_at)) <= parsed(at), "RETURN_FROM_FUTURE", "a return cannot be received in the future")
        data.update({"returned_units": {key: str(value) for key, value in r.returned_units.items()}, "return_condition": r.return_condition, "returned_at": r.received_at, "return_digest": r.return_digest})
    elif event == "close":
        data.update({"closed_at": at, "outcome": "closed"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    return next_status, data


FULFILMENT_LIFECYCLE = LifecycleSpec(entity="order_fulfilment", schema_prefix=FULFILMENT_KIND, statuses=FULFILMENT_STATUSES, terminal=TERMINAL_FULFILMENT_STATUSES, events=FULFILMENT_EVENTS, table=_FULFILMENT_TABLE, opening_event="capture", reason_events=("cancel",), apply=_apply_fulfilment, ledger_model=FulfilmentLedger, receipt_model=FulfilmentReceipt, effect_boundary_model=FulfilmentEffectBoundary, plan_model=FulfilmentPlan, max_transitions=MAX_FULFILMENT_TRANSITIONS)
OrderFulfilmentState = FULFILMENT_LIFECYCLE.State


def open_order_fulfilment(plan: FulfilmentPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return FULFILMENT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_order_fulfilment(plan: FulfilmentPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return FULFILMENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in ("host_read", "governed_read"), code, f"a {raw.get('source_tool')} read arrives on a read lane, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def _order_rows(payload: Any) -> list[dict[str, Any]]:
    raw = detached(payload)
    if isinstance(raw, Mapping):
        return [dict(item) for item in (raw.get("orders") or raw.get("data") or raw.get("items") or [])]
    return [dict(item) for item in raw]


def order_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, order_ref: str) -> dict[str, Any]:
    """The opening receipt from one paid order row of a storefront order read."""

    prov = _provenance(provenance, tools=ORDER_TOOLS, code="ORDER_NOT_BOUND")
    _require(str(prov["output_digest"]) == stable_digest(detached(payload)), "ORDER_NOT_BOUND", "the provenance does not seal this exact order read")
    row = next((item for item in _order_rows(payload) if str(item.get("id") or item.get("legacyResourceId") or item.get("order_id") or "") == order_ref), None)
    _require(row is not None, "ORDER_NOT_IN_READ", f"order {order_ref} is not in the read")
    assert row is not None
    units: dict[str, str] = {}
    for line in row.get("line_items") or row.get("lineItems") or []:
        item = dict(line)
        sku = str(item.get("sku") or item.get("sku_ref") or item.get("variant_id") or "")
        quantity = item.get("quantity")
        _require(bool(sku) and quantity is not None, "ORDER_LINE_INCOMPLETE", "each line item names its SKU and quantity")
        units[sku] = str(Decimal(units.get(sku, "0")) + Decimal(str(quantity)))
    total = row.get("total_price") if row.get("total_price") is not None else row.get("totalPrice")
    _require(total is not None, "ORDER_TOTAL_MISSING", "the order carries its total")
    created = row.get("created_at") or row.get("createdAt")
    status = row.get("financial_status") or row.get("displayFinancialStatus") or ""
    currency = row.get("currency") or row.get("currencyCode")
    customer = row.get("customer") if isinstance(row.get("customer"), Mapping) else {}
    customer_id = customer.get("id") or customer.get("legacyResourceId") or row.get("customer_ref")
    customer_ref = None if customer_id in (None, "") else f"customer:{str(customer_id).rsplit('/', 1)[-1]}"
    return {"customer_ref": customer_ref, "order_ref": order_ref, "order_created_at": timestamp(str(created), field_name="created_at"), "financial_status": str(status).lower(), "order_total": str(_money(Decimal(str(total)))), "order_currency": None if currency is None else str(currency).upper(), "units": units, "order_provenance": prov, "order_digest": str(prov["output_digest"]), "evidence_refs": [f"order:{order_ref}", f"orders:{prov['observation_ref']}"]}


def fulfilment_receipt(provenance: Mapping[str, Any] | Any, payload: Any, *, order_ref: str) -> dict[str, Any]:
    """From a fulfilment-order read: the fulfilment opened for this order and the location it ships from."""

    prov = _provenance(provenance, tools=FULFILMENT_TOOLS, code="FULFILMENT_NOT_BOUND")
    _require(str(prov["output_digest"]) == stable_digest(detached(payload)), "FULFILMENT_NOT_BOUND", "the provenance does not seal this exact fulfilment read")
    raw = detached(payload)
    rows = [dict(item) for item in (raw.get("fulfillment_orders") or raw.get("fulfilment_orders") or raw.get("data") or [])] if isinstance(raw, Mapping) else [dict(item) for item in raw]
    row = next((item for item in rows if str(item.get("order_id") or item.get("order_ref") or "") == order_ref), None)
    _require(row is not None and bool(row.get("id") or row.get("fulfilment_ref")), "FULFILMENT_NOT_IN_READ", f"no fulfilment order for {order_ref} is in the read")
    assert row is not None
    location = row.get("assigned_location_id") or row.get("location_ref") or row.get("location_id")
    return {"fulfilment_ref": str(row.get("id") or row.get("fulfilment_ref")), "location_ref": None if location is None else str(location), "fulfilment_provenance": prov, "fulfilment_digest": str(prov["output_digest"]), "evidence_refs": [f"fulfilment:{prov['observation_ref']}"]}


def shipment_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a carrier or fulfilment read: tracking, carrier, and the time the parcel left."""

    prov = _provenance(provenance, tools=CARRIER_TOOLS, code="SHIPMENT_NOT_BOUND")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "SHIPMENT_NOT_BOUND", "the provenance does not seal this exact shipment read")
    shipped_at = raw.get("shipped_at") or raw.get("in_transit_at") or raw.get("created_at")
    _require(shipped_at is not None, "SHIPMENT_INCOMPLETE", "a shipment read carries the time the parcel left")
    tracking = raw.get("tracking_number") or raw.get("tracking_ref")
    return {"tracking_ref": None if tracking is None else str(tracking), "carrier": None if raw.get("carrier") is None else str(raw["carrier"]), "shipped_at": timestamp(str(shipped_at), field_name="shipped_at"), "shipment_provenance": prov, "shipment_digest": str(prov["output_digest"]), "evidence_refs": [f"shipment:{prov['observation_ref']}"]}


def delivery_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the carrier's delivered read."""

    prov = _provenance(provenance, tools=CARRIER_TOOLS, code="DELIVERY_NOT_BOUND")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "DELIVERY_NOT_BOUND", "the provenance does not seal this exact delivery read")
    _require(str(raw.get("status") or raw.get("event") or "").lower() in ("delivered", "delivery"), "NOT_DELIVERED", f"the carrier read says {raw.get('status')}, not delivered")
    delivered_at = raw.get("delivered_at") or raw.get("occurred_at")
    _require(delivered_at is not None, "DELIVERY_INCOMPLETE", "a delivery read carries the delivery time")
    return {"delivered_at": timestamp(str(delivered_at), field_name="delivered_at"), "delivery_provenance": prov, "delivery_digest": str(prov["output_digest"]), "evidence_refs": [f"delivery:{prov['observation_ref']}"]}


def exception_receipt(*, kind: str, observed_at: str, detail: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"exception_kind": kind, "exception_at": timestamp(observed_at, field_name="observed_at"), "evidence_refs": [f"exception:{kind}"]}
    if detail:
        receipt["detail"] = detail[:600]
    return receipt


def return_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, condition: str = "unknown") -> dict[str, Any]:
    """From a returns or goods-receipt read: the units that came back by SKU and when."""

    prov = _provenance(provenance, tools=RETURN_TOOLS, code="RETURN_NOT_BOUND")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "RETURN_NOT_BOUND", "the provenance does not seal this exact return read")
    units: dict[str, str] = {}
    for line in raw.get("line_items") or raw.get("items") or raw.get("lines") or []:
        item = dict(line)
        sku = str(item.get("sku") or item.get("sku_ref") or "")
        _require(bool(sku) and item.get("quantity") is not None, "RETURN_LINE_INCOMPLETE", "each returned line names its SKU and quantity")
        units[sku] = str(Decimal(units.get(sku, "0")) + Decimal(str(item["quantity"])))
    received_at = raw.get("received_at") or raw.get("created_at")
    _require(bool(units) and received_at is not None, "RETURN_INCOMPLETE", "a return carries its lines and the time it was received")
    return {"returned_units": units, "return_condition": condition, "received_at": timestamp(str(received_at), field_name="received_at"), "return_provenance": prov, "return_digest": str(prov["output_digest"]), "evidence_refs": [f"return:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def restock_receipt(state: Any, *, source_plan: Any, sku_ref: str) -> dict[str, Any]:
    """The inventory chain's ``restock`` receipt: resaleable units of one SKU from a returned order, fenced by this state's digest."""

    _, bound = FULFILMENT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status == "returned", "ORDER_NOT_RETURNED", f"the order is {bound.status}")
    _require(ledger.return_condition == "resaleable", "RETURN_NOT_RESALEABLE", f"the return is {ledger.return_condition}; only resaleable units go back to stock")
    units = ledger.returned_units.get(sku_ref)
    _require(units is not None and units > 0, "SKU_NOT_RETURNED", f"{sku_ref} was not among the returned units")
    return {"restock_units": str(units), "restock_source": bound.state_digest, "restock_condition": "resaleable", "evidence_refs": [f"order_fulfilment:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def refund_expectation(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """What a refund for this order must say: the order, its total, and why."""

    plan, bound = FULFILMENT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    reason = "returned" if bound.status == "returned" else ("exception:" + ledger.exceptions[-1] if ledger.exceptions else "cancelled" if bound.status == "cancelled" else None)
    _require(reason is not None, "NO_REFUND_EXPECTED", f"an order that is {bound.status} expects no refund")
    return {"schema": REFUND_EXPECTATION_SCHEMA, "order_ref": ledger.order_ref, "currency": plan.currency, "amount": str(ledger.order_total), "reason": reason, "returned_units": {key: str(value) for key, value in ledger.returned_units.items()}, "source_digest": bound.state_digest}


def late_shipments_signal(states: Sequence[Any], *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    """A ``signals.late_shipments`` payload when any open order shipped late or is unshipped past the promise; ``None`` otherwise."""

    plan = FulfilmentPlan.model_validate(detached(source_plan))
    stamp = timestamp(emitted_at, field_name="emitted_at")
    late: list[str] = []
    digest = None
    for state in states:
        if state.status in TERMINAL_FULFILMENT_STATUSES:
            continue
        ledger = state.ledger
        unshipped_late = ledger.shipped_at is None and (parsed(stamp) - parsed(str(ledger.order_created_at))).days > plan.promised_ship_days
        if ledger.shipped_late or unshipped_late:
            late.append(str(ledger.order_ref))
            digest = digest or state.state_digest
    if not late:
        return None
    return {"name": "signals.late_shipments", "producer": FULFILMENT_KIND, "emitted_at": stamp, "payload": {"store_ref": plan.store_ref, "late_count": len(late), "order_refs": ",".join(late[:10]), "promised_ship_days": plan.promised_ship_days, "source_digest": str(digest)}}


def fulfilment_summary(states: Sequence[Any]) -> dict[str, Any]:
    shipped = [state for state in states if state.ledger.shipped_at is not None]
    delivered = [state for state in states if state.ledger.delivered_at is not None]
    counts = {status: sum(1 for state in states if state.status == status) for status in FULFILMENT_STATUSES}
    on_time_ship = None if not shipped else str((Decimal(sum(1 for state in shipped if not state.ledger.shipped_late)) / Decimal(len(shipped)) * _HUNDRED).quantize(Decimal("0.01")))
    on_time_delivery = None if not delivered else str((Decimal(sum(1 for state in delivered if not state.ledger.delivered_late)) / Decimal(len(delivered)) * _HUNDRED).quantize(Decimal("0.01")))
    days = [state.ledger.days_to_deliver for state in delivered if state.ledger.days_to_deliver is not None]
    returned = [state for state in states if state.ledger.returned_at is not None]
    return {"orders": len(states), "by_status": counts, "on_time_ship_percent": on_time_ship, "on_time_delivery_percent": on_time_delivery, "average_days_to_deliver": None if not days else str((Decimal(sum(days)) / Decimal(len(days))).quantize(Decimal("0.1"))), "exceptions": sum(len(state.ledger.exceptions) for state in states), "returns": len(returned), "return_rate_percent": None if not states else str((Decimal(len(returned)) / Decimal(len(states)) * _HUNDRED).quantize(Decimal("0.01"))), "order_value": str(_money(sum((state.ledger.order_total for state in states), Decimal("0"))))}


FULFILMENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": FULFILMENT_KIND,
    "golden_loop": FULFILMENT_GOLDEN_LOOP,
    "stages": ["capture", "create_fulfilment", "ship", "deliver", "receive_return", "close"],
    "statuses": list(FULFILMENT_STATUSES),
    "events": list(FULFILMENT_EVENTS),
    "hops": {"capture": "a paid order row of a storefront order read", "create_fulfilment": "fulfilment-order read naming the location", "ship": "carrier or fulfilment read with tracking; days to ship computed against the promise", "deliver": "carrier delivered read; days to deliver computed", "receive_return": "returns read; never more units than were ordered, inside the return window", "close": "delivered or returned"},
    "required_connectors": ["shopify", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "only a paid order is fulfilled and its units and total are the read's, never typed",
        "late is computed from the plan's promise; the caller cannot assert on-time",
        "a return never exceeds the order and only resaleable units reach the inventory chain",
        "refunds are expectations handed to the refund chain, never issued here",
    ],
}

__all__ = ["CARRIER_TOOLS", "FULFILMENT_EVENTS", "FULFILMENT_GOLDEN_LOOP", "FULFILMENT_KIND", "FULFILMENT_LIFECYCLE", "FULFILMENT_MANIFEST", "FULFILMENT_STATUSES", "FULFILMENT_TOOLS", "ORDER_TOOLS", "RETURN_TOOLS", "TERMINAL_FULFILMENT_STATUSES", "FulfilmentChainError", "FulfilmentLedger", "FulfilmentPlan", "FulfilmentReceipt", "OrderFulfilmentState", "advance_order_fulfilment", "compile_fulfilment_chain", "delivery_receipt", "exception_receipt", "fulfilment_receipt", "fulfilment_summary", "late_shipments_signal", "open_order_fulfilment", "order_receipt", "refund_expectation", "restock_receipt", "return_receipt", "shipment_receipt"]
