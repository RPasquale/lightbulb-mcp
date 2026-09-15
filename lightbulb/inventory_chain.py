"""The inventory chain: one replay-fenced stock position per SKU and location, from a counted position to costed units sold.

Stock is cash the storefront chain never saw.  Supply-chain controls
evaluated replenishment plan lines as a no-effect projection, the product
cycle carried an inventory-readiness flag, and settled batches counted the
units each SKU sold, but nothing held the position: no ledger said what was
on hand, at what cost, when to reorder, what the supplier was owed for it,
or what the units that sold actually cost.  ``INVENTORY_LIFECYCLE`` does:

    counted -> reorder_proposed -> purchase_committed -> received -> counted   (the cycle)
    counted | reorder_proposed | purchase_committed | received
            -(recognise_cogs | recount | write_down)-> same status
    recount beyond the tolerance, or units sold beyond the units held
            -> reconciliation_required                                        (terminal)
    any non-terminal -> discontinued                                          (terminal, with a reason)

Every hop consumes a sealed artifact and the caller asserts nothing:

* ``count_receipt`` opens the position from a host-lane inventory read;
  the opening cost is the policy's standard unit cost.
* ``reorder_proposal`` is computed from the policy (reorder point, safety
  stock, lead time) and the position; the guard recomputes it.
* ``purchase_receipt`` commits the exact proposed quantity to the policy's
  supplier; a plan may demand a ``commitment`` authority proof.
* ``goods_receipt`` consumes a host-lane receiving read against the open
  purchase; short receipts are allowed, late ones need reconciliation.
* ``landed_cost_receipt`` consumes the supplier's paid or approved
  ``PayableCaseState`` replayed against its plan: the bill must equal the
  purchase price of the units received (the three-way match), freight and
  duty are operator lines with evidence, and the weighted average unit
  cost moves.
* ``cogs_receipt`` consumes a settled ``SettlementBatchState`` replayed
  against its plan and takes this SKU's units from the batch's own lines;
  cost of goods sold is those units at the average cost, and a batch is
  costed once.

``inventory_cogs_receipt`` hands the cost register the COGS of one batch as
a proven source; ``expected_bill`` tells the payables chain what a supplier
bill for the open purchase must look like.  Nothing here reads a provider,
writes to one, or persists anything.
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
    add_days,
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

INVENTORY_KIND = "inventory_chain"
INVENTORY_GOLDEN_LOOP = "inventory.demand_signal_to_replenished_stock@0.1.0"
INVENTORY_PLAN_SCHEMA = "lightbulb.inventory_chain_plan.v1"
EXPECTED_BILL_SCHEMA = "lightbulb.inventory_expected_bill.v1"
MAX_INVENTORY_TRANSITIONS = 400
INVENTORY_TOOLS: frozenset[str] = frozenset({"shopify.get_inventory_levels", "square.get_inventory", "ecommerce.inventory_levels", "host.stock_count"})
RECEIVING_TOOLS: frozenset[str] = frozenset({"host.goods_receipt", "supplier.advice_shipping_notice", "shopify.get_inventory_levels", "square.get_inventory"})
SETTLED_BATCH_STATUSES: frozenset[str] = frozenset({"payout_settled", "net_revenue_recorded", "reconciled"})
COSTABLE_PAYABLE_STATUSES: frozenset[str] = frozenset({"approved", "scheduled", "paid", "cleared"})
_QTY = Decimal("0.001")
_HUNDRED = Decimal("100")

INVENTORY_STATUSES: tuple[str, ...] = ("counted", "reorder_proposed", "purchase_committed", "received", "reconciliation_required", "discontinued")
TERMINAL_INVENTORY_STATUSES: frozenset[str] = frozenset({"reconciliation_required", "discontinued"})
INVENTORY_EVENTS: tuple[str, ...] = ("count", "recognise_cogs", "propose_reorder", "commit_purchase", "receive", "record_landed_cost", "recount", "write_down", "restock", "issue", "discontinue")
_OPEN: tuple[str, ...] = ("counted", "reorder_proposed", "purchase_committed", "received")
_INVENTORY_TABLE: dict[tuple[str, str], str] = {
    ("new", "count"): "counted",
    ("counted", "propose_reorder"): "reorder_proposed",
    ("reorder_proposed", "commit_purchase"): "purchase_committed",
    ("purchase_committed", "receive"): "received",
    ("received", "record_landed_cost"): "counted",
    **{(status, "recognise_cogs"): status for status in _OPEN},
    **{(status, "recount"): status for status in _OPEN},
    **{(status, "write_down"): status for status in _OPEN},
    **{(status, "restock"): status for status in _OPEN},
    **{(status, "issue"): status for status in _OPEN},
    **{(status, "discontinue"): "discontinued" for status in _OPEN},
}


class InventoryChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise InventoryChainError(code, message)


def _dec(value: Any, *, field_name: str, quantum: Decimal, allow_negative: bool = False) -> Decimal:
    """Exact decimal parsing at the field's own quantum; money helpers round to cents, quantities and unit costs do not."""

    try:
        result = Decimal(str(value))
    except Exception as exc:  # noqa: BLE001 - any non-decimal input is one refusal
        raise ValueError(f"{field_name} must be a decimal number") from exc
    if not result.is_finite():
        raise ValueError(f"{field_name} must be finite")
    if result < 0 and not allow_negative:
        raise ValueError(f"{field_name} must not be negative")
    return result.quantize(quantum)


def _qty(value: Any, *, field_name: str) -> Decimal:
    return _dec(value, field_name=field_name, quantum=_QTY)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class SkuPolicy(StrictModel):
    sku_ref: OpaqueRef
    location_ref: OpaqueRef
    supplier_ref: OpaqueRef
    unit_of_measure: ShortText = "each"
    standard_unit_cost: Decimal
    reorder_point: Decimal
    reorder_quantity: Decimal
    safety_stock: Decimal = Field(default=Decimal("0"), validate_default=True)
    lead_time_days: int = Field(default=14, ge=0, le=365)

    @field_validator("standard_unit_cost", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="standard_unit_cost")

    @field_validator("reorder_point", "reorder_quantity", "safety_stock", mode="before")
    @classmethod
    def _quantities(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _qty(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> "SkuPolicy":
        if self.standard_unit_cost <= 0 or self.reorder_quantity <= 0:
            raise ValueError("a policy prices a unit and reorders a positive quantity")
        return self

    @property
    def key(self) -> str:
        return f"{self.sku_ref}@{self.location_ref}"


class InventoryChainPlan(StrictModel):
    """What the chain enforces: the per-SKU policies, the count tolerance, the receipt window, and whether purchases need authority."""

    schema_id: str = Field(default=INVENTORY_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    policies: tuple[SkuPolicy, ...] = Field(min_length=1, max_length=2000)
    count_variance_tolerance_percent: Decimal = Field(default=Decimal("2"), validate_default=True)
    late_receipt_tolerance_days: int = Field(default=14, ge=0, le=180)
    dead_stock_days: int = Field(default=90, ge=1, le=730)
    require_purchase_authority: bool = False
    product_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("policies", mode="before")
    @classmethod
    def _policies(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("count_variance_tolerance_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="count_variance_tolerance_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "InventoryChainPlan":
        keys = [policy.key for policy in self.policies]
        if len(keys) != len(set(keys)):
            raise ValueError("one policy per SKU and location")
        if not skip_digests(info) and self.plan_digest != sealed_digest(InventoryChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def policy(self, sku_ref: str, location_ref: str) -> SkuPolicy | None:
        return next((item for item in self.policies if item.sku_ref == sku_ref and item.location_ref == location_ref), None)


def compile_inventory_chain(company_ref: str, *, currency: str, policies: Sequence[Mapping[str, Any]], product_plan: Any = None, overrides: Mapping[str, Any] | None = None) -> InventoryChainPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "policies": [dict(detached(item)) for item in policies], **dict(overrides or {})}
    if product_plan is not None:
        raw["product_plan_digest"] = str(dict(detached(product_plan)).get("plan_digest") or stable_digest(detached(product_plan)))
    return seal(InventoryChainPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class InventoryReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    sku_ref: OpaqueRef | None = None
    location_ref: OpaqueRef | None = None
    on_hand: Decimal | None = None
    count_provenance: dict[str, Any] | None = None
    count_digest: Sha256Digest | None = None
    counted_at: str | None = None
    proposed_quantity: Decimal | None = None
    expected_receipt_at: str | None = None
    po_ref: OpaqueRef | None = None
    supplier_ref: OpaqueRef | None = None
    quantity: Decimal | None = None
    unit_price: Decimal | None = None
    amount: Decimal | None = None
    authorization_proof: dict[str, Any] | None = None
    received_quantity: Decimal | None = None
    received_at: str | None = None
    receiving_provenance: dict[str, Any] | None = None
    receiving_digest: Sha256Digest | None = None
    payable_source: dict[str, Any] | None = None
    payable_plan: dict[str, Any] | None = None
    freight_amount: Decimal | None = None
    duty_amount: Decimal | None = None
    settlement_source: dict[str, Any] | None = None
    settlement_plan: dict[str, Any] | None = None
    units_sold: Decimal | None = None
    batch_ref: OpaqueRef | None = None
    write_down_units: Decimal | None = None
    write_down_amount: Decimal | None = None
    restock_units: Decimal | None = None
    restock_source: Sha256Digest | None = None
    restock_condition: ShortText | None = None
    issue_units: Decimal | None = None
    issue_ref: OpaqueRef | None = None
    issue_purpose: ShortText | None = None
    issued_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("on_hand", "proposed_quantity", "quantity", "received_quantity", "units_sold", "write_down_units", "restock_units", "issue_units", mode="before")
    @classmethod
    def _quantities(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else _qty(value, field_name=str(info.field_name))

    @field_validator("unit_price", "amount", "freight_amount", "duty_amount", "write_down_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("counted_at", "expected_receipt_at", "received_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class StockIssue(StrictModel):
    issue_ref: OpaqueRef
    purpose: ShortText
    units: Decimal
    unit_cost: Decimal
    value: Decimal
    issued_at: str

    @field_validator("units", "unit_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return Decimal(str(value))

    @field_validator("value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")


class InventoryLedger(StrictModel):
    sku_ref: str | None = None
    location_ref: str | None = None
    supplier_ref: str | None = None
    unit_of_measure: str | None = None
    on_hand: Decimal = Field(default=Decimal("0"), validate_default=True)
    inbound: Decimal = Field(default=Decimal("0"), validate_default=True)
    avg_unit_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    stock_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    reorder_point: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_counted_at: str | None = None
    count_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    proposed_quantity: Decimal = Field(default=Decimal("0"), validate_default=True)
    proposed_at: str | None = None
    expected_receipt_at: str | None = None
    po_ref: str | None = None
    committed_quantity: Decimal = Field(default=Decimal("0"), validate_default=True)
    committed_unit_price: Decimal = Field(default=Decimal("0"), validate_default=True)
    committed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    committed_at: str | None = None
    purchase_approval_ref: str | None = None
    received_quantity: Decimal = Field(default=Decimal("0"), validate_default=True)
    received_at: str | None = None
    receiving_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    landed_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    landed_cost_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    freight_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    duty_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    purchases: int = Field(default=0, ge=0)
    cogs_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    cogs_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    units_sold_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_cogs_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_cogs_units: Decimal = Field(default=Decimal("0"), validate_default=True)
    last_cogs_batch_ref: str | None = None
    last_cogs_at: str | None = None
    last_sale_at: str | None = None
    shrinkage_units: Decimal = Field(default=Decimal("0"), validate_default=True)
    shrinkage_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    write_down_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    restock_sources: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    restocked_units_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    issues: tuple[StockIssue, ...] = Field(default_factory=tuple, max_length=400)
    issued_units_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    issued_value_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    oversold_units: Decimal = Field(default=Decimal("0"), validate_default=True)
    reconciliation_reason: str | None = None
    discontinue_reason: str | None = None
    outcome: Literal["open", "reconciliation_required", "discontinued"] = "open"

    @field_validator("count_digests", "receiving_digests", "landed_sources", "cogs_sources", "restock_sources", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("on_hand", "inbound", "reorder_point", "proposed_quantity", "committed_quantity", "received_quantity", "units_sold_total", "last_cogs_units", "shrinkage_units", "oversold_units", "restocked_units_total", "issued_units_total", mode="before")
    @classmethod
    def _quantities(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _dec(value, field_name=str(info.field_name), quantum=_QTY, allow_negative=True)

    @field_validator("stock_value", "committed_unit_price", "committed_amount", "landed_cost_total", "freight_total", "duty_total", "cogs_total", "last_cogs_amount", "shrinkage_value", "write_down_total", "issued_value_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("avg_unit_cost", mode="before")
    @classmethod
    def _unit_cost(cls, value: Any) -> Decimal:
        return _dec(value, field_name="avg_unit_cost", quantum=Decimal("0.0001"))

    @property
    def available(self) -> Decimal:
        return self.on_hand + self.inbound


class InventoryEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    purchase_order_sent: Literal[False] = False
    stock_adjusted_at_provider: Literal[False] = False
    provider_read: Literal[False] = False


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM)


def _revalue(data: dict[str, Any], on_hand: Decimal, value: Decimal) -> None:
    avg = (value / on_hand).quantize(Decimal("0.0001")) if on_hand > 0 else Decimal("0")
    data.update({"on_hand": str(on_hand.quantize(_QTY)), "stock_value": str(_money(value if on_hand > 0 else Decimal("0"))), "avg_unit_cost": str(avg)})


def _proposal(plan: InventoryChainPlan, policy: SkuPolicy, on_hand: Decimal, inbound: Decimal, now: str) -> tuple[Decimal, str]:
    gap = policy.reorder_point + policy.safety_stock - on_hand - inbound
    quantity = max(policy.reorder_quantity, gap).quantize(_QTY)
    return quantity, add_days(now, policy.lead_time_days)


def _apply_inventory(plan: InventoryChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "count":
        require(r.sku_ref is not None and r.location_ref is not None and r.on_hand is not None and r.count_provenance is not None and r.count_digest is not None and r.counted_at is not None, "COUNT_MISSING", "a count names the SKU, the location, the units on hand, the read provenance, its digest, and the count time")
        policy = plan.policy(str(r.sku_ref), str(r.location_ref))
        require(policy is not None, "SKU_UNPOLICED", f"{r.sku_ref} at {r.location_ref} has no policy in this plan")
        assert policy is not None and r.on_hand is not None
        require(str(dict(r.count_provenance or {}).get("output_digest")) == r.count_digest, "COUNT_NOT_BOUND", "the provenance does not seal this count")
        require(parsed(r.counted_at) <= parsed(at), "COUNT_FROM_FUTURE", "a count cannot post-date its recording")
        data.update({"sku_ref": r.sku_ref, "location_ref": r.location_ref, "supplier_ref": policy.supplier_ref, "unit_of_measure": policy.unit_of_measure, "reorder_point": str(policy.reorder_point), "last_counted_at": r.counted_at, "count_digests": [r.count_digest]})
        _revalue(data, r.on_hand, r.on_hand * policy.standard_unit_cost)
        return next_status, data
    policy = plan.policy(str(data["sku_ref"]), str(data["location_ref"]))
    assert policy is not None
    on_hand, inbound = Decimal(str(data["on_hand"])), Decimal(str(data["inbound"]))
    value = Decimal(str(data["stock_value"]))
    if event == "propose_reorder":
        require(r.proposed_quantity is not None and r.expected_receipt_at is not None, "PROPOSAL_MISSING", "a reorder names the quantity and the expected receipt")
        require(on_hand + inbound <= policy.reorder_point, "ABOVE_REORDER_POINT", f"{on_hand + inbound} available is above the reorder point {policy.reorder_point}")
        quantity, expected = _proposal(plan, policy, on_hand, inbound, at)
        require(r.proposed_quantity == quantity and r.expected_receipt_at == expected, "PROPOSAL_NOT_DERIVED", f"the policy proposes {quantity} arriving {expected}; use reorder_proposal")
        data.update({"proposed_quantity": str(quantity), "proposed_at": at, "expected_receipt_at": expected})
    elif event == "commit_purchase":
        require(r.po_ref is not None and r.supplier_ref is not None and r.quantity is not None and r.unit_price is not None and r.amount is not None, "PURCHASE_MISSING", "a purchase names the order, the supplier, the quantity, the unit price, and the amount")
        assert r.quantity is not None and r.unit_price is not None and r.amount is not None
        require(r.supplier_ref == policy.supplier_ref, "SUPPLIER_MISMATCH", f"{data['sku_ref']} is sourced from {policy.supplier_ref}, not {r.supplier_ref}")
        require(r.quantity == Decimal(str(data["proposed_quantity"])), "PURCHASE_QUANTITY_MISMATCH", f"the proposal was {data['proposed_quantity']} units")
        require(r.unit_price > 0 and r.amount == _money(r.quantity * r.unit_price), "PURCHASE_AMOUNT_MISMATCH", "the amount is the quantity at the unit price")
        approval_ref = None
        if plan.require_purchase_authority:
            require(r.authorization_proof is not None, "PURCHASE_NOT_AUTHORIZED", f"committing {r.amount} {plan.currency} to {policy.supplier_ref} needs commitment authority", "await_approval")
            from lightbulb.authority_matrix import require_authorization_proof
            proof = require_authorization_proof(r.authorization_proof, category="commitment", amount=r.amount, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
            require(proof.engine == INVENTORY_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
            approval_ref = proof.approval_task_id
        data.update({"po_ref": r.po_ref, "committed_quantity": str(r.quantity), "committed_unit_price": str(r.unit_price), "committed_amount": str(r.amount), "committed_at": at, "inbound": str((inbound + r.quantity).quantize(_QTY)), "purchase_approval_ref": approval_ref, "purchases": int(data.get("purchases", 0)) + 1})
    elif event == "receive":
        require(r.received_quantity is not None and r.received_at is not None and r.receiving_provenance is not None and r.receiving_digest is not None and r.po_ref is not None, "RECEIPT_MISSING", "a goods receipt names the order, the units, the time, the read provenance, and its digest")
        assert r.received_quantity is not None and r.received_at is not None
        require(r.po_ref == data.get("po_ref"), "PURCHASE_MISMATCH", f"the receipt is for {r.po_ref}; the open purchase is {data.get('po_ref')}")
        require(str(dict(r.receiving_provenance or {}).get("output_digest")) == r.receiving_digest, "RECEIPT_NOT_BOUND", "the provenance does not seal this goods receipt")
        require(r.receiving_digest not in data.get("receiving_digests", ()), "RECEIPT_ALREADY_APPLIED", "this goods receipt was already applied")
        committed = Decimal(str(data["committed_quantity"]))
        require(0 < r.received_quantity <= committed, "RECEIPT_QUANTITY_INVALID", f"received {r.received_quantity}; the order was for {committed}")
        late_by = (parsed(r.received_at) - parsed(str(data["expected_receipt_at"]))).days
        require(late_by <= plan.late_receipt_tolerance_days, "RECEIPT_LATE", f"the goods arrived {late_by} days after the expected receipt; confirm the order before costing it", "manual_reconciliation")
        require(parsed(str(data["committed_at"])) <= parsed(r.received_at) <= parsed(at), "RECEIPT_TIME_INVALID", "goods are received after the purchase and before the recording")
        unit_price = Decimal(str(data["committed_unit_price"]))
        provisional = r.received_quantity * unit_price
        _revalue(data, on_hand + r.received_quantity, value + provisional)
        data.update({"inbound": str((inbound - committed).quantize(_QTY)), "received_quantity": str(r.received_quantity), "received_at": r.received_at, "receiving_digests": [*data.get("receiving_digests", ()), r.receiving_digest]})
    elif event == "record_landed_cost":
        require(r.payable_source is not None and r.payable_plan is not None, "BILL_NOT_PROVEN", "landed cost requires the supplier's replayed payable case and its plan, not a typed total")
        from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE
        try:
            bill_plan, bill = PAYABLES_CHAIN_LIFECYCLE.bind(r.payable_plan, r.payable_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "BILL_NOT_PROVEN", f"the payable must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(bill_plan.company_ref == plan.company_ref and bill.scope.currency == plan.currency, "BILL_SCOPE_MISMATCH", "the bill belongs to another company or currency")
        require(bill.status in COSTABLE_PAYABLE_STATUSES, "BILL_NOT_APPROVED", f"the payable case is {bill.status}; only an approved bill costs stock")
        require(str(bill.ledger.supplier_ref) == policy.supplier_ref, "SUPPLIER_MISMATCH", f"the bill is from {bill.ledger.supplier_ref}, not {policy.supplier_ref}")
        require(bill.state_digest not in data.get("landed_sources", ()), "BILL_ALREADY_COSTED", "this bill already costed stock")
        require(parsed(bill.transition_history[-1].command.occurred_at) <= parsed(at), "BILL_FROM_FUTURE", "the bill cannot come from the future")
        received = Decimal(str(data["received_quantity"]))
        expected_bill = _money(received * Decimal(str(data["committed_unit_price"])))
        bill_amount = _money(bill.ledger.amount)
        require(bill_amount == expected_bill, "BILL_PO_MISMATCH", f"the bill is {bill_amount}; {received} units at {data['committed_unit_price']} is {expected_bill}", "manual_reconciliation")
        freight, duty = _money(r.freight_amount or 0), _money(r.duty_amount or 0)
        require(freight >= 0 and duty >= 0, "LANDED_COST_INVALID", "freight and duty are never negative")
        landed = bill_amount + freight + duty
        provisional = _money(received * Decimal(str(data["committed_unit_price"])))
        _revalue(data, on_hand, value - provisional + landed)
        data.update({"landed_sources": [*data.get("landed_sources", ()), bill.state_digest], "landed_cost_total": str(_money(Decimal(str(data["landed_cost_total"])) + landed)), "freight_total": str(_money(Decimal(str(data["freight_total"])) + freight)), "duty_total": str(_money(Decimal(str(data["duty_total"])) + duty)), "po_ref": None, "committed_quantity": "0", "committed_unit_price": "0", "committed_amount": "0", "received_quantity": "0", "proposed_quantity": "0", "expected_receipt_at": None})
    elif event == "recognise_cogs":
        require(r.settlement_source is not None and r.settlement_plan is not None and r.units_sold is not None and r.batch_ref is not None, "BATCH_NOT_PROVEN", "cost of goods sold requires the replayed settlement batch, its plan, the units, and the batch ref")
        assert r.units_sold is not None
        from lightbulb.storefront_settlement_chain import STOREFRONT_SETTLEMENT_LIFECYCLE
        try:
            batch_plan, batch = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(r.settlement_plan, r.settlement_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "BATCH_NOT_PROVEN", f"the batch must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(batch_plan.company_ref == plan.company_ref and batch.scope.currency == plan.currency, "BATCH_SCOPE_MISMATCH", "the batch belongs to another company or currency")
        require(batch.status in SETTLED_BATCH_STATUSES, "BATCH_NOT_SETTLED", f"the batch is {batch.status}; only settled sales cost stock")
        require(batch.scope.entity_ref == r.batch_ref, "BATCH_MISMATCH", "the batch ref must be the replayed batch's entity")
        require(batch.state_digest not in data.get("cogs_sources", ()), "BATCH_ALREADY_COSTED", "this batch already costed this position")
        require(parsed(batch.transition_history[-1].command.occurred_at) <= parsed(at), "BATCH_FROM_FUTURE", "the batch cannot come from the future")
        line = next((item for item in batch.ledger.sku_lines if str(item.sku_ref) == str(data["sku_ref"])), None)
        require(line is not None, "SKU_NOT_IN_BATCH", f"{data['sku_ref']} sold no units in {r.batch_ref}")
        assert line is not None
        require(r.units_sold == Decimal(line.units).quantize(_QTY), "UNITS_NOT_DERIVED", f"the batch sold {line.units} units of {data['sku_ref']}")
        avg = Decimal(str(data["avg_unit_cost"]))
        sold = r.units_sold
        sold_at = str(batch.ledger.window_end or batch.transition_history[-1].command.occurred_at)
        if sold > on_hand:
            cogs = _money(on_hand * avg)
            data.update({"oversold_units": str((sold - on_hand).quantize(_QTY)), "reconciliation_reason": f"{r.batch_ref} sold {sold} units but only {on_hand} were held", "outcome": "reconciliation_required", "cogs_sources": [*data.get("cogs_sources", ()), batch.state_digest], "cogs_total": str(_money(Decimal(str(data["cogs_total"])) + cogs)), "units_sold_total": str((Decimal(str(data["units_sold_total"])) + sold).quantize(_QTY)), "last_cogs_amount": str(cogs), "last_cogs_units": str(sold), "last_cogs_batch_ref": r.batch_ref, "last_cogs_at": sold_at, "last_sale_at": sold_at})
            _revalue(data, Decimal("0"), Decimal("0"))
            return "reconciliation_required", data
        cogs = _money(sold * avg)
        _revalue(data, on_hand - sold, value - sold * avg)
        data.update({"cogs_sources": [*data.get("cogs_sources", ()), batch.state_digest], "cogs_total": str(_money(Decimal(str(data["cogs_total"])) + cogs)), "units_sold_total": str((Decimal(str(data["units_sold_total"])) + sold).quantize(_QTY)), "last_cogs_amount": str(cogs), "last_cogs_units": str(sold), "last_cogs_batch_ref": r.batch_ref, "last_cogs_at": sold_at, "last_sale_at": sold_at})
    elif event == "recount":
        require(r.on_hand is not None and r.count_provenance is not None and r.count_digest is not None and r.counted_at is not None, "COUNT_MISSING", "a recount carries the units, the read provenance, its digest, and the count time")
        assert r.on_hand is not None and r.counted_at is not None
        require(str(dict(r.count_provenance or {}).get("output_digest")) == r.count_digest, "COUNT_NOT_BOUND", "the provenance does not seal this count")
        require(r.count_digest not in data.get("count_digests", ()), "COUNT_ALREADY_APPLIED", "this count was already applied")
        require(parsed(str(data.get("last_counted_at") or at)) <= parsed(r.counted_at) <= parsed(at), "COUNT_TIME_INVALID", "a recount follows the last count and precedes its recording")
        variance = (r.on_hand - on_hand).quantize(_QTY)
        avg = Decimal(str(data["avg_unit_cost"]))
        data.update({"last_counted_at": r.counted_at, "count_digests": [*data.get("count_digests", ()), r.count_digest]})
        if variance < 0:
            data.update({"shrinkage_units": str((Decimal(str(data["shrinkage_units"])) - variance).quantize(_QTY)), "shrinkage_value": str(_money(Decimal(str(data["shrinkage_value"])) - variance * avg))})
        _revalue(data, r.on_hand, value + variance * avg)
        tolerance = (on_hand * plan.count_variance_tolerance_percent / _HUNDRED) if on_hand > 0 else Decimal("0")
        if abs(variance) > tolerance and variance != 0:
            data.update({"reconciliation_reason": f"recount moved {data['sku_ref']} by {variance} units against a tolerance of {tolerance.quantize(_QTY)}: {str(command.reason)[:200]}", "outcome": "reconciliation_required"})
            return "reconciliation_required", data
    elif event == "write_down":
        require(r.write_down_amount is not None and r.write_down_amount > 0, "WRITE_DOWN_MISSING", "a write-down names a positive amount")
        assert r.write_down_amount is not None
        units = r.write_down_units or Decimal("0")
        require(units <= on_hand and _money(r.write_down_amount) <= _money(value), "WRITE_DOWN_EXCEEDS_STOCK", "a write-down cannot exceed the units or the value held")
        _revalue(data, on_hand - units, value - r.write_down_amount)
        data.update({"write_down_total": str(_money(Decimal(str(data["write_down_total"])) + r.write_down_amount))})
    elif event == "restock":
        require(r.restock_units is not None and r.restock_units > 0 and r.restock_source is not None and r.restock_condition is not None, "RESTOCK_MISSING", "a restock names the units, the fulfilment state digest they came from, and their condition")
        assert r.restock_units is not None
        require(r.restock_condition == "resaleable", "RESTOCK_NOT_RESALEABLE", f"{r.restock_condition} units do not return to saleable stock; write them down instead")
        require(r.restock_source not in data.get("restock_sources", ()), "RESTOCK_ALREADY_APPLIED", "this return already restocked the position")
        avg = Decimal(str(data["avg_unit_cost"])) if Decimal(str(data["avg_unit_cost"])) > 0 else policy.standard_unit_cost
        _revalue(data, on_hand + r.restock_units, value + r.restock_units * avg)
        data.update({"restock_sources": [*data.get("restock_sources", ()), r.restock_source], "restocked_units_total": str((Decimal(str(data["restocked_units_total"])) + r.restock_units).quantize(_QTY))})
    elif event == "issue":
        require(r.issue_units is not None and r.issue_units > 0 and r.issue_ref is not None and r.issue_purpose is not None and r.issued_at is not None, "ISSUE_MISSING", "an issue names the units, what they were issued to, why, and when")
        assert r.issue_units is not None
        require(r.issue_units <= on_hand, "ISSUE_EXCEEDS_STOCK", f"{r.issue_units} units requested; {on_hand} held")
        require(all(str(r.issue_ref) != item["issue_ref"] for item in data.get("issues", ())), "ISSUE_ALREADY_APPLIED", f"{r.issue_ref} already drew stock from this position")
        require(parsed(str(r.issued_at)) <= parsed(at), "ISSUE_FROM_FUTURE", "an issue cannot come from the future")
        avg = Decimal(str(data["avg_unit_cost"]))
        issue_value = _money(r.issue_units * avg)
        record = StockIssue(issue_ref=str(r.issue_ref), purpose=str(r.issue_purpose), units=r.issue_units.quantize(_QTY), unit_cost=avg, value=issue_value, issued_at=str(r.issued_at)).to_dict()
        _revalue(data, on_hand - r.issue_units, value - r.issue_units * avg)
        data.update({"issues": [*[dict(item) for item in data.get("issues", ())], record], "issued_units_total": str((Decimal(str(data["issued_units_total"])) + r.issue_units).quantize(_QTY)), "issued_value_total": str(_money(Decimal(str(data["issued_value_total"])) + issue_value))})
    elif event == "discontinue":
        data.update({"discontinue_reason": str(command.reason)[:300], "outcome": "discontinued"})
    return next_status, data


INVENTORY_LIFECYCLE = LifecycleSpec(entity="stock_position", schema_prefix=INVENTORY_KIND, statuses=INVENTORY_STATUSES, terminal=TERMINAL_INVENTORY_STATUSES, events=INVENTORY_EVENTS, table=_INVENTORY_TABLE, opening_event="count", reason_events=("recount", "write_down", "discontinue"), apply=_apply_inventory, ledger_model=InventoryLedger, receipt_model=InventoryReceipt, effect_boundary_model=InventoryEffectBoundary, plan_model=InventoryChainPlan, max_transitions=MAX_INVENTORY_TRANSITIONS)
StockPositionState = INVENTORY_LIFECYCLE.State


def open_stock_position(plan: InventoryChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return INVENTORY_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_stock_position(plan: InventoryChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return INVENTORY_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def _provenance(provenance: Mapping[str, Any] | Any, *, tools: frozenset[str], lanes: tuple[str, ...], code: str) -> dict[str, Any]:
    raw = dict(detached(provenance))
    _require(str(raw.get("source_tool", "")) in tools, code, f"expected a read from {sorted(tools)}, got {raw.get('source_tool')!r}")
    _require(str(raw.get("lane", "")) in lanes, code, f"a {raw.get('source_tool')} read arrives on {lanes}, not {raw.get('lane')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(raw.get(key)), code, f"the provenance lacks {key}")
    return raw


def _level_row(payload: Any, *, sku_ref: str, location_ref: str) -> dict[str, Any]:
    raw = detached(payload)
    rows = list(raw.get("levels") or raw.get("inventory_levels") or raw.get("counts") or raw.get("data") or []) if isinstance(raw, Mapping) else list(raw)
    for item in rows:
        row = dict(item)
        if str(row.get("sku_ref") or row.get("sku") or "") == sku_ref and str(row.get("location_ref") or row.get("location_id") or row.get("location") or "") == location_ref:
            return row
    raise InventoryChainError("SKU_NOT_IN_READ", f"{sku_ref} at {location_ref} is not in the inventory read")


def count_receipt(plan: InventoryChainPlan | Mapping[str, Any], provenance: Mapping[str, Any] | Any, payload: Any, *, sku_ref: str, location_ref: str) -> dict[str, Any]:
    """The opening (or recount) receipt from a host-lane inventory read: this SKU's row at this location."""

    parsed_plan = InventoryChainPlan.model_validate(detached(plan))
    _require(parsed_plan.policy(sku_ref, location_ref) is not None, "SKU_UNPOLICED", f"{sku_ref} at {location_ref} has no policy in this plan")
    prov = _provenance(provenance, tools=INVENTORY_TOOLS, lanes=("host_read", "governed_read"), code="COUNT_NOT_BOUND")
    _require(str(prov["output_digest"]) == stable_digest(detached(payload)), "COUNT_NOT_BOUND", "the provenance does not seal this exact inventory read")
    row = _level_row(payload, sku_ref=sku_ref, location_ref=location_ref)
    on_hand = row.get("available") if row.get("available") is not None else row.get("on_hand", row.get("quantity"))
    _require(on_hand is not None, "COUNT_INCOMPLETE", "the inventory row carries no available or on-hand quantity")
    return {"sku_ref": sku_ref, "location_ref": location_ref, "on_hand": str(_qty(on_hand, field_name="on_hand")), "count_provenance": prov, "count_digest": str(prov["output_digest"]), "counted_at": str(row.get("updated_at") or prov.get("window_end") or prov["completed_at"]), "evidence_refs": [f"count:{prov['observation_ref']}"]}


def reorder_proposal(plan: InventoryChainPlan | Mapping[str, Any], state: Any, *, now: str) -> dict[str, Any]:
    """The reorder the policy derives from the position; refused above the reorder point."""

    parsed_plan, bound = INVENTORY_LIFECYCLE.bind(plan, state)
    policy = parsed_plan.policy(str(bound.ledger.sku_ref), str(bound.ledger.location_ref))
    assert policy is not None
    stamp = timestamp(now, field_name="now")
    _require(bound.ledger.available <= policy.reorder_point, "ABOVE_REORDER_POINT", f"{bound.ledger.available} available is above the reorder point {policy.reorder_point}")
    quantity, expected = _proposal(parsed_plan, policy, bound.ledger.on_hand, bound.ledger.inbound, stamp)
    return {"proposed_quantity": str(quantity), "expected_receipt_at": expected, "evidence_refs": [f"policy:{policy.key}"]}


def purchase_receipt(*, po_ref: str, supplier_ref: str, quantity: Any, unit_price: Any, authorization: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """A purchase as the operator commits it; the guard holds it to the proposal, the supplier, and the plan's authority rule."""

    qty, price = _qty(quantity, field_name="quantity"), decimal_value(unit_price, field_name="unit_price")
    receipt: dict[str, Any] = {"po_ref": po_ref, "supplier_ref": supplier_ref, "quantity": str(qty), "unit_price": str(price), "amount": str(_money(qty * price)), "evidence_refs": [f"po:{po_ref}"]}
    if authorization is not None:
        from lightbulb.authority_matrix import authorization_evidence

        evidence = authorization_evidence(authorization)
        receipt["authorization_proof"] = evidence["authorization_proof"]
        receipt["evidence_refs"] = [*receipt["evidence_refs"], *evidence["evidence_refs"]]
    return receipt


def goods_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, po_ref: str) -> dict[str, Any]:
    """From a host-lane receiving read: the units that arrived against the order and when."""

    prov = _provenance(provenance, tools=RECEIVING_TOOLS, lanes=("host_read", "governed_read"), code="RECEIPT_NOT_BOUND")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "RECEIPT_NOT_BOUND", "the provenance does not seal this exact goods receipt")
    _require(str(raw.get("po_ref") or raw.get("purchase_order_ref") or "") == po_ref, "PURCHASE_MISMATCH", f"the goods receipt names {raw.get('po_ref')}, not {po_ref}")
    quantity = raw.get("received_quantity", raw.get("quantity"))
    received_at = raw.get("received_at") or raw.get("completed_at")
    _require(quantity is not None and received_at is not None, "RECEIPT_INCOMPLETE", "a goods receipt carries the units received and the time")
    return {"po_ref": po_ref, "received_quantity": str(_qty(quantity, field_name="received_quantity")), "received_at": timestamp(str(received_at), field_name="received_at"), "receiving_provenance": prov, "receiving_digest": str(prov["output_digest"]), "evidence_refs": [f"receipt:{prov['observation_ref']}"]}


def landed_cost_receipt(payable_state: Any, *, source_plan: Any, freight_amount: Any = "0", duty_amount: Any = "0", evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    """From the supplier's payable case: retained whole and replayed at the consuming transition."""

    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise InventoryChainError("BILL_NOT_PROVEN", "retain the original payable state and its sealed plan") from exc
    _require(state.status in COSTABLE_PAYABLE_STATUSES, "BILL_NOT_APPROVED", f"the payable case is {state.status}")
    return {"payable_source": state.to_dict(), "payable_plan": plan.to_dict(), "freight_amount": str(_money(decimal_value(freight_amount, field_name="freight_amount"))), "duty_amount": str(_money(decimal_value(duty_amount, field_name="duty_amount"))), "evidence_refs": [f"payable:{state.scope.entity_ref}:{state.state_digest[:16]}", *evidence_refs]}


def cogs_receipt(batch_state: Any, *, source_plan: Any, sku_ref: str) -> dict[str, Any]:
    """From a settled storefront batch: this SKU's units from the batch's own lines."""

    from lightbulb.storefront_settlement_chain import STOREFRONT_SETTLEMENT_LIFECYCLE

    try:
        plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(source_plan, batch_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise InventoryChainError("BATCH_NOT_PROVEN", "retain the original settlement batch and its sealed plan") from exc
    _require(state.status in SETTLED_BATCH_STATUSES, "BATCH_NOT_SETTLED", f"the batch is {state.status}")
    line = next((item for item in state.ledger.sku_lines if str(item.sku_ref) == sku_ref), None)
    _require(line is not None, "SKU_NOT_IN_BATCH", f"{sku_ref} sold no units in {state.scope.entity_ref}")
    assert line is not None
    return {"settlement_source": state.to_dict(), "settlement_plan": plan.to_dict(), "units_sold": str(Decimal(line.units).quantize(_QTY)), "batch_ref": state.scope.entity_ref, "evidence_refs": [f"batch:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def write_down_receipt(*, amount: Any, units: Any = "0", evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    return {"write_down_amount": str(_money(decimal_value(amount, field_name="amount"))), "write_down_units": str(_qty(units, field_name="units")), "evidence_refs": list(evidence_refs)}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def expected_bill(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """What the supplier's bill for the open purchase must say before it costs stock: the three-way match, stated up front."""

    plan, bound = INVENTORY_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.po_ref is not None, "NO_OPEN_PURCHASE", "the position has no open purchase")
    units = ledger.received_quantity if ledger.received_quantity > 0 else ledger.committed_quantity
    return {"schema": EXPECTED_BILL_SCHEMA, "po_ref": ledger.po_ref, "supplier_ref": ledger.supplier_ref, "currency": plan.currency, "units": str(units), "unit_price": str(ledger.committed_unit_price), "amount": str(_money(units * ledger.committed_unit_price)), "basis": "received units at the committed unit price" if ledger.received_quantity > 0 else "committed units at the committed unit price; the received quantity governs once goods arrive", "position_digest": bound.state_digest}


def inventory_cogs_receipt(state: Any, *, source_plan: Any, centre_ref: str, engine: str | None = None, category: str | None = None) -> dict[str, Any]:
    """The cost register's source receipt for the last batch this position costed: replayed, keyed by SKU and batch, never typed.

    The centre, and the engine or overhead category it carries, are the operator's
    attribution choice; the amount, the time, and the identity come from the replayed position.
    """

    plan, bound = INVENTORY_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(ledger.last_cogs_batch_ref is not None and ledger.last_cogs_at is not None, "NO_COGS_RECOGNISED", "the position has costed no batch")
    return {"source_kind": "inventory_cogs", "source_ref": f"inventory_cogs:{ledger.sku_ref}:{ledger.location_ref}:{ledger.last_cogs_batch_ref}", "source_digest": bound.state_digest, "centre_ref": centre_ref, "amount": str(ledger.last_cogs_amount), "currency": plan.currency, "occurred_at": ledger.last_cogs_at, "engine": engine, "category": category, "operator_supplied": engine is not None or category is not None, "source_state": bound.to_dict(), "source_plan": plan.to_dict(), "evidence_refs": [f"stock_position:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def stockout_risk_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    """A ``signals.stockout_risk`` payload when the position is at or below its reorder point with nothing inbound; ``None`` otherwise."""

    plan, bound = INVENTORY_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    policy = plan.policy(str(ledger.sku_ref), str(ledger.location_ref))
    assert policy is not None
    if bound.status in TERMINAL_INVENTORY_STATUSES or ledger.available > policy.reorder_point or ledger.inbound > 0:
        return None
    return {"name": "signals.stockout_risk", "producer": INVENTORY_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"sku_ref": str(ledger.sku_ref), "location_ref": str(ledger.location_ref), "on_hand": str(ledger.on_hand), "reorder_point": str(policy.reorder_point), "source_digest": bound.state_digest}}


STOCK_ISSUE_SCHEMA = "lightbulb.inventory_stock_issue.v1"


def issue_receipt(*, units: Any, issue_ref: str, purpose: str, issued_at: str) -> dict[str, Any]:
    """Stock drawn from the position for a job, a sample, or internal use, at the position's weighted average cost."""

    return {"issue_units": str(Decimal(str(units)).quantize(_QTY)), "issue_ref": issue_ref, "issue_purpose": purpose, "issued_at": timestamp(issued_at, field_name="issued_at"), "evidence_refs": [f"issue:{issue_ref}"]}


def stock_issue(state: Any, *, source_plan: Any, issue_ref: str) -> dict[str, Any]:
    """What the work order chain binds: one issue from the replayed position, valued at the cost the position carried."""

    plan, bound = INVENTORY_LIFECYCLE.bind(source_plan, state)
    record = next((item for item in bound.ledger.issues if item.issue_ref == issue_ref), None)
    _require(record is not None, "ISSUE_UNKNOWN", f"{issue_ref} drew no stock from this position")
    assert record is not None
    return {"schema": STOCK_ISSUE_SCHEMA, "sku_ref": bound.ledger.sku_ref, "location_ref": bound.ledger.location_ref, "issue_ref": record.issue_ref, "purpose": record.purpose, "units": str(record.units), "unit_cost": str(record.unit_cost), "value": str(record.value), "currency": plan.currency, "issued_at": record.issued_at, "position_ref": bound.scope.entity_ref, "source_digest": bound.state_digest}


def inventory_summary(states: Sequence[Any], *, now: str) -> dict[str, Any]:
    """Stock value, positions below their reorder point, dead stock, and the money the chain has proven."""

    stamp = timestamp(now, field_name="now")
    open_states = [state for state in states if state.status not in TERMINAL_INVENTORY_STATUSES]
    value = sum((state.ledger.stock_value for state in open_states), Decimal("0"))
    below = [state.scope.entity_ref for state in open_states if state.ledger.available <= state.ledger.reorder_point]
    dead = [state.scope.entity_ref for state in open_states if state.ledger.on_hand > 0 and (state.ledger.last_sale_at is None or (parsed(stamp) - parsed(state.ledger.last_sale_at)).days > 90)]
    counts = {status: sum(1 for state in states if state.status == status) for status in INVENTORY_STATUSES}
    return {"positions": len(states), "by_status": counts, "stock_value": str(_money(value)), "inbound_value": str(_money(sum((state.ledger.committed_amount for state in open_states), Decimal("0")))), "below_reorder_point": below, "dead_stock": dead, "cogs_recognised": str(_money(sum((state.ledger.cogs_total for state in states), Decimal("0")))), "units_sold": str(sum((state.ledger.units_sold_total for state in states), Decimal("0")).quantize(_QTY)), "shrinkage_value": str(_money(sum((state.ledger.shrinkage_value for state in states), Decimal("0")))), "write_downs": str(_money(sum((state.ledger.write_down_total for state in states), Decimal("0"))))}


INVENTORY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": INVENTORY_KIND,
    "golden_loop": INVENTORY_GOLDEN_LOOP,
    "stages": ["count", "propose_reorder", "commit_purchase", "receive", "record_landed_cost", "recognise_cogs", "restock", "issue"],
    "statuses": list(INVENTORY_STATUSES),
    "events": list(INVENTORY_EVENTS),
    "hops": {"count": "host-lane inventory read at the policy's standard cost", "propose_reorder": "policy-derived quantity and expected receipt", "commit_purchase": "operator purchase at the proposal, optionally under commitment authority", "receive": "host-lane goods receipt against the open purchase", "record_landed_cost": "the supplier's replayed payable case equal to received units at the committed price, plus freight and duty", "recognise_cogs": "a settled storefront batch's own SKU line at the weighted average cost", "restock": "resaleable units from a returned order in the fulfilment chain, fenced by its state digest", "issue": "stock drawn for a job, a sample, or internal use at the position's weighted average cost, once per issue"},
    "required_connectors": ["shopify", "stripe", "quickbooks", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a reorder is derived from the policy and the position; the caller cannot type a quantity",
        "a bill costs stock only when it equals the received units at the committed price; anything else is reconciled by a human",
        "units sold come from the settled batch's own SKU line and each batch costs a position once",
        "selling more than is held or a recount beyond tolerance stops the position for reconciliation",
        "the cost register receives COGS as a replayed source keyed by SKU and batch",
    ],
}

__all__ = ["COSTABLE_PAYABLE_STATUSES", "EXPECTED_BILL_SCHEMA", "INVENTORY_EVENTS", "INVENTORY_GOLDEN_LOOP", "INVENTORY_KIND", "INVENTORY_LIFECYCLE", "INVENTORY_MANIFEST", "INVENTORY_STATUSES", "INVENTORY_TOOLS", "RECEIVING_TOOLS", "SETTLED_BATCH_STATUSES", "TERMINAL_INVENTORY_STATUSES", "InventoryChainError", "InventoryChainPlan", "InventoryLedger", "InventoryReceipt", "SkuPolicy", "StockPositionState", "advance_stock_position", "cogs_receipt", "compile_inventory_chain", "count_receipt", "expected_bill", "goods_receipt", "inventory_cogs_receipt", "inventory_summary", "landed_cost_receipt", "open_stock_position", "purchase_receipt", "reorder_proposal", "stockout_risk_signal", "write_down_receipt"]
