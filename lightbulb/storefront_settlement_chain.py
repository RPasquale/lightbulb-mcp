"""The storefront settlement chain: one replay-fenced lifecycle from a window of paid store orders to the payout that hit the bank.

``dtc_commerce`` and ``marketplace`` are two of the four archetypes and
neither binds the pipeline engine, so ``revenue_chain``'s only opening is
unreachable for a store and every storefront dollar reached a period either
as a hand-typed ``record_evidence`` or as gross Stripe balance revenue with
spend defaulted to zero: a number 8-15% too high that drove ``total_revenue``,
health, replan, and every memory prior.  Card money is a batch, not a deal:

    orders_captured -> payout_announced -> payout_settled
                    -> net_revenue_recorded -> reconciled        (terminal)
    orders_captured | payout_announced -> cancelled              (terminal)
    payout_announced | payout_settled | net_revenue_recorded
                    -> reconciliation_required                   (terminal)

Every hop consumes a read with :class:`ObservationProvenance` and nothing is
asserted by the caller: ``orders_receipt`` from ``ecommerce.search_orders``
(or a ``shopify.bulk_operation_result`` JSONL page for a large store),
``refunds_receipt`` from ``shopify.list_refunds`` / ``square.list_refunds``,
``fee_receipt`` from the governed ``stripe.list_balance_transactions`` split
by transaction type, ``payout_receipt`` from ``stripe.list_payouts`` /
``square.list_payouts`` / ``shopify.list_transactions``, and
``clearance_receipt`` from a closed finance period that reconciled both cash
and the revenue subledger.  The arithmetic is the proof: gross minus refunds
minus fees minus chargebacks minus the reserve equals the payout, or the
batch refuses rather than estimates.

What it hands on: ``period_evidence_receipt`` gives the operating period the
settled payout as revenue and the processor's take plus refunds as spend
(keyed by the batch state digest so a cost register can fence the double
count), ``merchant_settlement_source_balance`` gives the close an
independent cash / revenue-subledger source balance,
``merchant_payout_flows`` gives treasury the payout and reserve release as
scheduled flows, ``sku_margin_rows`` gives unit economics contribution rows
against a sealed standard-cost map, and a batch left in
``reconciliation_required`` is what ``exceptions_desk.exception_from_chain``
turns into a ``chain_reconciliation`` case.  Nothing here reads a provider,
writes to one, or moves money.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    iso,
    parsed,
    percent_value,
    ratio_percent,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_execution_bridge import ObservationProvenance
from lightbulb.finance_close_observations import SourceBalance
from lightbulb.governed_connector_contracts import GOVERNED_CONNECTOR_READ_TOOLS

STOREFRONT_SETTLEMENT_KIND = "storefront_settlement_chain"
STOREFRONT_SETTLEMENT_GOLDEN_LOOP = "growth.store_truth_to_attributed_revenue@0.1.0"
STOREFRONT_SETTLEMENT_PLAN_SCHEMA = "lightbulb.storefront_settlement_plan.v1"
STANDARD_COST_MAP_SCHEMA = "lightbulb.storefront_standard_cost_map.v1"
BATCH_STATE_SCHEMA = "lightbulb.storefront_settlement_state.v1"
MAX_BATCH_TRANSITIONS = 16
_HUNDRED = Decimal("100")

ORDER_TOOLS: tuple[str, ...] = ("ecommerce.search_orders", "shopify.bulk_operation_result")
REFUND_TOOLS: tuple[str, ...] = ("shopify.list_refunds", "square.list_refunds")
FEE_TOOL = "stripe.list_balance_transactions"
PAYOUT_TOOLS: tuple[str, ...] = ("stripe.list_payouts", "square.list_payouts", "shopify.list_transactions")
# Money was captured: anything else in the window is not this batch's cash.
PAID_ORDER_STATUSES: frozenset[str] = frozenset({"paid", "partially_refunded", "refunded", "completed"})

BATCH_STATUSES: tuple[str, ...] = ("orders_captured", "payout_announced", "payout_settled", "net_revenue_recorded", "reconciled", "cancelled", "reconciliation_required")
TERMINAL_BATCH_STATUSES: frozenset[str] = frozenset({"reconciled", "cancelled", "reconciliation_required"})
BATCH_EVENTS: tuple[str, ...] = ("capture_orders", "record_refunds", "announce_payout", "settle_payout", "record_net_revenue", "reconcile_settlement", "cancel", "require_reconciliation")
_BATCH_TABLE: dict[tuple[str, str], str] = {
    ("new", "capture_orders"): "orders_captured",
    ("orders_captured", "record_refunds"): "orders_captured",
    ("orders_captured", "announce_payout"): "payout_announced",
    ("payout_announced", "settle_payout"): "payout_settled",
    ("payout_settled", "record_net_revenue"): "net_revenue_recorded",
    ("net_revenue_recorded", "reconcile_settlement"): "reconciled",
    **{(status, "cancel"): "cancelled" for status in ("orders_captured", "payout_announced")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("payout_announced", "payout_settled", "net_revenue_recorded")},
}

# The close an AUD storefront can actually run: register under the key
# ``dtc_weekly_close`` in ``finance_close_engine.FINANCE_CLOSE_PROFILES``.
DTC_WEEKLY_CLOSE_PROFILE_KEY = "dtc_weekly_close"
DTC_WEEKLY_CLOSE_PROFILE: dict[str, Any] = {
    "profile": "custom",
    "name": "DTC weekly close",
    "currency": "AUD",
    "ledger_system": "xero",
    "period_days": 7,
    "materiality": "250",
    "variance_threshold_percent": "1",
    "required_reconciliations": ["cash", "revenue_subledger", "accounts_payable"],
    "independent_approver_required": True,
    "close_deadline_days": 3,
    "reopen_window_days": 14,
    "targets": {"max_days_to_close": 2, "max_open_exceptions": 0, "min_on_time_percent": "90"},
}

# Of the whole commerce surface only the fee read is governed today.  There is
# no ``shopify.list_orders``: it appears only in the growth loop's known-tools
# list, so orders arrive through ``ecommerce.search_orders`` or the bulk page.
PROPOSED_GOVERNED_READS: tuple[dict[str, str], ...] = (
    {"contract": "commerce.order_page", "tool": "ecommerce.search_orders", "shape": "orders[] with line_items, totals, financial_status", "why": "gross, discounts, shipping, tax and SKU units for a settlement window"},
    {"contract": "commerce.refund_page", "tool": "shopify.list_refunds", "shape": "refunds[] with order_id and transactions[].amount", "why": "the refunds netted out of one payout, correlated so one refund is netted once"},
    {"contract": "commerce.payout_page", "tool": "stripe.list_payouts", "shape": "data[] with amount, arrival_date, status", "why": "the bank-side payout the batch must reconcile to"},
)


def read_lane(tool: str) -> str:
    """Which lane a commerce read runs on today; everything but the Stripe fee read is a host read."""

    return "governed_read" if tool in GOVERNED_CONNECTOR_READ_TOOLS else "host_read"


class StorefrontSettlementPlan(StrictModel):
    """What the chain enforces: the store, the processor, how far the settlement may miss, and the fee ceiling above which a payout is a decision."""

    schema_id: Literal["lightbulb.storefront_settlement_plan.v1"] = Field(default=STOREFRONT_SETTLEMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    store_ref: OpaqueRef
    currency: CurrencyCode
    processor: Literal["stripe", "shopify_payments", "square", "paypal"] = "stripe"
    settlement_tolerance_percent: Decimal = Field(default=Decimal("0.50"), validate_default=True)
    max_effective_fee_percent: Decimal = Field(default=Decimal("5.00"), validate_default=True)
    reserve_release_days: int = Field(default=90, ge=1, le=365)
    require_clearance: bool = True
    centre_ref: OpaqueRef | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("settlement_tolerance_percent", "max_effective_fee_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> StorefrontSettlementPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(StorefrontSettlementPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_storefront_settlement(company_ref: str, *, store_ref: str, currency: str, overrides: Mapping[str, Any] | None = None) -> StorefrontSettlementPlan:
    return seal(StorefrontSettlementPlan, {"company_ref": company_ref, "store_ref": store_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class SkuLine(StrictModel):
    sku_ref: OpaqueRef
    units: int = Field(ge=0, le=1000000)
    net_sales: Decimal

    @field_validator("net_sales", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="net_sales")


class SettlementReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    source_observation: dict[str, Any] | None = None
    sibling_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    close_source: dict[str, Any] | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    currency: ShortText | None = None
    window_start: str | None = None
    window_end: str | None = None
    order_count: int | None = Field(default=None, ge=0, le=1000000)
    order_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=10000)
    unpaid_count: int | None = Field(default=None, ge=0, le=1000000)
    gross_sales: Decimal | None = None
    discounts: Decimal | None = None
    shipping_collected: Decimal | None = None
    tax_collected: Decimal | None = None
    orders_digest: Sha256Digest | None = None
    orders_source_tool: ShortText | None = None
    sku_lines: tuple[SkuLine, ...] = Field(default_factory=tuple, max_length=200)
    attribution_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    sibling_windows: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    refunds: Decimal | None = None
    refund_count: int | None = Field(default=None, ge=0, le=100000)
    refund_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    refunds_digest: Sha256Digest | None = None
    sibling_refund_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=400)
    payout_ref: OpaqueRef | None = None
    payout_amount: Decimal | None = None
    payout_arrival_at: str | None = None
    payout_digest: Sha256Digest | None = None
    payout_source_tool: ShortText | None = None
    fees: Decimal | None = None
    chargebacks: Decimal | None = None
    reserve_held: Decimal | None = None
    reserve_released: Decimal | None = None
    refunds_observed: Decimal | None = None
    gross_observed: Decimal | None = None
    payout_observed: Decimal | None = None
    fee_digest: Sha256Digest | None = None
    recognised_revenue: Decimal | None = None
    reserve_recognised: Decimal | None = None
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    reconciliation_ref: OpaqueRef | None = None
    period_end: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "sku_lines", "attribution_refs", "sibling_windows", "refund_refs", "sibling_refund_refs", "sibling_sources", "order_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("gross_sales", "discounts", "shipping_collected", "tax_collected", "refunds", "payout_amount", "fees", "chargebacks", "reserve_held", "reserve_released", "refunds_observed", "gross_observed", "payout_observed", "recognised_revenue", "reserve_recognised", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("window_start", "window_end", "payout_arrival_at", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class SettlementLedger(StrictModel):
    entity_scope: EngineScope | None = None
    store_ref: OpaqueRef | None = None
    order_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=10000)
    window_start: str | None = None
    window_end: str | None = None
    order_count: int = Field(default=0, ge=0)
    gross_sales: Decimal = Field(default=Decimal("0"), validate_default=True)
    discounts: Decimal = Field(default=Decimal("0"), validate_default=True)
    shipping_collected: Decimal = Field(default=Decimal("0"), validate_default=True)
    tax_collected: Decimal = Field(default=Decimal("0"), validate_default=True)
    refunds: Decimal = Field(default=Decimal("0"), validate_default=True)
    refund_count: int = Field(default=0, ge=0)
    refund_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=400)
    fees: Decimal = Field(default=Decimal("0"), validate_default=True)
    chargebacks: Decimal = Field(default=Decimal("0"), validate_default=True)
    reserve_held: Decimal = Field(default=Decimal("0"), validate_default=True)
    reserve_released: Decimal = Field(default=Decimal("0"), validate_default=True)
    net_settled: Decimal = Field(default=Decimal("0"), validate_default=True)
    recognised_revenue: Decimal = Field(default=Decimal("0"), validate_default=True)
    payout_ref: str | None = None
    payout_arrival_at: str | None = None
    payout_source_tool: str | None = None
    payout_digest: str | None = None
    orders_digest: str | None = None
    fee_digest: str | None = None
    sku_lines: tuple[SkuLine, ...] = Field(default_factory=tuple, max_length=200)
    attribution_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=50)
    effective_fee_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    days_order_to_cash: int | None = None
    settled_at: str | None = None
    recognised_at: str | None = None
    close_ref: str | None = None
    reconciled_at: str | None = None
    cancel_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "reconciled", "cancelled", "reconciliation_required"] = "open"

    @field_validator("sku_lines", "attribution_refs", "refund_refs", "order_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("gross_sales", "discounts", "shipping_collected", "tax_collected", "refunds", "fees", "chargebacks", "reserve_held", "reserve_released", "net_settled", "recognised_revenue", "effective_fee_percent", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SettlementEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    provider_read: Literal[False] = False
    payout_initiated: Literal[False] = False
    refund_issued: Literal[False] = False
    journal_posted: Literal[False] = False


def _money(value: Any, default: str = "0") -> Decimal:
    return Decimal(str(value if value is not None else default))


def _days(start: str | None, end: str) -> int:
    return 0 if not start else (parsed(end) - parsed(start)).days


def _overlaps(start: str, end: str, window: str) -> bool:
    parts = window.split("/")
    if len(parts) != 2:
        return False
    return parsed(start) < parsed(parts[1]) and parsed(parts[0]) < parsed(end)


def _apply_batch(plan: StorefrontSettlementPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "capture_orders":
        require(r.window_start is not None and r.window_end is not None and r.order_count is not None and r.gross_sales is not None and r.currency is not None and r.orders_digest is not None, "ORDERS_MISSING", "a captured batch names its window, order count, gross sales, currency, and the read digest that proved them")
        window_ordered = parsed(r.window_end) > parsed(r.window_start)
        require(window_ordered, "WINDOW_INVERTED", "the batch window ends after it starts")
        require(not r.unpaid_count, "ORDER_NOT_PAID", f"{r.unpaid_count} order(s) in the window are not paid; re-read the window filtered to paid orders")
        require(r.order_count > 0, "BATCH_EMPTY", "a settlement batch needs at least one paid order")
        currency_matches = r.currency.upper() == plan.currency
        require(currency_matches, "BATCH_CURRENCY_MISMATCH", f"the orders are in {r.currency}; the store settles in {plan.currency}")
        overlapping = [window for window in r.sibling_windows if _overlaps(r.window_start, r.window_end, window)]
        require(not overlapping, "WINDOW_OVERLAP", f"the window {r.window_start}/{r.window_end} intersects sibling batch window(s) {overlapping[:3]} for this store; one order settles in one batch", "do_not_replay")
        data.update({"window_start": r.window_start, "window_end": r.window_end, "order_count": r.order_count, "gross_sales": str(r.gross_sales), "discounts": str(r.discounts or 0), "shipping_collected": str(r.shipping_collected or 0), "tax_collected": str(r.tax_collected or 0), "orders_digest": r.orders_digest, "sku_lines": [line.to_dict() for line in r.sku_lines], "attribution_refs": list(r.attribution_refs)})
    elif event == "record_refunds":
        require(r.refunds is not None and r.refunds_digest is not None, "REFUNDS_MISSING", "a refund hop names the refunded amount and the read digest that proved it")
        currency_matches = r.currency is None or r.currency.upper() == plan.currency
        require(currency_matches, "BATCH_CURRENCY_MISMATCH", f"the refunds are in {r.currency}; the store settles in {plan.currency}")
        recorded = tuple(data.get("refund_refs", ()))
        clashes = [ref for ref in r.refund_refs if ref in recorded or ref in r.sibling_refund_refs]
        require(not clashes, "REFUND_ALREADY_NETTED", f"refund(s) {clashes[:3]} are already netted into this or a sibling batch; one refund is netted once", "do_not_replay")
        data.update({"refunds": str(_money(data.get("refunds")) + r.refunds), "refund_count": int(data.get("refund_count", 0)) + int(r.refund_count or len(r.refund_refs)), "refund_refs": [*recorded, *r.refund_refs]})
    elif event == "announce_payout":
        require(r.payout_ref is not None and r.payout_amount is not None and r.payout_arrival_at is not None and r.payout_digest is not None, "PAYOUT_MISSING", "an announced payout names its ref, amount, arrival, and the read digest that proved them")
        currency_matches = r.currency is None or r.currency.upper() == plan.currency
        require(currency_matches, "BATCH_CURRENCY_MISMATCH", f"the payout is in {r.currency}; the store settles in {plan.currency}")
        require(r.payout_amount > 0, "PAYOUT_AMOUNT_INVALID", "the payout amount is positive")
        data.update({"payout_ref": r.payout_ref, "net_settled": str(r.payout_amount), "payout_arrival_at": r.payout_arrival_at, "payout_digest": r.payout_digest, "payout_source_tool": r.payout_source_tool})
    elif event == "settle_payout":
        require(r.fees is not None and r.fee_digest is not None, "FEES_MISSING", "a settled payout names the processor fees and the balance-transaction digest that proved them")
        payout_arrived = parsed(str(data.get("payout_arrival_at"))) <= parsed(at)
        require(payout_arrived, "PAYOUT_IN_FUTURE", "a payout that has not arrived cannot settle a batch")
        gross, refunds, net = _money(data.get("gross_sales")), _money(data.get("refunds")), _money(data.get("net_settled"))
        fees, chargebacks = r.fees, r.chargebacks or Decimal("0")
        held, released = r.reserve_held or Decimal("0"), r.reserve_released or Decimal("0")
        expected = (gross - refunds - fees - chargebacks - held + released).quantize(MONEY_QUANTUM)
        variance = (expected - net).copy_abs()
        tolerance = (gross * plan.settlement_tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)
        require(variance <= tolerance, "SETTLEMENT_NOT_RECONCILED", f"gross {gross} - refunds {refunds} - fees {fees} - chargebacks {chargebacks} - reserve {(held - released).quantize(MONEY_QUANTUM)} = {expected}, but the payout was {net} ({variance} out, tolerance {tolerance}; the processor netted {r.refunds_observed} of refunds)", "manual_reconciliation")
        effective = ratio_percent(fees, gross) or Decimal("0")
        require(effective <= plan.max_effective_fee_percent, "EFFECTIVE_FEE_ABOVE_CEILING", f"the effective processor fee is {effective}% of gross, above the plan's {plan.max_effective_fee_percent}%; approve the batch or renegotiate the rate", "await_approval")
        data.update({"fees": str(fees), "chargebacks": str(chargebacks), "reserve_held": str(held), "reserve_released": str(released), "fee_digest": r.fee_digest, "effective_fee_percent": str(effective), "settled_at": at, "days_order_to_cash": _days(data.get("window_start"), str(data.get("payout_arrival_at")))})
    elif event == "record_net_revenue":
        require(r.recognised_revenue is not None, "NET_REVENUE_MISSING", "the revenue hop names the amount it recognises")
        net = _money(data.get("net_settled"))
        outstanding = (_money(data.get("reserve_held")) - _money(data.get("reserve_released"))).quantize(MONEY_QUANTUM)
        reserve_respected = not (outstanding > 0 and (r.recognised_revenue > net or (r.reserve_recognised or Decimal("0")) > _money(data.get("reserve_released"))))
        require(reserve_respected, "RESERVE_UNRELEASED", f"the processor still holds {outstanding}; a rolling reserve is revenue only once it is released and paid out")
        require(r.recognised_revenue == net, "NET_REVENUE_NOT_SETTLED_CASH", f"recognised {r.recognised_revenue} is not the settled payout {net}; period revenue is net settled cash, never gross orders", "manual_reconciliation")
        data.update({"recognised_revenue": str(r.recognised_revenue), "recognised_at": at})
    elif event == "reconcile_settlement":
        if plan.require_clearance:
            require(r.close_ref is not None and r.close_state_digest is not None and r.reconciliation_ref is not None and r.period_end is not None, "CLEARANCE_MISSING", "a clearance names the close, its state digest, the reconciliation, and the period end")
            close_covers_settlement = parsed(str(r.period_end)) >= parsed(str(data.get("settled_at")))
            require(close_covers_settlement, "CLOSE_BEFORE_SETTLEMENT", f"the close ends {r.period_end}, before the batch settled at {data.get('settled_at')}", "manual_reconciliation")
        data.update({"close_ref": r.close_ref, "reconciled_at": at, "outcome": "reconciled"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    return next_status, data


def _guarded_batch(plan: StorefrontSettlementPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    previous = deepcopy(data)
    try:
        result = _apply_batch(plan, next_status, status, data, command)
        _verify_transition_sources(plan, previous, result[1], command)
        return result
    except Rejected:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        require(False, getattr(exc, "code", "SOURCE_NOT_PROVEN"), str(exc))


STOREFRONT_SETTLEMENT_LIFECYCLE = LifecycleSpec(entity="settlement_batch", schema_prefix="storefront_settlement", statuses=BATCH_STATUSES, terminal=TERMINAL_BATCH_STATUSES, events=BATCH_EVENTS, table=_BATCH_TABLE, opening_event="capture_orders", reason_events=("cancel", "require_reconciliation"), apply=_guarded_batch, ledger_model=SettlementLedger, receipt_model=SettlementReceipt, effect_boundary_model=SettlementEffectBoundary, plan_model=StorefrontSettlementPlan, max_transitions=MAX_BATCH_TRANSITIONS)
SettlementBatchState = STOREFRONT_SETTLEMENT_LIFECYCLE.State


def open_settlement_batch(plan: StorefrontSettlementPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return STOREFRONT_SETTLEMENT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_scope": dict(detached(scope))})


def advance_settlement_batch(plan: StorefrontSettlementPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return STOREFRONT_SETTLEMENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the reads' sealed artifacts
# --------------------------------------------------------------------------- #


class StorefrontSettlementError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise StorefrontSettlementError(code, message)


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    known_tool = provenance.source_tool in tools
    _require(known_tool, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; provenance names {provenance.source_tool} (there is no shopify.list_orders: it exists only in the growth loop's known-tools list)")


def _sealed_page(provenance: ObservationProvenance, payload: Any) -> Any:
    """The page must hash to the digest the read sealed: a provenance proves the rows it was taken with, never any rows handed to it."""

    raw = detached(payload)
    page_is_the_read = stable_digest(raw) == provenance.output_digest
    _require(page_is_the_read, "PAGE_DIGEST_MISMATCH", f"the page does not hash to the read's output digest {provenance.output_digest[:16]}; these are not the rows the platform read")
    return raw


def _stamp(value: Any, *, field_name: str) -> str:
    stated = not isinstance(value, bool) and value is not None and value != ""
    _require(stated, "TIMESTAMP_MISSING", f"{field_name} is missing from the read")
    if isinstance(value, int) or str(value).isdigit():
        return iso(datetime.fromtimestamp(int(value), tz=timezone.utc))
    text = str(value)
    if "T" not in text:
        text = f"{text}T00:00:00Z"
    if not text.endswith("Z"):
        text = iso(datetime.fromisoformat(text))
    return timestamp(text, field_name=field_name)


def _minor(value: Any, *, field_name: str) -> Decimal:
    stated = not isinstance(value, bool) and value is not None
    _require(stated, "AMOUNT_MISSING", f"{field_name} is missing from the read")
    number = Decimal(str(value))
    _require(number.is_finite() and number == number.to_integral_value(), "AMOUNT_INVALID", "provider minor-unit amounts must be integers")
    return (number / _HUNDRED).quantize(MONEY_QUANTUM)


def _rows(payload: Any, *keys: str) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        raw = dict(detached(payload))
        if isinstance(raw.get("jsonl"), str):  # shopify.bulk_operation_result
            return [json.loads(line) for line in str(raw["jsonl"]).splitlines() if line.strip()]
        for key in keys:
            if isinstance(raw.get(key), list):
                return [dict(item) for item in raw[key]]
        _require(False, "PAYLOAD_SHAPE_UNKNOWN", f"the page carries none of {keys} (nor a bulk jsonl body)")
    rows_shaped = isinstance(payload, Sequence) and not isinstance(payload, str)
    _require(rows_shaped, "PAYLOAD_SHAPE_UNKNOWN", "the page arrives as a list or a mapping of rows")
    return [dict(detached(item)) for item in payload]  # type: ignore[union-attr]


_ORDER_ALIASES: dict[str, tuple[str, ...]] = {
    "id": ("id", "order_number", "name", "legacyResourceId"),
    "created_at": ("created_at", "createdAt", "processed_at", "processedAt"),
    "financial_status": ("financial_status", "displayFinancialStatus", "financialStatus", "status"),
    "currency": ("currency", "currency_code", "currencyCode", "presentment_currency"),
    "total_price": ("total_price", "totalPrice", "total_price_set", "totalPriceSet", "total"),
    "subtotal_price": ("subtotal_price", "subtotalPrice", "subtotal_price_set", "subtotalPriceSet", "subtotal"),
    "total_discounts": ("total_discounts", "totalDiscounts", "total_discounts_set", "totalDiscountsSet"),
    "total_shipping": ("total_shipping", "total_shipping_price", "total_shipping_price_set", "totalShippingPriceSet"),
    "total_tax": ("total_tax", "totalTax", "total_tax_set", "totalTaxSet"),
}


_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")


def _safe_ref(value: Any) -> str | None:
    """A provider label is not a ref: real SKUs and source names carry spaces, so fold whitespace and drop what is still not opaque rather than crashing the receipt."""

    text = "-".join(str(value).split())[:200]
    return text if _SAFE_REF.match(text) else None


def _order_field(item: Mapping[str, Any], key: str) -> Any:
    for alias in _ORDER_ALIASES[key]:
        value = item.get(alias)
        if isinstance(value, Mapping):  # a Shopify money set
            money = value.get("shop_money") or value.get("shopMoney") or value
            if isinstance(money, Mapping) and money.get("amount") is not None:
                return money["amount"]
            continue
        if value not in (None, ""):
            return value
    return None


def orders_receipt(provenance: ObservationProvenance, payload: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, window_start: str, window_end: str, siblings: Sequence[Any] = ()) -> dict[str, Any]:
    """The opening receipt from an order page: paid orders inside the window, their totals, their SKU units, and the sibling windows this batch may not intersect."""

    provenance = ObservationProvenance.model_validate(detached(provenance))
    _expect_tool(provenance, *ORDER_TOOLS)
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    window_ordered = parsed(end) > parsed(start)
    _require(window_ordered, "WINDOW_REQUIRED", "the batch window ends after it starts")
    # The window keys the replay fence, so it is the read's window, never a number the caller chose.
    window_observed = provenance.window_start is not None and provenance.window_end is not None and parsed(provenance.window_start) <= parsed(start) and parsed(end) <= parsed(provenance.window_end)
    _require(window_observed, "WINDOW_NOT_OBSERVED", f"the batch window {start}/{end} is not covered by the read's own window {provenance.window_start}/{provenance.window_end}; a batch may only claim the orders the read looked at")
    page = _sealed_page(provenance, payload)
    rows = _rows(page, "orders", "data", "items")
    page_has_rows = len(rows) > 0
    _require(page_has_rows, "ORDER_PAGE_EMPTY", "the order page carries no orders")
    currency, unpaid, counted = None, 0, 0
    gross = discounts = shipping = tax = Decimal("0")
    units: dict[str, list[Any]] = {}
    attribution: list[str] = []
    order_refs: list[str] = []
    for row in rows:
        item = dict(row)
        order_ref = _safe_ref(_order_field(item, "id"))
        _require(order_ref is not None, "ORDER_FIELD_MISSING", "each order has an identifier")
        _require(order_ref not in order_refs, "ORDER_ALREADY_CAPTURED", "an order contributes once to the page")
        order_refs.append(order_ref)
        created = _stamp(_order_field(item, "created_at"), field_name="created_at")
        inside_window = parsed(start) <= parsed(created) < parsed(end)
        _require(inside_window, "ORDER_OUTSIDE_WINDOW", f"order {_order_field(item, 'id')} was created {created}, outside {start}/{end}")
        if str(_order_field(item, "financial_status") or "").lower() not in PAID_ORDER_STATUSES:
            unpaid += 1
            continue
        code = str(_order_field(item, "currency") or "")
        currency_stated = code != ""
        _require(currency_stated, "ORDER_FIELD_MISSING", f"order {_order_field(item, 'id')} carries no currency")
        currency_matches = currency is None or code.upper() == currency
        _require(currency_matches, "ORDER_CURRENCY_MISMATCH", f"order {_order_field(item, 'id')} is in {code}; the page opened in {currency}")
        currency = code.upper()
        total = _order_field(item, "total_price")
        _require(total is not None, "ORDER_FIELD_MISSING", f"order {_order_field(item, 'id')} carries no total_price")
        gross += decimal_value(total, field_name="total_price")
        discounts += decimal_value(_order_field(item, "total_discounts") or "0", field_name="total_discounts")
        shipping += decimal_value(_order_field(item, "total_shipping") or "0", field_name="total_shipping")
        tax += decimal_value(_order_field(item, "total_tax") or "0", field_name="total_tax")
        counted += 1
        for raw_ref in (item.get("campaign_ref"), item.get("offer_ref"), item.get("source_name"), item.get("referring_site_ref")):
            ref = _safe_ref(raw_ref) if raw_ref else None
            if ref and ref not in attribution and len(attribution) < 50:
                attribution.append(ref)
        for line in item.get("line_items") or item.get("lineItems") or ():
            entry = dict(detached(line))
            sku = _safe_ref(entry.get("sku") or entry.get("variant_ref") or entry.get("product_ref") or "")
            if not sku:
                continue
            quantity = int(entry.get("quantity") or 0)
            net = (decimal_value(entry.get("price") or "0", field_name="price") * quantity - decimal_value(entry.get("total_discount") or "0", field_name="total_discount")).quantize(MONEY_QUANTUM)
            bucket = units.setdefault(sku, [0, Decimal("0")])
            bucket[0] += quantity
            bucket[1] += net
    skus_bounded = len(units) <= 200
    _require(skus_bounded, "SKU_LINES_TOO_MANY", f"{len(units)} SKUs in one batch exceeds the retained bound of 200")
    history = batch_history(siblings)
    return {
        "source_observation": {"provenance": provenance.to_dict(), "payload": page},
        "sibling_sources": _sibling_sources(siblings),
        "currency": currency or "XXX",
        "window_start": start,
        "window_end": end,
        "order_count": counted,
        "order_refs": order_refs,
        "unpaid_count": unpaid,
        "gross_sales": str(gross.quantize(MONEY_QUANTUM)),
        "discounts": str(discounts.quantize(MONEY_QUANTUM)),
        "shipping_collected": str(shipping.quantize(MONEY_QUANTUM)),
        "tax_collected": str(tax.quantize(MONEY_QUANTUM)),
        "orders_digest": provenance.provenance_digest,
        "orders_source_tool": provenance.source_tool,
        "sku_lines": [{"sku_ref": sku, "units": int(bucket[0]), "net_sales": str(Decimal(bucket[1]).quantize(MONEY_QUANTUM))} for sku, bucket in sorted(units.items())],
        "attribution_refs": attribution,
        "sibling_windows": history["sibling_windows"],
        "evidence_refs": [f"orders:{provenance.observation_ref}", f"window:{start}/{end}"],
    }


def refunds_receipt(provenance: ObservationProvenance, payload: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, siblings: Sequence[Any] = ()) -> dict[str, Any]:
    """The ``record_refunds`` receipt from a refund page, correlated so one refund is netted in exactly one batch."""

    provenance = ObservationProvenance.model_validate(detached(provenance))
    _expect_tool(provenance, *REFUND_TOOLS)
    minor = provenance.source_tool.startswith("square.")
    rows = _rows(_sealed_page(provenance, payload), "refunds", "data", "items")
    page_has_rows = len(rows) > 0
    _require(page_has_rows, "REFUND_PAGE_EMPTY", "the refund page carries no refunds")
    total, refs, currency = Decimal("0"), [], None
    for row in rows:
        item = dict(row)
        ref = str(item.get("id") or "")
        ref_stated = ref != ""
        _require(ref_stated, "REFUND_FIELD_MISSING", "every refund names its id")
        if minor:
            money = dict(item.get("amount_money") or {})
            amount = _minor(money.get("amount"), field_name="amount_money.amount")
            code = str(money.get("currency") or "").upper()
            _require(bool(code) and currency in (None, code), "REFUND_CURRENCY_MISMATCH", "all refund rows must have one currency")
            currency = code
            _require(str(item.get("status", "")).lower() in {"completed", "paid", "success"}, "REFUND_NOT_COMPLETED", "only completed refunds reduce settled sales")
        else:
            transactions = item.get("transactions") or item.get("refund_line_items") or ()
            transactions_stated = len(transactions) > 0
            _require(transactions_stated, "REFUND_FIELD_MISSING", f"refund {ref} carries no transactions to net")
            amount = Decimal("0")
            for transaction in transactions:
                entry = dict(detached(transaction))
                _require(entry.get("amount") is not None or entry.get("subtotal") is not None, "AMOUNT_MISSING", "refund transactions state their amount")
                amount += decimal_value(entry.get("amount", entry.get("subtotal")), field_name="amount")
                code = str(entry.get("currency") or "").upper()
                _require(bool(code) and currency in (None, code), "REFUND_CURRENCY_MISMATCH", "all refund rows must have one currency")
                currency = code
                _require(str(entry.get("status", "")).lower() in {"completed", "paid", "success"}, "REFUND_NOT_COMPLETED", "only completed refund transactions reduce sales")
        total += amount
        refs.append(f"refund:{ref}")
    unique(refs, label="refund refs on the page")
    history = batch_history(siblings)
    return {"source_observation": {"provenance": provenance.to_dict(), "payload": detached(payload)}, "sibling_sources": _sibling_sources(siblings), "currency": currency, "refunds": str(total.quantize(MONEY_QUANTUM)), "refund_count": len(refs), "refund_refs": refs, "refunds_digest": provenance.provenance_digest, "sibling_refund_refs": history["sibling_refund_refs"], "evidence_refs": [f"refunds:{provenance.observation_ref}"]}


_FEE_TYPES: dict[str, str] = {"charge": "charge", "payment": "charge", "refund": "refund", "payment_refund": "refund", "adjustment": "chargeback", "chargeback": "chargeback", "dispute": "chargeback", "stripe_fee": "fee", "application_fee": "fee", "reserve_transaction": "reserve", "reserve_hold": "reserve", "reserve_release": "reserve", "payout": "payout"}


def fee_receipt(provenance: ObservationProvenance, payload: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, currency: str) -> dict[str, Any]:
    """The ``settle_payout`` receipt from the governed ``stripe.list_balance_transactions`` read, split by transaction type."""

    provenance = ObservationProvenance.model_validate(detached(provenance))
    _expect_tool(provenance, FEE_TOOL)
    rows = _rows(_sealed_page(provenance, payload), "data", "items", "transactions")
    page_has_rows = len(rows) > 0
    _require(page_has_rows, "FEE_PAGE_EMPTY", "the balance transaction page carries no rows")
    fees = chargebacks = held = released = refunds = gross = payout = Decimal("0")
    refs: set[str] = set()
    for row in rows:
        item = dict(row)
        ref = str(item.get("id") or "")
        _require(bool(ref) and ref not in refs, "TRANSACTION_ALREADY_RECORDED", "each balance transaction has a distinct identifier")
        refs.add(ref)
        code = str(item.get("currency") or "").upper()
        currency_matches = code == currency.upper()
        _require(currency_matches, "FEE_CURRENCY_MISMATCH", f"a balance transaction is in {code}; the batch settles in {currency.upper()}")
        kind = _FEE_TYPES.get(str(item.get("type") or ""))
        _require(kind is not None, "FEE_TYPE_UNKNOWN", f"balance transaction type {item.get('type')!r} is not one this adapter nets; classify it before settling")
        amount = _minor(item.get("amount"), field_name="amount")
        fee = _minor(item.get("fee"), field_name="fee")
        if item.get("net") is not None:
            _require(_minor(item["net"], field_name="net") == amount - fee, "TRANSACTION_UNBALANCED", "each processor row must satisfy amount minus fee equals net")
        fees += fee
        if kind == "charge":
            gross += amount
        elif kind == "refund":
            refunds += amount.copy_abs()
        elif kind == "chargeback" and amount < 0:
            chargebacks += amount.copy_abs()
        elif kind == "fee" and amount < 0:
            fees += amount.copy_abs()
        elif kind == "reserve":
            held += amount.copy_abs() if amount < 0 else Decimal("0")
            released += amount if amount > 0 else Decimal("0")
        elif kind == "payout":
            payout += amount.copy_abs()
    return {"source_observation": {"provenance": provenance.to_dict(), "payload": detached(payload)}, "currency": currency.upper(), "fees": str(fees.quantize(MONEY_QUANTUM)), "chargebacks": str(chargebacks.quantize(MONEY_QUANTUM)), "reserve_held": str(held.quantize(MONEY_QUANTUM)), "reserve_released": str(released.quantize(MONEY_QUANTUM)), "refunds_observed": str(refunds.quantize(MONEY_QUANTUM)), "gross_observed": str(gross.quantize(MONEY_QUANTUM)), "payout_observed": str(payout.quantize(MONEY_QUANTUM)), "fee_digest": provenance.provenance_digest, "evidence_refs": [f"fees:{provenance.observation_ref}", f"payout_observed:{payout.quantize(MONEY_QUANTUM)}"]}


def payout_receipt(provenance: ObservationProvenance, payload: Mapping[str, Any] | Sequence[Mapping[str, Any]], *, currency: str, payout_ref: str | None = None) -> dict[str, Any]:
    """The ``announce_payout`` receipt from a payout page; only a single paid payout in the batch's currency announces."""

    provenance = ObservationProvenance.model_validate(detached(provenance))
    _expect_tool(provenance, *PAYOUT_TOOLS)
    minor = not provenance.source_tool.startswith("shopify.")
    rows = _rows(_sealed_page(provenance, payload), "data", "payouts", "transactions", "items")
    candidates = []
    for row in rows:
        item = dict(row)
        ref = str(item.get("id") or item.get("payout_ref") or "")
        _require(bool(ref), "PAYOUT_REF_MISSING", "a payout must have an identifier")
        if payout_ref is not None and ref != payout_ref:
            continue
        money = dict(item.get("amount_money") or {}) if item.get("amount_money") is not None else {}
        code = str(money.get("currency") or item.get("currency") or "").upper()
        currency_matches = code == currency.upper()
        _require(currency_matches, "PAYOUT_CURRENCY_MISMATCH", f"payout {ref} is in {code}; the batch settles in {currency.upper()}")
        status = str(item.get("status") or "").lower()
        paid = status in ("paid", "sent", "success", "completed")
        _require(paid, "PAYOUT_NOT_PAID", f"payout {ref} is {status or 'missing a status'}; only a paid payout settles a batch")
        amount = _minor(money.get("amount", item.get("amount")), field_name="amount") if minor else decimal_value(item.get("amount") or "0", field_name="amount")
        # Never the creation time: a payout is created before it arrives, and PAYOUT_IN_FUTURE fences on arrival.
        arrival = _stamp(item.get("arrival_date") or item.get("payout_date") or item.get("processed_at"), field_name="arrival_date")
        candidates.append({"payout_ref": ref, "payout_amount": str(amount), "payout_arrival_at": arrival})
    exactly_one = len(candidates) == 1
    _require(exactly_one, "PAYOUT_NOT_UNIQUE", f"{len(candidates)} payouts match; name the payout_ref the batch settles to")
    return {**candidates[0], "source_observation": {"provenance": provenance.to_dict(), "payload": detached(payload), "payout_ref": payout_ref}, "currency": currency.upper(), "payout_digest": provenance.provenance_digest, "payout_source_tool": provenance.source_tool, "evidence_refs": [f"payout:{candidates[0]['payout_ref']}", f"read:{provenance.observation_ref}"]}


def net_revenue_receipt(state: Any, *, source_plan: Any, reserve_recognised: Any | None = None) -> dict[str, Any]:
    """The ``record_net_revenue`` receipt, derived from the batch's own settled payout; nothing here is typed by a caller."""

    state = verify_settlement_batch(state, source_plan=source_plan)
    _require(state.status == "payout_settled", "BATCH_NOT_SETTLED", f"the batch is {state.status}; revenue is recognised once the payout settled")
    ledger = state.ledger
    recognised = ledger.reserve_released if reserve_recognised is None else decimal_value(reserve_recognised, field_name="reserve_recognised")
    return {"source_state": state.to_dict(), "source_plan": detached(source_plan), "recognised_revenue": str(ledger.net_settled), "reserve_recognised": str(recognised), "evidence_refs": [f"payout:{ledger.payout_ref}", f"fees:{str(ledger.fee_digest)[:24]}"]}


def clearance_receipt(close_state: Any, *, source_plan: Any, reconciliation_ref: str | None = None) -> dict[str, Any]:
    """From a closed finance period that reconciled both the revenue subledger and cash (copied from ``revenue_chain.clearance_receipt``, which fences receivables)."""

    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, verify_books
    close_plan, close_state = CLOSE_LIFECYCLE.bind(source_plan, close_state)
    _require(close_state.status == "closed", "CLOSE_NOT_CLOSED", f"the close is {close_state.status}")
    _require(verify_books(close_plan, close_state).verified, "BOOKS_NOT_VERIFIED", "clearance requires the replayed close's verified books")
    ledger = close_state.ledger
    reconciled = list(getattr(ledger, "reconciled_accounts", ()) or ())
    missing = [kind for kind in ("revenue_subledger", "cash") if kind not in reconciled]
    _require(not missing, "SETTLEMENT_NOT_RECONCILED_IN_CLOSE", f"the close did not reconcile {missing}; a storefront batch clears against both revenue and cash")
    rows = [item.command.receipt for item in close_state.transition_history if item.command.event == "reconcile_account" and item.command.receipt.account_kind == "revenue_subledger"]
    ref = reconciliation_ref or rows[-1].reconciliation_ref
    _require(any(item.reconciliation_ref == ref for item in rows), "SETTLEMENT_NOT_RECONCILED_IN_CLOSE", "the clearance names a retained revenue-subledger reconciliation")
    return {"close_source": {"state": close_state.to_dict(), "source_plan": close_plan.to_dict()}, "close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "reconciliation_ref": ref, "period_end": str(ledger.period_end), "evidence_refs": [f"close:{close_state.scope.entity_ref}", f"state:{close_state.state_digest[:24]}"]}


# --------------------------------------------------------------------------- #
# What the batch hands to the other engines
# --------------------------------------------------------------------------- #


def verify_settlement_batch(state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(source_plan, state)
    _require(company_ref is None or plan.company_ref == company_ref, "SCOPE_MISMATCH", "settlement belongs to the selected logical company")
    _require(currency is None or plan.currency == currency, "BATCH_CURRENCY_MISMATCH", "settlement currency must match")
    if expected_scope is not None:
        scope = dict(detached(expected_scope))
        _require(all(getattr(state.scope, key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "settlement belongs to the authenticated company execution scope")
    _require(at is None or parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "settlement must exist before it is consumed")
    return state


def _settled(state: Any, *, source_plan: Any) -> Any:
    state = verify_settlement_batch(state, source_plan=source_plan)
    settled = state.status in ("payout_settled", "net_revenue_recorded", "reconciled")
    _require(settled, "BATCH_NOT_SETTLED", f"the batch is {state.status}; only a settled payout is cash")
    return state.ledger


def _sibling_sources(siblings: Sequence[Any]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for source in siblings:
        raw = dict(detached(source))
        _require("state" in raw and "source_plan" in raw, "SOURCE_PLAN_MISSING", "each sibling retains its actual state and source_plan")
        _require(raw["state"].get("schema") == BATCH_STATE_SCHEMA, "SIBLING_SCHEMA_MISMATCH", "siblings are storefront settlement states")
        plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(raw["source_plan"], raw["state"])
        identity = tuple(getattr(state.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "entity_ref"))
        _require(identity not in seen, "SOURCE_ALREADY_RECORDED", "retain one current version per sibling")
        seen.add(identity)
        result.append({"state": state.to_dict(), "source_plan": plan.to_dict()})
    return result


def batch_history(siblings: Sequence[Any] = ()) -> dict[str, list[str]]:
    """The windows and refund correlations sibling batches already hold: the fence the period ledger lacks."""

    windows: list[str] = []
    refunds: list[str] = []
    for source in _sibling_sources(siblings):
        raw = source["state"]
        sibling_is_a_batch = raw.get("schema") == BATCH_STATE_SCHEMA
        _require(sibling_is_a_batch, "SIBLING_SCHEMA_MISMATCH", f"a sibling batch is a {raw.get('schema')}; expected {BATCH_STATE_SCHEMA}")
        ledger = dict(raw.get("ledger") or {})
        if ledger.get("outcome") == "cancelled":
            continue
        if ledger.get("window_start") and ledger.get("window_end"):
            windows.append(f"{ledger['window_start']}/{ledger['window_end']}")
        refunds.extend(str(ref) for ref in ledger.get("refund_refs") or ())
    return {"sibling_windows": windows, "sibling_refund_refs": refunds}


class MerchantSourceBalance(SourceBalance):
    source_state: dict[str, Any]
    source_plan: dict[str, Any]

    @model_validator(mode="after")
    def _source(self) -> MerchantSourceBalance:
        state = verify_settlement_batch(self.source_state, source_plan=self.source_plan)
        _settled(state, source_plan=self.source_plan)
        ledger = state.ledger
        expected = {"source_ref": f"storefront-{'cash' if self.kind == 'cash' else 'settled'}:{state.scope.entity_ref}", "source_tool": ledger.payout_source_tool, "provenance_digest": ledger.payout_digest, "balance": ledger.net_settled, "items": ledger.order_count, "window_end": ledger.window_end}
        _require(self.kind in {"cash", "revenue_subledger"} and all(getattr(self, key) == value for key, value in expected.items()), "SOURCE_NOT_DERIVED", "the source balance must reproduce its retained settled batch")
        return self


def merchant_settlement_source_balance(state: Any, *, source_plan: Any, kind: Literal["cash", "revenue_subledger"] = "cash") -> MerchantSourceBalance:
    """The close's independent source balance for the batch: the payout that hit the bank, and the same number as settled revenue."""

    state = verify_settlement_batch(state, source_plan=source_plan)
    ledger = _settled(state, source_plan=source_plan)
    return MerchantSourceBalance.model_validate({"source_state": state.to_dict(), "source_plan": detached(source_plan), "kind": kind, "source_ref": f"storefront-{'cash' if kind == 'cash' else 'settled'}:{state.scope.entity_ref}", "source_tool": str(ledger.payout_source_tool), "provenance_digest": str(ledger.payout_digest), "balance": str(ledger.net_settled), "items": int(ledger.order_count), "window_end": ledger.window_end})


def period_evidence_receipt(state: Any, *, source_plan: Any, engine: str = "growth_engine", evidence_ref: str | None = None, centre_ref: str | None = None) -> dict[str, Any]:
    """The operating period's ``record_evidence`` receipt: the settled payout as revenue, the processor's take plus refunds as spend, keyed by the batch digest so a cost register can fence the double count."""

    state = verify_settlement_batch(state, source_plan=source_plan)
    ledger = _settled(state, source_plan=source_plan)
    _require(engine == "growth_engine", "ENGINE_NOT_BOUND", "storefront cash belongs to its growth engine; use the cost register for the operating-period handoff")
    spend = (ledger.fees + ledger.refunds).quantize(MONEY_QUANTUM)
    centre = centre_ref or ""
    ref = evidence_ref or f"storefront_batch:{centre + ':' if centre else ''}{state.scope.entity_ref}:{state.state_digest[:16]}"
    # Preserve the readable artifact ref, but fence the economic payout itself
    # so a later status or batch alias cannot book the same cash a second time.
    fenced = state.state_digest[:16] in ref
    _require(fenced, "EVIDENCE_REF_UNFENCED", f"a period evidence ref must carry the batch state digest {state.state_digest[:16]}; without it the same batch books twice")
    plan = StorefrontSettlementPlan.model_validate(detached(source_plan))
    origin = stable_digest({"scope": {key: getattr(state.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")}, "company_ref": plan.company_ref, "store_ref": plan.store_ref, "payout_ref": ledger.payout_ref})
    return {"engine": engine, "evidence_ref": ref, "source_kind": "storefront_batch", "source_digest": origin, "source_digests": [origin], "spend": str(spend), "revenue": str(ledger.net_settled), "signals": []}


def merchant_payout_flows(plan: StorefrontSettlementPlan | Mapping[str, Any], state: Any) -> list[dict[str, Any]]:
    """Treasury flows the batch proves: the announced payout, and the reserve the processor still holds, due after the plan's release days."""

    parsed_plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(plan, state)
    ledger = state.ledger
    _require(state.status in {"payout_announced", "payout_settled", "net_revenue_recorded", "reconciled"} and ledger.payout_ref is not None and ledger.payout_arrival_at is not None, "PAYOUT_NOT_ANNOUNCED", f"the batch is {state.status}; no active payout has been announced")
    source = str(ledger.payout_source_tool or "host.merchant_payout")
    flows = [{"kind": "merchant_payout", "ref": f"merchant_payout:{ledger.payout_ref}", "due_at": str(ledger.payout_arrival_at), "amount": str(ledger.net_settled), "source": source}]
    outstanding = (ledger.reserve_held - ledger.reserve_released).quantize(MONEY_QUANTUM)
    if outstanding > 0 and ledger.window_end:
        due = add_days(str(ledger.window_end), parsed_plan.reserve_release_days)
        flows.append({"kind": "merchant_payout", "ref": f"reserve_release:{ledger.payout_ref}", "due_at": due, "amount": str(outstanding), "source": source})
    return flows


class StandardCost(StrictModel):
    sku_ref: OpaqueRef
    unit_cost: Decimal

    @field_validator("unit_cost", mode="before")
    @classmethod
    def _cost(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="unit_cost")


class StandardCostMap(StrictModel):
    """What a unit costs to make or buy: an explicit operator input that names itself, sealed, never inferred from a price."""

    schema_id: Literal["lightbulb.storefront_standard_cost_map.v1"] = Field(default=STANDARD_COST_MAP_SCHEMA, alias="schema")
    operator_supplied: Literal[True] = True
    currency: CurrencyCode
    costs: tuple[StandardCost, ...] = Field(min_length=1, max_length=500)
    map_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("costs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> StandardCostMap:
        unique([item.sku_ref for item in self.costs], label="standard cost SKUs")
        if not skip_digests(info) and self.map_digest != sealed_digest(StandardCostMap, self, "map_digest"):
            raise ValueError("map_digest must commit the exact cost map")
        return self

    def cost(self, sku_ref: str) -> Decimal | None:
        return next((item.unit_cost for item in self.costs if item.sku_ref == sku_ref), None)


def standard_cost_map(currency: str, costs: Mapping[str, Any]) -> StandardCostMap:
    return seal(StandardCostMap, {"currency": currency.upper(), "costs": [{"sku_ref": sku, "unit_cost": cost} for sku, cost in costs.items()]}, "map_digest")


def sku_margin_rows(state: Any, standard_costs: StandardCostMap | Mapping[str, Any], *, source_plan: Any) -> list[dict[str, Any]]:
    """Contribution per SKU for unit economics: net sales less standard cost, with fees, refunds and chargebacks allocated pro rata across the SKU base.

    The base is the SKU net sales the page actually carries, not gross (which
    includes tax and shipping): allocating over gross would leave the tax and
    shipping share of the processor's take unallocated and overstate every
    contribution.  The last row takes the rounding remainder so the pool is
    always exhausted exactly.
    """

    state = verify_settlement_batch(state, source_plan=source_plan)
    ledger = _settled(state, source_plan=source_plan)
    costs = StandardCostMap.model_validate(detached(standard_costs))
    _require(costs.currency == state.scope.currency, "BATCH_CURRENCY_MISMATCH", "standard costs must use the settlement currency")
    lines = list(ledger.sku_lines)
    lines_present = len(lines) > 0
    _require(lines_present, "SKU_LINES_MISSING", "the order page carried no line items; a contribution row needs SKU units")
    deductions = (ledger.fees + ledger.refunds + ledger.chargebacks).quantize(MONEY_QUANTUM)
    base = sum((line.net_sales for line in lines), Decimal("0"))
    rows: list[dict[str, Any]] = []
    running = booked = Decimal("0")
    for index, line in enumerate(lines, start=1):
        unit_cost = costs.cost(line.sku_ref)
        _require(unit_cost is not None, "STANDARD_COST_MISSING", f"the cost map carries no standard cost for {line.sku_ref}")
        assert unit_cost is not None
        running += line.net_sales
        if base <= 0:
            allocated = Decimal("0")
        elif index == len(lines):
            allocated = deductions - booked
        else:
            allocated = (deductions * running / base).quantize(MONEY_QUANTUM) - booked
        booked += allocated
        cogs = (unit_cost * line.units).quantize(MONEY_QUANTUM)
        contribution = (line.net_sales - cogs - allocated).quantize(MONEY_QUANTUM)
        rows.append({"sku_ref": line.sku_ref, "units": line.units, "net_sales": str(line.net_sales), "standard_unit_cost": str(unit_cost), "cogs": str(cogs), "allocated_settlement_cost": str(allocated), "contribution": str(contribution), "contribution_margin_percent": str(ratio_percent(contribution, line.net_sales) or Decimal("0")), "cost_map_digest": costs.map_digest})
    return rows


def settlement_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    state = verify_settlement_batch(state, source_plan=source_plan)
    ledger = state.ledger
    return {"batch_ref": str(state.scope.entity_ref), "status": state.status, "window": f"{ledger.window_start}/{ledger.window_end}", "order_count": ledger.order_count, "gross_sales": str(ledger.gross_sales), "refunds": str(ledger.refunds), "fees": str(ledger.fees), "chargebacks": str(ledger.chargebacks), "reserve_outstanding": str((ledger.reserve_held - ledger.reserve_released).quantize(MONEY_QUANTUM)), "net_settled": str(ledger.net_settled), "effective_fee_percent": str(ledger.effective_fee_percent), "days_order_to_cash": ledger.days_order_to_cash, "outcome": ledger.outcome, "state_digest": state.state_digest}


def _verify_transition_sources(plan: StorefrontSettlementPlan, previous: dict[str, Any], data: dict[str, Any], command: Any) -> None:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "capture_orders":
        _require(r.entity_scope is not None, "SCOPE_MISSING", "the opening retains its authenticated execution scope")
        _require(command.expected_state_digest == STOREFRONT_SETTLEMENT_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the opening scope is bound to this batch")
        _require(parsed(r.window_end) <= parsed(at), "SOURCE_FROM_FUTURE", "capture the complete order window after it ends")
        data.update(entity_scope=r.entity_scope.to_dict(), store_ref=plan.store_ref, order_refs=list(r.order_refs))
    scope = data.get("entity_scope")
    _require(scope is not None, "SCOPE_MISSING", "the batch must retain its execution scope")

    if event in {"capture_orders", "record_refunds", "announce_payout", "settle_payout"}:
        _require(r.source_observation is not None, "SOURCE_NOT_PROVEN", "retain the actual provider page and observation provenance")
        observation = r.source_observation
        provenance = ObservationProvenance.model_validate(observation.get("provenance"))
        page = observation.get("payload")
        _require(provenance.lane == read_lane(provenance.source_tool), "OBSERVATION_LANE_MISMATCH", "the provider read must use its registered observation lane")
        _require(parsed(provenance.completed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "provider evidence must exist before it is recorded")
        if event == "capture_orders":
            expected = orders_receipt(provenance, page, window_start=r.window_start, window_end=r.window_end, siblings=r.sibling_sources)
            rows = _rows(page, "orders", "data", "items")
        elif event == "record_refunds":
            expected = refunds_receipt(provenance, page, siblings=r.sibling_sources)
            rows = _rows(page, "refunds", "data", "items")
            for row in rows:
                _require(_safe_ref(row.get("order_id")) in set(previous.get("order_refs", ())), "REFUND_ORDER_MISMATCH", "every refund belongs to an order captured in this batch")
        elif event == "announce_payout":
            expected = payout_receipt(provenance, page, currency=plan.currency, payout_ref=observation.get("payout_ref"))
            rows = _rows(page, "data", "payouts", "transactions", "items")
        else:
            expected = fee_receipt(provenance, page, currency=plan.currency)
            rows = _rows(page, "data", "items", "transactions")
            _require(r.gross_observed == _money(previous.get("gross_sales")) and r.refunds_observed == _money(previous.get("refunds")) and r.payout_observed == _money(previous.get("net_settled")), "SETTLEMENT_NOT_RECONCILED", "the processor's gross, refund, and payout rows must reproduce this batch's orders, refunds and announced payout")
            _require(provenance.window_start is not None and provenance.window_end is not None and parsed(provenance.window_start) <= parsed(str(previous["window_start"])) and parsed(provenance.window_end) >= parsed(str(previous["payout_arrival_at"])), "WINDOW_NOT_OBSERVED", "the processor read must cover the order window through payout arrival")
        parsed_expected = SettlementReceipt.model_validate(expected)
        for key in expected:
            _require(detached(getattr(r, key)) == detached(getattr(parsed_expected, key)), "SOURCE_NOT_DERIVED", f"{key} must be derived from the retained provider observation")
        for row in [page, *rows] if isinstance(page, Mapping) else rows:
            for key in ("company_ref",):
                _require(row.get(key) is None or str(row[key]) == plan.company_ref, "SCOPE_MISMATCH", "the observed company must match the selected logical company")
            for key in ("store_ref", "store_id"):
                _require(row.get(key) is None or str(row[key]) == plan.store_ref, "STORE_MISMATCH", "the observed store must match the bound plan")
            for key in ("created_at", "createdAt", "created", "available_on"):
                if row.get(key) is not None:
                    _require(parsed(_stamp(row[key], field_name=key)) <= parsed(provenance.completed_at), "SOURCE_FROM_FUTURE", "the read cannot prove provider facts from after its completion")
            if event == "settle_payout" and row.get("payout_ref") is not None:
                _require(str(row["payout_ref"]) == str(previous["payout_ref"]), "PAYOUT_CORRELATION_MISMATCH", "processor rows belong to the announced payout")
        for sibling_source in r.sibling_sources:
            sibling_plan = StorefrontSettlementPlan.model_validate(sibling_source["source_plan"])
            sibling = verify_settlement_batch(sibling_source["state"], source_plan=sibling_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
            _require(sibling_plan.store_ref == plan.store_ref, "STORE_MISMATCH", "a sibling belongs to this store")
            _require(sibling.scope.entity_ref != scope["entity_ref"], "SOURCE_ALREADY_RECORDED", "a batch cannot cite itself as a sibling")
    elif event == "record_net_revenue":
        _require(r.source_state is not None and r.source_plan is not None, "SOURCE_PLAN_MISSING", "revenue retains the settled batch and its source plan")
        source = verify_settlement_batch(r.source_state, source_plan=r.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
        _require(source.state_digest == command.expected_state_digest and source.plan_digest == plan.plan_digest, "SOURCE_NOT_DERIVED", "revenue must consume this exact settled batch version")
        expected = net_revenue_receipt(source, source_plan=r.source_plan, reserve_recognised=r.reserve_recognised)
        _require(r.recognised_revenue == Decimal(expected["recognised_revenue"]), "SOURCE_NOT_DERIVED", "revenue is the retained batch's actual payout")
    elif event == "reconcile_settlement" and plan.require_clearance:
        _require(r.close_source is not None, "CLEARANCE_MISSING", "clearance retains the closed finance state and its plan")
        expected = clearance_receipt(r.close_source["state"], source_plan=r.close_source["source_plan"], reconciliation_ref=r.reconciliation_ref)
        parsed_expected = SettlementReceipt.model_validate(expected)
        _require(all(getattr(r, key) == getattr(parsed_expected, key) for key in ("close_ref", "close_state_digest", "period_end")), "SOURCE_NOT_DERIVED", "clearance fields reproduce the retained close")
        from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
        _, close = CLOSE_LIFECYCLE.bind(r.close_source["source_plan"], r.close_source["state"])
        _require(all(getattr(close.scope, key) == scope[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "the close belongs to this company execution scope")
        _require(parsed(close.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the close must exist before clearance")
        _require(parsed(close.ledger.period_start) <= parsed(str(previous["payout_arrival_at"])) < parsed(close.ledger.period_end), "CLOSE_BEFORE_SETTLEMENT", "the close covers the provider's actual payout arrival")
        for kind, prefix in (("cash", "cash"), ("revenue_subledger", "settled")):
            ref = f"source:storefront-{prefix}:{scope['entity_ref']}"
            rows = [item.command.receipt for item in close.transition_history if item.command.event == "reconcile_account" and item.command.receipt.account_kind == kind]
            _require(any(ref in item.evidence_refs and item.source_balance == _money(previous["net_settled"]) for item in rows), "SETTLEMENT_NOT_RECONCILED_IN_CLOSE", "the close must reconcile this batch's exact cash and settled-revenue source balances")


STOREFRONT_SETTLEMENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": STOREFRONT_SETTLEMENT_KIND,
    "golden_loop": STOREFRONT_SETTLEMENT_GOLDEN_LOOP,
    "stages": ["capture_orders", "record_refunds", "announce_payout", "settle_payout", "record_net_revenue", "reconcile_settlement"],
    "statuses": list(BATCH_STATUSES),
    "events": list(BATCH_EVENTS),
    "hops": {
        "capture_orders": "ecommerce.search_orders (or shopify.bulk_operation_result JSONL) page of paid orders in the window",
        "record_refunds": "shopify.list_refunds or square.list_refunds page, correlated against sibling batches",
        "announce_payout": "stripe.list_payouts, square.list_payouts or shopify.list_transactions paid payout",
        "settle_payout": "the governed stripe.list_balance_transactions read split by type",
        "record_net_revenue": "the batch's own settled payout",
        "reconcile_settlement": "finance_close closed with cash and revenue_subledger reconciled",
    },
    "required_connectors": ["shopify", "stripe", "square", "xero", "lightbulb.sdk_engine_state"],
    "lanes": {tool: read_lane(tool) for tool in (*ORDER_TOOLS, *REFUND_TOOLS, FEE_TOOL, *PAYOUT_TOOLS)},
    "proposed_governed_reads": [dict(item) for item in PROPOSED_GOVERNED_READS],
    "hard_rules": [
        "period revenue is net settled cash, never gross orders",
        "a settlement that does not reconcile opens an exception; it is never estimated",
        "one refund is netted once, in one batch",
        "batch windows never overlap for one store",
    ],
}

__all__ = [
    "BATCH_EVENTS",
    "BATCH_STATE_SCHEMA",
    "BATCH_STATUSES",
    "DTC_WEEKLY_CLOSE_PROFILE",
    "DTC_WEEKLY_CLOSE_PROFILE_KEY",
    "FEE_TOOL",
    "ORDER_TOOLS",
    "PAYOUT_TOOLS",
    "PROPOSED_GOVERNED_READS",
    "REFUND_TOOLS",
    "STOREFRONT_SETTLEMENT_GOLDEN_LOOP",
    "STOREFRONT_SETTLEMENT_KIND",
    "STOREFRONT_SETTLEMENT_LIFECYCLE",
    "STOREFRONT_SETTLEMENT_MANIFEST",
    "SettlementBatchState",
    "MerchantSourceBalance",
    "StandardCost",
    "StandardCostMap",
    "StorefrontSettlementError",
    "StorefrontSettlementPlan",
    "advance_settlement_batch",
    "batch_history",
    "clearance_receipt",
    "compile_storefront_settlement",
    "fee_receipt",
    "merchant_payout_flows",
    "merchant_settlement_source_balance",
    "net_revenue_receipt",
    "open_settlement_batch",
    "orders_receipt",
    "payout_receipt",
    "period_evidence_receipt",
    "read_lane",
    "refunds_receipt",
    "settlement_summary",
    "sku_margin_rows",
    "standard_cost_map",
    "verify_settlement_batch",
]
