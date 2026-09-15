"""Product margin: what each SKU actually earned after discounts, returns, landed cost, fees, and fulfilment, and why revenue moved between two windows.

The storefront batch knows fees and refunds by batch, the fulfilment
chain knows which SKUs shipped and came back, the inventory chain knows
what each unit cost landed, and the price catalog knows what each SKU
lists for.  Nothing put them on one line per SKU.  ``build_product_margin``
does, from replayed states and the sealed plan only:

* revenue per SKU is units shipped at the published catalog price, the
  order's discount (list value less the order total) shared across its
  lines by list value; an order with an unpriced SKU keeps its total in an
  unallocated bucket rather than being guessed;
* returns are the returned units at list price plus the plan's handling
  cost; cost of goods is units at the stock position's average landed unit
  cost; fees are the settlement batches' observed fee rate over the window
  applied to net revenue (else the plan's rate, and the report says which);
  fulfilment is the plan's per-order and per-unit cost;
* contribution, contribution margin, contribution per unit, revenue share,
  break-even units against the plan's fixed cost pool, and a waterfall from
  gross revenue to contribution are sealed with every digest read.

``price_volume_mix`` decomposes the revenue change between two sealed
reports into price, volume, and mix effects per SKU (the three sum exactly
to the change), the management-accounting form that says whether growth
came from charging more, selling more, or selling a richer mix.  Nothing
here reads a provider, persists anything, or estimates elasticity.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    CurrencyCode,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

PRODUCT_MARGIN_PLAN_SCHEMA = "lightbulb.product_margin_plan.v1"
PRODUCT_MARGIN_SCHEMA = "lightbulb.product_margin.v1"
PRICE_VOLUME_MIX_SCHEMA = "lightbulb.price_volume_mix.v1"
WATERFALL_STEPS: tuple[str, ...] = ("gross_revenue", "discounts", "returns", "net_revenue", "cost_of_goods", "gross_profit", "fees", "fulfilment", "return_handling", "contribution")
SETTLED_ORDER_STATUSES: frozenset[str] = frozenset({"fulfilled", "shipped", "delivered", "returned", "closed", "exception"})
_HUNDRED = Decimal("100")
_QTY = Decimal("0.001")
_RATE = Decimal("0.01")


class ProductMarginError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ProductMarginError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE, rounding=ROUND_HALF_UP)


def _qty(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_QTY, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ProductMarginPlan(StrictModel):
    """The costs no chain observes and the fee fallback, sealed so every reader computes the same margin."""

    schema_id: str = Field(default=PRODUCT_MARGIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    fulfilment_cost_per_order: Decimal = Field(default=Decimal("0"), validate_default=True)
    fulfilment_cost_per_unit: Decimal = Field(default=Decimal("0"), validate_default=True)
    return_handling_cost_per_unit: Decimal = Field(default=Decimal("0"), validate_default=True)
    payment_fee_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    fixed_cost_pool: Decimal = Field(default=Decimal("0"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("fulfilment_cost_per_order", "fulfilment_cost_per_unit", "return_handling_cost_per_unit", "payment_fee_percent", "fixed_cost_pool", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if info.field_name == "payment_fee_percent" and result >= _HUNDRED:
            raise ValueError("the payment fee is a percentage below 100")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProductMarginPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ProductMarginPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_product_margin_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ProductMarginPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(ProductMarginPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #


class ProductMarginRow(StrictModel):
    sku_ref: OpaqueRef
    orders: int = Field(ge=0)
    units_sold: Decimal
    units_returned: Decimal
    list_price: Decimal | None = None
    unit_cost: Decimal | None = None
    gross_revenue: Decimal
    discounts: Decimal
    returns_value: Decimal
    net_revenue: Decimal
    cost_of_goods: Decimal
    fees: Decimal
    fulfilment_cost: Decimal
    return_handling: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    contribution_per_unit: Decimal | None = None
    revenue_share_percent: Decimal
    return_rate_percent: Decimal | None = None
    break_even_units: int | None = None
    rank: int = Field(ge=1)
    priced: bool
    costed: bool

    @field_validator("units_sold", "units_returned", "list_price", "unit_cost", "gross_revenue", "discounts", "returns_value", "net_revenue", "cost_of_goods", "fees", "fulfilment_cost", "return_handling", "contribution", "contribution_margin_percent", "contribution_per_unit", "revenue_share_percent", "return_rate_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class WaterfallStep(StrictModel):
    step: Literal["gross_revenue", "discounts", "returns", "net_revenue", "cost_of_goods", "gross_profit", "fees", "fulfilment", "return_handling", "contribution"]
    amount: Decimal

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount", allow_negative=True)


class ProductMarginReport(StrictModel):
    schema_id: str = Field(default=PRODUCT_MARGIN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    window_start: str
    window_end: str
    plan_digest: Sha256Digest
    price_source: Literal["catalog", "none"]
    catalog_digest: Sha256Digest | None = None
    fee_basis: Literal["settlement_batches", "plan_rate"]
    fee_rate_percent: Decimal
    orders: int = Field(ge=0)
    orders_unallocated: int = Field(ge=0)
    unallocated_revenue: Decimal
    gross_revenue: Decimal
    discounts: Decimal
    returns_value: Decimal
    net_revenue: Decimal
    cost_of_goods: Decimal
    fees: Decimal
    fulfilment_cost: Decimal
    return_handling: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    rows: tuple[ProductMarginRow, ...] = Field(default_factory=tuple, max_length=5000)
    unpriced_skus: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=500)
    uncosted_skus: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=500)
    waterfall: tuple[WaterfallStep, ...] = Field(default_factory=tuple, max_length=10)
    assumptions: dict[str, str] = Field(default_factory=dict)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=12000)
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "unpriced_skus", "uncosted_skus", "waterfall", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("fee_rate_percent", "unallocated_revenue", "gross_revenue", "discounts", "returns_value", "net_revenue", "cost_of_goods", "fees", "fulfilment_cost", "return_handling", "contribution", "contribution_margin_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProductMarginReport":
        if sum((row.contribution for row in self.rows), Decimal("0")).quantize(MONEY_QUANTUM) != self.contribution:
            raise ValueError("contribution must equal the rows")
        if not skip_digests(info) and self.report_digest != sealed_digest(ProductMarginReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def row(self, sku_ref: str) -> ProductMarginRow | None:
        return next((row for row in self.rows if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        margin = "n/a" if self.contribution_margin_percent is None else f"{self.contribution_margin_percent}%"
        lines = [f"**Product margin {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.orders} order(s), net revenue {self.net_revenue} {self.currency}, contribution {self.contribution} ({margin}); fees at {self.fee_rate_percent}% ({self.fee_basis})."]
        for row in self.rows:
            cm = "n/a" if row.contribution_margin_percent is None else f"{row.contribution_margin_percent}%"
            lines.append(f"{row.rank}. {row.sku_ref}: {row.units_sold} unit(s), net {row.net_revenue}, COGS {row.cost_of_goods}, contribution {row.contribution} ({cm})" + ("" if row.priced else "; unpriced") + ("" if row.costed else "; uncosted"))
        if self.unallocated_revenue > 0:
            lines.append(f"- {self.orders_unallocated} order(s) worth {self.unallocated_revenue} carry an unpriced SKU and are not allocated")
        return "\n".join(lines)


def _catalog_prices(catalog_states: Sequence[tuple[Any, Any]], *, currency: str, company_ref: str) -> tuple[dict[str, Decimal], str | None]:
    """List prices per SKU from the latest published (or superseded) catalog version; the newest effective date wins."""

    from lightbulb.price_catalog import PRICE_CATALOG_LIFECYCLE

    best: tuple[str, Any] | None = None
    for plan_doc, state_doc in catalog_states:
        plan, state = PRICE_CATALOG_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == company_ref and plan.currency == currency, "SOURCE_SCOPE_MISMATCH", f"catalog {state.scope.entity_ref} belongs to another company or currency")
        if state.status not in ("published", "superseded"):
            continue
        effective = str(state.ledger.effective_from or "")
        if best is None or effective > best[0]:
            best = (effective, state)
    if best is None:
        return {}, None
    state = best[1]
    return {item.item_ref: Decimal(str(item.list_price)) for item in state.ledger.items if item.kind == "sku"}, state.state_digest


def _unit_costs(inventory_states: Sequence[tuple[Any, Any]], *, currency: str, company_ref: str) -> tuple[dict[str, Decimal], list[str]]:
    """Average landed unit cost per SKU across its stock positions, weighted by units on hand (unweighted when nothing is on hand)."""

    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    weights: dict[str, list[tuple[Decimal, Decimal]]] = {}
    digests: list[str] = []
    for plan_doc, state_doc in inventory_states:
        plan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == company_ref and plan.currency == currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        cost = Decimal(str(ledger.avg_unit_cost))
        if ledger.sku_ref and cost > 0:
            weights.setdefault(str(ledger.sku_ref), []).append((cost, Decimal(str(ledger.on_hand))))
    costs: dict[str, Decimal] = {}
    for sku, rows in weights.items():
        total = sum((weight for _cost, weight in rows), Decimal("0"))
        costs[sku] = (sum((cost * weight for cost, weight in rows), Decimal("0")) / total) if total > 0 else (sum((cost for cost, _weight in rows), Decimal("0")) / len(rows))
    return costs, digests


def _fee_rate(settlement_states: Sequence[tuple[Any, Any]], *, currency: str, company_ref: str, window_start: str, window_end: str) -> tuple[Decimal | None, list[str]]:
    """Fees over gross sales across the settled batches whose window overlaps the report window."""

    from lightbulb.storefront_settlement_chain import STOREFRONT_SETTLEMENT_LIFECYCLE

    fees = gross = Decimal("0")
    digests: list[str] = []
    for plan_doc, state_doc in settlement_states:
        plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == company_ref and plan.currency == currency, "SOURCE_SCOPE_MISMATCH", f"batch {state.scope.entity_ref} belongs to another company or currency")
        ledger = state.ledger
        if ledger.window_start is None or ledger.window_end is None or parsed(str(ledger.window_end)) < parsed(window_start) or parsed(str(ledger.window_start)) > parsed(window_end):
            continue
        digests.append(state.state_digest)
        fees += Decimal(str(ledger.fees))
        gross += Decimal(str(ledger.gross_sales))
    return (None if gross <= 0 else fees / gross * _HUNDRED), digests


def build_product_margin(plan: ProductMarginPlan | Mapping[str, Any], *, fulfilment_states: Sequence[tuple[Any, Any]], inventory_states: Sequence[tuple[Any, Any]] = (), settlement_states: Sequence[tuple[Any, Any]] = (), catalog_states: Sequence[tuple[Any, Any]] = (), window_start: str, window_end: str, as_of: str) -> ProductMarginReport:
    """The sealed per-SKU contribution over a window from replayed orders, stock positions, settlement batches, and the published catalog."""

    from lightbulb.fulfilment_chain import FULFILMENT_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ProductMarginPlan) else ProductMarginPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(start) < parsed(end), "WINDOW_EMPTY", "the window starts before it ends")
    prices, catalog_digest = _catalog_prices(catalog_states, currency=parsed_plan.currency, company_ref=parsed_plan.company_ref)
    costs, cost_digests = _unit_costs(inventory_states, currency=parsed_plan.currency, company_ref=parsed_plan.company_ref)
    observed_fee_rate, fee_digests = _fee_rate(settlement_states, currency=parsed_plan.currency, company_ref=parsed_plan.company_ref, window_start=start, window_end=end)
    fee_basis = "settlement_batches" if observed_fee_rate is not None else "plan_rate"
    fee_rate = _rate(observed_fee_rate if observed_fee_rate is not None else parsed_plan.payment_fee_percent)
    digests: list[str] = [*cost_digests, *fee_digests]
    per_sku: dict[str, dict[str, Any]] = {}
    orders = 0
    orders_unallocated = 0
    unallocated = Decimal("0")

    def bucket(sku: str) -> dict[str, Any]:
        return per_sku.setdefault(sku, {"orders": 0, "units": Decimal("0"), "returned": Decimal("0"), "gross": Decimal("0"), "discounts": Decimal("0"), "fulfilment": Decimal("0")})

    for plan_doc, state_doc in fulfilment_states:
        source_plan, state = FULFILMENT_LIFECYCLE.bind(plan_doc, state_doc)
        _require(source_plan.company_ref == parsed_plan.company_ref and state.scope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"order {state.scope.entity_ref} belongs to another company or currency")
        ledger = state.ledger
        created = ledger.order_created_at
        if created is None or parsed(created) < parsed(start) or parsed(created) >= parsed(end) or state.status == "cancelled":
            continue
        digests.append(state.state_digest)
        orders += 1
        units = {str(sku): Decimal(str(quantity)) for sku, quantity in dict(ledger.units).items()}
        returned = {str(sku): Decimal(str(quantity)) for sku, quantity in dict(ledger.returned_units).items()}
        total_units = sum(units.values(), Decimal("0"))
        for sku, quantity in units.items():
            row = bucket(sku)
            row["orders"] += 1
            row["units"] += quantity
            row["returned"] += returned.get(sku, Decimal("0"))
            if total_units > 0:
                row["fulfilment"] += parsed_plan.fulfilment_cost_per_order * quantity / total_units + parsed_plan.fulfilment_cost_per_unit * quantity
        if any(sku not in prices for sku in units):
            orders_unallocated += 1
            unallocated += Decimal(str(ledger.order_total))
            continue
        list_value = sum((units[sku] * prices[sku] for sku in units), Decimal("0"))
        discount = max(Decimal("0"), list_value - Decimal(str(ledger.order_total)))
        for sku, quantity in units.items():
            line_value = quantity * prices[sku]
            row = bucket(sku)
            row["gross"] += line_value
            if list_value > 0:
                row["discounts"] += discount * line_value / list_value
    rows: list[dict[str, Any]] = []
    total_net = sum((row["gross"] - row["discounts"] - row["returned"] * prices.get(sku, Decimal("0")) for sku, row in per_sku.items()), Decimal("0"))
    for sku, row in per_sku.items():
        price = prices.get(sku)
        cost = costs.get(sku)
        returns_value = _money(row["returned"] * price) if price is not None else Decimal("0")
        gross = _money(row["gross"])
        discounts = _money(row["discounts"])
        net = _money(gross - discounts - returns_value)
        cogs = _money(row["units"] * cost) if cost is not None else Decimal("0")
        fees = _money(net * fee_rate / _HUNDRED) if net > 0 else Decimal("0")
        fulfilment = _money(row["fulfilment"])
        handling = _money(row["returned"] * parsed_plan.return_handling_cost_per_unit)
        contribution = _money(net - cogs - fees - fulfilment - handling)
        sold = _qty(row["units"])
        cpu = None if sold <= 0 or price is None else _money(contribution / sold)
        share = _rate(net / total_net * _HUNDRED) if total_net > 0 else Decimal("0")
        break_even = None
        if cpu is not None and cpu > 0 and parsed_plan.fixed_cost_pool > 0:
            break_even = int(math.ceil(parsed_plan.fixed_cost_pool * share / _HUNDRED / cpu))
        rows.append({"sku_ref": sku, "orders": row["orders"], "units_sold": str(sold), "units_returned": str(_qty(row["returned"])), "list_price": None if price is None else str(_money(price)), "unit_cost": None if cost is None else str(cost.quantize(Decimal("0.0001"))), "gross_revenue": str(gross), "discounts": str(discounts), "returns_value": str(returns_value), "net_revenue": str(net), "cost_of_goods": str(cogs), "fees": str(fees), "fulfilment_cost": str(fulfilment), "return_handling": str(handling), "contribution": str(contribution), "contribution_margin_percent": None if net <= 0 else str(_rate(contribution / net * _HUNDRED)), "contribution_per_unit": None if cpu is None else str(cpu), "revenue_share_percent": str(share), "return_rate_percent": None if sold <= 0 else str(_rate(row["returned"] / sold * _HUNDRED)), "break_even_units": break_even, "priced": price is not None, "costed": cost is not None})
    rows.sort(key=lambda item: (-Decimal(item["contribution"]), item["sku_ref"]))
    for index, item in enumerate(rows, start=1):
        item["rank"] = index
    totals = {key: _money(sum((Decimal(item[key]) for item in rows), Decimal("0"))) for key in ("gross_revenue", "discounts", "returns_value", "net_revenue", "cost_of_goods", "fees", "fulfilment_cost", "return_handling", "contribution")}
    gross_profit = _money(totals["net_revenue"] - totals["cost_of_goods"])
    waterfall = [
        {"step": "gross_revenue", "amount": str(totals["gross_revenue"])}, {"step": "discounts", "amount": str(-totals["discounts"])}, {"step": "returns", "amount": str(-totals["returns_value"])}, {"step": "net_revenue", "amount": str(totals["net_revenue"])},
        {"step": "cost_of_goods", "amount": str(-totals["cost_of_goods"])}, {"step": "gross_profit", "amount": str(gross_profit)}, {"step": "fees", "amount": str(-totals["fees"])}, {"step": "fulfilment", "amount": str(-totals["fulfilment_cost"])}, {"step": "return_handling", "amount": str(-totals["return_handling"])}, {"step": "contribution", "amount": str(totals["contribution"])},
    ]
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "window_start": start, "window_end": end, "plan_digest": parsed_plan.plan_digest,
        "price_source": "catalog" if catalog_digest is not None else "none", "catalog_digest": catalog_digest, "fee_basis": fee_basis, "fee_rate_percent": str(fee_rate),
        "orders": orders, "orders_unallocated": orders_unallocated, "unallocated_revenue": str(_money(unallocated)), **{key: str(value) for key, value in totals.items()},
        "contribution_margin_percent": None if totals["net_revenue"] <= 0 else str(_rate(totals["contribution"] / totals["net_revenue"] * _HUNDRED)),
        "rows": rows, "unpriced_skus": sorted(sku for sku in per_sku if sku not in prices), "uncosted_skus": sorted(sku for sku in per_sku if sku not in costs), "waterfall": waterfall,
        "assumptions": {"fulfilment_cost_per_order": str(parsed_plan.fulfilment_cost_per_order), "fulfilment_cost_per_unit": str(parsed_plan.fulfilment_cost_per_unit), "return_handling_cost_per_unit": str(parsed_plan.return_handling_cost_per_unit), "payment_fee_percent": str(parsed_plan.payment_fee_percent), "fixed_cost_pool": str(parsed_plan.fixed_cost_pool)},
        "source_digests": [*([catalog_digest] if catalog_digest else []), *digests],
    }
    return seal(ProductMarginReport, payload, "report_digest")


def verify_product_margin(value: Any) -> ProductMarginReport:
    return value if isinstance(value, ProductMarginReport) else ProductMarginReport.model_validate(dict(detached(value)))


# --------------------------------------------------------------------------- #
# Price / volume / mix
# --------------------------------------------------------------------------- #


class PriceVolumeMixRow(StrictModel):
    sku_ref: OpaqueRef
    previous_units: Decimal
    current_units: Decimal
    previous_price: Decimal | None = None
    current_price: Decimal | None = None
    previous_revenue: Decimal
    current_revenue: Decimal
    price_effect: Decimal
    volume_effect: Decimal
    mix_effect: Decimal
    status: Literal["continuing", "new", "dropped", "unpriced"]

    @field_validator("previous_units", "current_units", "previous_price", "current_price", "previous_revenue", "current_revenue", "price_effect", "volume_effect", "mix_effect", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class PriceVolumeMix(StrictModel):
    schema_id: str = Field(default=PRICE_VOLUME_MIX_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    previous_digest: Sha256Digest
    current_digest: Sha256Digest
    previous_window: ShortText
    current_window: ShortText
    previous_revenue: Decimal
    current_revenue: Decimal
    revenue_change: Decimal
    price_effect: Decimal
    volume_effect: Decimal
    mix_effect: Decimal
    rows: tuple[PriceVolumeMixRow, ...] = Field(default_factory=tuple, max_length=5000)
    explanation: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    variance_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "explanation", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("previous_revenue", "current_revenue", "revenue_change", "price_effect", "volume_effect", "mix_effect", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PriceVolumeMix":
        if (self.price_effect + self.volume_effect + self.mix_effect).quantize(MONEY_QUANTUM) != self.revenue_change.quantize(MONEY_QUANTUM):
            raise ValueError("price, volume, and mix effects must sum to the revenue change")
        if not skip_digests(info) and self.variance_digest != sealed_digest(PriceVolumeMix, self, "variance_digest"):
            raise ValueError("variance_digest must commit the exact variance")
        return self

    def render(self) -> str:
        lines = [f"**Price / volume / mix {self.company_ref}** {self.previous_window} -> {self.current_window}: revenue {self.previous_revenue} -> {self.current_revenue} ({self.revenue_change:+}); price {self.price_effect:+}, volume {self.volume_effect:+}, mix {self.mix_effect:+} {self.currency}."]
        lines.extend(f"- {item}" for item in self.explanation)
        return "\n".join(lines)


def price_volume_mix(previous: ProductMarginReport | Mapping[str, Any], current: ProductMarginReport | Mapping[str, Any]) -> PriceVolumeMix:
    """Decompose the change in net revenue between two sealed reports into price, volume, and mix effects per SKU; the three sum exactly to the change."""

    before, after = verify_product_margin(previous), verify_product_margin(current)
    _require(before.company_ref == after.company_ref and before.currency == after.currency, "SOURCE_SCOPE_MISMATCH", "the two reports name different companies or currencies")
    _require(parsed(before.window_end) <= parsed(after.window_start), "WINDOWS_OVERLAP", "the previous window must end before the current one starts")
    prev = {row.sku_ref: row for row in before.rows}
    curr = {row.sku_ref: row for row in after.rows}
    skus = sorted(set(prev) | set(curr))

    def realised(row: ProductMarginRow | None) -> tuple[Decimal, Decimal | None, Decimal]:
        if row is None:
            return Decimal("0"), None, Decimal("0")
        units = row.units_sold
        price = None if units <= 0 or not row.priced else row.net_revenue / units
        return units, price, row.net_revenue

    total_prev_units = sum((prev[s].units_sold for s in prev), Decimal("0"))
    total_curr_units = sum((curr[s].units_sold for s in curr), Decimal("0"))
    rows: list[dict[str, Any]] = []
    price_total = volume_total = mix_total = Decimal("0")
    for sku in skus:
        q0, p0, r0 = realised(prev.get(sku))
        q1, p1, r1 = realised(curr.get(sku))
        if p0 is None and p1 is None:
            status, price_effect, volume_effect, mix_effect = "unpriced", Decimal("0"), r1 - r0, Decimal("0")
        elif p0 is None:
            status, price_effect, volume_effect, mix_effect = "new", Decimal("0"), r1 - r0, Decimal("0")
        elif p1 is None or q1 <= 0:
            status, price_effect, volume_effect, mix_effect = "dropped", Decimal("0"), r1 - r0, Decimal("0")
        else:
            status = "continuing"
            price_effect = (p1 - p0) * q1
            expected_q1 = (total_curr_units * q0 / total_prev_units) if total_prev_units > 0 else q1
            volume_effect = (expected_q1 - q0) * p0
            mix_effect = (q1 - expected_q1) * p0
            residual = (r1 - r0) - (price_effect + volume_effect + mix_effect)
            price_effect += residual  # rounding of realised prices lands with price so the identity holds exactly
        price_effect, volume_effect, mix_effect = _money(price_effect), _money(volume_effect), _money(mix_effect)
        drift = _money(r1 - r0) - (price_effect + volume_effect + mix_effect)
        volume_effect += drift
        price_total += price_effect
        volume_total += volume_effect
        mix_total += mix_effect
        rows.append({"sku_ref": sku, "previous_units": str(_qty(q0)), "current_units": str(_qty(q1)), "previous_price": None if p0 is None else str(_money(p0)), "current_price": None if p1 is None else str(_money(p1)), "previous_revenue": str(_money(r0)), "current_revenue": str(_money(r1)), "price_effect": str(price_effect), "volume_effect": str(volume_effect), "mix_effect": str(mix_effect), "status": status})
    change = _money(after.net_revenue - before.net_revenue)
    allocated = sum((Decimal(row["current_revenue"]) - Decimal(row["previous_revenue"]) for row in rows), Decimal("0"))
    unallocated_change = _money(change - allocated)
    if unallocated_change != 0 and rows:
        rows[0]["volume_effect"] = str(_money(Decimal(rows[0]["volume_effect"]) + unallocated_change))
        volume_total += unallocated_change
    explanation: list[str] = []
    biggest = max((abs(price_total), "price"), (abs(volume_total), "volume"), (abs(mix_total), "mix"))[1] if rows else "volume"
    if change > 0:
        explanation.append(f"revenue grew {change}; the largest driver is {biggest} ({ {'price': price_total, 'volume': volume_total, 'mix': mix_total}[biggest]:+})")
    elif change < 0:
        explanation.append(f"revenue fell {abs(change)}; the largest driver is {biggest} ({ {'price': price_total, 'volume': volume_total, 'mix': mix_total}[biggest]:+})")
    else:
        explanation.append("revenue is unchanged")
    for row in sorted(rows, key=lambda item: -abs(Decimal(item["current_revenue"]) - Decimal(item["previous_revenue"])))[:3]:
        explanation.append(f"{row['sku_ref']}: {row['status']}; price {Decimal(row['price_effect']):+}, volume {Decimal(row['volume_effect']):+}, mix {Decimal(row['mix_effect']):+}")
    payload = {"company_ref": after.company_ref, "currency": after.currency, "previous_digest": before.report_digest, "current_digest": after.report_digest, "previous_window": f"{before.window_start[:10]}..{before.window_end[:10]}", "current_window": f"{after.window_start[:10]}..{after.window_end[:10]}", "previous_revenue": str(before.net_revenue), "current_revenue": str(after.net_revenue), "revenue_change": str(change), "price_effect": str(_money(price_total)), "volume_effect": str(_money(volume_total)), "mix_effect": str(_money(mix_total)), "rows": rows, "explanation": explanation[:8]}
    return seal(PriceVolumeMix, payload, "variance_digest")


PRODUCT_MARGIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "product_margin",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["replay_orders", "price_from_catalog", "cost_from_stock", "fees_from_batches", "seal_report", "decompose_variance"],
    "waterfall": list(WATERFALL_STEPS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "revenue per SKU is shipped units at the published catalog price; an order with an unpriced SKU is left unallocated, never guessed",
        "cost of goods is the stock position's landed average unit cost; a SKU without one is reported uncosted",
        "fees are the settlement batches' observed rate over the window, else the plan's rate, and the report says which",
        "price, volume, and mix effects sum exactly to the revenue change; nothing estimates elasticity",
    ],
}

__all__ = ["PRICE_VOLUME_MIX_SCHEMA", "PRODUCT_MARGIN_MANIFEST", "PRODUCT_MARGIN_PLAN_SCHEMA", "PRODUCT_MARGIN_SCHEMA", "WATERFALL_STEPS", "PriceVolumeMix", "PriceVolumeMixRow", "ProductMarginError", "ProductMarginPlan", "ProductMarginReport", "ProductMarginRow", "WaterfallStep", "build_product_margin", "compile_product_margin_plan", "price_volume_mix", "verify_product_margin"]
