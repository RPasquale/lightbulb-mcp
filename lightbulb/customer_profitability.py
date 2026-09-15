"""Customer profitability: what each customer earned after the cost to serve them, from the replayed orders and the sealed product margin.

A product can be profitable while the customers who buy it are not: many
small orders, returns, and discounts eat the contribution.  From the
replayed fulfilment orders (each captured with the customer it was
placed for) and the sealed product margin report for the same window,
``build_customer_profitability`` seals per customer:

* orders, units, and the order totals as placed; gross revenue,
  discounts, returns, cost of goods, and fees allocated from the report's
  SKU rows by units (so the customer table is the margin report cut by
  customer, and ties to it); fulfilment per order and per unit and
  return handling per returned unit from the margin plan: the cost to
  serve;
* contribution, margin, average order value, return rate, and each
  customer's share of contribution and revenue;
* a rank and a class: core (the customers who carry the contribution),
  promising (few orders, good margin), drain (negative contribution or a
  return rate over the threshold), and long tail;
* the concentration: how much of the contribution the top customers
  carry, and whether the customer totals tie to the margin report (they
  do when every order in the window is supplied).

Orders captured without a customer are one "unattributed" row so the
totals still tie to the margin report.  Nothing here reads a provider,
profiles a person, or persists anything: a customer is an opaque ref.
"""

from __future__ import annotations

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
from lightbulb.product_margin import ProductMarginPlan, verify_product_margin

CUSTOMER_PROFITABILITY_SCHEMA = "lightbulb.customer_profitability.v1"
CUSTOMER_CLASSES: tuple[str, ...] = ("core", "promising", "drain", "long_tail")
CustomerClass = Literal["core", "promising", "drain", "long_tail"]
UNATTRIBUTED = "customer:unattributed"
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class CustomerProfitabilityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CustomerProfitabilityError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(numerator: Decimal, denominator: Decimal) -> Decimal | None:
    return None if denominator <= 0 else (numerator / denominator * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class CustomerRow(StrictModel):
    customer_ref: OpaqueRef
    orders: int = Field(ge=0)
    units: Decimal
    returned_units: Decimal
    order_value: Decimal
    gross_revenue: Decimal
    discounts: Decimal
    returns_value: Decimal
    net_revenue: Decimal
    cost_of_goods: Decimal
    fees: Decimal
    fulfilment_cost: Decimal
    return_handling: Decimal
    cost_to_serve: Decimal
    contribution: Decimal
    margin_percent: Decimal | None = None
    average_order_value: Decimal
    return_rate_percent: Decimal | None = None
    revenue_share_percent: Decimal
    contribution_share_percent: Decimal | None = None
    rank: int = Field(ge=1)
    customer_class: CustomerClass
    rationale: ShortText

    @field_validator("units", "returned_units", "order_value", "gross_revenue", "discounts", "returns_value", "net_revenue", "cost_of_goods", "fees", "fulfilment_cost", "return_handling", "cost_to_serve", "contribution", "margin_percent", "average_order_value", "return_rate_percent", "revenue_share_percent", "contribution_share_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class CustomerProfitability(StrictModel):
    schema_id: str = Field(default=CUSTOMER_PROFITABILITY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest
    target_margin_percent: Decimal
    return_rate_threshold_percent: Decimal
    core_share_percent: Decimal
    rows: tuple[CustomerRow, ...] = Field(default_factory=tuple, max_length=20000)
    customers: int = Field(ge=0)
    orders: int = Field(ge=0)
    net_revenue: Decimal
    contribution: Decimal
    top_customers_for_half_contribution: int = Field(ge=0)
    ties_to_report: bool
    by_class: dict[str, int] = Field(default_factory=dict)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    profitability_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("target_margin_percent", "return_rate_threshold_percent", "core_share_percent", "net_revenue", "contribution", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CustomerProfitability":
        if sum(self.by_class.values()) != len(self.rows) or self.customers != len(self.rows):
            raise ValueError("every customer is counted once by class")
        if not skip_digests(info) and self.profitability_digest != sealed_digest(CustomerProfitability, self, "profitability_digest"):
            raise ValueError("profitability_digest must commit the exact document")
        return self

    def row(self, customer_ref: str) -> CustomerRow | None:
        return next((row for row in self.rows if row.customer_ref == customer_ref), None)

    def render(self) -> str:
        lines = [f"**Customer profitability {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.customers} customer(s), {self.orders} order(s), net revenue {self.net_revenue} {self.currency}, contribution {self.contribution}; the top {self.top_customers_for_half_contribution} carry half the contribution; " + ", ".join(f"{count} {name.replace('_', ' ')}" for name, count in self.by_class.items() if count) + "."]
        for row in self.rows:
            lines.append(f"- #{row.rank} {row.customer_ref} [{row.customer_class}]: {row.rationale}")
        return "\n".join(lines)


def build_customer_profitability(plan: ProductMarginPlan | Mapping[str, Any], *, margin_report: Mapping[str, Any] | Any, fulfilment_states: Sequence[tuple[Any, Any]], as_of: str, target_margin_percent: Any = "30", return_rate_threshold_percent: Any = "10", core_share_percent: Any = "80") -> CustomerProfitability:
    """The sealed customer table for the margin report's window from the replayed orders captured with their customers."""

    from lightbulb.fulfilment_chain import FULFILMENT_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ProductMarginPlan) else ProductMarginPlan.model_validate(detached(plan))
    report = verify_product_margin(margin_report)
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
    target = decimal_value(target_margin_percent, field_name="target_margin_percent")
    threshold = decimal_value(return_rate_threshold_percent, field_name="return_rate_threshold_percent")
    core_share = decimal_value(core_share_percent, field_name="core_share_percent")
    _require(Decimal("0") < core_share <= _HUNDRED, "THRESHOLD_INVALID", "core_share_percent is in (0, 100]")
    at = timestamp(as_of, field_name="as_of")
    start, end = parsed(report.window_start), parsed(report.window_end)
    def per_unit(field: str) -> dict[str, Decimal]:
        return {row.sku_ref: Decimal(str(getattr(row, field))) / Decimal(str(row.units_sold)) if Decimal(str(row.units_sold)) > 0 else Decimal("0") for row in report.rows}

    unit_gross, unit_discount, unit_cogs, unit_fees = per_unit("gross_revenue"), per_unit("discounts"), per_unit("cost_of_goods"), per_unit("fees")
    unit_return = {row.sku_ref: Decimal(str(row.returns_value)) / Decimal(str(row.units_returned)) if Decimal(str(row.units_returned)) > 0 else Decimal("0") for row in report.rows}
    per_order = Decimal(str(parsed_plan.fulfilment_cost_per_order))
    per_unit = Decimal(str(parsed_plan.fulfilment_cost_per_unit))
    per_return = Decimal(str(parsed_plan.return_handling_cost_per_unit))
    customers: dict[str, dict[str, Any]] = {}
    digests: list[str] = [report.report_digest]
    orders = 0
    for plan_doc, state_doc in fulfilment_states:
        fplan, state = FULFILMENT_LIFECYCLE.bind(plan_doc, state_doc)
        _require(fplan.company_ref == parsed_plan.company_ref and fplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"order {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if ledger.order_created_at is None or not (start <= parsed(str(ledger.order_created_at)) < end) or state.status == "cancelled":
            continue
        orders += 1
        customer_ref = str(getattr(ledger, "customer_ref", None) or UNATTRIBUTED)
        row = customers.setdefault(customer_ref, {"orders": 0, "units": Decimal("0"), "returned": Decimal("0"), "order_value": Decimal("0"), "gross": Decimal("0"), "discounts": Decimal("0"), "fees": Decimal("0"), "returns_value": Decimal("0"), "cogs": Decimal("0"), "fulfilment": Decimal("0"), "return_handling": Decimal("0")})
        row["orders"] += 1
        row["order_value"] += Decimal(str(ledger.order_total))
        row["fulfilment"] += per_order
        for sku_ref, quantity in ledger.units.items():
            units = Decimal(str(quantity))
            row["units"] += units
            row["gross"] += units * unit_gross.get(sku_ref, Decimal("0"))
            row["discounts"] += units * unit_discount.get(sku_ref, Decimal("0"))
            row["fees"] += units * unit_fees.get(sku_ref, Decimal("0"))
            row["cogs"] += units * unit_cogs.get(sku_ref, Decimal("0"))
            row["fulfilment"] += units * per_unit
        for sku_ref, quantity in ledger.returned_units.items():
            returned = Decimal(str(quantity))
            row["returned"] += returned
            row["returns_value"] += returned * unit_return.get(sku_ref, Decimal("0"))
            row["return_handling"] += returned * per_return
    rows: list[dict[str, Any]] = []
    for customer_ref, row in customers.items():
        net = _money(row["gross"] - row["discounts"] - row["returns_value"])
        fees = _money(row["fees"])
        cogs, fulfilment, returns_cost = _money(row["cogs"]), _money(row["fulfilment"]), _money(row["return_handling"])
        serve = _money(fees + fulfilment + returns_cost)
        contribution = _money(net - cogs - serve)
        rows.append({"customer_ref": customer_ref, "orders": row["orders"], "units": str(row["units"]), "returned_units": str(row["returned"]), "order_value": str(_money(row["order_value"])), "gross_revenue": str(_money(row["gross"])), "discounts": str(_money(row["discounts"])), "returns_value": str(_money(row["returns_value"])), "net_revenue": str(net), "cost_of_goods": str(cogs), "fees": str(fees), "fulfilment_cost": str(fulfilment), "return_handling": str(returns_cost), "cost_to_serve": str(serve), "contribution": str(contribution), "margin_percent": None if _pct(contribution, net) is None else str(_pct(contribution, net)), "average_order_value": str(_money(row["order_value"] / row["orders"])) if row["orders"] else "0", "return_rate_percent": None if row["units"] <= 0 else str(_pct(row["returned"], row["units"]))})
    total_net = _money(sum((Decimal(row["net_revenue"]) for row in rows), Decimal("0")))
    total_contribution = _money(sum((Decimal(row["contribution"]) for row in rows), Decimal("0")))
    positive = sum((Decimal(row["contribution"]) for row in rows if Decimal(row["contribution"]) > 0), Decimal("0"))
    rows.sort(key=lambda row: (-Decimal(row["contribution"]), row["customer_ref"]))
    running = Decimal("0")
    half = 0
    counts: dict[str, int] = {}
    for index, row in enumerate(rows, start=1):
        contribution = Decimal(row["contribution"])
        row["rank"] = index
        row["revenue_share_percent"] = str(_pct(Decimal(row["net_revenue"]), total_net) or Decimal("0"))
        row["contribution_share_percent"] = None if positive <= 0 or contribution <= 0 else str(_pct(contribution, positive))
        if contribution > 0:
            running += contribution
            if half == 0 and positive > 0 and running * 2 >= positive:
                half = index
        margin = None if row["margin_percent"] is None else Decimal(row["margin_percent"])
        return_rate = None if row["return_rate_percent"] is None else Decimal(row["return_rate_percent"])
        share_so_far = _pct(running, positive) if positive > 0 else None
        if contribution <= 0 or (return_rate is not None and return_rate > threshold):
            klass = "drain"
            rationale = (f"contribution {contribution} on {row['net_revenue']} net" if contribution <= 0 else f"{return_rate}% of units come back against a {threshold}% threshold") + f"; {row['orders']} order(s), cost to serve {row['cost_to_serve']}"
        elif share_so_far is not None and share_so_far <= core_share and (margin is None or margin >= target):
            klass = "core"
            rationale = f"contribution {contribution} ({row['contribution_share_percent']}% of the positive total) at {margin}% margin over {row['orders']} order(s)"
        elif row["orders"] <= 2 and margin is not None and margin >= target:
            klass = "promising"
            rationale = f"{row['orders']} order(s) at {margin}% margin, contribution {contribution}; worth a second order"
        else:
            klass = "long_tail"
            rationale = f"contribution {contribution} at {margin}% margin over {row['orders']} order(s), average order {row['average_order_value']}"
        row["customer_class"] = klass
        row["rationale"] = rationale[:300]
        counts[klass] = counts.get(klass, 0) + 1
    recommendations = [f"{row['customer_ref']}: {row['customer_class']}; {row['rationale']}" for row in rows if row["customer_class"] in ("drain", "promising")][:20]
    if rows and half:
        recommendations.insert(0, f"the top {half} of {len(rows)} customer(s) carry half the contribution; {counts.get('core', 0)} core customer(s) sit inside the first {core_share}% of it")
    if not recommendations:
        recommendations.append("no orders with customers in the window" if not rows else "every customer earns the target margin with returns inside the threshold")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": report.window_start, "window_end": report.window_end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report.report_digest,
        "target_margin_percent": str(target), "return_rate_threshold_percent": str(threshold), "core_share_percent": str(core_share), "rows": rows, "customers": len(rows), "orders": orders, "net_revenue": str(total_net), "contribution": str(total_contribution),
        "top_customers_for_half_contribution": half, "ties_to_report": abs(total_net - _money(report.net_revenue)) <= Decimal("0.01") * max(1, len(rows)) and abs(total_contribution - _money(report.contribution)) <= Decimal("0.01") * max(1, len(rows)), "by_class": {name: counts[name] for name in CUSTOMER_CLASSES if counts.get(name)}, "recommendations": [item[:300] for item in recommendations[:24]], "source_digests": digests,
    }
    return seal(CustomerProfitability, payload, "profitability_digest")


def verify_customer_profitability(value: Any) -> CustomerProfitability:
    return value if isinstance(value, CustomerProfitability) else CustomerProfitability.model_validate(dict(detached(value)))


CUSTOMER_PROFITABILITY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "customer_profitability",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["verify_margin_report", "replay_orders_with_customers", "cost_to_serve_per_order", "rank_and_classify", "concentration", "seal_document"],
    "classes": list(CUSTOMER_CLASSES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "gross revenue, discounts, returns, cost of goods, and fees are the report's SKU rows allocated by units, so the customer totals tie to the report within a cent a customer; the order totals as placed are kept beside them",
        "a customer is the opaque reference the order was captured with; nothing here profiles a person",
        "unit costs and prices come from the sealed margin report for the same window; fulfilment and return handling from the margin plan",
        "a drain is negative contribution or a return rate over the threshold; core customers carry the contribution up to the core share at or above the target margin",
        "orders without a customer stay one unattributed row so the totals tie",
    ],
}

__all__ = ["CUSTOMER_CLASSES", "CUSTOMER_PROFITABILITY_MANIFEST", "CUSTOMER_PROFITABILITY_SCHEMA", "UNATTRIBUTED", "CustomerProfitability", "CustomerProfitabilityError", "CustomerRow", "build_customer_profitability", "verify_customer_profitability"]
