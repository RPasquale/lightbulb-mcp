"""Returns ledger: what came back, in what condition, what it cost after restocking and write-downs, and which SKUs bleed, from the replayed fulfilment and inventory chains.

The margin report nets returns off revenue; nothing said what a return
actually costs once the goods are back.  ``build_returns_ledger`` seals
that from the chains:

* per SKU: units sold and returned inside the window, the return rate,
  the returned orders and their conditions (resaleable, damaged, and the
  rest), the refund value at the margin report's realised price for the
  SKU (the order's average price when no report is supplied), the
  handling cost at the plan's rate, the units the inventory chain actually
  restocked from those returns (bound by the fulfilment state's digest)
  and the stock value they put back, and the units written down in the
  window on that SKU's positions with the amount;
* per SKU the net cost of returns (refund plus handling plus write-downs
  less the value restocked) and that cost as a share of net revenue when
  a margin report is supplied;
* totals, and recommendations naming the SKUs returning above the plan's
  rate threshold and the SKUs whose returns come back unsaleable more
  often than the plan's floor allows.

A return the inventory chain has not restocked is counted as unsaleable
until it is, never assumed back on the shelf.  Nothing here reads a
provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

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

RETURNS_PLAN_SCHEMA = "lightbulb.returns_plan.v1"
RETURNS_LEDGER_SCHEMA = "lightbulb.returns_ledger.v1"
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")
_QTY = Decimal("0.01")


class ReturnsLedgerError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ReturnsLedgerError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _qty(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_QTY, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ReturnsPlan(StrictModel):
    schema_id: str = Field(default=RETURNS_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    return_rate_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    resaleable_floor_percent: Decimal = Field(default=Decimal("70"), validate_default=True)
    return_handling_cost_per_unit: Decimal = Field(default=Decimal("0"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("return_rate_threshold_percent", "resaleable_floor_percent", "return_handling_cost_per_unit", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReturnsPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ReturnsPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_returns_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ReturnsPlan:
    return seal(ReturnsPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class ReturnedOrder(StrictModel):
    order_ref: OpaqueRef
    customer_ref: OpaqueRef | None = None
    returned_at: str
    days_to_return: int | None = None
    units: Decimal
    condition: ShortText
    refund_value: Decimal
    restocked: bool

    @field_validator("units", "refund_value", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class SkuReturns(StrictModel):
    sku_ref: OpaqueRef
    units_sold: Decimal
    units_returned: Decimal
    return_rate_percent: Decimal | None = None
    returned_orders: int = Field(ge=0)
    by_condition: dict[str, Decimal] = Field(default_factory=dict)
    resaleable_percent: Decimal | None = None
    refund_value: Decimal
    handling_cost: Decimal
    restocked_units: Decimal
    restocked_value: Decimal
    unsaleable_units: Decimal
    written_down_units: Decimal
    written_down_amount: Decimal
    net_cost: Decimal
    net_revenue: Decimal | None = None
    cost_of_revenue_percent: Decimal | None = None
    orders: tuple[ReturnedOrder, ...] = Field(default_factory=tuple, max_length=2000)
    verdict: ShortText

    @field_validator("orders", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("units_sold", "units_returned", "return_rate_percent", "resaleable_percent", "refund_value", "handling_cost", "restocked_units", "restocked_value", "unsaleable_units", "written_down_units", "written_down_amount", "net_cost", "net_revenue", "cost_of_revenue_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("by_condition", mode="before")
    @classmethod
    def _buckets(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(key): decimal_value(amount, field_name=str(info.field_name), allow_negative=True) for key, amount in dict(value or {}).items()}


class ReturnsLedger(StrictModel):
    schema_id: str = Field(default=RETURNS_LEDGER_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest | None = None
    skus: tuple[SkuReturns, ...] = Field(default_factory=tuple, max_length=5000)
    orders_in_window: int = Field(ge=0)
    orders_returned: int = Field(ge=0)
    units_sold: Decimal
    units_returned: Decimal
    return_rate_percent: Decimal | None = None
    refund_value: Decimal
    handling_cost: Decimal
    restocked_value: Decimal
    written_down_amount: Decimal
    net_cost: Decimal
    cost_of_revenue_percent: Decimal | None = None
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=12000)
    returns_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("skus", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("units_sold", "units_returned", "return_rate_percent", "refund_value", "handling_cost", "restocked_value", "written_down_amount", "net_cost", "cost_of_revenue_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ReturnsLedger":
        if self.net_cost != self.refund_value + self.handling_cost + self.written_down_amount - self.restocked_value:
            raise ValueError("net_cost is refund plus handling plus write-downs less the value restocked")
        if not skip_digests(info) and self.returns_digest != sealed_digest(ReturnsLedger, self, "returns_digest"):
            raise ValueError("returns_digest must commit the exact ledger")
        return self

    def sku(self, sku_ref: str) -> SkuReturns | None:
        return next((row for row in self.skus if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        rate = "n/a" if self.return_rate_percent is None else f"{self.return_rate_percent}%"
        lines = [f"**Returns {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.orders_returned} of {self.orders_in_window} order(s) returned ({self.units_returned} of {self.units_sold} unit(s), {rate}); net cost {self.net_cost} {self.currency} after {self.restocked_value} restocked."]
        lines.extend(f"- {row.sku_ref}: {row.verdict}" for row in self.skus)
        return "\n".join(lines)


def build_returns_ledger(plan: ReturnsPlan | Mapping[str, Any], *, fulfilment_states: Sequence[tuple[Any, Any]], inventory_states: Sequence[tuple[Any, Any]] = (), margin_report: Mapping[str, Any] | Any | None = None, window_start: str, window_end: str, as_of: str) -> ReturnsLedger:
    """The sealed returns ledger over the window from the replayed orders and stock positions, with the margin report's net revenue per SKU when supplied."""

    from lightbulb.fulfilment_chain import FULFILMENT_LIFECYCLE
    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    parsed_plan = plan if isinstance(plan, ReturnsPlan) else ReturnsPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = []
    revenue_by_sku: dict[str, Decimal] = {}
    price_by_sku: dict[str, Decimal] = {}
    report_digest = None
    if margin_report is not None:
        from lightbulb.product_margin import verify_product_margin

        report = verify_product_margin(margin_report)
        _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
        _require(report.window_start == start and report.window_end == end, "REPORT_WINDOW_MISMATCH", "the margin report must cover exactly this window")
        revenue_by_sku = {row.sku_ref: Decimal(str(row.net_revenue)) for row in report.rows}
        price_by_sku = {row.sku_ref: Decimal(str(row.net_revenue)) / Decimal(str(row.units_sold)) for row in report.rows if row.priced and Decimal(str(row.units_sold)) > 0}
        report_digest = report.report_digest
        digests.append(report_digest)

    # restocks and write-downs from the stock positions, keyed by the fulfilment state digest they came from and by SKU
    restocked_from: dict[str, Decimal] = {}
    restock_value_from: dict[str, Decimal] = {}
    write_downs: dict[str, tuple[Decimal, Decimal]] = {}
    for plan_doc, state_doc in inventory_states:
        chain_plan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
        _require(chain_plan.company_ref == parsed_plan.company_ref and chain_plan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        sku_ref = str(state.ledger.sku_ref)
        avg = Decimal(str(state.ledger.avg_unit_cost))
        for item in state.transition_history:
            command = detached(item.command) if not isinstance(item, Mapping) else dict(item["command"])
            event = str(command.get("event"))
            receipt = dict(command.get("receipt") or {})
            stamp = str(command.get("occurred_at"))
            if event == "restock" and receipt.get("restock_source"):
                units = Decimal(str(receipt.get("restock_units") or "0"))
                source = str(receipt["restock_source"])
                restocked_from[source] = restocked_from.get(source, Decimal("0")) + units
                restock_value_from[source] = restock_value_from.get(source, Decimal("0")) + units * avg
            elif event == "write_down" and parsed(start) <= parsed(stamp) < parsed(end):
                units, amount = write_downs.get(sku_ref, (Decimal("0"), Decimal("0")))
                write_downs[sku_ref] = (units + Decimal(str(receipt.get("write_down_units") or "0")), amount + Decimal(str(receipt.get("write_down_amount") or "0")))

    per_sku: dict[str, dict[str, Any]] = {}
    orders_in_window = 0
    orders_returned: set[str] = set()
    for order_plan, state in fulfilment_states:
        chain_plan, bound = FULFILMENT_LIFECYCLE.bind(order_plan, state)
        _require(chain_plan.company_ref == parsed_plan.company_ref and chain_plan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"order {bound.scope.entity_ref} belongs to another company or currency")
        ledger = bound.ledger
        if ledger.order_created_at is None or bound.status == "cancelled" or not (parsed(start) <= parsed(str(ledger.order_created_at)) < parsed(end)):
            continue
        digests.append(bound.state_digest)
        orders_in_window += 1
        total_units = sum((Decimal(str(value)) for value in ledger.units.values()), Decimal("0"))
        unit_price = Decimal("0") if total_units <= 0 else Decimal(str(ledger.order_total)) / total_units
        for sku_ref, units in ledger.units.items():
            row = per_sku.setdefault(str(sku_ref), {"sold": Decimal("0"), "returned": Decimal("0"), "orders": [], "conditions": {}, "refund": Decimal("0"), "restocked": Decimal("0"), "restocked_value": Decimal("0")})
            row["sold"] += Decimal(str(units))
        if not ledger.returned_units:
            continue
        condition = str(ledger.return_condition or "unknown")
        restocked_units = restocked_from.get(bound.state_digest, Decimal("0"))
        for sku_ref, units in ledger.returned_units.items():
            quantity = Decimal(str(units))
            if quantity <= 0:
                continue
            orders_returned.add(bound.scope.entity_ref)
            row = per_sku.setdefault(str(sku_ref), {"sold": Decimal("0"), "returned": Decimal("0"), "orders": [], "conditions": {}, "refund": Decimal("0"), "restocked": Decimal("0"), "restocked_value": Decimal("0")})
            row["returned"] += quantity
            row["conditions"][condition] = row["conditions"].get(condition, Decimal("0")) + quantity
            refund = _money(quantity * price_by_sku.get(str(sku_ref), unit_price))
            row["refund"] += refund
            put_back = min(restocked_units, quantity)
            row["restocked"] += put_back
            row["restocked_value"] += (restock_value_from.get(bound.state_digest, Decimal("0")) / restocked_units * put_back) if restocked_units > 0 else Decimal("0")
            days = None if ledger.returned_at is None else (parsed(str(ledger.returned_at)) - parsed(str(ledger.order_created_at))).days
            row["orders"].append({"order_ref": str(ledger.order_ref or bound.scope.entity_ref), "customer_ref": getattr(ledger, "customer_ref", None), "returned_at": str(ledger.returned_at), "days_to_return": days, "units": str(_qty(quantity)), "condition": condition, "refund_value": str(refund), "restocked": put_back > 0})
    handling_rate = parsed_plan.return_handling_cost_per_unit
    rows: list[dict[str, Any]] = []
    for sku_ref, row in per_sku.items():
        sold, returned = row["sold"], row["returned"]
        rate = None if sold <= 0 else _pct(returned / sold * _HUNDRED)
        resaleable = None if returned <= 0 else _pct(row["conditions"].get("resaleable", Decimal("0")) / returned * _HUNDRED)
        handling = _money(returned * handling_rate)
        restocked_value = _money(row["restocked_value"])
        wd_units, wd_amount = write_downs.get(sku_ref, (Decimal("0"), Decimal("0")))
        net = _money(row["refund"] + handling + wd_amount - restocked_value)
        revenue = revenue_by_sku.get(sku_ref)
        share = None if revenue is None or revenue <= 0 else _pct(net / revenue * _HUNDRED)
        unsaleable = _qty(returned - row["restocked"])
        if returned <= 0:
            verdict = f"{_qty(sold)} sold, none returned" + (f"; {_qty(wd_units)} unit(s) written down for {_money(wd_amount)}" if wd_units > 0 or wd_amount > 0 else "")
        else:
            verdict = f"{_qty(returned)} of {_qty(sold)} unit(s) returned ({rate}%) across {len(row['orders'])} order(s); {_qty(row['restocked'])} restocked worth {restocked_value}, {unsaleable} not back on the shelf; net cost {net}" + (f" ({share}% of net revenue)" if share is not None else "")
        rows.append({"sku_ref": sku_ref, "units_sold": str(_qty(sold)), "units_returned": str(_qty(returned)), "return_rate_percent": None if rate is None else str(rate), "returned_orders": len(row["orders"]), "by_condition": {key: str(_qty(value)) for key, value in sorted(row["conditions"].items())}, "resaleable_percent": None if resaleable is None else str(resaleable), "refund_value": str(_money(row["refund"])), "handling_cost": str(handling), "restocked_units": str(_qty(row["restocked"])), "restocked_value": str(restocked_value), "unsaleable_units": str(unsaleable), "written_down_units": str(_qty(wd_units)), "written_down_amount": str(_money(wd_amount)), "net_cost": str(net), "net_revenue": None if revenue is None else str(_money(revenue)), "cost_of_revenue_percent": None if share is None else str(share), "orders": row["orders"], "verdict": verdict[:300]})
    rows.sort(key=lambda row: (-Decimal(row["net_cost"]), row["sku_ref"]))
    units_sold = _qty(sum((Decimal(row["units_sold"]) for row in rows), Decimal("0")))
    units_returned = _qty(sum((Decimal(row["units_returned"]) for row in rows), Decimal("0")))
    refund_total = _money(sum((Decimal(row["refund_value"]) for row in rows), Decimal("0")))
    handling_total = _money(sum((Decimal(row["handling_cost"]) for row in rows), Decimal("0")))
    restocked_total = _money(sum((Decimal(row["restocked_value"]) for row in rows), Decimal("0")))
    written_total = _money(sum((Decimal(row["written_down_amount"]) for row in rows), Decimal("0")))
    net_total = _money(refund_total + handling_total + written_total - restocked_total)
    revenue_total = _money(sum(revenue_by_sku.values(), Decimal("0"))) if revenue_by_sku else None
    recommendations: list[str] = []
    for row in rows:
        if row["return_rate_percent"] is not None and Decimal(row["return_rate_percent"]) > parsed_plan.return_rate_threshold_percent:
            recommendations.append(f"{row['sku_ref']}: {row['return_rate_percent']}% returned against the {parsed_plan.return_rate_threshold_percent}% threshold, net cost {row['net_cost']}; find out why before selling more")
        if row["resaleable_percent"] is not None and Decimal(row["resaleable_percent"]) < parsed_plan.resaleable_floor_percent:
            recommendations.append(f"{row['sku_ref']}: only {row['resaleable_percent']}% of returns came back resaleable against the {parsed_plan.resaleable_floor_percent}% floor; a quality or packaging problem, not a change of mind")
        if Decimal(row["units_returned"]) > 0 and Decimal(row["unsaleable_units"]) > 0 and row["by_condition"].get("resaleable") and Decimal(row["by_condition"]["resaleable"]) > Decimal(row["restocked_units"]):
            recommendations.append(f"{row['sku_ref']}: {_qty(Decimal(row['by_condition']['resaleable']) - Decimal(row['restocked_units']))} resaleable unit(s) returned but not yet restocked; put them back on the shelf")
    if not recommendations:
        recommendations.append("no SKU returns above the threshold and every return that could go back on the shelf did" if rows else "no order in the window")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report_digest, "skus": rows, "orders_in_window": orders_in_window, "orders_returned": len(orders_returned), "units_sold": str(units_sold), "units_returned": str(units_returned), "return_rate_percent": None if units_sold <= 0 else str(_pct(units_returned / units_sold * _HUNDRED)), "refund_value": str(refund_total), "handling_cost": str(handling_total), "restocked_value": str(restocked_total), "written_down_amount": str(written_total), "net_cost": str(net_total), "cost_of_revenue_percent": None if revenue_total is None or revenue_total <= 0 else str(_pct(net_total / revenue_total * _HUNDRED)), "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": digests}
    return seal(ReturnsLedger, payload, "returns_digest")


def verify_returns_ledger(value: Any) -> ReturnsLedger:
    return value if isinstance(value, ReturnsLedger) else ReturnsLedger.model_validate(dict(detached(value)))


RETURNS_LEDGER_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "returns_ledger",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["replay_returned_orders", "bind_restocks_by_fulfilment_digest", "write_downs_in_window", "net_cost_per_sku", "seal_ledger"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a return counts as restocked only when a stock position replayed a restock bound to that fulfilment state's digest; otherwise its units are not back on the shelf",
        "the refund value is the returned units at the margin report's realised price for the SKU, else the order's average price; handling is the plan's rate per unit; write-downs are the window's, on the SKU's positions",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["RETURNS_LEDGER_MANIFEST", "RETURNS_LEDGER_SCHEMA", "RETURNS_PLAN_SCHEMA", "ReturnedOrder", "ReturnsLedger", "ReturnsLedgerError", "ReturnsPlan", "SkuReturns", "build_returns_ledger", "compile_returns_plan", "verify_returns_ledger"]
