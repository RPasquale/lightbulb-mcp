"""Product portfolio: every SKU placed by what it earns, how fast it moves, how much is held, and what to do about it.

The product margin report says what each SKU earned; the stock positions
say what is on hand, inbound, and on order and how long the supplier takes;
a previous margin report says how the units moved.  ``build_product_portfolio``
puts them on one line per SKU with sealed thresholds:

* velocity (units a week over the window), growth against the previous
  window, contribution margin, revenue share, return rate;
* days of cover (on hand plus inbound over velocity), sell-through (units
  sold over units sold plus on hand), stock value at landed cost;
* a quadrant from growth and margin against the plan's thresholds (grow,
  harvest, fix, cut) and flags the thresholds justify (overstocked, stockout
  risk, return problem, unpriced, uncosted);
* one recommendation per SKU that names the number behind it: reorder
  before the lead time runs out, run down stock, run the price probe the
  growth engine plans, fix the return problem, or discontinue.

Everything is arithmetic on replayed states and sealed reports; nothing
here predicts demand, estimates elasticity, or reads a provider.
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

PRODUCT_PORTFOLIO_PLAN_SCHEMA = "lightbulb.product_portfolio_plan.v1"
PRODUCT_PORTFOLIO_SCHEMA = "lightbulb.product_portfolio.v1"
QUADRANTS: tuple[str, ...] = ("grow", "harvest", "fix", "cut", "new", "unmeasured")
FLAGS: tuple[str, ...] = ("overstocked", "stockout_risk", "return_problem", "unpriced", "uncosted", "no_stock_position")
ACTIONS: tuple[str, ...] = ("reorder", "run_down", "price_probe", "fix_returns", "discontinue", "hold", "price_and_cost")
Quadrant = Literal["grow", "harvest", "fix", "cut", "new", "unmeasured"]
Action = Literal["reorder", "run_down", "price_probe", "fix_returns", "discontinue", "hold", "price_and_cost"]
_HUNDRED = Decimal("100")
_RATE = Decimal("0.01")


class ProductPortfolioError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ProductPortfolioError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _rate(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_RATE, rounding=ROUND_HALF_UP)


class ProductPortfolioPlan(StrictModel):
    """The thresholds that place a SKU, sealed so every reader places it the same way."""

    schema_id: str = Field(default=PRODUCT_PORTFOLIO_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    growth_threshold_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    margin_threshold_percent: Decimal = Field(default=Decimal("30"), validate_default=True)
    overstock_days: int = Field(default=90, ge=1, le=3650)
    stockout_buffer_days: int = Field(default=7, ge=0, le=365)
    return_rate_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    minimum_units_to_judge: Decimal = Field(default=Decimal("5"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("growth_threshold_percent", "margin_threshold_percent", "return_rate_threshold_percent", "minimum_units_to_judge", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=info.field_name == "growth_threshold_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProductPortfolioPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ProductPortfolioPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_product_portfolio_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ProductPortfolioPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(ProductPortfolioPlan, raw, "plan_digest")


class PortfolioRow(StrictModel):
    sku_ref: OpaqueRef
    units_sold: Decimal
    previous_units: Decimal | None = None
    growth_percent: Decimal | None = None
    velocity_per_week: Decimal
    net_revenue: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    revenue_share_percent: Decimal
    return_rate_percent: Decimal | None = None
    on_hand: Decimal | None = None
    inbound: Decimal | None = None
    stock_value: Decimal | None = None
    lead_time_days: int | None = None
    days_of_cover: Decimal | None = None
    sell_through_percent: Decimal | None = None
    quadrant: Quadrant
    flags: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    action: Action
    rationale: ShortText

    @field_validator("flags", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("units_sold", "previous_units", "growth_percent", "velocity_per_week", "net_revenue", "contribution", "contribution_margin_percent", "revenue_share_percent", "return_rate_percent", "on_hand", "inbound", "stock_value", "days_of_cover", "sell_through_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ProductPortfolio(StrictModel):
    schema_id: str = Field(default=PRODUCT_PORTFOLIO_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest
    previous_report_digest: Sha256Digest | None = None
    window_days: int = Field(ge=1)
    rows: tuple[PortfolioRow, ...] = Field(min_length=0, max_length=5000)
    by_quadrant: dict[str, int] = Field(default_factory=dict)
    stock_value: Decimal
    contribution: Decimal
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    portfolio_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("stock_value", "contribution", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProductPortfolio":
        if sum(self.by_quadrant.values()) != len(self.rows):
            raise ValueError("every row sits in one quadrant")
        if not skip_digests(info) and self.portfolio_digest != sealed_digest(ProductPortfolio, self, "portfolio_digest"):
            raise ValueError("portfolio_digest must commit the exact portfolio")
        return self

    def row(self, sku_ref: str) -> PortfolioRow | None:
        return next((row for row in self.rows if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        lines = [f"**Product portfolio {self.company_ref}** as of {self.as_of[:10]}: {len(self.rows)} SKU(s), contribution {self.contribution} {self.currency}, stock at cost {self.stock_value}; " + ", ".join(f"{count} {quadrant}" for quadrant, count in self.by_quadrant.items() if count) + "."]
        for row in self.rows:
            cover = "n/a" if row.days_of_cover is None else f"{row.days_of_cover}d"
            lines.append(f"- {row.sku_ref} [{row.quadrant}] {row.action}: {row.rationale} (cover {cover}{'; ' + ', '.join(row.flags) if row.flags else ''})")
        return "\n".join(lines)


def _stock(inventory_states: Sequence[tuple[Any, Any]], *, company_ref: str, currency: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    out: dict[str, dict[str, Any]] = {}
    digests: list[str] = []
    for plan_doc, state_doc in inventory_states:
        plan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
        _require(plan.company_ref == company_ref and plan.currency == currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
        digests.append(state.state_digest)
        ledger = state.ledger
        if not ledger.sku_ref:
            continue
        row = out.setdefault(str(ledger.sku_ref), {"on_hand": Decimal("0"), "inbound": Decimal("0"), "stock_value": Decimal("0"), "lead_time_days": None})
        row["on_hand"] += Decimal(str(ledger.on_hand))
        row["inbound"] += Decimal(str(ledger.inbound))
        row["stock_value"] += Decimal(str(ledger.stock_value))
        policy = next((item for item in plan.policies if item.sku_ref == ledger.sku_ref and (ledger.location_ref is None or item.location_ref == ledger.location_ref)), None)
        lead = getattr(policy, "lead_time_days", None) if policy is not None else None
        if lead is not None:
            row["lead_time_days"] = max(int(lead), int(row["lead_time_days"] or 0))
    return out, digests


def build_product_portfolio(plan: ProductPortfolioPlan | Mapping[str, Any], *, margin_report: Mapping[str, Any] | Any, previous_report: Mapping[str, Any] | Any | None = None, inventory_states: Sequence[tuple[Any, Any]] = (), as_of: str) -> ProductPortfolio:
    """The sealed portfolio from a product margin report, optionally the previous window's report, and the replayed stock positions."""

    from lightbulb.product_margin import verify_product_margin

    parsed_plan = plan if isinstance(plan, ProductPortfolioPlan) else ProductPortfolioPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    report = verify_product_margin(margin_report)
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
    previous = None if previous_report is None else verify_product_margin(previous_report)
    if previous is not None:
        _require(previous.company_ref == report.company_ref and parsed(previous.window_end) <= parsed(report.window_start), "PREVIOUS_NOT_EARLIER", "the previous report must end before the current window starts")
    stock, digests = _stock(inventory_states, company_ref=parsed_plan.company_ref, currency=parsed_plan.currency)
    window_days = max(1, (parsed(report.window_end) - parsed(report.window_start)).days)
    prior = {} if previous is None else {row.sku_ref: row for row in previous.rows}
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {quadrant: 0 for quadrant in QUADRANTS}
    for item in report.rows:
        units = item.units_sold
        velocity = units / Decimal(window_days)
        weekly = (velocity * 7).quantize(_RATE, rounding=ROUND_HALF_UP)
        before = prior.get(item.sku_ref)
        growth = None
        if before is not None and before.units_sold > 0:
            growth = _rate((units - before.units_sold) / before.units_sold * _HUNDRED)
        position = stock.get(item.sku_ref)
        on_hand = inbound = value = cover = sell_through = None
        lead = None
        if position is not None:
            on_hand, inbound, value, lead = position["on_hand"], position["inbound"], position["stock_value"], position["lead_time_days"]
            available = on_hand + inbound
            cover = None if velocity <= 0 else (available / velocity).quantize(_RATE, rounding=ROUND_HALF_UP)
            sell_through = None if units + on_hand <= 0 else _rate(units / (units + on_hand) * _HUNDRED)
        flags: list[str] = []
        if not item.priced:
            flags.append("unpriced")
        if not item.costed:
            flags.append("uncosted")
        if position is None:
            flags.append("no_stock_position")
        if cover is not None and cover > parsed_plan.overstock_days:
            flags.append("overstocked")
        if cover is not None and lead is not None and cover < Decimal(lead + parsed_plan.stockout_buffer_days):
            flags.append("stockout_risk")
        if item.return_rate_percent is not None and item.return_rate_percent > parsed_plan.return_rate_threshold_percent and units >= parsed_plan.minimum_units_to_judge:
            flags.append("return_problem")
        margin = item.contribution_margin_percent
        if not item.priced or not item.costed or margin is None:
            quadrant = "unmeasured"
        elif previous is None or before is None:
            quadrant = "new"
        elif units < parsed_plan.minimum_units_to_judge and before.units_sold < parsed_plan.minimum_units_to_judge:
            quadrant = "unmeasured"
        else:
            growing = growth is not None and growth >= parsed_plan.growth_threshold_percent
            earning = margin >= parsed_plan.margin_threshold_percent
            quadrant = "grow" if growing and earning else "harvest" if earning else "fix" if growing else "cut"
        counts[quadrant] += 1
        if "unpriced" in flags or "uncosted" in flags:
            action, rationale = "price_and_cost", f"{'no published price' if not item.priced else 'no landed cost'}; margin cannot be judged until the {'catalog prices it' if not item.priced else 'stock position costs it'}"
        elif "return_problem" in flags:
            action, rationale = "fix_returns", f"{item.return_rate_percent}% of units come back against a {parsed_plan.return_rate_threshold_percent}% threshold; contribution {item.contribution}"
        elif quadrant == "cut" and "overstocked" in flags:
            action, rationale = "discontinue", f"margin {margin}% and growth {growth}% both below threshold with {cover} days of cover"
        elif "stockout_risk" in flags and quadrant in ("grow", "harvest", "new"):
            action, rationale = "reorder", f"{cover} days of cover against a {lead}-day lead time plus {parsed_plan.stockout_buffer_days}-day buffer at {weekly} units a week"
        elif "overstocked" in flags:
            action, rationale = "run_down", f"{cover} days of cover against the {parsed_plan.overstock_days}-day threshold; sell down before reordering"
        elif quadrant == "fix":
            action, rationale = "price_probe", f"growing {growth}% but margin {margin}% is below the {parsed_plan.margin_threshold_percent}% threshold; plan a margin-guarded price move"
        elif quadrant == "cut":
            action, rationale = "discontinue", f"margin {margin}% and growth {growth}% both below threshold"
        else:
            action, rationale = "hold", f"margin {margin}%" + (f", growth {growth}%" if growth is not None else "") + f", {units} unit(s) sold"
        rows.append({"sku_ref": item.sku_ref, "units_sold": str(units), "previous_units": None if before is None else str(before.units_sold), "growth_percent": None if growth is None else str(growth), "velocity_per_week": str(weekly), "net_revenue": str(item.net_revenue), "contribution": str(item.contribution), "contribution_margin_percent": None if margin is None else str(margin), "revenue_share_percent": str(item.revenue_share_percent), "return_rate_percent": None if item.return_rate_percent is None else str(item.return_rate_percent), "on_hand": None if on_hand is None else str(on_hand), "inbound": None if inbound is None else str(inbound), "stock_value": None if value is None else str(_money(value)), "lead_time_days": lead, "days_of_cover": None if cover is None else str(cover), "sell_through_percent": None if sell_through is None else str(sell_through), "quadrant": quadrant, "flags": flags, "action": action, "rationale": rationale[:200]})
    rows.sort(key=lambda row: (-Decimal(row["contribution"]), row["sku_ref"]))
    recommendations = [f"{row['sku_ref']}: {row['action']}; {row['rationale']}" for row in rows if row["action"] != "hold"][:24]
    if not recommendations:
        recommendations.append("every SKU holds: margins and cover are inside the thresholds")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report.report_digest, "previous_report_digest": None if previous is None else previous.report_digest,
        "window_days": window_days, "rows": rows, "by_quadrant": {quadrant: count for quadrant, count in counts.items() if count}, "stock_value": str(_money(sum((Decimal(row["stock_value"]) for row in rows if row["stock_value"] is not None), Decimal("0")))), "contribution": str(report.contribution),
        "recommendations": [item[:200] for item in recommendations], "source_digests": [report.report_digest, *([previous.report_digest] if previous else []), *digests],
    }
    return seal(ProductPortfolio, payload, "portfolio_digest")


def verify_product_portfolio(value: Any) -> ProductPortfolio:
    return value if isinstance(value, ProductPortfolio) else ProductPortfolio.model_validate(dict(detached(value)))


PRODUCT_PORTFOLIO_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "product_portfolio",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["verify_margin_reports", "replay_stock", "measure_velocity_and_cover", "place_in_quadrant", "recommend", "seal_portfolio"],
    "quadrants": list(QUADRANTS),
    "flags": list(FLAGS),
    "actions": list(ACTIONS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "growth and margin come from two sealed margin reports; nothing predicts demand",
        "days of cover is on hand plus inbound over the window's velocity; the lead time is the stock policy's",
        "a SKU without a price or a landed cost is unmeasured and its action is to price and cost it, never to guess",
        "every recommendation names the number behind it",
    ],
}

__all__ = ["ACTIONS", "FLAGS", "PRODUCT_PORTFOLIO_MANIFEST", "PRODUCT_PORTFOLIO_PLAN_SCHEMA", "PRODUCT_PORTFOLIO_SCHEMA", "QUADRANTS", "PortfolioRow", "ProductPortfolio", "ProductPortfolioError", "ProductPortfolioPlan", "build_product_portfolio", "compile_product_portfolio_plan", "verify_product_portfolio"]
