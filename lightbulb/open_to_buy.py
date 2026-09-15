"""Open to buy: how much of each SKU to order now, from the portfolio's velocity and cover, inside the cash the envelope allows.

The portfolio says reorder or run down; the inventory chain's reorder
point is a static policy.  ``build_open_to_buy`` sizes the buy the way a
merchandiser does, from sealed documents only:

* per SKU the demand over the lead time plus the target cover (velocity
  a week from the portfolio, the stock policy's lead time), less what is
  on hand and inbound: the units to order and their cost at the landed
  unit cost the portfolio carries (or the margin report's when the
  position has none);
* a priority: contribution per unit from the margin report, so the cash
  buys the units that earn the most first;
* the budget: the cash envelope's one-time discretionary capacity when
  one is supplied, capped by the plan's maximum spend; SKUs are funded
  in priority order and the rest are deferred with the shortfall named;
* what the run-down, discontinue, and unmeasured SKUs are not bought,
  and why.

Nothing here forecasts demand beyond the window's velocity, reads a
provider, commits a purchase, or persists anything; the funded lines are
shaped for the inventory chain's own reorder proposal.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.product_margin import verify_product_margin
from lightbulb.product_portfolio import verify_product_portfolio

OPEN_TO_BUY_PLAN_SCHEMA = "lightbulb.open_to_buy_plan.v1"
OPEN_TO_BUY_SCHEMA = "lightbulb.open_to_buy.v1"
BUY_DECISIONS: tuple[str, ...] = ("fund", "defer", "covered", "run_down", "discontinue", "unmeasured")
BuyDecision = Literal["fund", "defer", "covered", "run_down", "discontinue", "unmeasured"]
_HUNDRED = Decimal("100")
_QTY = Decimal("0.01")


class OpenToBuyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OpenToBuyError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class OpenToBuyPlan(StrictModel):
    schema_id: str = Field(default=OPEN_TO_BUY_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    target_cover_days: int = Field(default=60, ge=1, le=730)
    default_lead_time_days: int = Field(default=14, ge=0, le=365)
    maximum_spend: Decimal | None = None
    minimum_order_units: Decimal = Field(default=Decimal("1"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("maximum_spend", "minimum_order_units", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OpenToBuyPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(OpenToBuyPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_open_to_buy_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> OpenToBuyPlan:
    return seal(OpenToBuyPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class BuyLine(StrictModel):
    sku_ref: OpaqueRef
    decision: BuyDecision
    priority: int = Field(ge=1)
    velocity_per_week: Decimal
    lead_time_days: int = Field(ge=0)
    on_hand: Decimal
    inbound: Decimal
    demand_units: Decimal
    order_units: Decimal
    unit_cost: Decimal | None = None
    order_cost: Decimal
    funded_units: Decimal
    funded_cost: Decimal
    contribution_per_unit: Decimal | None = None
    days_of_cover_after: Decimal | None = None
    rationale: ShortText

    @field_validator("velocity_per_week", "on_hand", "inbound", "demand_units", "order_units", "unit_cost", "order_cost", "funded_units", "funded_cost", "contribution_per_unit", "days_of_cover_after", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class OpenToBuy(StrictModel):
    schema_id: str = Field(default=OPEN_TO_BUY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    portfolio_digest: Sha256Digest
    margin_report_digest: Sha256Digest
    envelope_ref: OpaqueRef | None = None
    budget: Decimal | None = None
    lines: tuple[BuyLine, ...] = Field(default_factory=tuple, max_length=5000)
    requested_cost: Decimal
    funded_cost: Decimal
    deferred_cost: Decimal
    by_decision: dict[str, int] = Field(default_factory=dict)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=10)
    buy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("budget", "requested_cost", "funded_cost", "deferred_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OpenToBuy":
        if sum(self.by_decision.values()) != len(self.lines) or self.funded_cost + self.deferred_cost != self.requested_cost:
            raise ValueError("every line is counted once and funded plus deferred is the request")
        if not skip_digests(info) and self.buy_digest != sealed_digest(OpenToBuy, self, "buy_digest"):
            raise ValueError("buy_digest must commit the exact document")
        return self

    def line(self, sku_ref: str) -> BuyLine | None:
        return next((row for row in self.lines if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        lines = [f"**Open to buy {self.company_ref}** as of {self.as_of[:10]}: {self.requested_cost} {self.currency} requested, {self.funded_cost} funded" + (f" inside a {self.budget} budget" if self.budget is not None else "") + f", {self.deferred_cost} deferred; " + ", ".join(f"{count} {decision}" for decision, count in self.by_decision.items() if count) + "."]
        for row in self.lines:
            lines.append(f"- #{row.priority} {row.sku_ref} [{row.decision}]: {row.rationale}")
        return "\n".join(lines)


def build_open_to_buy(plan: OpenToBuyPlan | Mapping[str, Any], *, portfolio: Mapping[str, Any] | Any, margin_report: Mapping[str, Any] | Any, budget_envelope: Mapping[str, Any] | None = None, as_of: str) -> OpenToBuy:
    """The sealed buy list: units per SKU to reach the target cover over the lead time, funded in contribution order inside the envelope's one-time capacity."""

    parsed_plan = plan if isinstance(plan, OpenToBuyPlan) else OpenToBuyPlan.model_validate(detached(plan))
    parsed_portfolio = verify_product_portfolio(portfolio)
    report = verify_product_margin(margin_report)
    _require(parsed_portfolio.company_ref == parsed_plan.company_ref and parsed_portfolio.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the portfolio names another company or currency")
    _require(parsed_portfolio.margin_report_digest == report.report_digest, "PORTFOLIO_NOT_BOUND", "the portfolio was built from another margin report")
    at = timestamp(as_of, field_name="as_of")
    budget: Decimal | None = None
    envelope_ref = None
    if budget_envelope is not None:
        from lightbulb.cash_runway import CashBudgetEnvelope

        envelope = CashBudgetEnvelope.model_validate(detached(budget_envelope))
        _require(envelope.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the envelope is in another currency")
        envelope_ref = envelope.envelope_ref
        capacity = getattr(envelope, "one_time_discretionary_capacity", None)
        budget = None if capacity is None else _money(capacity)
    if parsed_plan.maximum_spend is not None:
        budget = _money(parsed_plan.maximum_spend) if budget is None else min(budget, _money(parsed_plan.maximum_spend))
    unit_cogs = {row.sku_ref: Decimal(str(row.cost_of_goods)) / Decimal(str(row.units_sold)) if Decimal(str(row.units_sold)) > 0 and row.costed else None for row in report.rows}
    contribution = {row.sku_ref: row.contribution_per_unit for row in report.rows}
    rows: list[dict[str, Any]] = []
    for item in parsed_portfolio.rows:
        velocity = Decimal(str(item.velocity_per_week))
        lead = int(item.lead_time_days) if item.lead_time_days is not None else parsed_plan.default_lead_time_days
        on_hand = Decimal(str(item.on_hand)) if item.on_hand is not None else Decimal("0")
        inbound = Decimal(str(item.inbound)) if item.inbound is not None else Decimal("0")
        unit_cost = None
        if item.stock_value is not None and on_hand > 0:
            unit_cost = _money(Decimal(str(item.stock_value)) / on_hand)
        elif unit_cogs.get(item.sku_ref) is not None:
            unit_cost = _money(unit_cogs[item.sku_ref])
        demand = (velocity / Decimal(7) * Decimal(lead + parsed_plan.target_cover_days)).quantize(_QTY, rounding=ROUND_HALF_UP)
        order = max(demand - on_hand - inbound, Decimal("0")).quantize(_QTY, rounding=ROUND_HALF_UP)
        per_unit = contribution.get(item.sku_ref)
        if item.action in ("run_down", "discontinue"):
            decision, order = item.action, Decimal("0")
            rationale = f"the portfolio says {item.action}: {item.rationale}"
        elif unit_cost is None or "unpriced" in item.flags:
            decision, order = "unmeasured", Decimal("0")
            rationale = "no landed cost or no price; size nothing until the SKU is costed and priced"
        elif order < parsed_plan.minimum_order_units:
            decision, order = "covered", Decimal("0")
            rationale = f"{on_hand + inbound} on hand and inbound covers {demand} units of demand over {lead} days of lead time plus {parsed_plan.target_cover_days} days of cover"
        else:
            decision = "fund"
            rationale = f"order {order} units: demand {demand} over {lead} days of lead time plus {parsed_plan.target_cover_days} days of cover, less {on_hand} on hand and {inbound} inbound, at {unit_cost} a unit"
        rows.append({"sku_ref": item.sku_ref, "decision": decision, "velocity_per_week": str(velocity), "lead_time_days": lead, "on_hand": str(on_hand), "inbound": str(inbound), "demand_units": str(demand), "order_units": str(order), "unit_cost": None if unit_cost is None else str(unit_cost), "order_cost": str(_money(order * unit_cost)) if unit_cost is not None else "0", "funded_units": "0", "funded_cost": "0", "contribution_per_unit": None if per_unit is None else str(per_unit), "days_of_cover_after": None, "rationale": rationale[:300]})
    rows.sort(key=lambda row: (row["decision"] != "fund", -(Decimal(row["contribution_per_unit"]) if row["contribution_per_unit"] is not None else Decimal("-999999")), row["sku_ref"]))
    remaining = budget
    for index, row in enumerate(rows, start=1):
        row["priority"] = index
        if row["decision"] != "fund":
            continue
        cost = Decimal(row["order_cost"])
        unit_cost = Decimal(row["unit_cost"])
        if remaining is None or cost <= remaining:
            row["funded_units"], row["funded_cost"] = row["order_units"], str(cost)
            if remaining is not None:
                remaining -= cost
        else:
            units = (remaining / unit_cost).quantize(_QTY, rounding=ROUND_HALF_UP) if unit_cost > 0 else Decimal("0")
            if units < parsed_plan.minimum_order_units:
                row["decision"] = "defer"
                row["rationale"] = f"deferred: {cost} needed and {remaining} left in the budget; " + row["rationale"]
            else:
                row["funded_units"], row["funded_cost"] = str(units), str(_money(units * unit_cost))
                row["rationale"] = f"funded {units} of {row['order_units']} units inside the budget; " + row["rationale"]
                remaining -= _money(units * unit_cost)
        velocity = Decimal(row["velocity_per_week"])
        after = Decimal(row["on_hand"]) + Decimal(row["inbound"]) + Decimal(row["funded_units"])
        row["days_of_cover_after"] = None if velocity <= 0 else str((after / velocity * 7).quantize(_QTY, rounding=ROUND_HALF_UP))
    requested = _money(sum((Decimal(row["order_cost"]) for row in rows if row["decision"] in ("fund", "defer")), Decimal("0")))
    funded = _money(sum((Decimal(row["funded_cost"]) for row in rows), Decimal("0")))
    counts = {decision: sum(1 for row in rows if row["decision"] == decision) for decision in BUY_DECISIONS if any(row["decision"] == decision for row in rows)}
    recommendations = [f"{row['sku_ref']}: {row['decision']} {row['funded_units']} unit(s) for {row['funded_cost']}" for row in rows if row["decision"] == "fund"][:12]
    recommendations += [f"{row['sku_ref']}: {row['rationale']}" for row in rows if row["decision"] == "defer"][:8]
    if not recommendations:
        recommendations.append("nothing to buy: every priced and costed SKU is covered or told to run down")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "portfolio_digest": parsed_portfolio.portfolio_digest, "margin_report_digest": report.report_digest, "envelope_ref": envelope_ref, "budget": None if budget is None else str(budget), "lines": rows, "requested_cost": str(requested), "funded_cost": str(funded), "deferred_cost": str(_money(requested - funded)), "by_decision": counts, "recommendations": [item[:300] for item in recommendations], "source_digests": [parsed_portfolio.portfolio_digest, report.report_digest]}
    return seal(OpenToBuy, payload, "buy_digest")


def verify_open_to_buy(value: Any) -> OpenToBuy:
    return value if isinstance(value, OpenToBuy) else OpenToBuy.model_validate(dict(detached(value)))


OPEN_TO_BUY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "open_to_buy",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["verify_portfolio_and_report", "demand_over_lead_and_cover", "units_to_order_at_landed_cost", "fund_by_contribution_inside_the_envelope", "seal_buy_list"],
    "decisions": list(BUY_DECISIONS),
    "hand_off": "funded lines feed inventory_chain.reorder_proposal and commit_purchase; nothing here commits a purchase",
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "demand is the portfolio's velocity over the policy's lead time plus the target cover; nothing forecasts beyond it",
        "the budget is the cash envelope's one-time discretionary capacity capped by the plan's maximum spend; SKUs are funded in contribution-per-unit order",
        "a SKU the portfolio says to run down or discontinue is never bought; an unpriced or uncosted SKU is never sized",
    ],
}

__all__ = ["BUY_DECISIONS", "OPEN_TO_BUY_MANIFEST", "OPEN_TO_BUY_PLAN_SCHEMA", "OPEN_TO_BUY_SCHEMA", "BuyLine", "OpenToBuy", "OpenToBuyError", "OpenToBuyPlan", "build_open_to_buy", "compile_open_to_buy_plan", "verify_open_to_buy"]
