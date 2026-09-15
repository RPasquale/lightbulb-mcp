"""Price probes: for every priced and costed SKU, what each price move does to unit contribution and how much volume it can afford to lose.

The portfolio says which SKUs want a price probe; the growth engine plans
a margin-guarded move as a preregistered test and the catalog approves
the version.  Between them sits the arithmetic this module seals from the
product margin report alone:

* the realised price (net revenue over units, so discounts and returns
  are already in it), the unit cost of goods, the fee rate, the unit
  fulfilment and return-handling cost, and the unit contribution;
* for each candidate move, the new price, the new unit contribution (fees
  scale with price, the rest does not), the margin after the move, and
  the break-even volume change: how far volume may fall before an
  increase stops paying, or how far it must rise before a decrease does;
* the floor price under which the plan's minimum margin is gone;
* one recommendation per SKU: probe the largest increase whose break-even
  volume loss sits inside the plan's tolerance, reprice to the floor when
  the SKU is already under the minimum margin, or hold.

Nothing here estimates elasticity or predicts demand: every number is a
break-even, and the operator decides which probe to run.
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
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.product_margin import verify_product_margin

PRICE_PROBE_PLAN_SCHEMA = "lightbulb.price_probe_plan.v1"
PRICE_PROBES_SCHEMA = "lightbulb.price_probes.v1"
PROBE_ACTIONS: tuple[str, ...] = ("probe", "reprice_to_floor", "hold", "unmeasured")
ProbeAction = Literal["probe", "reprice_to_floor", "hold", "unmeasured"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class PriceProbeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PriceProbeError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class PriceProbePlan(StrictModel):
    schema_id: str = Field(default=PRICE_PROBE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    minimum_margin_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    maximum_breakeven_volume_loss_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    moves_percent: tuple[Decimal, ...] = Field(default=(Decimal("-10"), Decimal("-5"), Decimal("5"), Decimal("10"), Decimal("15"), Decimal("20")), validate_default=True, min_length=1, max_length=12)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("minimum_margin_percent", "maximum_breakeven_volume_loss_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result >= _HUNDRED:
            raise ValueError(f"{info.field_name} is below 100")
        return result

    @field_validator("moves_percent", mode="before")
    @classmethod
    def _moves(cls, value: object) -> object:
        if isinstance(value, (list, tuple)):
            moves = tuple(decimal_value(item, field_name="moves_percent", allow_negative=True) for item in value)
            if any(move == 0 or move <= Decimal("-100") for move in moves) or len(set(moves)) != len(moves):
                raise ValueError("moves are distinct, non-zero, and above -100")
            return tuple(sorted(moves))
        return value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PriceProbePlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(PriceProbePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_price_probe_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PriceProbePlan:
    return seal(PriceProbePlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class PriceMove(StrictModel):
    move_percent: Decimal
    ratio: Decimal
    price: Decimal
    unit_contribution: Decimal
    margin_percent: Decimal | None = None
    breakeven_volume_change_percent: Decimal | None = None
    allowed: bool
    note: ShortText

    @field_validator("move_percent", "ratio", "price", "unit_contribution", "margin_percent", "breakeven_volume_change_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class SkuProbe(StrictModel):
    sku_ref: OpaqueRef
    units_sold: Decimal
    list_price: Decimal | None = None
    realised_price: Decimal
    unit_cost_of_goods: Decimal
    unit_fulfilment: Decimal
    unit_return_handling: Decimal
    fee_rate_percent: Decimal
    unit_contribution: Decimal
    margin_percent: Decimal | None = None
    floor_price: Decimal
    moves: tuple[PriceMove, ...] = Field(default_factory=tuple, max_length=12)
    action: ProbeAction
    recommended_move_percent: Decimal | None = None
    rationale: ShortText

    @field_validator("moves", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("units_sold", "list_price", "realised_price", "unit_cost_of_goods", "unit_fulfilment", "unit_return_handling", "fee_rate_percent", "unit_contribution", "margin_percent", "floor_price", "recommended_move_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class PriceProbes(StrictModel):
    schema_id: str = Field(default=PRICE_PROBES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest
    portfolio_digest: Sha256Digest | None = None
    skus: tuple[SkuProbe, ...] = Field(default_factory=tuple, max_length=5000)
    by_action: dict[str, int] = Field(default_factory=dict)
    recommended_moves: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=5000)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=10)
    probes_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("skus", "recommended_moves", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PriceProbes":
        if sum(self.by_action.values()) != len(self.skus):
            raise ValueError("every SKU is counted once by action")
        if not skip_digests(info) and self.probes_digest != sealed_digest(PriceProbes, self, "probes_digest"):
            raise ValueError("probes_digest must commit the exact document")
        return self

    def sku(self, sku_ref: str) -> SkuProbe | None:
        return next((row for row in self.skus if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        lines = [f"**Price probes {self.company_ref}** as of {self.as_of[:10]}: {len(self.skus)} SKU(s); " + ", ".join(f"{count} {action}" for action, count in self.by_action.items() if count) + "."]
        for row in self.skus:
            lines.append(f"- {row.sku_ref} [{row.action}]: {row.rationale}")
        return "\n".join(lines)


def plan_price_probes(plan: PriceProbePlan | Mapping[str, Any], *, margin_report: Mapping[str, Any] | Any, portfolio: Mapping[str, Any] | Any | None = None, as_of: str) -> PriceProbes:
    """The sealed probe table from a product margin report and, optionally, the portfolio whose actions ask for probes."""

    parsed_plan = plan if isinstance(plan, PriceProbePlan) else PriceProbePlan.model_validate(detached(plan))
    report = verify_product_margin(margin_report)
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
    asked: dict[str, str] = {}
    portfolio_digest = None
    if portfolio is not None:
        from lightbulb.product_portfolio import verify_product_portfolio

        parsed_portfolio = verify_product_portfolio(portfolio)
        _require(parsed_portfolio.margin_report_digest == report.report_digest, "PORTFOLIO_NOT_BOUND", "the portfolio was built from another margin report")
        portfolio_digest = parsed_portfolio.portfolio_digest
        asked = {row.sku_ref: row.action for row in parsed_portfolio.rows}
    at = timestamp(as_of, field_name="as_of")
    fee_rate = Decimal(str(report.fee_rate_percent))
    minimum = parsed_plan.minimum_margin_percent
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    recommended: list[dict[str, Any]] = []
    for item in report.rows:
        units = Decimal(str(item.units_sold))
        if not item.priced or not item.costed or units <= 0:
            counts["unmeasured"] = counts.get("unmeasured", 0) + 1
            rows.append({"sku_ref": item.sku_ref, "units_sold": str(units), "list_price": None if getattr(item, "list_price", None) is None else str(item.list_price), "realised_price": "0", "unit_cost_of_goods": "0", "unit_fulfilment": "0", "unit_return_handling": "0", "fee_rate_percent": str(fee_rate), "unit_contribution": "0", "margin_percent": None, "floor_price": "0", "moves": [], "action": "unmeasured", "recommended_move_percent": None, "rationale": ("no published price" if not item.priced else "no landed cost" if not item.costed else "no units sold") + "; a probe needs a price, a cost, and volume"})
            continue
        price = _money(Decimal(str(item.net_revenue)) / units)
        unit_cogs = _money(Decimal(str(item.cost_of_goods)) / units)
        unit_fulfilment = _money(Decimal(str(item.fulfilment_cost)) / units)
        unit_returns = _money(Decimal(str(item.return_handling)) / units)
        fixed_unit = unit_cogs + unit_fulfilment + unit_returns
        contribution = _money(price * (Decimal("1") - fee_rate / _HUNDRED) - fixed_unit)
        margin = None if price <= 0 else _pct(contribution / price * _HUNDRED)
        denominator = Decimal("1") - fee_rate / _HUNDRED - minimum / _HUNDRED
        floor = _money(fixed_unit / denominator) if denominator > 0 else _money(fixed_unit)
        moves: list[dict[str, Any]] = []
        for move in parsed_plan.moves_percent:
            ratio = (Decimal("1") + move / _HUNDRED)
            new_price = _money(price * ratio)
            new_contribution = _money(new_price * (Decimal("1") - fee_rate / _HUNDRED) - fixed_unit)
            new_margin = None if new_price <= 0 else _pct(new_contribution / new_price * _HUNDRED)
            breakeven = None if new_contribution <= 0 or contribution <= 0 else _pct((contribution / new_contribution - Decimal("1")) * _HUNDRED)
            allowed = new_contribution > 0 and new_margin is not None and new_margin >= minimum and new_price >= floor
            if new_contribution <= 0:
                note = f"{new_price} does not cover the {fixed_unit} unit cost plus fees"
            elif not allowed:
                note = f"{new_price} leaves {new_margin}% margin, under the {minimum}% minimum (floor {floor})"
            elif move > 0:
                note = f"{new_price} earns {new_contribution} a unit; volume may fall {abs(breakeven) if breakeven is not None else 'n/a'}% before it stops paying"
            else:
                note = f"{new_price} earns {new_contribution} a unit; volume must rise {abs(breakeven) if breakeven is not None else 'n/a'}% to pay for the cut"
            moves.append({"move_percent": str(move), "ratio": str(_pct(ratio)), "price": str(new_price), "unit_contribution": str(new_contribution), "margin_percent": None if new_margin is None else str(new_margin), "breakeven_volume_change_percent": None if breakeven is None else str(breakeven), "allowed": allowed, "note": note[:300]})
        wanted = asked.get(item.sku_ref) in (None, "price_probe", "hold") if portfolio is None else asked.get(item.sku_ref) == "price_probe"
        increases = [move for move in moves if Decimal(move["move_percent"]) > 0 and move["allowed"] and move["breakeven_volume_change_percent"] is not None and abs(Decimal(move["breakeven_volume_change_percent"])) <= parsed_plan.maximum_breakeven_volume_loss_percent]
        if margin is not None and margin < minimum:
            action, chosen = "reprice_to_floor", None
            rationale = f"margin {margin}% is under the {minimum}% minimum at {price}; the floor is {floor}" + (f" ({_pct((floor / price - 1) * _HUNDRED)}% up)" if price > 0 else "")
            recommended.append({"sku_ref": item.sku_ref, "kind": "reprice_to_floor", "target_price": str(floor), "ratio": str(_pct(floor / price)) if price > 0 else None, "move_percent": str(_pct((floor / price - 1) * _HUNDRED)) if price > 0 else None})
        elif wanted and increases:
            best = max(increases, key=lambda move: Decimal(move["move_percent"]))
            action, chosen = "probe", Decimal(best["move_percent"])
            rationale = f"probe {best['move_percent']}% to {best['price']}: unit contribution {contribution} to {best['unit_contribution']}, break-even volume loss {abs(Decimal(best['breakeven_volume_change_percent']))}% inside the {parsed_plan.maximum_breakeven_volume_loss_percent}% tolerance"
            recommended.append({"sku_ref": item.sku_ref, "kind": "probe", "target_price": best["price"], "ratio": best["ratio"], "move_percent": best["move_percent"], "breakeven_volume_change_percent": best["breakeven_volume_change_percent"]})
        elif wanted:
            action, chosen = "hold", None
            rationale = f"no increase keeps the break-even volume loss inside {parsed_plan.maximum_breakeven_volume_loss_percent}%; margin {margin}% at {price}"
        else:
            action, chosen = "hold", None
            rationale = f"the portfolio asks for {asked.get(item.sku_ref)}, not a price probe; margin {margin}% at {price}"
        counts[action] = counts.get(action, 0) + 1
        rows.append({"sku_ref": item.sku_ref, "units_sold": str(units), "list_price": None if getattr(item, "list_price", None) is None else str(item.list_price), "realised_price": str(price), "unit_cost_of_goods": str(unit_cogs), "unit_fulfilment": str(unit_fulfilment), "unit_return_handling": str(unit_returns), "fee_rate_percent": str(fee_rate), "unit_contribution": str(contribution), "margin_percent": None if margin is None else str(margin), "floor_price": str(floor), "moves": moves, "action": action, "recommended_move_percent": None if chosen is None else str(chosen), "rationale": rationale[:300]})
    recommendations = [f"{row['sku_ref']}: {row['rationale']}" for row in rows if row["action"] in ("probe", "reprice_to_floor")][:24]
    if not recommendations:
        recommendations.append("no SKU asks for a price move inside the plan's guardrails")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report.report_digest, "portfolio_digest": portfolio_digest, "skus": rows, "by_action": counts, "recommended_moves": recommended, "recommendations": [item[:300] for item in recommendations], "source_digests": [report.report_digest, *([portfolio_digest] if portfolio_digest else [])]}
    return seal(PriceProbes, payload, "probes_digest")


def verify_price_probes(value: Any) -> PriceProbes:
    return value if isinstance(value, PriceProbes) else PriceProbes.model_validate(dict(detached(value)))


PRICE_PROBES_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "price_probes",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["verify_margin_report", "unit_economics_per_sku", "price_each_move", "break_even_volume", "guard_by_floor_and_tolerance", "seal_probes"],
    "actions": list(PROBE_ACTIONS),
    "hand_off": "recommended_moves feed growth_profit.plan_price_move (ratio per SKU) and then price_catalog.draft_from_price_plan; nothing here dispatches a price",
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the realised price is net revenue over units, so discounts and returns are already inside it",
        "fees scale with price; cost of goods, fulfilment, and return handling do not",
        "every number is a break-even; nothing estimates elasticity or predicts demand",
        "a move under the floor price or the minimum margin is never recommended",
    ],
}

__all__ = ["PRICE_PROBES_MANIFEST", "PRICE_PROBES_SCHEMA", "PRICE_PROBE_PLAN_SCHEMA", "PROBE_ACTIONS", "PriceMove", "PriceProbeError", "PriceProbePlan", "PriceProbes", "SkuProbe", "compile_price_probe_plan", "plan_price_probes", "verify_price_probes"]
