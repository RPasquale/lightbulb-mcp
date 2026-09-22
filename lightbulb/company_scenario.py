"""What-if: the exact consequence of a decision, from the books, with every assumption shown.

Every intelligence document so far describes a past window.  An owner
deciding whether to raise prices, hire, or take on a big customer needs the
same arithmetic pointed forward.  ``run_scenario`` takes a baseline (the
books snapshot for a window) and a list of levers, applies them in order,
and seals the result: the profit and loss ladder after the change, the
break-even and margin of safety after it, and the change in each against
the baseline.  Elasticity, ramp and utilisation are explicit inputs echoed
in the document; a price lever is shown at three elasticities so the owner
sees how much the answer depends on the guess.  Nothing is forecast in the
fortune-telling sense: this is what the baseline arithmetic gives under
the stated changes, and it says so.

Levers: ``price`` (percent change, with elasticity), ``volume`` (percent
change in units at constant price), ``hire`` (an employee: annual cost,
on-costs, ramp months, the billable share and rate when the hire earns
revenue), ``contractor`` (hours and rate, with the revenue those hours
bill), ``customer`` (a customer won or lost: annual revenue and its
variable share), ``cost_line`` (a fixed cost added or removed), and
``payment_terms`` (a change to receivable days, which moves cash and not
profit).  ``compare_scenarios`` lines several up.  A decision recorded in
the review may cite a scenario digest, so the outcomes can later say
whether the arithmetic was borne out.  Nothing here reads a provider or
persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, timestamp

SCENARIO_SCHEMA = "lightbulb.company_scenario.v1"
SCENARIO_COMPARISON_SCHEMA = "lightbulb.company_scenario_comparison.v1"
SCENARIO_MANIFEST: dict[str, Any] = {"engine": "company_scenario", "kind": "intelligence_document", "reads": ("books_snapshot",), "writes": ()}
LEVER_KINDS: tuple[str, ...] = ("price", "volume", "hire", "contractor", "customer", "cost_line", "payment_terms")
LeverKind = Literal["price", "volume", "hire", "contractor", "customer", "cost_line", "payment_terms"]
ELASTICITIES: tuple[Decimal, ...] = (Decimal("-0.5"), Decimal("-1.0"), Decimal("-1.5"))
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")
_DAYS = Decimal("0.1")


class ScenarioError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ScenarioError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class Lever(StrictModel):
    kind: LeverKind
    label: ShortText
    percent: Decimal | None = None
    elasticity: Decimal | None = None
    annual_cost: Decimal | None = None
    on_cost_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    ramp_months: int = Field(default=0, ge=0, le=24)
    billable_share_percent: Decimal | None = None
    bill_rate: Decimal | None = None
    hours: Decimal | None = None
    rate: Decimal | None = None
    annual_revenue: Decimal | None = None
    variable_share_percent: Decimal | None = None
    amount: Decimal | None = None
    receivable_days: int | None = Field(default=None, ge=0, le=365)

    @field_validator("percent", "elasticity", "annual_cost", "on_cost_percent", "billable_share_percent", "bill_rate", "hours", "rate", "annual_revenue", "variable_share_percent", "amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self) -> "Lever":
        need = {"price": ("percent",), "volume": ("percent",), "hire": ("annual_cost",), "contractor": ("hours", "rate"), "customer": ("annual_revenue",), "cost_line": ("amount",), "payment_terms": ("receivable_days",)}[self.kind]
        for field in need:
            if getattr(self, field) is None:
                raise ValueError(f"LEVER_INCOMPLETE: a {self.kind} lever needs {field}")
        return self


class Ladder(StrictModel):
    revenue: Decimal
    variable_costs: Decimal
    contribution: Decimal
    fixed_costs: Decimal
    operating_result: Decimal
    contribution_margin_percent: Decimal | None = None
    break_even_revenue: Decimal | None = None
    margin_of_safety_percent: Decimal | None = None
    receivables: Decimal | None = None
    receivable_days: Decimal | None = None

    @field_validator("revenue", "variable_costs", "contribution", "fixed_costs", "operating_result", "contribution_margin_percent", "break_even_revenue", "margin_of_safety_percent", "receivables", "receivable_days", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class LeverEffect(StrictModel):
    lever: Lever
    revenue_change: Decimal
    variable_cost_change: Decimal
    fixed_cost_change: Decimal
    cash_change: Decimal
    note: ShortText

    @field_validator("revenue_change", "variable_cost_change", "fixed_cost_change", "cash_change", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class Scenario(StrictModel):
    schema_id: str = Field(default=SCENARIO_SCHEMA, alias="schema")
    scenario_ref: OpaqueRef
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    books_digest: Sha256Digest
    window_start: str
    window_end: str
    days_in_window: int = Field(ge=1)
    baseline: Ladder
    after: Ladder
    effects: tuple[LeverEffect, ...] = Field(max_length=12)
    operating_result_change: Decimal
    break_even_change: Decimal | None = None
    cash_change: Decimal
    payback_months: Decimal | None = None
    sensitivity: dict[str, Decimal] = Field(default_factory=dict)
    assumptions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    scenario_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("effects", "assumptions", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("operating_result_change", "break_even_change", "cash_change", "payback_months", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("sensitivity", mode="before")
    @classmethod
    def _sens(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="sensitivity", allow_negative=True) for key, item in dict(value or {}).items()}

    @field_validator("as_of", "window_start", "window_end")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "Scenario":
        if self.operating_result_change != _money(self.after.operating_result - self.baseline.operating_result):
            raise ValueError("operating_result_change is after less baseline")
        if self.after.contribution != _money(self.after.revenue - self.after.variable_costs) or self.after.operating_result != _money(self.after.contribution - self.after.fixed_costs):
            raise ValueError("the ladder after the change must foot")
        if not skip_digests(info) and self.scenario_digest != sealed_digest(Scenario, self, "scenario_digest"):
            raise ValueError("scenario_digest must commit the exact scenario")
        return self

    def render(self) -> str:
        lines = [f"**What if: {self.scenario_ref}** ({self.company_ref}, over {self.days_in_window} days from the books): {self.verdict}"]
        lines.extend(f"- {effect.lever.label}: {effect.note}" for effect in self.effects)
        lines.extend(f"- assumed: {item}" for item in self.assumptions)
        return "\n".join(lines)


def _ladder(revenue: Decimal, variable: Decimal, fixed: Decimal, receivables: Decimal | None, days: int) -> dict[str, Any]:
    contribution = _money(revenue - variable)
    margin = None if revenue <= 0 else _pct(contribution / revenue * _HUNDRED)
    break_even = None if margin is None or margin <= 0 else _money(fixed / (margin / _HUNDRED))
    safety = None if break_even is None or revenue <= 0 else _pct((revenue - break_even) / revenue * _HUNDRED)
    dso = None if receivables is None or revenue <= 0 else (receivables / (revenue / days)).quantize(_DAYS, rounding=ROUND_HALF_UP)
    return {"revenue": str(_money(revenue)), "variable_costs": str(_money(variable)), "contribution": str(contribution), "fixed_costs": str(_money(fixed)), "operating_result": str(_money(contribution - fixed)), "contribution_margin_percent": None if margin is None else str(margin), "break_even_revenue": None if break_even is None else str(break_even), "margin_of_safety_percent": None if safety is None else str(safety), "receivables": None if receivables is None else str(_money(receivables)), "receivable_days": None if dso is None else str(dso)}


def run_scenario(books: Mapping[str, Any] | Any, *, scenario_ref: str, levers: Sequence[Mapping[str, Any] | Lever], as_of: str) -> Scenario:
    """The sealed consequence of the levers applied, in order, to the books' window."""

    from lightbulb.books_snapshot import verify_books_snapshot

    snapshot = verify_books_snapshot(books)
    at = timestamp(as_of, field_name="as_of")
    parsed_levers = [item if isinstance(item, Lever) else Lever.model_validate(detached(item)) for item in levers]
    _require(bool(parsed_levers), "LEVERS_MISSING", "a scenario changes at least one thing")
    _require(len(parsed_levers) <= 12, "LEVERS_TOO_MANY", "a scenario takes at most twelve levers")
    days = snapshot.days_in_window
    year = Decimal(days) / Decimal(365)
    revenue, variable, fixed = Decimal(str(snapshot.revenue)), Decimal(str(snapshot.variable_costs)), Decimal(str(snapshot.fixed_costs))
    receivables = None if snapshot.receivables is None else Decimal(str(snapshot.receivables))
    base_margin_ratio = Decimal("0") if revenue <= 0 else (revenue - variable) / revenue
    variable_ratio = Decimal("0") if revenue <= 0 else variable / revenue
    baseline = _ladder(revenue, variable, fixed, receivables, days)
    assumptions: list[str] = [f"the baseline is the books for {snapshot.period_label} ({days} days); annual figures are scaled by {days}/365", "every change is applied to the window as if it had been in force throughout it"]
    if snapshot.finding("NO_COSTS_RECORDED") is not None or snapshot.finding("COSTS_IMPLAUSIBLY_LOW") is not None:
        assumptions.append("the books record too little cost for the baseline's fixed cost to mean anything: the operating result and break-even after the change inherit that")
    effects: list[dict[str, Any]] = []
    sensitivity: dict[str, str] = {}
    cash_change = Decimal("0")
    for lever in parsed_levers:
        d_rev = d_var = d_fix = d_cash = Decimal("0")
        if lever.kind == "price":
            pct = lever.percent / _HUNDRED
            elasticity = lever.elasticity if lever.elasticity is not None else Decimal("-1.0")
            volume_change = elasticity * pct
            new_revenue = revenue * (1 + pct) * (1 + volume_change)
            d_rev = new_revenue - revenue
            d_var = variable * volume_change
            note = f"price {lever.percent:+}% at elasticity {elasticity}: volume {volume_change * _HUNDRED:+.1f}%, revenue {_money(d_rev):+}, variable cost {_money(d_var):+}"
            if lever.elasticity is None:
                assumptions.append("elasticity of -1.0 is assumed for the price lever (each 1% of price loses 1% of volume); the sensitivity table shows -0.5 and -1.5")
            for e in ELASTICITIES:
                vc = e * pct
                sensitivity[f"price {lever.percent:+}% at elasticity {e}"] = str(_money(revenue * (1 + pct) * (1 + vc) - revenue - variable * vc))
        elif lever.kind == "volume":
            pct = lever.percent / _HUNDRED
            d_rev, d_var = revenue * pct, variable * pct
            note = f"volume {lever.percent:+}% at constant price: revenue {_money(d_rev):+}, variable cost {_money(d_var):+}"
        elif lever.kind == "hire":
            cost = lever.annual_cost * (1 + lever.on_cost_percent / _HUNDRED) * year
            productive = Decimal(1) if lever.ramp_months == 0 else max(Decimal(0), (Decimal(days) - Decimal(lever.ramp_months) * Decimal(30)) / Decimal(days))
            d_fix = cost
            if lever.billable_share_percent is not None and lever.bill_rate is not None:
                hours = Decimal(days) / Decimal(7) * Decimal(38) * lever.billable_share_percent / _HUNDRED * productive
                d_rev = hours * lever.bill_rate
                note = f"hire at {lever.annual_cost}/yr +{lever.on_cost_percent}% on-costs = {_money(cost)} fixed over the window; {productive * _HUNDRED:.0f}% productive after a {lever.ramp_months}-month ramp, {hours:.0f} billable hours at {lever.bill_rate} = {_money(d_rev)} revenue"
                assumptions.append("a hire's billable hours are 38 a week times the billable share, after the ramp; the rate is the one given, not the rate card's")
            else:
                note = f"hire at {lever.annual_cost}/yr +{lever.on_cost_percent}% on-costs = {_money(cost)} fixed over the window, earning nothing directly"
        elif lever.kind == "contractor":
            d_fix = lever.hours * lever.rate
            if lever.bill_rate is not None:
                d_rev = lever.hours * lever.bill_rate
            note = f"contractor {lever.hours} hours at {lever.rate} = {_money(d_fix)} cost" + (f", billed at {lever.bill_rate} = {_money(d_rev)} revenue" if lever.bill_rate is not None else ", not billed on")
        elif lever.kind == "customer":
            share = (lever.variable_share_percent / _HUNDRED) if lever.variable_share_percent is not None else variable_ratio
            d_rev = lever.annual_revenue * year
            d_var = d_rev * share
            note = f"customer {'won' if d_rev >= 0 else 'lost'}: {_money(d_rev):+} revenue over the window at {share * _HUNDRED:.1f}% variable cost ({_money(d_var):+})"
            if lever.variable_share_percent is None:
                assumptions.append(f"the customer's variable cost share is the books' own ({variable_ratio * _HUNDRED:.1f}%)")
        elif lever.kind == "cost_line":
            d_fix = lever.amount
            note = f"fixed cost {_money(d_fix):+} over the window"
        else:
            if receivables is None or revenue <= 0:
                note = "payment terms: the books do not state receivables, so nothing moves"
            else:
                current_days = receivables / (revenue / Decimal(days))
                new_receivables = revenue / Decimal(days) * Decimal(lever.receivable_days)
                d_cash = receivables - new_receivables
                receivables = new_receivables
                note = f"receivable days {current_days:.1f} -> {lever.receivable_days}: {_money(d_cash):+} cash released, profit unchanged"
        revenue, variable, fixed = revenue + d_rev, variable + d_var, fixed + d_fix
        cash_change += d_rev - d_var - d_fix + d_cash
        effects.append({"lever": lever.to_dict(), "revenue_change": str(_money(d_rev)), "variable_cost_change": str(_money(d_var)), "fixed_cost_change": str(_money(d_fix)), "cash_change": str(_money(d_rev - d_var - d_fix + d_cash)), "note": note[:300]})
    after = _ladder(revenue, variable, fixed, receivables, days)
    op_change = _money(Decimal(after["operating_result"]) - Decimal(baseline["operating_result"]))
    be_change = None if after["break_even_revenue"] is None or baseline["break_even_revenue"] is None else _money(Decimal(after["break_even_revenue"]) - Decimal(baseline["break_even_revenue"]))
    # payback: months of the change's own monthly gain needed to recover a one-off cost line; only when both exist
    one_offs = sum((Decimal(effect["fixed_cost_change"]) for effect in effects if effect["lever"]["kind"] == "cost_line" and Decimal(effect["fixed_cost_change"]) > 0), Decimal("0"))
    monthly_gain = (op_change + one_offs) / (Decimal(days) / Decimal(30))
    payback = None if one_offs <= 0 or monthly_gain <= 0 else (one_offs / monthly_gain).quantize(_DAYS, rounding=ROUND_HALF_UP)
    verdict = f"operating result {op_change:+} {snapshot.currency} ({baseline['operating_result']} -> {after['operating_result']})" + ("" if be_change is None else f"; break-even revenue {be_change:+} ({baseline['break_even_revenue']} -> {after['break_even_revenue']})") + f"; cash {_money(cash_change):+} over the window"
    payload = {"scenario_ref": scenario_ref, "company_ref": snapshot.company_ref, "currency": snapshot.currency, "as_of": at, "books_digest": snapshot.snapshot_digest, "window_start": snapshot.window_start, "window_end": snapshot.window_end, "days_in_window": days, "baseline": baseline, "after": after, "effects": effects, "operating_result_change": str(op_change), "break_even_change": None if be_change is None else str(be_change), "cash_change": str(_money(cash_change)), "payback_months": payback, "sensitivity": sensitivity, "assumptions": [item[:300] for item in assumptions][:24], "verdict": verdict[:300], "source_digests": [snapshot.snapshot_digest]}
    return seal(Scenario, {key: value for key, value in payload.items() if value is not None}, "scenario_digest")


def verify_scenario(value: Any) -> Scenario:
    return value if isinstance(value, Scenario) else Scenario.model_validate(dict(detached(value)))


class ScenarioComparison(StrictModel):
    schema_id: str = Field(default=SCENARIO_COMPARISON_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    books_digest: Sha256Digest
    rows: tuple[dict[str, Any], ...] = Field(min_length=1, max_length=12)
    best_operating_result: ShortText
    best_cash: ShortText
    verdict: ShortText
    comparison_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ScenarioComparison":
        if not skip_digests(info) and self.comparison_digest != sealed_digest(ScenarioComparison, self, "comparison_digest"):
            raise ValueError("comparison_digest must commit the exact comparison")
        return self


def compare_scenarios(scenarios: Sequence[Mapping[str, Any] | Scenario], *, as_of: str) -> ScenarioComparison:
    """Several scenarios over the same books, side by side, with the best by operating result and by cash named."""

    parsed = [verify_scenario(item) for item in scenarios]
    _require(bool(parsed), "SCENARIOS_MISSING", "compare at least one scenario")
    digests = {item.books_digest for item in parsed}
    _require(len(digests) == 1, "BASELINE_MISMATCH", "every scenario compared must start from the same books")
    rows = [{"scenario_ref": item.scenario_ref, "operating_result_change": str(item.operating_result_change), "break_even_change": None if item.break_even_change is None else str(item.break_even_change), "cash_change": str(item.cash_change), "scenario_digest": item.scenario_digest} for item in parsed]
    best_op = max(parsed, key=lambda item: item.operating_result_change).scenario_ref
    best_cash = max(parsed, key=lambda item: item.cash_change).scenario_ref
    verdict = f"{len(parsed)} scenario(s) from the same books; best operating result: {best_op}; best cash: {best_cash}"
    return seal(ScenarioComparison, {"company_ref": parsed[0].company_ref, "currency": parsed[0].currency, "as_of": timestamp(as_of, field_name="as_of"), "books_digest": parsed[0].books_digest, "rows": rows, "best_operating_result": best_op, "best_cash": best_cash, "verdict": verdict[:300]}, "comparison_digest")


__all__ = ["ELASTICITIES", "LEVER_KINDS", "SCENARIO_COMPARISON_SCHEMA", "SCENARIO_MANIFEST", "SCENARIO_SCHEMA", "Ladder", "Lever", "LeverEffect", "Scenario", "ScenarioComparison", "ScenarioError", "compare_scenarios", "run_scenario", "verify_scenario"]
