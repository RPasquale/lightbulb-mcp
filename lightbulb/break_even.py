"""Break-even: the revenue the company must earn before the fixed costs the registers prove are covered, and how far above or below it the window ran.

Contribution documents say what each SKU and engagement earns after its
variable costs; the cost registers say what the company spends whether or
not it sells.  ``build_break_even`` seals the two together:

* contribution from the window's sealed product margin report (goods) and
  services margin (engagements), with the plan deciding whether services
  labour already sits in the registers' labour spend (so services count at
  their recognisable value) or is netted inside the services margin;
* fixed cost from every replayed cost register whose period overlaps the
  window, prorated by the overlapping days, taking the centre kinds the
  plan calls fixed (overhead and labour by default) and leaving out the
  source kinds a contribution document already carries (cost of goods,
  job and work order cost, refunds, FX);
* the operating result, the break-even revenue at the window's blended
  contribution margin, the margin of safety, the operating leverage, and
  the three ways to close a gap: revenue, contribution margin, or fixed
  cost, each named with its number.

No register overlapping the window means the fixed cost is unknown, and
the document says so instead of calling the company profitable.  Nothing
here reads a provider or persists anything.
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

BREAK_EVEN_PLAN_SCHEMA = "lightbulb.break_even_plan.v1"
BREAK_EVEN_SCHEMA = "lightbulb.break_even.v1"
FIXED_CENTRE_KINDS: tuple[str, ...] = ("overhead", "labour")
VARIABLE_SOURCE_KINDS: tuple[str, ...] = ("inventory_cogs", "work_order", "job_case", "refund_case", "fx_cost")
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class BreakEvenError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BreakEvenError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class BreakEvenPlan(StrictModel):
    schema_id: str = Field(default=BREAK_EVEN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    fixed_centre_kinds: tuple[ShortText, ...] = Field(default=FIXED_CENTRE_KINDS, min_length=1, max_length=3)
    variable_source_kinds: tuple[ShortText, ...] = Field(default=VARIABLE_SOURCE_KINDS, max_length=24)
    services_labour_in_fixed_cost: bool = True
    safety_floor_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("fixed_centre_kinds", "variable_source_kinds", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("safety_floor_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BreakEvenPlan":
        if any(kind not in ("engine", "overhead", "labour") for kind in self.fixed_centre_kinds):
            raise ValueError("fixed_centre_kinds are drawn from engine, overhead, and labour")
        if not skip_digests(info) and self.plan_digest != sealed_digest(BreakEvenPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_break_even_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> BreakEvenPlan:
    return seal(BreakEvenPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class FixedCostLine(StrictModel):
    register_ref: OpaqueRef
    period_start: str
    period_end: str
    overlap_days: int = Field(ge=0)
    period_days: int = Field(ge=1)
    spend_in_period: Decimal
    fixed_in_window: Decimal
    excluded: Decimal

    @field_validator("spend_in_period", "fixed_in_window", "excluded", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class BreakEven(StrictModel):
    schema_id: str = Field(default=BREAK_EVEN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    window_days: int = Field(ge=1)
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest | None = None
    services_margin_digest: Sha256Digest | None = None
    goods_revenue: Decimal
    goods_contribution: Decimal
    services_revenue: Decimal
    services_cost: Decimal
    services_contribution: Decimal
    revenue: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    fixed_cost_known: bool
    fixed_cost: Decimal
    fixed_by_kind: dict[str, Decimal] = Field(default_factory=dict)
    fixed_by_category: dict[str, Decimal] = Field(default_factory=dict)
    registers: tuple[FixedCostLine, ...] = Field(default_factory=tuple, max_length=200)
    operating_result: Decimal | None = None
    break_even_revenue: Decimal | None = None
    margin_of_safety_percent: Decimal | None = None
    operating_leverage: Decimal | None = None
    daily_contribution: Decimal
    daily_fixed_cost: Decimal | None = None
    revenue_to_break_even: Decimal | None = None
    margin_percent_to_break_even: Decimal | None = None
    fixed_cost_to_cut: Decimal | None = None
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    break_even_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("registers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("goods_revenue", "goods_contribution", "services_revenue", "services_cost", "services_contribution", "revenue", "contribution", "contribution_margin_percent", "fixed_cost", "operating_result", "break_even_revenue", "margin_of_safety_percent", "operating_leverage", "daily_contribution", "daily_fixed_cost", "revenue_to_break_even", "margin_percent_to_break_even", "fixed_cost_to_cut", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("fixed_by_kind", "fixed_by_category", mode="before")
    @classmethod
    def _buckets(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(key): decimal_value(amount, field_name=str(info.field_name), allow_negative=True) for key, amount in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BreakEven":
        if self.revenue != self.goods_revenue + self.services_revenue or self.contribution != self.goods_contribution + self.services_contribution:
            raise ValueError("revenue and contribution are the goods and services figures added")
        if self.fixed_cost_known and self.operating_result != self.contribution - self.fixed_cost:
            raise ValueError("operating_result is contribution less fixed cost")
        if not skip_digests(info) and self.break_even_digest != sealed_digest(BreakEven, self, "break_even_digest"):
            raise ValueError("break_even_digest must commit the exact document")
        return self

    def render(self) -> str:
        lines = [f"**Break-even {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: {self.verdict}"]
        lines.extend(f"- {row}" for row in self.recommendations)
        return "\n".join(lines)


def _overlap_days(start: str, end: str, period_start: str, period_end: str) -> tuple[int, int]:
    a, b = parsed(start), parsed(end)
    c, d = parsed(period_start), parsed(period_end)
    period = max((d - c).days, 1)
    overlap = (min(b, d) - max(a, c)).days
    return max(overlap, 0), period


def build_break_even(plan: BreakEvenPlan | Mapping[str, Any], *, margin_report: Mapping[str, Any] | Any | None = None, services_margin: Mapping[str, Any] | Any | None = None, register_states: Sequence[tuple[Any, Any]] = (), window_start: str, window_end: str, as_of: str) -> BreakEven:
    """The sealed break-even over the window from the contribution documents and the replayed cost registers."""

    parsed_plan = plan if isinstance(plan, BreakEvenPlan) else BreakEvenPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    days = (parsed(end) - parsed(start)).days
    _require(days > 0, "WINDOW_EMPTY", "the window spans at least one day")
    _require(margin_report is not None or services_margin is not None, "DOCUMENTS_MISSING", "supply a margin report, a services margin, or both")
    digests: list[str] = []

    goods_revenue = goods_contribution = Decimal("0")
    report_digest = None
    if margin_report is not None:
        from lightbulb.product_margin import verify_product_margin

        report = verify_product_margin(margin_report)
        _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
        _require(report.window_start == start and report.window_end == end, "REPORT_WINDOW_MISMATCH", "the margin report must cover exactly this window")
        goods_revenue, goods_contribution = Decimal(str(report.net_revenue)), Decimal(str(report.contribution))
        report_digest = report.report_digest
        digests.append(report_digest)

    services_revenue = services_cost = services_contribution = Decimal("0")
    services_digest = None
    if services_margin is not None:
        from lightbulb.services_margin import verify_services_margin

        services = verify_services_margin(services_margin)
        _require(services.company_ref == parsed_plan.company_ref and services.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the services margin names another company or currency")
        _require(services.window_start == start and services.window_end == end, "REPORT_WINDOW_MISMATCH", "the services margin must cover exactly this window")
        services_revenue, services_cost = Decimal(str(services.recognisable_value)), Decimal(str(services.actual_cost))
        services_contribution = services_revenue if parsed_plan.services_labour_in_fixed_cost else services_revenue - services_cost
        services_digest = services.margin_digest
        digests.append(services_digest)

    fixed_kinds = set(parsed_plan.fixed_centre_kinds)
    if services_margin is not None and not parsed_plan.services_labour_in_fixed_cost:
        fixed_kinds.discard("labour")
    variable = set(parsed_plan.variable_source_kinds)
    lines: list[dict[str, Any]] = []
    by_kind: dict[str, Decimal] = {}
    by_category: dict[str, Decimal] = {}
    fixed_total = Decimal("0")
    for register_plan, state in register_states:
        _require(getattr(register_plan, "company_ref", None) == parsed_plan.company_ref and getattr(register_plan, "currency", None) == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"register {state.scope.entity_ref} belongs to another company or currency")
        ledger = state.ledger
        _require(ledger.period_start is not None and ledger.period_end is not None, "REGISTER_WINDOW_UNKNOWN", f"register {state.scope.entity_ref} has no accounting period")
        overlap, period = _overlap_days(start, end, str(ledger.period_start), str(ledger.period_end))
        if overlap == 0:
            continue
        share = Decimal(overlap) / Decimal(period)
        spend = excluded = Decimal("0")
        for source in ledger.sources:
            amount = Decimal(str(source.spend_amount))
            if source.centre_kind in fixed_kinds and source.source_kind not in variable:
                spend += amount
                slice_ = _money(amount * share)
                by_kind[source.centre_kind] = by_kind.get(source.centre_kind, Decimal("0")) + slice_
                label = str(source.category or source.engine or source.centre_ref)
                by_category[label] = by_category.get(label, Decimal("0")) + slice_
            else:
                excluded += amount
        fixed = _money(spend * share)
        fixed_total += fixed
        lines.append({"register_ref": state.scope.entity_ref, "period_start": str(ledger.period_start), "period_end": str(ledger.period_end), "overlap_days": overlap, "period_days": period, "spend_in_period": str(_money(spend)), "fixed_in_window": str(fixed), "excluded": str(_money(excluded))})
        digests.append(state.state_digest)
    known = bool(lines)

    revenue = _money(goods_revenue + services_revenue)
    contribution = _money(_money(goods_contribution) + _money(services_contribution))
    margin = None if revenue <= 0 else _pct(contribution / revenue * _HUNDRED)
    fixed_cost = _money(fixed_total)
    daily_contribution = _money(contribution / days)
    operating = _money(contribution - fixed_cost) if known else None
    break_even = None if not known or margin is None or margin <= 0 else _money(fixed_cost / (margin / _HUNDRED))
    safety = None if break_even is None or revenue <= 0 else _pct((revenue - break_even) / revenue * _HUNDRED)
    leverage = None if operating is None or operating <= 0 else _pct(contribution / operating)
    gap_revenue = None if break_even is None else _money(max(break_even - revenue, Decimal("0")))
    gap_margin = None if not known or revenue <= 0 else _pct(fixed_cost / revenue * _HUNDRED)
    gap_fixed = None if operating is None else _money(max(-operating, Decimal("0")))
    recommendations: list[str] = []
    if not known:
        verdict = f"contribution {contribution} {parsed_plan.currency} on {revenue} revenue" + (f" ({margin}%)" if margin is not None else "") + "; no cost register overlaps the window, so the fixed cost and the break-even are unknown"
        recommendations.append("open and close a cost register for this period before reading the operating result")
    elif margin is None or margin <= 0:
        verdict = f"contribution {contribution} {parsed_plan.currency} does not cover {fixed_cost} of fixed cost and the contribution margin is not positive; no revenue level breaks even at this margin"
        recommendations.append(f"fixed cost {fixed_cost} over {days} day(s); contribution must turn positive before a break-even exists")
    elif operating is not None and operating < 0:
        verdict = f"below break-even: contribution {contribution} against {fixed_cost} fixed ({operating}); break-even revenue {break_even} at {margin}% margin, margin of safety {safety}%"
        recommendations.append(f"revenue: {gap_revenue} more at {margin}% margin reaches break-even ({break_even} against {revenue})")
        recommendations.append(f"margin: {gap_margin}% contribution margin breaks even at {revenue} revenue (now {margin}%)")
        recommendations.append(f"fixed cost: cut {gap_fixed} of {fixed_cost} to break even at this contribution")
    else:
        verdict = f"above break-even: contribution {contribution} against {fixed_cost} fixed (+{operating}); break-even revenue {break_even}, margin of safety {safety}%" + (f", operating leverage {leverage}x" if leverage is not None else "")
        if safety is not None and safety < parsed_plan.safety_floor_percent:
            recommendations.append(f"margin of safety {safety}% is under the {parsed_plan.safety_floor_percent}% floor: revenue can fall only {_money(revenue - break_even)} before the fixed cost is uncovered")
        else:
            recommendations.append(f"every further {parsed_plan.currency} of revenue at {margin}% margin adds {_money(margin / _HUNDRED)} to the operating result")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "window_days": days, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report_digest, "services_margin_digest": services_digest, "goods_revenue": str(_money(goods_revenue)), "goods_contribution": str(_money(goods_contribution)), "services_revenue": str(_money(services_revenue)), "services_cost": str(_money(services_cost)), "services_contribution": str(_money(services_contribution)), "revenue": str(revenue), "contribution": str(contribution), "contribution_margin_percent": None if margin is None else str(margin), "fixed_cost_known": known, "fixed_cost": str(fixed_cost), "fixed_by_kind": {key: str(_money(value)) for key, value in sorted(by_kind.items())}, "fixed_by_category": {key: str(_money(value)) for key, value in sorted(by_category.items())}, "registers": lines, "operating_result": None if operating is None else str(operating), "break_even_revenue": None if break_even is None else str(break_even), "margin_of_safety_percent": None if safety is None else str(safety), "operating_leverage": None if leverage is None else str(leverage), "daily_contribution": str(daily_contribution), "daily_fixed_cost": None if not known else str(_money(fixed_cost / days)), "revenue_to_break_even": None if gap_revenue is None else str(gap_revenue), "margin_percent_to_break_even": None if gap_margin is None else str(gap_margin), "fixed_cost_to_cut": None if gap_fixed is None else str(gap_fixed), "verdict": verdict[:300], "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": digests}
    return seal(BreakEven, payload, "break_even_digest")


def verify_break_even(value: Any) -> BreakEven:
    return value if isinstance(value, BreakEven) else BreakEven.model_validate(dict(detached(value)))


BREAK_EVEN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "break_even",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["verify_contribution_documents", "prorate_registers_to_window", "fixed_cost_by_kind", "break_even_and_safety", "name_the_gap", "seal_document"],
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "fixed cost comes from replayed cost registers prorated by the days they overlap the window; no register means the fixed cost is unknown, never zero",
        "source kinds a contribution document already carries are excluded from fixed cost so nothing is counted twice",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["BREAK_EVEN_MANIFEST", "BREAK_EVEN_PLAN_SCHEMA", "BREAK_EVEN_SCHEMA", "FIXED_CENTRE_KINDS", "VARIABLE_SOURCE_KINDS", "BreakEven", "BreakEvenError", "BreakEvenPlan", "FixedCostLine", "build_break_even", "compile_break_even_plan", "verify_break_even"]
