"""Price probe outcomes: whether each recommended price move was actually taken, and whether it paid, from the margin report of the window after.

The probe table says what to charge and how much volume the move can
afford to lose.  ``score_probe_outcomes`` closes the loop with sealed
documents only:

* the probes must have been planned from the ``before`` margin report
  (their bound digest), and the ``after`` report must cover a window that
  starts once the before window has ended;
* per probed SKU: the realised price before and after, the move the
  probe asked for and the move the market shows, whether the move was
  applied within the plan's tolerance, the volume change per day against
  the break-even volume change the probe allowed, the contribution per
  day before and after, and the money that made over the after window;
* a verdict per SKU: ``held`` (applied and contribution a day did not
  fall), ``backfired`` (applied and it fell), ``not_applied`` (the price
  did not move), ``unmeasured`` (the SKU stopped selling or was never
  measured); and per document the counts, the money on applied probes,
  and what to do next: keep, revert, or apply.

Nothing here judges why volume moved; it reads what the chains proved.
Nothing reads a provider or persists anything.
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
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

PROBE_OUTCOMES_PLAN_SCHEMA = "lightbulb.probe_outcomes_plan.v1"
PROBE_OUTCOMES_SCHEMA = "lightbulb.probe_outcomes.v1"
VERDICTS: tuple[str, ...] = ("held", "backfired", "not_applied", "unmeasured")
ProbeVerdict = Literal["held", "backfired", "not_applied", "unmeasured"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class ProbeOutcomesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ProbeOutcomesError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ProbeOutcomesPlan(StrictModel):
    schema_id: str = Field(default=PROBE_OUTCOMES_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    applied_tolerance_percent: Decimal = Field(default=Decimal("2"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("applied_tolerance_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProbeOutcomesPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(ProbeOutcomesPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_probe_outcomes_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> ProbeOutcomesPlan:
    return seal(ProbeOutcomesPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class ProbeOutcome(StrictModel):
    sku_ref: OpaqueRef
    probe_action: ShortText
    price_before: Decimal
    target_price: Decimal
    target_move_percent: Decimal
    price_after: Decimal | None = None
    realised_move_percent: Decimal | None = None
    applied: bool
    units_before: Decimal
    units_after: Decimal
    units_per_day_before: Decimal
    units_per_day_after: Decimal
    volume_change_percent: Decimal | None = None
    allowed_volume_change_percent: Decimal | None = None
    unit_contribution_before: Decimal
    target_unit_contribution: Decimal
    expected_change: Decimal
    unit_contribution_after: Decimal | None = None
    contribution_per_day_before: Decimal
    contribution_per_day_after: Decimal
    contribution_change: Decimal
    verdict: ProbeVerdict
    next_step: ShortText
    rationale: ShortText

    @field_validator("price_before", "target_price", "target_move_percent", "price_after", "realised_move_percent", "units_before", "units_after", "units_per_day_before", "units_per_day_after", "volume_change_percent", "allowed_volume_change_percent", "unit_contribution_before", "target_unit_contribution", "expected_change", "unit_contribution_after", "contribution_per_day_before", "contribution_per_day_after", "contribution_change", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class ProbeOutcomes(StrictModel):
    schema_id: str = Field(default=PROBE_OUTCOMES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    probes_digest: Sha256Digest
    before_report_digest: Sha256Digest
    after_report_digest: Sha256Digest
    before_window_start: str
    before_window_end: str
    after_window_start: str
    after_window_end: str
    after_days: int = Field(ge=1)
    outcomes: tuple[ProbeOutcome, ...] = Field(default_factory=tuple, max_length=5000)
    skipped: int = Field(ge=0)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    applied: int = Field(ge=0)
    contribution_change_applied: Decimal
    contribution_change_all: Decimal
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=10)
    outcomes_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("outcomes", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("contribution_change_applied", "contribution_change_all", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProbeOutcomes":
        if sum(self.by_verdict.values()) != len(self.outcomes) or self.applied != sum(1 for row in self.outcomes if row.applied):
            raise ValueError("by_verdict counts every outcome and applied counts the applied ones")
        if not skip_digests(info) and self.outcomes_digest != sealed_digest(ProbeOutcomes, self, "outcomes_digest"):
            raise ValueError("outcomes_digest must commit the exact document")
        return self

    def outcome(self, sku_ref: str) -> ProbeOutcome | None:
        return next((row for row in self.outcomes if row.sku_ref == sku_ref), None)

    def render(self) -> str:
        lines = [f"**Probe outcomes {self.company_ref}** {self.after_window_start[:10]} to {self.after_window_end[:10]}: {self.verdict}"]
        lines.extend(f"- {row.sku_ref}: [{row.verdict}] {row.rationale}" for row in self.outcomes)
        return "\n".join(lines)


def score_probe_outcomes(plan: ProbeOutcomesPlan | Mapping[str, Any], *, probes: Mapping[str, Any] | Any, before: Mapping[str, Any] | Any, after: Mapping[str, Any] | Any, as_of: str) -> ProbeOutcomes:
    """The sealed outcome of every probe the table recommended, read from the margin report of the window after."""

    from lightbulb.price_probes import verify_price_probes
    from lightbulb.product_margin import verify_product_margin

    parsed_plan = plan if isinstance(plan, ProbeOutcomesPlan) else ProbeOutcomesPlan.model_validate(detached(plan))
    table = verify_price_probes(probes)
    first, second = verify_product_margin(before), verify_product_margin(after)
    _require(table.company_ref == parsed_plan.company_ref and table.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the probes name another company or currency")
    _require(first.company_ref == parsed_plan.company_ref and first.currency == parsed_plan.currency and second.company_ref == parsed_plan.company_ref and second.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "a margin report names another company or currency")
    _require(table.margin_report_digest == first.report_digest, "PROBES_NOT_BOUND", "the probes were planned from another margin report")
    _require(parsed(second.window_start) >= parsed(first.window_end), "WINDOWS_OVERLAP", "the after window must start once the before window has ended")
    at = timestamp(as_of, field_name="as_of")
    before_days = max((parsed(first.window_end) - parsed(first.window_start)).days, 1)
    after_days = max((parsed(second.window_end) - parsed(second.window_start)).days, 1)
    later = {row.sku_ref: row for row in second.rows}
    targets = {row["sku_ref"]: row for row in table.recommended_moves}
    tolerance = parsed_plan.applied_tolerance_percent
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    skipped = 0
    change_applied = change_all = Decimal("0")
    recommendations: list[str] = []
    for probe in table.skus:
        target = targets.get(probe.sku_ref)
        if probe.action not in ("probe", "reprice_to_floor") or target is None:
            skipped += 1
            continue
        price_before = Decimal(str(probe.realised_price))
        target_price = Decimal(str(target["target_price"]))
        target_move = _pct((target_price / price_before - Decimal("1")) * _HUNDRED) if price_before > 0 else Decimal("0")
        unit_costs = Decimal(str(probe.unit_cost_of_goods)) + Decimal(str(probe.unit_fulfilment)) + Decimal(str(probe.unit_return_handling))
        fee_rate = Decimal(str(probe.fee_rate_percent))
        units_before = Decimal(str(probe.units_sold))
        per_day_before = _pct(units_before / before_days)
        contribution_before = Decimal(str(probe.unit_contribution))
        cpd_before = _money(contribution_before * units_before / before_days)
        allowed = None if target.get("breakeven_volume_change_percent") is None else Decimal(str(target["breakeven_volume_change_percent"]))
        move = next((item for item in probe.moves if Decimal(str(item.move_percent)) == Decimal(str(target.get("move_percent") or "0"))), None) if probe.action == "probe" else None
        target_contribution = Decimal(str(move.unit_contribution)) if move is not None else _money(target_price * (Decimal("1") - fee_rate / _HUNDRED) - unit_costs)
        expected = _money((target_contribution - contribution_before) * units_before)
        row = later.get(probe.sku_ref)
        units_after = Decimal("0") if row is None else Decimal(str(row.units_sold))
        base = {"sku_ref": probe.sku_ref, "probe_action": probe.action, "price_before": str(_money(price_before)), "target_price": str(_money(target_price)), "target_move_percent": str(target_move), "units_before": str(_money(units_before)), "units_after": str(_money(units_after)), "units_per_day_before": str(per_day_before), "units_per_day_after": str(_pct(units_after / after_days)), "allowed_volume_change_percent": None if allowed is None else str(allowed), "unit_contribution_before": str(_money(contribution_before)), "target_unit_contribution": str(_money(target_contribution)), "expected_change": str(expected), "contribution_per_day_before": str(cpd_before)}
        if row is None or units_after <= 0 or not row.priced or not row.costed:
            reason = "the SKU sold nothing in the window after" if row is None or units_after <= 0 else "the SKU is not priced and costed in the window after"
            cpd_after = Decimal("0.00")
            change = _money((cpd_after - cpd_before) * after_days)
            change_all += change
            rows.append({**base, "price_after": None, "realised_move_percent": None, "applied": False, "volume_change_percent": None, "unit_contribution_after": None, "contribution_per_day_after": str(cpd_after), "contribution_change": str(change), "verdict": "unmeasured", "next_step": "measure", "rationale": f"{reason}; contribution a day {cpd_before} to {cpd_after}"[:300]})
            counts["unmeasured"] = counts.get("unmeasured", 0) + 1
            continue
        price_after = _money(Decimal(str(row.net_revenue)) / units_after)
        realised_move = _pct((price_after / price_before - Decimal("1")) * _HUNDRED) if price_before > 0 else Decimal("0")
        applied = abs(realised_move - target_move) <= tolerance if probe.action == "probe" else price_after >= _money(target_price * (Decimal("1") - tolerance / _HUNDRED))
        volume_change = None if per_day_before <= 0 else _pct((units_after / after_days) / (units_before / before_days) * _HUNDRED - _HUNDRED)
        contribution_after = _money(Decimal(str(row.contribution)) / units_after)
        cpd_after = _money(Decimal(str(row.contribution)) / after_days)
        change = _money((cpd_after - cpd_before) * after_days)
        change_all += change
        if not applied:
            verdict, step = "not_applied", f"apply {target_price}"
            rationale = f"price {price_before} to {price_after} ({realised_move}%) against the {target_move}% move asked; contribution a day {cpd_before} to {cpd_after}"
        elif cpd_after >= cpd_before:
            verdict, step = "held", "keep"
            change_applied += change
            rationale = f"price {price_before} to {price_after} ({realised_move}%); volume a day {volume_change if volume_change is not None else 'n/a'}%" + (f" against {allowed}% allowed" if allowed is not None else "") + f"; contribution a day {cpd_before} to {cpd_after} (+{_money(cpd_after - cpd_before)})"
        else:
            verdict, step = "backfired", f"revert to {_money(price_before)}"
            change_applied += change
            rationale = f"price {price_before} to {price_after} ({realised_move}%); volume a day {volume_change if volume_change is not None else 'n/a'}%" + (f" against {allowed}% allowed" if allowed is not None else "") + f"; contribution a day {cpd_before} to {cpd_after} ({_money(cpd_after - cpd_before)})"
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append({**base, "price_after": str(price_after), "realised_move_percent": str(realised_move), "applied": applied, "volume_change_percent": None if volume_change is None else str(volume_change), "unit_contribution_after": str(contribution_after), "contribution_per_day_after": str(cpd_after), "contribution_change": str(change), "verdict": verdict, "next_step": step[:300], "rationale": rationale[:300]})
    order = {"backfired": 0, "not_applied": 1, "held": 2, "unmeasured": 3}
    rows.sort(key=lambda row: (order[row["verdict"]], -abs(Decimal(row["contribution_change"])), row["sku_ref"]))
    for row in rows:
        if row["verdict"] == "backfired":
            recommendations.append(f"{row['sku_ref']}: {row['next_step']}; {row['rationale']}")
        elif row["verdict"] == "not_applied":
            recommendations.append(f"{row['sku_ref']}: {row['next_step']}; {row['rationale']}")
    if not recommendations:
        if not rows:
            recommendations.append("no probe was recommended, so nothing is scored")
        elif counts.get("held", 0):
            recommendations.append("every applied probe held")
        else:
            recommendations.append("no probe could be measured in the window after")
    applied_count = sum(1 for row in rows if row["applied"])
    verdict = f"{len(rows)} probe(s) scored: {counts.get('held', 0)} held, {counts.get('backfired', 0)} backfired, {counts.get('not_applied', 0)} not applied, {counts.get('unmeasured', 0)} unmeasured; applied probes moved contribution {_money(change_applied)} {parsed_plan.currency} over {after_days} day(s)"
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "probes_digest": table.probes_digest, "before_report_digest": first.report_digest, "after_report_digest": second.report_digest, "before_window_start": first.window_start, "before_window_end": first.window_end, "after_window_start": second.window_start, "after_window_end": second.window_end, "after_days": after_days, "outcomes": rows, "skipped": skipped, "by_verdict": counts, "applied": applied_count, "contribution_change_applied": str(_money(change_applied)), "contribution_change_all": str(_money(change_all)), "verdict": verdict[:300], "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": [table.probes_digest, first.report_digest, second.report_digest]}
    return seal(ProbeOutcomes, payload, "outcomes_digest")


def verify_probe_outcomes(value: Any) -> ProbeOutcomes:
    return value if isinstance(value, ProbeOutcomes) else ProbeOutcomes.model_validate(dict(detached(value)))


PROBE_OUTCOMES_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "probe_outcomes",
    "golden_loop": "commerce.product_truth_to_measured_income@0.1.0",
    "stages": ["bind_probes_to_before_report", "read_after_report", "applied_within_tolerance", "volume_against_allowed", "contribution_per_day", "seal_outcomes"],
    "verdicts": list(VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the probes must be bound to the before report by digest and the after window must follow the before window",
        "applied means the realised price moved within the plan's tolerance of the move asked; nothing infers a price change from a catalog draft",
        "nothing here judges why volume moved, reads a provider, or persists anything",
    ],
}

__all__ = ["PROBE_OUTCOMES_MANIFEST", "PROBE_OUTCOMES_PLAN_SCHEMA", "PROBE_OUTCOMES_SCHEMA", "VERDICTS", "ProbeOutcome", "ProbeOutcomes", "ProbeOutcomesError", "ProbeOutcomesPlan", "compile_probe_outcomes_plan", "score_probe_outcomes", "verify_probe_outcomes"]
