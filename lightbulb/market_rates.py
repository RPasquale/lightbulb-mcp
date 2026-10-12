"""Market rates from what the company actually paid: realised contractor rates per skill, beside the rates typed into the sourcing plan.

Labour sourcing, the rate card and skills development price the "contract"
route with a market rate per skill, typed by hand into the plan and never
checked again.  The contractor chain already records, per engagement, the
work delivered (units and value) and the bills paid against it.
``observe_market_rates`` turns those into evidence: for every engagement
with money actually paid, the realised hourly rate (value over units; a day
rate over the stated hours per day; deliverable rates cannot be made hourly
and are listed, not guessed), grouped by the skill the owner says that
contractor supplies.  Per skill it reports the observations, the median,
low and high, the latest payment, and the typed rate beside them.

Observations older than ``max_age_days`` are left out and counted, so an
old rate never passes for today's.  Where the median departs from the
typed rate by more than the tolerance, a proposed rate is returned for the
owner to write into the plan; nothing is applied.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

MARKET_RATES_SCHEMA = "lightbulb.market_rate_observations.v1"
MARKET_RATES_MANIFEST: dict[str, Any] = {"engine": "market_rates", "kind": "intelligence_document", "reads": ("contractor_chain",), "writes": ()}
RateStatus = Literal["above_plan", "below_plan", "in_line", "no_plan_rate"]
_CENT = Decimal("0.01")


class MarketRatesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise MarketRatesError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _median(values: Sequence[Decimal]) -> Decimal:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


class RateObservation(StrictModel):
    contractor_ref: OpaqueRef
    hourly_rate: Decimal
    units: Decimal
    rate_uom: ShortText
    paid_at: str
    source_digest: Sha256Digest

    @field_validator("hourly_rate", "units", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SkillRate(StrictModel):
    skill_ref: OpaqueRef
    observations: tuple[RateObservation, ...] = Field(min_length=1, max_length=200)
    median: Decimal
    low: Decimal
    high: Decimal
    latest_paid_at: str
    plan_rate: Decimal | None = None
    status: RateStatus
    proposed_rate: Decimal | None = None
    note: ShortText

    @field_validator("observations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("median", "low", "high", "plan_rate", "proposed_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class MarketRateObservations(StrictModel):
    schema_id: str = Field(default=MARKET_RATES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    max_age_days: int = Field(ge=1, le=3650)
    tolerance_percent: Decimal
    skills: tuple[SkillRate, ...] = Field(default_factory=tuple, max_length=500)
    stale: int = Field(ge=0)
    unpriced: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)
    proposed_market_rates: dict[str, str] = Field(default_factory=dict)
    verdict: ShortText
    rates_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("skills", "unpriced", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("tolerance_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="tolerance_percent")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "MarketRateObservations":
        if self.proposed_market_rates != {row.skill_ref: str(row.proposed_rate) for row in self.skills if row.proposed_rate is not None}:
            raise ValueError("the proposals are the skills' proposed rates")
        if not skip_digests(info) and self.rates_digest != sealed_digest(MarketRateObservations, self, "rates_digest"):
            raise ValueError("rates_digest must commit the exact observations")
        return self

    def skill(self, skill_ref: str) -> SkillRate:
        found = next((row for row in self.skills if row.skill_ref == skill_ref), None)
        if found is None:
            raise LookupError(f"no paid work observed for {skill_ref}")
        return found

    def render(self) -> str:
        lines = [f"**Market rates paid** ({self.company_ref}, to {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.skill_ref}: {row.note}" for row in self.skills)
        lines.extend(f"- not priced: {item}" for item in self.unpriced)
        return "\n".join(lines)


def observe_market_rates(*, company_ref: str, currency: str, as_of: str, engagements: Sequence[Mapping[str, Any]], skills_by_contractor: Mapping[str, str], plan_rates: Mapping[str, Any] | None = None, max_age_days: int = 180, tolerance_percent: Any = "10", hours_per_day: Any = "8") -> MarketRateObservations:
    """Realised hourly rates per skill from engagements with money paid; each engagement is ``{contractor_ref, rate_uom, units_total, work_value_total, paid_at, source_digest}``."""

    at = timestamp(as_of, field_name="as_of")
    tolerance = decimal_value(tolerance_percent, field_name="tolerance_percent")
    per_day = decimal_value(hours_per_day, field_name="hours_per_day")
    _require(1 <= int(max_age_days) <= 3650, "MAX_AGE_INVALID", "the maximum age is 1 to 3650 days")
    _require(Decimal("0") < per_day <= Decimal("24"), "HOURS_PER_DAY_INVALID", "a day is more than 0 and at most 24 hours")
    plan = {str(key): decimal_value(value, field_name=f"plan_rates.{key}") for key, value in dict(plan_rates or {}).items()}
    grouped: dict[str, list[dict[str, Any]]] = {}
    unpriced: list[str] = []
    stale = 0
    for raw in engagements:
        item = dict(detached(raw))
        contractor = str(item["contractor_ref"])
        paid_at = item.get("paid_at")
        units = decimal_value(item.get("units_total", "0"), field_name="units_total")
        value = decimal_value(item.get("work_value_total", "0"), field_name="work_value_total")
        if not paid_at or units <= 0 or value <= 0:
            continue
        skill = skills_by_contractor.get(contractor)
        if skill is None:
            unpriced.append(f"{contractor}: no skill named for this contractor")
            continue
        uom = str(item.get("rate_uom") or "")
        if uom == "hour":
            hourly = value / units
        elif uom == "day":
            hourly = value / (units * per_day)
        else:
            unpriced.append(f"{contractor}: paid per {uom or 'unknown unit'}, which has no hourly equivalent")
            continue
        if (parsed(at) - parsed(timestamp(str(paid_at), field_name="paid_at"))).days > int(max_age_days):
            stale += 1
            continue
        grouped.setdefault(skill, []).append({"contractor_ref": contractor, "hourly_rate": str(hourly.quantize(_CENT, rounding=ROUND_HALF_UP)), "units": str(units), "rate_uom": uom, "paid_at": timestamp(str(paid_at), field_name="paid_at"), "source_digest": str(item["source_digest"])})
    skills: list[dict[str, Any]] = []
    for skill in sorted(grouped):
        rows = sorted(grouped[skill], key=lambda row: (row["paid_at"], row["contractor_ref"]))
        rates = [Decimal(row["hourly_rate"]) for row in rows]
        median = _median(rates).quantize(_CENT, rounding=ROUND_HALF_UP)
        typed = plan.get(skill)
        if typed is None:
            status, proposed = "no_plan_rate", median
        else:
            gap = ((median - typed) / typed * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            status = "above_plan" if gap > tolerance else ("below_plan" if gap < -tolerance else "in_line")
            proposed = None if status == "in_line" else median
        note = f"paid {median}/h median over {len(rows)} engagement(s) ({min(rates)} to {max(rates)}), latest {rows[-1]['paid_at'][:10]}" + ("" if typed is None else f"; the plan types {typed}/h") + ("" if proposed is None else f"; propose {proposed}/h")
        skills.append({"skill_ref": skill, "observations": rows, "median": str(median), "low": str(min(rates)), "high": str(max(rates)), "latest_paid_at": rows[-1]["paid_at"], "plan_rate": None if typed is None else str(typed), "status": status, "proposed_rate": None if proposed is None else str(proposed), "note": note[:300]})
    proposals = {row["skill_ref"]: row["proposed_rate"] for row in skills if row["proposed_rate"] is not None}
    verdict = (f"{len(skills)} skill(s) priced from paid work, {len(proposals)} proposal(s) for the sourcing plan" if skills else "no paid contractor work to price yet") + (f"; {stale} observation(s) older than {int(max_age_days)} days left out" if stale else "") + "; nothing is applied until written into the plan"
    return seal(MarketRateObservations, {"company_ref": company_ref, "currency": str(currency).upper(), "as_of": at, "max_age_days": int(max_age_days), "tolerance_percent": str(tolerance), "skills": [{key: value for key, value in row.items() if value is not None} for row in skills], "stale": stale, "unpriced": [item[:300] for item in unpriced], "proposed_market_rates": proposals, "verdict": verdict[:300]}, "rates_digest")


def verify_market_rates(value: Any) -> MarketRateObservations:
    return value if isinstance(value, MarketRateObservations) else MarketRateObservations.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built"}})


__all__ = ["MARKET_RATES_MANIFEST", "MARKET_RATES_SCHEMA", "MarketRateObservations", "MarketRatesError", "RateObservation", "SkillRate", "observe_market_rates", "verify_market_rates"]
