"""Quote outcomes: whether each job quote held once the job was costed, from the sealed quotes and the sealed job costing, with the contingency the overruns say to carry.

The quote prices a job from the matched team; the costing says what the
job actually cost.  ``score_quote_outcomes`` closes the loop with
sealed documents only:

* every quote is bound to the costed job it was written for (the job's
  work order by source ref, else the job ref itself) and only a
  completed, costed job scores it;
* per quote: the quoted hours and the recorded labour hours, the quoted
  loaded labour cost (direct plus contingency) against the actual labour
  and contractor cost, the parts and stock the costing carries that the
  quote never priced, the quoted price (the offer, else the target) and
  the margin it actually realised on the whole cost, the labour variance
  against the plan's tolerance, and a verdict: ``held`` (labour inside
  the quote and margin above the plan's minimum), ``overran`` (labour
  past the quote), ``underquoted`` (labour inside the quote but the price
  left less than the minimum margin), ``open`` (the job is not
  completed), ``unmatched`` (no costed job carries the quote's job);
* per document: the counts, the quoted and actual cost and hours, the
  realised margin across scored quotes, and the contingency the
  overruns say to carry (the mean overrun on stretch quotes against the
  plan's current contingency), named as a number.

Nothing here judges why a job overran; it reads what the chains proved.
Nothing reads a provider or persists anything.
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

QUOTE_OUTCOMES_PLAN_SCHEMA = "lightbulb.quote_outcomes_plan.v1"
QUOTE_OUTCOMES_SCHEMA = "lightbulb.quote_outcomes.v1"
VERDICTS: tuple[str, ...] = ("held", "overran", "underquoted", "open", "unmatched")
QuoteVerdict = Literal["held", "overran", "underquoted", "open", "unmatched"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class QuoteOutcomesError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise QuoteOutcomesError(code, message)


def _money(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _pct(value: Any) -> Decimal:
    result = Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)
    return Decimal("0.00") if result == 0 else result


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class QuoteOutcomesPlan(StrictModel):
    schema_id: str = Field(default=QUOTE_OUTCOMES_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    cost_tolerance_percent: Decimal = Field(default=Decimal("5"), validate_default=True)
    minimum_margin_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("cost_tolerance_percent", "minimum_margin_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "QuoteOutcomesPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(QuoteOutcomesPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_quote_outcomes_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> QuoteOutcomesPlan:
    return seal(QuoteOutcomesPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class QuoteOutcome(StrictModel):
    job_ref: OpaqueRef
    work_order_ref: OpaqueRef | None = None
    quote_digest: Sha256Digest
    quote_verdict: ShortText
    stretch: bool
    quoted_hours: Decimal
    actual_hours: Decimal | None = None
    hours_variance_percent: Decimal | None = None
    direct_cost: Decimal
    contingency_cost: Decimal
    loaded_cost: Decimal
    actual_labour_cost: Decimal | None = None
    unquoted_cost: Decimal | None = None
    actual_cost: Decimal | None = None
    cost_variance: Decimal | None = None
    cost_variance_percent: Decimal | None = None
    price: Decimal | None = None
    price_basis: ShortText
    quoted_margin_percent: Decimal | None = None
    realised_margin_percent: Decimal | None = None
    realised_margin: Decimal | None = None
    verdict: QuoteVerdict
    rationale: ShortText

    @field_validator("quoted_hours", "actual_hours", "hours_variance_percent", "direct_cost", "contingency_cost", "loaded_cost", "actual_labour_cost", "unquoted_cost", "actual_cost", "cost_variance", "cost_variance_percent", "price", "quoted_margin_percent", "realised_margin_percent", "realised_margin", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class QuoteOutcomes(StrictModel):
    schema_id: str = Field(default=QUOTE_OUTCOMES_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    costing_digest: Sha256Digest
    outcomes: tuple[QuoteOutcome, ...] = Field(default_factory=tuple, max_length=5000)
    scored: int = Field(ge=0)
    by_verdict: dict[str, int] = Field(default_factory=dict)
    quoted_hours: Decimal
    actual_hours: Decimal
    loaded_cost: Decimal
    actual_cost: Decimal
    unquoted_cost: Decimal
    cost_variance: Decimal
    mean_cost_variance_percent: Decimal | None = None
    price: Decimal
    realised_margin: Decimal
    realised_margin_percent: Decimal | None = None
    contingency_percent_now: Decimal
    contingency_percent_needed: Decimal | None = None
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    outcomes_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("outcomes", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("quoted_hours", "actual_hours", "loaded_cost", "actual_cost", "unquoted_cost", "cost_variance", "mean_cost_variance_percent", "price", "realised_margin", "realised_margin_percent", "contingency_percent_now", "contingency_percent_needed", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "QuoteOutcomes":
        if sum(self.by_verdict.values()) != len(self.outcomes) or self.scored != sum(1 for row in self.outcomes if row.verdict in ("held", "overran", "underquoted")):
            raise ValueError("by_verdict counts every outcome and scored counts the costed ones")
        if not skip_digests(info) and self.outcomes_digest != sealed_digest(QuoteOutcomes, self, "outcomes_digest"):
            raise ValueError("outcomes_digest must commit the exact document")
        return self

    def outcome(self, job_ref: str) -> QuoteOutcome | None:
        return next((row for row in self.outcomes if row.job_ref == job_ref), None)

    def render(self) -> str:
        lines = [f"**Quote outcomes {self.company_ref}** as of {self.as_of[:10]}: {self.verdict}"]
        lines.extend(f"- {row.job_ref}: [{row.verdict}] {row.rationale}" for row in self.outcomes)
        return "\n".join(lines)


def score_quote_outcomes(plan: QuoteOutcomesPlan | Mapping[str, Any], *, quotes: Sequence[Mapping[str, Any] | Any], costing: Mapping[str, Any] | Any, contingency_percent: Any = "15", as_of: str) -> QuoteOutcomes:
    """The sealed outcome of every quote against the costed jobs, with the contingency the overruns say to carry."""

    from lightbulb.job_costing import verify_job_costing
    from lightbulb.job_quote import verify_job_quote

    parsed_plan = plan if isinstance(plan, QuoteOutcomesPlan) else QuoteOutcomesPlan.model_validate(detached(plan))
    costed = verify_job_costing(costing)
    _require(costed.company_ref == parsed_plan.company_ref and costed.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the job costing names another company or currency")
    at = timestamp(as_of, field_name="as_of")
    now_contingency = decimal_value(contingency_percent, field_name="contingency_percent")
    jobs = {row.work_order_ref: row for row in costed.jobs}
    tolerance = parsed_plan.cost_tolerance_percent
    minimum = parsed_plan.minimum_margin_percent
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    digests: list[str] = [costed.costing_digest]
    seen: set[str] = set()
    overruns: list[Decimal] = []
    for raw in quotes:
        quote = verify_job_quote(raw)
        _require(quote.company_ref == parsed_plan.company_ref and quote.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"quote {quote.job_ref} names another company or currency")
        _require(quote.job_ref not in seen, "QUOTE_DUPLICATED", f"quote {quote.job_ref} is supplied twice")
        seen.add(quote.job_ref)
        digests.append(quote.quote_digest)
        stretch = any(line.stretch_skills for line in quote.team)
        quoted_hours = _money(sum((Decimal(str(line.hours)) for line in quote.team), Decimal("0")))
        loaded = Decimal(str(quote.loaded_cost))
        price = None if quote.offered_price is None and quote.target_price is None else Decimal(str(quote.offered_price if quote.offered_price is not None else quote.target_price))
        basis = "offer" if quote.offered_price is not None else "target"
        quoted_margin = None if price is None or price <= 0 else _pct((price - loaded) / price * _HUNDRED)
        key = str(getattr(quote, "source_ref", None) or quote.job_ref)
        job = next((jobs[candidate] for candidate in (key, key.split(":", 1)[-1], quote.job_ref, quote.job_ref.split(":", 1)[-1]) if candidate in jobs), None)
        base = {"job_ref": quote.job_ref, "work_order_ref": None if job is None else job.work_order_ref, "quote_digest": quote.quote_digest, "quote_verdict": quote.verdict, "stretch": stretch, "quoted_hours": str(quoted_hours), "direct_cost": str(_money(quote.direct_cost)), "contingency_cost": str(_money(quote.contingency_cost)), "loaded_cost": str(_money(loaded)), "price": None if price is None else str(_money(price)), "price_basis": basis, "quoted_margin_percent": None if quoted_margin is None else str(quoted_margin)}
        if job is None:
            verdict, rationale = "unmatched", f"no costed job carries {key}; the quote cannot be scored"
            rows.append({**base, "verdict": verdict, "rationale": rationale[:300]})
            counts[verdict] = counts.get(verdict, 0) + 1
            continue
        if job.completed_at is None:
            verdict, rationale = "open", f"{job.work_order_ref} is {job.status}; {_money(job.actual_cost)} spent to date against {_money(loaded)} quoted"
            rows.append({**base, "actual_hours": str(_money(job.labour_hours)), "actual_cost": str(_money(job.actual_cost)), "verdict": verdict, "rationale": rationale[:300]})
            counts[verdict] = counts.get(verdict, 0) + 1
            continue
        actual_hours = Decimal(str(job.labour_hours))
        actual_cost = Decimal(str(job.actual_cost))
        labour_cost = Decimal(str(job.labour_cost)) + Decimal(str(job.contractor_cost))
        unquoted = _money(Decimal(str(job.parts_cost)) + Decimal(str(job.stock_cost)))
        hours_variance = None if quoted_hours <= 0 else _pct((actual_hours - quoted_hours) / quoted_hours * _HUNDRED)
        cost_variance = _money(labour_cost - loaded)
        cost_variance_pct = None if loaded <= 0 else _pct(cost_variance / loaded * _HUNDRED)
        realised = None if price is None else _money(price - actual_cost)
        realised_pct = None if price is None or price <= 0 else _pct((price - actual_cost) / price * _HUNDRED)
        if cost_variance_pct is not None and cost_variance_pct > tolerance:
            verdict = "overran"
            rationale = f"labour {_money(labour_cost)} against {_money(loaded)} quoted ({cost_variance_pct:+}%), past the {tolerance}% tolerance; hours {_money(actual_hours)} against {quoted_hours}" + (f"; parts and stock {unquoted} were not in the quote" if unquoted > 0 else "") + (f"; margin {realised_pct}% at {_money(price)}" if realised_pct is not None else "")
            if stretch:
                direct = Decimal(str(quote.direct_cost))
                if direct > 0:
                    overruns.append(_pct((labour_cost - direct) / direct * _HUNDRED))
        elif realised_pct is not None and realised_pct < minimum:
            verdict = "underquoted"
            rationale = f"labour {_money(labour_cost)} inside {_money(loaded)} quoted" + (f", but parts and stock {unquoted} were not in the quote" if unquoted > 0 else "") + f"; {_money(price)} ({basis}) left {realised_pct}% margin on {_money(actual_cost)}, under the {minimum}% minimum"
        else:
            verdict = "held"
            rationale = f"labour {_money(labour_cost)} against {_money(loaded)} quoted ({cost_variance_pct if cost_variance_pct is not None else 'n/a'}%); hours {_money(actual_hours)} against {quoted_hours}" + (f"; parts and stock {unquoted} were not in the quote" if unquoted > 0 else "") + (f"; margin {realised_pct}% at {_money(price)}" if realised_pct is not None else "; no price to measure a margin")
        rows.append({**base, "actual_hours": str(_money(actual_hours)), "hours_variance_percent": None if hours_variance is None else str(hours_variance), "actual_labour_cost": str(_money(labour_cost)), "unquoted_cost": str(unquoted), "actual_cost": str(_money(actual_cost)), "cost_variance": str(cost_variance), "cost_variance_percent": None if cost_variance_pct is None else str(cost_variance_pct), "realised_margin_percent": None if realised_pct is None else str(realised_pct), "realised_margin": None if realised is None else str(realised), "verdict": verdict, "rationale": rationale[:300]})
        counts[verdict] = counts.get(verdict, 0) + 1
    order = {"overran": 0, "underquoted": 1, "held": 2, "open": 3, "unmatched": 4}
    rows.sort(key=lambda row: (order[row["verdict"]], -Decimal(row.get("cost_variance") or "0"), row["job_ref"]))
    scored = [row for row in rows if row["verdict"] in ("held", "overran", "underquoted")]
    quoted_hours_total = _money(sum((Decimal(row["quoted_hours"]) for row in scored), Decimal("0")))
    actual_hours_total = _money(sum((Decimal(row["actual_hours"]) for row in scored), Decimal("0")))
    loaded_total = _money(sum((Decimal(row["loaded_cost"]) for row in scored), Decimal("0")))
    actual_total = _money(sum((Decimal(row["actual_labour_cost"]) for row in scored), Decimal("0")))
    unquoted_total = _money(sum((Decimal(row["unquoted_cost"]) for row in scored), Decimal("0")))
    price_total = _money(sum((Decimal(row["price"]) for row in scored if row["price"] is not None), Decimal("0")))
    priced_cost = _money(sum((Decimal(row["actual_cost"]) for row in scored if row["price"] is not None), Decimal("0")))
    realised_total = _money(price_total - priced_cost)
    realised_total_pct = None if price_total <= 0 else _pct(realised_total / price_total * _HUNDRED)
    variances = [Decimal(row["cost_variance_percent"]) for row in scored if row["cost_variance_percent"] is not None]
    mean_variance = None if not variances else _pct(sum(variances, Decimal("0")) / len(variances))
    needed = None if not overruns else _pct(max(sum(overruns, Decimal("0")) / len(overruns), now_contingency))
    recommendations: list[str] = []
    for row in rows:
        if row["verdict"] in ("overran", "underquoted"):
            recommendations.append(f"{row['job_ref']}: {row['verdict']}; {row['rationale']}")
    if needed is not None and needed > now_contingency:
        recommendations.append(f"stretch quotes overran their direct cost by {needed}% on average against a {now_contingency}% contingency; carry {needed}% on stretch teams")
    if not recommendations:
        recommendations.append("every costed quote held" if scored else "no quote has a completed, costed job yet")
    verdict = f"{len(scored)} quote(s) scored: {counts.get('held', 0)} held, {counts.get('overran', 0)} overran, {counts.get('underquoted', 0)} underquoted; {counts.get('open', 0)} open, {counts.get('unmatched', 0)} unmatched; labour {actual_total} against {loaded_total} quoted" + (f" plus {unquoted_total} of parts and stock not quoted" if unquoted_total > 0 else "") + (f", realised margin {realised_total_pct}%" if realised_total_pct is not None else "")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "costing_digest": costed.costing_digest, "outcomes": rows, "scored": len(scored), "by_verdict": counts, "quoted_hours": str(quoted_hours_total), "actual_hours": str(actual_hours_total), "loaded_cost": str(loaded_total), "actual_cost": str(actual_total), "unquoted_cost": str(unquoted_total), "cost_variance": str(_money(actual_total - loaded_total)), "mean_cost_variance_percent": None if mean_variance is None else str(mean_variance), "price": str(price_total), "realised_margin": str(realised_total), "realised_margin_percent": None if realised_total_pct is None else str(realised_total_pct), "contingency_percent_now": str(_pct(now_contingency)), "contingency_percent_needed": None if needed is None else str(needed), "verdict": verdict[:300], "recommendations": [row[:300] for row in recommendations[:24]], "source_digests": digests}
    return seal(QuoteOutcomes, payload, "outcomes_digest")


def verify_quote_outcomes(value: Any) -> QuoteOutcomes:
    return value if isinstance(value, QuoteOutcomes) else QuoteOutcomes.model_validate(dict(detached(value)))


QUOTE_OUTCOMES_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "quote_outcomes",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["verify_quotes_and_costing", "bind_quote_to_costed_job", "hours_and_cost_against_the_quote", "margin_realised_at_the_price", "contingency_from_overruns", "seal_outcomes"],
    "verdicts": list(VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a quote is scored only by a completed, costed job bound by the quote's work order (source ref) or job ref; open and unmatched quotes are named, never estimated",
        "the contingency needed is the mean overrun of stretch quotes on their direct cost, never below the contingency carried now",
        "nothing here judges why a job overran, reads a provider, or persists anything",
    ],
}

__all__ = ["QUOTE_OUTCOMES_MANIFEST", "QUOTE_OUTCOMES_PLAN_SCHEMA", "QUOTE_OUTCOMES_SCHEMA", "VERDICTS", "QuoteOutcome", "QuoteOutcomes", "QuoteOutcomesError", "QuoteOutcomesPlan", "compile_quote_outcomes_plan", "score_quote_outcomes", "verify_quote_outcomes"]
