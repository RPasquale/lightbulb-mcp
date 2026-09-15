"""Job quote: should we take this job at this price? The team that would do it, what it costs loaded, the floor, the target, and the verdict.

A services business loses money one badly priced job at a time.
``build_job_quote`` prices a job the way the rest of the SDK reasons:

* the team is the match report's, from the same corroborated standing
  (claims discounted by the work order chain's recorded hours, licences
  that expire, transfers from adjacent skills); a stretch fit staffs the
  job with a contingency, a short or missing mandatory skill does not, and
  a job the profiles cannot staff is not quoted;
* the direct cost is each team member's cost rate times their share of
  the hours, plus a contingency on the hours of every member who only
  stretches to a requirement;
* the loaded cost carries overhead and the target utilisation, so the
  quote pays for the hours nobody bills;
* the floor price is the loaded cost at the minimum margin, the target
  price at the target margin; against an offered price (or the job's
  budget) the margin is arithmetic and the verdict follows: bid,
  negotiate, no bid, or cannot staff;
* the risks are named: stretch fits, key-person dependencies (a mandatory
  skill only one candidate can cover), and a window the team cannot fill.

Nothing here estimates win probability, reads a provider, or persists
anything.
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
from lightbulb.skills_matching import JobRequirements, SkillsMatchingPlan, SkillsTaxonomy, WorkerProfile, effective_levels, evidence_from_work_orders, match_job, with_evidence

JOB_QUOTE_PLAN_SCHEMA = "lightbulb.job_quote_plan.v1"
JOB_QUOTE_SCHEMA = "lightbulb.job_quote.v1"
QUOTE_VERDICTS: tuple[str, ...] = ("bid", "negotiate", "no_bid", "cannot_staff", "unpriced")
QuoteVerdict = Literal["bid", "negotiate", "no_bid", "cannot_staff", "unpriced"]
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")


class JobQuoteError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise JobQuoteError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _pct(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_PCT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class JobQuotePlan(StrictModel):
    schema_id: str = Field(default=JOB_QUOTE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    target_margin_percent: Decimal = Field(default=Decimal("35"), validate_default=True)
    minimum_margin_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    target_utilisation_percent: Decimal = Field(default=Decimal("75"), validate_default=True)
    overhead_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    stretch_contingency_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_margin_percent", "minimum_margin_percent", "target_utilisation_percent", "overhead_percent", "stretch_contingency_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if info.field_name in ("target_margin_percent", "minimum_margin_percent") and result >= _HUNDRED:
            raise ValueError(f"{info.field_name} is below 100")
        if info.field_name == "target_utilisation_percent" and not Decimal("0") < result <= _HUNDRED:
            raise ValueError("target_utilisation_percent is in (0, 100]")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobQuotePlan":
        if self.minimum_margin_percent > self.target_margin_percent:
            raise ValueError("minimum_margin_percent is at most target_margin_percent")
        if not skip_digests(info) and self.plan_digest != sealed_digest(JobQuotePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_job_quote_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> JobQuotePlan:
    return seal(JobQuotePlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class QuoteLine(StrictModel):
    worker_ref: OpaqueRef
    kind: ShortText
    verdict: ShortText
    hours: Decimal
    cost_rate: Decimal
    cost: Decimal
    contingency_hours: Decimal
    contingency_cost: Decimal
    stretch_skills: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("stretch_skills", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours", "cost_rate", "cost", "contingency_hours", "contingency_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class JobQuote(StrictModel):
    schema_id: str = Field(default=JOB_QUOTE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    job_ref: OpaqueRef
    source_ref: OpaqueRef | None = None
    requirements_digest: Sha256Digest
    hours_required: Decimal
    headcount: int = Field(ge=1)
    staffed: bool
    team: tuple[QuoteLine, ...] = Field(default_factory=tuple, max_length=500)
    direct_cost: Decimal
    contingency_cost: Decimal
    loaded_cost: Decimal
    floor_price: Decimal
    target_price: Decimal
    offered_price: Decimal | None = None
    margin_at_offer_percent: Decimal | None = None
    verdict: QuoteVerdict
    risks: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    gaps: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    rationale: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    quote_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("team", "risks", "gaps", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_required", "direct_cost", "contingency_cost", "loaded_cost", "floor_price", "target_price", "offered_price", "margin_at_offer_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobQuote":
        if not skip_digests(info) and self.quote_digest != sealed_digest(JobQuote, self, "quote_digest"):
            raise ValueError("quote_digest must commit the exact quote")
        return self

    def render(self) -> str:
        lines = [f"**Job quote {self.job_ref}** ({self.company_ref}, as of {self.as_of[:10]}) [{self.verdict}]: {self.rationale}"]
        for line in self.team:
            lines.append(f"- {line.worker_ref} ({line.kind}, {line.verdict}): {line.hours}h at {line.cost_rate}/h = {line.cost}" + (f" + {line.contingency_hours}h contingency on {', '.join(line.stretch_skills)}" if line.contingency_hours > 0 else ""))
        lines.extend(f"- risk: {item}" for item in self.risks)
        lines.extend(f"- gap: {item}" for item in self.gaps)
        return "\n".join(lines)


def build_job_quote(plan: JobQuotePlan | Mapping[str, Any], *, job: JobRequirements | Mapping[str, Any], taxonomy: SkillsTaxonomy | Mapping[str, Any], matching_plan: SkillsMatchingPlan | Mapping[str, Any], profiles: Sequence[WorkerProfile | Mapping[str, Any]], work_order_states: Sequence[tuple[Any, Any]] = (), offered_price: Any | None = None, as_of: str) -> JobQuote:
    """The sealed quote: the matched team, its direct and loaded cost, the floor and target prices, and the verdict against the offered price or the job's budget."""

    parsed_plan = plan if isinstance(plan, JobQuotePlan) else JobQuotePlan.model_validate(detached(plan))
    parsed_job = job if isinstance(job, JobRequirements) else JobRequirements.model_validate(detached(job))
    parsed_taxonomy = taxonomy if isinstance(taxonomy, SkillsTaxonomy) else SkillsTaxonomy.model_validate(detached(taxonomy))
    parsed_matching = matching_plan if isinstance(matching_plan, SkillsMatchingPlan) else SkillsMatchingPlan.model_validate(detached(matching_plan))
    _require(parsed_taxonomy.company_ref == parsed_plan.company_ref and parsed_matching.company_ref == parsed_plan.company_ref and parsed_matching.currency == parsed_plan.currency and parsed_job.currency == parsed_plan.currency, "SCOPE_MISMATCH", "the taxonomy, matching plan, and job must name this company and currency")
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    _require(len({worker.worker_ref for worker in workers}) == len(workers), "WORKER_DUPLICATE", "worker refs must be unique")
    at = timestamp(as_of, field_name="as_of")
    digests: list[str] = [parsed_job.requirements_digest, parsed_taxonomy.taxonomy_digest, parsed_matching.plan_digest]
    if work_order_states:
        from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

        extra = evidence_from_work_orders(work_order_states, [parsed_job], taxonomy=parsed_taxonomy)
        workers = [with_evidence(worker, extra[worker.worker_ref]) if worker.worker_ref in extra else worker for worker in workers]
        digests.extend(WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)[1].state_digest for plan_doc, state_doc in work_order_states)
    digests.extend(worker.profile_digest for worker in workers)
    standings = {worker.worker_ref: effective_levels(parsed_taxonomy, parsed_matching, worker, as_of=at) for worker in workers}
    match = match_job(parsed_taxonomy, parsed_matching, parsed_job, workers, as_of=at, standings=standings)
    by_ref = {worker.worker_ref: worker for worker in workers}
    candidates = {row.worker_ref: row for row in match.candidates}
    hours_per_head = parsed_job.hours_per_head
    team: list[dict[str, Any]] = []
    risks: list[str] = []
    for worker_ref in match.team:
        row = candidates[worker_ref]
        worker = by_ref[worker_ref]
        stretch = [fit.skill_ref for fit in row.fits if fit.status == "stretch"]
        contingency_hours = (hours_per_head * parsed_plan.stretch_contingency_percent / _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP) if stretch else Decimal("0")
        cost = _money(worker.cost_rate * hours_per_head)
        contingency = _money(worker.cost_rate * contingency_hours)
        if stretch:
            risks.append(f"{worker_ref} stretches to {', '.join(stretch)}: {contingency_hours}h contingency at {worker.cost_rate}/h")
        team.append({"worker_ref": worker_ref, "kind": worker.kind, "verdict": row.verdict, "hours": str(hours_per_head), "cost_rate": str(worker.cost_rate), "cost": str(cost), "contingency_hours": str(contingency_hours), "contingency_cost": str(contingency), "stretch_skills": stretch})
    for requirement in parsed_job.requirements:
        if not requirement.mandatory:
            continue
        able = [row.worker_ref for row in match.candidates if row.verdict in ("fit", "stretch") and next(fit for fit in row.fits if fit.skill_ref == requirement.skill_ref).status in ("met", "stretch")]
        if len(able) == 1 and match.team:
            risks.append(f"{requirement.skill_ref} rests on {able[0]} alone among the candidates")
    stretched = {fit.skill_ref for worker_ref in match.team for fit in candidates[worker_ref].fits if fit.status == "stretch"}
    hard_gaps = [gap for gap in match.gaps if gap.mandatory and gap.skill_ref not in stretched]
    staffed = len(match.team) == parsed_job.headcount and not hard_gaps
    gaps = [f"{gap.skill_ref} at level {gap.minimum_level}: {gap.note}" for gap in hard_gaps]
    direct = _money(sum((Decimal(line["cost"]) for line in team), Decimal("0")))
    contingency = _money(sum((Decimal(line["contingency_cost"]) for line in team), Decimal("0")))
    loaded = _money((direct + contingency) * (Decimal("1") + parsed_plan.overhead_percent / _HUNDRED) / (parsed_plan.target_utilisation_percent / _HUNDRED))
    floor = _money(loaded / (Decimal("1") - parsed_plan.minimum_margin_percent / _HUNDRED))
    target = _money(loaded / (Decimal("1") - parsed_plan.target_margin_percent / _HUNDRED))
    offer = None if offered_price is None else _money(decimal_value(offered_price, field_name="offered_price"))
    if offer is None and parsed_job.budget is not None:
        offer = _money(parsed_job.budget)
    margin = None if offer is None or offer <= 0 or not staffed else _pct((offer - loaded) / offer * _HUNDRED)
    if not staffed:
        verdict = "cannot_staff"
        rationale = f"{len(match.team)} of {parsed_job.headcount} head(s) found" + (f"; mandatory gaps: {', '.join(gap.skill_ref for gap in hard_gaps)}" if gaps else "") + "; source the gap before quoting"
    elif offer is None:
        verdict = "unpriced"
        rationale = f"loaded cost {loaded}; quote at least {floor} (the {parsed_plan.minimum_margin_percent}% floor) and aim for {target} (the {parsed_plan.target_margin_percent}% target)"
    elif margin is not None and margin >= parsed_plan.target_margin_percent:
        verdict = "bid"
        rationale = f"{offer} earns {margin}% on a loaded cost of {loaded}, at or above the {parsed_plan.target_margin_percent}% target"
    elif margin is not None and margin >= parsed_plan.minimum_margin_percent:
        verdict = "negotiate"
        rationale = f"{offer} earns {margin}% on a loaded cost of {loaded}, above the {parsed_plan.minimum_margin_percent}% floor but under the {parsed_plan.target_margin_percent}% target; ask {target}"
    else:
        verdict = "no_bid"
        rationale = f"{offer} earns {margin}% on a loaded cost of {loaded}, under the {parsed_plan.minimum_margin_percent}% floor of {floor}"
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "job_ref": parsed_job.job_ref, "source_ref": parsed_job.source_ref, "requirements_digest": parsed_job.requirements_digest, "hours_required": str(parsed_job.hours_required), "headcount": parsed_job.headcount, "staffed": staffed,
        "team": team, "direct_cost": str(direct), "contingency_cost": str(contingency), "loaded_cost": str(loaded), "floor_price": str(floor), "target_price": str(target), "offered_price": None if offer is None else str(offer), "margin_at_offer_percent": None if margin is None else str(margin),
        "verdict": verdict, "risks": [item[:300] for item in risks[:24]], "gaps": [item[:300] for item in gaps[:50]], "rationale": rationale[:300], "source_digests": digests,
    }
    return seal(JobQuote, payload, "quote_digest")


def verify_job_quote(value: Any) -> JobQuote:
    return value if isinstance(value, JobQuote) else JobQuote.model_validate(dict(detached(value)))


JOB_QUOTE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "job_quote",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["credit_chain_evidence", "match_team", "direct_cost_and_contingency", "load_for_unbilled_hours", "floor_and_target", "verdict_against_offer", "seal_quote"],
    "verdicts": list(QUOTE_VERDICTS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the team is the match report's; a job the profiles cannot staff is not quoted",
        "cost is the team's cost rates times their hours plus a contingency on every stretch; the loaded cost carries overhead and the target utilisation",
        "the floor is the loaded cost at the minimum margin and the target at the target margin; the verdict is arithmetic against the offered price or the job's budget",
        "nothing here estimates win probability, reads a provider, or persists anything",
    ],
}

__all__ = ["JOB_QUOTE_MANIFEST", "JOB_QUOTE_PLAN_SCHEMA", "JOB_QUOTE_SCHEMA", "QUOTE_VERDICTS", "JobQuote", "JobQuoteError", "JobQuotePlan", "QuoteLine", "build_job_quote", "compile_job_quote_plan", "verify_job_quote"]
