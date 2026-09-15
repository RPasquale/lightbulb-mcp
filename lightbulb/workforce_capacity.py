"""Workforce capacity: week by week, the hours each skill is asked for against the hours the qualified people can give, and what the bench costs.

The sourcing plan closes one gap at a time.  The capacity plan looks
across the horizon: ``build_workforce_capacity`` spreads every job's
hours evenly over its window and across its requirements by weight,
credits every qualified worker's weekly hours to each skill they hold at
the level the week demands (a worker who holds three skills is counted
in all three, and the document says so), and seals per week and skill
the demand, the supply, the utilisation, the shortfall, and the bench.
Per skill it names the peak shortfall week, the weeks short in a row
(the case for a hire rather than a contractor), and the bench hours and
their cost at the qualified workers' average cost rate; per worker it
sizes the hours on offer against the hours the skills they hold are
asked for.  Nothing here assigns anyone, predicts demand, reads a
provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
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
    iso,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.skills_matching import JobRequirements, SkillsMatchingPlan, SkillsTaxonomy, WorkerProfile, effective_levels, evidence_from_work_orders, with_evidence

WORKFORCE_CAPACITY_SCHEMA = "lightbulb.workforce_capacity.v1"
WEEK_STATUSES: tuple[str, ...] = ("short", "tight", "balanced", "bench", "quiet")
WeekStatus = Literal["short", "tight", "balanced", "bench", "quiet"]
_HUNDRED = Decimal("100")
_HOURS = Decimal("0.01")


class WorkforceCapacityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WorkforceCapacityError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _hours(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_HOURS, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class WeekCapacity(StrictModel):
    week_start: str
    skill_ref: OpaqueRef
    required_level: int = Field(ge=1, le=5)
    demand_hours: Decimal
    supply_hours: Decimal
    qualified_workers: int = Field(ge=0)
    utilisation_percent: Decimal | None = None
    shortfall_hours: Decimal
    bench_hours: Decimal
    status: WeekStatus

    @field_validator("demand_hours", "supply_hours", "utilisation_percent", "shortfall_hours", "bench_hours", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class SkillCapacitySummary(StrictModel):
    skill_ref: OpaqueRef
    demand_hours: Decimal
    supply_hours: Decimal
    shortfall_hours: Decimal
    bench_hours: Decimal
    bench_cost: Decimal
    peak_shortfall_week: str | None = None
    peak_shortfall_hours: Decimal
    weeks_short: int = Field(ge=0)
    longest_run_short: int = Field(ge=0)
    recommendation: ShortText

    @field_validator("demand_hours", "supply_hours", "shortfall_hours", "bench_hours", "bench_cost", "peak_shortfall_hours", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class WorkerLoad(StrictModel):
    worker_ref: OpaqueRef
    kind: ShortText
    skills_held: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    offered_hours: Decimal
    asked_hours: Decimal
    load_percent: Decimal | None = None
    note: ShortText

    @field_validator("skills_held", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("offered_hours", "asked_hours", "load_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class WorkforceCapacity(StrictModel):
    schema_id: str = Field(default=WORKFORCE_CAPACITY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    horizon_start: str
    horizon_end: str
    weeks: int = Field(ge=1, le=104)
    plan_digest: Sha256Digest
    taxonomy_digest: Sha256Digest
    cells: tuple[WeekCapacity, ...] = Field(default_factory=tuple, max_length=20000)
    skills: tuple[SkillCapacitySummary, ...] = Field(default_factory=tuple, max_length=2000)
    workers: tuple[WorkerLoad, ...] = Field(default_factory=tuple, max_length=5000)
    demand_hours: Decimal
    supply_hours: Decimal
    shortfall_hours: Decimal
    bench_hours: Decimal
    bench_cost: Decimal
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    capacity_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("cells", "skills", "workers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("demand_hours", "supply_hours", "shortfall_hours", "bench_hours", "bench_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkforceCapacity":
        if not skip_digests(info) and self.capacity_digest != sealed_digest(WorkforceCapacity, self, "capacity_digest"):
            raise ValueError("capacity_digest must commit the exact document")
        return self

    def cell(self, week_start: str, skill_ref: str) -> WeekCapacity | None:
        return next((cell for cell in self.cells if cell.week_start == week_start and cell.skill_ref == skill_ref), None)

    def skill(self, skill_ref: str) -> SkillCapacitySummary | None:
        return next((row for row in self.skills if row.skill_ref == skill_ref), None)

    def render(self) -> str:
        lines = [f"**Workforce capacity {self.company_ref}** {self.horizon_start[:10]} to {self.horizon_end[:10]} ({self.weeks} week(s)): demand {self.demand_hours}h against {self.supply_hours}h qualified supply; shortfall {self.shortfall_hours}h, bench {self.bench_hours}h costing {self.bench_cost} {self.currency}."]
        for row in self.skills:
            lines.append(f"- {row.skill_ref}: {row.recommendation}")
        return "\n".join(lines)


def _overlap(start: datetime, end: datetime, week_start: datetime, week_end: datetime) -> Decimal:
    begin, finish = max(start, week_start), min(end, week_end)
    return Decimal("0") if finish <= begin else Decimal((finish - begin).total_seconds()) / Decimal(7 * 86400)


def build_workforce_capacity(plan: SkillsMatchingPlan | Mapping[str, Any], *, taxonomy: SkillsTaxonomy | Mapping[str, Any], profiles: Sequence[WorkerProfile | Mapping[str, Any]], jobs: Sequence[JobRequirements | Mapping[str, Any]], work_order_states: Sequence[tuple[Any, Any]] = (), as_of: str, weeks: int = 8) -> WorkforceCapacity:
    """The sealed weekly capacity plan: demand from the jobs spread over their windows, supply from the qualified workers' weekly hours."""

    parsed_plan = plan if isinstance(plan, SkillsMatchingPlan) else SkillsMatchingPlan.model_validate(detached(plan))
    parsed_taxonomy = taxonomy if isinstance(taxonomy, SkillsTaxonomy) else SkillsTaxonomy.model_validate(detached(taxonomy))
    _require(parsed_taxonomy.company_ref == parsed_plan.company_ref, "SCOPE_MISMATCH", "the taxonomy names another company")
    _require(1 <= weeks <= 104, "HORIZON_INVALID", "weeks is between 1 and 104")
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    _require(len({worker.worker_ref for worker in workers}) == len(workers), "WORKER_DUPLICATE", "worker refs must be unique")
    parsed_jobs = [item if isinstance(item, JobRequirements) else JobRequirements.model_validate(detached(item)) for item in jobs]
    _require(bool(parsed_jobs), "JOBS_MISSING", "plan capacity against at least one job")
    for job in parsed_jobs:
        _require(job.currency == parsed_plan.currency, "SCOPE_MISMATCH", f"job {job.job_ref} is priced in {job.currency}, the plan in {parsed_plan.currency}")
        for requirement in job.requirements:
            _require(parsed_taxonomy.skill(requirement.skill_ref) is not None, "SKILL_UNKNOWN", f"job {job.job_ref} requires {requirement.skill_ref}, which the taxonomy does not define")
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    horizon_start = now - timedelta(days=now.weekday(), hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond)
    digests: list[str] = []
    if work_order_states:
        from lightbulb.work_order_chain import WORK_ORDER_LIFECYCLE

        extra = evidence_from_work_orders(work_order_states, parsed_jobs, taxonomy=parsed_taxonomy)
        workers = [with_evidence(worker, extra[worker.worker_ref]) if worker.worker_ref in extra else worker for worker in workers]
        digests.extend(WORK_ORDER_LIFECYCLE.bind(plan_doc, state_doc)[1].state_digest for plan_doc, state_doc in work_order_states)
    standings = {worker.worker_ref: effective_levels(parsed_taxonomy, parsed_plan, worker, as_of=at) for worker in workers}
    cells: list[dict[str, Any]] = []
    per_skill: dict[str, list[dict[str, Any]]] = {}
    asked: dict[str, Decimal] = {worker.worker_ref: Decimal("0") for worker in workers}
    offered: dict[str, Decimal] = {worker.worker_ref: Decimal("0") for worker in workers}
    for index in range(weeks):
        week_start = horizon_start + timedelta(days=7 * index)
        week_end = week_start + timedelta(days=7)
        demand: dict[str, Decimal] = {}
        level: dict[str, int] = {}
        for job in parsed_jobs:
            start, end = parsed(job.starts_at), parsed(job.due_at)
            share = _overlap(start, end, week_start, week_end) * Decimal(7 * 86400) / Decimal((end - start).total_seconds())
            if share <= 0:
                continue
            total_weight = sum((item.weight for item in job.requirements), Decimal("0"))
            for requirement in job.requirements:
                demand[requirement.skill_ref] = demand.get(requirement.skill_ref, Decimal("0")) + job.hours_required * share * requirement.weight / total_weight
                level[requirement.skill_ref] = max(level.get(requirement.skill_ref, 0), requirement.minimum_level)
        for worker in workers:
            begin = max(week_start, parsed(worker.available_from)) if worker.available_from else week_start
            finish = min(week_end, parsed(worker.available_until)) if worker.available_until else week_end
            offered[worker.worker_ref] += worker.hours_per_week * _overlap(begin, finish, week_start, week_end) if finish > begin else Decimal("0")
        for skill_ref in sorted(demand):
            need = _hours(demand[skill_ref])
            required = level[skill_ref]
            qualified: list[WorkerProfile] = []
            supply = Decimal("0")
            for worker in workers:
                if standings[worker.worker_ref][skill_ref].effective_level < Decimal(required):
                    continue
                begin = max(week_start, parsed(worker.available_from)) if worker.available_from else week_start
                finish = min(week_end, parsed(worker.available_until)) if worker.available_until else week_end
                hours = worker.hours_per_week * _overlap(begin, finish, week_start, week_end) if finish > begin else Decimal("0")
                if hours > 0:
                    qualified.append(worker)
                    supply += hours
                    asked[worker.worker_ref] += need / max(1, len([w for w in workers if standings[w.worker_ref][skill_ref].effective_level >= Decimal(required)]))
            supply = _hours(supply)
            shortfall = _hours(max(need - supply, Decimal("0")))
            bench = _hours(max(supply - need, Decimal("0")))
            utilisation = None if supply <= 0 else (need / supply * _HUNDRED).quantize(_HOURS, rounding=ROUND_HALF_UP)
            status = "short" if shortfall > 0 else "tight" if utilisation is not None and utilisation >= Decimal("90") else "balanced" if utilisation is not None and utilisation >= Decimal("60") else "bench"
            cell = {"week_start": iso(week_start), "skill_ref": skill_ref, "required_level": required, "demand_hours": str(need), "supply_hours": str(supply), "qualified_workers": len(qualified), "utilisation_percent": None if utilisation is None else str(utilisation), "shortfall_hours": str(shortfall), "bench_hours": str(bench), "status": status, "_cost": (sum((w.cost_rate for w in qualified), Decimal("0")) / len(qualified)) if qualified else Decimal("0")}
            cells.append(cell)
            per_skill.setdefault(skill_ref, []).append(cell)
    summaries: list[dict[str, Any]] = []
    for skill_ref, rows in sorted(per_skill.items()):
        demand_total = sum((Decimal(row["demand_hours"]) for row in rows), Decimal("0"))
        supply_total = sum((Decimal(row["supply_hours"]) for row in rows), Decimal("0"))
        shortfall_total = sum((Decimal(row["shortfall_hours"]) for row in rows), Decimal("0"))
        bench_total = sum((Decimal(row["bench_hours"]) for row in rows), Decimal("0"))
        bench_cost = _money(sum((Decimal(row["bench_hours"]) * row["_cost"] for row in rows), Decimal("0")))
        peak = max(rows, key=lambda row: (Decimal(row["shortfall_hours"]), row["week_start"]))
        short_weeks = [row for row in rows if Decimal(row["shortfall_hours"]) > 0]
        longest = run = 0
        for row in rows:
            run = run + 1 if Decimal(row["shortfall_hours"]) > 0 else 0
            longest = max(longest, run)
        if shortfall_total > 0 and longest >= 4:
            recommendation = f"short {shortfall_total}h over {len(short_weeks)} week(s), {longest} in a row (peak {peak['shortfall_hours']}h in the week of {peak['week_start'][:10]}): a sustained gap, hire or a standing contractor"
        elif shortfall_total > 0:
            recommendation = f"short {shortfall_total}h over {len(short_weeks)} week(s) (peak {peak['shortfall_hours']}h in the week of {peak['week_start'][:10]}): contract the peak weeks"
        elif bench_total > 0 and demand_total <= 0:
            recommendation = f"no demand over the horizon against {supply_total}h of qualified supply: sell the bench or redeploy"
        elif bench_total > 0:
            recommendation = f"covered: {demand_total}h demand against {supply_total}h supply; {bench_total}h on the bench costing {bench_cost}"
        else:
            recommendation = f"exactly covered: {demand_total}h demand against {supply_total}h supply"
        summaries.append({"skill_ref": skill_ref, "demand_hours": str(_hours(demand_total)), "supply_hours": str(_hours(supply_total)), "shortfall_hours": str(_hours(shortfall_total)), "bench_hours": str(_hours(bench_total)), "bench_cost": str(bench_cost), "peak_shortfall_week": peak["week_start"] if Decimal(peak["shortfall_hours"]) > 0 else None, "peak_shortfall_hours": peak["shortfall_hours"], "weeks_short": len(short_weeks), "longest_run_short": longest, "recommendation": recommendation[:300]})
    summaries.sort(key=lambda row: (-Decimal(row["shortfall_hours"]), row["skill_ref"]))
    worker_rows: list[dict[str, Any]] = []
    for worker in workers:
        held = sorted(skill_ref for skill_ref, standing in standings[worker.worker_ref].items() if standing.effective_level > 0 and skill_ref in per_skill)
        offer, ask = _hours(offered[worker.worker_ref]), _hours(asked[worker.worker_ref])
        load = None if offer <= 0 else (ask / offer * _HUNDRED).quantize(_HOURS, rounding=ROUND_HALF_UP)
        note = f"{ask}h asked of the {len(held)} demanded skill(s) held against {offer}h offered over the horizon" + ("" if load is None else f" ({load}%)") if held else f"holds no skill the horizon demands; {offer}h offered"
        worker_rows.append({"worker_ref": worker.worker_ref, "kind": worker.kind, "skills_held": held, "offered_hours": str(offer), "asked_hours": str(ask), "load_percent": None if load is None else str(load), "note": note[:300]})
    for cell in cells:
        cell.pop("_cost", None)
    recommendations = [f"{row['skill_ref']}: {row['recommendation']}" for row in summaries if Decimal(row["shortfall_hours"]) > 0 or Decimal(row["demand_hours"]) <= 0][:24]
    if not recommendations:
        recommendations.append("every demanded skill is covered across the horizon")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "horizon_start": iso(horizon_start), "horizon_end": iso(horizon_start + timedelta(days=7 * weeks)), "weeks": weeks, "plan_digest": parsed_plan.plan_digest, "taxonomy_digest": parsed_taxonomy.taxonomy_digest,
        "cells": cells, "skills": summaries, "workers": worker_rows, "demand_hours": str(_hours(sum((Decimal(row["demand_hours"]) for row in summaries), Decimal("0")))), "supply_hours": str(_hours(sum((Decimal(row["supply_hours"]) for row in summaries), Decimal("0")))),
        "shortfall_hours": str(_hours(sum((Decimal(row["shortfall_hours"]) for row in summaries), Decimal("0")))), "bench_hours": str(_hours(sum((Decimal(row["bench_hours"]) for row in summaries), Decimal("0")))), "bench_cost": str(_money(sum((Decimal(row["bench_cost"]) for row in summaries), Decimal("0")))),
        "recommendations": [item[:300] for item in recommendations], "source_digests": [parsed_taxonomy.taxonomy_digest, *[worker.profile_digest for worker in workers], *[job.requirements_digest for job in parsed_jobs], *digests],
    }
    return seal(WorkforceCapacity, payload, "capacity_digest")


def verify_workforce_capacity(value: Any) -> WorkforceCapacity:
    return value if isinstance(value, WorkforceCapacity) else WorkforceCapacity.model_validate(dict(detached(value)))


WORKFORCE_CAPACITY_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "workforce_capacity",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["credit_chain_evidence", "compute_standing", "spread_job_hours_by_week", "credit_qualified_supply", "ledger_shortfall_and_bench", "seal_plan"],
    "week_statuses": list(WEEK_STATUSES),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "demand is each job's hours spread evenly over its window and across its requirements by weight",
        "supply is every qualified worker's weekly hours inside their availability; a worker counts toward every demanded skill they hold, and the document says so",
        "four or more weeks short in a row is the case for a hire; fewer is the case for a contractor",
        "nothing here assigns anyone, predicts demand, reads a provider, or persists anything",
    ],
}

__all__ = ["WEEK_STATUSES", "WORKFORCE_CAPACITY_MANIFEST", "WORKFORCE_CAPACITY_SCHEMA", "SkillCapacitySummary", "WeekCapacity", "WorkerLoad", "WorkforceCapacity", "WorkforceCapacityError", "build_workforce_capacity", "verify_workforce_capacity"]
