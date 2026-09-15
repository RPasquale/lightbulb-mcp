"""Labour sourcing: close every skill gap the match report named by the cheapest feasible route, and say why.

The skills match report says which jobs are short of which skills.  This
module turns each gap into a procurement decision the operator can act
on, with the alternatives priced side by side:

* **assign** a worker already on the books (employee or engaged contractor)
  who holds the level and has the hours free in the window, at their cost
  rate: the gap was one of team composition, not of skill;
* **upskill** an employee already within the plan's reach of the level,
  if the training (weeks per level) finishes before the job starts and
  they have the hours free: training hours plus the job hours at their
  cost rate;
* **contract** the skill at the typed market rate for the job's hours,
  if a rate is typed and the contractor lead time fits;
* **hire** into a role that carries the skill at the required level,
  priced from the hiring chain's pay band (or the role's typed rate),
  only when the demand for that skill across the window is recurring
  (at least the plan's hours a week) and the hiring lead time lands
  before the job starts.

The cheapest feasible option wins; ties go make-before-buy (assign,
upskill, contract, hire).  A skill capacity ledger sets demand hours per skill
against the hours of qualified workers in the window, and structural
shortfalls with recurring demand become requisitions shaped for the
hiring chain.  Every option carries its cost, lead time, and the reason
it is feasible or not.  Nothing here reads a provider, opens a
requisition, engages anyone, or persists anything.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import timedelta
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
from lightbulb.skills_matching import JobRequirements, SkillsMatchingPlan, SkillsTaxonomy, WorkerProfile, effective_levels, verify_skills_match_report

LABOUR_SOURCING_PLAN_SCHEMA = "lightbulb.labour_sourcing_plan.v1"
LABOUR_SOURCING_SCHEMA = "lightbulb.labour_sourcing.v1"
SOURCING_KINDS: tuple[str, ...] = ("assign", "upskill", "contract", "hire", "escalate")
CAPACITY_STATUSES: tuple[str, ...] = ("short", "tight", "covered", "idle", "unused")
SourcingKind = Literal["assign", "upskill", "contract", "hire", "escalate"]
CapacityStatus = Literal["short", "tight", "covered", "idle", "unused"]
_HOURS = Decimal("0.01")
_PCT = Decimal("0.01")
_HUNDRED = Decimal("100")
_PREFERENCE = {"assign": 0, "upskill": 1, "contract": 2, "hire": 3, "escalate": 4}


class LabourSourcingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise LabourSourcingError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class RoleDefinition(StrictModel):
    role_ref: OpaqueRef
    title: ShortText
    skills: dict[str, int] = Field(default_factory=dict)
    hours_per_week: Decimal = Field(default=Decimal("38"), validate_default=True)
    pay_rate: Decimal | None = None
    pay_rate_uom: Literal["hour", "year"] | None = None

    @field_validator("skills", mode="before")
    @classmethod
    def _levels(cls, value: object) -> object:
        if isinstance(value, Mapping):
            out = {str(key): int(level) for key, level in value.items()}
            if any(not 1 <= level <= 5 for level in out.values()) or not out:
                raise ValueError("a role carries at least one skill at a level from 1 to 5")
            return out
        return value

    @field_validator("hours_per_week", "pay_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class LabourSourcingPlan(StrictModel):
    schema_id: str = Field(default=LABOUR_SOURCING_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    roles: tuple[RoleDefinition, ...] = Field(default_factory=tuple, max_length=500)
    market_rates: dict[str, Decimal] = Field(default_factory=dict)
    hire_threshold_hours_per_week: Decimal = Field(default=Decimal("20"), validate_default=True)
    hiring_lead_weeks: int = Field(default=8, ge=0, le=104)
    contractor_lead_weeks: int = Field(default=1, ge=0, le=52)
    upskill_weeks_per_level: int = Field(default=6, ge=1, le=104)
    upskill_hours_per_level: Decimal = Field(default=Decimal("40"), validate_default=True)
    upskill_max_levels: int = Field(default=1, ge=0, le=4)
    recruiting_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    annual_hours: Decimal = Field(default=Decimal("2080"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("roles", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("market_rates", mode="before")
    @classmethod
    def _rates(cls, value: object) -> object:
        if isinstance(value, Mapping):
            out = {str(key): decimal_value(rate, field_name=f"market_rates[{key}]") for key, rate in value.items()}
            if any(rate <= 0 for rate in out.values()):
                raise ValueError("a market rate is positive")
            return out
        return value

    @field_validator("hire_threshold_hours_per_week", "upskill_hours_per_level", "recruiting_cost", "annual_hours", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "LabourSourcingPlan":
        refs = [role.role_ref for role in self.roles]
        if len(set(refs)) != len(refs):
            raise ValueError("role refs must be unique")
        if self.annual_hours <= 0:
            raise ValueError("annual_hours is positive")
        if not skip_digests(info) and self.plan_digest != sealed_digest(LabourSourcingPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def role(self, role_ref: str) -> RoleDefinition | None:
        return next((role for role in self.roles if role.role_ref == role_ref), None)


def compile_labour_sourcing_plan(company_ref: str, *, currency: str, roles: Sequence[Mapping[str, Any]] = (), market_rates: Mapping[str, Any] | None = None, overrides: Mapping[str, Any] | None = None) -> LabourSourcingPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "roles": [dict(detached(role)) for role in roles], "market_rates": {str(key): str(value) for key, value in dict(market_rates or {}).items()}, **dict(overrides or {})}
    return seal(LabourSourcingPlan, raw, "plan_digest")


class SkillCapacityRow(StrictModel):
    skill_ref: OpaqueRef
    demand_hours: Decimal
    demand_hours_per_week: Decimal
    required_level: int = Field(ge=0, le=5)
    qualified_workers: int = Field(ge=0)
    qualified_hours: Decimal
    utilisation_percent: Decimal | None = None
    status: CapacityStatus

    @field_validator("demand_hours", "demand_hours_per_week", "qualified_hours", "utilisation_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class SourcingOption(StrictModel):
    kind: SourcingKind
    feasible: bool
    cost: Decimal | None = None
    lead_weeks: int | None = None
    subject_ref: OpaqueRef | None = None
    rationale: ShortText
    request: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="cost")


class SourcingAction(StrictModel):
    job_ref: OpaqueRef
    skill_ref: OpaqueRef
    minimum_level: int = Field(ge=1, le=5)
    mandatory: bool
    hours: Decimal
    starts_at: str
    weeks_to_start: Decimal
    chosen: SourcingKind
    cost: Decimal | None = None
    subject_ref: OpaqueRef | None = None
    options: tuple[SourcingOption, ...] = Field(min_length=1, max_length=8)
    rationale: ShortText
    request: dict[str, Any] = Field(default_factory=dict)

    @field_validator("options", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours", "weeks_to_start", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class Requisition(StrictModel):
    role_ref: OpaqueRef
    headcount: int = Field(ge=1, le=500)
    pay_rate: Decimal
    pay_rate_uom: Literal["hour", "year"]
    skills: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    shortfall_hours_per_week: Decimal
    rationale: ShortText

    @field_validator("skills", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("pay_rate", "shortfall_hours_per_week", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class LabourSourcing(StrictModel):
    schema_id: str = Field(default=LABOUR_SOURCING_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    window_end: str
    plan_digest: Sha256Digest
    match_report_digest: Sha256Digest
    capacity: tuple[SkillCapacityRow, ...] = Field(default_factory=tuple, max_length=2000)
    actions: tuple[SourcingAction, ...] = Field(default_factory=tuple, max_length=2000)
    requisitions: tuple[Requisition, ...] = Field(default_factory=tuple, max_length=500)
    by_kind: dict[str, int] = Field(default_factory=dict)
    total_cost: Decimal
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    sourcing_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("capacity", "actions", "requisitions", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("total_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="total_cost")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "LabourSourcing":
        if sum(self.by_kind.values()) != len(self.actions):
            raise ValueError("every action is counted once by kind")
        if not skip_digests(info) and self.sourcing_digest != sealed_digest(LabourSourcing, self, "sourcing_digest"):
            raise ValueError("sourcing_digest must commit the exact document")
        return self

    def capacity_row(self, skill_ref: str) -> SkillCapacityRow | None:
        return next((row for row in self.capacity if row.skill_ref == skill_ref), None)

    def render(self) -> str:
        lines = [f"**Labour sourcing {self.company_ref}** as of {self.as_of[:10]}: {len(self.actions)} gap(s) to close for {self.total_cost} {self.currency}" + (" (" + ", ".join(f"{count} {kind}" for kind, count in self.by_kind.items()) + ")" if self.by_kind else "") + f"; {len(self.requisitions)} requisition(s)."]
        for action in self.actions:
            lines.append(f"- {action.job_ref} / {action.skill_ref} L{action.minimum_level}: {action.chosen}" + (f" {action.subject_ref}" if action.subject_ref else "") + (f" at {action.cost}" if action.cost is not None else "") + f"; {action.rationale}")
        for row in self.capacity:
            if row.status in ("short", "tight"):
                lines.append(f"- capacity {row.skill_ref}: {row.status}, demand {row.demand_hours}h against {row.qualified_hours}h qualified ({row.qualified_workers} worker(s))")
        for item in self.requisitions:
            lines.append(f"- requisition {item.role_ref} x{item.headcount} at {item.pay_rate}/{item.pay_rate_uom}: {item.rationale}")
        return "\n".join(lines)


def _weeks(start: Any, end: Any) -> Decimal:
    return max(Decimal("0"), (Decimal((end - start).total_seconds()) / Decimal(7 * 86400))).quantize(_PCT, rounding=ROUND_HALF_UP)


def _free_hours(profile: WorkerProfile, start: Any, end: Any) -> Decimal:
    begin = max([start] + ([parsed(profile.available_from)] if profile.available_from else []))
    finish = end if not profile.available_until else min(end, parsed(profile.available_until))
    return Decimal("0") if finish <= begin else (profile.hours_per_week * _weeks(begin, finish)).quantize(_HOURS, rounding=ROUND_HALF_UP)


def _band(plan: LabourSourcingPlan, role: RoleDefinition, hiring_plan: Any) -> tuple[Decimal, str] | None:
    band = hiring_plan.band(role.role_ref) if hiring_plan is not None and hasattr(hiring_plan, "band") else None
    if band is not None:
        return _money((band.min_amount + band.max_amount) / 2), str(band.pay_rate_uom)
    if role.pay_rate is not None and role.pay_rate_uom is not None:
        return _money(role.pay_rate), role.pay_rate_uom
    return None


def _hourly(plan: LabourSourcingPlan, rate: Decimal, uom: str) -> Decimal:
    return rate if uom == "hour" else (rate / plan.annual_hours).quantize(_HOURS, rounding=ROUND_HALF_UP)


def build_labour_sourcing(plan: LabourSourcingPlan | Mapping[str, Any], *, match_report: Mapping[str, Any] | Any, taxonomy: SkillsTaxonomy | Mapping[str, Any], matching_plan: SkillsMatchingPlan | Mapping[str, Any], jobs: Sequence[JobRequirements | Mapping[str, Any]], profiles: Sequence[WorkerProfile | Mapping[str, Any]], hiring_plan: Any = None, as_of: str) -> LabourSourcing:
    """The sealed sourcing document: one priced decision per gap in the match report, the skill capacity ledger, and the requisitions recurring shortfalls justify."""

    parsed_plan = plan if isinstance(plan, LabourSourcingPlan) else LabourSourcingPlan.model_validate(detached(plan))
    report = verify_skills_match_report(match_report)
    parsed_taxonomy = taxonomy if isinstance(taxonomy, SkillsTaxonomy) else SkillsTaxonomy.model_validate(detached(taxonomy))
    parsed_matching = matching_plan if isinstance(matching_plan, SkillsMatchingPlan) else SkillsMatchingPlan.model_validate(detached(matching_plan))
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SCOPE_MISMATCH", "the match report names another company or currency")
    _require(report.taxonomy_digest == parsed_taxonomy.taxonomy_digest and report.plan_digest == parsed_matching.plan_digest, "REPORT_NOT_BOUND", "the match report was built from another taxonomy or matching plan")
    if hiring_plan is not None:
        _require(getattr(hiring_plan, "company_ref", parsed_plan.company_ref) == parsed_plan.company_ref and getattr(hiring_plan, "currency", parsed_plan.currency) == parsed_plan.currency, "SCOPE_MISMATCH", "the hiring plan names another company or currency")
    parsed_jobs = {job.job_ref: job for job in (item if isinstance(item, JobRequirements) else JobRequirements.model_validate(detached(item)) for item in jobs)}
    for match in report.jobs:
        _require(match.job_ref in parsed_jobs and parsed_jobs[match.job_ref].requirements_digest == match.requirements_digest, "REPORT_NOT_BOUND", f"the report's job {match.job_ref} is not among the jobs supplied at the same digest")
    workers = [item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles]
    at = timestamp(as_of, field_name="as_of")
    now = parsed(at)
    window_end = max([parsed(job.due_at) for job in parsed_jobs.values()] + [now + timedelta(days=7)])
    window_weeks = max(_weeks(now, window_end), Decimal("1"))
    standings = {worker.worker_ref: effective_levels(parsed_taxonomy, parsed_matching, worker, as_of=at) for worker in workers}
    free = {worker.worker_ref: _free_hours(worker, now, window_end) for worker in workers}
    by_ref = {worker.worker_ref: worker for worker in workers}

    demand: dict[str, Decimal] = {}
    required: dict[str, int] = {}
    for job in parsed_jobs.values():
        total_weight = sum((item.weight for item in job.requirements), Decimal("0"))
        for requirement in job.requirements:
            demand[requirement.skill_ref] = demand.get(requirement.skill_ref, Decimal("0")) + (job.hours_required * requirement.weight / total_weight)
            required[requirement.skill_ref] = max(required.get(requirement.skill_ref, 0), requirement.minimum_level)
    capacity: list[dict[str, Any]] = []
    for skill in parsed_taxonomy.skills:
        level = required.get(skill.skill_ref, 0)
        qualified = [worker for worker in workers if standings[worker.worker_ref][skill.skill_ref].effective_level >= Decimal(max(level, 1))]
        hours = sum((free[worker.worker_ref] for worker in qualified), Decimal("0")).quantize(_HOURS)
        need = demand.get(skill.skill_ref, Decimal("0")).quantize(_HOURS, rounding=ROUND_HALF_UP)
        utilisation = None if hours <= 0 else (need / hours * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)
        if need <= 0:
            status = "idle" if qualified else "unused"
        elif hours < need:
            status = "short"
        elif utilisation is not None and utilisation >= Decimal("80"):
            status = "tight"
        else:
            status = "covered"
        if need <= 0 and not qualified:
            continue
        capacity.append({"skill_ref": skill.skill_ref, "demand_hours": str(need), "demand_hours_per_week": str((need / window_weeks).quantize(_HOURS, rounding=ROUND_HALF_UP)), "required_level": level, "qualified_workers": len(qualified), "qualified_hours": str(hours), "utilisation_percent": None if utilisation is None else str(utilisation), "status": status})
    capacity_by_skill = {row["skill_ref"]: row for row in capacity}

    actions: list[dict[str, Any]] = []
    for match in report.jobs:
        job = parsed_jobs[match.job_ref]
        weeks_to_start = _weeks(now, parsed(job.starts_at))
        job_end = parsed(job.due_at)
        for gap in match.gaps:
            skill = parsed_taxonomy.skill(gap.skill_ref)
            hours = gap.hours
            options: list[dict[str, Any]] = []
            # assign: someone on the books already holds the level
            holders = [worker for worker in workers if worker.kind in ("employee", "contractor") and standings[worker.worker_ref][gap.skill_ref].effective_level >= Decimal(gap.minimum_level) and not standings[worker.worker_ref][gap.skill_ref].licence_expired]
            holders.sort(key=lambda worker: (worker.cost_rate, worker.worker_ref))
            able = [worker for worker in holders if _free_hours(worker, max(now, parsed(job.starts_at)), job_end) >= hours]
            if not holders:
                options.append({"kind": "assign", "feasible": False, "rationale": f"nobody on the books holds {gap.skill_ref} at level {gap.minimum_level}"})
            elif not able:
                options.append({"kind": "assign", "feasible": False, "subject_ref": holders[0].worker_ref, "rationale": f"{', '.join(worker.worker_ref for worker in holders[:3])} hold the level but lack {hours}h free in the window"})
            else:
                worker = able[0]
                options.append({"kind": "assign", "feasible": True, "cost": str(_money(worker.cost_rate * hours)), "lead_weeks": 0, "subject_ref": worker.worker_ref, "rationale": f"{worker.worker_ref} ({worker.kind}) holds {gap.skill_ref} at {standings[worker.worker_ref][gap.skill_ref].effective_level} with the hours free; {hours}h at {worker.cost_rate}/h"[:300], "request": {"worker_ref": worker.worker_ref, "job_ref": match.job_ref, "skill_ref": gap.skill_ref, "hours": str(hours)}})
            # upskill
            best: tuple[Decimal, WorkerProfile] | None = None
            for worker in workers:
                if worker.kind != "employee":
                    continue
                standing = standings[worker.worker_ref][gap.skill_ref]
                if standing.effective_level <= 0 or standing.licence_expired or (skill is not None and skill.licence):
                    continue
                short = Decimal(gap.minimum_level) - standing.effective_level
                if short <= 0 or short > parsed_plan.upskill_max_levels or worker in holders:
                    continue
                if best is None or standing.effective_level > best[0] or (standing.effective_level == best[0] and worker.cost_rate < best[1].cost_rate):
                    best = (standing.effective_level, worker)
            if best is None:
                options.append({"kind": "upskill", "feasible": False, "rationale": ("a licence cannot be trained into; it must be held" if skill is not None and skill.licence else f"no employee holds {gap.skill_ref} within {parsed_plan.upskill_max_levels} level(s) of {gap.minimum_level}")})
            else:
                level, worker = best
                levels = int(math.ceil(Decimal(gap.minimum_level) - level))
                weeks = levels * parsed_plan.upskill_weeks_per_level
                free_hours = _free_hours(worker, max(now, parsed(job.starts_at)), job_end)
                training = parsed_plan.upskill_hours_per_level * levels
                cost = _money(worker.cost_rate * (training + hours))
                in_time = Decimal(weeks) <= weeks_to_start
                has_hours = free_hours >= hours
                feasible = in_time and has_hours
                rationale = f"{worker.worker_ref} at {level} needs {levels} level(s), {weeks} week(s) of training ({training}h) " + ("before the job starts" if in_time else f"but the job starts in {weeks_to_start} week(s)") + ("" if has_hours else f"; only {free_hours}h free against {hours}h")
                options.append({"kind": "upskill", "feasible": feasible, "cost": str(cost), "lead_weeks": weeks, "subject_ref": worker.worker_ref, "rationale": rationale[:300], "request": {"worker_ref": worker.worker_ref, "skill_ref": gap.skill_ref, "from_level": str(level), "to_level": gap.minimum_level, "training_hours": str(training), "complete_by": job.starts_at}})
            # contract
            rate = parsed_plan.market_rates.get(gap.skill_ref)
            if rate is None:
                options.append({"kind": "contract", "feasible": False, "rationale": f"no market rate typed for {gap.skill_ref}"})
            else:
                cost = _money(rate * hours)
                in_time = Decimal(parsed_plan.contractor_lead_weeks) <= weeks_to_start
                options.append({"kind": "contract", "feasible": in_time, "cost": str(cost), "lead_weeks": parsed_plan.contractor_lead_weeks, "rationale": (f"{hours}h at the {rate}/h market rate, {parsed_plan.contractor_lead_weeks} week(s) to engage" + ("" if in_time else f" but the job starts in {weeks_to_start} week(s)"))[:300], "request": {"rate": str(rate), "rate_uom": "hour", "monthly_cap": str(cost), "engagement_end": job.due_at, "skill_ref": gap.skill_ref, "minimum_level": gap.minimum_level}})
            # hire
            roles = [role for role in parsed_plan.roles if role.skills.get(gap.skill_ref, 0) >= gap.minimum_level]
            per_week = Decimal(capacity_by_skill.get(gap.skill_ref, {}).get("demand_hours_per_week", "0"))
            recurring = per_week >= parsed_plan.hire_threshold_hours_per_week
            priced = [(role, _band(parsed_plan, role, hiring_plan)) for role in roles]
            priced = [(role, band) for role, band in priced if band is not None]
            if not priced:
                options.append({"kind": "hire", "feasible": False, "rationale": (f"no role carries {gap.skill_ref} at level {gap.minimum_level}" if not roles else f"no pay band or typed rate for {', '.join(role.role_ref for role in roles)}")})
            else:
                role, (pay, uom) = min(priced, key=lambda item: (_hourly(parsed_plan, item[1][0], item[1][1]), item[0].role_ref))
                hourly = _hourly(parsed_plan, pay, uom)
                cost = _money(hourly * hours + parsed_plan.recruiting_cost)
                in_time = Decimal(parsed_plan.hiring_lead_weeks) <= weeks_to_start
                feasible = recurring and in_time
                rationale = f"{role.role_ref} at {pay}/{uom} band midpoint ({hourly}/h), {parsed_plan.hiring_lead_weeks} week(s) to hire; demand {per_week}h/week " + ("meets" if recurring else "is below") + f" the {parsed_plan.hire_threshold_hours_per_week}h/week hire threshold" + ("" if in_time else f"; the job starts in {weeks_to_start} week(s)")
                options.append({"kind": "hire", "feasible": feasible, "cost": str(cost), "lead_weeks": parsed_plan.hiring_lead_weeks, "subject_ref": role.role_ref, "rationale": rationale[:300], "request": {"role_ref": role.role_ref, "headcount": 1, "pay_rate": str(pay), "pay_rate_uom": uom}})
            feasible = sorted((option for option in options if option["feasible"]), key=lambda option: (Decimal(option["cost"]), _PREFERENCE[option["kind"]]))
            if feasible:
                chosen = feasible[0]
                others = [option for option in feasible[1:]]
                rationale = f"cheapest feasible route at {chosen['cost']}" + (f"; next {others[0]['kind']} at {others[0]['cost']}" if others else "; the only feasible route")
                actions.append({"job_ref": match.job_ref, "skill_ref": gap.skill_ref, "minimum_level": gap.minimum_level, "mandatory": gap.mandatory, "hours": str(hours), "starts_at": job.starts_at, "weeks_to_start": str(weeks_to_start), "chosen": chosen["kind"], "cost": chosen["cost"], "subject_ref": chosen.get("subject_ref"), "options": options, "rationale": rationale[:300], "request": chosen.get("request", {})})
            else:
                actions.append({"job_ref": match.job_ref, "skill_ref": gap.skill_ref, "minimum_level": gap.minimum_level, "mandatory": gap.mandatory, "hours": str(hours), "starts_at": job.starts_at, "weeks_to_start": str(weeks_to_start), "chosen": "escalate", "cost": None, "subject_ref": None, "options": options, "rationale": ("no route is feasible: " + "; ".join(f"{option['kind']}: {option['rationale']}" for option in options))[:300], "request": {}})

    requisitions: dict[str, dict[str, Any]] = {}
    for row in capacity:
        if row["status"] != "short" or Decimal(row["demand_hours_per_week"]) < parsed_plan.hire_threshold_hours_per_week:
            continue
        shortfall = ((Decimal(row["demand_hours"]) - Decimal(row["qualified_hours"])) / window_weeks).quantize(_HOURS, rounding=ROUND_HALF_UP)
        roles = [role for role in parsed_plan.roles if role.skills.get(row["skill_ref"], 0) >= max(row["required_level"], 1)]
        priced = [(role, _band(parsed_plan, role, hiring_plan)) for role in roles]
        priced = [(role, band) for role, band in priced if band is not None]
        if not priced:
            continue
        role, (pay, uom) = min(priced, key=lambda item: (_hourly(parsed_plan, item[1][0], item[1][1]), item[0].role_ref))
        heads = max(1, int(math.ceil(shortfall / role.hours_per_week)))
        current = requisitions.get(role.role_ref)
        if current is None or heads > current["headcount"]:
            requisitions[role.role_ref] = {"role_ref": role.role_ref, "headcount": heads, "pay_rate": str(pay), "pay_rate_uom": uom, "skills": sorted({row["skill_ref"], *(current["skills"] if current else [])}), "shortfall_hours_per_week": str(max(shortfall, Decimal(current["shortfall_hours_per_week"]) if current else shortfall)), "rationale": f"{row['skill_ref']} is short {shortfall}h/week over {window_weeks} week(s) with recurring demand {row['demand_hours_per_week']}h/week; {heads} head(s) at {role.hours_per_week}h/week"[:300]}
        else:
            current["skills"] = sorted({row["skill_ref"], *current["skills"]})

    by_kind: dict[str, int] = {}
    for action in actions:
        by_kind[action["chosen"]] = by_kind.get(action["chosen"], 0) + 1
    total = _money(sum((Decimal(action["cost"]) for action in actions if action["cost"] is not None), Decimal("0")))
    recommendations = [f"{action['job_ref']} / {action['skill_ref']}: {action['chosen']}" + (f" {action['subject_ref']}" if action["subject_ref"] else "") + (f" at {action['cost']}" if action["cost"] is not None else "") + f"; {action['rationale']}" for action in actions][:20]
    recommendations += [f"open {item['role_ref']} x{item['headcount']}: {item['rationale']}" for item in requisitions.values()][: 24 - len(recommendations)]
    if not recommendations:
        recommendations.append("no gaps to source: every job is covered by the workers on hand")
    payload = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "window_end": timestamp(window_end.isoformat().replace("+00:00", "Z"), field_name="window_end"), "plan_digest": parsed_plan.plan_digest, "match_report_digest": report.report_digest,
        "capacity": capacity, "actions": actions, "requisitions": list(requisitions.values()), "by_kind": by_kind, "total_cost": str(total), "recommendations": [item[:300] for item in recommendations],
        "source_digests": [report.report_digest, parsed_taxonomy.taxonomy_digest, parsed_matching.plan_digest, *[worker.profile_digest for worker in workers], *([hiring_plan.plan_digest] if hiring_plan is not None and hasattr(hiring_plan, "plan_digest") else [])],
    }
    return seal(LabourSourcing, payload, "sourcing_digest")


def verify_labour_sourcing(value: Any) -> LabourSourcing:
    return value if isinstance(value, LabourSourcing) else LabourSourcing.model_validate(dict(detached(value)))


LABOUR_SOURCING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "labour_sourcing",
    "golden_loop": "services.quote_to_cash@0.1.0",
    "stages": ["verify_match_report", "ledger_skill_capacity", "price_options_per_gap", "choose_cheapest_feasible", "raise_requisitions", "seal_document"],
    "kinds": list(SOURCING_KINDS),
    "capacity_statuses": list(CAPACITY_STATUSES),
    "hand_offs": {"assign": "worker_ref, job_ref, skill_ref, hours (a staffing read for the engagement or work order)", "hire": "hiring_chain.headcount_receipt(role_ref, headcount, pay_rate, pay_rate_uom)", "contract": "contractor_chain program (rate, rate_uom, monthly_cap, engagement_end)", "upskill": "worker_ref, skill_ref, from_level, to_level, training_hours, complete_by"},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every option is priced for the same hours so the comparison is like for like; the cheapest feasible route wins and ties go make-before-buy (assign, upskill, contract, hire)",
        "a hire is feasible only when the skill's demand across the window is recurring and the lead time lands before the job starts",
        "a licence is never trained into; an expired one is a gap",
        "market rates and pay bands are typed or come from the hiring chain's plan; nothing is estimated",
        "nothing here opens a requisition, engages anyone, or persists anything",
    ],
}

__all__ = [
    "CAPACITY_STATUSES", "LABOUR_SOURCING_MANIFEST", "LABOUR_SOURCING_PLAN_SCHEMA", "LABOUR_SOURCING_SCHEMA", "SOURCING_KINDS",
    "LabourSourcing", "LabourSourcingError", "LabourSourcingPlan", "Requisition", "RoleDefinition", "SkillCapacityRow", "SourcingAction", "SourcingOption",
    "build_labour_sourcing", "compile_labour_sourcing_plan", "verify_labour_sourcing",
]
