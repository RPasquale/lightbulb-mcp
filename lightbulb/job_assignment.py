"""Job assignment: every open job staffed at once, so a person's hours are given only once.

``build_skills_match_report`` scores every worker against every job and
assembles each job's team on its own.  Two jobs in the same fortnight can
therefore both be "staffed" by the same electrician for more hours than she
has, and the report will not say so.  ``assign_jobs`` takes that report
(so the skill judgement stays exactly where it is) and allocates hours
across all the jobs together.

The allocation is exact and explainable, not searched: jobs are taken in
priority order (the plan's stated priority, then the earliest due date,
then the most money at stake), and for each job the fit workers are taken
in the report's rank order, each giving what remains of their capacity
across the jobs whose windows overlap.  A worker's capacity in an overlap
is her hours a week over the overlapping weeks less what earlier jobs
already took.  A job that cannot be filled from what remains is short by a
stated number of hours, and the document names who would have covered it
had they not been taken by which earlier job, so the owner can reorder.
Stretch candidates are used only when the plan allows it, and disqualified
and over-budget ones never.  The deterministic order means the same inputs
give the same allocation every time.

The output feeds the sourcing document with a true gap (hours nobody can
give, by skill and week) and the capacity document with a true load.
Nothing here reads a provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

JOB_ASSIGNMENT_PLAN_SCHEMA = "lightbulb.job_assignment_plan.v1"
JOB_ASSIGNMENT_SCHEMA = "lightbulb.job_assignment.v1"
JOB_ASSIGNMENT_MANIFEST: dict[str, Any] = {"engine": "job_assignment", "kind": "intelligence_document", "reads": ("skills_match",), "writes": ()}
ASSIGNMENT_STATUSES: tuple[str, ...] = ("staffed", "short", "unstaffable")
AssignmentStatus = Literal["staffed", "short", "unstaffable"]
_HOURS = Decimal("0.1")
_WEEK = Decimal(7 * 86400)


class JobAssignmentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise JobAssignmentError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _hours(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_HOURS, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class JobAssignmentPlan(StrictModel):
    schema_id: str = Field(default=JOB_ASSIGNMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    priority: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    allow_stretch: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("priority", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobAssignmentPlan":
        if len(set(self.priority)) != len(self.priority):
            raise ValueError("PRIORITY_DUPLICATE: a job appears once in the priority order")
        if not skip_digests(info) and self.plan_digest != sealed_digest(JobAssignmentPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_job_assignment_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> JobAssignmentPlan:
    return seal(JobAssignmentPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class Allocation(StrictModel):
    worker_ref: OpaqueRef
    hours: Decimal
    cost: Decimal
    verdict: ShortText

    @field_validator("hours", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class AssignedJob(StrictModel):
    job_ref: OpaqueRef
    title: ShortText
    order: int = Field(ge=1)
    starts_at: str
    due_at: str
    hours_required: Decimal
    hours_assigned: Decimal
    hours_short: Decimal
    cost: Decimal
    status: AssignmentStatus
    allocations: tuple[Allocation, ...] = Field(default_factory=tuple, max_length=100)
    taken_by_earlier: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    note: ShortText

    @field_validator("allocations", "taken_by_earlier", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_required", "hours_assigned", "hours_short", "cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class WorkerLoad(StrictModel):
    worker_ref: OpaqueRef
    hours_assigned: Decimal
    jobs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    peak_week_hours: Decimal
    peak_week: str | None = None

    @field_validator("jobs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_assigned", "peak_week_hours", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class JobAssignment(StrictModel):
    schema_id: str = Field(default=JOB_ASSIGNMENT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    plan_digest: Sha256Digest
    match_report_digest: Sha256Digest
    jobs: tuple[AssignedJob, ...] = Field(max_length=500)
    workers: tuple[WorkerLoad, ...] = Field(default_factory=tuple, max_length=500)
    staffed: int = Field(ge=0)
    short: int = Field(ge=0)
    unstaffable: int = Field(ge=0)
    hours_required: Decimal
    hours_assigned: Decimal
    hours_short: Decimal
    total_cost: Decimal
    double_bookings_avoided: int = Field(ge=0)
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    assignment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("jobs", "workers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("hours_required", "hours_assigned", "hours_short", "total_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "JobAssignment":
        counts = {status: sum(1 for job in self.jobs if job.status == status) for status in ASSIGNMENT_STATUSES}
        if (self.staffed, self.short, self.unstaffable) != (counts["staffed"], counts["short"], counts["unstaffable"]):
            raise ValueError("the counts count the jobs")
        if self.hours_assigned != _hours(sum((job.hours_assigned for job in self.jobs), Decimal("0"))) or self.total_cost != _money(sum((job.cost for job in self.jobs), Decimal("0"))):
            raise ValueError("hours assigned and cost are the jobs' allocations added")
        for job in self.jobs:
            if job.hours_assigned != _hours(sum((item.hours for item in job.allocations), Decimal("0"))) or job.hours_short != _hours(max(job.hours_required - job.hours_assigned, Decimal("0"))):
                raise ValueError(f"{job.job_ref}: the hours assigned are its allocations added, and the shortfall is what remains")
        if not skip_digests(info) and self.assignment_digest != sealed_digest(JobAssignment, self, "assignment_digest"):
            raise ValueError("assignment_digest must commit the exact document")
        return self

    def job(self, job_ref: str) -> AssignedJob:
        found = next((item for item in self.jobs if item.job_ref == job_ref), None)
        if found is None:
            raise LookupError(f"no job {job_ref}")
        return found

    def render(self) -> str:
        lines = [f"**Job assignment** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- [{job.status}] {job.title}: {job.note}" for job in self.jobs)
        return "\n".join(lines)


def _weeks(start: datetime, end: datetime) -> list[datetime]:
    """The Monday-aligned week starts a window touches."""

    first = (start - timedelta(days=start.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    out = []
    week = first
    while week < end:
        out.append(week)
        week += timedelta(days=7)
    return out


def assign_jobs(plan: JobAssignmentPlan | Mapping[str, Any], *, match_report: Mapping[str, Any] | Any, profiles: Sequence[Mapping[str, Any] | Any], as_of: str) -> JobAssignment:
    """The sealed allocation of every worker's hours across every job in the match report."""

    from lightbulb.skills_matching import WorkerProfile, verify_skills_match_report

    parsed_plan = plan if isinstance(plan, JobAssignmentPlan) else JobAssignmentPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    report = verify_skills_match_report(match_report)
    _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the match report names another company or currency")
    workers = {item.worker_ref: item for item in (item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(detached(item)) for item in profiles)}
    missing = sorted({candidate.worker_ref for job in report.jobs for candidate in job.candidates} - set(workers))
    _require(not missing, "PROFILES_MISSING", f"the report names workers whose profiles were not supplied: {missing[:5]}")
    unknown = sorted(set(parsed_plan.priority) - {job.job_ref for job in report.jobs})
    _require(not unknown, "PRIORITY_UNKNOWN_JOB", f"the priority order names jobs not in the report: {unknown[:5]}")

    rank = {ref: index for index, ref in enumerate(parsed_plan.priority)}
    ordered = sorted(report.jobs, key=lambda job: (rank.get(job.job_ref, len(rank)), job.due_at, -Decimal(str(job.budget)) if job.budget is not None else Decimal("0"), job.job_ref))
    # capacity per worker per week; a week's capacity is the profile's hours a week, and every job in that week draws on the same pool
    used: dict[tuple[str, datetime], Decimal] = {}
    taken_by: dict[tuple[str, datetime], str] = {}
    loads: dict[str, dict[str, Any]] = {ref: {"hours": Decimal("0"), "jobs": [], "weeks": {}} for ref in workers}
    jobs_out: list[dict[str, Any]] = []
    avoided = 0
    for order, job in enumerate(ordered, start=1):
        start, end = parsed(job.starts_at), parsed(job.due_at)
        weeks = _weeks(max(start, parsed(at)), end)
        need = Decimal(str(job.hours_required))
        allocations: list[dict[str, Any]] = []
        blocked: list[str] = []
        candidates = [item for item in job.candidates if item.verdict == "fit" or (parsed_plan.allow_stretch and item.verdict == "stretch")]
        for candidate in sorted(candidates, key=lambda item: item.rank):
            if need <= 0:
                break
            profile = workers[candidate.worker_ref]
            weekly = Decimal(str(profile.hours_per_week))
            free = Decimal("0")
            for week in weeks:
                free += max(weekly - used.get((candidate.worker_ref, week), Decimal("0")), Decimal("0"))
            free = min(free, Decimal(str(candidate.available_hours)))
            if free <= 0:
                elsewhere = sorted({taken_by[(candidate.worker_ref, week)] for week in weeks if (candidate.worker_ref, week) in taken_by})
                if elsewhere:
                    blocked.append(f"{candidate.worker_ref} (rank {candidate.rank}) has no hours left in these weeks: taken by {', '.join(elsewhere)}")
                    avoided += 1
                continue
            give = min(free, need)
            if free < min(Decimal(str(candidate.available_hours)), need):
                avoided += 1  # the per-job report would have given this worker hours already given to an earlier job
            remaining = give
            for week in weeks:
                if remaining <= 0:
                    break
                room = max(weekly - used.get((candidate.worker_ref, week), Decimal("0")), Decimal("0"))
                slice_ = min(room, remaining)
                if slice_ > 0:
                    used[(candidate.worker_ref, week)] = used.get((candidate.worker_ref, week), Decimal("0")) + slice_
                    taken_by[(candidate.worker_ref, week)] = job.job_ref
                    loads[candidate.worker_ref]["weeks"][week] = loads[candidate.worker_ref]["weeks"].get(week, Decimal("0")) + slice_
                    remaining -= slice_
            cost = _money(give * Decimal(str(candidate.cost_rate)))
            allocations.append({"worker_ref": candidate.worker_ref, "hours": str(_hours(give)), "cost": str(cost), "verdict": candidate.verdict})
            loads[candidate.worker_ref]["hours"] += give
            loads[candidate.worker_ref]["jobs"].append(job.job_ref)
            need -= give
        assigned = _hours(Decimal(str(job.hours_required)) - max(need, Decimal("0")))
        short = _hours(max(need, Decimal("0")))
        if short == 0:
            status, note = "staffed", f"{assigned} hour(s) from {', '.join(item['worker_ref'] for item in allocations)}"
        elif assigned > 0:
            status, note = "short", f"{assigned} of {job.hours_required} hour(s) covered; {short} short" + (f"; {blocked[0]}" if blocked else "; nobody else fits")
        else:
            status, note = "unstaffable", f"no fit worker has hours left: {blocked[0]}" if blocked else "no worker fits this job"
        jobs_out.append({"job_ref": job.job_ref, "title": job.title, "order": order, "starts_at": job.starts_at, "due_at": job.due_at, "hours_required": str(_hours(job.hours_required)), "hours_assigned": str(assigned), "hours_short": str(short), "cost": str(_money(sum((Decimal(item["cost"]) for item in allocations), Decimal("0")))), "status": status, "allocations": allocations, "taken_by_earlier": [item[:300] for item in blocked][:20], "note": note[:300]})
    worker_rows = []
    for ref, load in loads.items():
        if load["hours"] <= 0:
            continue
        peak_week, peak = max(load["weeks"].items(), key=lambda item: (item[1], -item[0].timestamp()))
        worker_rows.append({"worker_ref": ref, "hours_assigned": str(_hours(load["hours"])), "jobs": load["jobs"], "peak_week_hours": str(_hours(peak)), "peak_week": peak_week.isoformat().replace("+00:00", "Z")})
    worker_rows.sort(key=lambda item: (-Decimal(item["hours_assigned"]), item["worker_ref"]))
    counts = {status: sum(1 for job in jobs_out if job["status"] == status) for status in ASSIGNMENT_STATUSES}
    required = _hours(sum((Decimal(job["hours_required"]) for job in jobs_out), Decimal("0")))
    assigned_total = _hours(sum((Decimal(job["hours_assigned"]) for job in jobs_out), Decimal("0")))
    recommendations: list[str] = []
    for job in jobs_out:
        if job["status"] != "staffed":
            recommendations.append(f"{job['title']}: {job['hours_short']} hour(s) nobody can give in its window; source them, move the job, or reorder the priority so it is staffed first")
    if avoided and not recommendations:
        recommendations.append(f"{avoided} double booking(s) the per-job report would have made were avoided; every job is still staffed")
    if not recommendations:
        recommendations.append("every job is staffed without anyone's hours being given twice")
    verdict = f"{counts['staffed']} staffed, {counts['short']} short, {counts['unstaffable']} unstaffable; {assigned_total} of {required} hour(s) assigned at {_money(sum((Decimal(job['cost']) for job in jobs_out), Decimal('0')))} {parsed_plan.currency}; {avoided} double booking(s) avoided"
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "as_of": at, "plan_digest": parsed_plan.plan_digest, "match_report_digest": report.report_digest, "jobs": jobs_out, "workers": worker_rows, "staffed": counts["staffed"], "short": counts["short"], "unstaffable": counts["unstaffable"], "hours_required": str(required), "hours_assigned": str(assigned_total), "hours_short": str(_hours(sum((Decimal(job["hours_short"]) for job in jobs_out), Decimal("0")))), "total_cost": str(_money(sum((Decimal(job["cost"]) for job in jobs_out), Decimal("0")))), "double_bookings_avoided": avoided, "verdict": verdict[:300], "recommendations": [item[:300] for item in recommendations][:24], "source_digests": [report.report_digest]}
    return seal(JobAssignment, payload, "assignment_digest")


def verify_job_assignment(value: Any) -> JobAssignment:
    return value if isinstance(value, JobAssignment) else JobAssignment.model_validate(dict(detached(value)))


__all__ = ["ASSIGNMENT_STATUSES", "JOB_ASSIGNMENT_MANIFEST", "JOB_ASSIGNMENT_PLAN_SCHEMA", "JOB_ASSIGNMENT_SCHEMA", "Allocation", "AssignedJob", "JobAssignment", "JobAssignmentError", "JobAssignmentPlan", "WorkerLoad", "assign_jobs", "compile_job_assignment_plan", "verify_job_assignment"]
