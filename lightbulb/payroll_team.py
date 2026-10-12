"""The team from payroll: who works here, the hours they work and what an hour of their time costs, read from the payroll's own governed pages.

Every staffing document (the skills match, job assignment, workforce
capacity, sourcing, job quotes) plans with worker profiles typed in by
hand: an ``hours_per_week`` and a ``cost_rate`` that nobody checks against
what the payroll pays.  The payroll already knows.  ``build_payroll_team``
reads three governed Xero Payroll AU observations, whose identities the
platform has already reduced to sha256 commitments, so no name, tax file
number, bank account, address or date of birth ever reaches the SDK:

* ``xero.observe_headcount``: who is on the payroll, active or terminated,
  since and until when;
* ``xero.observe_payrun``: for each posted pay run, each worker's wages and
  super for the pay period;
* ``xero.observe_timesheets``: approved and processed hours per worker.

For each worker it seals the hours worked in the observed window and their
weekly average, and the cost of an hour: the wages and super the posted pay
runs paid for their pay periods, over the timesheet hours inside those
periods, with the on-costs the owner states (payroll tax, workers'
compensation, leave loading) added as one stated percentage.  A worker paid
with no timesheet hours (a salaried worker) is costed only on the weekly
hours the owner states for them; otherwise the hour's cost stays unknown and
says why.  The employment basis (full time, part time, casual) is not on the
governed pages, so it is the owner's to state and ``unstated`` until then.

An active worker with both figures known gets a worker profile ready for
the staffing documents: kind ``employee``, the hours, the cost rate,
available from the start date, with the skills the owner already confirmed
on an earlier profile carried over and never invented.  Workers are joined
across the pages by the payroll commitment ``worker:<sha[:24]>`` the payroll,
employment and worked-hours documents already use.  The document carries no
pay total, only the rate and hours a profile holds.

QuickBooks Online's payroll reads return names, addresses and payslips that
cannot be joined to an employee, so they are refused by name until the
platform observes them the way it observes Xero's.  Nothing here reads a
provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
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
    stable_digest,
    timestamp,
)
from lightbulb.employment_chain import payroll_worker_ref
from lightbulb.skills_matching import WorkerProfile

PAYROLL_TEAM_SCHEMA = "lightbulb.payroll_team.v1"
PAYROLL_TEAM_MANIFEST: dict[str, Any] = {"engine": "payroll_team", "kind": "intelligence_document", "reads": ("headcount", "payruns", "timesheets"), "writes": ()}
HEADCOUNT_TOOLS: tuple[str, ...] = ("xero.observe_headcount",)
PAYRUN_TOOLS: tuple[str, ...] = ("xero.observe_payrun",)
TIMESHEET_TOOLS: tuple[str, ...] = ("xero.observe_timesheets",)
HEADCOUNT_PAGE_SCHEMA = "lightbulb.xero_headcount_page.v1"
PAYRUN_SCHEMA = "lightbulb.xero_payrun_observation.v1"
TIMESHEET_PAGE_SCHEMA = "lightbulb.xero_timesheet_page.v1"
# Reads that carry a person's identity; the team is built only from pages the platform has already reduced to commitments.
IDENTIFYING_TOOLS: tuple[str, ...] = ("quickbooks.payroll_employees", "quickbooks.payroll_payslips", "xero.list_payroll_au_employees", "xero.list_payroll_au_payruns", "xero.list_payroll_au_timesheets", "xero.list_employees_accounting")
EMPLOYMENT_BASES: tuple[str, ...] = ("full_time", "part_time", "casual")
COUNTED_TIMESHEET_STATUSES: tuple[str, ...] = ("APPROVED", "PROCESSED")
MEMBER_STATUSES: tuple[str, ...] = ("active", "terminated", "not_on_headcount")
MemberStatus = Literal["active", "terminated", "not_on_headcount"]
EmploymentBasis = Literal["full_time", "part_time", "casual", "unstated"]
MAX_HOURS_PER_WEEK = Decimal("84")
_HALF = Decimal("0.5")
_TENTH = Decimal("0.1")
_HUNDRED = Decimal("100")


class PayrollTeamError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PayrollTeamError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _half_hours(value: Decimal) -> Decimal:
    return ((value / _HALF).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * _HALF).quantize(_TENTH)


class TeamMember(StrictModel):
    worker_ref: OpaqueRef
    status: MemberStatus
    start_date: str | None = None
    termination_date: str | None = None
    employment_basis: EmploymentBasis = "unstated"
    hours_worked: Decimal = Field(default=Decimal("0"), validate_default=True)
    worked_hours_per_week: Decimal | None = None
    hours_per_week: Decimal | None = None
    hours_basis: Literal["timesheets", "stated"] | None = None
    paid_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    pay_periods: int = Field(default=0, ge=0)
    cost_rate: Decimal | None = None
    cost_basis: Literal["timesheets", "stated_hours"] | None = None
    profile_ready: bool = False
    note: ShortText

    @field_validator("hours_worked", "worked_hours_per_week", "hours_per_week", "paid_hours", "cost_rate", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class PayrollTeam(StrictModel):
    schema_id: str = Field(default=PAYROLL_TEAM_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    period_start: str | None = None
    period_end: str | None = None
    weeks: Decimal | None = None
    pay_runs: int = Field(ge=0)
    on_cost_percent: Decimal
    members: tuple[TeamMember, ...] = Field(default_factory=tuple, max_length=2000)
    profiles: tuple[WorkerProfile, ...] = Field(default_factory=tuple, max_length=2000)
    by_status: dict[str, int] = Field(default_factory=dict)
    ready: int = Field(ge=0)
    confirm: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assumptions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=200)
    team_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("members", "profiles", "confirm", "assumptions", "notes", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("as_of")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @field_validator("weeks", "on_cost_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PayrollTeam":
        counts: dict[str, int] = {}
        for member in self.members:
            counts[member.status] = counts.get(member.status, 0) + 1
        if self.by_status != counts:
            raise ValueError("by_status counts the members")
        ready = {member.worker_ref: member for member in self.members if member.profile_ready}
        if self.ready != len(ready) or {profile.worker_ref for profile in self.profiles} != set(ready):
            raise ValueError("there is one profile for every member whose profile is ready, and no other")
        for profile in self.profiles:
            member = ready[profile.worker_ref]
            if (profile.kind, profile.currency, profile.hours_per_week, profile.cost_rate) != ("employee", self.currency, member.hours_per_week, member.cost_rate):
                raise ValueError("each profile carries its member's hours and cost rate")
        if not skip_digests(info) and self.team_digest != sealed_digest(PayrollTeam, self, "team_digest"):
            raise ValueError("team_digest must commit the exact document")
        return self

    def member(self, worker_ref: str) -> TeamMember:
        found = next((member for member in self.members if member.worker_ref == worker_ref), None)
        if found is None:
            raise LookupError(f"{worker_ref} is not on this team")
        return found

    def render(self) -> str:
        lines = [f"**Team from payroll** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {member.worker_ref}: {member.note}" for member in self.members)
        lines.extend(f"- confirm: {item}" for item in self.confirm)
        return "\n".join(lines)


def _read(source: Any, *, tools: tuple[str, ...], schema: str, as_of: str, what: str) -> tuple[dict[str, Any], str]:
    from lightbulb.company_execution_bridge import ObservationProvenance

    raw = dict(detached(source)) if isinstance(source, Mapping) else {}
    _require(raw.get("provenance") is not None and raw.get("payload") is not None, "SOURCE_NOT_SEALED", f"the {what} read carries its provenance and the exact payload it returned")
    read = ObservationProvenance.model_validate(raw["provenance"])
    _require(read.source_tool not in IDENTIFYING_TOOLS, "IDENTITY_NOT_OBSERVED", f"{read.source_tool} carries people's names and details; the team is read only from the governed pages ({', '.join(tools)}), whose identities the platform has already reduced to commitments")
    _require(read.provenance_digest != GENESIS_DIGEST and read.source_tool in tools, "SOURCE_TOOL_MISMATCH", f"the {what} is read with {list(tools)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(raw["payload"])), "SOURCE_DIGEST_MISMATCH", f"the {what} must be the exact output the read returned")
    _require(parsed(read.completed_at) <= parsed(as_of), "SOURCE_FROM_FUTURE", f"the {what} read must complete before the team is built")
    payload = dict(raw["payload"])
    _require(payload.get("schema") == schema, "PAGE_SHAPE_UNKNOWN", f"expected a {schema} {what} page")
    return payload, read.provenance_digest


def _day(value: Any, *, what: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise PayrollTeamError("DATE_UNREADABLE", f"{what} {value!r} is not a calendar date") from exc


def _covered_days(periods: Sequence[tuple[date, date]], *, from_day: date | None = None, until_day: date | None = None) -> int:
    """Calendar days the periods cover between them, a day counted once however many pages cover it, within the worker's own employment when given."""

    days = 0
    cursor: date | None = None
    for start, end in sorted(periods):
        start, end = max(start, from_day) if from_day else start, min(end, until_day) if until_day else end
        if cursor is not None and start <= cursor:
            start = cursor + timedelta(days=1)
        if end >= start:
            days += (end - start).days + 1
            cursor = end if cursor is None else max(cursor, end)
    return days


def build_payroll_team(*, company_ref: str, currency: str, as_of: str, headcount: Mapping[str, Any], payruns: Sequence[Mapping[str, Any]] = (), timesheets: Sequence[Mapping[str, Any]] = (), basis_by_worker: Mapping[str, str] | None = None, hours_by_worker: Mapping[str, Any] | None = None, on_cost_percent: Any = "0", profiles: Sequence[Mapping[str, Any] | WorkerProfile] = ()) -> PayrollTeam:
    """The sealed team: every worker the payroll pages name, their hours and the cost of their hour, and a ready profile where both are known."""

    at = timestamp(as_of, field_name="as_of")
    money = str(currency).upper()
    on_cost = decimal_value(on_cost_percent, field_name="on_cost_percent")
    _require(Decimal("0") <= on_cost <= _HUNDRED, "ON_COST_INVALID", "on-costs are a percentage from 0 to 100")
    stated_basis = {str(ref): str(value) for ref, value in dict(basis_by_worker or {}).items()}
    bad = sorted(value for value in stated_basis.values() if value not in EMPLOYMENT_BASES)
    _require(not bad, "BASIS_UNKNOWN", f"{bad} are not among {EMPLOYMENT_BASES}")
    stated_hours = {str(ref): decimal_value(value, field_name="hours_by_worker") for ref, value in dict(hours_by_worker or {}).items()}
    _require(all(Decimal("0") < value <= MAX_HOURS_PER_WEEK for value in stated_hours.values()), "HOURS_INVALID", f"stated weekly hours are above 0 and at most {MAX_HOURS_PER_WEEK}")
    earlier = {profile.worker_ref: profile for profile in (item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(dict(detached(item))) for item in profiles)}
    digests: list[str] = []
    notes: list[str] = []

    # who is on the payroll
    page, digest = _read(headcount, tools=HEADCOUNT_TOOLS, schema=HEADCOUNT_PAGE_SCHEMA, as_of=at, what="headcount")
    _require(page.get("has_more") is False, "PAGE_INCOMPLETE", "the headcount page says more employees follow; read them all before building the team")
    digests.append(digest)
    people: dict[str, dict[str, Any]] = {}
    for row in page.get("employees") or ():
        ref = payroll_worker_ref(dict(row).get("employee_id_sha256"))
        status = str(dict(row).get("status", "")).upper()
        _require(status in ("ACTIVE", "TERMINATED"), "STATUS_UNKNOWN", f"an employee's status is {status or 'missing'}, not ACTIVE or TERMINATED")
        people[ref] = {"status": "active" if status == "ACTIVE" else "terminated", "start_date": None if not row.get("start_date") else _day(row["start_date"], what="a start date").isoformat(), "termination_date": None if not row.get("termination_date") else _day(row["termination_date"], what="a termination date").isoformat()}

    # what the posted pay runs paid, per worker and pay period
    paid: dict[str, list[tuple[date, date, Decimal]]] = {}
    seen_runs: dict[str, str] = {}
    posted = drafts = 0
    for source in payruns:
        run, digest = _read(source, tools=PAYRUN_TOOLS, schema=PAYRUN_SCHEMA, as_of=at, what="pay run")
        run_ref = str(run.get("pay_run_id_sha256"))
        body = stable_digest({key: value for key, value in run.items() if key not in ("observed_at", "evidence_sha256", "query_sha256")})
        if run_ref in seen_runs:
            _require(seen_runs[run_ref] == body, "PAYRUN_CONFLICT", "the same pay run was read twice and the reads disagree")
            continue
        seen_runs[run_ref] = body
        digests.append(digest)
        if str(run.get("disposition")) != "POSTED":
            drafts += 1
            continue
        _require(str(run.get("currency", "")).upper() == money, "PAYRUN_CURRENCY_MISMATCH", f"the pay run is in {run.get('currency')}; the company's books are in {money}")
        posted += 1
        start, end = _day(run.get("period_start"), what="a pay period start"), _day(run.get("period_end"), what="a pay period end")
        _require(end >= start, "PERIOD_INVALID", "a pay period ends before it starts")
        for worker in run.get("workers") or ():
            pay = (Decimal(int(dict(worker).get("wages_minor", 0))) + Decimal(int(dict(worker).get("super_minor", 0)))) / _HUNDRED
            paid.setdefault(payroll_worker_ref(dict(worker).get("employee_id_sha256")), []).append((start, end, pay))
    if drafts:
        notes.append(f"{drafts} pay run(s) not posted (draft or not found) are not counted")

    # the hours the timesheets approve
    sheets: dict[str, dict[str, tuple[date, date, Decimal]]] = {}
    periods: list[tuple[date, date]] = []
    for source in timesheets:
        sheet_page, digest = _read(source, tools=TIMESHEET_TOOLS, schema=TIMESHEET_PAGE_SCHEMA, as_of=at, what="timesheet")
        _require(sheet_page.get("has_more") is False, "PAGE_INCOMPLETE", "a timesheet page says more rows follow; read them all before building the team")
        digests.append(digest)
        periods.append((_day(sheet_page.get("period_start"), what="a timesheet page start"), _day(sheet_page.get("period_end"), what="a timesheet page end")))
        for row in sheet_page.get("timesheets") or ():
            if str(dict(row).get("status", "")).upper() not in COUNTED_TIMESHEET_STATUSES:
                continue
            ref = payroll_worker_ref(dict(row).get("employee_id_sha256"))
            entry = (_day(row.get("start_date"), what="a timesheet start"), _day(row.get("end_date"), what="a timesheet end"), decimal_value(row.get("hours"), field_name="hours"))
            key = str(row.get("timesheet_id_sha256"))
            prior = sheets.setdefault(ref, {}).get(key)
            _require(prior is None or prior == entry, "TIMESHEET_CONFLICT", "the same timesheet was read twice and the reads disagree")
            sheets[ref][key] = entry
    days = _covered_days(periods)
    weeks = None if days == 0 else (Decimal(days) / Decimal(7)).quantize(Decimal("0.01"))

    members: list[dict[str, Any]] = []
    ready_profiles: list[WorkerProfile] = []
    for ref in sorted(set(people) | set(paid) | set(sheets)):
        person = people.get(ref, {"status": "not_on_headcount", "start_date": None, "termination_date": None})
        entries = list(sheets.get(ref, {}).values())
        worked = sum((hours for _s, _e, hours in entries), Decimal("0"))
        # a worker who started or left inside the window is averaged over the days they were employed, not the whole window
        employed = _covered_days(periods, from_day=None if not person["start_date"] else date.fromisoformat(person["start_date"]), until_day=None if not person["termination_date"] else date.fromisoformat(person["termination_date"]))
        per_week = None if not entries or employed == 0 else (worked / (Decimal(employed) / Decimal(7))).quantize(_TENTH, rounding=ROUND_HALF_UP)
        costed_pay = costed_hours = salaried_pay = Decimal("0")
        salaried_days = 0
        for start, end, pay in paid.get(ref, ()):
            hours = sum((h for s, e, h in entries if s >= start and e <= end), Decimal("0"))
            if hours > 0:
                costed_pay, costed_hours = costed_pay + pay, costed_hours + hours
            else:
                salaried_pay, salaried_days = salaried_pay + pay, salaried_days + (end - start).days + 1
        loading = Decimal("1") + on_cost / _HUNDRED
        stated = stated_hours.get(ref)
        cost_rate: Decimal | None = None
        cost_basis = None
        if costed_hours > 0:
            cost_rate, cost_basis = _money(costed_pay / costed_hours * loading), "timesheets"
        elif salaried_days and stated is not None:
            cost_rate, cost_basis = _money(salaried_pay / (Decimal(salaried_days) / Decimal(7)) / stated * loading), "stated_hours"
        if per_week is not None and per_week > 0:
            hours_per_week, hours_basis = min(_half_hours(per_week), MAX_HOURS_PER_WEEK), "timesheets"
        elif stated is not None:
            hours_per_week, hours_basis = stated, "stated"
        else:
            hours_per_week, hours_basis = None, None
        ready = person["status"] == "active" and cost_rate is not None and cost_rate > 0 and hours_per_week is not None
        basis = stated_basis.get(ref, "unstated")
        if ready:
            note = f"{hours_per_week}h a week ({hours_basis}), an hour costs {cost_rate} {money} ({'wages and super over timesheet hours' if cost_basis == 'timesheets' else 'weekly pay over the stated hours'})"
        elif person["status"] == "terminated":
            note = f"left on {person['termination_date'] or 'an unrecorded date'}; no profile"
        elif person["status"] == "not_on_headcount":
            note = "paid or on a timesheet but not on the headcount page read; read the headcount with every status before profiling them"
        elif paid.get(ref) and costed_hours == 0 and stated is None:
            note = "paid with no timesheet hours: state their weekly hours in hours_by_worker to price their hour"
        elif not paid.get(ref):
            note = "no posted pay run in the reads pays this worker yet, so their hour has no cost"
        else:
            note = "the hours or the hour's cost are not known yet"
        members.append({"worker_ref": ref, "status": person["status"], "start_date": person["start_date"], "termination_date": person["termination_date"], "employment_basis": basis, "hours_worked": str(worked), "worked_hours_per_week": None if per_week is None else str(per_week), "hours_per_week": None if hours_per_week is None else str(hours_per_week), "hours_basis": hours_basis, "paid_hours": str(costed_hours), "pay_periods": len(paid.get(ref, ())), "cost_rate": None if cost_rate is None else str(cost_rate), "cost_basis": cost_basis, "profile_ready": ready, "note": note[:300]})
        if ready:
            from lightbulb.skills_matching import compile_worker_profile

            prior = earlier.get(ref)
            carried: dict[str, Any] = {} if prior is None else {key: value for key, value in (("role_ref", prior.role_ref), ("location_ref", prior.location_ref)) if value is not None}
            ready_profiles.append(compile_worker_profile(ref, kind="employee", cost_rate=cost_rate, currency=money, claims=[] if prior is None else [item.to_dict() for item in prior.claims], evidence=[] if prior is None else [item.to_dict() for item in prior.evidence], hours_per_week=str(hours_per_week), **({"available_from": f"{person['start_date']}T00:00:00Z"} if person["start_date"] else {}), **carried))

    by_status: dict[str, int] = {}
    for member in members:
        by_status[member["status"]] = by_status.get(member["status"], 0) + 1
    confirm: list[str] = []
    unskilled = sum(1 for profile in ready_profiles if not profile.claims)
    if unskilled:
        confirm.append(f"skills: {unskilled} ready profile(s) carry no confirmed skills; the skills are the owner's to confirm (payroll does not know them): add claims to those profiles")
    unstated = sum(1 for member in members if member["status"] == "active" and member["employment_basis"] == "unstated")
    if unstated:
        confirm.append(f"employment basis: {unstated} active worker(s) unstated; pass basis_by_worker (full_time, part_time or casual), the governed pages do not carry it")
    salaried = sum(1 for member in members if member["status"] == "active" and member["cost_rate"] is None and member["pay_periods"])
    if salaried:
        confirm.append(f"weekly hours: {salaried} worker(s) are paid with no timesheet hours; state their hours in hours_by_worker to price their hour")
    assumptions = [
        "an hour's cost is the wages and super the posted pay runs paid over the approved timesheet hours in the same pay periods, so pay for leave taken falls on the hours worked",
        f"on-costs of {on_cost}% (payroll tax, workers' compensation, leave loading) are added as stated" if on_cost > 0 else "no on-costs are added beyond wages and super: state payroll tax, workers' compensation and leave loading with on_cost_percent",
    ]
    ready_count = len(ready_profiles)
    verdict = f"{ready_count} of {len(members)} worker(s) have a profile ready from the payroll" + (f"; {by_status['terminated']} left" if by_status.get("terminated") else "") + (f"; {len(confirm)} thing(s) to confirm" if confirm else "") + ("; no posted pay run was read, so no hour has a cost" if posted == 0 else "")
    payload = {
        "company_ref": company_ref, "currency": money, "as_of": at, "period_start": None if not periods else min(start for start, _end in periods).isoformat(), "period_end": None if not periods else max(end for _start, end in periods).isoformat(),
        "weeks": None if weeks is None else str(weeks), "pay_runs": posted, "on_cost_percent": str(on_cost), "members": [{key: value for key, value in member.items() if value is not None} for member in members],
        "profiles": [profile.to_dict() for profile in ready_profiles], "by_status": by_status, "ready": ready_count, "confirm": [item[:300] for item in confirm], "assumptions": [item[:300] for item in assumptions], "notes": [item[:300] for item in notes],
        "verdict": verdict[:300], "source_digests": digests,
    }
    return seal(PayrollTeam, {key: value for key, value in payload.items() if value is not None}, "team_digest")


def verify_payroll_team(value: Any) -> PayrollTeam:
    return value if isinstance(value, PayrollTeam) else PayrollTeam.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built", "entity_ref", "version", "unchanged", "persisted"}})


__all__ = [
    "COUNTED_TIMESHEET_STATUSES", "EMPLOYMENT_BASES", "HEADCOUNT_PAGE_SCHEMA", "HEADCOUNT_TOOLS", "IDENTIFYING_TOOLS", "MEMBER_STATUSES", "PAYROLL_TEAM_MANIFEST", "PAYROLL_TEAM_SCHEMA", "PAYRUN_SCHEMA", "PAYRUN_TOOLS", "TIMESHEET_PAGE_SCHEMA", "TIMESHEET_TOOLS",
    "PayrollTeam", "PayrollTeamError", "TeamMember", "build_payroll_team", "verify_payroll_team",
]
