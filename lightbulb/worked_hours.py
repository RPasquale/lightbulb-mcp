"""Worked hours: what the timesheets say people actually worked, against the hours every staffing document assumes.

The skills match, job assignment, workforce capacity and sourcing documents
all plan with each worker's ``hours_per_week`` as typed into their profile.
Nobody checks it against what people really work.  ``compare_worked_hours``
reads the governed ``xero.observe_timesheets`` page (hashed employee ids,
hours per timesheet, status), counts approved and processed hours per worker
over the page's period, and puts the weekly average beside the profile:

* ``over``: working more than the profile says by more than the plan's
  tolerance, so capacity is understated and the person may be stretched;
* ``under``: working well below it, so capacity is overstated or there is a
  bench to fill;
* ``as_planned`` within tolerance; ``unprofiled`` when the timesheets name a
  worker no profile describes; ``no_timesheet`` when a profile has none.

Each worker outside tolerance gets a proposed ``hours_per_week`` (the
observed weekly average, rounded to the half hour, capped at the profile
limit of 84), as a proposal for the owner to write into the profile, never
applied.  Workers are joined by the payroll commitment ``worker:<sha[:24]>``
the payroll and employment chains already use; no identity is read.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, stable_digest, timestamp

WORKED_HOURS_SCHEMA = "lightbulb.worked_hours.v1"
WORKED_HOURS_MANIFEST: dict[str, Any] = {"engine": "worked_hours", "kind": "intelligence_document", "reads": ("worker_profiles",), "writes": ()}
TIMESHEET_TOOLS: tuple[str, ...] = ("xero.observe_timesheets",)
TIMESHEET_PAGE_SCHEMA = "lightbulb.xero_timesheet_page.v1"
COUNTED_STATUSES: tuple[str, ...] = ("APPROVED", "PROCESSED")
HoursStatus = Literal["over", "under", "as_planned", "unprofiled", "no_timesheet"]
_HALF = Decimal("0.5")


class WorkedHoursError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WorkedHoursError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _half_hours(value: Decimal) -> Decimal:
    return ((value / _HALF).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * _HALF).quantize(Decimal("0.1"))


class WorkedHoursRow(StrictModel):
    worker_ref: OpaqueRef
    status: HoursStatus
    profile_hours_per_week: Decimal | None = None
    worked_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    worked_hours_per_week: Decimal | None = None
    proposed_hours_per_week: Decimal | None = None
    note: ShortText

    @field_validator("profile_hours_per_week", "worked_hours", "worked_hours_per_week", "proposed_hours_per_week", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class WorkedHours(StrictModel):
    schema_id: str = Field(default=WORKED_HOURS_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    period_start: str
    period_end: str
    weeks: Decimal
    tolerance_percent: Decimal
    rows: tuple[WorkedHoursRow, ...] = Field(default_factory=tuple, max_length=2000)
    by_status: dict[str, int] = Field(default_factory=dict)
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    worked_hours_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("weeks", "tolerance_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkedHours":
        if sum(self.by_status.values()) != len(self.rows):
            raise ValueError("by_status counts the rows")
        if not skip_digests(info) and self.worked_hours_digest != sealed_digest(WorkedHours, self, "worked_hours_digest"):
            raise ValueError("worked_hours_digest must commit the exact comparison")
        return self

    def row(self, worker_ref: str) -> WorkedHoursRow:
        found = next((row for row in self.rows if row.worker_ref == worker_ref), None)
        if found is None:
            raise LookupError(f"{worker_ref} is not in this comparison")
        return found

    def render(self) -> str:
        lines = [f"**Worked hours** ({self.company_ref}, {self.period_start} to {self.period_end}): {self.verdict}"]
        lines.extend(f"- {row.worker_ref}: {row.status}; {row.note}" for row in self.rows if row.status != "as_planned")
        return "\n".join(lines)


def compare_worked_hours(*, company_ref: str, as_of: str, timesheets: Mapping[str, Any], profiles: Sequence[Mapping[str, Any] | Any], tolerance_percent: Any = "10") -> WorkedHours:
    """Approved and processed timesheet hours per worker over the page's period, against each profile's weekly hours, with a proposal where they part."""

    from lightbulb.company_execution_bridge import ObservationProvenance
    from lightbulb.employment_chain import payroll_worker_ref
    from lightbulb.skills_matching import WorkerProfile

    source = dict(detached(timesheets))
    _require(source.get("provenance") is not None and source.get("payload") is not None, "SOURCE_NOT_SEALED", "the timesheets read carries its provenance and the exact payload")
    read = ObservationProvenance.model_validate(source["provenance"])
    _require(read.source_tool in TIMESHEET_TOOLS, "SOURCE_TOOL_MISMATCH", f"timesheets are read with {list(TIMESHEET_TOOLS)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(source["payload"])), "SOURCE_DIGEST_MISMATCH", "the timesheets must be the exact output the read returned")
    page = dict(source["payload"])
    _require(page.get("schema") == TIMESHEET_PAGE_SCHEMA, "PAGE_SHAPE_UNKNOWN", f"expected a {TIMESHEET_PAGE_SCHEMA} page")
    _require(page.get("has_more") is False, "PAGE_INCOMPLETE", "the timesheet page says more rows follow; read them all before comparing")
    start, end = date.fromisoformat(str(page["period_start"])), date.fromisoformat(str(page["period_end"]))
    _require(end >= start, "PERIOD_INVALID", "the page's period ends before it starts")
    weeks = (Decimal((end - start).days + 1) / Decimal(7)).quantize(Decimal("0.01"))
    tolerance = decimal_value(tolerance_percent, field_name="tolerance_percent")
    _require(Decimal("0") < tolerance <= Decimal("100"), "TOLERANCE_INVALID", "the tolerance is a percentage above 0 and at most 100")

    worked: dict[str, Decimal] = {}
    for row in page.get("timesheets") or ():
        if str(row.get("status", "")).upper() not in COUNTED_STATUSES:
            continue
        ref = payroll_worker_ref(str(row["employee_id_sha256"]))
        worked[ref] = worked.get(ref, Decimal("0")) + decimal_value(row["hours"], field_name="hours")
    parsed_profiles = {profile.worker_ref: profile for profile in (item if isinstance(item, WorkerProfile) else WorkerProfile.model_validate(dict(detached(item))) for item in profiles)}

    rows: list[dict[str, Any]] = []
    for ref in sorted(set(worked) | set(parsed_profiles)):
        profile = parsed_profiles.get(ref)
        hours = worked.get(ref)
        if profile is None:
            per_week = (hours / weeks).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
            rows.append({"worker_ref": ref, "status": "unprofiled", "worked_hours": str(hours), "worked_hours_per_week": str(per_week), "note": f"worked {per_week}h a week but no profile describes this worker, so no staffing document counts them"})
            continue
        planned = Decimal(str(profile.hours_per_week))
        if hours is None:
            rows.append({"worker_ref": ref, "status": "no_timesheet", "profile_hours_per_week": str(planned), "note": "no approved timesheet in the period; a contractor or someone paid outside payroll shows here too"})
            continue
        per_week = (hours / weeks).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        gap = ((per_week - planned) / planned * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP) if planned > 0 else Decimal("0")
        if gap > tolerance:
            status = "over"
        elif gap < -tolerance:
            status = "under"
        else:
            status = "as_planned"
        proposed = None if status == "as_planned" else min(_half_hours(per_week), Decimal("84"))
        note = f"worked {per_week}h a week against the {planned.quantize(Decimal('0.1'))}h the profile plans with ({gap:+}%)" + ("" if proposed is None else f"; propose {proposed}h in the profile")
        rows.append({"worker_ref": ref, "status": status, "profile_hours_per_week": str(planned), "worked_hours": str(hours), "worked_hours_per_week": str(per_week), "proposed_hours_per_week": None if proposed is None else str(proposed), "note": note[:300]})
    by_status: dict[str, int] = {}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    off = by_status.get("over", 0) + by_status.get("under", 0)
    verdict = (f"{off} worker(s) work materially different hours from their profile" if off else "everyone profiled works about the hours their profile plans with") + (f"; {by_status['unprofiled']} worker(s) on the timesheets have no profile" if by_status.get("unprofiled") else "") + "; proposals only, nothing is applied"
    return seal(WorkedHours, {"company_ref": company_ref, "as_of": timestamp(as_of, field_name="as_of"), "period_start": start.isoformat(), "period_end": end.isoformat(), "weeks": str(weeks), "tolerance_percent": str(tolerance), "rows": [{key: value for key, value in row.items() if value is not None} for row in rows], "by_status": by_status, "verdict": verdict[:300], "source_digests": [read.provenance_digest]}, "worked_hours_digest")


def verify_worked_hours(value: Any) -> WorkedHours:
    return value if isinstance(value, WorkedHours) else WorkedHours.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built"}})


__all__ = ["COUNTED_STATUSES", "TIMESHEET_TOOLS", "WORKED_HOURS_MANIFEST", "WORKED_HOURS_SCHEMA", "WorkedHours", "WorkedHoursError", "WorkedHoursRow", "compare_worked_hours", "verify_worked_hours"]
