"""Backfill on connect: the past months of a company's books, read one month at a time, so the history works on day one.

A company that connects its ledger today has one window of books and an
empty history: no trend, no warning, no calibrated threshold, a break-even
on a single period.  Its ledger already holds the answer for every past
month.  ``plan_books_backfill`` lists the reads that recover it: one profit
and loss read per complete calendar month and, when asked, one balance
sheet as at each month end, oldest first, each with the exact arguments the
platform's read takes.  The host makes the reads; nothing here reads a
provider.

``group_backfill_sources`` pairs the returned reads by the period each
report states for itself (never by the order they arrive), so a month is
built only from reports that say they describe it.  ``seal_backfill``
records what happened to every planned month: recorded, amended, unchanged,
refused with the snapshot's own reason, skipped because the ledger shows no
activity yet, or missing because no read came back.  Months before the
ledger's first activity are skipped rather than recorded as zeros, so a
business that started in March does not show revenue "rising from nothing".
One read per month keeps every snapshot bound to the exact read that
produced it.

Xero and QuickBooks Online are read, each with its own tool and argument
names.  A QuickBooks read also asks for the accrual basis, so its months mean
what Xero's do (the report states its basis, and a cash-basis month says so
in the snapshot's notes).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.books_snapshot import BALANCE_SHEET_TOOLS, PROFIT_AND_LOSS_TOOLS, BooksSnapshotError, report_as_at, report_period
from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, parsed, seal, sealed_digest, skip_digests, timestamp

BOOKS_BACKFILL_PLAN_SCHEMA = "lightbulb.books_backfill_plan.v1"
BOOKS_BACKFILL_SCHEMA = "lightbulb.books_backfill.v1"
BACKFILL_MANIFEST: dict[str, Any] = {"engine": "books_backfill", "kind": "intelligence_document", "reads": ("books_snapshot",), "writes": ("books_snapshot",)}
# provider -> source kind -> (read tool, argument names); only ledgers whose reports the books snapshot parses
BACKFILL_READS: dict[str, dict[str, tuple[str, tuple[str, ...]]]] = {
    "xero": {"profit_and_loss": ("xero.profit_loss_report", ("fromDate", "toDate")), "balance_sheet": ("xero.balance_sheet_report", ("date",))},
    "quickbooks": {"profit_and_loss": ("quickbooks.profit_loss_report", ("start_date", "end_date")), "balance_sheet": ("quickbooks.balance_sheet_report", ("as_of_date",))},
}
# provider -> source kind -> arguments every read carries as well as its dates
BACKFILL_FIXED_ARGUMENTS: dict[str, dict[str, dict[str, str]]] = {
    "quickbooks": {"profit_and_loss": {"accounting_method": "Accrual"}, "balance_sheet": {"accounting_method": "Accrual"}},
}
WINDOW_STATUSES: tuple[str, ...] = ("recorded", "amended", "unchanged", "refused", "skipped_before_activity", "missing")
WindowStatus = Literal["recorded", "amended", "unchanged", "refused", "skipped_before_activity", "missing"]
MAX_MONTHS = 36


class BooksBackfillError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BooksBackfillError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _month_start(day: date) -> date:
    return day.replace(day=1)


def _next_month(day: date) -> date:
    return (day.replace(day=28) + timedelta(days=4)).replace(day=1)


def _stamp(day: date) -> str:
    return f"{day.isoformat()}T00:00:00Z"


class BackfillRead(StrictModel):
    window_start: str
    window_end: str
    kind: Literal["profit_and_loss", "balance_sheet"]
    tool: ShortText
    arguments: dict[str, str]


class BooksBackfillPlan(StrictModel):
    schema_id: str = Field(default=BOOKS_BACKFILL_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    provider: ShortText
    as_of: str
    months: int = Field(ge=1, le=MAX_MONTHS)
    balance_sheets: bool
    windows: tuple[str, ...] = Field(max_length=MAX_MONTHS)
    reads: tuple[BackfillRead, ...] = Field(max_length=MAX_MONTHS * 2)
    verdict: ShortText
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("windows", "reads", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksBackfillPlan":
        if len(self.windows) != self.months or len(self.reads) != self.months * (2 if self.balance_sheets else 1):
            raise ValueError("the plan reads every month it names, once per report")
        if not skip_digests(info) and self.plan_digest != sealed_digest(BooksBackfillPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def render(self) -> str:
        return f"**Books backfill plan** ({self.company_ref}): {self.verdict}"


def plan_books_backfill(company_ref: str, *, as_of: str, months: int = 12, provider: str = "xero", balance_sheets: bool = True) -> BooksBackfillPlan:
    """The reads that recover the last ``months`` complete calendar months before ``as_of``, oldest first."""

    _require(provider in BACKFILL_READS, "PROVIDER_UNSUPPORTED", f"backfill reads the ledgers whose reports the books snapshot parses: {sorted(BACKFILL_READS)}; {provider} is not one yet")
    _require(1 <= int(months) <= MAX_MONTHS, "MONTHS_INVALID", f"backfill covers 1 to {MAX_MONTHS} months")
    at = timestamp(as_of, field_name="as_of")
    end = _month_start(parsed(at).date())
    starts: list[date] = []
    cursor = end
    for _ in range(int(months)):
        cursor = _month_start(cursor - timedelta(days=1))
        starts.append(cursor)
    starts.reverse()
    tools = BACKFILL_READS[provider]
    fixed = BACKFILL_FIXED_ARGUMENTS.get(provider, {})
    reads: list[dict[str, Any]] = []
    windows: list[str] = []
    for start in starts:
        stop = _next_month(start)
        last = stop - timedelta(days=1)
        windows.append(f"books:{start.isoformat()}:{stop.isoformat()}")
        tool, names = tools["profit_and_loss"]
        reads.append({"window_start": _stamp(start), "window_end": _stamp(stop), "kind": "profit_and_loss", "tool": tool, "arguments": {names[0]: start.isoformat(), names[1]: last.isoformat(), **fixed.get("profit_and_loss", {})}})
        if balance_sheets:
            tool, names = tools["balance_sheet"]
            reads.append({"window_start": _stamp(start), "window_end": _stamp(stop), "kind": "balance_sheet", "tool": tool, "arguments": {names[0]: last.isoformat(), **fixed.get("balance_sheet", {})}})
    verdict = f"{len(reads)} read(s) recover {int(months)} month(s), {starts[0].strftime('%B %Y')} to {starts[-1].strftime('%B %Y')}" + (", each with its month-end balance sheet" if balance_sheets else ", without balance sheets") + "; record them with backfill record"
    return seal(BooksBackfillPlan, {"company_ref": company_ref, "provider": provider, "as_of": at, "months": int(months), "balance_sheets": bool(balance_sheets), "windows": windows, "reads": reads, "verdict": verdict[:300]}, "plan_digest")


_PRESENTATION = frozenset({"summary", "provider_effect_executed", "documents_built"})


def verify_books_backfill_plan(value: Any) -> BooksBackfillPlan:
    """The sealed plan, from the model or from the dict a console returned (its summary fields are dropped, never trusted)."""

    return value if isinstance(value, BooksBackfillPlan) else BooksBackfillPlan.model_validate({key: item for key, item in dict(detached(value)).items() if key not in _PRESENTATION})


def group_backfill_sources(sources: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """The supplied reads paired into monthly windows by the period each report states, oldest first, and the reads that could not be placed (with why)."""

    months: dict[tuple[str, str], dict[str, Any]] = {}
    unplaced: list[str] = []
    for index, raw in enumerate(sources):
        source = dict(detached(raw))
        kind = str(source.get("kind", ""))
        tool = str(dict(source.get("provenance") or {}).get("source_tool", ""))
        try:
            if kind == "profit_and_loss":
                _require(tool in PROFIT_AND_LOSS_TOOLS, "SOURCE_TOOL_MISMATCH", f"read {index} is {tool}, not a profit and loss read")
                start, end, _label = report_period(source.get("payload"))
                start_day, end_day = parsed(start).date(), parsed(end).date()
                _require(start_day.day == 1 and _next_month(start_day) == end_day, "WINDOW_NOT_A_MONTH", f"read {index} covers {start[:10]} to {end[:10]}; backfill records calendar months")
            elif kind == "balance_sheet":
                _require(tool in BALANCE_SHEET_TOOLS, "SOURCE_TOOL_MISMATCH", f"read {index} is {tool}, not a balance sheet read")
                as_at = parsed(report_as_at(source.get("payload"))).date()
                start_day = _month_start(as_at)
                end_day = _next_month(start_day)
                _require(as_at == end_day - timedelta(days=1), "WINDOW_NOT_A_MONTH", f"read {index} is as at {as_at.isoformat()}; backfill pairs month-end balance sheets")
            else:
                raise BooksBackfillError("SOURCE_KIND_UNKNOWN", f"read {index} is {kind or 'untyped'}, not profit_and_loss or balance_sheet")
        except (BooksBackfillError, BooksSnapshotError) as exc:
            unplaced.append(str(exc)[:300])
            continue
        window = months.setdefault((_stamp(start_day), _stamp(end_day)), {"window_start": _stamp(start_day), "window_end": _stamp(end_day), "sources": []})
        if any(item["kind"] == kind for item in window["sources"]):
            unplaced.append(f"SOURCE_DUPLICATE: a second {kind} read for {start_day.strftime('%B %Y')}")
            continue
        window["sources"].append(source)
    grouped = [months[key] for key in sorted(months)]
    for window in grouped:
        if not any(item["kind"] == "profit_and_loss" for item in window["sources"]):
            unplaced.append(f"SOURCES_MISSING: the balance sheet for {window['window_start'][:7]} came without its profit and loss read")
    return [window for window in grouped if any(item["kind"] == "profit_and_loss" for item in window["sources"])], unplaced


class BackfillWindow(StrictModel):
    window_ref: OpaqueRef
    window_start: str
    window_end: str
    status: WindowStatus
    snapshot_digest: Sha256Digest | None = None
    with_balance_sheet: bool = False
    detail: ShortText | None = None


class BooksBackfill(StrictModel):
    schema_id: str = Field(default=BOOKS_BACKFILL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    plan_digest: Sha256Digest | None = None
    windows: tuple[BackfillWindow, ...] = Field(max_length=MAX_MONTHS * 2)
    recorded: int = Field(ge=0)
    refused: int = Field(ge=0)
    skipped: int = Field(ge=0)
    missing: int = Field(ge=0)
    unplaced: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=MAX_MONTHS * 2)
    verdict: ShortText
    backfill_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("windows", "unplaced", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksBackfill":
        counts = {status: sum(1 for row in self.windows if row.status == status) for status in WINDOW_STATUSES}
        if (self.recorded, self.refused, self.skipped, self.missing) != (counts["recorded"] + counts["amended"] + counts["unchanged"], counts["refused"], counts["skipped_before_activity"], counts["missing"]):
            raise ValueError("the counts count the windows")
        if not skip_digests(info) and self.backfill_digest != sealed_digest(BooksBackfill, self, "backfill_digest"):
            raise ValueError("backfill_digest must commit the exact backfill")
        return self

    def render(self) -> str:
        lines = [f"**Books backfill** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.window_start[:7]}: {row.status}" + (f" ({row.detail})" if row.detail else "") for row in self.windows if row.status not in ("recorded", "unchanged"))
        lines.extend(f"- not placed: {item}" for item in self.unplaced)
        return "\n".join(lines)


def seal_backfill(company_ref: str, *, as_of: str, outcomes: Sequence[Mapping[str, Any]], unplaced: Sequence[str] = (), plan: BooksBackfillPlan | Mapping[str, Any] | None = None) -> BooksBackfill:
    """The sealed record of a backfill: every month that came back and what happened to it, and every planned month that did not."""

    rows = {str(item["window_start"]): {**dict(item), "window_ref": f"books:{str(item['window_start'])[:10]}:{str(item['window_end'])[:10]}"} for item in outcomes}
    plan_digest = None
    if plan is not None:
        parsed_plan = verify_books_backfill_plan(plan)
        _require(parsed_plan.company_ref == company_ref, "SOURCE_SCOPE_MISMATCH", "the plan names another company")
        plan_digest = parsed_plan.plan_digest
        for read in parsed_plan.reads:
            if read.kind == "profit_and_loss" and read.window_start not in rows:
                rows[read.window_start] = {"window_ref": f"books:{read.window_start[:10]}:{read.window_end[:10]}", "window_start": read.window_start, "window_end": read.window_end, "status": "missing", "detail": f"no {read.tool} read came back for {read.window_start[:7]}"}
    windows = [rows[key] for key in sorted(rows)]

    def count(*statuses: str) -> int:
        return sum(1 for row in windows if row["status"] in statuses)

    recorded, refused, skipped, missing = count("recorded", "amended", "unchanged"), count("refused"), count("skipped_before_activity"), count("missing")
    verdict = f"{recorded} month(s) on record" + (f", {refused} refused" if refused else "") + (f", {skipped} before the ledger's first activity" if skipped else "") + (f", {missing} still to read" if missing else "") + (f", {len(unplaced)} read(s) not placed" if unplaced else "")
    return seal(BooksBackfill, {"company_ref": company_ref, "as_of": timestamp(as_of, field_name="as_of"), "plan_digest": plan_digest, "windows": [{key: value for key, value in row.items() if value is not None} for row in windows], "recorded": recorded, "refused": refused, "skipped": skipped, "missing": missing, "unplaced": [str(item)[:300] for item in unplaced], "verdict": verdict[:300]}, "backfill_digest")


def verify_books_backfill(value: Any) -> BooksBackfill:
    return value if isinstance(value, BooksBackfill) else BooksBackfill.model_validate({key: item for key, item in dict(detached(value)).items() if key not in _PRESENTATION})


__all__ = ["BACKFILL_FIXED_ARGUMENTS", "BACKFILL_MANIFEST", "BACKFILL_READS", "BOOKS_BACKFILL_PLAN_SCHEMA", "BOOKS_BACKFILL_SCHEMA", "WINDOW_STATUSES", "BackfillRead", "BackfillWindow", "BooksBackfill", "BooksBackfillError", "BooksBackfillPlan", "group_backfill_sources", "plan_books_backfill", "seal_backfill", "verify_books_backfill", "verify_books_backfill_plan"]
