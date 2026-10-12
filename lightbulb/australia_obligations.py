"""Australian corporate deadlines: dated facts, never tax amounts or authority.

Civil due dates are inclusive. The snapshot covers 2026 and the 2026-27 tax
year; a configured registration/program is not inferred from cash estimates.
Payday Super dates are supplied by the existing compliance calendar engine.
"""
from __future__ import annotations

from calendar import monthrange
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import urlsplit

from pydantic import Field, ValidationInfo, field_validator, model_serializer, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, StrictModel, detached, seal, sealed_digest, skip_digests

VERIFIED_AS_OF = "2026-10-05"
COVERAGE_END = "2027-12-31"
EFFECTIVE_FROM = "2026-01-01"  # snapshot coverage, not original enactment
ATO = "https://www.ato.gov.au/"
SOURCES = {
    "bas": ATO + "businesses-and-organisations/preparing-lodging-and-paying/business-activity-statements-bas/due-dates-for-lodging-and-paying-your-bas",
    "agent": ATO + "tax-and-super-professionals/for-tax-professionals/prepare-and-lodge/registered-agent-lodgment-program/due-dates-by-obligation-type/activity-statements",
    "payg": ATO + "businesses-and-organisations/hiring-and-paying-your-workers/payg-withholding/paying-and-reporting-withheld-amounts/paying-and-reporting-payg-withholding-amounts-for-small-and-medium-withholders",
    "stp": ATO + "businesses-and-organisations/hiring-and-paying-your-workers/single-touch-payroll/start-reporting",
    "stp_finalisation": ATO + "businesses-and-organisations/hiring-and-paying-your-workers/single-touch-payroll/start-reporting/end-of-year-finalisation-through-stp",
    "fbt": ATO + "tax-and-super-professionals/for-tax-professionals/prepare-and-lodge/registered-agent-lodgment-program/due-dates-by-obligation-type/fbt-return",
    "tpar": "https://softwaredevelopers.ato.gov.au/TPRS",
    "company_tax": ATO + "tax-and-super-professionals/for-tax-professionals/prepare-and-lodge/registered-agent-lodgment-program/due-dates-for-tax-returns-by-client-type/companies-and-super-funds",
    "ato_holidays": ATO + "tax-and-super-professionals/for-tax-professionals/prepare-and-lodge/registered-agent-lodgment-program/lodgment-and-payment-dates-on-weekends-or-public-holidays",
    "payg_large": ATO + "businesses-and-organisations/hiring-and-paying-your-workers/payg-withholding/paying-and-reporting-withheld-amounts/paying-and-reporting-payg-withholding-amounts-for-large-withholders",
    "super": "https://softwaredevelopers.ato.gov.au/PaydaySuper",
    "super_business_days": "https://www.legislation.gov.au/C2025A00057/asmade/text",
    "consolidated_instalments": "https://www.ato.gov.au/law/view/print?DocID=CON%2FC8-0-100",
    "workers_compensation": "https://www.safeworkaustralia.gov.au/workers-compensation",
}
State = Literal["NSW", "VIC", "QLD", "WA", "SA", "TAS", "ACT", "NT"]
# Annual full-year Australian group wages only. Exemptions, grouping, partial
# years and diminishing deductions require the authority's assessment.
PAYROLL_TAX_RULES = {
    "NSW": {"annual_threshold": "1200000", "monthly_day": 7, "annual_day": 28, "source_url": "https://www.revenue.nsw.gov.au/taxes-duties-levies-royalties/payroll-tax/lodge-and-pay-returns/monthly-return", "threshold_source_url": "https://www.revenue.nsw.gov.au/taxes-duties-levies-royalties/payroll-tax/lodge-and-pay-returns/thresholds-and-rates"},
    "VIC": {"annual_threshold": "1000000", "monthly_day": 7, "annual_day": 21, "source_url": "https://www.sro.vic.gov.au/businesses-and-organisations/payroll-tax/understanding-payroll-tax", "threshold_source_url": "https://www.sro.vic.gov.au/about-us/rates-and-statistics/current-rates/payroll-tax-current-rates"},
    "QLD": {"annual_threshold": "1300000", "monthly_day": 7, "annual_day": 21, "source_url": "https://qro.qld.gov.au/payroll-tax/returns/due-dates/", "threshold_source_url": "https://qro.qld.gov.au/payroll-tax/liability/rates-thresholds/"},
    "WA": {"annual_threshold": "1000000", "monthly_day": 7, "annual_day": 21, "source_url": "https://www.wa.gov.au/government/multi-step-guides/payroll-tax-employer-guide/returns-payroll-tax-employer-guide", "threshold_source_url": "https://www.wa.gov.au/government/multi-step-guides/payroll-tax-employer-guide/calculation-payroll-tax-employer-guide"},
    "SA": {"annual_threshold": "1500000", "monthly_day": 7, "annual_day": 28, "source_url": "https://revenuesa.sa.gov.au/payrolltax/returns-and-annual-reconciliation/monthly-returns", "threshold_source_url": "https://revenuesa.sa.gov.au/forms-and-publications/documents/guides-to-legislation/guide-to-legislation-payroll-tax/2025-26-guide-to-legislation-payroll-tax"},
    "TAS": {"annual_threshold": "1250000", "monthly_day": 7, "annual_day": 21, "source_url": "https://www.sro.tas.gov.au/payroll-tax/lodge-your-return", "threshold_source_url": "https://www.sro.tas.gov.au/payroll-tax/rates-thresholds"},
    "ACT": {"annual_threshold": "1750000", "previous_annual_threshold": "2000000", "threshold_changed_on": "2026-07-01", "monthly_day": 7, "annual_day": 28, "december_day": 14, "source_url": "https://www.revenue.act.gov.au/business-taxes-and-levies/payroll-tax/about-payroll-tax", "threshold_source_url": "https://www.revenue.act.gov.au/business-taxes-and-levies/payroll-tax/about-payroll-tax"},
    "NT": {"annual_threshold": "2500000", "monthly_day": 21, "annual_day": 21, "source_url": "https://treasury.nt.gov.au/pms/tro/information/payroll-tax-guide-for-nt-employers-and-businesses.pdf", "threshold_source_url": "https://treasury.nt.gov.au/dtf/territory-revenue-office/payroll-tax/faqs_pt"},
}
THRESHOLDS = {"payg_small_inclusive": "25000", "payg_large_exclusive": "1000000", "bas_monthly_inclusive": "20000000", "december_bas_turnover_inclusive": "10000000"}


def _money(value: Any) -> Decimal:
    amount = Decimal(str(value))
    if not amount.is_finite() or amount < 0:
        raise ValueError("threshold input must be finite and non-negative")
    return amount


def withholder_from_annual_withholding(value: Any) -> str:
    amount = _money(value)
    return "large" if amount > Decimal(THRESHOLDS["payg_large_exclusive"]) else "medium" if amount > Decimal(THRESHOLDS["payg_small_inclusive"]) else "small"


def payroll_tax_threshold(state: State, *, period_end: str) -> dict[str, Any]:
    day = date.fromisoformat(period_end)
    rule = PAYROLL_TAX_RULES[state]
    if not date(2025, 7, 1) <= day <= date(2027, 6, 30):
        raise ValueError("payroll-tax threshold snapshot covers 2025-26 and 2026-27 only")
    annual = rule["previous_annual_threshold"] if state == "ACT" and period_end < rule["threshold_changed_on"] else rule["annual_threshold"]
    return {"annual_threshold": annual, "currency": "AUD", "basis": "full-year Australian group taxable wages; not a liability calculation or registration decision", "effective_from": rule.get("threshold_changed_on", "2025-07-01") if state != "ACT" or period_end >= "2026-07-01" else "2025-07-01", "effective_until": "2027-06-30", "verified_as_of": VERIFIED_AS_OF, "source_url": rule["threshold_source_url"]}


def exceeds_annual_payroll_threshold(state: State, annual_group_wages: Any, *, period_end: str) -> bool:
    return _money(annual_group_wages) > Decimal(payroll_tax_threshold(state, period_end=period_end)["annual_threshold"])


# State-office full-day holidays. Customer-local holidays cannot postpone tax.
# ATO uses its own national table, including specified part-day holidays.
_COMMON = {2026: "01-01 01-26 04-03 04-06 04-25 12-25 12-26 12-28", 2027: "01-01 01-26 03-26 03-29 04-25 12-25 12-26 12-27 12-28"}
_STATE = {
    2026: {"NSW": "04-27 06-08 10-05", "VIC": "03-09 06-08 09-25", "QLD": "05-04 10-05", "WA": "03-02 04-27 06-01", "SA": "03-09 06-08 10-05", "TAS": "03-09 06-08", "ACT": "03-09 04-27 06-01 06-08 10-05", "NT": "05-04 06-08 08-03"},
    2027: {"NSW": "04-26 06-14 10-04", "VIC": "03-08 06-14", "QLD": "04-26 05-03 10-04", "WA": "03-01 04-26 06-07", "SA": "03-08 06-14 10-04", "TAS": "03-08 06-14", "ACT": "03-08 04-26 05-31 06-14 10-04", "NT": "04-26 05-03 06-14 08-02"},
}


def ato_holidays(year: int) -> frozenset[date]:
    """ATO national table applies to taxpayers in every state and territory."""
    if year not in _COMMON:
        raise ValueError("Australian holiday snapshot covers 2026-2027 only")
    # These additions follow the published ATO table, not the statutory
    # whole-of-State definition: WA King's Birthday, Melbourne Cup, part-days.
    extra = {2026: "09-28 11-03 12-24 12-31", 2027: "09-27 11-02 12-24 12-31"}
    return super_holidays(year) | frozenset(date.fromisoformat(f"{year}-{day}") for day in extra[year].split())


def state_holidays(year: int, state: State) -> frozenset[date]:
    if year not in _STATE:
        raise ValueError("Australian holiday snapshot covers 2026-2027 only")
    return frozenset(date.fromisoformat(f"{year}-{d}") for d in (_COMMON[year] + " " + _STATE[year][state]).split())


def super_holidays(year: int) -> frozenset[date]:
    """SGAA business days exclude a holiday for the whole of *any* state/ACT/NT.

    Local show days, Melbourne Cup, regional WA King's Birthday dates and
    part-day holidays aren't represented as whole-day statewide closures.
    The 2027 AFL holiday was TBC when verified; September onward is unverified.
    """
    return frozenset().union(*(state_holidays(year, state) for state in PAYROLL_TAX_RULES))


class BoardObligation(StrictModel):
    obligation_ref: OpaqueRef
    state: State
    due_on: date
    source_url: str
    basis: str = Field(min_length=1, max_length=1000)
    effective_from: date
    verified_as_of: date
    move_to_business_day: bool = False

    @field_validator("due_on", "effective_from", "verified_as_of", mode="before")
    @classmethod
    def dates(cls, value: Any) -> Any:
        return date.fromisoformat(value) if isinstance(value, str) else value

    @field_validator("source_url")
    @classmethod
    def official_source(cls, value: str) -> str:
        url = urlsplit(value)
        hosts = {"icare.nsw.gov.au", "sira.nsw.gov.au", "worksafe.vic.gov.au", "worksafe.qld.gov.au", "workcover.wa.gov.au", "rtwsa.com", "worksafe.tas.gov.au", "worksafe.act.gov.au", "worksafe.nt.gov.au", "comcare.gov.au"}
        if url.scheme != "https" or url.username or url.password or url.query or url.fragment or not any(url.hostname == host or (url.hostname or "").endswith("." + host) for host in hosts):
            raise ValueError("workers compensation requires an official authority HTTPS source without credentials or query")
        return value


class AustraliaCalendarFacts(StrictModel):
    states: tuple[State, ...] = ()
    federal_state: State | None = None
    # Retained as optional board facts; never used to extend ATO/payroll tax.
    local_holidays: dict[State, tuple[date, ...]] = Field(default_factory=dict)
    gst_reporting: Literal["monthly", "quarterly", "annual"] | None = None
    bas_program: Literal["self", "self_online", "agent"] | None = None
    bas_extension_eligible: bool | None = None
    registered_agent: bool | None = None
    fiscal_year_end_month: int | None = Field(default=None, ge=1, le=12)
    december_monthly_bas_concession: bool | None = None
    withholder: Literal["small", "medium", "large"] | None = None
    stp: Literal["standard", "exempt", "concession"] | None = None
    fbt_required: bool | None = None
    fbt_program: Literal["self_or_paper", "agent_electronic"] | None = None
    fbt_agent_eligible: bool | None = None
    tpar_required: bool | None = None
    company_tax_program: Literal["self_preparing", "tax_agent", "large_medium", "over_2m", "prior_returns_overdue"] | None = None
    company_tax_program_confirmed: bool | None = None
    instalments: Literal["monthly", "quarterly", "none"] | None = None
    consolidated_head_company: bool | None = None
    # Assigned cycles, not a schedule inferred from wage estimates.
    payroll_tax: dict[State, Literal["monthly", "quarterly", "half_yearly", "annual", "none"]] = Field(default_factory=dict)
    workers_compensation: tuple[BoardObligation, ...] | None = None

    @field_validator("states", "workers_compensation", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return None if value is None else tuple(value)

    @field_validator("local_holidays", mode="before")
    @classmethod
    def holiday_dates(cls, value: Any) -> Any:
        return {key: tuple(date.fromisoformat(d) if isinstance(d, str) else d for d in days) for key, days in value.items()}

    @model_validator(mode="after")
    def consistent(self) -> AustraliaCalendarFacts:
        if len(set(self.states)) != len(self.states):
            raise ValueError("each state appears once")
        if not set(self.payroll_tax).union(self.local_holidays).issubset(self.states):
            raise ValueError("tax accounts and holiday calendars must belong to confirmed company states")
        if self.federal_state is not None and self.federal_state not in self.states:
            raise ValueError("federal_state must be a confirmed company state")
        if any(cycle == "quarterly" and state != "WA" for state, cycle in self.payroll_tax.items()):
            raise ValueError("quarterly payroll tax is supported only for an assigned WA cycle")
        if any(cycle == "half_yearly" and state != "QLD" for state, cycle in self.payroll_tax.items()):
            raise ValueError("half-yearly payroll tax is supported only for an assigned QLD cycle")
        if any(item.state not in self.states for item in self.workers_compensation or ()):
            raise ValueError("board obligations must belong to confirmed company states")
        refs = [item.obligation_ref for item in self.workers_compensation or ()]
        if len(set(refs)) != len(refs):
            raise ValueError("board obligation references must be unique")
        return self


class AustraliaObligation(StrictModel):
    obligation_ref: OpaqueRef
    kind: str
    state: State | None = None
    period_end: str | None = None
    period_start: str | None = None
    nominal_due_on: str | None = None
    due_on: str | None = None
    status: Literal["scheduled", "needs_confirmation"]
    missing_facts: tuple[str, ...] = ()

    amount: None = None
    basis: str
    source_url: str
    effective_from: str
    verified_as_of: str
    holiday_source_url: str | None = None
    threshold: dict[str, Any] | None = None
    projected: bool | None = None
    existing_obligation_ref: OpaqueRef | None = None
    business_day_source_url: str | None = None

    @field_validator("missing_facts", mode="before")
    @classmethod
    def missing_fact_tuple(cls, value: Any) -> tuple[str, ...]:
        return tuple(value)

    @model_serializer(mode="wrap")
    def explicit_unknowns(self, handler: Any) -> dict[str, Any]:
        raw = handler(self)
        for key in ("amount", "state", "period_end", "due_on", "nominal_due_on"):
            raw[key] = getattr(self, key)
        return raw

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class AustraliaObligationsCalendar(StrictModel):
    schema_id: Literal["lightbulb.australia_obligations.v1"] = Field(default="lightbulb.australia_obligations.v1", alias="schema")
    company_ref: OpaqueRef
    start_on: str
    end_on: str
    obligations: tuple[AustraliaObligation, ...]
    coverage_end: str = COVERAGE_END
    missing_facts: tuple[str, ...]
    facts: dict[str, Any]
    calendar_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("obligations", "missing_facts", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return tuple(value)

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo) -> AustraliaObligationsCalendar:
        if not skip_digests(info) and self.calendar_digest != sealed_digest(AustraliaObligationsCalendar, self, "calendar_digest"):
            raise ValueError("calendar_digest must commit the exact calendar")
        return self


def _month(day: date, offset: int, target_day: int = 1) -> date:
    year, month = divmod(day.year * 12 + day.month - 1 + offset, 12)
    return date(year, month + 1, min(target_day, monthrange(year, month + 1)[1]))


def _next_business_day(day: date, holidays: frozenset[date]) -> date:
    while day.weekday() >= 5 or day in holidays:
        day += timedelta(days=1)
    return day


def compile_australia_obligations(company_ref: str, *, start_on: str, horizon_months: int = 12, facts: Mapping[str, Any] | AustraliaCalendarFacts | None = None, has_payroll: bool = True, registered_for_gst: bool = True, fiscal_year_end_month: int | None = None, pay_runs: Sequence[Mapping[str, Any]] = (), payday_schedule: Sequence[Mapping[str, Any]] = (), pay_cycle_confirmed: bool = False) -> AustraliaObligationsCalendar:
    start = date.fromisoformat(start_on)
    if not 1 <= horizon_months <= 24 or start.year < 2026:
        raise ValueError("Australia calendar requires 2026+ and 1..24 months")
    end = _month(start, horizon_months)
    f = facts if isinstance(facts, AustraliaCalendarFacts) else AustraliaCalendarFacts.model_validate(dict(facts or {}))
    if fiscal_year_end_month is not None and f.fiscal_year_end_month is not None and fiscal_year_end_month != f.fiscal_year_end_month:
        raise ValueError("conflicting Australia calendar fact: fiscal_year_end_month")
    fy_end = f.fiscal_year_end_month or fiscal_year_end_month
    rows: list[dict[str, Any]] = []
    gaps: set[str] = set()

    def add(kind: str, due: date | None, period: date | None, source: str, basis: str, *, state: str | None = None, shift: bool = True, extra: Mapping[str, Any] | None = None, effective: str = EFFECTIVE_FROM) -> None:
        nominal = due
        if due is not None and shift:
            if due.year not in _STATE or (state in (None, "VIC") and due >= date(2027, 9, 1)):
                gaps.add(f"Refresh {state or 'ATO'} holidays for {due.year}; the published snapshot is incomplete")
                due = None
            elif state is None:
                due = _next_business_day(due, ato_holidays(due.year) | (ato_holidays(due.year + 1) if due.year + 1 in _STATE else frozenset()))
                basis += "; ATO national table (all taxpayers); no company-local extension"
            elif state == "TAS" and kind.startswith("state_payroll_tax"):
                basis += "; earlier nominal date retained: Tasmania weekend/holiday concession unverified"
                gaps.add("Confirm Tasmania payroll-tax weekend/holiday treatment; nominal date retained")
            else:
                due = _next_business_day(due, state_holidays(due.year, state))
        if nominal is not None and not start <= (due or nominal) < end:
            return
        if due is not None and due > date.fromisoformat(COVERAGE_END):
            gaps.add("Refresh statutory rules beyond " + COVERAGE_END)
            due = None
        rows.append({"obligation_ref": f"AU:{kind}:{state or 'federal'}:{period or nominal or 'unknown'}", "kind": kind, "state": state, "period_end": None if period is None else period.isoformat(), "nominal_due_on": None if nominal is None else nominal.isoformat(), "due_on": None if due is None else due.isoformat(), "status": "scheduled" if due else "needs_confirmation", "amount": None, "basis": basis + "; amounts not computed", "source_url": source, "effective_from": effective, "verified_as_of": VERIFIED_AS_OF, **({"holiday_source_url": (SOURCES["ato_holidays"] if state is None else f"https://www.fairwork.gov.au/employment-conditions/public-holidays/{nominal.year}-public-holidays")} if shift and nominal else {}), **dict(extra or {})})

    def unknown(kind: str, message: str, source: str, state: str | None = None) -> None:
        gaps.add(message)
        add(kind, None, None, source, message, state=state, shift=False)

    def bas_due(period: date) -> date | None:
        # Unknown GST cannot justify a later date; flag the candidate below.
        if f.gst_reporting in (None, "monthly"):
            return _month(period, 1, 21)
        due = date(period.year + 1, 2, 28) if period.month == 12 else _month(period, 1, 28)
        if period.month == 12:
            return due
        eligible = f.bas_extension_eligible is True and f.instalments in ("none", "quarterly") and f.gst_reporting is not None
        if f.bas_program == "agent" and f.registered_agent is True and eligible:
            # Published dates, not a recurring rule carried into the next program.
            published = {"2026-06-30": "2026-08-25", "2026-09-30": "2026-11-25", "2027-03-31": "2027-05-26"}
            if period >= date(2027, 6, 30):
                return None
            if period.isoformat() in published:
                return date.fromisoformat(published[period.isoformat()])
            if start <= due < end:
                gaps.add("Earlier agent-program dates are outside the verified snapshot; self-lodger date retained")
        elif f.bas_program in ("agent", "self_online") and (not eligible or f.bas_program == "agent" and f.registered_agent is not True):
            gaps.add("Agent/online extension eligibility not established or statement excluded; self-lodger date retained")
        if f.bas_program == "self_online" and eligible:
            return due + timedelta(days=14)
        return due

    periods = []
    cursor = _month(start, -14)
    while cursor < end:
        periods.append(_month(cursor, 1) - timedelta(days=1))
        cursor = _month(cursor, 1)
    if registered_for_gst and f.gst_reporting is None:
        unknown("bas", "Confirm gst_reporting", SOURCES["bas"])
    if registered_for_gst and f.gst_reporting == "annual":
        unknown("bas", "Annual GST: confirm the return-specific due date with the tax agent/ATO", SOURCES["bas"])
    if f.gst_reporting == "quarterly" or f.withholder == "small" or f.instalments == "quarterly":
        if bas_due(date(2026, 9, 30)) is None:
            unknown("bas_program", "Confirm bas_program and eligibility for any online/agent extension from the issued statement", SOURCES["agent"])
    if has_payroll and f.withholder is None:
        unknown("payg_withholding", "Confirm ATO-assigned withholder class", SOURCES["payg"])
    for period in periods:
        quarterly = period.month % 3 == 0
        if registered_for_gst and f.gst_reporting == "monthly":
            concession = period.month == 12 and f.registered_agent is True and f.bas_program == "agent" and f.december_monthly_bas_concession is True
            due = _month(period, 2 if concession else 1, 21)
            add("bas", due, period, SOURCES["agent"] if concession else SOURCES["bas"], "Monthly BAS lodgment and payment; December extension only for confirmed eligible electronic registered-agent clients")
        if registered_for_gst and f.gst_reporting == "quarterly" and quarterly:
            due = bas_due(period)
            if due:
                add("bas", due, period, SOURCES["agent"] if f.bas_program == "agent" else SOURCES["bas"], f"Quarterly BAS lodgment and payment; {f.bas_program or 'self'} program, extensions require eligibility")
            elif _month(period, 1, 28) < end and start <= _month(period, 2, 25):
                gaps.add("Quarterly agent extension for 2027-06-30 and later is TBC; confirm the issued statement")
                add("bas", None, period, SOURCES["agent"], "Agent extension TBC; 25 August 2027 is not a confirmed deadline", shift=False)
        if has_payroll and (f.withholder == "medium" or f.withholder == "small" and quarterly):
            combined_quarter = quarterly and f.gst_reporting != "monthly" and (f.gst_reporting == "quarterly" or f.instalments == "quarterly")
            due = bas_due(period) if f.withholder == "small" or combined_quarter else _month(period, 1, 21)
            if due:
                missing = ("gst_reporting",) if f.gst_reporting is None and (f.withholder == "small" or combined_quarter) else ()
                gaps.update(missing)
                add("payg_withholding", due, period, SOURCES["agent"] if combined_quarter else SOURCES["payg"], f"{f.withholder} withholder; " + ("quarterly combined activity statement" if combined_quarter else "withholding activity statement") + ("; earlier candidate pending GST cycle confirmation" if missing else ""), extra={"period_start": _month(period, -2 if f.withholder == "small" else 0, 1).isoformat(), **({"status": "needs_confirmation", "missing_facts": missing} if missing else {})})
            elif _month(period, 1, 28) < end and start <= _month(period, 2, 25):
                gaps.add("Quarterly combined agent statement extension TBC; confirm the issued statement")
                add("payg_withholding", None, period, SOURCES["agent"], "Quarterly combined agent statement extension TBC; confirm the issued statement", shift=False, extra={"period_start": _month(period, -2 if f.withholder == "small" else 0, 1).isoformat()})
        if f.instalments in ("monthly", "quarterly") and (f.instalments == "monthly" or quarterly):
            # Instalment notices are not entitled to agent program extensions.
            confirmed_21 = f.instalments == "monthly" or f.gst_reporting == "monthly" or f.consolidated_head_company is True
            missing = tuple(name for name in ("gst_reporting", "consolidated_head_company") if getattr(f, name) is None) if not confirmed_21 else ()
            gaps.update(missing)
            due = _month(period, 1, 21) if confirmed_21 or missing else date(period.year + 1, 2, 28) if period.month == 12 else _month(period, 1, 28)
            source = SOURCES["consolidated_instalments"] if f.consolidated_head_company is not False else SOURCES["agent"]
            add("income_tax_instalment", due, period, source, "Assigned PAYG instalment notice; head companies pay on the 21st; no agent extension assumed" + ("; earlier candidate pending " + ", ".join(missing) if missing else ""), extra={"status": "needs_confirmation", "missing_facts": missing} if missing else None)

    if has_payroll:
        if not payday_schedule:
            unknown("superannuation", "Confirm Australia calendar facts and paydays to resolve statutory Payday Super dates through the existing compliance engine", SOURCES["super"])
        if f.stp not in ("standard", "exempt"):
            unknown("stp", "Confirm standard STP reporting or the employee-specific exemption/concession and finalisation date", SOURCES["stp"])
        # Projected payday evidence comes from #613, not a second cycle engine.
        paydays = {str(row["pay_date"])[:10]: bool(row.get("projected")) for row in payday_schedule if row.get("pay_date") and row.get("kind") == "superannuation" and (pay_cycle_confirmed or not row.get("projected"))}
        paydays.update({str(row["pay_date"])[:10]: False for row in pay_runs})
        if not paydays and f.stp == "standard":
            unknown("stp_pay_event", "Confirm paydays or committed pay runs for STP pay events", SOURCES["stp"])
        for payday, projected in sorted(paydays.items()):
            day = date.fromisoformat(payday)
            if f.stp == "standard":
                add("stp_pay_event", day, day, SOURCES["stp"], "Report on or before payday; no next-business-day extension assumed", shift=False, extra={"projected": projected})
            if f.withholder == "large":
                offsets = (7, 6, 8, 7, 6, 9, 8)
                add("payg_withholding", day + timedelta(days=offsets[day.weekday()]), day, SOURCES["payg_large"], "Large withholder twice-weekly remittance", extra={"projected": projected, "period_start": day.isoformat()})
        if f.withholder == "large" and not paydays:
            unknown("payg_withholding", "Confirm paydays for large-withholder remittances", SOURCES["payg"])
        for row in payday_schedule:
            if row.get("kind") != "superannuation":
                continue
            pay_date = str(row.get("pay_date") or "")[:10]
            due = date.fromisoformat(str(row["due_at"])[:10]) - timedelta(days=1)
            period = date.fromisoformat(str(row["period_end"])[:10]) - timedelta(days=1)
            if row.get("projected") and not pay_cycle_confirmed:
                continue
            known = due < date(2027, 9, 1)
            if not known:
                gaps.add("Refresh national Payday Super business-day holidays (2027 AFL holiday is not yet published)")
            add("superannuation", due if known else None, period, SOURCES["super"], "Existing compliance engine: standard 7 business days after payday; special employee extensions require confirmation" if pay_date else "Final pre-Payday-Super quarterly contribution", shift=False, effective="2026-07-01" if pay_date else EFFECTIVE_FROM, extra={"existing_obligation_ref": row["obligation_ref"], "projected": bool(row.get("projected")), "business_day_source_url": SOURCES["super_business_days"]})
        if not pay_cycle_confirmed:
            gaps.add("Confirm pay cycle/next payday for forecast STP and Payday Super dates")
        if not f.states:
            unknown("state_payroll_tax", "Confirm states/territories employing staff and assigned payroll-tax registrations", SOURCES["payg"])
        for state in f.states:
            cycle = f.payroll_tax.get(state)
            rule = PAYROLL_TAX_RULES[state]
            if cycle is None:
                unknown("state_payroll_tax", f"Confirm {state} payroll_tax assigned cycle or none; threshold is not a registration decision", rule["source_url"], state)
                continue
            if cycle == "none":
                continue
            for period in periods:
                if period.month == 6 or cycle == "annual" or (cycle == "quarterly" and period.month % 3) or (cycle == "half_yearly" and period.month != 12):
                    continue
                due_day = rule.get("december_day", rule["monthly_day"]) if period.month == 12 else rule["monthly_day"]
                # Published December extensions, not an assumed recurring rule.
                if state in ("NSW", "SA", "QLD") and period == date(2026, 12, 31) or state == "QLD" and period == date(2025, 12, 31):
                    due_day = 14
                due = _month(period, 1, due_day)
                if start <= due < end:
                    if period > date(2027, 6, 30):
                        unknown("state_payroll_tax", f"Refresh {state} payroll-tax rules for 2027-28", rule["source_url"], state)
                    else:
                        source = "https://www.revenue.nsw.gov.au/taxes-duties-levies-royalties/payroll-tax/lodge-and-pay-returns/key-dates" if state == "NSW" else rule["source_url"]
                        add("state_payroll_tax", due, period, source, f"Assigned {cycle} payroll-tax return and payment", state=state, extra={"threshold": payroll_tax_threshold(state, period_end=period.isoformat())})
        if f.workers_compensation is None:
            unknown("workers_compensation", "Confirm board/insurer obligations with dates from each authority or policy; [] confirms none", SOURCES["workers_compensation"])
    if f.fbt_required is None:
        unknown("fbt", "Confirm fbt_required", SOURCES["fbt"])
    elif f.fbt_required and (f.fbt_program is None or f.fbt_program == "agent_electronic" and (f.fbt_agent_eligible is not True or f.registered_agent is not True)):
        unknown("fbt", "Confirm fbt_program; electronic agent extension requires appointment/client-list eligibility by 21 May", SOURCES["fbt"])
    if f.tpar_required is None:
        unknown("tpar", "Confirm whether taxable payments annual reporting applies", SOURCES["tpar"])
    if f.company_tax_program is None or f.company_tax_program_confirmed is not True or fy_end != 6:
        unknown("company_tax_return", "Confirm fiscal_year_end_month, ATO company_tax_program and eligibility; substituted accounting periods require the issued return date", SOURCES["company_tax"])
    if f.instalments is None:
        unknown("income_tax_instalment", "Confirm ATO-assigned instalments or none", SOURCES["agent"])
    for year in range(start.year - 1, end.year + 1):
        period = date(year, 6, 30)
        if has_payroll and f.stp == "standard":
            add("stp_finalisation", date(year, 7, 14), period, SOURCES["stp_finalisation"], "Standard arm's-length employee STP finalisation; concessions must be separately confirmed")
        if f.fbt_required and f.fbt_program and (f.fbt_program != "agent_electronic" or f.fbt_agent_eligible and f.registered_agent is True):
            add("fbt", date(year, 6, 25) if f.fbt_program == "agent_electronic" else date(year, 5, 21), date(year, 3, 31), SOURCES["fbt"], f"FBT return and payment; {f.fbt_program}")
        if f.tpar_required:
            add("tpar", date(year, 8, 28), period, SOURCES["tpar"], "Taxable payments annual report")
        if f.company_tax_program and f.company_tax_program_confirmed and fy_end == 6:
            dates = {"self_preparing": date(year + 1, 2, 28), "tax_agent": date(year + 1, 5, 15), "over_2m": date(year + 1, 3, 31), "large_medium": date(year + 1, 1, 31), "prior_returns_overdue": date(year, 10, 31)}
            if f.company_tax_program == "large_medium":
                unknown("company_tax_return", "Taxable large/medium companies, including self-lodgers: confirm issued return date; January publications conflict (15/31), no later date inferred", SOURCES["company_tax"])
            elif f.company_tax_program in ("tax_agent", "over_2m") and f.registered_agent is not True:
                unknown("company_tax_return", "Confirm registered_agent before using the company agent program", SOURCES["company_tax"])
            else:
                add("company_tax_return", dates[f.company_tax_program], period, SOURCES["company_tax"], f"Company return: confirmed {f.company_tax_program} lodgment category; payment requires assessment/ATO notice")
            if f.company_tax_program in ("large_medium", "prior_returns_overdue"):
                add("company_tax_balance", date(year, 12, 1), period, SOURCES["company_tax"], "Taxable large/medium company balance due")
        if has_payroll and 2026 <= year <= 2027:
            for state, cycle in f.payroll_tax.items():
                if cycle != "none":
                    rule = PAYROLL_TAX_RULES[state]
                    add("state_payroll_tax_annual", date(year, 7, rule["annual_day"]), period, rule["source_url"], "Annual payroll-tax reconciliation including June; replaces June monthly return", state=state, extra={"threshold": payroll_tax_threshold(state, period_end=period.isoformat())})
    for item in f.workers_compensation or ():
        add("workers_compensation", item.due_on, None, item.source_url, item.basis, state=item.state, shift=item.move_to_business_day, effective=item.effective_from.isoformat(), extra={"obligation_ref": f"AU:workers_compensation:{item.obligation_ref}", "verified_as_of": item.verified_as_of.isoformat()})
    # Missing-fact rows appear once even when several periods need that fact.
    unique = {row["obligation_ref"]: row for row in rows}
    return seal(AustraliaObligationsCalendar, {"company_ref": company_ref, "start_on": start.isoformat(), "end_on": end.isoformat(), "obligations": sorted(unique.values(), key=lambda r: (r["due_on"] or "9999", r["obligation_ref"])), "missing_facts": sorted(gaps), "facts": f.to_dict()}, "calendar_digest")


def due_this_month(calendar: AustraliaObligationsCalendar | Mapping[str, Any], *, company_ref: str, as_of: str) -> list[dict[str, Any]]:
    parsed = AustraliaObligationsCalendar.model_validate(detached(calendar))
    if parsed.company_ref != company_ref:
        raise ValueError("SCOPE_MISMATCH: calendar belongs to another company")
    month = date.fromisoformat(as_of[:10]).isoformat()[:7]
    return [row.to_dict() for row in parsed.obligations if row.get("due_on") and row["due_on"][:7] == month]
