"""Canadian corporate deadlines, never tax calculations or payment authority.

Dates are local civil dates (inclusive), not UTC payment cutoffs. Unknown
registrations, assigned frequencies and eligibility remain explicit gaps.
The effective date is the start of this rule snapshot's supported coverage,
not a claim about when the legislation was first enacted.
"""
from __future__ import annotations

from calendar import monthrange
from datetime import date, timedelta
from decimal import Decimal
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from pydantic import Field, ValidationInfo, field_validator, model_serializer, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, OpaqueRef, Sha256Digest, StrictModel, detached,
    seal, sealed_digest, skip_digests, stable_digest,
)

VERIFIED_AS_OF = "2026-10-05"
EFFECTIVE_FROM = "2026-01-01"
COVERAGE_END = "2027-12-31"
CRA = "https://www.canada.ca/en/revenue-agency/services/"
RQ = "https://www.revenuquebec.ca/en/businesses/"
SOURCES = {
    "holidays": CRA + "tax/public-holidays.html",
    "gst_hst": CRA + "tax/businesses/topics/gst-hst-businesses/complete-file-return-business/when-file.html",
    "gst_instalment": CRA + "tax/businesses/topics/gst-hst-businesses/remit-pay-gst-hst-collected/pay-instalment.html",
    "payroll": CRA + "tax/businesses/topics/payroll/remitting-source-deductions/how-when-remit-due-dates.html",
    "t4": CRA + "tax/businesses/topics/payroll/file-information-returns-slip-summaries/when-to-file.html",
    "t4a": CRA + "tax/businesses/topics/payroll/file-information-returns-slip-summaries/when-to-file.html",
    "roe": "https://www.canada.ca/en/employment-social-development/programs/ei/ei-list/reports/roe-guide.html",
    "corporate_instalment": CRA + "tax/businesses/topics/corporations/corporation-payments/paying-instalments/instalment-dates.html",
    "corporate_balance": CRA + "tax/businesses/topics/corporations/corporation-payments/paying-your-balance-corporation-tax/balance-day.html",
    "t2": CRA + "tax/businesses/topics/corporations/corporation-income-tax-return/when-file-your-corporation-income-tax-return.html",
    "qst": RQ + "consumption-taxes/gsthst-and-qst/reporting-gsthst-and-qst/filing-frequency/",
    "qc_payroll": RQ + "source-deductions-and-employer-contributions/remitting-source-deductions-and-employer-contributions/frequency-of-remittances/",
    "qc_hsf": RQ + "source-deductions-and-employer-contributions/calculating-source-deductions-and-contributions/employer-contribution-to-the-health-services-fund/health-services-fund-contribution-what-you-need-to-know/",
    "rl1": RQ + "rl-slips-and-summaries/rl-slips/",
    "bc_pst": "https://www2.gov.bc.ca/gov/content/taxes/sales-taxes/pst/report-pay",
    "sk_pst": "https://www.saskatchewan.ca/government/news-and-media/2020/january/14/cut-red-tape",
    "mb_rst": "https://www.gov.mb.ca/finance/taxation/pubs/bulletins/004.pdf",
    "on_eht": "https://www.ontario.ca/document/employer-health-tax-eht",
    "bc_eht": "https://www2.gov.bc.ca/gov/content/taxes/employer-health-tax/employer-health-tax-overview",
    "mb_he": "https://www.gov.mb.ca/finance/taxation/pubs/bulletins/001he.pdf",
    "nl_hapset": "https://www.gov.nl.ca/fin/tax-programs-incentives/business/education/",
    "workers_compensation": "https://www.canada.ca/en/employment-social-development/programs/ei/ei-list/work-accident-illness.html",
    "qst_instalment": RQ + "consumption-taxes/gsthst-and-qst/reporting-gsthst-and-qst/gsthst-and-qst-remittance-or-refund/gst-and-qst-instalments/",
}
# Thresholds are versioned data. They select schedules, never deduction amounts.
THRESHOLDS = {
    "cra_quarterly_existing_exclusive": "3000", "cra_quarterly_new_exclusive": "1000",
    "accelerated_1": "25000", "accelerated_2": "100000",
    "gst_instalments_inclusive": "3000", "qst_instalments_inclusive": "3000", "on_eht_instalments_exclusive": "1200000",
    "bc_eht_instalments_exclusive": "2925",
}
Province = Literal["AB", "BC", "MB", "NB", "NL", "NS", "NT", "NU", "ON", "PE", "QC", "SK", "YT"]
Frequency = Literal["monthly", "quarterly", "annual"]
Remitter = Literal["regular", "quarterly", "threshold_1", "threshold_2"]


def _money(value: Any) -> Decimal:
    number = Decimal(str(value))
    if not number.is_finite() or number < 0:
        raise ValueError("a schedule threshold input must be finite and non-negative")
    return number


def remitter_from_amwa(amwa: Any, *, quarterly_approved: bool = False, new_employer: bool = False) -> str:
    """AMWA is the CRA lookback amount; quarterly also requires CRA approval.

    For a new employer the supplied amount must be the monthly withholding,
    not an invented two-year average. Never changes an assigned remitter type.
    """
    amount = _money(amwa)
    limit = THRESHOLDS["cra_quarterly_new_exclusive" if new_employer else "cra_quarterly_existing_exclusive"]
    if quarterly_approved and amount < Decimal(limit):
        return "quarterly"
    if new_employer:
        return "regular"
    if amount >= Decimal(THRESHOLDS["accelerated_2"]):
        return "threshold_2"
    if amount >= Decimal(THRESHOLDS["accelerated_1"]):
        return "threshold_1"
    return "regular"


class ROEEvent(StrictModel):
    event_ref: OpaqueRef
    interruption_on: date
    pay_period_end: date
    format: Literal["electronic", "paper"] | None = None
    pay_cycle: Literal["weekly", "biweekly", "semi_monthly", "monthly", "four_weekly"]
    learned_on: date | None = None

    @field_validator("interruption_on", "pay_period_end", "learned_on", mode="before")
    @classmethod
    def dates(cls, value: Any) -> Any:
        return date.fromisoformat(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def chronology(self) -> ROEEvent:
        if self.pay_period_end < self.interruption_on:
            raise ValueError("ROE pay period must contain the interruption")
        return self


class BoardObligation(StrictModel):
    obligation_ref: OpaqueRef
    province: Province
    due_on: date
    source_url: str
    basis: str = Field(min_length=1, max_length=1000)
    effective_from: date
    verified_as_of: date
    move_to_business_day: bool = False
    holidays: tuple[date, ...] = ()

    @field_validator("due_on", "effective_from", "verified_as_of", mode="before")
    @classmethod
    def dates(cls, value: Any) -> Any:
        return date.fromisoformat(value) if isinstance(value, str) else value

    @field_validator("holidays", mode="before")
    @classmethod
    def holiday_dates(cls, value: Any) -> Any:
        return tuple(date.fromisoformat(v) if isinstance(v, str) else v for v in value)

    @field_validator("source_url")
    @classmethod
    def official_board(cls, value: str) -> str:
        parsed = urlsplit(value)
        boards = {"wsib.ca", "worksafebc.com", "wcb.ab.ca", "wcb.mb.ca", "wcbsask.com", "wcb.ns.ca", "worksafenb.ca", "workplacenl.ca", "wcb.pe.ca", "cnesst.gouv.qc.ca", "wcb.yk.ca", "wscc.nt.ca", "wscc.nu.ca"}
        host = parsed.hostname or ""
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or not any(host == b or host.endswith("." + b) for b in boards):
            raise ValueError("workers compensation requires an official board HTTPS source")
        return value


class CorporateFiscalFacts(StrictModel):
    """Eligibility for one exact tax year; prior income refers to that year's predecessor."""
    ccpc_throughout_year: bool | None = None
    small_business_deduction_claimed: bool | None = None
    prior_income_within_business_limit: bool | None = None
    quarterly_corporate_eligible: bool | None = None


class CanadaCalendarFacts(StrictModel):
    provinces: tuple[Province, ...] = ()
    entity_type: Literal["corporation", "sole_proprietor", "partnership", "other"] | None = None
    fiscal_year_end_month: int | None = Field(default=None, ge=1, le=12)
    remitter_year: int | None = Field(default=None, ge=2025, le=2027)
    remitters_by_year: dict[str, Remitter] = Field(default_factory=dict)
    gst_net_tax_fiscal_year_end: date | None = None
    qst_net_tax_fiscal_year_end: date | None = None
    bc_prior_eht_year: int | None = Field(default=None, ge=2025, le=2026)
    bc_pst_period_end_month: int | None = Field(default=None, ge=1, le=12)
    qc_remitter_year: int | None = Field(default=None, ge=2025, le=2027)
    on_annual_payroll_year: int | None = Field(default=None, ge=2025, le=2027)
    gst_reporting: Frequency | None = None
    gst_prior_net_tax: Decimal | None = None
    gst_current_net_tax: Decimal | None = None
    remitter: Remitter | None = None
    amwa: Decimal | None = None
    quarterly_remittance_approved: bool = False
    new_employer: bool = False
    t4a_required: bool | None = None
    corporate_instalments: Literal["monthly", "quarterly", "none"] | None = None
    corporate_facts_fiscal_year_end: date | None = None
    corporate_facts_by_fiscal_year_end: dict[str, CorporateFiscalFacts] = Field(default_factory=dict)
    quarterly_corporate_eligible: bool | None = None
    ccpc_throughout_year: bool | None = None
    small_business_deduction_claimed: bool | None = None
    prior_income_within_business_limit: bool | None = None
    fiscal_year_end_day: int | None = Field(default=None, ge=1, le=31)
    # None means unknown; "none" is an explicit confirmed non-registration.
    provincial_sales: dict[Literal["QC", "BC", "SK", "MB"], Literal["monthly", "quarterly", "annual", "none"]] = Field(default_factory=dict)
    sk_electronic: bool | None = None
    qc_remitter: Literal["annual", "quarterly", "regular", "threshold_1", "threshold_2"] | None = None
    qc_annual_last_pay_month: int | None = Field(default=None, ge=1, le=12)
    health_tax_accounts: dict[Literal["ON", "BC", "MB", "QC", "NL"], bool] = Field(default_factory=dict)
    on_annual_payroll: Decimal | None = None
    bc_prior_eht: Decimal | None = None
    qst_prior_net_tax: Decimal | None = None
    qst_current_net_tax: Decimal | None = None
    federal_province: Province | None = None
    roe_events: tuple[ROEEvent, ...] | None = None
    workers_compensation: tuple[BoardObligation, ...] | None = None

    @field_validator("gst_net_tax_fiscal_year_end", "qst_net_tax_fiscal_year_end", "corporate_facts_fiscal_year_end", mode="before")
    @classmethod
    def year_dates(cls, value: Any) -> Any:
        return date.fromisoformat(value) if isinstance(value, str) else value

    @field_validator("gst_prior_net_tax", "gst_current_net_tax", "amwa", "on_annual_payroll", "bc_prior_eht", "qst_prior_net_tax", "qst_current_net_tax", mode="before")
    @classmethod
    def money(cls, value: Any) -> Any:
        return None if value is None else _money(value)

    @field_validator("provinces", "roe_events", "workers_compensation", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return None if value is None else tuple(value)

    @model_validator(mode="after")
    def jurisdictions(self) -> CanadaCalendarFacts:
        if len(set(self.provinces)) != len(self.provinces):
            raise ValueError("each province appears once")
        if not set(self.provincial_sales).union(self.health_tax_accounts).issubset(self.provinces):
            raise ValueError("registration provinces must belong to the company's confirmed provinces")
        if any(year not in ("2025", "2026", "2027") for year in self.remitters_by_year):
            raise ValueError("remitter assignment years must be within 2025-2027")
        if self.federal_province is not None and self.federal_province not in self.provinces:
            raise ValueError("federal_province must belong to the confirmed provinces")
        year_ends = [date.fromisoformat(key) for key in self.corporate_facts_by_fiscal_year_end]
        year_ends += [d for d in (self.gst_net_tax_fiscal_year_end, self.qst_net_tax_fiscal_year_end, self.corporate_facts_fiscal_year_end) if d is not None]
        if self.fiscal_year_end_month is not None and any(d.month != self.fiscal_year_end_month for d in year_ends):
            raise ValueError("year-bound tax facts must match fiscal_year_end_month")
        return self


def remitter_assignments(facts: CanadaCalendarFacts) -> tuple[dict[str, str], set[str]]:
    """CRA assignments outrank an AMWA estimate; conflicting explicit facts stay unknown."""
    assignments = dict(facts.remitters_by_year)
    conflicts = set()
    if facts.remitter is not None:
        for year, assigned in list(assignments.items()):
            if (facts.remitter_year is None or year == str(facts.remitter_year)) and assigned != facts.remitter:
                conflicts.add(year)
                assignments.pop(year)
    if facts.remitter_year is not None:
        year = str(facts.remitter_year)
        if year not in assignments and year not in conflicts:
            inferred = facts.remitter
            if inferred is None and facts.amwa is not None:
                inferred = remitter_from_amwa(facts.amwa, quarterly_approved=facts.quarterly_remittance_approved, new_employer=facts.new_employer)
            if inferred is not None:
                assignments[year] = inferred
    return assignments, conflicts


def _corporate_facts(facts: CanadaCalendarFacts, year_end: date) -> dict[str, Any]:
    names = tuple(CorporateFiscalFacts.model_fields)
    dated = facts.corporate_facts_by_fiscal_year_end.get(year_end.isoformat())
    bound = {name: getattr(facts, name) for name in names} if facts.corporate_facts_fiscal_year_end == year_end else {}
    if dated is not None:
        explicit = dated.to_dict()
        if any(value is not None and explicit.get(name) is not None and explicit[name] != value for name, value in bound.items()):
            return {}
        return {**bound, **{k: v for k, v in explicit.items() if v is not None}}
    return bound


def _month(day: date, offset: int, *, end: bool = False) -> date:
    index = day.year * 12 + day.month - 1 + offset
    year, month = divmod(index, 12)
    last = monthrange(year, month + 1)[1]
    return date(year, month + 1, last if end else min(day.day, last))


def _easter(year: int) -> date:
    a, b, c = year % 19, year // 100, year % 100
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    return date(year, (h + l - 7 * m + 114) // 31, (h + l - 7 * m + 114) % 31 + 1)


def _monday(year: int, month: int, n: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(-first.weekday()) % 7 + 7 * (n - 1))


HOLIDAY_SOURCES = {
    "CRA": SOURCES["holidays"],
    "RQ": "https://www.revenuquebec.ca/en/contact-us/holidays/",
    "ON": "https://www.ontario.ca/page/pay-ontario-taxes-and-charges",
    "BC": "https://www2.gov.bc.ca/gov/content/employment-business/employment-standards-advice/employment-standards/statutory-holidays",
    "SK": "https://www.saskatchewan.ca/business/employment-standards/public-statutory-holidays/list-of-saskatchewan-public-holidays",
    "MB": SOURCES["mb_rst"], "NL": SOURCES["nl_hapset"],
}


def cra_holidays(year: int, province: str | None = None) -> set[date]:
    """CRA's named holidays only; do not invent weekend substitute days."""
    easter = _easter(year)
    victoria = date(year, 5, 24) - timedelta(days=date(year, 5, 24).weekday())
    days = {date(year, 1, 1), easter - timedelta(days=2), easter + timedelta(days=1), victoria,
            date(year, 7, 1), _monday(year, 9, 1), date(year, 9, 30), _monday(year, 10, 2),
            date(year, 11, 11), date(year, 12, 25), date(year, 12, 26)}
    if province == "QC":
        days.add(date(year, 6, 24))
    elif province:
        days.add(_monday(year, 8, 1))
    return days


def _observed(days: set[date]) -> set[date]:
    result = set(days)
    for day in sorted(days):
        if day.weekday() >= 5:
            while day.weekday() >= 5 or day in result:
                day += timedelta(days=1)
            result.add(day)
    return result


def _authority_holidays(year: int, province: str | None, *, authority: str = "CRA") -> set[date]:
    easter = _easter(year)
    victoria = date(year, 5, 24) - timedelta(days=date(year, 5, 24).weekday())
    if authority == "CRA":
        return cra_holidays(year, province)
    if authority in ("RQ", "ON") and year >= 2027:
        return set()  # no unverified in-lieu days in accelerated-remittance arithmetic
    if authority == "RQ":
        # RQ office closures plus banking holidays used in its remittance tables.
        # New Year's second closure is observed separately from January 1.
        return _observed({date(year, 1, 1), date(year, 1, 2), easter - timedelta(days=2),
            easter + timedelta(days=1), victoria, date(year, 6, 24), date(year, 7, 1),
            _monday(year, 9, 1), date(year, 9, 30), _monday(year, 10, 2), date(year, 11, 11),
            date(year, 12, 24), date(year, 12, 25), date(year, 12, 26), date(year, 12, 31)})
    if authority == "ON":
        # Ontario explicitly accepts Ontario holidays AND federal banking holidays.
        return _observed(cra_holidays(year, "ON") | {_monday(year, 2, 3)})
    if authority in ("BC", "SK"):
        days = {date(year, 1, 1), _monday(year, 2, 3), easter - timedelta(days=2), victoria,
            date(year, 7, 1), _monday(year, 8, 1), _monday(year, 9, 1), _monday(year, 10, 2),
            date(year, 11, 11), date(year, 12, 25)}
        if authority == "BC":
            days.add(date(year, 9, 30))
        # No discretionary employer substitute is a tax-authority extension.
        return days
    # MB/NL: the authority's closure list is not verified by this snapshot.
    # The compiler exposes this gap and retains the earlier nominal date.
    return set()


def next_business_day(day: date, *, province: str | None = None, holidays: set[date] | None = None,
                      quebec: bool = False, authority: str = "CRA") -> date:
    authority = "RQ" if quebec else authority
    while day.weekday() >= 5 or day in (_authority_holidays(day.year, province, authority=authority) if holidays is None else holidays):
        day += timedelta(days=1)
    return day


def _business_after(day: date, count: int, province: str | None, *, quebec: bool = False) -> date:
    for _ in range(count):
        day = next_business_day(day + timedelta(days=1), province=province, quebec=quebec)
    return day


class CanadaObligation(StrictModel):
    obligation_ref: OpaqueRef
    kind: str
    province: Province | None = None
    period_end: str | None = None
    remitter_basis: str | None = None
    due_on: str | None = None
    nominal_due_on: str | None = None
    basis: str
    status: Literal["scheduled", "needs_confirmation"]
    amount: None = None
    amount_basis: Literal["not_computed_calendar_only"] = "not_computed_calendar_only"
    source_url: str
    effective_from: str
    verified_as_of: str
    holiday_source_url: str | None = None
    authority: str
    components: tuple[str, ...] = ()

    @field_validator("components", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return tuple(value)

    @model_serializer(mode="wrap")
    def explicit_unknowns(self, handler: Any) -> dict[str, Any]:
        raw = handler(self)
        for key in ("amount", "province", "period_end", "due_on", "nominal_due_on", "holiday_source_url"):
            raw[key] = getattr(self, key)
        return raw

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class CalendarThreshold(StrictModel):
    value: str
    source_url: str
    effective_from: str
    verified_as_of: str


def threshold_metadata() -> dict[str, Any]:
    return {name: {"value": value, "source_url": SOURCES[
        "bc_eht" if name.startswith("bc_") else "on_eht" if name.startswith("on_") else
        "gst_instalment" if name.startswith("gst_") else "qst_instalment" if name.startswith("qst_") else "payroll"],
        "effective_from": EFFECTIVE_FROM, "verified_as_of": VERIFIED_AS_OF} for name, value in THRESHOLDS.items()}


class CanadaObligationsCalendar(StrictModel):
    schema_id: str = Field(default="lightbulb.canada_obligations.v1", alias="schema")
    company_ref: OpaqueRef
    start_on: str
    end_on: str
    obligations: tuple[CanadaObligation, ...]
    thresholds: dict[str, CalendarThreshold] = Field(default_factory=dict)
    coverage_end: str = COVERAGE_END
    missing_facts: tuple[str, ...]
    facts: dict[str, Any] | None = None
    calendar_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("obligations", "missing_facts", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return tuple(value)

    @model_validator(mode="after")
    def digest(self, info: ValidationInfo) -> CanadaObligationsCalendar:
        if not skip_digests(info) and self.calendar_digest != sealed_digest(type(self), self, "calendar_digest"):
            raise ValueError("calendar_digest must commit the exact calendar")
        return self


def compile_canada_obligations(company_ref: str, *, start_on: str, horizon_months: int = 12,
                               fiscal_year_end_month: int | None = None, has_payroll: bool = True,
                               registered_for_gst: bool = True,
                               facts: CanadaCalendarFacts | Mapping[str, Any] | None = None) -> CanadaObligationsCalendar:
    """Compile deadlines within [start_on, end_on), and explicit unresolved rules.

    Assigned frequencies and registration are company facts, not inferred from
    revenue estimates. Amount is always unknown; a provider liability is needed.
    """
    f = CanadaCalendarFacts.model_validate(detached(facts or {}))
    if fiscal_year_end_month is not None:
        if f.fiscal_year_end_month is not None and f.fiscal_year_end_month != fiscal_year_end_month:
            raise ValueError("conflicting fiscal_year_end_month")
        f = CanadaCalendarFacts.model_validate({**f.to_dict(), "fiscal_year_end_month": fiscal_year_end_month})
    fiscal_year_end_month = f.fiscal_year_end_month
    start = date.fromisoformat(start_on)
    if start < date.fromisoformat(EFFECTIVE_FROM) or not 1 <= horizon_months <= 24:
        raise ValueError("calendar supports dates from 2026, a 1-24 month horizon and a valid fiscal month")
    end = _month(start, horizon_months)
    rows: list[dict[str, Any]] = []
    missing: set[str] = set()
    province = f.federal_province or (f.provinces[0] if len(f.provinces) == 1 else None)

    def add(kind: str, due: date | None, basis: str, *, period: date | None = None,
            region: str | None = None, source: str | None = None, missing_fact: str | None = None,
            adjust: bool = True, holiday_dates: set[date] | None = None, authority: str | None = None,
            remitter_basis: str | None = None) -> None:
        nominal = due
        authority = authority or ("RQ" if region == "QC" or kind in ("gst_hst", "gst_instalment", "gst_payment") and province == "QC" else region or "CRA")
        if authority == "RQ" and kind in ("gst_hst", "gst_payment", "gst_instalment"):
            source = SOURCES["qst_instalment" if kind == "gst_instalment" else "qst"]
        unverified_holidays = due is not None and adjust and holiday_dates is None and authority in ("RQ", "ON") and due.year >= 2027
        if due is not None and adjust and (holiday_dates is not None or authority not in ("MB", "NL")):
            due = next_business_day(due, province=region or province, holidays=holiday_dates, authority=authority)
        if due is not None and adjust and holiday_dates is None and authority in ("RQ", "ON") and (unverified_holidays or due.year >= 2027):
            due = nominal
            missing_fact = authority + " authority holiday list for 2027 (nominal date retained; extension unverified)"
        if due is not None and not start <= due < end:
            return
        if missing_fact:
            missing.add(missing_fact)
        if due is not None and (start > date.fromisoformat(COVERAGE_END) or due > date.fromisoformat(COVERAGE_END)):
            missing_fact = "rules beyond " + COVERAGE_END + " are unverified"
            due = None
        if region is None and province is None and adjust:
            missing_fact = "federal_province (confirm applicable provincial holidays)"
            due = None
        if due is not None and adjust and authority in ("MB", "NL") and holiday_dates is None:
            missing_fact = authority + " authority holiday list (nominal date retained; extension unverified)"
            basis += "; nominal deadline retained pending the authority's closure list"
        if missing_fact:
            missing.add(missing_fact)
        key = f"ca:{kind}:{region or 'federal'}:{period or 'unknown'}:{nominal or 'unknown'}"
        if missing_fact:
            key += ":" + stable_digest(basis)[:12]
        rows.append({"obligation_ref": key, "kind": kind, "province": region,
                     "period_end": None if period is None else period.isoformat(), "remitter_basis": remitter_basis,
                     "due_on": None if due is None else due.isoformat(),
                     "nominal_due_on": None if nominal is None else nominal.isoformat(),
                     "basis": basis, "status": "needs_confirmation" if missing_fact or due is None else "scheduled",
                     "amount": None, "amount_basis": "not_computed_calendar_only",
                     "source_url": source or SOURCES["gst_hst" if kind == "gst_payment" else "qst" if kind == "qst_payment" else kind], "effective_from": EFFECTIVE_FROM,
                     "verified_as_of": VERIFIED_AS_OF, "authority": authority,
                     "holiday_source_url": HOLIDAY_SOURCES.get(authority) if adjust else None})

    def unknown(kind: str, name: str, *, region: str | None = None, period: date | None = None) -> None:
        if any(row["kind"] == kind and row["province"] == region and row["basis"] == "Confirm " + name + "; a deadline cannot be inferred." for row in rows):
            return
        add(kind, None, "Confirm " + name + "; a deadline cannot be inferred.", region=region, missing_fact=name, adjust=kind != "roe", period=period)

    # Include periods from the preceding year whose return falls in this window.
    months = []
    cursor = _month(start.replace(day=1), -12)
    while cursor < end:
        months.append(cursor)
        cursor = _month(cursor, 1)

    def periodic(kind: str, frequency: str, *, day: int = 31, offset: int = 1,
                 fiscal: bool = False, region: str | None = None, basis: str = "Assigned filing frequency", anchor_month: int | None = None, only_year: int | None = None, fiscal_tax_year: date | None = None, remitter_basis: str | None = None) -> None:
        if fiscal and frequency != "monthly" and fiscal_year_end_month is None:
            unknown(kind, "fiscal_year_end_month", region=region)
            return
        if fiscal and f.fiscal_year_end_day not in (None, 31):
            # Corporate balance/instalments support arbitrary year-end days;
            # sales-tax reporting periods require the authority's own election.
            unknown(kind, "confirmed sales-tax reporting periods for a non-month-end fiscal year", region=region)
            return
        step = {"monthly": 1, "quarterly": 3, "annual": 12}[frequency]
        anchor = anchor_month or (fiscal_year_end_month if fiscal else 12) or 12
        for month in months:
            if (month.month - anchor) % step:
                continue
            last = _month(month, 0, end=True)
            target = _month(month, offset)
            due = target.replace(day=min(day, monthrange(target.year, target.month)[1]))
            if only_year is not None and last.year != only_year:
                if start <= due < end and kind not in ("payroll", "qc_payroll"):
                    unknown(kind, f"annual assignment or eligibility facts for {last.year}", region=region)
                continue
            if fiscal_tax_year is not None and not _month(fiscal_tax_year, -12) < last <= fiscal_tax_year:
                if start <= due < end:
                    unknown(kind, f"net tax facts for fiscal year containing {last}", region=region)
                continue
            add(kind, due, basis, period=last, region=region, remitter_basis=remitter_basis)

    def payroll(kind: str, remitter: str | None, *, region: str | None = None, assignment_year: int | None = None) -> None:
        if assignment_year is None:
            unknown(kind, "qc_remitter_year" if region else "remitter_year", region=region)
            return
        if remitter is None:
            unknown(kind, "qc_remitter" if region else "remitter", region=region)
        elif remitter == "annual":
            if f.qc_annual_last_pay_month is None:
                unknown(kind, "qc_annual_last_pay_month", region=region)
            else:
                for year in (assignment_year,):
                    period = _month(date(year, f.qc_annual_last_pay_month, 1), 0, end=True)
                    add(kind, _month(period.replace(day=15), 1), "Annual remittance, 15th after the last month remuneration was paid", period=period, region=region, remitter_basis=remitter)
        elif remitter in ("regular", "quarterly", "annual"):
            periodic(kind, {"regular": "monthly", "quarterly": "quarterly", "annual": "annual"}[remitter], day=15, region=region, only_year=assignment_year, remitter_basis=remitter, basis=f"Assigned {remitter} source-deduction remittance; includes applicable pension and insurance contributions")
        else:
            for month in months:
                if month.year != assignment_year:
                    continue
                last = _month(month, 0, end=True)
                for day in ([15, last.day] if remitter == "threshold_1" else [7, 14, 21, last.day]):
                    period = month.replace(day=day)
                    due = (month.replace(day=25) if day == 15 else _month(month, 1).replace(day=10)) if remitter == "threshold_1" else _business_after(period, 3, region or province, quebec=region == "QC")
                    add(kind, due, f"Assigned {remitter} remittance", period=period, region=region, remitter_basis=remitter)

    if not f.provinces:
        missing.add("provinces (registrations and local holiday applicability)")
    if len(f.provinces) > 1 and f.federal_province is None:
        missing.add("federal_province (the federal account's applicable holiday calendar)")
    if registered_for_gst:
        if f.gst_reporting is None:
            unknown("gst_hst", "gst_reporting")
        else:
            if f.gst_reporting == "annual" and f.entity_type is None:
                unknown("gst_hst", "entity_type")
            elif f.gst_reporting == "annual" and f.entity_type == "sole_proprietor":
                if fiscal_year_end_month != 12:
                    unknown("gst_hst", "confirmed sole-proprietor GST fiscal year end and income election")
                else:
                    periodic("gst_hst", "annual", day=15, offset=6, fiscal=True, basis="Individual annual filer with December year end: return due June 15")
                    periodic("gst_payment", "annual", day=30, offset=4, fiscal=True, basis="Individual annual filer with December year end: payment due April 30")
            else:
                periodic("gst_hst", f.gst_reporting, offset=3 if f.gst_reporting == "annual" else 1, fiscal=True)
            if f.gst_reporting == "annual":
                threshold = Decimal(THRESHOLDS["gst_instalments_inclusive"])
                if f.gst_prior_net_tax is None or f.gst_current_net_tax is None or f.gst_net_tax_fiscal_year_end is None:
                    unknown("gst_instalment", "gst_prior_net_tax, gst_current_net_tax and gst_net_tax_fiscal_year_end")
                elif min(f.gst_prior_net_tax, f.gst_current_net_tax) >= threshold:
                    periodic("gst_instalment", "quarterly", fiscal=True, fiscal_tax_year=f.gst_net_tax_fiscal_year_end, basis="Annual filer; current and previous net tax meet the instalment threshold")
    if has_payroll:
        remitter = f.remitter
        if remitter is None and f.amwa is not None:
            remitter = remitter_from_amwa(f.amwa, quarterly_approved=f.quarterly_remittance_approved, new_employer=f.new_employer)
        assignments, conflicts = remitter_assignments(f)
        for year in sorted(conflicts):
            unknown("payroll", f"conflicting explicit remitter assignments for {year}")
        if not assignments and not conflicts:
            payroll("payroll", remitter, assignment_year=f.remitter_year)
        else:
            for year, assigned in sorted(assignments.items()):
                payroll("payroll", assigned, assignment_year=int(year))
            # Missing assignments are a visible gap; never carry last year's type.
            for year in range((start - timedelta(days=31)).year, (end - timedelta(days=1)).year + 1):
                if str(year) not in assignments:
                    unknown("payroll", f"remitters_by_year.{year} (needed if pay was made in that year)")
        periodic("t4", "annual", day=31, offset=2, basis="T4 slips and summary for the prior calendar year")
        if f.roe_events is None:
            unknown("roe", "roe_events (interruption of earnings and pay-period facts)")
        for event in f.roe_events or ():
            if event.format is None:
                unknown("roe", f"format for ROE {event.event_ref}")
                continue
            if event.format == "paper":
                if event.learned_on is None:
                    unknown("roe", f"learned_on for paper ROE {event.event_ref}")
                    continue
                due = max(event.interruption_on, event.learned_on or event.interruption_on) + timedelta(days=5)
            else:
                due = event.pay_period_end + timedelta(days=5)
                if event.pay_cycle in ("monthly", "four_weekly"):
                    due = min(due, event.interruption_on + timedelta(days=15))
            before = len(rows)
            add("roe", due, f"{event.format} ROE; {event.pay_cycle}; event {event.event_ref}", period=event.interruption_on, adjust=False)
            if len(rows) > before:
                rows[-1]["obligation_ref"] = f"ca:roe:{event.event_ref}"
        if f.workers_compensation is None:
            unknown("workers_compensation", "workers_compensation board, coverage and assigned dates")
    if f.t4a_required is None:
        unknown("t4a", "t4a_required")
    elif f.t4a_required:
        periodic("t4a", "annual", day=31, offset=2, basis="T4A slips and summary for the prior calendar year")

    if f.entity_type is None:
        for kind in ("corporate_balance", "corporate_instalment", "t2"):
            unknown(kind, "entity_type")
    elif f.entity_type == "corporation" and fiscal_year_end_month is None:
        for kind in ("corporate_balance", "corporate_instalment", "t2"):
            unknown(kind, "fiscal_year_end_month")
    elif f.entity_type == "corporation":
        for year in range(start.year - 1, end.year + 1):
            last = monthrange(year, fiscal_year_end_month)[1]
            fy = date(year, fiscal_year_end_month, min(f.fiscal_year_end_day or last, last))
            eom = fy.day == last
            scoped = _corporate_facts(f, fy)
            ccpc = tuple(scoped.get(name) for name in ("ccpc_throughout_year", "small_business_deduction_claimed", "prior_income_within_business_limit"))
            balance_months = 3 if all(v is True for v in ccpc) else 2 if any(v is False for v in ccpc) else None
            if balance_months is None and _month(fy, 2, end=eom) < end and _month(fy, 3, end=eom) >= start:
                unknown("corporate_balance", f"CCPC, small-business deduction and prior income/business limits for fiscal year ending {fy}", period=fy)
            if balance_months is not None:
                add("corporate_balance", _month(fy, balance_months, end=eom), f"Corporate balance: {balance_months} months after year end; CCPC conditions explicitly evaluated", period=fy)
            add("t2", _month(fy, 6, end=eom), "Corporate income tax return six months after year end", period=fy)
        if f.corporate_instalments is None:
            unknown("corporate_instalment", "corporate_instalments")
        elif f.corporate_instalments != "none":
            step = 3 if f.corporate_instalments == "quarterly" else 1
            for month in months:
                if (month.month - fiscal_year_end_month) % step == 0:
                    due = month.replace(day=min(f.fiscal_year_end_day or 31, monthrange(month.year, month.month)[1]))
                    fy_year = month.year + (month.month > fiscal_year_end_month)
                    fy = date(fy_year, fiscal_year_end_month, min(f.fiscal_year_end_day or 31, monthrange(fy_year, fiscal_year_end_month)[1]))
                    if f.corporate_instalments == "quarterly" and _corporate_facts(f, fy).get("quarterly_corporate_eligible") is not True:
                        if start <= due < end:
                            unknown("corporate_instalment", f"quarterly_corporate_eligible for fiscal year ending {fy} (CCPC, compliance, associated income and capital tests)", period=fy)
                        continue
                    add("corporate_instalment", due, f"Confirmed {f.corporate_instalments} corporate instalment schedule for fiscal year ending {fy}", period=due)

    for region in f.provinces:
        kind = {"QC": "qst", "BC": "bc_pst", "SK": "sk_pst", "MB": "mb_rst"}.get(region)
        if kind:
            frequency = f.provincial_sales.get(region)
            if frequency is None:
                unknown(kind, f"provincial_sales.{region}", region=region)
            elif frequency != "none":
                if region == "SK" and f.sk_electronic is None:
                    unknown(kind, "sk_electronic (both return and payment)", region=region)
                elif region == "BC" and frequency != "monthly" and f.bc_pst_period_end_month is None:
                    unknown(kind, "bc_pst_period_end_month (authority-assigned reporting period)", region=region)
                else:
                    day = 20 if region == "MB" or region == "SK" and not f.sk_electronic else 31
                    if region == "QC" and frequency == "annual" and f.entity_type is None:
                        unknown(kind, "entity_type", region=region)
                    elif region == "QC" and frequency == "annual" and f.entity_type == "sole_proprietor":
                        if fiscal_year_end_month != 12:
                            unknown(kind, "confirmed sole-proprietor QST fiscal year end and income election", region=region)
                        else:
                            periodic(kind, "annual", day=15, offset=6, fiscal=True, region=region, basis="Individual annual filer with December year end: return due June 15")
                            periodic("qst_payment", "annual", day=30, offset=4, fiscal=True, region=region, basis="Individual annual filer with December year end: payment due April 30")
                    else:
                        periodic(kind, frequency, day=day, offset=3 if region == "QC" and frequency == "annual" else 1, fiscal=region == "QC", region=region, anchor_month=f.bc_pst_period_end_month if region == "BC" else None)
                    if region == "QC" and frequency == "annual":
                        if f.qst_prior_net_tax is None or f.qst_current_net_tax is None or f.qst_net_tax_fiscal_year_end is None:
                            unknown("qst_instalment", "qst_prior_net_tax, qst_current_net_tax and qst_net_tax_fiscal_year_end", region=region)
                        elif min(f.qst_prior_net_tax, f.qst_current_net_tax) >= Decimal(THRESHOLDS["qst_instalments_inclusive"]):
                            periodic("qst_instalment", "quarterly", fiscal=True, region=region, fiscal_tax_year=f.qst_net_tax_fiscal_year_end, basis="Annual QST filer meets the net-tax instalment threshold")
        if region == "QC" and has_payroll:
            payroll("qc_payroll", f.qc_remitter, region=region, assignment_year=f.qc_remitter_year)
            for year in range((start - timedelta(days=31)).year, (end - timedelta(days=1)).year + 1):
                if year != f.qc_remitter_year:
                    unknown("qc_payroll", f"qc_remitter assignment for {year}", region=region)
            periodic("rl1", "annual", offset=2, region=region, basis="RL-1 slips, summary and annual contribution reconciliation")
        kind = {"ON": "on_eht", "BC": "bc_eht", "MB": "mb_he", "QC": "qc_hsf", "NL": "nl_hapset"}.get(region)
        if not has_payroll or not kind:
            continue
        if region not in f.health_tax_accounts:
            unknown(kind, f"health_tax_accounts.{region} (registration and exemptions)", region=region)
        elif f.health_tax_accounts[region]:
            if region == "QC":
                periodic(kind, "annual", offset=2, region=region, basis="HSF annual reconciliation with the RL-1 summary")
            elif region == "ON":
                periodic(kind, "annual", day=15, offset=3, region=region, basis="EHT annual return and balance")
                if f.on_annual_payroll is None or f.on_annual_payroll_year is None:
                    unknown(kind, "on_annual_payroll and on_annual_payroll_year for instalment eligibility", region=region)
                elif f.on_annual_payroll > Decimal(THRESHOLDS["on_eht_instalments_exclusive"]):
                    periodic(kind, "monthly", day=15, region=region, only_year=f.on_annual_payroll_year, basis="Ontario payroll exceeds the monthly instalment threshold")
            elif region == "BC":
                periodic(kind, "annual", offset=3, region=region, basis="BC EHT annual return and balance")
                if f.bc_prior_eht is None or f.bc_prior_eht_year is None:
                    unknown(kind, "bc_prior_eht and bc_prior_eht_year for instalment eligibility", region=region)
                else:
                    for year in range(start.year, end.year + 1):
                        if year != f.bc_prior_eht_year + 1:
                            if date(year, 6, 15) < end:
                                unknown(kind, f"bc_prior_eht for {year - 1}", region=region)
                            continue
                        if f.bc_prior_eht <= Decimal(THRESHOLDS["bc_eht_instalments_exclusive"]):
                            continue
                        for month in (6, 9, 12):
                            add(kind, date(year, month, 15), "Prior-year EHT exceeds the instalment threshold", period=date(year, month, 1), region=region)
            else:
                periodic(kind, "monthly", day=15 if region == "MB" else 20, region=region, basis="Registered employer's monthly health levy return and payment")
                if region == "NL":
                    unknown(kind, "NL HAPSET annual return is not modelled; confirm with the authority", region=region)
                if region == "MB":
                    periodic(kind, "annual", offset=3, region=region, basis="Manitoba HE levy annual report, reconciliation and balance")
    for region in set(f.provinces) & {"NT", "NU"}:
        if has_payroll:
            missing.add(region + " payroll tax is not modelled; confirm territorial remittances and annual return")
    for board in f.workers_compensation or ():
        if board.province not in f.provinces:
            raise ValueError("board obligation province must be in the company's confirmed provinces")
        before = len(rows)
        add("workers_compensation", board.due_on, f"Board-assigned {board.obligation_ref}: {board.basis}", region=board.province, source=board.source_url, adjust=board.move_to_business_day, holiday_dates=set(board.holidays))
        if len(rows) > before:
            rows[-1].update(obligation_ref=f"ca:workers_compensation:{board.province}:{board.obligation_ref}", effective_from=board.effective_from.isoformat(), verified_as_of=board.verified_as_of.isoformat(), holiday_source_url=board.source_url)
    rows.sort(key=lambda r: (r["due_on"] or "9999", r["obligation_ref"]))
    refs = [row["obligation_ref"] for row in rows]
    if len(refs) != len(set(refs)):
        raise ValueError("duplicate obligation reference; each event or board obligation needs a distinct reference")
    for row in rows:
        if row["kind"] == "payroll":
            row["components"] = ["federal_income_tax", "EI"] + ([] if province == "QC" else ["CPP", "CPP2"] if province else [])
        elif row["kind"] == "qc_payroll":
            row["components"] = ["quebec_income_tax", "QPP", "QPIP", "HSF"]
    return seal(CanadaObligationsCalendar, {"company_ref": company_ref, "start_on": start.isoformat(), "end_on": end.isoformat(), "obligations": rows, "missing_facts": sorted(missing), "facts": f.to_dict(), "thresholds": threshold_metadata()}, "calendar_digest")


def due_this_month(calendar: CanadaObligationsCalendar | Mapping[str, Any], *, company_ref: str, as_of: str) -> list[dict[str, Any]]:
    parsed = CanadaObligationsCalendar.model_validate(detached(calendar))
    if parsed.company_ref != company_ref:
        raise ValueError("SCOPE_MISMATCH: obligations belong to another company")
    month = date.fromisoformat(as_of[:10]).isoformat()[:7]
    return [row.to_dict() for row in parsed.obligations if row.get("due_on", "") and row["due_on"][:7] == month]
