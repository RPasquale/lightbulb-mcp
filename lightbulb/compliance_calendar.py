"""The compliance calendar: statutory obligations as replay-fenced cases whose reservations flow into the cash forecast.

The treasury forecast knew about payroll, bills, and the operating budget
and nothing about tax, which is the outflow most likely to be wrong.
``compile_compliance_calendar`` derives the obligations a company carries
from its jurisdiction, archetype, and payroll (GST/BAS or sales tax, PAYG
withholding, superannuation, payroll tax, income tax instalments, the annual
return) with their periods and due dates.  Each obligation is a lifecycle:

    scheduled -> reserved -> lodged -> paid        (terminal)
    reserved | overdue -> paid_awaiting_lodgement -> paid   (paid first, lodged after)
    scheduled | reserved | lodged -> overdue       (non-terminal; may still lodge/pay)
    any non-terminal -> waived                     (terminal, with a reason)

* ``reserve`` consumes a liability read: the Xero BAS or GST report, the
  QuickBooks tax report, or a payroll run summary, with provenance; the
  reservation is the reported liability, never an estimate.
* ``lodge`` consumes a filing receipt (the lodgement reference, the time,
  the amount lodged) that the operator holds from the authority's portal;
  the platform has no filing write, so the receipt names what it is.
* ``pay`` consumes an applied payment observation or bank transaction on
  the same amount: the lodged amount, or, for an obligation paid before it is
  lodged, the reserved liability.  A payment may come before the lodgement,
  never before the period it pays for began.

Due dates follow each jurisdiction's own rule.  The rules name the day of
the month the authority names (the 15th, the 21st, the 28th, the last day),
move the dates the authority moves (Australia's October to December quarter
is due 28 February; New Zealand's 28 December becomes 15 January and 28 April
becomes 7 May), and schedule income tax instalments in the months of the
fiscal year the authority names (the United States' 4th, 6th, 9th and 12th;
New Zealand's provisional tax in the 5th, 9th and 13th).  Each rule carries a
note saying what it assumes.  A period that has ended stays on the calendar
until its obligation falls due.

Australia's and Canada's dates turn on facts the SDK cannot read: how often
the company reports GST, how much it withholds from wages (its withholder or
remitter type), how it pays income tax instalments, and its income tax
lodgment program or balance-due day.  Each is a calendar input
(``CALENDAR_FACTS``).  Left out, the calendar takes the value that never
shows a date later than the law's for the company's own estimates, records
the value in the plan (``calendar_facts``) and lists it in ``assumed_facts``,
so the owner can see what to confirm.

Some obligations fall on paydays, not periods.  Since Payday Super began on
1 July 2026, an Australian employer's super guarantee must reach each
employee's fund within 7 business days of every payday, so each pay run is
its own obligation (``superannuation:pay:<payday>``), reserved from that
run.  The pay runs the company has approved or paid are obligations; the
paydays after them are projected from the pay cycle, for the forecast only,
and become obligations when their runs are approved.  Quarters that ended by
30 June 2026 keep the quarterly rule.

``reservations`` turns every open obligation into treasury ``ScheduledFlow``
rows of kind ``tax_reservation`` so the forecast carries them, and
``calendar_summary`` says what is due, reserved, overdue, and unfunded.
Nothing here lodges or pays anything.
"""

from __future__ import annotations

from calendar import monthrange
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import ObservationProvenance
from lightbulb.jurisdictions import JURISDICTIONS, UnsupportedJurisdictionError, normalize_jurisdiction

COMPLIANCE_KIND = "compliance_obligation"
COMPLIANCE_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
CALENDAR_SCHEMA = "lightbulb.compliance_calendar_plan.v1"
LIABILITY_TOOLS: tuple[str, ...] = ("xero.bas_report", "xero.gst_report", "quickbooks.report", "xero.payroll_summary_report", "host.payroll_run_summary")
MAX_OBLIGATION_TRANSITIONS = 12
_HUNDRED = Decimal("100")

Jurisdiction = Literal["AU", "CA", "US", "UK", "NZ"]
ObligationKind = Literal["gst_bas", "sales_tax", "payg_withholding", "superannuation", "payroll_tax", "income_tax_instalment", "annual_return"]
Frequency = Literal["four_times_monthly", "twice_monthly", "monthly", "two_monthly", "quarterly", "annual", "per_pay_run"]
PayCycle = Literal["weekly", "fortnightly", "four_weekly", "monthly"]
PAY_CYCLE_DAYS: dict[str, int] = {"weekly": 7, "fortnightly": 14, "four_weekly": 28}
PAYDAY_SUPER_STARTS = "2026-07-01T00:00:00Z"
# The pay-run states whose payday is committed: approved or funded, or paid (a run sent for reconciliation counts once it was paid).
COMMITTED_PAY_RUN_STATUSES: frozenset[str] = frozenset({"approved", "funded", "paid", "liabilities_reserved", "reconciled"})

OBLIGATION_STATUSES: tuple[str, ...] = ("scheduled", "reserved", "lodged", "paid_awaiting_lodgement", "paid", "overdue", "waived")
TERMINAL_OBLIGATION_STATUSES: frozenset[str] = frozenset({"paid", "waived"})
OBLIGATION_EVENTS: tuple[str, ...] = ("schedule", "reserve", "lodge", "pay", "mark_overdue", "waive")
_OBLIGATION_TABLE: dict[tuple[str, str], str] = {
    ("new", "schedule"): "scheduled",
    ("scheduled", "reserve"): "reserved",
    ("reserved", "lodge"): "lodged",
    ("lodged", "pay"): "paid",
    # paid before it is lodged: the payment is recorded when it is made, and the obligation completes when it is lodged
    ("reserved", "pay"): "paid_awaiting_lodgement",
    ("paid_awaiting_lodgement", "lodge"): "paid",
    ("overdue", "reserve"): "reserved",
    ("overdue", "lodge"): "lodged",
    ("overdue", "pay"): "paid",  # or paid_awaiting_lodgement, when it was never lodged
    **{(status, "mark_overdue"): "overdue" for status in ("scheduled", "reserved", "lodged")},
    **{(status, "waive"): "waived" for status in ("scheduled", "reserved", "lodged", "overdue", "paid_awaiting_lodgement")},
}

# Statutory shapes per jurisdiction: kind, frequency, days after period end the lodgement is due, the basis it is reserved on.
_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    # Australia's and Canada's GST, withholding, instalment and income tax rules depend on the company's facts: see _FACT_RULES
    "AU": (
        {"kind": "superannuation", "frequency": "quarterly", "due_days_after_period": 28, "basis": "payroll_gross", "rate_percent": "12", "effective_until": PAYDAY_SUPER_STARTS,
         "note": "the super guarantee for a quarter that ended by 30 June 2026, due 28 days after it"},
        {"kind": "superannuation", "frequency": "per_pay_run", "due_business_days_after_pay": 7, "basis": "payroll_gross", "rate_percent": "12", "effective_from": PAYDAY_SUPER_STARTS,
         "note": "Payday Super: from 1 July 2026 the super guarantee (12%) must reach each employee's fund within 7 business days of every payday; weekends are skipped but public holidays are not, so a holiday only makes the legal date later than this one, and a new employee's first contribution (or the first to a new fund), which has 20 business days, is scheduled at 7"},
    ),
    "CA": (),
    "US": (
        {"kind": "sales_tax", "frequency": "monthly", "due_month_offset": 1, "due_day": 20, "basis": "net_gst", "rate_percent": "0",
         "note": "state sales tax: each state sets its rate, filing frequency and due day, the 20th of the following month the most common; the reservation is sized from the sales tax report"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_month_offset": 1, "due_day": 15, "basis": "payroll_withholding", "rate_percent": "0",
         "note": "federal income tax withheld and the employees' Social Security and Medicare, deposited by the 15th of the following month by a monthly depositor; a semiweekly depositor pays sooner"},
        {"kind": "payroll_tax", "frequency": "monthly", "due_month_offset": 1, "due_day": 15, "basis": "payroll_gross", "rate_percent": "7.65",
         "note": "the employer's Social Security (6.2%) and Medicare (1.45%), deposited with the withholding; Form 941 reports the quarter by the last day of the following month; federal and state unemployment taxes are not included"},
        {"kind": "income_tax_instalment", "frequency": "annual", "fiscal_instalments": [4, 6, 9, 12], "due_day": 15, "basis": "instalment_income", "rate_percent": "0",
         "note": "corporate estimated tax on the 15th of the 4th, 6th, 9th and 12th months of the tax year (a C corporation)"},
        {"kind": "annual_return", "frequency": "annual", "due_month_offset": 4, "due_day": 15, "basis": "assessed", "rate_percent": "0",
         "note": "Form 1120 and the balance of tax on the 15th of the 4th month after the year end (a C corporation; an S corporation files on the 15th of the 3rd month)"},
    ),
    "UK": (
        {"kind": "gst_bas", "frequency": "quarterly", "due_month_offset": 2, "due_day": 7, "basis": "net_gst", "rate_percent": "20",
         "note": "the VAT return and payment 1 month and 7 days after the quarter ends, under Making Tax Digital; HMRC sets which months a company's quarters end in"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_month_offset": 1, "due_day": 22, "basis": "payroll_withholding", "rate_percent": "0",
         "note": "PAYE income tax and employee National Insurance paid electronically by the 22nd of the following month; tax months run from the 6th, and an employer paying less than GBP 1,500 a month may pay quarterly"},
        {"kind": "payroll_tax", "frequency": "monthly", "due_month_offset": 1, "due_day": 22, "basis": "payroll_gross", "rate_percent": "15",
         "note": "employer National Insurance at 15% above GBP 5,000 a year per employee, less the Employment Allowance, paid with PAYE; the estimate applies 15% to the whole payroll"},
        {"kind": "superannuation", "frequency": "monthly", "due_month_offset": 1, "due_day": 22, "basis": "payroll_gross", "rate_percent": "3",
         "note": "the automatic-enrolment workplace pension: the employer pays at least 3% of qualifying earnings to the scheme by the 22nd of the following month"},
        {"kind": "annual_return", "frequency": "annual", "due_month_offset": 10, "due_day": 1, "lodge_month_offset": 12, "lodge_day": 31, "basis": "assessed", "rate_percent": "0",
         "note": "Corporation Tax is paid 9 months and 1 day after the accounting period ends and the CT600 filed within 12 months; a company with profits over GBP 1.5 million pays in quarterly instalments instead"},
    ),
    "NZ": (
        {"kind": "gst_bas", "frequency": "two_monthly", "due_month_offset": 1, "due_day": 28, "due_month_shifts": {"12": [1, 15], "4": [1, 7]}, "basis": "net_gst", "rate_percent": "15",
         "note": "the two-monthly GST return and payment by the 28th of the following month; a period ending in November is due 15 January and one ending in March 7 May; monthly or six-monthly filing is elected with Inland Revenue"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_month_offset": 1, "due_day": 20, "basis": "payroll_withholding", "rate_percent": "0",
         "note": "PAYE by the 20th of the following month for an employer deducting less than NZD 500,000 a year (larger employers pay twice a month); employment information is filed within 2 working days of each payday"},
        {"kind": "superannuation", "frequency": "monthly", "due_month_offset": 1, "due_day": 20, "basis": "payroll_gross", "rate_percent": "3.5",
         "note": "KiwiSaver employer contributions of at least 3.5% of gross pay from 1 April 2026 (4% from 1 April 2028), paid with PAYE; ESCT is deducted from the contribution"},
        {"kind": "income_tax_instalment", "frequency": "annual", "fiscal_instalments": [5, 9, 13], "due_day": 28, "due_month_shifts": {"12": [1, 15], "4": [1, 7]}, "basis": "instalment_income", "rate_percent": "0",
         "note": "provisional tax on the standard option in 3 instalments: 28 August, 15 January and 7 May for a 31 March balance date; a company whose residual income tax is NZD 5,000 or less pays none"},
        {"kind": "annual_return", "frequency": "annual", "due_month_offset": 11, "due_day": 7, "lodge_month_offset": 4, "lodge_day": 7, "basis": "assessed", "rate_percent": "0",
         "note": "terminal tax on the 7th of the 11th month after the balance date (7 February for 31 March), or of the 13th with a tax agent's extension of time; the IR4 return is due before it, by the 7th of the 4th month (7 July for 31 March; a balance date from October to February files by the following 7 July, so this date is never later than the law), or by the next 31 March with a tax agent"},
    ),
}


# The facts an Australian or Canadian calendar turns on that the SDK cannot read, and the values each may take.
CALENDAR_FACTS: dict[str, dict[str, tuple[str, ...]]] = {
    "AU": {
        "gst_reporting": ("quarterly", "monthly"),
        "withholder": ("small", "medium", "large"),
        "instalments": ("quarterly", "monthly"),
        "income_tax_program": ("large_medium", "self_preparing", "over_2m", "tax_agent"),
    },
    "CA": {
        "gst_reporting": ("monthly", "quarterly", "annual"),
        "withholder": ("quarterly", "regular", "threshold_1", "threshold_2"),
        "instalments": ("monthly", "quarterly"),
        "income_tax_program": ("general", "ccpc_small_business"),
    },
}
_AU_QUARTER: dict[str, Any] = {"frequency": "quarterly", "due_month_offset": 1, "due_day": 28, "due_month_shifts": {"1": [1, 28]}}
_AU_MONTH: dict[str, Any] = {"frequency": "monthly", "due_month_offset": 1, "due_day": 21}
_CA_MONTH_AFTER: dict[str, Any] = {"due_month_offset": 1, "due_day": 31}
# One rule per (jurisdiction, fact, value), from the authorities' published due dates (ATO; Canada Revenue Agency).
_FACT_RULES: dict[tuple[str, str, str], dict[str, Any]] = {
    ("AU", "gst_reporting", "quarterly"): {"kind": "gst_bas", **_AU_QUARTER, "basis": "net_gst", "rate_percent": "10",
        "note": "the quarterly BAS by the 28th of the month after the quarter, and the October to December quarter by 28 February (ATO); lodging online can add two weeks, which the calendar does not take"},
    ("AU", "gst_reporting", "monthly"): {"kind": "gst_bas", **_AU_MONTH, "basis": "net_gst", "rate_percent": "10",
        "note": "monthly GST, required from a GST turnover of $20 million, lodged and paid by the 21st of the following month"},
    ("AU", "withholder", "small"): {"kind": "payg_withholding", **_AU_QUARTER, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "a small withholder ($25,000 or less withheld a year) pays with the quarterly activity statement: the 28th after the quarter, 28 February for October to December"},
    ("AU", "withholder", "medium"): {"kind": "payg_withholding", **_AU_MONTH, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "a medium withholder ($25,001 to $1 million withheld a year) pays by the 21st of the following month"},
    ("AU", "withholder", "large"): {"kind": "payg_withholding", "frequency": "per_pay_run", "due_days_after_pay_by_weekday": [7, 6, 8, 7, 6, 9, 8], "basis": "payroll_withholding", "rate_percent": "0",
        "note": "a large withholder (more than $1 million withheld a year) pays within days of each payday: withheld on a Monday or Tuesday, by the following Monday; on a Wednesday, the second Thursday after; on a Thursday or Friday, the following Thursday; on a weekend, the second Monday after; a public holiday moves it later, never earlier"},
    ("AU", "instalments", "quarterly"): {"kind": "income_tax_instalment", **_AU_QUARTER, "basis": "instalment_income", "rate_percent": "0",
        "note": "quarterly PAYG instalments: 28 October, 28 February, 28 April and 28 July"},
    ("AU", "instalments", "monthly"): {"kind": "income_tax_instalment", **_AU_MONTH, "basis": "instalment_income", "rate_percent": "0",
        "note": "monthly PAYG instalments, required from instalment income of $20 million, by the 21st of the following month"},
    ("AU", "income_tax_program", "large_medium"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 6, "due_day": 1, "lodge_month_offset": 7, "lodge_day": 31, "basis": "assessed", "rate_percent": "0",
        "note": "company tax for a 30 June year paid by 1 December: the date for a large or medium company that was taxable last year, or one required to lodge by 31 October (the return itself by 31 January or 31 October); the earliest payment date the ATO sets"},
    ("AU", "income_tax_program", "self_preparing"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 8, "due_day": 28, "basis": "assessed", "rate_percent": "0",
        "note": "company tax for a 30 June year lodged and paid by 28 February: a company preparing its own return, or a large or medium one that was not taxable last year or is newly registered"},
    ("AU", "income_tax_program", "over_2m"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 9, "due_day": 31, "basis": "assessed", "rate_percent": "0",
        "note": "company tax for a 30 June year lodged and paid by 31 March: a tax agent's client whose total income the year before was over $2 million"},
    ("AU", "income_tax_program", "tax_agent"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 11, "due_day": 15, "basis": "assessed", "rate_percent": "0",
        "note": "company tax for a 30 June year lodged and paid by 15 May: every other tax agent client"},
    ("CA", "gst_reporting", "monthly"): {"kind": "gst_bas", "frequency": "monthly", **_CA_MONTH_AFTER, "basis": "net_gst", "rate_percent": "5",
        "note": "a monthly GST/HST return filed and paid 1 month after the period ends; required above $6 million of annual taxable supplies"},
    ("CA", "gst_reporting", "quarterly"): {"kind": "gst_bas", "frequency": "quarterly", **_CA_MONTH_AFTER, "basis": "net_gst", "rate_percent": "5",
        "note": "a quarterly GST/HST return filed and paid 1 month after the quarter ends: the CRA's period from $1.5 million to $6 million of supplies, and the dates an annual filer who owed $3,000 or more pays its instalments on"},
    ("CA", "gst_reporting", "annual"): {"kind": "gst_bas", "frequency": "annual", "due_month_offset": 3, "due_day": 31, "basis": "net_gst", "rate_percent": "5",
        "note": "an annual GST/HST return filed and paid 3 months after the fiscal year ends ($1.5 million of supplies or less); an annual filer who owed $3,000 or more also pays quarterly instalments, which this rule does not schedule: keep quarterly reporting on the calendar for their dates"},
    ("CA", "withholder", "quarterly"): {"kind": "payg_withholding", "frequency": "quarterly", "due_month_offset": 1, "due_day": 15, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "a quarterly remitter (a small employer with a perfect compliance record) remits by 15 April, 15 July, 15 October and 15 January"},
    ("CA", "withholder", "regular"): {"kind": "payg_withholding", "frequency": "monthly", "due_month_offset": 1, "due_day": 15, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "a regular remitter (average monthly withholding under $25,000) remits each month's source deductions by the 15th of the next month"},
    ("CA", "withholder", "threshold_1"): {"kind": "payg_withholding", "frequency": "twice_monthly", "due_days_after_period": 10, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "an accelerated remitter, threshold 1 (average monthly withholding of $25,000 to $99,999.99): pay from the 1st to the 15th remitted by the 25th, and from the 16th to the month end by the 10th of the next month"},
    ("CA", "withholder", "threshold_2"): {"kind": "payg_withholding", "frequency": "four_times_monthly", "due_business_days_after_period": 3, "basis": "payroll_withholding", "rate_percent": "0",
        "note": "an accelerated remitter, threshold 2 (average monthly withholding of $100,000 or more): four periods a month (1st-7th, 8th-14th, 15th-21st, 22nd-end), each remitted by the 3rd working day after it; public holidays are not skipped, so the date is never later than the law's"},
    ("CA", "instalments", "monthly"): {"kind": "income_tax_instalment", "frequency": "monthly", "due_days_after_period": 0, "basis": "instalment_income", "rate_percent": "0",
        "note": "corporate income tax instalments on the last day of each month of the tax year, the CRA's general rule (a corporation whose tax for this or last year is $3,000 or less pays none)"},
    ("CA", "instalments", "quarterly"): {"kind": "income_tax_instalment", "frequency": "annual", "fiscal_instalments": [3, 6, 9, 12], "due_day": 31, "basis": "instalment_income", "rate_percent": "0",
        "note": "quarterly instalments on the last day of each quarter of the tax year, allowed a CCPC with a perfect compliance record, taxable income of $500,000 or less and taxable capital of $10 million or less"},
    ("CA", "income_tax_program", "general"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 2, "due_day": 31, "lodge_month_offset": 6, "lodge_day": 31, "basis": "assessed", "rate_percent": "0",
        "note": "the balance of corporation tax is due 2 months after the tax year ends; the T2 return is filed within 6 months"},
    ("CA", "income_tax_program", "ccpc_small_business"): {"kind": "annual_return", "frequency": "annual", "due_month_offset": 3, "due_day": 31, "lodge_month_offset": 6, "lodge_day": 31, "basis": "assessed", "rate_percent": "0",
        "note": "a CCPC that claimed the small business deduction this year or last, with last year's taxable income within its business limit, pays the balance 3 months after the tax year ends; the T2 return is filed within 6 months"},
}
# A company's withholding estimated as the calendar estimates it: 22% of its payroll.
_WITHHOLDING_SHARE = Decimal("0.22")


def calendar_facts(jurisdiction: str, *, estimated_revenue_per_month: Any = "0", estimated_payroll_per_month: Any = "0", **given: str | None) -> tuple[dict[str, str], tuple[str, ...]]:
    """The facts an Australian or Canadian calendar is compiled on, and which of them were assumed.

    A fact left out takes the value that never shows a date later than the law's for the company's own
    estimates: Australia's quarterly GST and instalments below $20 million a year, a medium withholder
    (monthly) unless its estimated withholding passes $1 million a year, and company tax paid by 1 December
    (a large or medium company's date, the earliest the ATO sets); Canada's monthly GST/HST above $6 million
    of supplies and quarterly below, a regular remitter (monthly) unless its estimated withholding passes
    $25,000 or $100,000 a month, monthly instalments (the CRA's general rule), and the balance due 2 months
    after the year ends.
    """

    code = normalize_jurisdiction(jurisdiction)
    known = CALENDAR_FACTS.get(code, {})
    supplied = {name: value for name, value in given.items() if value is not None and value != ""}
    for name, value in supplied.items():
        _require(name in known, "CALENDAR_FACT_UNKNOWN", f"{name} is not a fact of the {code} calendar; its facts are {', '.join(known) or 'none'}")
        _require(value in known[name], "CALENDAR_FACT_INVALID", f"{name} is one of {', '.join(known[name])}; got {value!r}")
    if not known:
        return {}, ()
    revenue_year = decimal_value(estimated_revenue_per_month, field_name="estimated_revenue_per_month") * 12
    withheld_month = decimal_value(estimated_payroll_per_month, field_name="estimated_payroll_per_month") * _WITHHOLDING_SHARE
    if code == "AU":
        defaults = {
            "gst_reporting": "monthly" if revenue_year >= 20_000_000 else "quarterly",
            "withholder": "large" if withheld_month * 12 > 1_000_000 else "medium",
            "instalments": "monthly" if revenue_year > 20_000_000 else "quarterly",
            "income_tax_program": "large_medium",
        }
    else:
        defaults = {
            "gst_reporting": "monthly" if revenue_year > 6_000_000 else "quarterly",
            "withholder": "threshold_2" if withheld_month >= 100_000 else "threshold_1" if withheld_month >= 25_000 else "regular",
            "instalments": "monthly",
            "income_tax_program": "general",
        }
    facts = {name: supplied.get(name, defaults[name]) for name in known}
    return facts, tuple(name for name in known if name not in supplied)


def _fact_rules(code: str, facts: Mapping[str, str], *, fiscal_year_end_month: int) -> list[dict[str, Any]]:
    rules = [dict(_FACT_RULES[(code, name, value)]) for name, value in facts.items()]
    if code == "AU" and fiscal_year_end_month != 6:
        # a substituted accounting period pays on the 1st day of the 6th month after its year ends, whatever the program
        for rule in rules:
            if rule["kind"] == "annual_return":
                rule.update({"due_month_offset": 6, "due_day": 1, "lodge_month_offset": 7, "lodge_day": 15, "note": "company tax for a substituted accounting period is paid on the 1st day of the 6th month after the year ends, and the return lodged by the 15th day of the 7th"})
    return rules


class ObligationRule(StrictModel):
    """One statutory obligation: how often it falls, when it is due, and what it is reserved on.

    A rule is due either ``due_days_after_period`` after its period, or on
    ``due_day`` of the month ``due_month_offset`` months after the month the
    period ends in, or, for ``fiscal_instalments``, on ``due_day`` of those
    months of the fiscal year (month 1 is its first).  ``due_month_shifts``
    moves a date the authority moves: a date falling in the named month moves
    on by the given months, to the given day.  A ``per_pay_run`` rule falls on
    each payday and is due ``due_business_days_after_pay`` weekdays after it,
    or, with ``due_days_after_pay_by_weekday``, the days given for the payday's
    weekday (Monday first).  ``due_business_days_after_period`` counts weekdays
    after the period's last day.  ``twice_monthly`` periods run from the 1st
    and the 16th, ``four_times_monthly`` ones from the 1st, 8th, 15th and 22nd.
    ``lodge_month_offset`` and ``lodge_day`` date the return itself when it
    has its own date: after the money is due (a Canadian T2 six months on,
    against a balance due at two; the UK CT600 at twelve, against Corporation
    Tax at nine and a day) or before it (New Zealand's IR4 in July, against
    terminal tax the next February).
    ``effective_until`` ends a period rule with the last period that closes by
    that date; ``effective_from`` starts a rule with the first payday, or the
    first period, from that date.
    """

    kind: ObligationKind
    frequency: Frequency
    due_days_after_period: int | None = Field(default=None, ge=0, le=365)
    due_month_offset: int | None = Field(default=None, ge=0, le=24)
    due_day: int | None = Field(default=None, ge=1, le=31)
    fiscal_instalments: tuple[int, ...] | None = Field(default=None, min_length=1, max_length=12)
    due_month_shifts: dict[str, tuple[int, int]] | None = None
    due_business_days_after_pay: int | None = Field(default=None, ge=1, le=30)
    due_days_after_pay_by_weekday: tuple[int, ...] | None = Field(default=None, min_length=7, max_length=7)
    due_business_days_after_period: int | None = Field(default=None, ge=1, le=30)
    # the return's own date, where it is not the payment's: lodge_day of the month lodge_month_offset months on
    lodge_month_offset: int | None = Field(default=None, ge=0, le=24)
    lodge_day: int | None = Field(default=None, ge=1, le=31)
    effective_from: str | None = None
    effective_until: str | None = None
    basis: Literal["net_gst", "payroll_withholding", "payroll_gross", "instalment_income", "assessed"]
    rate_percent: Decimal
    note: BoundedText | None = None

    @field_validator("effective_from", "effective_until")
    @classmethod
    def _effective(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @field_validator("rate_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="rate_percent")

    @field_validator("fiscal_instalments", "due_days_after_pay_by_weekday", mode="before")
    @classmethod
    def _instalments(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("due_month_shifts", mode="before")
    @classmethod
    def _shifts(cls, value: object) -> object:
        return {str(key): tuple(item) if isinstance(item, list) else item for key, item in dict(value).items()} if isinstance(value, Mapping) else value

    @model_validator(mode="after")
    def _one_due_rule(self) -> "ObligationRule":
        by_days = self.due_days_after_period is not None
        by_month = self.due_month_offset is not None
        by_instalment = self.fiscal_instalments is not None
        by_payday = self.due_business_days_after_pay is not None or self.due_days_after_pay_by_weekday is not None
        by_business_days = self.due_business_days_after_period is not None
        if by_days + by_month + by_instalment + by_payday + by_business_days != 1 or (self.due_business_days_after_pay is not None and self.due_days_after_pay_by_weekday is not None):
            raise ValueError("a rule is due by days after its period, by a day of a later month, by fiscal-year instalments, by business days after its period, or by days after a payday; exactly one")
        if by_payday != (self.frequency == "per_pay_run"):
            raise ValueError("a rule falls on paydays exactly when it is due business days after them")
        if any(not 0 <= days <= 14 for days in self.due_days_after_pay_by_weekday or ()):
            raise ValueError("a payday's due date falls 0 to 14 days after it")
        if (self.lodge_month_offset is None) != (self.lodge_day is None) or (self.lodge_month_offset is not None and self.frequency == "per_pay_run"):
            raise ValueError("a lodgement date names both its month and its day, on a period rule")
        if (by_month or by_instalment) != (self.due_day is not None):
            raise ValueError("a rule due on a day of the month names that day, and only such a rule does")
        months = list(self.fiscal_instalments or ())
        if by_instalment and (self.frequency != "annual" or any(not 1 <= month <= 24 for month in months) or months != sorted(set(months))):
            raise ValueError("fiscal instalments fall in rising months 1-24 of an annual rule")
        for month, (months_on, day) in (self.due_month_shifts or {}).items():
            if not month.isdigit() or not 1 <= int(month) <= 12 or not 0 <= months_on <= 2 or not 1 <= day <= 31:
                raise ValueError("a due-date shift names a calendar month, moves it on by at most 2 months, and names a day")
        return self


class ScheduledObligation(StrictModel):
    obligation_ref: OpaqueRef
    kind: ObligationKind
    period_start: str
    period_end: str
    due_at: str
    basis: ShortText
    estimated_amount: Decimal
    # A payday obligation names its payday; a projected one is a payday the cycle expects and nothing has committed yet.
    pay_date: str | None = None
    projected: Literal[True] | None = None
    # When the return is lodged later than the money is due (a Canadian T2 after the balance-due day); absent, both fall on due_at.
    lodge_due_at: str | None = None
    # A withdrawn fact leaves the historical marker for replay only, not a due date.
    deadline_status: Literal["unknown"] | None = None
    deadline_missing_facts: tuple[ShortText, ...] | None = None

    @field_validator("estimated_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="estimated_amount")


class ComplianceCalendarPlan(StrictModel):
    """The obligations a company carries: jurisdiction, rules, and the schedule derived for the horizon."""

    schema_id: str = Field(default=CALENDAR_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    jurisdiction: Jurisdiction
    currency: ShortText
    fiscal_year_end_month: int = Field(default=6, ge=1, le=12)
    has_payroll: bool = True
    registered_for_gst: bool = True
    rules: tuple[ObligationRule, ...] = Field(min_length=1, max_length=12)
    schedule: tuple[ScheduledObligation, ...] = Field(default_factory=tuple, max_length=200)
    # The pay cycle payday obligations are projected on, and whether it was assumed for want of one.
    pay_cycle: PayCycle | None = None
    pay_cycle_assumed: Literal[True] | None = None
    # The facts an Australian or Canadian calendar was compiled on (CALENDAR_FACTS), and those the company did not give.
    calendar_facts: dict[str, ShortText] | None = None
    assumed_facts: tuple[ShortText, ...] | None = None
    reserve_tolerance_percent: Decimal = Field(default=Decimal("2.00"), validate_default=True)
    overdue_grace_days: int = Field(default=0, ge=0, le=60)
    # Date-only statutory facts are separate from forecast estimates and payment authority.
    canada_calendar: dict[str, Any] | None = None
    australia_calendar: dict[str, Any] | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reserve_tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="reserve_tolerance_percent")

    @field_validator("rules", "schedule", "assumed_facts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ComplianceCalendarPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(ComplianceCalendarPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def obligation(self, obligation_ref: str) -> ScheduledObligation | None:
        return next((item for item in self.schedule if item.obligation_ref == obligation_ref), None)


def _month_start(year: int, month: int) -> datetime:
    return datetime(year, month, 1, tzinfo=timezone.utc)


def _add_months(value: datetime, months: int) -> datetime:
    month = value.month - 1 + months
    return _month_start(value.year + month // 12, month % 12 + 1)


def _periods(frequency: str, start: datetime, horizon_months: int, fiscal_year_end_month: int) -> list[tuple[datetime, datetime]]:
    """Every period from the one before ``start`` through the horizon; the caller keeps those not yet due."""

    if frequency in _SPLIT_MONTH:
        # periods inside each month, from the month before start (whose last period may not be due yet) through the horizon
        cursor, end_limit = _add_months(_month_start(start.year, start.month), -1), _add_months(_month_start(start.year, start.month), horizon_months)
        out_split: list[tuple[datetime, datetime]] = []
        while cursor < end_limit:
            following = _add_months(cursor, 1)
            starts = [cursor.replace(day=day) for day in _SPLIT_MONTH[frequency]]
            out_split.extend(zip(starts, [*starts[1:], following]))
            cursor = following
        return out_split
    step = {"monthly": 1, "two_monthly": 2, "quarterly": 3, "annual": 12}[frequency]
    if frequency == "annual":
        first = _month_start(start.year if start.month <= fiscal_year_end_month else start.year + 1, fiscal_year_end_month)
        first = _add_months(first, 1)  # the period ends at the fiscal year end; the obligation period starts the month after last year end
        first = _add_months(first, -12)
    elif frequency == "two_monthly":
        # two-monthly periods are aligned so that one of them ends at the fiscal year end
        first = _add_months(_month_start(start.year, start.month), -((start.month - 1 - fiscal_year_end_month) % step))
    else:
        offset = (start.month - 1) % step
        first = _month_start(start.year, start.month - offset)
    # A period that ended before start stays on the calendar until it falls due; no rule is due more than a period late.
    cursor = _add_months(first, -step)
    out: list[tuple[datetime, datetime]] = []
    end_limit = _add_months(_month_start(start.year, start.month), horizon_months)
    while cursor < end_limit:
        period_end = _add_months(cursor, step)
        out.append((cursor, period_end))
        cursor = period_end
    return out


# The days of the month a split-month period starts on.
_SPLIT_MONTH: dict[str, tuple[int, ...]] = {"twice_monthly": (1, 16), "four_times_monthly": (1, 8, 15, 22)}


def _on_day(month_start: datetime, day: int, shifts: Mapping[str, tuple[int, int]] | None) -> datetime:
    """The end of the due day: ``day`` of that month, moved when the authority moves it, clamped to the month's length."""

    shift = (shifts or {}).get(str(month_start.month))
    if shift is not None:
        month_start, day = _add_months(month_start, shift[0]), shift[1]
    return month_start.replace(day=min(day, monthrange(month_start.year, month_start.month)[1])) + timedelta(days=1)


def _due(rule: ObligationRule, period_end: datetime) -> datetime:
    if rule.due_days_after_period is not None:
        return period_end + timedelta(days=rule.due_days_after_period)
    if rule.due_business_days_after_period is not None:
        # the end of the nth weekday after the period's last day
        return _business_days_after(period_end - timedelta(days=1), rule.due_business_days_after_period) + timedelta(days=1)
    assert rule.due_month_offset is not None and rule.due_day is not None
    # period_end is the first day after the period, so the period ends in the month before it
    return _on_day(_add_months(period_end, rule.due_month_offset - 1), rule.due_day, rule.due_month_shifts)


def _obligation_periods(rule: ObligationRule, start: datetime, horizon_months: int, fiscal_year_end_month: int) -> list[tuple[datetime, datetime, datetime]]:
    """(period start, period end, due) for every obligation of the rule not yet due at ``start``.

    An instalment's period runs from the start of its fiscal year to the start
    of the month it falls due in, so a read taken for it covers the year so far.
    """

    rows: list[tuple[datetime, datetime, datetime]] = []
    for period_start, period_end in _periods(rule.frequency, start, horizon_months, fiscal_year_end_month):
        if rule.fiscal_instalments is None:
            rows.append((period_start, period_end, _due(rule, period_end)))
            continue
        assert rule.due_day is not None
        for month in rule.fiscal_instalments:
            due_month = _add_months(period_start, month - 1)
            rows.append((period_start, due_month, _on_day(due_month, rule.due_day, rule.due_month_shifts)))
    return [row for row in rows if row[2] > start]


def _business_days_after(day: datetime, count: int, *, exclude_australian_holidays: bool = False) -> datetime:
    """Advance the existing Payday Super clock; optionally use statewide AU holidays.

    Without confirmed Australia facts legacy forecasts stay conservative weekdays.
    The statutory view marks unsupported holiday years as unknown.
    """

    cursor = day
    while count > 0:
        cursor += timedelta(days=1)
        holiday = False
        if exclude_australian_holidays and cursor.year in (2026, 2027):
            from lightbulb.australia_obligations import super_holidays
            holiday = cursor.date() in super_holidays(cursor.year)
        if cursor.weekday() < 5 and not holiday:
            count -= 1
    return cursor


def _day(value: Any, *, field_name: str) -> datetime:
    """A pay-run date as the start of its day, from a timestamp or a bare date."""

    text = str(value or "")
    stamp = parsed(timestamp(text if "T" in text else f"{text}T00:00:00Z", field_name=field_name))
    return stamp.replace(hour=0, minute=0, second=0, microsecond=0)


def _month_day(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, min(day, monthrange(year, month)[1]), tzinfo=timezone.utc)


def _next_payday(payday: datetime, cycle: str, anchor_day: int) -> datetime:
    if cycle == "monthly":
        following = _add_months(_month_start(payday.year, payday.month), 1)
        return _month_day(following.year, following.month, anchor_day)
    return payday + timedelta(days=PAY_CYCLE_DAYS[cycle])


def _prior_payday(payday: datetime, cycle: str, anchor_day: int) -> datetime:
    if cycle == "monthly":
        prior = _add_months(_month_start(payday.year, payday.month), -1)
        return _month_day(prior.year, prior.month, anchor_day)
    return payday - timedelta(days=PAY_CYCLE_DAYS[cycle])


def _payday_rows(rule: ObligationRule, *, start: datetime, end_limit: datetime, pay_runs: Sequence[Mapping[str, Any]], pay_cycle: str, next_pay_date: datetime | None, payroll: Decimal, exclude_australian_holidays: bool = False) -> list[dict[str, Any]]:
    """The payday obligations of a per-pay-run rule: one for each committed pay run, then the paydays the cycle projects after the last of them."""

    assert rule.due_business_days_after_pay is not None or rule.due_days_after_pay_by_weekday is not None
    since = parsed(rule.effective_from) if rule.effective_from else None
    rows: list[dict[str, Any]] = []

    def row(payday: datetime, period_start: datetime, days: int, *, projected: bool) -> None:
        """A payday's obligation covers what that payday paid: from its pay period's start through the end of the payday."""

        if since is not None and payday < since:
            return
        if rule.due_days_after_pay_by_weekday is not None:
            due = payday + timedelta(days=rule.due_days_after_pay_by_weekday[payday.weekday()] + 1)  # the end of the due day
        else:
            assert rule.due_business_days_after_pay is not None
            due = _business_days_after(payday, rule.due_business_days_after_pay, exclude_australian_holidays=exclude_australian_holidays) + timedelta(days=1)  # the end of the due day
        if due <= start:
            return
        share = _WITHHOLDING_SHARE if rule.basis == "payroll_withholding" else rule.rate_percent / _HUNDRED
        estimate = payroll * Decimal(max(1, days)) / Decimal("30") * share
        rows.append({"obligation_ref": f"{rule.kind}:pay:{payday.date().isoformat()}", "kind": rule.kind, "period_start": iso(period_start), "period_end": iso(payday + timedelta(days=1)), "due_at": iso(due), "basis": rule.basis, "estimated_amount": str(estimate.quantize(MONEY_QUANTUM)), "pay_date": iso(payday), **({"projected": True} if projected else {})})

    paydays: set[datetime] = set()
    for run in pay_runs:
        payday = _day(run.get("pay_date"), field_name="pay_date")
        if payday in paydays:
            continue
        paydays.add(payday)
        period_start = _day(run.get("period_start") or run.get("pay_date"), field_name="period_start")
        period_end = _day(run.get("period_end") or run.get("pay_date"), field_name="period_end")
        row(payday, period_start, (period_end - period_start).days + 1, projected=False)  # a pay run's period names its last day
    # The cycle runs on from the last committed payday, else from the payday the company named, else from month ends it assumes,
    # beginning with the month end before start, whose super may not be due yet.
    if paydays:
        anchor_day = max(paydays).day
        payday = _next_payday(max(paydays), pay_cycle, anchor_day)
    elif next_pay_date is not None:
        anchor_day, payday = next_pay_date.day, next_pay_date
    else:
        prior = _add_months(_month_start(start.year, start.month), -1)
        anchor_day, payday = 31, _month_day(prior.year, prior.month, 31)  # month ends, whatever each month's length
    while payday < end_limit:
        previous = _prior_payday(payday, pay_cycle, anchor_day)
        row(payday, previous + timedelta(days=1), (payday - previous).days, projected=True)
        payday = _next_payday(payday, pay_cycle, anchor_day)
    return rows


def committed_pay_runs(states: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    """The pay runs whose payday is committed, from persisted ``payroll_run_chain`` states: approved, funded or paid."""

    out: list[dict[str, str]] = []
    for state in states:
        raw = dict(detached(state))
        ledger = dict(raw.get("ledger") or {})
        status = str(raw.get("status") or "")
        if not ledger.get("pay_date") or not (status in COMMITTED_PAY_RUN_STATUSES or (status == "reconciliation_required" and ledger.get("paid_at"))):
            continue
        out.append({"pay_date": str(ledger["pay_date"]), "period_start": str(ledger.get("period_start") or ledger["pay_date"]), "period_end": str(ledger.get("period_end") or ledger["pay_date"])})
    return sorted(out, key=lambda row: row["pay_date"])


def pay_cycle_for_days(days: Any) -> str | None:
    """The calendar's pay cycle for a payroll plan's ``pay_cycle_days``: 7 weekly, 14 fortnightly, 28 four-weekly, 29-31 monthly."""

    value = int(days) if isinstance(days, int) and not isinstance(days, bool) else None
    if value is None:
        return None
    return {7: "weekly", 14: "fortnightly", 28: "four_weekly"}.get(value, "monthly" if 29 <= value <= 31 else None)


def compile_compliance_calendar(company_ref: str, *, jurisdiction: str, currency: str, start_at: str, horizon_months: int = 12, estimated_revenue_per_month: Any = "0", estimated_payroll_per_month: Any = "0", has_payroll: bool = True, registered_for_gst: bool = True, fiscal_year_end_month: int | None = None, pay_cycle: str | None = None, next_pay_date: str | None = None, pay_runs: Sequence[Mapping[str, Any]] = (), overrides: Mapping[str, Any] | None = None, gst_reporting: str | None = None, withholder: str | None = None, instalments: str | None = None, income_tax_program: str | None = None, australia_facts: Mapping[str, Any] | None = None, canada_facts: Mapping[str, Any] | None = None) -> ComplianceCalendarPlan:
    """Derive the obligations for the horizon; estimates only size the reservation until a liability read replaces them.

    ``pay_runs`` are the company's committed pay runs (``pay_date``, ``period_start``, ``period_end``);
    ``pay_cycle`` (weekly, fortnightly, four_weekly or monthly) and ``next_pay_date`` project the paydays
    after them.  With neither, paydays are assumed at each month end and the plan says so.

    ``gst_reporting``, ``withholder``, ``instalments`` and ``income_tax_program`` are the Australian and
    Canadian facts in ``CALENDAR_FACTS``; see ``calendar_facts`` for what each defaults to.
    """

    try:
        code = normalize_jurisdiction(jurisdiction)
    except UnsupportedJurisdictionError:
        raise ValueError(f"unsupported jurisdiction {jurisdiction!r}; known: {sorted(_RULES)}") from None
    start = parsed(timestamp(start_at, field_name="start_at"))
    fy_end = fiscal_year_end_month or JURISDICTIONS[code].fiscal_year_end_month
    revenue = decimal_value(estimated_revenue_per_month, field_name="estimated_revenue_per_month")
    payroll = decimal_value(estimated_payroll_per_month, field_name="estimated_payroll_per_month")
    ca_config = None
    stated_withholder = withholder
    if code == "CA" and (canada_facts is not None or start.year >= 2026):
        from lightbulb.canada_obligations import CanadaCalendarFacts, remitter_from_amwa, remitter_assignments
        ca_config = CanadaCalendarFacts.model_validate(detached(canada_facts or {}))
        if fiscal_year_end_month is not None and ca_config.fiscal_year_end_month is not None and fiscal_year_end_month != ca_config.fiscal_year_end_month:
            raise ValueError("conflicting Canada calendar fact: fiscal_year_end_month")
        fy_end = ca_config.fiscal_year_end_month or fy_end
        if income_tax_program is not None:
            ccpc = (ca_config.ccpc_throughout_year, ca_config.small_business_deduction_claimed, ca_config.prior_income_within_business_limit)
            if (income_tax_program == "ccpc_small_business" and any(v is False for v in ccpc)) or (income_tax_program == "general" and all(v is True for v in ccpc)):
                raise ValueError("conflicting income_tax_program and Canada CCPC facts")
        gst_reporting = gst_reporting or ca_config.gst_reporting
        assignments, _conflicts = remitter_assignments(ca_config)
        year_bound = ca_config.remitter_year is not None or bool(ca_config.remitters_by_year)
        if year_bound:
            withholder = (withholder if ca_config.remitter_year in (None, start.year) else None) or assignments.get(str(start.year))
        else:
            withholder = withholder or ca_config.remitter
            if withholder is None and ca_config.amwa is not None:
                withholder = remitter_from_amwa(ca_config.amwa, quarterly_approved=ca_config.quarterly_remittance_approved, new_employer=ca_config.new_employer)
        if instalments is None and ca_config.corporate_instalments in ("monthly", "quarterly"):
            instalments = ca_config.corporate_instalments
    facts, assumed = calendar_facts(code, estimated_revenue_per_month=revenue, estimated_payroll_per_month=payroll, gst_reporting=gst_reporting, withholder=withholder, instalments=instalments, income_tax_program=income_tax_program)
    au_facts = None
    if australia_facts is not None or (code == "AU" and start.year >= 2026 and any(v is not None for v in (gst_reporting, withholder, instalments, income_tax_program))):
        if code != "AU" or start.year < 2026:
            raise ValueError("australia_facts require an Australian calendar starting in 2026 or later")
        from lightbulb.australia_obligations import AustraliaCalendarFacts
        supplied = dict(australia_facts or {})
        for key, value in (("gst_reporting", gst_reporting), ("withholder", withholder), ("instalments", instalments), ("company_tax_program", income_tax_program)):
            if value is not None:
                if key in supplied and supplied[key] != value:
                    raise ValueError(f"conflicting Australia calendar fact: {key}")
                supplied[key] = value
        if fiscal_year_end_month is not None:
            if supplied.get("fiscal_year_end_month") not in (None, fiscal_year_end_month):
                raise ValueError("conflicting Australia calendar fact: fiscal_year_end_month")
            supplied["fiscal_year_end_month"] = fiscal_year_end_month
        au_facts = AustraliaCalendarFacts.model_validate(supplied)
        fy_end = au_facts.fiscal_year_end_month or fy_end
        for key in ("gst_reporting", "withholder", "instalments"):
            value = getattr(au_facts, key)
            if value is not None and value != "none" and value in CALENDAR_FACTS[code][key]:
                facts[key] = value
                assumed = tuple(name for name in assumed if name != key)
        if au_facts.company_tax_program in CALENDAR_FACTS[code]["income_tax_program"]:
            facts["income_tax_program"] = au_facts.company_tax_program
            assumed = tuple(name for name in assumed if name != "income_tax_program")
    candidates = [*_RULES[code], *_fact_rules(code, facts, fiscal_year_end_month=fy_end)]
    if ca_config is not None and ca_config.corporate_instalments == "none":
        candidates = [r for r in candidates if r["kind"] != "income_tax_instalment"]
    if ca_config is not None and ca_config.entity_type in ("sole_proprietor", "partnership", "other"):
        candidates = [r for r in candidates if r["kind"] not in ("annual_return", "income_tax_instalment")]
    rules = [ObligationRule.model_validate(rule) for rule in candidates if (registered_for_gst or rule["basis"] != "net_gst") and (has_payroll or rule["basis"] not in ("payroll_withholding", "payroll_gross"))]
    _require(pay_cycle is None or pay_cycle in ("weekly", "fortnightly", "four_weekly", "monthly"), "PAY_CYCLE_UNKNOWN", f"a pay cycle is weekly, fortnightly, four_weekly or monthly; got {pay_cycle!r}")
    if au_facts is not None and au_facts.instalments == "none":
        rules = [rule for rule in rules if rule.kind != "income_tax_instalment"]
    payday_rules = [rule for rule in rules if rule.frequency == "per_pay_run"]
    cycle_facts: dict[str, Any] = {}
    schedule: list[dict[str, Any]] = []
    if payday_rules:
        cycle_facts = {"pay_cycle": pay_cycle or "monthly", **({} if pay_cycle or next_pay_date or pay_runs else {"pay_cycle_assumed": True})}
        first = None if next_pay_date is None else _day(next_pay_date, field_name="next_pay_date")
        end_limit = _add_months(_month_start(start.year, start.month), horizon_months)
        for rule in payday_rules:
            schedule.extend(_payday_rows(rule, start=start, end_limit=end_limit, pay_runs=pay_runs, pay_cycle=cycle_facts["pay_cycle"], next_pay_date=first, payroll=payroll, exclude_australian_holidays=au_facts is not None))
    for rule in rules:
        if rule.frequency == "per_pay_run":
            continue
        until = parsed(rule.effective_until) if rule.effective_until else None
        since = parsed(rule.effective_from) if rule.effective_from else None
        for period_start, period_end, due in _obligation_periods(rule, start, horizon_months, fy_end):
            if (until is not None and period_end > until) or (since is not None and period_start < since):
                continue
            months: Decimal | int = max(1, round((period_end - period_start).days / 30))
            if rule.frequency in _SPLIT_MONTH:
                months = Decimal((period_end - period_start).days) / Decimal("30")  # a part of a month is its share of it
            if rule.basis == "net_gst":
                estimate = revenue * months * rule.rate_percent / _HUNDRED * Decimal("0.6")  # net of input credits at a conservative 40%
            elif rule.basis == "payroll_withholding":
                estimate = payroll * months * _WITHHOLDING_SHARE
            elif rule.basis == "payroll_gross":
                estimate = payroll * months * rule.rate_percent / _HUNDRED
            elif rule.basis == "instalment_income" and rule.fiscal_instalments is not None:
                estimate = revenue * 12 * Decimal("0.02") / len(rule.fiscal_instalments)  # the year's tax, spread over its instalments
            elif rule.basis == "instalment_income":
                estimate = revenue * months * Decimal("0.02")
            else:
                estimate = Decimal("0")
            lodge = {} if rule.lodge_month_offset is None or rule.lodge_day is None else {"lodge_due_at": iso(_on_day(_add_months(period_end, rule.lodge_month_offset - 1), rule.lodge_day, None))}
            schedule.append({"obligation_ref": f"{rule.kind}:{period_end.date().isoformat()}", "kind": rule.kind, "period_start": iso(period_start), "period_end": iso(period_end), "due_at": iso(due), "basis": rule.basis, "estimated_amount": str(estimate.quantize(MONEY_QUANTUM)), **lodge})
    schedule.sort(key=lambda item: (item["due_at"], item["obligation_ref"]))
    fact_fields = {"calendar_facts": facts, **({"assumed_facts": list(assumed)} if assumed else {})} if facts else {}
    raw = {"company_ref": company_ref, "jurisdiction": code, "currency": currency.upper(), "fiscal_year_end_month": fy_end, "has_payroll": has_payroll, "registered_for_gst": registered_for_gst, "rules": [rule.to_dict() for rule in rules], "schedule": schedule, **cycle_facts, **fact_fields, **dict(overrides or {})}
    if code == "AU" and start.year >= 2026:
        from lightbulb.australia_obligations import compile_australia_obligations
        raw["australia_calendar"] = compile_australia_obligations(company_ref, start_on=start.date().isoformat(), horizon_months=horizon_months, facts=au_facts, has_payroll=has_payroll, registered_for_gst=registered_for_gst, fiscal_year_end_month=fiscal_year_end_month, pay_runs=pay_runs, payday_schedule=schedule if au_facts is not None else (), pay_cycle_confirmed=bool(pay_cycle or next_pay_date)).to_dict()
        if raw["australia_calendar"]["facts"].get("gst_reporting") is None:
            raw["schedule"] = [item for item in raw["schedule"] if item["kind"] != "gst_bas"]
        kinds = {"gst_bas": "bas", "payg_withholding": "payg_withholding", "income_tax_instalment": "income_tax_instalment", "annual_return": "company_tax_balance"}
        statutory = raw["australia_calendar"]["obligations"]
        for item in raw["schedule"]:
            period = (parsed(item["period_end"]) - timedelta(days=1)).date().isoformat()
            matches = [r for r in statutory if r["kind"] == kinds.get(item["kind"]) and r["period_end"] == period and r["due_on"]]
            if len(matches) == 1:
                candidate = iso(_day(matches[0]["due_on"], field_name="due_on") + timedelta(days=1))
                # An uncertain candidate can only bring the estimate forward.
                item["due_at"] = candidate if matches[0]["status"] == "scheduled" else min(item["due_at"], candidate)
            if item["kind"] == "annual_return":
                returns = [r for r in statutory if r["kind"] == "company_tax_return" and r["period_end"] == period and r["due_on"] and r["status"] == "scheduled"]
                if len(returns) == 1:
                    item["lodge_due_at"] = iso(_day(returns[0]["due_on"], field_name="due_on") + timedelta(days=1))
        raw["schedule"].sort(key=lambda item: (item["due_at"], item["obligation_ref"]))
    if code == "CA" and start.year >= 2026:
        from lightbulb.canada_obligations import compile_canada_obligations
        ca_facts = dict(canada_facts or {})
        for name, value in (("gst_reporting", gst_reporting), ("remitter", stated_withholder), ("corporate_instalments", instalments)):
            if value is not None:
                if name in ca_facts and ca_facts[name] != value:
                    raise ValueError(f"conflicting Canada calendar fact: {name}")
                ca_facts[name] = value
        raw["canada_calendar"] = compile_canada_obligations(company_ref, start_on=start.date().isoformat(), horizon_months=horizon_months, fiscal_year_end_month=fiscal_year_end_month, has_payroll=has_payroll, registered_for_gst=registered_for_gst, facts=ca_facts).to_dict()
        # Existing cash-reservation cases keep their references and amounts;
        # when the confirmed statutory calendar has the same period, its date
        # also drives the existing overdue/payment path (exclusive end of day).
        kinds = {"gst_bas": "gst_hst", "payg_withholding": "payroll", "income_tax_instalment": "corporate_instalment", "annual_return": "corporate_balance"}
        if ca_facts.get("entity_type") == "sole_proprietor" and ca_facts.get("gst_reporting") == "annual":
            kinds["gst_bas"] = "gst_payment"
        statutory = raw["canada_calendar"]["obligations"]
        from lightbulb.canada_obligations import CanadaCalendarFacts, remitter_assignments
        resolved_ca = CanadaCalendarFacts.model_validate(raw["canada_calendar"]["facts"])
        assignments, conflicts = remitter_assignments(resolved_ca)
        retained = []
        for item in raw["schedule"]:
            period_date = (parsed(item["period_end"]) - timedelta(days=1)).date()
            if item["kind"] == "income_tax_instalment" and facts["instalments"] == "quarterly":
                due_month = parsed(item["period_end"])
                period_date = due_month.date().replace(day=min(resolved_ca.fiscal_year_end_day or 31, monthrange(due_month.year, due_month.month)[1]))
            period = period_date.isoformat()
            matching = [r for r in statutory if r["kind"] == kinds.get(item["kind"]) and r["period_end"] == period and r["due_on"] and r["status"] == "scheduled"]
            if item["kind"] == "payg_withholding":
                if str(period_date.year) in conflicts:
                    continue
                matching = [r for r in matching if r.get("remitter_basis") == facts["withholder"]]
                if (assignments or resolved_ca.remitter_year is not None or resolved_ca.remitters_by_year) and assignments.get(str(period_date.year)) != facts["withholder"]:
                    continue
                if len(matching) != 1:
                    continue  # estimates do not establish a remitter assignment
            if item["kind"] == "gst_bas" and len(matching) != 1:
                continue  # unknown filing facts never open a guessed cash deadline
            if item["kind"] in ("annual_return", "income_tax_instalment") and len(matching) != 1:
                continue  # unknown fiscal/eligibility facts never open a guessed corporate case
            retained.append(item)
            if len(matching) == 1:
                item["due_at"] = iso(_day(matching[0]["due_on"], field_name="due_on") + timedelta(days=1))
            if item["kind"] == "annual_return":
                returns = [r for r in statutory if r["kind"] == "t2" and r["period_end"] == period and r["due_on"] and r["status"] == "scheduled"]
                if len(returns) == 1:
                    item["lodge_due_at"] = iso(_day(returns[0]["due_on"], field_name="due_on") + timedelta(days=1))
        raw["schedule"] = sorted(retained, key=lambda item: (item["due_at"], item["obligation_ref"]))
    elif canada_facts is not None and code != "CA":
        raise ValueError("canada_facts require a Canadian calendar")
    # Historical CA obligations predate this statutory snapshot. Their legacy
    # plan can still rebuild; no 2026 statutory assertion is attached to it.
    return seal(ComplianceCalendarPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# The obligation lifecycle
# --------------------------------------------------------------------------- #


class ObligationReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    source_provenance: ObservationProvenance | None = None
    source_payload: dict[str, Any] | None = None
    payment_source: dict[str, Any] | None = None
    standing_source: dict[str, Any] | None = None
    disbursement_source: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    obligation_ref: OpaqueRef | None = None
    liability_amount: Decimal | None = None
    liability_source: ShortText | None = None
    liability_digest: Sha256Digest | None = None
    observed_at: str | None = None
    lodgement_ref: OpaqueRef | None = None
    lodged_at: str | None = None
    lodged_amount: Decimal | None = None
    lodged_by: OpaqueRef | None = None
    paid_amount: Decimal | None = None
    paid_at: str | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("liability_amount", "lodged_amount", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("observed_at", "lodged_at", "paid_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ObligationLedger(StrictModel):
    entity_scope: EngineScope | None = None
    obligation_ref: str | None = None
    kind: str | None = None
    period_end: str | None = None
    due_at: str | None = None
    deadline_status: Literal["unknown"] | None = None
    estimated_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    reserved_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    liability_source: str | None = None
    reserved_at: str | None = None
    lodgement_ref: str | None = None
    lodged_at: str | None = None
    lodged_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_at: str | None = None
    overdue_since: str | None = None
    days_late: int | None = None
    waive_reason: str | None = None
    outcome: Literal["open", "paid", "waived"] = "open"

    @field_validator("estimated_amount", "reserved_amount", "lodged_amount", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ObligationEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    lodged_with_authority: Literal[False] = False
    payment_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _within(value: Decimal, reference: Decimal, tolerance_percent: Decimal) -> bool:
    if reference <= 0:
        return value == reference
    return (value - reference).copy_abs() <= (reference * tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)


def _lodgement_due(plan: ComplianceCalendarPlan, data: Mapping[str, Any]) -> str:
    """When the obligation's return is due: its own lodgement date when the rule names one, else its due date."""

    row = plan.obligation(str(data.get("obligation_ref")))
    return row.lodge_due_at if row is not None and row.lodge_due_at else str(data["due_at"])


def obligation_deadline(row: ScheduledObligation | None, status: str, ledger: Mapping[str, Any] | Any) -> str:
    """The deadline an obligation still owes: its return's once it is paid, its payment's once it is lodged, and, owing both, whichever falls first.

    A return due before its payment (New Zealand's IR4 in July, terminal tax the next February) makes an
    obligation neither lodged nor paid overdue from the return's date.  Where the return follows the
    payment, as everywhere else, the deadline is the payment's until it is paid.
    """

    raw = ledger if isinstance(ledger, Mapping) else ledger.to_dict()
    due = str(raw.get("due_at") or (row.due_at if row is not None else ""))
    lodge_due = row.lodge_due_at if row is not None and row.lodge_due_at else due
    if status == "paid_awaiting_lodgement":
        return lodge_due
    if raw.get("lodged_at"):
        return due
    return min((due, lodge_due), key=parsed)


def _apply_obligation(plan: ComplianceCalendarPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "schedule":
        require(r.entity_scope is not None and r.entity_scope.currency == plan.currency, "SCOPE_MISMATCH", "the obligation binds its authenticated scope and currency")
        data["entity_scope"] = r.entity_scope.to_dict()
        require(r.obligation_ref is not None, "OBLIGATION_MISSING", "name the scheduled obligation")
        scheduled = plan.obligation(r.obligation_ref)
        require(scheduled is not None, "OBLIGATION_NOT_IN_CALENDAR", f"{r.obligation_ref} is not on this calendar")
        assert scheduled is not None
        require(not scheduled.projected, "OBLIGATION_PROJECTED", f"{r.obligation_ref} is a payday the pay cycle projects; it becomes an obligation when its pay run is approved")
        data.update({"obligation_ref": scheduled.obligation_ref, "kind": scheduled.kind, "period_end": scheduled.period_end, "due_at": scheduled.due_at, "estimated_amount": str(scheduled.estimated_amount)})
        if scheduled.deadline_status is not None:
            data["deadline_status"] = scheduled.deadline_status
    elif event == "reserve":
        require(r.liability_amount is not None and r.liability_source is not None and r.liability_digest is not None and r.observed_at is not None, "LIABILITY_MISSING", "a reservation carries the reported liability, its source, its digest, and the observation time")
        require(parsed(r.observed_at) >= parsed(str(data["period_end"])) - timedelta(days=7), "LIABILITY_READ_TOO_EARLY", "the liability was read before the period was substantially complete", "correct_input")
        require(parsed(r.observed_at) <= parsed(at), "LIABILITY_READ_IN_FUTURE", "the liability read must precede the reservation")
        try:
            if r.source_state is not None and r.source_plan is not None:
                from lightbulb.payroll_run_chain import liability_receipt_for, verify_paid_pay_run
                run = verify_paid_pay_run(r.source_state, source_plan=r.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"], at=at)
                scheduled = plan.obligation(str(data["obligation_ref"]))
                if scheduled is not None and scheduled.pay_date is not None:
                    require(run.ledger.pay_date is not None and parsed(str(run.ledger.pay_date)).date() == parsed(scheduled.pay_date).date(), "LIABILITY_PERIOD_MISMATCH", "a payday obligation is reserved from the pay run paid on that payday")
                else:
                    require(scheduled is not None and parsed(run.ledger.period_start) >= parsed(scheduled.period_start) and parsed(run.ledger.period_end) <= parsed(scheduled.period_end), "LIABILITY_PERIOD_MISMATCH", "the payroll run must fall within this statutory period")
                expected = liability_receipt_for(run, str(data["kind"]), source_plan=r.source_plan)
            else:
                require(r.source_provenance is not None and r.source_payload is not None, "LIABILITY_SOURCE_REQUIRED", "retain the provider report and its complete read provenance")
                expected = liability_receipt(r.source_provenance, r.source_payload, kind=str(data["kind"]))
                declared = r.source_payload
                require(declared.get("currency", declared.get("CurrencyCode", plan.currency)) == plan.currency and declared.get("company_ref", plan.company_ref) == plan.company_ref, "SCOPE_MISMATCH", "declared report company and currency must match the calendar")
            require(all(str(getattr(r, key)) == str(expected[key]) for key in ("liability_amount", "liability_source", "liability_digest", "observed_at")), "LIABILITY_SOURCE_MISMATCH", "the reservation must equal its replayed source")
        except Rejected:
            raise
        except ValueError as exc:
            require(False, getattr(exc, "code", "LIABILITY_SOURCE_INVALID"), str(exc))
        data.update({"reserved_amount": str(r.liability_amount), "liability_source": r.liability_source, "reserved_at": at})
    elif event == "lodge":
        require(r.lodgement_ref is not None and r.lodged_at is not None and r.lodged_amount is not None and r.lodged_by is not None, "LODGEMENT_MISSING", "a lodgement carries the authority reference, the time, the amount, and who lodged it")
        if r.standing_source is not None:
            from lightbulb.obligation_paper import STANDING_LIFECYCLE, annual_return_receipt
            try:
                source = r.standing_source
                standing_plan, standing = STANDING_LIFECYCLE.bind(source["source_plan"], source["state"])
                expected = annual_return_receipt(standing, source_plan=standing_plan)
                require(source == expected["standing_source"], "STANDING_SOURCE_MISMATCH", "retain the exact annual-return projection")
                require(standing_plan.company_ref == plan.company_ref and standing_plan.currency == plan.currency and standing_plan.jurisdiction == plan.jurisdiction and all(getattr(standing.scope, key) == data["entity_scope"][key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "STANDING_SCOPE_MISMATCH", "annual-return evidence must belong to this company, jurisdiction and authenticated scope")
                require(data["kind"] == "annual_return" and expected["standing_source"]["period_end"] == data["period_end"], "STANDING_PERIOD_MISMATCH", "the confirmed annual return must cover this statutory period")
                require(all(str(getattr(r, key)) == str(expected[key]) for key in ("lodgement_ref", "lodged_at", "lodged_amount", "lodged_by")) and parsed(standing.transition_history[-1].command.occurred_at) <= parsed(at), "STANDING_SOURCE_MISMATCH", "filing fields and time must equal the replayed standing evidence")
            except Rejected:
                raise
            except (ValueError, KeyError) as exc:
                require(False, getattr(exc, "code", "STANDING_SOURCE_INVALID"), str(exc))
        reserved = Decimal(str(data.get("reserved_amount", "0")))
        require(_within(r.lodged_amount, reserved, plan.reserve_tolerance_percent), "LODGED_AMOUNT_DRIFT", f"lodged {r.lodged_amount} differs from the reserved liability {reserved} by more than {plan.reserve_tolerance_percent}%", "manual_reconciliation")
        if status == "paid_awaiting_lodgement":
            # the obligation was paid first: the return must lodge what was paid, or the difference is owed or refunded outside it
            require(r.lodged_amount == Decimal(str(data.get("paid_amount", "0"))), "LODGED_NOT_PAID_AMOUNT", f"lodged {r.lodged_amount} but {data.get('paid_amount')} was paid; settle the difference with the authority, then record the lodgement", "manual_reconciliation")
        late = (parsed(r.lodged_at) - parsed(_lodgement_due(plan, data))).days
        data.update({"lodgement_ref": r.lodgement_ref, "lodged_at": r.lodged_at, "lodged_amount": str(r.lodged_amount), "days_late": max(0, late), **({"outcome": "paid"} if status == "paid_awaiting_lodgement" else {})})
    elif event == "pay":
        require(r.paid_amount is not None and r.paid_at is not None and r.payment_evidence_sha256 is not None, "PAYMENT_MISSING", "a payment carries the amount, the time, and the evidence digest")
        lodged = data.get("lodged_at") is not None
        if lodged:
            require(r.paid_amount == Decimal(str(data.get("lodged_amount", "0"))), "PAYMENT_NOT_LODGED_AMOUNT", f"paid {r.paid_amount} differs from the lodged {data.get('lodged_amount')}", "manual_reconciliation")
        else:
            # paid before it is lodged: the payment is the liability the obligation was reserved from
            require(data.get("reserved_at") is not None, "PAYMENT_NOT_RESERVED", "an obligation paid before it is lodged is reserved from its liability read first", "correct_input")
            require(r.paid_amount == Decimal(str(data.get("reserved_amount", "0"))), "PAYMENT_NOT_RESERVED_AMOUNT", f"paid {r.paid_amount} differs from the reserved liability {data.get('reserved_amount')}", "manual_reconciliation")
        require(r.payment_source is not None or r.disbursement_source is not None, "PAYMENT_SOURCE_REQUIRED", "retain the complete bank payment read or settled disbursement")
        try:
            if r.disbursement_source is not None:
                source = r.disbursement_source
                expected = disbursement_payment_receipt(source["state"], source_plan=source["source_plan"], obligation_ref=str(data["obligation_ref"]))
                require(source == expected["disbursement_source"], "PAYMENT_SOURCE_MISMATCH", "retain the exact settled allocation projection")
                require(expected["disbursement_source"]["obligation_entity_ref"] == data["entity_scope"]["entity_ref"], "PAYMENT_CORRELATION_MISMATCH", "the batch must pay this exact statutory entity")
                run_scope = source["state"]["scope"]
                require(source["source_plan"]["company_ref"] == plan.company_ref and all(run_scope[key] == data["entity_scope"][key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "PAYMENT_SCOPE_MISMATCH", "the disbursement must belong to this company and execution scope")
                observed_at = source["state"]["transition_history"][-1]["command"]["occurred_at"]
            else:
                source = r.payment_source
                expected = payment_receipt(source["payload"], provenance=source["provenance"], obligation_ref=str(data["obligation_ref"]), currency=plan.currency)
                require(source == expected["payment_source"], "PAYMENT_SOURCE_MISMATCH", "retain the exact bank payment projection")
                observed_at = source["provenance"]["completed_at"]
            require(all(str(getattr(r, key)) == str(expected[key]) for key in ("paid_amount", "paid_at", "payment_evidence_sha256")), "PAYMENT_SOURCE_MISMATCH", "payment fields must equal the original read")
            # a payment may come before the lodgement, never before the period it pays for began (one made after the
            # lodgement, the rule payments were first recorded under, always stands)
            row = plan.obligation(str(data["obligation_ref"]))
            in_period = row is not None and parsed(r.paid_at) >= parsed(row.period_start)
            after_lodgement = lodged and parsed(r.paid_at) >= parsed(str(data["lodged_at"]))
            require((in_period or after_lodgement) and parsed(observed_at) <= parsed(at), "PAYMENT_TIME_MISMATCH", "a payment is made once the period it pays for has begun, and observed before this transition")
        except Rejected:
            raise
        except (ValueError, KeyError) as exc:
            require(False, getattr(exc, "code", "PAYMENT_SOURCE_INVALID"), str(exc))
        data.update({"paid_amount": str(r.paid_amount), "paid_at": r.paid_at, **({"outcome": "paid"} if lodged else {})})
        if not lodged:
            next_status = "paid_awaiting_lodgement"
    elif event == "mark_overdue":
        # the deadline still owed; for every obligation whose return follows its payment it is the due date, as before
        deadline = obligation_deadline(plan.obligation(str(data.get("obligation_ref"))), status, data)
        require(parsed(at) > parsed(deadline) + timedelta(days=plan.overdue_grace_days), "NOT_YET_OVERDUE", "the obligation is not past its due date and grace")
        data.update({"overdue_since": at, "days_late": (parsed(at) - parsed(deadline)).days})
    elif event == "waive":
        data.update({"waive_reason": str(command.reason)[:300], "outcome": "waived"})
    return next_status, data


class _ComplianceLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope)}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope != self.ledger.entity_scope:
                    raise ValueError("SCOPE_MISMATCH: obligation state must equal its replayed opening scope")
                return self
        self.State = ScopedState


COMPLIANCE_LIFECYCLE = _ComplianceLifecycle(entity="obligation", schema_prefix=COMPLIANCE_KIND, statuses=OBLIGATION_STATUSES, terminal=TERMINAL_OBLIGATION_STATUSES, events=OBLIGATION_EVENTS, table=_OBLIGATION_TABLE, opening_event="schedule", reason_events=("waive",), apply=_apply_obligation, ledger_model=ObligationLedger, receipt_model=ObligationReceipt, effect_boundary_model=ObligationEffectBoundary, plan_model=ComplianceCalendarPlan, max_transitions=MAX_OBLIGATION_TRANSITIONS)
ObligationState = COMPLIANCE_LIFECYCLE.State


def open_obligation(plan: ComplianceCalendarPlan | Mapping[str, Any], scope: Mapping[str, Any], *, obligation_ref: str, opened_at: str, actor_ref: str) -> Any:
    parsed_plan = plan if isinstance(plan, ComplianceCalendarPlan) else ComplianceCalendarPlan.model_validate(detached(plan))
    row = parsed_plan.obligation(obligation_ref)
    _require(row is None or row.deadline_status is None, "OBLIGATION_DEADLINE_UNKNOWN", "confirm the statutory facts before opening an obligation")
    return COMPLIANCE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={"obligation_ref": obligation_ref})


def advance_obligation(plan: ComplianceCalendarPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    parsed_plan, bound = COMPLIANCE_LIFECYCLE.bind(plan, state)
    row = parsed_plan.obligation(str(bound.ledger.obligation_ref))
    raw_command = detached(command)
    event = raw_command.get("event") if isinstance(raw_command, Mapping) else None
    if event == "mark_overdue":
        _require(row is None or row.deadline_status is None, "OBLIGATION_DEADLINE_UNKNOWN", "an unknown deadline cannot establish overdue status")
    return COMPLIANCE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from reads and the operator's filing evidence
# --------------------------------------------------------------------------- #


class ComplianceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ComplianceError(code, message)


def _report_cells(report: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Flatten a Xero Reports API document into (label, value) pairs from its rows."""

    out: list[tuple[str, str]] = []

    def walk(rows: Any) -> None:
        for row in rows or []:
            item = dict(detached(row))
            cells = [dict(detached(cell)) for cell in item.get("Cells") or []]
            if len(cells) >= 2:
                out.append((str(cells[0].get("Value", "")).strip(), str(cells[-1].get("Value", "")).strip()))
            walk(item.get("Rows"))

    reports = report.get("Reports") if isinstance(report.get("Reports"), list) else [report]
    for item in reports or []:
        walk(dict(detached(item)).get("Rows"))
    return out


_LIABILITY_LABELS: dict[str, tuple[str, ...]] = {
    "gst_bas": ("net gst", "gst payable", "total amount payable", "net vat", "vat due", "net tax"),
    "sales_tax": ("sales tax payable", "tax payable", "total tax"),
    "payg_withholding": ("payg withholding", "total withholding", "paye", "tax withheld", "withholding"),
    "superannuation": ("superannuation", "super guarantee", "kiwisaver"),
    "payroll_tax": ("payroll tax", "employer contributions", "employer ni"),
    "income_tax_instalment": ("payg instalment", "income tax instalment", "instalment"),
    "annual_return": ("tax payable", "income tax payable", "total tax"),
}


def liability_receipt(provenance: ObservationProvenance, report: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    """The ``reserve`` receipt from a provider tax or payroll report: the first row whose label names the liability."""

    _require(provenance.source_tool in LIABILITY_TOOLS, "OBSERVATION_TOOL_MISMATCH", f"liabilities come from {LIABILITY_TOOLS}; provenance names {provenance.source_tool}")
    raw = dict(detached(report))
    _require(stable_digest(raw) == provenance.output_digest, "LIABILITY_DIGEST_MISMATCH", "the liability report must match the content committed by its read provenance")
    if provenance.source_tool == "host.payroll_run_summary":
        key = {"payg_withholding": "withholding_total", "superannuation": "super_total", "payroll_tax": "payroll_tax_total"}.get(kind)
        _require(key is not None and raw.get(key) is not None, "LIABILITY_NOT_IN_REPORT", f"the payroll summary carries no {kind} total")
        amount = decimal_value(raw[key], field_name=key)  # type: ignore[index]
    else:
        labels = _LIABILITY_LABELS.get(kind, ())
        match = next(((label, value) for label, value in _report_cells(raw) if any(token in label.lower() for token in labels) and value not in ("", "-")), None)
        _require(match is not None, "LIABILITY_NOT_IN_REPORT", f"no row of the report names the {kind} liability")
        text = str(match[1]).replace(",", "").replace("(", "-").replace(")", "")  # type: ignore[index]
        amount = decimal_value(text, field_name="liability", allow_negative=True)
    _require(amount >= 0, "LIABILITY_IS_REFUND", f"the report shows a refund of {amount.copy_abs()}; a refund is not reserved")
    return {"source_provenance": provenance.to_dict(), "source_payload": raw, "liability_amount": str(amount.quantize(MONEY_QUANTUM)), "liability_source": provenance.source_tool, "liability_digest": provenance.output_digest, "observed_at": provenance.completed_at, "evidence_refs": [f"read:{provenance.observation_ref}"]}


def filing_receipt(*, lodgement_ref: str, lodged_at: str, amount: Any, lodged_by: str, evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    """The ``lodge`` receipt: what the operator holds from the authority's portal; it names itself as operator-supplied evidence."""

    _require(len(lodgement_ref.strip()) >= 4, "LODGEMENT_REF_INVALID", "the lodgement reference is the authority's receipt number")
    return {"lodgement_ref": lodgement_ref.strip(), "lodged_at": timestamp(lodged_at, field_name="lodged_at"), "lodged_amount": str(decimal_value(amount, field_name="amount")), "lodged_by": lodged_by, "evidence_refs": [f"lodgement:{lodgement_ref.strip()}", *evidence_refs], "detail": "operator-supplied filing evidence; the platform holds no filing write"}


def disbursement_payment_receipt(run: Any, *, source_plan: Any, obligation_ref: str) -> dict[str, Any]:
    """Allocate actual settled batch cash to its retained statutory obligation."""
    from lightbulb.disbursement_run import DISBURSEMENT_LIFECYCLE
    plan, state = DISBURSEMENT_LIFECYCLE.bind(source_plan, run)
    _require(state.status in ("settled", "reconciled") and state.ledger.settled_total == state.ledger.batch_total, "PAYMENT_NOT_APPLIED", "only a completely bank-settled batch pays statutory liabilities")
    opening = state.transition_history[0].command.receipt
    sources = [row for row in opening.sources if row["state"].get("schema") == "lightbulb.compliance_obligation_state.v1" and row["state"]["ledger"].get("obligation_ref") == obligation_ref]
    _require(len(sources) == 1, "PAYMENT_CORRELATION_MISMATCH", "the batch must retain exactly one source for this obligation")
    source = sources[0]
    _, obligation = COMPLIANCE_LIFECYCLE.bind(source["plan"], source["state"])
    matches = [row for row in state.ledger.cases if row["kind"] == "compliance_calendar" and row["state_digest"] == obligation.state_digest and row["case_ref"] == obligation.scope.entity_ref]
    _require(len(matches) == 1, "PAYMENT_CORRELATION_MISMATCH", "the settled allocation must match the replayed statutory case")
    _require(Decimal(matches[0]["amount"]) == obligation.ledger.reserved_amount, "PAYMENT_SOURCE_MISMATCH", "the allocated payment must equal the reserved statutory liability")
    proof = {"state": state.to_dict(), "source_plan": plan.to_dict(), "obligation_ref": obligation_ref, "obligation_entity_ref": obligation.scope.entity_ref}
    return {"disbursement_source": proof, "paid_amount": str(obligation.ledger.reserved_amount), "paid_at": state.ledger.settled_at, "payment_evidence_sha256": stable_digest(proof), "evidence_refs": [f"disbursement:{state.state_digest}"]}


def payment_receipt(observation: Mapping[str, Any] | Any, *, provenance: ObservationProvenance | Mapping[str, Any], obligation_ref: str, currency: str) -> dict[str, Any]:
    """An exact statutory outflow from a retained native Xero or Airwallex bank read."""
    from lightbulb.bank_reconciliation import _normalize, _page_rows
    raw = dict(detached(observation))
    read = ObservationProvenance.model_validate(detached(provenance))
    _require(read.source_tool in ("xero.list_bank_transactions", "airwallex.list_transactions"), "OBSERVATION_TOOL_MISMATCH", "statutory payments require a native bank read")
    _require(stable_digest(raw) == read.output_digest, "PAYMENT_DIGEST_MISMATCH", "the payment page must equal the observed output")
    native = _page_rows(read.source_tool, raw)
    rows = [(item, _normalize(read.source_tool, item)) for item in native]
    matches = [(item, row) for item, row in rows if row["reference"] == obligation_ref]
    _require(len(matches) == 1, "PAYMENT_CORRELATION_MISMATCH", "exactly one bank line must name this obligation")
    item, row = matches[0]
    amount = Decimal(row["amount"])
    _require(row["currency"] == currency.upper(), "PAYMENT_CURRENCY_MISMATCH", "the bank payment must use the calendar currency")
    _require(amount < 0 and str(item.get("Status", item.get("status", "AUTHORISED"))).upper() in ("AUTHORISED", "COMPLETED", "SETTLED", "SUCCESS"), "PAYMENT_NOT_APPLIED", "a statutory payment is a completed outflow")
    _require(parsed(row["occurred_at"]) <= parsed(read.completed_at), "PAYMENT_TIME_MISMATCH", "the read must observe the payment after it happened")
    source = {"payload": raw, "provenance": read.to_dict(), "obligation_ref": obligation_ref, "currency": currency.upper()}
    return {"payment_source": source, "paid_amount": str(amount.copy_abs().quantize(MONEY_QUANTUM)), "paid_at": row["occurred_at"], "payment_evidence_sha256": stable_digest(source), "evidence_refs": [f"bank:{row['line_ref']}"]}


# --------------------------------------------------------------------------- #
# Into the treasury forecast and the operator's view
# --------------------------------------------------------------------------- #


def reservations(plan: ComplianceCalendarPlan | Mapping[str, Any], states: Sequence[Any] = (), *, now: str, horizon_days: int = 120, plans: Mapping[str, Any] | None = None, bound: Sequence[tuple[Any, Any]] = ()) -> list[dict[str, Any]]:
    """Treasury ``ScheduledFlow`` rows (kind ``tax_reservation``) for every unpaid obligation due inside the horizon: the lodged or reserved amount once there is one, the freshest estimate until then.

    Each persisted obligation is read under the plan it was opened under: ``plan``
    when it is that one, else ``plans[its plan digest]``; ``bound`` passes
    obligations already bound to their plans.  An obligation already due stays in
    the flows until it is paid or waived.
    """

    parsed_plan = ComplianceCalendarPlan.model_validate(detached(plan))
    stamp = parsed(timestamp(now, field_name="now"))
    out: list[dict[str, Any]] = []
    for item, state, current in _calendar_rows(parsed_plan, _calendar_states(parsed_plan, states, plans=plans, bound=bound)):
        if (current or item).deadline_status == "unknown":
            continue  # retain the liability in the summary without dating a cash flow
        due = parsed(item.due_at)
        if state is None and due < stamp - timedelta(days=parsed_plan.overdue_grace_days):
            continue
        if (due - stamp).days > horizon_days:
            continue
        if state is not None and state.status in ("paid", "waived", "paid_awaiting_lodgement"):
            continue  # paid, if not yet lodged: the money has left
        amount, source = _obligation_amount(item, state, current)
        out.append({"kind": "tax_reservation", "ref": f"tax:{item.obligation_ref}", "due_at": item.due_at, "amount": str(-amount.quantize(MONEY_QUANTUM)), "source": source})
    return out


def _obligation_amount(item: ScheduledObligation, state: Any, current: ScheduledObligation | None) -> tuple[Decimal, str]:
    """What the obligation will cost: the lodged amount, else the reserved one, else today's estimate (the plan it was opened under estimated it when it opened)."""

    if state is not None and state.ledger.lodged_at:
        return Decimal(str(state.ledger.lodged_amount)), str(state.ledger.liability_source or "lodgement")
    if state is not None and state.ledger.reserved_at:
        return Decimal(str(state.ledger.reserved_amount)), str(state.ledger.liability_source or "reservation")
    return (current or item).estimated_amount, "compliance_estimate"


def _calendar_rows(plan: ComplianceCalendarPlan, by_ref: Mapping[str, tuple[Any, Any]]) -> list[tuple[ScheduledObligation, Any, ScheduledObligation | None]]:
    """Every row the calendar knows, due first: today's schedule and every persisted obligation, each as (its own scheduled row, its state, today's row for it)."""

    rows: list[tuple[ScheduledObligation, Any, ScheduledObligation | None]] = []
    for item in plan.schedule:
        pair = by_ref.get(item.obligation_ref)
        if pair is None:
            rows.append((item, None, item))
            continue
        own_plan, state = pair
        rows.append((own_plan.obligation(item.obligation_ref) or item, state, item))
    listed = {item.obligation_ref for item in plan.schedule}
    for ref, (own_plan, state) in by_ref.items():
        if ref in listed:
            continue
        own = own_plan.obligation(ref)
        _require(own is not None, "OBLIGATION_NOT_IN_ITS_PLAN", f"{ref} is not on the plan it was opened under")
        rows.append((own, state, None))
    rows.sort(key=lambda row: (row[0].due_at, row[0].obligation_ref))
    return rows


EXPECTED_OUTFLOW_SCHEMA = "lightbulb.compliance_expected_outflow.v1"


def obligation_expectation(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The cash position chain's hand-off for one reserved or lodged obligation: the reported liability on its due date, bound to the replayed state."""

    plan, bound = COMPLIANCE_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    row = plan.obligation(str(ledger.obligation_ref))
    if row is not None and row.deadline_status == "unknown":
        raise ComplianceError("NO_OUTFLOW_EXPECTED", "confirm the statutory deadline before dating the retained liability")
    if bound.status not in ("reserved", "lodged", "overdue") or ledger.due_at is None:
        raise ComplianceError("NO_OUTFLOW_EXPECTED", f"an obligation that is {bound.status} carries no reserved liability")
    amount = ledger.lodged_amount if ledger.lodged_amount > 0 else ledger.reserved_amount
    if amount <= 0:
        raise ComplianceError("NO_OUTFLOW_EXPECTED", "the obligation has no reserved amount")
    return {"schema": EXPECTED_OUTFLOW_SCHEMA, "kind": "payable", "flow_ref": f"tax:{bound.scope.entity_ref}", "amount": str(amount), "currency": plan.currency, "expected_at": ledger.due_at, "basis": "lodged" if ledger.lodged_amount > 0 else "reserved from the liability read", "source_digest": bound.state_digest}


def obligation_due_on(row: Mapping[str, Any]) -> str:
    """Inclusive civil due date from the engine's exclusive end-of-day marker."""
    marker = row.get("due_at")
    return (parsed(str(marker)) - timedelta(seconds=1)).date().isoformat() if marker else "Unknown"


def calendar_summary(plan: ComplianceCalendarPlan | Mapping[str, Any], states: Sequence[Any] = (), *, now: str, plans: Mapping[str, Any] | None = None, bound: Sequence[tuple[Any, Any]] = ()) -> dict[str, Any]:
    """What is due, reserved, overdue and unfunded: every persisted obligation with its real status, read under the plan it was opened under, and the rest of today's schedule.

    An obligation past its due date that is neither paid nor waived is overdue
    here, whichever plan it came from and whether or not today's plan still lists
    it.  ``plans`` maps plan digests to the plans obligations were opened under;
    ``bound`` passes obligations already bound to theirs.
    """

    parsed_plan = ComplianceCalendarPlan.model_validate(detached(plan))
    stamp = parsed(timestamp(now, field_name="now"))
    rows: list[dict[str, Any]] = []
    overdue = reserved_total = estimated_total = Decimal("0")
    for item, state, current in _calendar_rows(parsed_plan, _calendar_states(parsed_plan, states, plans=plans, bound=bound)):
        status = state.status if state is not None else "unscheduled"
        if status in ("paid", "waived"):
            continue
        amount, _ = _obligation_amount(item, state, current)
        effective = current or item
        if effective.deadline_status == "unknown":
            read = state is not None and bool(state.ledger.reserved_at or state.ledger.lodged_at)
            if status != "paid_awaiting_lodgement":
                if read:
                    reserved_total += amount
                else:
                    estimated_total += amount
            rows.append({"obligation_ref": item.obligation_ref, "kind": item.kind, "due_at": None,
                "status": "needs_confirmation", "deadline_status": "unknown", "historical_due_at": item.due_at,
                "missing_facts": list(effective.deadline_missing_facts or ()), "persisted_status": status,
                "amount": str(amount.quantize(MONEY_QUANTUM)), "basis": "read" if read else "estimate", "overdue": False})
            continue
        if status == "paid_awaiting_lodgement":
            # paid, not yet lodged: nothing is owed or set aside, and it stays open until its return is lodged
            lodge_due = item.lodge_due_at or item.due_at
            lodgement_late = parsed(lodge_due) + timedelta(days=parsed_plan.overdue_grace_days) < stamp
            rows.append({"obligation_ref": item.obligation_ref, "kind": item.kind, "due_at": item.due_at, "status": status, "amount": str(amount.quantize(MONEY_QUANTUM)), "basis": "read", "overdue": False, "lodgement_due_at": lodge_due, "lodgement_overdue": lodgement_late})
            continue
        deadline = obligation_deadline(item, status, state.ledger if state is not None else {})
        late = parsed(deadline) < stamp
        if parsed(item.due_at) < stamp:
            overdue += amount  # money is overdue past its payment date; a return late before it makes the row overdue, not the money
        read = state is not None and bool(state.ledger.reserved_at or state.ledger.lodged_at)
        if read:
            reserved_total += amount
        else:
            estimated_total += amount
        rows.append({"obligation_ref": item.obligation_ref, "kind": item.kind, "due_at": item.due_at, "status": status, "amount": str(amount.quantize(MONEY_QUANTUM)), "basis": "read" if read else "estimate", "overdue": late, **({"lodgement_due_at": deadline} if deadline != item.due_at else {}), **({"projected": True} if item.projected else {})})
    statutory = {}
    if parsed_plan.australia_calendar is not None:
        from lightbulb.australia_obligations import AustraliaObligationsCalendar, due_this_month
        au = AustraliaObligationsCalendar.model_validate(parsed_plan.australia_calendar)
        statutory = {"statutory_obligations": [row.to_dict() for row in au.obligations], "due_this_month": due_this_month(au, company_ref=parsed_plan.company_ref, as_of=now), "missing_calendar_facts": list(au.missing_facts), "statutory_calendar_digest": au.calendar_digest}
    if parsed_plan.canada_calendar is not None:
        from lightbulb.canada_obligations import CanadaObligationsCalendar, due_this_month
        ca = CanadaObligationsCalendar.model_validate(parsed_plan.canada_calendar)
        statutory = {"statutory_obligations": [row.to_dict() for row in ca.obligations], "due_this_month": due_this_month(ca, company_ref=parsed_plan.company_ref, as_of=now), "missing_calendar_facts": list(ca.missing_facts), "statutory_calendar_digest": ca.calendar_digest}
    return {**statutory, "jurisdiction": parsed_plan.jurisdiction, "currency": parsed_plan.currency, "as_of": iso(stamp), **({"pay_cycle": parsed_plan.pay_cycle, "pay_cycle_assumed": bool(parsed_plan.pay_cycle_assumed)} if parsed_plan.pay_cycle else {}), "open": rows, "reserved_from_reads": str(reserved_total.quantize(MONEY_QUANTUM)), "still_estimated": str(estimated_total.quantize(MONEY_QUANTUM)), "overdue": str(overdue.quantize(MONEY_QUANTUM)), "summary_digest": stable_digest(rows)}


def _calendar_states(plan: ComplianceCalendarPlan, states: Sequence[Any], *, plans: Mapping[str, Any] | None = None, bound: Sequence[tuple[Any, Any]] = ()) -> dict[str, tuple[Any, Any]]:
    """Each obligation by its reference with the plan it binds to; an obligation no supplied plan accepts is refused, never dropped."""

    known = {plan.plan_digest: plan, **{digest: (item if isinstance(item, ComplianceCalendarPlan) else ComplianceCalendarPlan.model_validate(detached(item))) for digest, item in dict(plans or {}).items()}}
    pairs: list[tuple[Any, Any]] = []
    for source in states:
        digest = str(getattr(source, "plan_digest", None) or dict(detached(source)).get("plan_digest") or "")
        own = known.get(digest)
        _require(own is not None, "OBLIGATION_PLAN_UNKNOWN", f"an obligation was opened under plan {digest[:16]}, which was not supplied; pass it in plans")
        pairs.append(COMPLIANCE_LIFECYCLE.bind(own, source))
    pairs.extend((own, state) for own, state in bound)
    result: dict[str, tuple[Any, Any]] = {}
    scope = None
    for own, state in pairs:
        current = {key: value for key, value in state.scope.to_dict().items() if key != "entity_ref"}
        _require(scope is None or scope == current, "SCOPE_MISMATCH", "calendar projections cannot mix authenticated execution scopes")
        scope = current
        _require(own.company_ref == plan.company_ref and own.currency == plan.currency, "SCOPE_MISMATCH", "an obligation's plan belongs to another company or currency")
        ref = str(state.ledger.obligation_ref)
        _require(ref not in result, "OBLIGATION_DUPLICATED", "supply each obligation once")
        result[ref] = (own, state)
    return result


COMPLIANCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": COMPLIANCE_KIND,
    "golden_loop": COMPLIANCE_GOLDEN_LOOP,
    "stages": ["schedule", "reserve", "lodge", "pay"],
    "statuses": list(OBLIGATION_STATUSES),
    "events": list(OBLIGATION_EVENTS),
    "jurisdictions": sorted(_RULES),
    "tools": {"liabilities": list(LIABILITY_TOOLS)},
    "required_connectors": ["xero", "quickbooks", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "obligations come from the jurisdiction's rules and the company's payroll and registration facts, never from a typed list",
        "a reservation is the liability a provider report or payroll run reported; estimates only size it until then",
        "a lodgement is operator-supplied evidence and says so; the platform holds no filing write",
        "a payment must equal the lodged amount; the forecast carries every unpaid obligation as a tax reservation",
        "since 1 July 2026 Australian super is an obligation per payday, due 7 business days after it and reserved from that payday's run; a projected payday is forecast and never opened",
    ],
}

__all__ = ["CALENDAR_FACTS", "CALENDAR_SCHEMA", "COMMITTED_PAY_RUN_STATUSES", "calendar_facts", "COMPLIANCE_GOLDEN_LOOP", "COMPLIANCE_KIND", "COMPLIANCE_LIFECYCLE", "COMPLIANCE_MANIFEST", "PAYDAY_SUPER_STARTS", "PAY_CYCLE_DAYS", "committed_pay_runs", "obligation_deadline", "pay_cycle_for_days", "LIABILITY_TOOLS", "OBLIGATION_EVENTS", "OBLIGATION_STATUSES", "ComplianceCalendarPlan", "ComplianceError", "ObligationRule", "ObligationState", "ScheduledObligation", "advance_obligation", "calendar_summary", "compile_compliance_calendar", "disbursement_payment_receipt", "filing_receipt", "liability_receipt", "open_obligation", "payment_receipt", "reservations"]
