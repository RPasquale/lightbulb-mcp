"""The books snapshot: what the accounting system alone says about a company, sealed.

Most small companies have an accounting system and little else connected.
Every other intelligence document reads operational chains (orders, stock,
work orders) that such a company does not have, so until now a company
with only its books connected could be told nothing.  ``build_books_snapshot``
reads the two reports every ledger produces, the profit and loss for a
window and the balance sheet at its end, and seals:

* every account line with its class (revenue, cost of sales, expense,
  asset, liability, equity), the section the ledger put it in, and the role
  the plan maps it to (cash, receivable, payable, tax, inventory);
* the margin ladder (revenue, gross profit, operating profit, net profit),
  the split of cost into variable and fixed, contribution and its margin;
* the balance sheet positions a business is run on: cash, receivables,
  payables, tax owed, stock, cash net of tax, and the days of recorded cost
  the cash covers;
* books-health findings: revenue with no recorded cost, cost implausibly
  low against revenue, no wages or contractor cost, a net loss, negative
  cash, a suspense balance, sections the plan does not classify.

The reports are read as the provider sends them and are trusted about
themselves before they are trusted about the company.  The period comes
from the report's own title, not from the request: Xero answers a
mid-month balance sheet request with the month end, and a snapshot that
believed the request would misdate every balance.  The ladder must foot to
the report's stated gross and net profit, and assets less liabilities must
equal equity, or the snapshot is refused.  A role the plan does not map
stays unknown with the accounts that look like candidates named, never
guessed.  Digit runs that could be account numbers are masked out of
account names.  Nothing here reads a provider or persists anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
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

BOOKS_PLAN_SCHEMA = "lightbulb.books_plan.v1"
BOOKS_SNAPSHOT_SCHEMA = "lightbulb.books_snapshot.v1"
BOOKS_SNAPSHOT_MANIFEST: dict[str, Any] = {"engine": "books_snapshot", "kind": "intelligence_document", "reads": ("profit_and_loss", "balance_sheet"), "writes": ()}

PROFIT_AND_LOSS_TOOLS: tuple[str, ...] = ("xero.profit_loss_report", "host.books_profit_and_loss")
BALANCE_SHEET_TOOLS: tuple[str, ...] = ("xero.balance_sheet_report", "host.books_balance_sheet")
SOURCE_KINDS: tuple[str, ...] = ("profit_and_loss", "balance_sheet")

ACCOUNT_CLASSES: tuple[str, ...] = ("revenue", "other_income", "cost_of_sales", "expense", "other_expense", "asset", "liability", "equity")
AccountClass = Literal["revenue", "other_income", "cost_of_sales", "expense", "other_expense", "asset", "liability", "equity"]
ACCOUNT_ROLES: tuple[str, ...] = ("cash", "receivable", "inventory", "payable", "tax", "payroll_liability", "loan")
SEVERITIES: tuple[str, ...] = ("high", "medium", "low")
Severity = Literal["high", "medium", "low"]

# How a ledger titles its report sections.  A title not listed is left unclassified and reported, never guessed.
SECTION_CLASSES: dict[str, str] = {
    "income": "revenue", "revenue": "revenue", "trading income": "revenue", "sales": "revenue",
    "less cost of sales": "cost_of_sales", "cost of sales": "cost_of_sales", "less cost of goods sold": "cost_of_sales", "cost of goods sold": "cost_of_sales",
    "less operating expenses": "expense", "operating expenses": "expense", "less expenses": "expense", "expenses": "expense",
    "plus other income": "other_income", "other income": "other_income",
    "less other expenses": "other_expense", "other expenses": "other_expense",
    "bank": "asset", "current assets": "asset", "fixed assets": "asset", "non-current assets": "asset", "non current assets": "asset",
    "current liabilities": "liability", "non-current liabilities": "liability", "non current liabilities": "liability",
    "equity": "equity",
}
_GROUP_HEADINGS: frozenset[str] = frozenset({"assets", "liabilities"})
# Names that usually carry a role.  They only ever become suggestions for the plan; the snapshot never applies them.
_ROLE_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "receivable": ("accounts receivable", "trade debtors", "debtors", "trade receivables"),
    "payable": ("accounts payable", "trade creditors", "creditors", "trade payables"),
    "tax": ("gst", "vat", "hst", "gst/hst", "sales tax", "sales tax payable", "gst payable", "vat payable", "bas payable", "income tax payable", "tax payable"),
    "inventory": ("inventory", "stock on hand", "stock", "inventory asset"),
    "payroll_liability": ("payg withholdings payable", "superannuation payable", "wages payable", "payroll liabilities", "payroll tax payable"),
    "loan": ("loan", "bank loan", "director loan", "shareholder loan", "loans from directors"),
}
_LABOUR_WORDS: tuple[str, ...] = ("wage", "salar", "payroll", "superannuation", "contractor", "subcontract", "consult", "labour", "labor", "director fee", "drawings")
_SUSPENSE_WORDS: tuple[str, ...] = ("suspense", "unallocated", "uncategori", "ask my accountant", "unknown")
_MONTHS = {name: index for index, name in enumerate(("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"), start=1)}
_PERCENT = Decimal("0.01")
_DAYS = Decimal("0.1")
_PERIOD_TITLE = re.compile(r"^\s*(\d{1,2}) ([A-Za-z]+) (\d{4}) to (\d{1,2}) ([A-Za-z]+) (\d{4})\s*$")
_AS_AT_TITLE = re.compile(r"^\s*As at (\d{1,2}) ([A-Za-z]+) (\d{4})\s*$", re.IGNORECASE)
_LONG_DIGITS = re.compile(r"\d{9,}")


class BooksSnapshotError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BooksSnapshotError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _percent(part: Decimal, whole: Decimal) -> Decimal | None:
    return None if whole == 0 else (part / whole * 100).quantize(_PERCENT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _fold(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())


def _safe_name(value: Any) -> str:
    """An account name with any long digit run reduced to its last four, so an account number never enters a sealed document."""

    return _LONG_DIGITS.sub(lambda found: "x" * 4 + found.group()[-4:], " ".join(str(value or "").split()))[:300]


class BooksPlan(StrictModel):
    """How this company's books are read: which accounts play which role, which costs move with sales, and how far a report may be off its own totals."""

    schema_id: str = Field(default=BOOKS_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    account_roles: dict[str, tuple[ShortText, ...]] = Field(default_factory=dict)
    variable_accounts: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)
    section_classes: dict[str, str] = Field(default_factory=dict)
    tolerance: Decimal = Field(default=Decimal("0.05"), validate_default=True)
    minimum_cost_share_percent: Decimal = Field(default=Decimal("5.00"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("variable_accounts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("account_roles", mode="before")
    @classmethod
    def _roles(cls, value: object) -> object:
        return {str(role): tuple(accounts) for role, accounts in dict(value or {}).items()} if isinstance(value, Mapping) else value

    @field_validator("tolerance", "minimum_cost_share_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksPlan":
        unknown = sorted(set(self.account_roles) - set(ACCOUNT_ROLES))
        if unknown:
            raise ValueError(f"ROLE_UNKNOWN: {unknown} are not among {ACCOUNT_ROLES}")
        bad = sorted(name for name in self.section_classes.values() if name not in ACCOUNT_CLASSES)
        if bad:
            raise ValueError(f"CLASS_UNKNOWN: {bad} are not among {ACCOUNT_CLASSES}")
        if not skip_digests(info) and self.plan_digest != sealed_digest(BooksPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_books_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> BooksPlan:
    return seal(BooksPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class BooksLine(StrictModel):
    account_ref: OpaqueRef
    name: ShortText
    account_class: AccountClass
    section: ShortText
    role: ShortText | None = None
    variable: bool = False
    amount: Decimal
    comparative: Decimal | None = None

    @field_validator("amount", "comparative", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class BooksFinding(StrictModel):
    code: ShortText
    severity: Severity
    detail: ShortText
    amount: Decimal | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


_MONEY_FIELDS = ("revenue", "other_income", "cost_of_sales", "gross_profit", "operating_expenses", "other_expenses", "net_profit", "variable_costs", "fixed_costs", "contribution", "cash", "receivables", "inventory", "payables", "tax_owed", "cash_net_of_tax", "total_assets", "total_liabilities", "net_assets")


class BooksSnapshot(StrictModel):
    schema_id: str = Field(default=BOOKS_SNAPSHOT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    ledger: ShortText
    window_start: str
    window_end: str
    as_of: str
    period_label: ShortText
    balances_as_at: str | None = None
    plan_digest: Sha256Digest
    lines: tuple[BooksLine, ...] = Field(max_length=4000)
    revenue: Decimal
    other_income: Decimal
    cost_of_sales: Decimal
    gross_profit: Decimal
    operating_expenses: Decimal
    other_expenses: Decimal
    net_profit: Decimal
    variable_costs: Decimal
    fixed_costs: Decimal
    contribution: Decimal
    gross_margin_percent: Decimal | None = None
    contribution_margin_percent: Decimal | None = None
    net_margin_percent: Decimal | None = None
    cash: Decimal | None = None
    receivables: Decimal | None = None
    inventory: Decimal | None = None
    payables: Decimal | None = None
    tax_owed: Decimal | None = None
    cash_net_of_tax: Decimal | None = None
    total_assets: Decimal | None = None
    total_liabilities: Decimal | None = None
    net_assets: Decimal | None = None
    days_in_window: int = Field(ge=1, le=3700)
    cost_per_day: Decimal
    cash_cover_days: Decimal | None = None
    findings: tuple[BooksFinding, ...] = Field(default_factory=tuple, max_length=40)
    unclassified_sections: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    role_candidates: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=8)
    snapshot_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "findings", "unclassified_sections", "role_candidates", "notes", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator(*_MONEY_FIELDS, "gross_margin_percent", "contribution_margin_percent", "net_margin_percent", "cost_per_day", "cash_cover_days", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("window_start", "window_end", "as_of", "balances_as_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksSnapshot":
        def total(*classes: str) -> Decimal:
            return _money(sum((line.amount for line in self.lines if line.account_class in classes), Decimal("0")))

        if parsed(self.window_end) <= parsed(self.window_start):
            raise ValueError("WINDOW_EMPTY: window_end must follow window_start")
        if (self.revenue, self.cost_of_sales, self.operating_expenses) != (total("revenue"), total("cost_of_sales"), total("expense")):
            raise ValueError("the ladder counts the lines: revenue, cost of sales and operating expenses are the sums of their classes")
        if self.gross_profit != _money(self.revenue - self.cost_of_sales) or self.net_profit != _money(self.gross_profit + self.other_income - self.operating_expenses - self.other_expenses):
            raise ValueError("gross profit is revenue less cost of sales, and net profit is gross profit plus other income less expenses")
        if self.variable_costs + self.fixed_costs != _money(self.cost_of_sales + self.operating_expenses + self.other_expenses) or self.contribution != _money(self.revenue - self.variable_costs):
            raise ValueError("variable and fixed cost split every recorded cost, and contribution is revenue less variable cost")
        if self.cash is not None and self.cash != _money(sum((line.amount for line in self.lines if line.role == "cash"), Decimal("0"))):
            raise ValueError("cash counts the lines in the cash role")
        if not skip_digests(info) and self.snapshot_digest != sealed_digest(BooksSnapshot, self, "snapshot_digest"):
            raise ValueError("snapshot_digest must commit the exact snapshot")
        return self

    def finding(self, code: str) -> BooksFinding | None:
        return next((item for item in self.findings if item.code == code), None)

    def render(self) -> str:
        head = f"**Books {self.period_label}** ({self.company_ref}, as of {self.as_of[:10]}): {self.verdict}"
        ladder = [f"- revenue {self.revenue} {self.currency}", f"- gross profit {self.gross_profit} ({'n/a' if self.gross_margin_percent is None else str(self.gross_margin_percent) + '%'})", f"- net profit {self.net_profit} ({'n/a' if self.net_margin_percent is None else str(self.net_margin_percent) + '%'})"]
        if self.cash is not None:
            ladder.append(f"- cash {self.cash}" + ("" if self.tax_owed is None else f", {self.tax_owed} owed in tax, {self.cash_net_of_tax} net of it"))
        return "\n".join([head, *ladder, *[f"- [{item.severity}] {item.detail}" for item in self.findings]])


# --------------------------------------------------------------------------- #
# Reading the reports
# --------------------------------------------------------------------------- #


def _amount(value: Any, *, where: str) -> Decimal | None:
    text = str(value if value is not None else "").strip().replace(",", "")
    if not text:
        return None
    negative = text.startswith("(") and text.endswith(")")
    try:
        number = Decimal(text.strip("()"))
    except InvalidOperation as exc:
        raise BooksSnapshotError("REPORT_VALUE_UNREADABLE", f"{where} carries {text[:30]!r}, not an amount") from exc
    return _money(-number if negative else number)


def _title_date(day: str, month: str, year: str, *, where: str) -> date:
    number = _MONTHS.get(month.casefold())
    _require(number is not None, "REPORT_PERIOD_UNREADABLE", f"{where} names the month {month!r}")
    try:
        return date(int(year), int(number or 0), int(day))
    except ValueError as exc:
        raise BooksSnapshotError("REPORT_PERIOD_UNREADABLE", f"{where} is not a calendar date") from exc


def _report(payload: Any, *, report_type: str) -> dict[str, Any]:
    raw = detached(payload)
    reports = raw.get("Reports") if isinstance(raw, Mapping) else None
    _require(isinstance(reports, list) and len(reports) == 1 and isinstance(reports[0], Mapping), "REPORT_SHAPE_UNKNOWN", f"the {report_type} read must carry exactly one report")
    report = dict(reports[0])
    _require(str(report.get("ReportType") or report.get("ReportID") or "") == report_type, "REPORT_WRONG_TYPE", f"expected a {report_type} report, the read carries {report.get('ReportType') or report.get('ReportID')}")
    _require(isinstance(report.get("Rows"), list) and bool(report["Rows"]), "REPORT_SHAPE_UNKNOWN", f"the {report_type} report carries no rows")
    return report


def report_period(payload: Any) -> tuple[str, str, str]:
    """The window a profit and loss report states for itself, as (window_start, window_end, label); the end is exclusive."""

    report = _report(payload, report_type="ProfitAndLoss")
    titles = [str(item) for item in report.get("ReportTitles") or []]
    found = next((matched for matched in (_PERIOD_TITLE.match(title) for title in titles) if matched), None)
    _require(found is not None, "REPORT_PERIOD_UNREADABLE", f"no report title states a period like '1 July 2026 to 30 September 2026': {titles}")
    assert found is not None
    start = _title_date(found[1], found[2], found[3], where="the period start")
    end = _title_date(found[4], found[5], found[6], where="the period end")
    _require(end >= start, "REPORT_PERIOD_UNREADABLE", "the report's period ends before it starts")
    return f"{start.isoformat()}T00:00:00Z", f"{(end + timedelta(days=1)).isoformat()}T00:00:00Z", found[0].strip()


def report_as_at(payload: Any) -> str:
    """The date a balance sheet report states its balances are as at."""

    report = _report(payload, report_type="BalanceSheet")
    titles = [str(item) for item in report.get("ReportTitles") or []]
    found = next((matched for matched in (_AS_AT_TITLE.match(title) for title in titles) if matched), None)
    _require(found is not None, "REPORT_PERIOD_UNREADABLE", f"no report title states 'As at <date>': {titles}")
    assert found is not None
    return f"{_title_date(found[1], found[2], found[3], where='the as-at date').isoformat()}T00:00:00Z"


def _account_ref(cell: Mapping[str, Any], name: str) -> str | None:
    for attribute in cell.get("Attributes") or []:
        if isinstance(attribute, Mapping) and attribute.get("Id") == "account" and attribute.get("Value"):
            return str(attribute["Value"])
    return None


def _rows(report: Mapping[str, Any], plan: BooksPlan) -> tuple[list[dict[str, Any]], dict[str, Decimal], list[str]]:
    """Account rows with their section class, the report's own stated totals by label, and the titled sections nothing classifies."""

    overrides = {_fold(title): name for title, name in plan.section_classes.items()}
    lines: list[dict[str, Any]] = []
    stated: dict[str, Decimal] = {}
    unclassified: list[str] = []
    for section in report["Rows"]:
        if not isinstance(section, Mapping) or section.get("RowType") != "Section":
            continue
        title = " ".join(str(section.get("Title") or "").split())
        folded = _fold(title)
        account_class = overrides.get(folded) or SECTION_CLASSES.get(folded)
        for row in section.get("Rows") or []:
            cells = [dict(cell) for cell in (row.get("Cells") or []) if isinstance(cell, Mapping)] if isinstance(row, Mapping) else []
            if len(cells) < 2:
                continue
            label = str(cells[0].get("Value") or "")
            where = f"{title or 'the report'} / {label}"
            amount = _amount(cells[1].get("Value"), where=where)
            if amount is None:
                continue
            account = _account_ref(cells[0], label)
            if row.get("RowType") != "Row" or account is None:
                stated[_fold(label)] = amount
                continue
            if account_class is None:
                if folded not in _GROUP_HEADINGS and title not in unclassified:
                    unclassified.append(title or "(untitled section)")
                continue
            lines.append({"account_ref": account, "name": _safe_name(label), "account_class": account_class, "section": title[:300] or "(untitled)", "amount": amount, "comparative": _amount(cells[2].get("Value"), where=where) if len(cells) > 2 else None})
    return lines, stated, unclassified


def _source(source: Mapping[str, Any], *, tools: tuple[str, ...], as_of: str) -> tuple[Any, str]:
    from lightbulb.company_execution_bridge import ObservationProvenance

    _require(source.get("provenance") is not None and source.get("payload") is not None, "SOURCE_NOT_SEALED", "a books source carries its provenance and the exact payload the read returned")
    read = ObservationProvenance.model_validate(detached(source["provenance"]))
    _require(read.provenance_digest != GENESIS_DIGEST and read.source_tool in tools, "SOURCE_TOOL_MISMATCH", f"this report is read with one of {list(tools)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(source["payload"])), "SOURCE_DIGEST_MISMATCH", "the report must be the exact output the read returned")
    _require(parsed(read.completed_at) <= parsed(as_of), "SOURCE_FROM_FUTURE", "the read must complete before the snapshot is taken")
    return source["payload"], read.provenance_digest


def suggest_account_roles(lines: Sequence[BooksLine | Mapping[str, Any]], plan: BooksPlan | Mapping[str, Any] | None = None) -> list[dict[str, str]]:
    """Accounts whose names usually carry a role the plan has not mapped.  Suggestions only: the owner confirms them into ``account_roles``."""

    mapped = set((plan if isinstance(plan, BooksPlan) else BooksPlan.model_validate(detached(plan))).account_roles) if plan is not None else set()
    out: list[dict[str, str]] = []
    for item in lines:
        line = item if isinstance(item, BooksLine) else BooksLine.model_validate(detached(item))
        if line.account_class not in ("asset", "liability") or line.role is not None:
            continue
        for role, names in _ROLE_NAME_HINTS.items():
            if role not in mapped and _fold(line.name) in names:
                out.append({"role": role, "account_ref": line.account_ref, "name": line.name, "basis": "account name"})
    return out


def build_books_snapshot(plan: BooksPlan | Mapping[str, Any], *, sources: Sequence[Mapping[str, Any]], window_start: str, window_end: str, as_of: str) -> BooksSnapshot:
    """The sealed snapshot from one profit and loss read and, when supplied, one balance sheet read."""

    parsed_plan = plan if isinstance(plan, BooksPlan) else BooksPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    by_kind: dict[str, Mapping[str, Any]] = {}
    for source in sources:
        kind = str(dict(detached(source)).get("kind", ""))
        _require(kind in SOURCE_KINDS, "SOURCE_KIND_UNKNOWN", f"{kind or 'untyped'} is not one of {SOURCE_KINDS}")
        _require(kind not in by_kind, "SOURCE_DUPLICATE", f"one {kind} read per snapshot")
        by_kind[kind] = source
    _require("profit_and_loss" in by_kind, "SOURCES_MISSING", "the snapshot needs the profit and loss read; the balance sheet is optional")

    digests: list[str] = []
    notes: list[str] = []
    payload, digest = _source(by_kind["profit_and_loss"], tools=PROFIT_AND_LOSS_TOOLS, as_of=at)
    digests.append(digest)
    stated_start, stated_end, label = report_period(payload)
    _require((stated_start, stated_end) == (start, end), "REPORT_WINDOW_MISMATCH", f"the report states {label}, which is {stated_start[:10]} to {stated_end[:10]} exclusive, not the requested {start[:10]} to {end[:10]}")
    lines, stated, unclassified = _rows(_report(payload, report_type="ProfitAndLoss"), parsed_plan)
    _require(all(line["account_class"] not in ("asset", "liability", "equity") for line in lines), "REPORT_WRONG_TYPE", "a profit and loss section is classified as a balance sheet class")

    balances_as_at: str | None = None
    balance_stated: dict[str, Decimal] = {}
    if "balance_sheet" in by_kind:
        sheet, digest = _source(by_kind["balance_sheet"], tools=BALANCE_SHEET_TOOLS, as_of=at)
        digests.append(digest)
        balances_as_at = report_as_at(sheet)
        last_day = parsed(end) - timedelta(days=1)
        month_end = (last_day.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        _require(last_day <= parsed(balances_as_at) <= month_end, "REPORT_WINDOW_MISMATCH", f"the balance sheet is as at {balances_as_at[:10]}; the window's last day is {last_day.date().isoformat()} and a ledger may move that only to its month end")
        sheet_lines, balance_stated, sheet_unclassified = _rows(_report(sheet, report_type="BalanceSheet"), parsed_plan)
        _require(all(line["account_class"] in ("asset", "liability", "equity") for line in sheet_lines), "REPORT_WRONG_TYPE", "a balance sheet section is classified as a profit and loss class")
        lines.extend(sheet_lines)
        unclassified.extend(item for item in sheet_unclassified if item not in unclassified)
    else:
        notes.append("no balance sheet was read: cash, receivables, payables and tax owed are unknown")

    role_of: dict[str, str] = {}
    for role, accounts in parsed_plan.account_roles.items():
        for account in accounts:
            role_of[_fold(account)] = role
    variable = {_fold(item) for item in parsed_plan.variable_accounts}
    sealed_lines: list[BooksLine] = []
    seen: set[tuple[str, str]] = set()
    for raw in lines:
        key = (raw["account_class"], raw["account_ref"])
        _require(key not in seen, "ACCOUNT_DUPLICATE", f"{raw['name']} appears twice in the {raw['account_class']} rows")
        seen.add(key)
        role = role_of.get(_fold(raw["account_ref"])) or role_of.get(_fold(raw["name"]))
        if role is None and raw["account_class"] == "asset" and _fold(raw["section"]) == "bank":
            role = "cash"
        is_cost = raw["account_class"] in ("cost_of_sales", "expense", "other_expense")
        sealed_lines.append(BooksLine.model_validate({**raw, "role": role, "variable": is_cost and (raw["account_class"] == "cost_of_sales" or _fold(raw["account_ref"]) in variable or _fold(raw["name"]) in variable)}))

    def total(*classes: str) -> Decimal:
        return _money(sum((line.amount for line in sealed_lines if line.account_class in classes), Decimal("0")))

    def role_total(role: str) -> Decimal | None:
        if balances_as_at is None:
            return None
        matched = [line.amount for line in sealed_lines if line.role == role]
        if matched or role in parsed_plan.account_roles or role == "cash":
            return _money(sum(matched, Decimal("0")))
        return None

    revenue, other_income, cost_of_sales, expenses, other_expenses = total("revenue"), total("other_income"), total("cost_of_sales"), total("expense"), total("other_expense")
    gross, costs = _money(revenue - cost_of_sales), _money(cost_of_sales + expenses + other_expenses)
    net = _money(gross + other_income - expenses - other_expenses)
    tolerance = parsed_plan.tolerance
    if not unclassified:
        for stated_label, computed in (("gross profit", gross), ("net profit", net)):
            if stated_label in stated:
                _require(abs(stated[stated_label] - computed) <= tolerance, "PNL_DOES_NOT_FOOT", f"the report states {stated_label} {stated[stated_label]}, its account rows give {computed}")
    variable_costs = _money(sum((line.amount for line in sealed_lines if line.variable), Decimal("0")))
    days = max(1, (parsed(end) - parsed(start)).days)
    cost_per_day = _money(costs / days)

    assets = liabilities = net_assets = None
    if balances_as_at is not None:
        assets, liabilities = total("asset"), total("liability")
        net_assets = _money(assets - liabilities)
        if not unclassified:
            equity = total("equity")
            _require(abs(net_assets - equity) <= tolerance, "BALANCE_SHEET_UNBALANCED", f"assets less liabilities are {net_assets}, equity is {equity}")
            for stated_label, computed in (("total assets", assets), ("total liabilities", liabilities), ("net assets", net_assets)):
                if stated_label in balance_stated:
                    _require(abs(balance_stated[stated_label] - computed) <= tolerance, "BALANCE_SHEET_UNBALANCED", f"the report states {stated_label} {balance_stated[stated_label]}, its account rows give {computed}")
        if parsed(balances_as_at) > parsed(end) - timedelta(days=1):
            notes.append(f"the ledger reported balances as at {balances_as_at[:10]}, its month end, not the window's last day; entries dated after {(parsed(end) - timedelta(days=1)).date().isoformat()} are included")
    cash, tax = role_total("cash"), role_total("tax")
    cash_net = None if cash is None else _money(cash - (tax or Decimal("0")))
    if parsed(at) < parsed(end):
        notes.append(f"the window runs to {end[:10]} and the snapshot was taken {at[:10]}: the period is still open")

    share = _percent(costs, revenue)
    thin_costs = costs == 0 or (revenue > 0 and share is not None and share < parsed_plan.minimum_cost_share_percent)
    if cash_net is not None and thin_costs:
        notes.append("the days of cost the cash covers are not measured: the recorded costs are too thin for the figure to mean anything")

    candidates = suggest_account_roles(sealed_lines, parsed_plan)
    for role in ("receivable", "payable", "tax"):
        if balances_as_at is not None and role_total(role) is None:
            named = [item["name"] for item in candidates if item["role"] == role]
            notes.append(f"{role} is unknown: no account is mapped to it in account_roles" + (f"; by name, {', '.join(named[:3])} looks like it" if named else ""))

    findings: list[dict[str, Any]] = []
    labour = [line for line in sealed_lines if line.account_class in ("cost_of_sales", "expense", "other_expense") and any(word in _fold(line.name) for word in _LABOUR_WORDS)]
    if net < 0:
        findings.append({"code": "NET_LOSS", "severity": "high", "detail": f"the period lost {abs(net)} {parsed_plan.currency} on revenue of {revenue}", "amount": net})
    if cash is not None and any(line.role == "cash" and line.amount < 0 for line in sealed_lines):
        overdrawn = _money(sum((line.amount for line in sealed_lines if line.role == "cash" and line.amount < 0), Decimal("0")))
        findings.append({"code": "NEGATIVE_CASH", "severity": "high", "detail": f"a bank account is overdrawn by {abs(overdrawn)} {parsed_plan.currency}", "amount": overdrawn})
    if revenue > 0 and costs == 0:
        findings.append({"code": "NO_COSTS_RECORDED", "severity": "high", "detail": f"revenue of {revenue} {parsed_plan.currency} is recorded against no cost at all: every margin reads 100% until expenses are entered", "amount": revenue})
    elif revenue > 0 and share is not None and share < parsed_plan.minimum_cost_share_percent:
        findings.append({"code": "COSTS_IMPLAUSIBLY_LOW", "severity": "medium", "detail": f"recorded costs are {share}% of revenue ({costs} of {revenue} {parsed_plan.currency}); check that wages, software, rent and insurance are in the books", "amount": costs})
    if revenue > 0 and not labour:
        findings.append({"code": "NO_LABOUR_COST_RECORDED", "severity": "medium", "detail": "no account named for wages, salaries, super, contractors or drawings carries a balance: the owner's and the team's labour is not costed, so profit is overstated by whatever that labour is worth"})
    if tax is not None and tax > 0 and cash is not None:
        findings.append({"code": "TAX_OWED", "severity": "medium" if tax > cash else "low", "detail": f"{tax} {parsed_plan.currency} is owed in tax; cash net of it is {cash_net}", "amount": tax})
    for line in sealed_lines:
        if line.amount != 0 and any(word in _fold(line.name) for word in _SUSPENSE_WORDS):
            findings.append({"code": "SUSPENSE_BALANCE", "severity": "medium", "detail": f"{line.name} carries {line.amount} {parsed_plan.currency}: entries nobody has classified", "amount": line.amount})
    if unclassified:
        findings.append({"code": "SECTION_UNCLASSIFIED", "severity": "high", "detail": f"the report sections {', '.join(unclassified[:6])} are not classified, so their accounts are left out and the totals were not footed; map them in section_classes"})
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (rank[item["severity"]], item["code"]))

    margin = _percent(net, revenue)
    verdict = f"revenue {revenue} {parsed_plan.currency}, net profit {net}" + ("" if margin is None else f" ({margin}%)") + ("" if cash is None else f"; cash {cash}" + ("" if not tax else f", {tax} owed in tax")) + (f"; {len(findings)} finding(s), first: {findings[0]['detail']}" if findings else "; the books raise no finding")
    recommendations = [item["detail"] for item in findings][:24] or ["the books foot and raise no finding"]
    payload_out = {
        "company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "ledger": str(dict(detached(by_kind["profit_and_loss"]["provenance"])).get("source_tool", "")).split(".")[0] or "host",
        "window_start": start, "window_end": end, "as_of": at, "period_label": label[:300], "balances_as_at": balances_as_at, "plan_digest": parsed_plan.plan_digest,
        "lines": [line.to_dict() for line in sealed_lines], "revenue": str(revenue), "other_income": str(other_income), "cost_of_sales": str(cost_of_sales), "gross_profit": str(gross),
        "operating_expenses": str(expenses), "other_expenses": str(other_expenses), "net_profit": str(net), "variable_costs": str(variable_costs), "fixed_costs": str(_money(costs - variable_costs)),
        "contribution": str(_money(revenue - variable_costs)), "gross_margin_percent": _percent(gross, revenue), "contribution_margin_percent": _percent(revenue - variable_costs, revenue), "net_margin_percent": margin,
        "cash": cash, "receivables": role_total("receivable"), "inventory": role_total("inventory"), "payables": role_total("payable"), "tax_owed": tax, "cash_net_of_tax": cash_net,
        "total_assets": assets, "total_liabilities": liabilities, "net_assets": net_assets, "days_in_window": days, "cost_per_day": str(cost_per_day),
        "cash_cover_days": None if cash_net is None or thin_costs or cost_per_day == 0 else (cash_net / cost_per_day).quantize(_DAYS, rounding=ROUND_HALF_UP),
        "findings": findings, "unclassified_sections": [item[:300] for item in unclassified], "role_candidates": [f"{item['role']}: {item['name']}"[:300] for item in candidates][:40],
        "notes": [item[:300] for item in notes][:24], "verdict": verdict[:300], "recommendations": [item[:300] for item in recommendations], "source_digests": digests,
    }
    return seal(BooksSnapshot, {key: (str(value) if isinstance(value, Decimal) else value) for key, value in payload_out.items() if value is not None}, "snapshot_digest")


def verify_books_snapshot(value: Any) -> BooksSnapshot:
    return value if isinstance(value, BooksSnapshot) else BooksSnapshot.model_validate(dict(detached(value)))


__all__ = [
    "ACCOUNT_CLASSES", "ACCOUNT_ROLES", "BALANCE_SHEET_TOOLS", "BOOKS_PLAN_SCHEMA", "BOOKS_SNAPSHOT_MANIFEST", "BOOKS_SNAPSHOT_SCHEMA", "PROFIT_AND_LOSS_TOOLS", "SECTION_CLASSES",
    "BooksFinding", "BooksLine", "BooksPlan", "BooksSnapshot", "BooksSnapshotError", "build_books_snapshot", "compile_books_plan", "report_as_at", "report_period", "suggest_account_roles", "verify_books_snapshot",
]
