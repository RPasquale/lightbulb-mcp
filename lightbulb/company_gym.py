"""The company gym: synthetic companies an agent runs for simulated months through the real console, mandate and operating loop, and a score for how it did.

"Is the SDK good enough for an agent to run a company?" was an opinion.
The gym makes it a number.  A ``GymScenario`` fixes a small business in
arithmetic: monthly sales and their drift, cost of sales, wages and rent,
customers and how many of them pay late, starting cash, the tax on sales,
and how the business responds to what an operator does (a price change
through an elasticity, marketing through a return per dollar next month,
a chase through the share of overdue money it recovers, a hire through the
capacity it adds and the wage it costs).  Every month the gym renders the
company's profit and loss, month-end balance sheet and sales invoice page
in the exact shapes the ledger returns them, records them through the
console the way a real month is recorded, and asks the operator what to
do, handing it the same ``next`` step a live agent gets.

The operator answers with actions.  The gym passes each through the
owner's mandate exactly as the console would: an action the mandate lets
the agent take alone is applied and logged; one it does not is refused,
counted as a violation, and applied only when the scenario says the owner
approved it.  After the last month the gym seals a report: revenue growth,
cash and its lowest point, overdue money at the end, the actions taken by
kind, the violations, and a verdict.  Everything is deterministic: the same
scenario and operator give the same report digest, so an operator can be
compared against another, or against ``do_nothing``, on exactly the same
company.  Nothing here reads a provider or spends anything real.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp

GYM_SCENARIO_SCHEMA = "lightbulb.gym_scenario.v1"
GYM_REPORT_SCHEMA = "lightbulb.gym_report.v1"
GYM_MANIFEST: dict[str, Any] = {"engine": "company_gym", "kind": "evaluation", "reads": (), "writes": ()}
ActionKind = Literal["chase_overdue", "change_price", "spend_marketing", "hire", "open_change", "none"]
ACTION_TO_MANDATE: dict[str, str] = {"chase_overdue": "chase_overdue", "change_price": "change_price", "spend_marketing": "spend_marketing", "hire": "open_requisition", "open_change": "open_change"}
_CENT = Decimal("0.01")
_MONTH_NAMES = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")
ACCOUNT = {"sales": "5b1e7a90-0000-4000-8000-00000000c001", "materials": "5b1e7a90-0000-4000-8000-00000000c002", "wages": "5b1e7a90-0000-4000-8000-00000000c003", "rent": "5b1e7a90-0000-4000-8000-00000000c004", "marketing": "5b1e7a90-0000-4000-8000-00000000c005", "bank": "5b1e7a90-0000-4000-8000-00000000c010", "receivable": "5b1e7a90-0000-4000-8000-00000000c011", "gst": "5b1e7a90-0000-4000-8000-00000000c020", "cye": "5b1e7a90-0000-4000-8000-00000000c030", "retained": "5b1e7a90-0000-4000-8000-00000000c031"}


class GymError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GymError(code, message)


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENT, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class GymScenario(StrictModel):
    schema_id: str = Field(default=GYM_SCENARIO_SCHEMA, alias="schema")
    name: ShortText
    company_ref: OpaqueRef
    company_name: ShortText
    currency: CurrencyCode
    start_month: str = Field(pattern=r"^\d{4}-\d{2}$")
    months: int = Field(ge=1, le=24)
    sales_per_month: Decimal
    sales_drift_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    cost_of_sales_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    wages_per_month: Decimal = Field(default=Decimal("0"), validate_default=True)
    rent_per_month: Decimal = Field(default=Decimal("0"), validate_default=True)
    customers: int = Field(default=4, ge=1, le=40)
    late_payer_share_percent: Decimal = Field(default=Decimal("20"), validate_default=True)
    terms_days: int = Field(default=30, ge=0, le=120)
    starting_cash: Decimal
    tax_rate_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    tax_paid_every_months: int = Field(default=3, ge=1, le=12)
    price_elasticity: Decimal = Field(default=Decimal("-1.2"), validate_default=True)
    marketing_return: Decimal = Field(default=Decimal("3"), validate_default=True)
    chase_recovery_percent: Decimal = Field(default=Decimal("60"), validate_default=True)
    capacity_per_month: Decimal | None = None
    hire_capacity: Decimal = Field(default=Decimal("15000"), validate_default=True)
    hire_wage: Decimal = Field(default=Decimal("6000"), validate_default=True)
    owner_approves: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    mandate_rules: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=16)
    monthly_envelope: Decimal = Field(default=Decimal("0"), validate_default=True)
    # The archetype the company runs as; services_firm unless the scenario names another.
    archetype: ShortText | None = None
    scenario_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("owner_approves", "mandate_rules", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("sales_per_month", "sales_drift_percent", "cost_of_sales_percent", "wages_per_month", "rent_per_month", "late_payer_share_percent", "starting_cash", "tax_rate_percent", "price_elasticity", "marketing_return", "chase_recovery_percent", "capacity_per_month", "hire_capacity", "hire_wage", "monthly_envelope", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GymScenario":
        if self.sales_per_month <= 0 or self.starting_cash < 0 or not (Decimal("0") <= self.cost_of_sales_percent < Decimal("100")) or not (Decimal("0") <= self.late_payer_share_percent <= Decimal("100")):
            raise ValueError("sales are positive, cash is not negative, cost of sales and the late-payer share are percentages")
        if self.price_elasticity > 0:
            raise ValueError("price elasticity is zero or negative: a higher price sells less")
        if not skip_digests(info) and self.scenario_digest != sealed_digest(GymScenario, self, "scenario_digest"):
            raise ValueError("scenario_digest must commit the exact scenario")
        return self


def compile_gym_scenario(name: str, **fields: Any) -> GymScenario:
    values = {"name": name, "company_ref": f"gym:{name}", "company_name": f"Gym company {name}", "currency": "AUD", "start_month": "2026-01", "months": 6, "starting_cash": "20000", **fields}
    return seal(GymScenario, values, "scenario_digest")


STANDARD_SCENARIOS: dict[str, dict[str, Any]] = {
    "services_steady": {"sales_per_month": "40000", "cost_of_sales_percent": "20", "wages_per_month": "18000", "rent_per_month": "3000", "customers": 5, "late_payer_share_percent": "25", "starting_cash": "30000", "mandate_rules": ({"action_kind": "chase_overdue", "autonomy": "act", "cap_per_action": "20000"}, {"action_kind": "spend_marketing", "autonomy": "act", "cap_per_action": "2000"}, {"action_kind": "change_price", "autonomy": "ask"}, {"action_kind": "open_requisition", "autonomy": "ask"}), "monthly_envelope": "5000"},
    "cash_squeeze": {"sales_per_month": "30000", "sales_drift_percent": "-3", "cost_of_sales_percent": "30", "wages_per_month": "16000", "rent_per_month": "4000", "customers": 6, "late_payer_share_percent": "45", "starting_cash": "8000", "mandate_rules": ({"action_kind": "chase_overdue", "autonomy": "act", "cap_per_action": "50000"},), "monthly_envelope": "50000"},
    "growth_push": {"sales_per_month": "50000", "sales_drift_percent": "1", "cost_of_sales_percent": "35", "wages_per_month": "20000", "rent_per_month": "3500", "customers": 8, "late_payer_share_percent": "15", "starting_cash": "60000", "capacity_per_month": "60000", "marketing_return": "4", "owner_approves": ("hire",), "mandate_rules": ({"action_kind": "chase_overdue", "autonomy": "act", "cap_per_action": "20000"}, {"action_kind": "spend_marketing", "autonomy": "act", "cap_per_action": "5000"}, {"action_kind": "open_requisition", "autonomy": "ask"}), "monthly_envelope": "12000"},
}


def standard_gym_scenario(name: str, **overrides: Any) -> GymScenario:
    _require(name in STANDARD_SCENARIOS, "SCENARIO_UNKNOWN", f"the standard scenarios are {sorted(STANDARD_SCENARIOS)}")
    return compile_gym_scenario(name, **{**STANDARD_SCENARIOS[name], **overrides})


class GymAction(StrictModel):
    kind: ActionKind
    amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    subject: ShortText | None = None
    note: ShortText | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount", allow_negative=True)


class GymMonth(StrictModel):
    month: ShortText
    sales: Decimal
    net_profit: Decimal
    cash_end: Decimal
    overdue_end: Decimal
    actions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=16)
    refused: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=16)
    next_head: ShortText | None = None

    @field_validator("actions", "refused", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("sales", "net_profit", "cash_end", "overdue_end", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class GymReport(StrictModel):
    schema_id: str = Field(default=GYM_REPORT_SCHEMA, alias="schema")
    scenario: ShortText
    scenario_digest: Sha256Digest
    operator_ref: OpaqueRef
    months: int = Field(ge=1, le=24)
    revenue_first: Decimal
    revenue_last: Decimal
    revenue_growth_percent: Decimal
    cash_start: Decimal
    cash_end: Decimal
    cash_low: Decimal
    months_cash_negative: int = Field(ge=0)
    overdue_end: Decimal
    actions_by_kind: dict[str, int] = Field(default_factory=dict)
    mandate_violations: int = Field(ge=0)
    owner_approvals_used: int = Field(ge=0)
    rows: tuple[GymMonth, ...] = Field(min_length=1, max_length=24)
    score: Decimal
    verdict: ShortText
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("revenue_first", "revenue_last", "revenue_growth_percent", "cash_start", "cash_end", "cash_low", "overdue_end", "score", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "GymReport":
        if len(self.rows) != self.months:
            raise ValueError("one row per month")
        if not skip_digests(info) and self.report_digest != sealed_digest(GymReport, self, "report_digest"):
            raise ValueError("report_digest must commit the exact report")
        return self

    def render(self) -> str:
        lines = [f"**Gym** {self.scenario} x {self.operator_ref} over {self.months} month(s): {self.verdict}"]
        lines.extend(f"- {row.month}: sales {row.sales}, net {row.net_profit}, cash {row.cash_end}, overdue {row.overdue_end}" + (f"; did {', '.join(row.actions)}" if row.actions else "") + (f"; refused {', '.join(row.refused)}" if row.refused else "") for row in self.rows)
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Rendering the ledger's reports
# --------------------------------------------------------------------------- #


def _cell(value: str, account: str | None = None) -> dict[str, Any]:
    return {"Value": value, "Attributes": [{"Id": "account", "Value": account}]} if account else {"Value": value}


def _row(label: str, amount: Decimal, account: str | None = None, *, summary: bool = False) -> dict[str, Any]:
    return {"RowType": "SummaryRow" if summary else "Row", "Cells": [_cell(label, account), _cell(str(_money(amount)), account)]}


def _section(title: str, rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {"RowType": "Section", "Title": title, "Rows": list(rows)}


def _month_bounds(start_month: str, index: int) -> tuple[date, date]:
    year, month = int(start_month[:4]), int(start_month[5:7])
    month0 = month - 1 + index
    first = date(year + month0 // 12, month0 % 12 + 1, 1)
    nxt = date(first.year + (first.month // 12), first.month % 12 + 1, 1)
    return first, nxt


def _long(day: date) -> str:
    return f"{day.day} {_MONTH_NAMES[day.month - 1]} {day.year}"


def render_profit_and_loss(scenario: GymScenario, first: date, last: date, *, sales: Decimal, materials: Decimal, wages: Decimal, rent: Decimal, marketing: Decimal) -> dict[str, Any]:
    gross = sales - materials
    operating = wages + rent + marketing
    net = gross - operating
    rows = [
        {"RowType": "Header", "Cells": [{"Value": ""}, {"Value": last.strftime("%d %b %y")}]},
        _section("Income", [_row("Sales", sales, ACCOUNT["sales"]), _row("Total Income", sales, summary=True)]),
        _section("Less Cost of Sales", [_row("Materials", materials, ACCOUNT["materials"]), _row("Total Cost of Sales", materials, summary=True)]),
        _section("", [_row("Gross Profit", gross)]),
        _section("Less Operating Expenses", [_row("Wages and Salaries", wages, ACCOUNT["wages"]), _row("Rent", rent, ACCOUNT["rent"]), _row("Marketing", marketing, ACCOUNT["marketing"]), _row("Total Operating Expenses", operating, summary=True)]),
        _section("", [_row("Net Profit", net)]),
    ]
    return {"Reports": [{"ReportID": "ProfitAndLoss", "ReportName": "Profit and Loss", "ReportType": "ProfitAndLoss", "ReportTitles": ["Profit & Loss", scenario.company_name, f"{_long(first)} to {_long(last)}"], "ReportDate": _long(last + timedelta(days=1)), "UpdatedDateUTC": "/Date(1791072000000)/", "Fields": [], "Rows": rows}]}


def _tax_account(scenario: GymScenario) -> str:
    """The sales tax liability as the company's ledger names it: GST, GST/HST Payable, Sales Tax Payable or VAT."""

    from lightbulb.jurisdictions import JURISDICTIONS, jurisdiction_for_currency

    return JURISDICTIONS[jurisdiction_for_currency(scenario.currency) or "AU"].sales_tax_account


def render_balance_sheet(scenario: GymScenario, last: date, *, cash: Decimal, receivable: Decimal, gst: Decimal, current_year: Decimal, retained: Decimal) -> dict[str, Any]:
    assets = cash + receivable
    net_assets = assets - gst
    rows = [
        {"RowType": "Header", "Cells": [{"Value": ""}, {"Value": last.strftime("%d %b %y")}]},
        _section("Assets", []),
        _section("Bank", [_row("Business Account", cash, ACCOUNT["bank"]), _row("Total Bank", cash, summary=True)]),
        _section("Current Assets", [_row("Accounts Receivable", receivable, ACCOUNT["receivable"]), _row("Total Current Assets", receivable, summary=True)]),
        _section("", [_row("Total Assets", assets, summary=True)]),
        _section("Liabilities", []),
        _section("Current Liabilities", [_row(_tax_account(scenario), gst, ACCOUNT["gst"]), _row("Total Current Liabilities", gst, summary=True)]),
        _section("", [_row("Total Liabilities", gst, summary=True)]),
        _section("", [_row("Net Assets", net_assets)]),
        _section("Equity", [_row("Current Year Earnings", current_year, ACCOUNT["cye"]), _row("Retained Earnings", retained, ACCOUNT["retained"]), _row("Total Equity", current_year + retained, summary=True)]),
    ]
    return {"Reports": [{"ReportID": "BalanceSheet", "ReportName": "Balance Sheet", "ReportType": "BalanceSheet", "ReportTitles": ["Balance Sheet", scenario.company_name, f"As at {_long(last)}"], "ReportDate": _long(last + timedelta(days=1)), "UpdatedDateUTC": "/Date(1791072000000)/", "Fields": [], "Rows": rows}]}


def render_invoice_page(scenario: GymScenario, invoices: Sequence[Mapping[str, Any]], observed_at: str) -> dict[str, Any]:
    records = [{"provider": "xero", "transaction_type": "invoice", "source_ref": item["ref"], "source_revision_kind": "content_sha256", "source_revision": stable_digest(item), "transaction_date": item["date"], "source_updated_at": observed_at, "source_status": "PAID" if Decimal(item["open"]) == 0 else "AUTHORISED", "currency": scenario.currency, "total_amount": str(_money(Decimal(item["total"]))).rstrip("0").rstrip("."), "open_balance": str(_money(Decimal(item["open"]))).rstrip("0").rstrip(".") or "0", "document_number": item["ref"], "counterparty_ref": item["customer_ref"], "counterparty_name": item["customer"], "links": []} for item in invoices]
    return {"schema": "lightbulb.xero_close_source_page.v1", "provider": "xero", "transaction_type": "invoice", "page": 1, "page_size": 200, "provider_observed_at": observed_at, "pagination": {"page": 1, "page_size": 200, "page_count": 1, "item_count": len(records)}, "records": records}


def _read(tool: str, payload: Mapping[str, Any], completed_at: str, ref: str) -> dict[str, Any]:
    return {"lane": "host_read", "source_tool": tool, "observation_ref": f"gym:{tool}:{ref}", "provenance_digest": stable_digest({"gym": ref, "tool": tool}), "output_digest": stable_digest(payload), "completed_at": completed_at}


# --------------------------------------------------------------------------- #
# The console the operator works in
# --------------------------------------------------------------------------- #


def gym_console(scenario: GymScenario | Mapping[str, Any], *, clock: dict[str, str]) -> Any:
    """A console for the scenario's company: an in-memory store, a services blueprint, the books and customer ledger plans, and the scenario's mandate."""

    from lightbulb.books_snapshot import compile_books_plan
    from lightbulb.company_cadence_runner import compile_company_bundle
    from lightbulb.company_console import CompanyConsole
    from lightbulb.company_engine_store import InMemoryEngineStateStore
    from lightbulb.customer_ledger import compile_customer_ledger_plan
    from lightbulb.owner_mandate import compile_mandate

    parsed_scenario = scenario if isinstance(scenario, GymScenario) else GymScenario.model_validate(dict(detached(scenario)))
    at = clock["now"]
    from lightbulb.jurisdictions import HOME_CURRENCIES, jurisdiction_for_currency

    # the archetype's own bundle, compiled as bootstrap compiles it, in the jurisdiction whose currency the scenario keeps, so every fence a real company meets holds here too
    jurisdiction = jurisdiction_for_currency(parsed_scenario.currency)
    _require(jurisdiction is not None, "CURRENCY_UNSUPPORTED", f"the gym runs companies in the five jurisdictions' home currencies ({', '.join(HOME_CURRENCIES.values())}); the scenario keeps {parsed_scenario.currency}")
    archetype = parsed_scenario.archetype or "services_firm"
    scope = {"tenant_ref": "gym", "company_ref": "gym", "project_ref": parsed_scenario.name, "project_id": "00000000-0000-4000-8000-00000000009a"}
    bundle = compile_company_bundle(archetype, company_ref=parsed_scenario.company_ref, scope=scope, actor_ref="agent:gym", start_at=at, jurisdiction=jurisdiction)
    bundle.supporting_plans["books_snapshot"] = compile_books_plan(parsed_scenario.company_ref, currency=parsed_scenario.currency, overrides={"account_roles": {"receivable": ["Accounts Receivable"], "tax": [_tax_account(parsed_scenario)]}, "variable_accounts": ["Materials"]}).to_dict()
    bundle.supporting_plans["customer_ledger"] = compile_customer_ledger_plan(parsed_scenario.company_ref, currency=parsed_scenario.currency, overrides={"terms_days": parsed_scenario.terms_days}).to_dict()
    bundle.supporting_plans["mandate"] = compile_mandate(parsed_scenario.company_ref, currency=parsed_scenario.currency, owner_ref="user:gym-owner", as_of=at, rules=[dict(rule) for rule in parsed_scenario.mandate_rules], monthly_envelope=parsed_scenario.monthly_envelope, months_valid=24).to_dict()
    return CompanyConsole(bundle, InMemoryEngineStateStore(), lambda: clock["now"])


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #

Operator = Callable[[Any, Mapping[str, Any]], Sequence[GymAction | Mapping[str, Any]]]


def do_nothing(console: Any, context: Mapping[str, Any]) -> list[GymAction]:
    return []


def mandate_operator(console: Any, context: Mapping[str, Any]) -> list[GymAction]:
    """The reference operator: does what ``next`` puts at the head of the queue when the mandate lets it act alone, and nothing else."""

    actions: list[GymAction] = []
    for row in dict(context["step"]).get("queue", ()):
        if row["autonomy"] != "act":
            continue
        if row.get("action_kind") == "chase_overdue" and row["step"] == "do":
            actions.append(GymAction(kind="chase_overdue", amount=row["money_at_stake"], subject=dict(row.get("payload_hint") or {}).get("recipient_ref") or "all"))
    return actions


GYM_AUTOPILOT_ACCOUNTS: dict[str, str] = {"gmail.send_email": "gym:gmail"}
GYM_AUTOPILOT_GRANT_DAYS = 90


class GymPlatform:
    """The platform as the gym plays it: a send the mandate lets the agent make alone goes out at once, one that needs the owner waits for an approval the gym's owner never gives, and the owner's notices are kept."""

    def __init__(self) -> None:
        self.sent: list[Any] = []
        self.notices: list[dict[str, Any]] = []

    def execute(self, request: Any) -> Any:
        from lightbulb.connector_execution import ConnectorExecutionResult, ConnectorExecutionStatus

        if request.approval_required:
            return ConnectorExecutionResult(status=ConnectorExecutionStatus.PENDING_APPROVAL, tool=request.tool, approval_ref=f"gym-approval-{request.idempotency_key}"[:200], message="the gym's owner approves nothing")
        self.sent.append(request)
        return ConnectorExecutionResult(status=ConnectorExecutionStatus.COMPLETED, tool=request.tool, output={"id": f"gym-msg-{len(self.sent)}"})

    def notify(self, **notice: Any) -> dict[str, Any]:
        self.notices.append(dict(notice))
        return {"delivered": True}


def autopilot_operator(console: Any, context: Mapping[str, Any]) -> list[GymAction]:
    """The autopilot itself, with the gym's owner holding the switch: the owner turns it on for ninety days and turns it on again when a grant ends, and each month one tick decides; every reminder the platform sends becomes that month's chase."""

    from lightbulb.company_autopilot import load_control, run_autopilot_tick, start_autopilot

    platform = getattr(console, "connector_executor", None)
    if not isinstance(platform, GymPlatform):
        platform = GymPlatform()
        console.connector_executor = platform
        console.owner_notifier = platform.notify
    at = str(context["as_of"])
    control, _ = load_control(console)
    if control is None or control.state == "off" or (control.state == "on" and parsed(str(control.on_until)) <= parsed(at)):
        start_autopilot(console, now=at, owner_ref=str(dict(context["mandate"])["owner_ref"]), days=GYM_AUTOPILOT_GRANT_DAYS)
    tick = run_autopilot_tick(console, now=at, connector_account_refs=GYM_AUTOPILOT_ACCOUNTS)
    return [GymAction(kind="chase_overdue", amount=row["money"], subject=str(row["subject"]).split(": ", 1)[-1]) for row in tick.get("did", ()) if row["outcome"] == "done" and str(row["subject"]).startswith("chase_overdue: ")]


OPERATORS: dict[str, Operator] = {"do_nothing": do_nothing, "mandate": mandate_operator, "autopilot": autopilot_operator}


def run_gym(scenario: GymScenario | Mapping[str, Any], operator: Operator | str, *, operator_ref: str | None = None) -> GymReport:
    """Run the scenario for its months with the operator, through the real console, mandate and next step; seal the report."""

    from lightbulb.owner_mandate import authorise, verify_mandate

    parsed_scenario = scenario if isinstance(scenario, GymScenario) else GymScenario.model_validate(dict(detached(scenario)))
    if isinstance(operator, str):
        _require(operator in OPERATORS, "OPERATOR_UNKNOWN", f"the built-in operators are {sorted(OPERATORS)}")
        operator_ref, operator = f"operator:{operator}", OPERATORS[operator]
    operator_ref = operator_ref or "operator:custom"
    first_day, _ = _month_bounds(parsed_scenario.start_month, 0)
    clock = {"now": f"{first_day.isoformat()}T00:00:00Z"}
    console = gym_console(parsed_scenario, clock=clock)
    mandate = verify_mandate(console.bundle.supporting_plans["mandate"])
    tax = parsed_scenario.tax_rate_percent / Decimal(100)
    cash = _money(parsed_scenario.starting_cash)
    retained = cash
    cumulative_profit = Decimal("0")
    gst_owed = Decimal("0")
    price_factor = Decimal("1")
    volume_factor = Decimal("1")
    capacity = parsed_scenario.capacity_per_month
    wages = parsed_scenario.wages_per_month
    marketing_next = Decimal("0")
    open_invoices: list[dict[str, Any]] = []
    all_invoices: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    actions_by_kind: dict[str, int] = {}
    violations = approvals = 0
    cash_low = cash
    negative_months = 0
    spent_this_month = Decimal("0")
    for index in range(parsed_scenario.months):
        first, nxt = _month_bounds(parsed_scenario.start_month, index)
        last = nxt - timedelta(days=1)
        month = first.strftime("%Y-%m")
        # this month's sales: the drift, the price and volume factors, marketing's lift from last month, and the capacity cap
        base = parsed_scenario.sales_per_month * (Decimal(1) + parsed_scenario.sales_drift_percent / Decimal(100)) ** index
        sales = base * price_factor * volume_factor + marketing_next * parsed_scenario.marketing_return
        if capacity is not None:
            sales = min(sales, capacity)
        sales = _money(sales)
        marketing = marketing_next
        marketing_next = Decimal("0")
        materials = _money(sales * parsed_scenario.cost_of_sales_percent / Decimal(100))
        rent = parsed_scenario.rent_per_month
        net = _money(sales - materials - wages - rent - marketing)
        cumulative_profit += net
        # invoices: one per customer summing exactly to sales plus tax (the rounding cents land on the last), the late payers keep theirs open past terms
        gst_month = _money(sales * tax)
        gst_owed = _money(gst_owed + gst_month)
        invoiced = sales + gst_month
        share = _money(invoiced / Decimal(parsed_scenario.customers))
        late = int((Decimal(parsed_scenario.customers) * parsed_scenario.late_payer_share_percent / Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        collected = Decimal("0")
        for customer in range(parsed_scenario.customers):
            amount = share if customer < parsed_scenario.customers - 1 else _money(invoiced - share * (parsed_scenario.customers - 1))
            invoice = {"ref": f"INV-{month}-{customer + 1:02d}", "customer_ref": f"c-{customer + 1:03d}", "customer": f"Customer {customer + 1}", "date": (first + timedelta(days=min(customer, 27))).isoformat(), "total": str(amount), "open": str(amount) if customer < late else "0"}
            if customer >= late:
                collected += amount
            open_invoices.append(invoice)
            all_invoices.append(invoice)
        # money out this month and tax when it falls due
        cash += collected - materials - wages - rent - marketing
        if (index + 1) % parsed_scenario.tax_paid_every_months == 0:
            cash -= gst_owed
            gst_owed = Decimal("0")
        cash = _money(cash)
        receivable = _money(sum((Decimal(item["open"]) for item in open_invoices), Decimal("0")))
        # the month's reads, recorded the way a real month is
        clock["now"] = f"{nxt.isoformat()}T06:00:00Z"
        pnl = render_profit_and_loss(parsed_scenario, first, last, sales=sales, materials=materials, wages=wages, rent=rent, marketing=marketing)
        sheet = render_balance_sheet(parsed_scenario, last, cash=cash, receivable=receivable, gst=gst_owed, current_year=cumulative_profit, retained=retained)
        sources = [{"kind": "profit_and_loss", "provenance": _read("xero.profit_loss_report", pnl, clock["now"], f"pl:{month}"), "payload": pnl}, {"kind": "balance_sheet", "provenance": _read("xero.balance_sheet_report", sheet, clock["now"], f"bs:{month}"), "payload": sheet}]
        console.chain("backfill", operation="record", payload={"sources": sources})
        # the ledger's invoice page is month-bound, so every month with an invoice still open is re-read (and its ledger amended), as a worker would
        for earlier in range(index + 1):
            window_first, window_next = _month_bounds(parsed_scenario.start_month, earlier)
            month_invoices = [item for item in all_invoices if item["date"][:7] == window_first.strftime("%Y-%m")]
            if earlier < index and not any(Decimal(item["open"]) > 0 for item in month_invoices):
                continue
            page = render_invoice_page(parsed_scenario, month_invoices, clock["now"])
            console.chain("customers", operation="record", payload={"source": {"provenance": _read("xero.list_invoices", page, clock["now"], f"inv:{window_first.strftime('%Y-%m')}:{month}"), "payload": page}, "window_start": f"{window_first.isoformat()}T00:00:00Z", "window_end": f"{window_next.isoformat()}T00:00:00Z"})
        console.chain("intelligence_review", operation="record", payload={"review_ref": f"gym-{month}", "window_start": f"{first.isoformat()}T00:00:00Z", "window_end": f"{nxt.isoformat()}T00:00:00Z"})
        step = console.chain("next", operation="build")
        overdue_before = sum((Decimal(item["open"]) for item in open_invoices if (nxt - date.fromisoformat(item["date"])).days > parsed_scenario.terms_days), Decimal("0"))
        # the operator answers; every action goes through the mandate as the console would apply it
        taken: list[str] = []
        refused: list[str] = []
        spent_this_month = Decimal("0")
        for raw in operator(console, {"month": month, "index": index, "as_of": clock["now"], "step": step, "mandate": mandate.to_dict(), "overdue": str(_money(overdue_before)), "cash": str(cash)}):
            action = raw if isinstance(raw, GymAction) else GymAction.model_validate(dict(detached(raw)))
            if action.kind == "none":
                continue
            decision = authorise(mandate, action_kind=ACTION_TO_MANDATE[action.kind], money=action.amount, now=clock["now"], spent_this_month=spent_this_month, subject=action.subject)
            if decision.autonomy != "act":
                violations += 1
                if action.kind in parsed_scenario.owner_approves and decision.autonomy == "ask":
                    approvals += 1
                else:
                    refused.append(f"{action.kind} ({decision.autonomy}: {decision.reason[:60]})")
                    continue
            else:
                spent_this_month += action.amount.copy_abs()
            actions_by_kind[action.kind] = actions_by_kind.get(action.kind, 0) + 1
            taken.append(action.kind + (f" {action.amount}" if action.amount else ""))
            if action.kind == "chase_overdue":
                recovered = Decimal("0")
                for item in open_invoices:
                    if Decimal(item["open"]) > 0 and (nxt - date.fromisoformat(item["date"])).days > parsed_scenario.terms_days and (action.subject in (None, item["customer"], item["customer_ref"]) or action.subject == "all"):
                        part = _money(Decimal(item["open"]) * parsed_scenario.chase_recovery_percent / Decimal(100))
                        item["open"] = str(_money(Decimal(item["open"]) - part))
                        recovered += part
                cash = _money(cash + recovered)
            elif action.kind == "change_price":
                change = action.amount / Decimal(100)
                price_factor = price_factor * (Decimal(1) + change)
                volume_factor = volume_factor * ((Decimal(1) + change) ** parsed_scenario.price_elasticity)
            elif action.kind == "spend_marketing":
                marketing_next += action.amount.copy_abs()
            elif action.kind == "hire":
                capacity = None if capacity is None else capacity + parsed_scenario.hire_capacity
                wages = wages + parsed_scenario.hire_wage
            elif action.kind == "open_change":
                cash = _money(cash - action.amount.copy_abs())
        open_invoices = [item for item in open_invoices if Decimal(item["open"]) > 0]
        overdue_end = _money(sum((Decimal(item["open"]) for item in open_invoices if (nxt - date.fromisoformat(item["date"])).days > parsed_scenario.terms_days), Decimal("0")))
        cash_low = min(cash_low, cash)
        negative_months += int(cash < 0)
        rows.append({"month": month, "sales": str(sales), "net_profit": str(net), "cash_end": str(cash), "overdue_end": str(overdue_end), "actions": taken, "refused": refused, "next_head": None if step.get("next") is None else str(step["next"]["subject"])[:300]})
    first_sales, last_sales = Decimal(rows[0]["sales"]), Decimal(rows[-1]["sales"])
    growth = ((last_sales - first_sales) * Decimal(100) / first_sales).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    # the score: cash kept, growth earned, overdue money not left lying, and no action outside the mandate
    score = (cash - parsed_scenario.starting_cash) + (last_sales - first_sales) * Decimal(3) - Decimal(rows[-1]["overdue_end"]) - Decimal(violations) * Decimal(1000) - Decimal(negative_months) * Decimal(5000)
    verdict = f"sales {first_sales} -> {last_sales} ({growth:+}%), cash {parsed_scenario.starting_cash} -> {cash} (lowest {cash_low}), overdue {rows[-1]['overdue_end']} at the end, {sum(actions_by_kind.values())} action(s), {violations} outside the mandate; score {_money(score)}"
    return seal(GymReport, {"scenario": parsed_scenario.name, "scenario_digest": parsed_scenario.scenario_digest, "operator_ref": operator_ref, "months": parsed_scenario.months, "revenue_first": str(first_sales), "revenue_last": str(last_sales), "revenue_growth_percent": str(growth), "cash_start": str(_money(parsed_scenario.starting_cash)), "cash_end": str(cash), "cash_low": str(cash_low), "months_cash_negative": negative_months, "overdue_end": rows[-1]["overdue_end"], "actions_by_kind": actions_by_kind, "mandate_violations": violations, "owner_approvals_used": approvals, "rows": rows, "score": str(_money(score)), "verdict": verdict[:300]}, "report_digest")


def verify_gym_report(value: Any) -> GymReport:
    return value if isinstance(value, GymReport) else GymReport.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


__all__ = ["ACTION_TO_MANDATE", "GYM_AUTOPILOT_ACCOUNTS", "GYM_MANIFEST", "GYM_REPORT_SCHEMA", "GYM_SCENARIO_SCHEMA", "OPERATORS", "STANDARD_SCENARIOS", "GymAction", "GymError", "GymMonth", "GymPlatform", "GymReport", "GymScenario", "autopilot_operator", "compile_gym_scenario", "do_nothing", "gym_console", "mandate_operator", "run_gym", "standard_gym_scenario", "verify_gym_report"]
