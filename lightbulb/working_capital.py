"""Working capital: the days cash sits in receivables and stock less the days suppliers wait, from the replayed chains, and which lever frees the most.

Profit on paper is not cash in the bank until customers pay, stock
sells, and bills come due.  ``build_working_capital`` seals the cash
conversion cycle from the chains that hold the truth:

* receivables from the collections chain: the balance outstanding, the
  overdue part, credit sales in the window (receivables opened), days
  sales outstanding (balance over daily credit sales), and the realised
  days to collect on what was recovered;
* payables from the payables chain: the unpaid balance, bills received in
  the window, days payable outstanding (balance over daily bills), and
  the realised days from receipt to cash;
* stock from the inventory chain: stock value at cost and, with the
  window's sealed product margin report, days inventory outstanding
  (stock over daily cost of goods);
* the cash conversion cycle (days sales plus days inventory less days
  payable), the cash tied up, and per lever the days over the plan's
  target and the cash a day of improvement would release, so the
  recommendation names the lever that frees the most.

A metric whose flow is missing from the window is left unknown with the
reason, never estimated.  Nothing here reads a provider or persists
anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

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

WORKING_CAPITAL_PLAN_SCHEMA = "lightbulb.working_capital_plan.v1"
WORKING_CAPITAL_SCHEMA = "lightbulb.working_capital.v1"
LEVERS: tuple[str, ...] = ("receivables", "inventory", "payables")
_DAYS = Decimal("0.1")


class WorkingCapitalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WorkingCapitalError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _days(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(_DAYS, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class WorkingCapitalPlan(StrictModel):
    schema_id: str = Field(default=WORKING_CAPITAL_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    receivable_days_target: int = Field(default=30, ge=0, le=365)
    inventory_days_target: int = Field(default=60, ge=0, le=730)
    payable_days_target: int = Field(default=30, ge=0, le=365)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkingCapitalPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(WorkingCapitalPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_working_capital_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> WorkingCapitalPlan:
    return seal(WorkingCapitalPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class Lever(StrictModel):
    lever: ShortText
    balance: Decimal
    flow_in_window: Decimal
    daily_flow: Decimal | None = None
    days: Decimal | None = None
    realised_days: Decimal | None = None
    target_days: int = Field(ge=0)
    days_over_target: Decimal | None = None
    cash_per_day: Decimal | None = None
    cash_to_free: Decimal | None = None
    cases: int = Field(ge=0)
    basis: ShortText | None = None
    note: ShortText

    @field_validator("balance", "flow_in_window", "daily_flow", "days", "realised_days", "days_over_target", "cash_per_day", "cash_to_free", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class WorkingCapital(StrictModel):
    schema_id: str = Field(default=WORKING_CAPITAL_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    margin_report_digest: Sha256Digest | None = None
    books_digest: Sha256Digest | None = None
    levers: tuple[Lever, ...] = Field(min_length=3, max_length=3)
    overdue_receivables: Decimal
    cash_conversion_days: Decimal | None = None
    target_cycle_days: int = Field(ge=0)
    cash_tied: Decimal
    cash_to_free: Decimal
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=6000)
    capital_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("levers", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("overdue_receivables", "cash_conversion_days", "cash_tied", "cash_to_free", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkingCapital":
        if [lever.lever for lever in self.levers] != list(LEVERS):
            raise ValueError("the levers are receivables, inventory, and payables in that order")
        if not skip_digests(info) and self.capital_digest != sealed_digest(WorkingCapital, self, "capital_digest"):
            raise ValueError("capital_digest must commit the exact document")
        return self

    def lever(self, name: str) -> Lever | None:
        return next((row for row in self.levers if row.lever == name), None)

    def render(self) -> str:
        cycle = "unknown" if self.cash_conversion_days is None else f"{self.cash_conversion_days} day(s) against a {self.target_cycle_days}-day target"
        lines = [f"**Working capital {self.company_ref}** {self.window_start[:10]} to {self.window_end[:10]}: cash conversion cycle {cycle}; {self.cash_tied} {self.currency} tied up, {self.cash_to_free} to free."]
        for row in self.levers:
            lines.append(f"- {row.lever}: {row.note}")
        return "\n".join(lines)


def build_working_capital(plan: WorkingCapitalPlan | Mapping[str, Any], *, collections_states: Sequence[tuple[Any, Any]] = (), payables_states: Sequence[tuple[Any, Any]] = (), inventory_states: Sequence[tuple[Any, Any]] = (), margin_report: Mapping[str, Any] | Any | None = None, books: Mapping[str, Any] | Any | None = None, window_start: str, window_end: str, as_of: str) -> WorkingCapital:
    """The sealed cash conversion cycle over the window from the replayed receivables, payables, and stock positions.

    ``books`` is the window's sealed books snapshot.  A lever reads it only when its own chain holds nothing, and only
    for a role the snapshot knows: the balance is the ledger's, and the flow is the nearest the books carry (revenue
    for credit sales, recorded cost for bills, cost of sales for cost of goods).  The lever says so.  The books do not
    age receivables, so nothing from them is called overdue.
    """

    parsed_plan = plan if isinstance(plan, WorkingCapitalPlan) else WorkingCapitalPlan.model_validate(detached(plan))
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    at = timestamp(as_of, field_name="as_of")
    days = Decimal((parsed(end) - parsed(start)).days)
    _require(days > 0, "WINDOW_EMPTY", "the window spans at least one day")
    digests: list[str] = []

    def inside(stamp: Any) -> bool:
        return stamp is not None and parsed(start) <= parsed(str(stamp)) < parsed(end)

    # receivables
    ar = overdue = credit_sales = Decimal("0")
    collect_days: list[Decimal] = []
    receivables = 0
    if collections_states:
        from lightbulb.collections_chain import COLLECTIONS_LIFECYCLE

        for plan_doc, state_doc in collections_states:
            cplan, state = COLLECTIONS_LIFECYCLE.bind(plan_doc, state_doc)
            _require(cplan.company_ref == parsed_plan.company_ref and cplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"receivable {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            ledger = state.ledger
            receivables += 1
            if ledger.outcome == "open":
                ar += Decimal(str(ledger.balance))
                if ledger.days_past_due > 0:
                    overdue += Decimal(str(ledger.balance))
            if inside(ledger.issued_at):
                credit_sales += Decimal(str(ledger.invoice_total))
            if ledger.outcome == "recovered" and ledger.issued_at and ledger.applied_at:
                collect_days.append(Decimal((parsed(str(ledger.applied_at)) - parsed(str(ledger.issued_at))).days))
    # payables
    ap = bills = Decimal("0")
    pay_days: list[Decimal] = []
    payables = 0
    if payables_states:
        from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

        for plan_doc, state_doc in payables_states:
            pplan, state = PAYABLES_CHAIN_LIFECYCLE.bind(plan_doc, state_doc)
            _require(pplan.company_ref == parsed_plan.company_ref and pplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"payable {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            ledger = state.ledger
            payables += 1
            if ledger.outcome == "open" and ledger.paid_at is None:
                ap += Decimal(str(ledger.amount)) - Decimal(str(ledger.applied_amount))
            if inside(ledger.received_at):
                bills += Decimal(str(ledger.amount))
            if ledger.days_receipt_to_cash is not None:
                pay_days.append(Decimal(ledger.days_receipt_to_cash))
    # inventory
    stock = Decimal("0")
    positions = 0
    if inventory_states:
        from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

        for plan_doc, state_doc in inventory_states:
            iplan, state = INVENTORY_LIFECYCLE.bind(plan_doc, state_doc)
            _require(iplan.company_ref == parsed_plan.company_ref and iplan.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"stock position {state.scope.entity_ref} belongs to another company or currency")
            digests.append(state.state_digest)
            positions += 1
            stock += Decimal(str(state.ledger.stock_value))
    cogs = None
    report_digest = None
    if margin_report is not None:
        from lightbulb.product_margin import verify_product_margin

        report = verify_product_margin(margin_report)
        _require(report.company_ref == parsed_plan.company_ref and report.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the margin report names another company or currency")
        _require(report.window_start == start and report.window_end == end, "REPORT_WINDOW_MISMATCH", "the margin report must cover exactly this window")
        cogs = Decimal(str(report.cost_of_goods))
        report_digest = report.report_digest
        digests.append(report_digest)

    books_digest = None
    from_books: dict[str, str] = {}
    if books is not None:
        from lightbulb.books_snapshot import verify_books_snapshot

        snapshot = verify_books_snapshot(books)
        _require(snapshot.company_ref == parsed_plan.company_ref and snapshot.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the books snapshot names another company or currency")
        _require(snapshot.window_start == start and snapshot.window_end == end, "REPORT_WINDOW_MISMATCH", "the books snapshot must cover exactly this window")
        books_digest = snapshot.snapshot_digest
        digests.append(books_digest)
        if not collections_states and snapshot.receivables is not None:
            ar, credit_sales = Decimal(str(snapshot.receivables)), Decimal(str(snapshot.revenue))
            from_books["receivables"] = "the ledger's receivable balance over its revenue, which stands in for credit sales; the books do not age it"
        if not payables_states and snapshot.payables is not None:
            ap, bills = Decimal(str(snapshot.payables)), Decimal(str(snapshot.cost_of_sales)) + Decimal(str(snapshot.operating_expenses)) + Decimal(str(snapshot.other_expenses))
            from_books["payables"] = "the ledger's payable balance over its recorded cost, which stands in for bills received"
        if not inventory_states and snapshot.inventory is not None:
            stock = Decimal(str(snapshot.inventory))
            if cogs is None:
                cogs = Decimal(str(snapshot.cost_of_sales))
            from_books["inventory"] = "the ledger's stock balance over its cost of sales"

    def lever(name: str, balance: Decimal, flow: Decimal | None, realised: list[Decimal], target: int, cases: int, missing: str, *, stretch: bool = False) -> dict[str, Any]:
        daily = None if flow is None or flow <= 0 else flow / days
        metric = None if daily is None else _days(balance / daily)
        if metric is None and name in from_books and balance == 0:
            metric = _days(0)  # the books know this balance is nil: nothing is tied up in it, whatever the flow
        realised_days = None if not realised else _days(sum(realised, Decimal("0")) / len(realised))
        over = None if metric is None else _days(metric - Decimal(target))
        cash_per_day = None if daily is None else _money(daily)
        # receivables and stock free cash by coming down to target; payables free cash by stretching up to it
        gap = None if over is None else (max(-over, Decimal("0")) if stretch else max(over, Decimal("0")))
        to_free = None if gap is None or daily is None else _money(gap * daily)
        if metric is None:
            note = f"{_money(balance)} outstanding across {cases} case(s); {missing}"
        else:
            note = f"{metric} day(s) ({_money(balance)} over {_money(daily)} a day) against a {target}-day target" + (f"; realised {realised_days} day(s)" if realised_days is not None else "") + (f"; {to_free} to free" + (" by paying at the target" if stretch else "") if to_free is not None and to_free > 0 else "; inside target")
        if name in from_books:
            note = f"from the books ({from_books[name]}): {note}"[:300]
        return {"basis": "books" if name in from_books else None, "lever": name, "balance": str(_money(balance)), "flow_in_window": str(_money(flow or Decimal("0"))), "daily_flow": None if daily is None else str(_money(daily)), "days": None if metric is None else str(metric), "realised_days": None if realised_days is None else str(realised_days), "target_days": target, "days_over_target": None if over is None else str(over), "cash_per_day": cash_per_day if cash_per_day is None else str(cash_per_day), "cash_to_free": None if to_free is None else str(to_free), "cases": cases, "note": note[:300]}

    levers = [
        lever("receivables", ar, credit_sales, collect_days, parsed_plan.receivable_days_target, receivables, "no receivables were opened in the window, so days sales outstanding is unknown"),
        lever("inventory", stock, cogs, [], parsed_plan.inventory_days_target, positions, "no sealed margin report for the window, so days inventory outstanding is unknown" if cogs is None else "no cost of goods in the window, so days inventory outstanding is unknown"),
        lever("payables", ap, bills, pay_days, parsed_plan.payable_days_target, payables, "no bills were received in the window, so days payable outstanding is unknown", stretch=True),
    ]
    dso, dio, dpo = (levers[0]["days"], levers[1]["days"], levers[2]["days"])
    cycle = None if dso is None or dio is None or dpo is None else _days(Decimal(dso) + Decimal(dio) - Decimal(dpo))
    target_cycle = parsed_plan.receivable_days_target + parsed_plan.inventory_days_target - parsed_plan.payable_days_target
    cash_tied = _money(ar + stock - ap)
    to_free = _money(sum((Decimal(row["cash_to_free"]) for row in levers if row["cash_to_free"] is not None), Decimal("0")))
    ranked = sorted((row for row in levers if row["cash_to_free"] is not None and Decimal(row["cash_to_free"]) > 0), key=lambda row: -Decimal(row["cash_to_free"]))
    recommendations = [f"{row['lever']}: {row['note']}" for row in ranked]
    if overdue > 0:
        recommendations.append(f"receivables: {_money(overdue)} is past due; collect it before anything else")
    if not recommendations:
        recommendations.append("every lever is inside its target" if cycle is not None else "the cycle cannot be measured until the window carries receivables, bills, and a sealed margin report")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "margin_report_digest": report_digest, "books_digest": books_digest, "levers": levers, "overdue_receivables": str(_money(overdue)), "cash_conversion_days": None if cycle is None else str(cycle), "target_cycle_days": target_cycle, "cash_tied": str(cash_tied), "cash_to_free": str(to_free), "recommendations": [item[:300] for item in recommendations[:24]], "source_digests": digests}
    return seal(WorkingCapital, payload, "capital_digest")


def verify_working_capital(value: Any) -> WorkingCapital:
    return value if isinstance(value, WorkingCapital) else WorkingCapital.model_validate(dict(detached(value)))


WORKING_CAPITAL_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "working_capital",
    "golden_loop": "finance.observed_balances_to_reviewed_cash_forecast@0.1.0",
    "stages": ["replay_receivables", "replay_payables", "replay_stock", "days_per_lever", "cash_conversion_cycle", "rank_levers_by_cash", "seal_document"],
    "levers": list(LEVERS),
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "days sales outstanding is the open balance over daily credit sales opened in the window; days payable is the unpaid balance over daily bills received; days inventory is stock at cost over the window's sealed cost of goods",
        "a lever whose flow is missing from the window is unknown with the reason, never estimated",
        "cash to free is the days over target times the daily flow; payables free cash by paying at the target, not before",
        "nothing here reads a provider or persists anything",
    ],
}

__all__ = ["LEVERS", "WORKING_CAPITAL_MANIFEST", "WORKING_CAPITAL_PLAN_SCHEMA", "WORKING_CAPITAL_SCHEMA", "Lever", "WorkingCapital", "WorkingCapitalError", "WorkingCapitalPlan", "build_working_capital", "compile_working_capital_plan", "verify_working_capital"]
