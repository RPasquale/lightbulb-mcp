"""The customer ledger: what each customer is worth and how they pay, from the sales invoices the ledger already holds.

Customer profitability and cohorts read the fulfilment chain, which a
services company with only its ledger connected does not have.  Its sales
invoices carry most of what an owner asks about customers: who brought the
revenue, how concentrated it is, who owes what and how old it is, and how
long each customer takes to pay.  ``build_customer_ledger`` reads the
ledger's sales invoice page for a window, bound to its read by digest as
every adopted source is, and seals per customer: invoices, revenue in the
window, share of revenue, the balance outstanding, how much of it is past
due and by how long, and the realised days to pay on the invoices that were
paid.  It raises the findings an owner acts on: one customer carrying more
than the plan's concentration ceiling, a balance past due beyond the plan's
tolerance, and a customer whose paying has slowed.

The page is read as the platform returns it: Spring's governed
``lightbulb.xero_close_source_page.v1`` projection (source_ref,
counterparty, total, open balance, transaction date; it states no due date)
or a provider-body Xero ``Invoices`` page of type ACCREC (which does).  A
due date the page does not carry comes from the plan's terms, and the
document says so.  A paid invoice on the governed page shows a nil balance
but no paid date, so realised days to pay are known only from a page that
carries ``FullyPaidOnDate``; otherwise they are unknown and the note says
why.  Cost to serve is not in the invoices, so this is revenue and cash
behaviour, not profit; the customer profitability document remains the one
that answers profit when the chains exist.  Nothing here reads a provider or
persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp

CUSTOMER_LEDGER_PLAN_SCHEMA = "lightbulb.customer_ledger_plan.v1"
CUSTOMER_LEDGER_SCHEMA = "lightbulb.customer_ledger.v1"
CUSTOMER_LEDGER_MANIFEST: dict[str, Any] = {"engine": "customer_ledger", "kind": "intelligence_document", "reads": ("ledger_invoices",), "writes": ()}
LEDGER_INVOICE_TOOLS: tuple[str, ...] = ("xero.list_invoices", "quickbooks.list_invoices", "host.ledger_invoices")
AGING_BUCKETS: tuple[str, ...] = ("current", "1-30", "31-60", "61-90", "90+")
_HUNDRED = Decimal("100")
_PCT = Decimal("0.01")
_DAYS = Decimal("0.1")
_VOID = frozenset({"VOIDED", "DELETED", "DRAFT"})


class CustomerLedgerError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CustomerLedgerError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class CustomerLedgerPlan(StrictModel):
    schema_id: str = Field(default=CUSTOMER_LEDGER_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    terms_days: int = Field(default=30, ge=0, le=365)
    concentration_ceiling_percent: Decimal = Field(default=Decimal("40.00"), validate_default=True)
    overdue_tolerance_days: int = Field(default=14, ge=0, le=365)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("concentration_ceiling_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CustomerLedgerPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(CustomerLedgerPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_customer_ledger_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> CustomerLedgerPlan:
    return seal(CustomerLedgerPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class CustomerRow(StrictModel):
    customer_ref: OpaqueRef
    name: ShortText
    invoices: int = Field(ge=0)
    revenue: Decimal
    revenue_share_percent: Decimal
    outstanding: Decimal
    overdue: Decimal
    oldest_overdue_days: int = Field(ge=0)
    aging: dict[str, Decimal] = Field(default_factory=dict)
    paid_invoices: int = Field(ge=0)
    realised_days_to_pay: Decimal | None = None
    rank: int = Field(ge=1)
    flags: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=6)

    @field_validator("flags", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("revenue", "revenue_share_percent", "outstanding", "overdue", "realised_days_to_pay", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("aging", mode="before")
    @classmethod
    def _aging(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="aging") for key, item in dict(value or {}).items()}


class CustomerLedger(StrictModel):
    schema_id: str = Field(default=CUSTOMER_LEDGER_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    rows: tuple[CustomerRow, ...] = Field(max_length=2000)
    customers: int = Field(ge=0)
    invoices: int = Field(ge=0)
    revenue: Decimal
    outstanding: Decimal
    overdue: Decimal
    top_customer_share_percent: Decimal | None = None
    top_three_share_percent: Decimal | None = None
    due_basis: ShortText
    paid_dates_known: bool
    rejected: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=4)
    ledger_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("rows", "rejected", "notes", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("revenue", "outstanding", "overdue", "top_customer_share_percent", "top_three_share_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("window_start", "window_end", "as_of")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CustomerLedger":
        if (self.revenue, self.outstanding, self.overdue, self.customers) != (_money(sum((row.revenue for row in self.rows), Decimal("0"))), _money(sum((row.outstanding for row in self.rows), Decimal("0"))), _money(sum((row.overdue for row in self.rows), Decimal("0"))), len(self.rows)):
            raise ValueError("the totals count the rows")
        if not skip_digests(info) and self.ledger_digest != sealed_digest(CustomerLedger, self, "ledger_digest"):
            raise ValueError("ledger_digest must commit the exact document")
        return self

    def row(self, customer_ref: str) -> CustomerRow:
        found = next((item for item in self.rows if item.customer_ref == customer_ref), None)
        if found is None:
            raise LookupError(f"no customer {customer_ref}")
        return found

    def render(self) -> str:
        lines = [f"**Customers from the ledger** ({self.company_ref}, {self.window_start[:10]} to {self.window_end[:10]}): {self.verdict}"]
        lines.extend(f"- {row}" for row in self.recommendations)
        return "\n".join(lines)


def ledger_invoice_rows(page: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Sales invoice rows read into one shape from the governed page or a provider body; nothing is inferred."""

    from lightbulb.provider_payloads import XERO_CLOSE_SOURCE_PAGE_SCHEMA, first_present, governed_schema

    raw = detached(page)
    if governed_schema(raw) == XERO_CLOSE_SOURCE_PAGE_SCHEMA:
        _require(raw.get("transaction_type") == "invoice", "INVOICE_PAGE_WRONG_TYPE", f"the governed page carries {raw.get('transaction_type')} records, not sales invoices")
        return [{"invoice_ref": str(item.get("source_ref") or ""), "customer_ref": str(item.get("counterparty_ref") or ""), "customer": str(item.get("counterparty_name") or ""), "date": str(item.get("transaction_date") or ""), "due": "", "paid_on": "", "total": item.get("total_amount"), "outstanding": item.get("open_balance"), "currency": str(item.get("currency") or ""), "status": str(item.get("source_status") or ""), "kind": "ACCREC"} for item in (dict(row) for row in raw.get("records") or [])]
    if isinstance(raw, Mapping):
        rows = raw.get("Invoices") or (raw.get("QueryResponse") or {}).get("Invoice") or raw.get("invoices") or raw.get("data") or []
    else:
        rows = list(raw)
    out = []
    for item in rows:
        row = dict(item)
        contact = row.get("Contact") or row.get("CustomerRef") or {}
        out.append({"invoice_ref": str(row.get("InvoiceID") or row.get("Id") or row.get("id") or ""), "customer_ref": str((contact.get("ContactID") or contact.get("value") or "") if isinstance(contact, Mapping) else ""), "customer": str((contact.get("Name") or contact.get("name") or "") if isinstance(contact, Mapping) else (contact or "")), "date": str(first_present(row, "DateString", "Date", "TxnDate") or ""), "due": str(first_present(row, "DueDateString", "DueDate") or ""), "paid_on": str(first_present(row, "FullyPaidOnDate") or ""), "total": row.get("Total", row.get("TotalAmt")), "outstanding": row.get("AmountDue", row.get("Balance")), "currency": str(row.get("CurrencyCode") or (dict(row.get("CurrencyRef") or {})).get("value") or ""), "status": str(row.get("Status") or ""), "kind": str(row.get("Type") or "ACCREC")})
    return out


def build_customer_ledger(plan: CustomerLedgerPlan | Mapping[str, Any], *, source: Mapping[str, Any], window_start: str, window_end: str, as_of: str) -> CustomerLedger:
    """The sealed customer ledger from one sales invoice read over the window."""

    from lightbulb.company_execution_bridge import ObservationProvenance
    from lightbulb.provider_payloads import ProviderPayloadError, provider_timestamp

    parsed_plan = plan if isinstance(plan, CustomerLedgerPlan) else CustomerLedgerPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    start, end = timestamp(window_start, field_name="window_start"), timestamp(window_end, field_name="window_end")
    _require(parsed(end) > parsed(start), "WINDOW_EMPTY", "window_end must follow window_start")
    _require(isinstance(source, Mapping) and source.get("provenance") is not None and source.get("payload") is not None, "SOURCE_NOT_SEALED", "the invoice source carries its provenance and the exact payload the read returned")
    read = ObservationProvenance.model_validate(detached(source["provenance"]))
    _require(read.provenance_digest != GENESIS_DIGEST and read.source_tool in LEDGER_INVOICE_TOOLS, "SOURCE_TOOL_MISMATCH", f"sales invoices are read with one of {list(LEDGER_INVOICE_TOOLS)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(source["payload"])), "SOURCE_DIGEST_MISMATCH", "the page must be the exact output the read returned")
    _require(parsed(read.completed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the read must complete before the document is built")

    rows = ledger_invoice_rows(source["payload"])
    by_customer: dict[str, dict[str, Any]] = {}
    rejected: list[str] = []
    due_from_terms = False
    paid_known = False
    invoices = 0
    for row in rows:
        ref = row["invoice_ref"] or "unnamed"
        if row["kind"] not in ("", "ACCREC", "Invoice", "invoice"):
            continue
        if row["status"].upper() in _VOID:
            rejected.append(f"{ref}: {row['status'].lower()}")
            continue
        if not row["customer"] and not row["customer_ref"]:
            rejected.append(f"{ref}: no customer named")
            continue
        if row["total"] is None or row["outstanding"] is None or not row["date"]:
            rejected.append(f"{ref}: no total, balance or date")
            continue
        if row["currency"] and row["currency"].upper() != parsed_plan.currency:
            rejected.append(f"{ref}: in {row['currency']}, the ledger runs in {parsed_plan.currency}")
            continue
        try:
            issued = provider_timestamp(row["date"], field_name="date")
            due = provider_timestamp(row["due"], field_name="due") if row["due"] else None
            paid_on = provider_timestamp(row["paid_on"], field_name="paid_on") if row["paid_on"] else None
        except ProviderPayloadError as exc:
            rejected.append(f"{ref}: {exc}")
            continue
        if not (parsed(start) <= parsed(issued) < parsed(end)):
            continue
        if due is None:
            due = (parsed(issued) + timedelta(days=parsed_plan.terms_days)).isoformat().replace("+00:00", "Z")
            due_from_terms = True
        total, outstanding = _money(row["total"]), _money(row["outstanding"])
        key = row["customer_ref"] or f"name:{stable_digest(row['customer'])[:16]}"
        bucket = by_customer.setdefault(key, {"customer_ref": key[:200], "name": (row["customer"] or key)[:300], "invoices": 0, "revenue": Decimal("0"), "outstanding": Decimal("0"), "overdue": Decimal("0"), "oldest": 0, "aging": {name: Decimal("0") for name in AGING_BUCKETS}, "paid": 0, "days_to_pay": []})
        bucket["invoices"] += 1
        invoices += 1
        bucket["revenue"] += total
        if outstanding > 0:
            bucket["outstanding"] += outstanding
            late = (parsed(at) - parsed(due)).days
            if late > 0:
                bucket["overdue"] += outstanding
                bucket["oldest"] = max(bucket["oldest"], late)
            name = "current" if late <= 0 else "1-30" if late <= 30 else "31-60" if late <= 60 else "61-90" if late <= 90 else "90+"
            bucket["aging"][name] += outstanding
        elif outstanding == 0 and total > 0:
            bucket["paid"] += 1
            if paid_on is not None:
                paid_known = True
                bucket["days_to_pay"].append(Decimal((parsed(paid_on) - parsed(issued)).days))
    revenue = _money(sum((item["revenue"] for item in by_customer.values()), Decimal("0")))
    ranked = sorted(by_customer.values(), key=lambda item: (-item["revenue"], item["name"]))
    out_rows: list[dict[str, Any]] = []
    recommendations: list[str] = []
    for index, item in enumerate(ranked, start=1):
        share = None if revenue <= 0 else (item["revenue"] / revenue * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)
        realised = None if not item["days_to_pay"] else (sum(item["days_to_pay"], Decimal("0")) / len(item["days_to_pay"])).quantize(_DAYS, rounding=ROUND_HALF_UP)
        flags: list[str] = []
        if share is not None and share > parsed_plan.concentration_ceiling_percent:
            flags.append("concentration")
            recommendations.append(f"{item['name']} is {share}% of revenue, over the {parsed_plan.concentration_ceiling_percent}% ceiling: losing them costs {item['revenue']} {parsed_plan.currency} of the window's revenue")
        if item["overdue"] > 0 and item["oldest"] > parsed_plan.overdue_tolerance_days:
            flags.append("overdue")
            recommendations.append(f"{item['name']} owes {item['overdue']} {parsed_plan.currency} past due, the oldest {item['oldest']} day(s): chase it before it ages further")
        if realised is not None and realised > parsed_plan.terms_days + parsed_plan.overdue_tolerance_days:
            flags.append("slow_payer")
            recommendations.append(f"{item['name']} takes {realised} day(s) to pay against {parsed_plan.terms_days}-day terms")
        out_rows.append({"customer_ref": item["customer_ref"], "name": item["name"], "invoices": item["invoices"], "revenue": str(_money(item["revenue"])), "revenue_share_percent": str(share if share is not None else Decimal("0.00")), "outstanding": str(_money(item["outstanding"])), "overdue": str(_money(item["overdue"])), "oldest_overdue_days": item["oldest"], "aging": {name: str(_money(value)) for name, value in item["aging"].items() if value > 0}, "paid_invoices": item["paid"], "realised_days_to_pay": None if realised is None else str(realised), "rank": index, "flags": flags})
    outstanding = _money(sum((Decimal(row["outstanding"]) for row in out_rows), Decimal("0")))
    overdue = _money(sum((Decimal(row["overdue"]) for row in out_rows), Decimal("0")))
    top = None if not out_rows or revenue <= 0 else Decimal(out_rows[0]["revenue_share_percent"])
    top3 = None if not out_rows or revenue <= 0 else (sum((Decimal(row["revenue"]) for row in out_rows[:3]), Decimal("0")) / revenue * _HUNDRED).quantize(_PCT, rounding=ROUND_HALF_UP)
    notes: list[str] = []
    if due_from_terms:
        notes.append(f"the page states no due dates; each invoice is due {parsed_plan.terms_days} day(s) from its date under the plan's terms")
    if not paid_known:
        notes.append("the page carries no paid dates, so the days customers take to pay are unknown; a provider-body invoice page with FullyPaidOnDate would give them")
    if not out_rows:
        notes.append("no sales invoice on the page falls in the window")
    if not recommendations:
        recommendations.append("no customer is over the concentration ceiling, past due beyond tolerance, or slow to pay" if out_rows else "nothing to say until the window holds an invoice")
    verdict = f"{len(out_rows)} customer(s), {invoices} invoice(s), revenue {revenue} {parsed_plan.currency}; {outstanding} outstanding of which {overdue} past due" + ("" if top is None else f"; top customer {top}%, top three {top3}%") + (f"; {len(rejected)} row(s) rejected" if rejected else "")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "rows": out_rows, "customers": len(out_rows), "invoices": invoices, "revenue": str(revenue), "outstanding": str(outstanding), "overdue": str(overdue), "top_customer_share_percent": None if top is None else str(top), "top_three_share_percent": None if top3 is None else str(top3), "due_basis": "plan terms" if due_from_terms else "the page's due dates", "paid_dates_known": paid_known, "rejected": [item[:300] for item in rejected][:200], "notes": [item[:300] for item in notes][:12], "verdict": verdict[:300], "recommendations": [item[:300] for item in recommendations][:24], "source_digests": [read.provenance_digest]}
    return seal(CustomerLedger, {key: value for key, value in payload.items() if value is not None}, "ledger_digest")


def verify_customer_ledger(value: Any) -> CustomerLedger:
    return value if isinstance(value, CustomerLedger) else CustomerLedger.model_validate(dict(detached(value)))


__all__ = ["AGING_BUCKETS", "CUSTOMER_LEDGER_MANIFEST", "CUSTOMER_LEDGER_PLAN_SCHEMA", "CUSTOMER_LEDGER_SCHEMA", "LEDGER_INVOICE_TOOLS", "CustomerLedger", "CustomerLedgerError", "CustomerLedgerPlan", "CustomerRow", "build_customer_ledger", "compile_customer_ledger_plan", "ledger_invoice_rows", "verify_customer_ledger"]
