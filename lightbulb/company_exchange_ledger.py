"""Posting the company exchange to the ledger: the bill and the invoice written into QuickBooks or Xero, as the platform's governed finance writes accept them.

The books already hold what the exchange reached (``company_exchange_books``): the
buyer's bill in the payables chain, the seller's sale and invoice in the revenue chain.
The accounting system of record did not.  Posting writes each there through the
platform's Governed Connector Execution, never directly: the platform classifies the
write, asks its financial reviewer for approval, and writes it once under the action's
idempotency key.

* **The ledger map** says which contact in the ledger each trading partner is (a
  QuickBooks vendor or customer Id, a Xero ContactID), which expense account a bill's
  lines go to, and which item or sales account an invoice's lines go to.  The owner sets
  it; nothing is guessed, and a partner the map does not name is not posted.
* **A posting** is the provider's own document, built to the platform's governed
  finance contract (``GovernedFinancialEffectClassifier``).  Its only input is the
  ``payload``; its lines carry the exchange invoice's exact quantities, prices and
  amounts; tax is not applicable, since exchange documents carry none; and there is no
  exchange rate.  Its document number is the invoice's ledger reference: ``LB-AP-`` on
  the buyer's bill, ``LB-CTC-`` on the seller's invoice.
* **QuickBooks** binds that reference as the write's correlation, and its payment
  observers find the document by it.  So a posted bill gives the payables chain the
  bill write receipt its payment is scheduled against (``bill_write_receipt``).  A
  posted invoice already carries the correlation of its revenue case, so the invoice
  payment observer settles it.
* **Xero** takes the same document as a draft, with the reference as its number.  The
  platform binds no correlation for Xero writes and has no Xero payment observer yet,
  so a Xero posting records the document and nothing is observed from it.

Nothing here posts, reads a provider or moves money.  The console plans each posting as
an owner action (``post_to_ledger`` under the mandate), and the act loop dispatches it.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, detached, seal, sealed_digest, skip_digests, timestamp

EXCHANGE_LEDGER_MAP_SCHEMA = "lightbulb.exchange_ledger_map.v1"
EXCHANGE_LEDGER_POSTING_SCHEMA = "lightbulb.exchange_ledger_posting.v1"
LEDGER_PROVIDERS: tuple[str, ...] = ("quickbooks", "xero")
#: The governed finance write each provider takes for each side of a trade.
LEDGER_TOOLS: dict[tuple[str, str], str] = {
    ("quickbooks", "payable"): "quickbooks.create_bill",
    ("quickbooks", "receivable"): "quickbooks.create_invoice",
    ("xero", "payable"): "xero.create_bill",
    ("xero", "receivable"): "xero.create_invoice",
}
#: The writes whose document number the platform binds as their correlation, so a payment observer can find them.
CORRELATED_TOOLS: frozenset[str] = frozenset({"quickbooks.create_bill", "quickbooks.create_invoice"})
_MONEY_PLACES = 2


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        from lightbulb.company_exchange import ExchangeError

        raise ExchangeError(code, message)


def _refs(value: Any, field: str) -> dict[str, str]:
    raw = dict(detached(value or {}))
    refs: dict[str, str] = {}
    for key, item in raw.items():
        text = str(item or "").strip()
        _require(bool(str(key).strip()) and bool(text) and len(text) <= 300 and not any(character.isspace() for character in text), "LEDGER_MAP_INVALID", f"{field} maps {key!r} to a ledger id that is empty, too long or carries spaces")
        refs[str(key)] = text
    return dict(sorted(refs.items()))


class ExchangeLedgerMap(StrictModel):
    """Who each trading partner is in the ledger, and where a bill's and an invoice's lines go."""

    schema_id: str = Field(default=EXCHANGE_LEDGER_MAP_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    provider: Literal["quickbooks", "xero"]
    currency: CurrencyCode
    suppliers: dict[str, str] = Field(default_factory=dict)
    customers: dict[str, str] = Field(default_factory=dict)
    bill_account: ShortText | None = None
    sales_item: ShortText | None = None
    sales_account: ShortText | None = None
    items: dict[str, str] = Field(default_factory=dict)
    updated_at: str
    map_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("suppliers", "customers", "items", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: ValidationInfo) -> dict[str, str]:
        return _refs(value, str(info.field_name))

    @field_validator("updated_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="updated_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ExchangeLedgerMap":
        for field in ("bill_account", "sales_item", "sales_account"):
            value = getattr(self, field)
            if value is not None and (not value.strip() or any(character.isspace() for character in value)):
                raise ValueError(f"{field} is a ledger id without spaces")
        if self.provider == "quickbooks" and self.sales_account is not None:
            raise ValueError("a QuickBooks invoice line names an item (sales_item), not a sales account")
        if self.provider == "xero" and self.sales_item is not None:
            raise ValueError("a Xero invoice line names a sales account (sales_account); its item codes go in items")
        if not skip_digests(info) and self.map_digest != sealed_digest(ExchangeLedgerMap, self, "map_digest"):
            raise ValueError("map_digest must commit the exact ledger map")
        return self

    def render(self) -> str:
        where = {"quickbooks": "QuickBooks", "xero": "Xero"}[self.provider]
        lines = [f"**Ledger map** ({where}, {self.currency}): {len(self.suppliers)} supplier(s), {len(self.customers)} customer(s); bills to {self.bill_account or 'no account yet'}; "
                 + (f"invoice lines to item {self.sales_item}" if self.provider == "quickbooks" and self.sales_item else f"invoice lines to account {self.sales_account}" if self.sales_account else "no invoice line target yet")
                 + (f", {len(self.items)} item(s) mapped" if self.items else "")]
        lines.extend(f"- supplier {party} is {ref}" for party, ref in self.suppliers.items())
        lines.extend(f"- customer {party} is {ref}" for party, ref in self.customers.items())
        return "\n".join(lines)


def compile_ledger_map(company_ref: str, *, provider: str, currency: str, now: str, suppliers: Mapping[str, Any] | None = None, customers: Mapping[str, Any] | None = None,
                       bill_account: str | None = None, sales_item: str | None = None, sales_account: str | None = None, items: Mapping[str, Any] | None = None) -> ExchangeLedgerMap:
    _require(provider in LEDGER_PROVIDERS, "LEDGER_PROVIDER_UNSUPPORTED", f"the exchange posts to {' or '.join(LEDGER_PROVIDERS)}")
    return seal(ExchangeLedgerMap, {"company_ref": company_ref, "provider": provider, "currency": str(currency).upper(), "suppliers": dict(suppliers or {}), "customers": dict(customers or {}),
                                    "bill_account": bill_account or None, "sales_item": sales_item or None, "sales_account": sales_account or None, "items": dict(items or {}), "updated_at": now}, "map_digest")


def verify_ledger_map(value: Any) -> ExchangeLedgerMap:
    return value if isinstance(value, ExchangeLedgerMap) else ExchangeLedgerMap.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "stored"}})


def _number(value: Decimal, field: str) -> int | float:
    """An exact amount as the JSON number the platform's contract requires: whole values as integers, cents as the shortest decimal."""

    _require(value > 0, "LEDGER_AMOUNT_INVALID", f"{field} must be more than nothing")
    _require(-value.as_tuple().exponent <= _MONEY_PLACES or value == value.quantize(Decimal(1).scaleb(-_MONEY_PLACES)), "LEDGER_AMOUNT_SCALE", f"{field} {value} carries more than {_MONEY_PLACES} decimal places")
    return int(value) if value == value.to_integral_value() else float(value)


def _quantity(value: Decimal) -> int | float:
    return int(value) if value == value.to_integral_value() else float(value)


def ledger_posting(thread: Any, *, party_ref: str, ledger_map: ExchangeLedgerMap | Mapping[str, Any]) -> dict[str, Any]:
    """The governed finance write that posts an exchange's invoice to the ledger: the tool, its only input (the payload), and the reference and correlation it carries."""

    from lightbulb.company_exchange_books import invoice_due_at, ledger_correlation, ledger_reference

    parsed = verify_ledger_map(ledger_map)
    _require(party_ref in (thread.buyer, thread.seller), "EXCHANGE_PARTY_NOT_IN_THREAD", f"{party_ref} neither buys nor sells in {thread.exchange_ref}")
    invoice = thread.document("invoice")
    _require(invoice is not None, "EXCHANGE_NOT_INVOICED", f"{thread.exchange_ref} has no invoice to post")
    _require(thread.currency == parsed.currency, "LEDGER_CURRENCY_MISMATCH", f"the exchange is in {thread.currency}; the ledger map posts in {parsed.currency}")
    side = "payable" if party_ref == thread.buyer else "receivable"
    counterparty = thread.seller if side == "payable" else thread.buyer
    contact = (parsed.suppliers if side == "payable" else parsed.customers).get(counterparty)
    _require(contact is not None, "LEDGER_CONTACT_UNMAPPED", f"the ledger map names no {'supplier' if side == 'payable' else 'customer'} for {counterparty}: set it with company_exchange ledger")
    assert contact is not None
    tool = LEDGER_TOOLS[(parsed.provider, side)]
    reference = ledger_reference(invoice.document_digest, side=side)
    issued, due = invoice.issued_at[:10], invoice_due_at(invoice)[:10]
    note = f"Lightbulb company exchange {thread.exchange_ref}: invoice {invoice.document_digest[:12]} from {thread.seller} to {thread.buyer}"
    lines: list[dict[str, Any]] = []
    for index, line in enumerate(invoice.lines):
        assert line.unit_price is not None and line.amount is not None
        description = f"{line.item_ref}: {line.quantity} {line.unit} at {line.unit_price}" + (f" ({line.note})" if line.note else "")
        amount, price, quantity = _number(line.amount, f"line {index + 1} amount"), _number(line.unit_price, f"line {index + 1} unit price"), _quantity(line.quantity)
        if parsed.provider == "quickbooks" and side == "payable":
            _require(parsed.bill_account is not None, "LEDGER_ACCOUNT_UNMAPPED", "the ledger map names no expense account for bills (bill_account)")
            lines.append({"Amount": amount, "Description": description[:4000], "DetailType": "AccountBasedExpenseLineDetail",
                          "AccountBasedExpenseLineDetail": {"AccountRef": {"value": parsed.bill_account}}})
        elif parsed.provider == "quickbooks":
            item = parsed.items.get(line.item_ref) or parsed.sales_item
            _require(item is not None, "LEDGER_ITEM_UNMAPPED", f"the ledger map names no QuickBooks item for {line.item_ref} and no sales_item for the rest")
            lines.append({"Amount": amount, "Description": description[:4000], "DetailType": "SalesItemLineDetail",
                          "SalesItemLineDetail": {"ItemRef": {"value": item}, "Qty": quantity, "UnitPrice": price}})
        else:
            account = parsed.bill_account if side == "payable" else parsed.sales_account
            _require(account is not None, "LEDGER_ACCOUNT_UNMAPPED", f"the ledger map names no Xero account for {'bills (bill_account)' if side == 'payable' else 'invoices (sales_account)'}")
            row: dict[str, Any] = {"Description": description[:4000], "Quantity": quantity, "UnitAmount": price, "LineAmount": amount, "AccountCode": account, "TaxType": "NONE"}
            if parsed.items.get(line.item_ref):
                row["ItemCode"] = parsed.items[line.item_ref]
            lines.append(row)
    if parsed.provider == "quickbooks":
        payload: dict[str, Any] = {"VendorRef" if side == "payable" else "CustomerRef": {"value": contact}, "DocNumber": reference, "TxnDate": issued, "DueDate": due,
                                   "CurrencyRef": {"value": thread.currency}, "GlobalTaxCalculation": "NotApplicable", "PrivateNote": note, "Line": lines}
    else:
        payload = {"Type": "ACCPAY" if side == "payable" else "ACCREC", "Contact": {"ContactID": contact}, "InvoiceNumber": reference, "Reference": thread.exchange_ref,
                   "Date": issued, "DueDate": due, "CurrencyCode": thread.currency, "LineAmountTypes": "NoTax", "LineItems": lines}
    return {"schema": EXCHANGE_LEDGER_POSTING_SCHEMA, "exchange_ref": thread.exchange_ref, "side": side, "counterparty": counterparty, "provider": parsed.provider, "tool": tool,
            "arguments": {"payload": payload}, "reference": reference, "correlation_sha256": ledger_correlation(reference) if tool in CORRELATED_TOOLS else None,
            "total": str(invoice.total), "currency": thread.currency, "issued_on": issued, "due_on": due, "invoice_digest": invoice.document_digest, "map_digest": parsed.map_digest}


def bill_write_receipt(action: Any) -> dict[str, Any]:
    """The payables chain's bill write receipt from a bill the platform posted to QuickBooks: the correlation it bound to the bill's reference, and the write's journal."""

    from lightbulb.company_exchange_books import ledger_correlation
    from lightbulb.owner_actions import verify_owner_action

    parsed = verify_owner_action(action)
    _require(parsed.action_kind == "post_to_ledger" and parsed.tool in LEDGER_TOOLS.values(), "LEDGER_POSTING_REQUIRED", "a bill write receipt comes from a ledger posting")
    _require(parsed.tool in CORRELATED_TOOLS and parsed.tool.endswith("create_bill"), "LEDGER_CORRELATION_UNAVAILABLE", f"{parsed.tool} carries no correlation the platform binds; a payment against it cannot be observed yet")
    _require(parsed.status == "done" and parsed.receipt is not None and bool(parsed.receipt.get("journal_ref")), "LEDGER_POSTING_NOT_DONE", f"the posting is {parsed.status}; the bill is not in the ledger yet")
    assert parsed.receipt is not None
    reference = str(dict(parsed.arguments["payload"])["DocNumber"])
    return {"state": "written", "provider_correlation_sha256": ledger_correlation(reference), "write_journal_ref": str(parsed.receipt["journal_ref"])[:200],
            "reference": reference, "provider_ref": parsed.receipt.get("provider_ref"), "tool": parsed.tool, "action_ref": parsed.action_ref}


__all__ = [
    "CORRELATED_TOOLS",
    "EXCHANGE_LEDGER_MAP_SCHEMA",
    "EXCHANGE_LEDGER_POSTING_SCHEMA",
    "LEDGER_PROVIDERS",
    "LEDGER_TOOLS",
    "ExchangeLedgerMap",
    "bill_write_receipt",
    "compile_ledger_map",
    "ledger_posting",
    "verify_ledger_map",
]
