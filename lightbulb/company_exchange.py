"""Trading with other businesses: a card others can read, and sealed commercial documents that pass between two companies' agents.

Two businesses' agents trade in seven kinds of document, each sealed and each answering the one before it:

    rfq (buyer -> seller) -> quote (seller -> buyer) [-> counter (buyer -> seller) -> quote]* -> purchase_order (buyer -> seller)
        -> order_acknowledgement (seller -> buyer: accepted or declined) -> invoice (seller -> buyer)
        -> remittance (buyer -> seller: the invoice is paid, when and under which reference)

A buyer may answer a quote with a counter-offer instead of an order, at most twice in an exchange:
the same lines at lower unit prices, with its reason; the seller answers with a revised quote.

* **The company card** says who the company is to others: its party reference (an
  opaque name, never an address), what it sells (the catalog version in force, with
  list prices), which documents it answers, its payment terms, how long its quotes
  hold, and which documents its agent answers alone under the owner's mandate.
* **A quote** prices the request's lines from that catalog. **A purchase order**
  accepts one exact quote before it lapses, with the same lines and prices. **An
  acknowledgement** accepts or declines that order. **An invoice** bills the accepted
  order in full. **A remittance** tells the seller the invoice is paid in full: when the
  money left and the reference the payment carries, so the seller expects it and does not
  chase it; the payment itself is made, and seen in the bank, outside the exchange.
* **Being found.** A card may say what the company does (``about``), the words it is
  found by (``keywords``) and what each offer is called (an offer's ``name``). When the
  owner lists the card in the platform's directory, other companies' agents search it by
  those words; unlisted, a company is reached only by the address it gives out.
* **``verify_thread``** checks a whole exchange: each document answers the one before
  it (by digest), comes from the party whose turn it is and goes to the other, and
  keeps the currency, the lines and the prices. Any break is refused with its reason.

Nothing here sends, records or charges anything.  The console side
(``company_exchange_surface``) records every document, asks the mandate before any is
issued, and hands it to the host's transport only when the mandate or the owner allows.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp

COMPANY_CARD_SCHEMA = "lightbulb.company_card.v1"
COMMERCIAL_DOCUMENT_SCHEMA = "lightbulb.commercial_document.v1"
EXCHANGE_THREAD_SCHEMA = "lightbulb.commercial_exchange_thread.v1"
EXCHANGE_MANIFEST: dict[str, Any] = {"engine": "commercial_exchange", "kind": "communication", "reads": ("price_catalog", "owner_mandate"), "writes": ("commercial_exchange",)}
DocumentKind = Literal["rfq", "quote", "purchase_order", "order_acknowledgement", "invoice", "remittance", "counter"]
DOCUMENT_KINDS: tuple[str, ...] = ("rfq", "quote", "purchase_order", "order_acknowledgement", "invoice", "remittance", "counter")
# which document answers which, and who sends each; a quote may instead be answered by a counter (see COUNTER_ANSWERS)
NEXT_KIND: dict[str, str] = {"rfq": "quote", "quote": "purchase_order", "purchase_order": "order_acknowledgement", "order_acknowledgement": "invoice", "invoice": "remittance", "counter": "quote"}
COUNTER_ANSWERS = "quote"
FROM_ROLE: dict[str, str] = {"rfq": "buyer", "quote": "seller", "purchase_order": "buyer", "order_acknowledgement": "seller", "invoice": "seller", "remittance": "buyer", "counter": "buyer"}
# the mandate action each document is, when this company issues it
DOCUMENT_ACTION: dict[str, str] = {"rfq": "message_supplier", "quote": "send_quote", "purchase_order": "place_order", "order_acknowledgement": "accept_order", "invoice": "send_invoice",
                                   "remittance": "message_supplier", "counter": "message_supplier"}
ThreadStatus = Literal["requested", "quoted", "countered", "ordered", "accepted", "declined", "invoiced", "remitted"]
STATUS_AFTER: dict[str, str] = {"rfq": "requested", "quote": "quoted", "counter": "countered", "purchase_order": "ordered", "invoice": "invoiced", "remittance": "remitted"}
MAX_COUNTERS = 2
# the six documents of a trade, and a counter and a revised quote for each counter-offer
MAX_DOCUMENTS = 6 + 2 * MAX_COUNTERS
MAX_LINES = 100
MAX_OFFERS = 200
MAX_KEYWORDS = 12
# a keyword: letters or digits in any script, with spaces, apostrophes, ampersands, full stops and hyphens between them
KEYWORD = re.compile(r"^[^\W_](?:[^\W_]|[ '&.-]){0,39}$")
_CENT = Decimal("0.01")


class ExchangeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ExchangeError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _money(value: Decimal) -> Decimal:
    return value.quantize(_CENT, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# The company card
# --------------------------------------------------------------------------- #


class CardOffer(StrictModel):
    item_ref: OpaqueRef
    kind: Literal["plan", "sku", "service", "rate"]
    unit: ShortText = "each"
    list_price: Decimal
    billing_period: Literal["once", "month", "year", "hour", "day"] = "once"
    # what a buyer searching the directory reads; documents still name the item by its reference
    name: ShortText | None = None

    @field_validator("list_price", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="list_price")


class CompanyCard(StrictModel):
    """Who the company is to other businesses and their agents: what it sells, on which terms, and what its agent answers alone."""

    schema_id: str = Field(default=COMPANY_CARD_SCHEMA, alias="schema")
    party_ref: OpaqueRef
    display_name: ShortText
    country: ShortText | None = None
    currency: CurrencyCode
    offers: tuple[CardOffer, ...] = Field(default_factory=tuple, max_length=MAX_OFFERS)
    catalog_version_ref: ShortText | None = None
    catalog_digest: Sha256Digest | None = None
    accepts: tuple[DocumentKind, ...] = Field(default_factory=tuple)
    answers_alone: tuple[DocumentKind, ...] = Field(default_factory=tuple)
    terms_days: int = Field(ge=0, le=365)
    quote_valid_days: int = Field(ge=1, le=365)
    contact_ref: OpaqueRef | None = None
    # what the company does and the words it is found by in the directory; absent from cards built before, so their seals hold
    about: ShortText | None = None
    keywords: tuple[ShortText, ...] | None = None
    issued_at: str
    card_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("offers", "accepts", "answers_alone", "keywords", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("keywords")
    @classmethod
    def _keywords(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        if not value or len(value) > MAX_KEYWORDS or len(set(value)) != len(value) or any(keyword != _keyword(keyword) or not KEYWORD.match(keyword) for keyword in value):
            raise ValueError(f"keywords are 1 to {MAX_KEYWORDS} distinct lowercase words or short phrases (letters, digits, spaces, apostrophes, ampersands, full stops and hyphens; at most 40 characters each)")
        return value

    @field_validator("issued_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="issued_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CompanyCard":
        refs = [offer.item_ref for offer in self.offers]
        if len(set(refs)) != len(refs):
            raise ValueError("one offer per item")
        if not set(self.answers_alone) <= set(self.accepts):
            raise ValueError("the agent answers alone only documents the company accepts")
        if not skip_digests(info) and self.card_digest != sealed_digest(CompanyCard, self, "card_digest"):
            raise ValueError("card_digest must commit the exact card")
        return self

    def offer(self, item_ref: str) -> CardOffer | None:
        return next((offer for offer in self.offers if offer.item_ref == item_ref), None)

    def render(self) -> str:
        head = f"**{self.display_name}** ({self.party_ref}): {len(self.offers)} offer(s) in {self.currency}" + (f" from catalog {self.catalog_version_ref}" if self.catalog_version_ref else "") + f"; pays and invoices on {self.terms_days} days; quotes hold {self.quote_valid_days} days"
        lines = [head]
        if self.about:
            lines.append(f"- {self.about}")
        if self.keywords:
            lines.append(f"- found by: {', '.join(self.keywords)}")
        lines.extend(f"- {f'{offer.name} ({offer.item_ref})' if offer.name else offer.item_ref}: {offer.list_price} per {offer.unit}" + ("" if offer.billing_period == "once" else f" a {offer.billing_period}") for offer in self.offers[:20])
        if self.answers_alone:
            lines.append(f"- its agent answers {', '.join(self.answers_alone)} without asking the owner")
        return "\n".join(lines)


def build_company_card(*, party_ref: str, display_name: str, currency: str, issued_at: str, offers: Sequence[Mapping[str, Any]] = (), country: str | None = None, catalog_version_ref: str | None = None, catalog_digest: str | None = None, accepts: Sequence[str] = DOCUMENT_KINDS, answers_alone: Sequence[str] = (), terms_days: int = 30, quote_valid_days: int = 30, contact_ref: str | None = None, about: str | None = None, keywords: Sequence[str] | None = None) -> CompanyCard:
    return seal(CompanyCard, {"party_ref": party_ref, "display_name": display_name, "country": country, "currency": currency, "offers": [dict(offer) for offer in offers], "catalog_version_ref": catalog_version_ref, "catalog_digest": catalog_digest, "accepts": list(accepts), "answers_alone": list(answers_alone), "terms_days": int(terms_days), "quote_valid_days": int(quote_valid_days), "contact_ref": contact_ref,
                              "about": about or None, "keywords": list(keywords) if keywords else None, "issued_at": issued_at}, "card_digest")


def _keyword(value: Any) -> str:
    return unicodedata.normalize("NFC", " ".join(str(value).split())).lower()


def normal_keywords(values: str | Sequence[Any]) -> list[str]:
    """Keywords as a card keeps them: trimmed, lowercase and distinct, in the order given (a string is split at its commas)."""

    items = str(values).split(",") if isinstance(values, str) else list(values)
    kept: list[str] = []
    for value in items:
        keyword = _keyword(value)
        if not keyword:
            continue
        _require(bool(KEYWORD.match(keyword)), "KEYWORD_INVALID", f"{str(value)[:60]!r} is not a keyword: letters and digits, with spaces, apostrophes, ampersands, full stops or hyphens between them, at most 40 characters")
        if keyword not in kept:
            kept.append(keyword)
    _require(len(kept) <= MAX_KEYWORDS, "KEYWORDS_TOO_MANY", f"a card carries at most {MAX_KEYWORDS} keywords; keep the ones buyers would search for")
    return kept


def verify_company_card(value: Any) -> CompanyCard:
    return value if isinstance(value, CompanyCard) else CompanyCard.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "stored"}})


# --------------------------------------------------------------------------- #
# The documents
# --------------------------------------------------------------------------- #


class ExchangeLine(StrictModel):
    item_ref: OpaqueRef
    quantity: Decimal
    unit: ShortText = "each"
    unit_price: Decimal | None = None
    amount: Decimal | None = None
    note: ShortText | None = None

    @field_validator("quantity", "unit_price", "amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> "ExchangeLine":
        if self.quantity <= 0:
            raise ValueError("a line asks for more than nothing")
        if (self.unit_price is None) != (self.amount is None):
            raise ValueError("a priced line carries its unit price and its amount")
        if self.unit_price is not None and self.amount != _money(self.quantity * self.unit_price):
            raise ValueError("a line's amount is its quantity times its unit price")
        return self

    def terms(self) -> tuple[str, str, str, str | None]:
        return (self.item_ref, str(self.quantity), self.unit, None if self.unit_price is None else str(self.unit_price))


class CommercialDocument(StrictModel):
    """One document in an exchange, sealed; it names the document it answers by digest."""

    schema_id: str = Field(default=COMMERCIAL_DOCUMENT_SCHEMA, alias="schema")
    kind: DocumentKind
    exchange_ref: OpaqueRef
    sequence: int = Field(ge=1, le=MAX_DOCUMENTS)
    from_party: OpaqueRef
    to_party: OpaqueRef
    issued_at: str
    currency: CurrencyCode
    lines: tuple[ExchangeLine, ...] = Field(min_length=1, max_length=MAX_LINES)
    total: Decimal | None = None
    in_reply_to: Sha256Digest | None = None
    needed_by: str | None = None
    reply_by: str | None = None
    valid_until: str | None = None
    terms_days: int | None = Field(default=None, ge=0, le=365)
    accepted: bool | None = None
    reason: ShortText | None = None
    # a remittance's: when the money left and the reference the payment carries (absent from every other document, so their seals hold)
    paid_at: str | None = None
    payment_reference: ShortText | None = None
    document_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("total", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="total")

    @field_validator("issued_at", "needed_by", "reply_by", "valid_until", "paid_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "CommercialDocument":
        if self.from_party == self.to_party:
            raise ValueError("a document goes from one party to another")
        priced = self.kind != "rfq"
        if any((line.unit_price is None) == priced for line in self.lines):
            raise ValueError("a request for quote carries no prices; every other document prices every line")
        if priced and self.total != _money(sum((line.amount for line in self.lines if line.amount is not None), Decimal("0"))):
            raise ValueError("the total is the sum of the lines")
        if not priced and self.total is not None:
            raise ValueError("a request for quote carries no total")
        if (self.kind == "rfq") != (self.in_reply_to is None) or (self.kind == "rfq") != (self.sequence == 1):
            raise ValueError("only the request for quote opens an exchange; every other document answers one before it")
        if (self.needed_by is not None or self.reply_by is not None) and self.kind != "rfq":
            raise ValueError("needed_by and reply_by belong to the request for quote")
        if (self.kind == "quote") != (self.valid_until is not None):
            raise ValueError("a quote, and only a quote, says how long it holds")
        if self.valid_until is not None and parsed(self.valid_until) <= parsed(self.issued_at):
            raise ValueError("a quote holds for some time after it is issued")
        if self.kind in ("quote", "invoice") and self.terms_days is None:
            raise ValueError("a quote and an invoice state the payment terms")
        if (self.kind == "order_acknowledgement") != (self.accepted is not None):
            raise ValueError("an acknowledgement, and only an acknowledgement, accepts or declines")
        if self.accepted is False and not self.reason:
            raise ValueError("a declined order says why")
        if (self.kind == "remittance") != (self.paid_at is not None and self.payment_reference is not None) or (self.kind != "remittance" and (self.paid_at or self.payment_reference)):
            raise ValueError("a remittance, and only a remittance, says when the payment was made and the reference it carries")
        if self.paid_at is not None and parsed(self.paid_at) > parsed(self.issued_at):
            raise ValueError("a remittance reports a payment already made")
        if not skip_digests(info) and self.document_digest != sealed_digest(CommercialDocument, self, "document_digest"):
            raise ValueError("document_digest must commit the exact document")
        return self

    def render(self) -> str:
        what = {"rfq": "requests a quote for", "quote": "quotes", "purchase_order": "orders", "order_acknowledgement": "accepts the order for" if self.accepted else "declines the order for", "invoice": "invoices",
                "remittance": "has paid for", "counter": "offers instead"}[self.kind]
        items = ", ".join(f"{line.quantity} x {line.item_ref}" for line in self.lines[:5])
        return f"{self.from_party} {what} {items}" + (f" ({self.total} {self.currency})" if self.total is not None else "") + (f"; holds until {self.valid_until[:10]}" if self.valid_until else "") + (f"; {self.reason}" if self.reason else "") \
            + (f"; paid {self.paid_at[:10]}, reference {self.payment_reference}" if self.paid_at else "")


def verify_document(value: Any) -> CommercialDocument:
    return value if isinstance(value, CommercialDocument) else CommercialDocument.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed"}})


def issue_document(kind: str, *, exchange_ref: str, from_party: str, to_party: str, issued_at: str, currency: str, lines: Sequence[Mapping[str, Any]], previous: CommercialDocument | Mapping[str, Any] | None = None, **fields: Any) -> CommercialDocument:
    """Seal one document: priced lines get their amounts and the document its total; a reply names the document it answers."""

    _require(kind in DOCUMENT_KINDS, "KIND_UNKNOWN", f"the documents are {', '.join(DOCUMENT_KINDS)}")
    before = None if previous is None else verify_document(previous)
    shaped = []
    for line in lines:
        raw = dict(detached(line))
        if raw.get("unit_price") is not None:
            price = decimal_value(raw["unit_price"], field_name="unit_price")
            quantity = decimal_value(raw["quantity"], field_name="quantity")
            raw["unit_price"] = str(price)
            raw["amount"] = str(_money(quantity * price))
        shaped.append({key: value for key, value in raw.items() if value is not None})
    total = None if kind == "rfq" else str(_money(sum((Decimal(line["amount"]) for line in shaped), Decimal("0"))))
    document = {"kind": kind, "exchange_ref": exchange_ref, "sequence": 1 if before is None else before.sequence + 1, "from_party": from_party, "to_party": to_party, "issued_at": issued_at, "currency": currency, "lines": shaped, "total": total, "in_reply_to": None if before is None else before.document_digest, **{key: value for key, value in fields.items() if value is not None}}
    return seal(CommercialDocument, {key: value for key, value in document.items() if value is not None}, "document_digest")


# --------------------------------------------------------------------------- #
# The thread
# --------------------------------------------------------------------------- #


class ExchangeThread(StrictModel):
    """One exchange, verified end to end: who buys and sells, where it stands, and whose turn it is."""

    schema_id: str = Field(default=EXCHANGE_THREAD_SCHEMA, alias="schema")
    exchange_ref: OpaqueRef
    buyer: OpaqueRef
    seller: OpaqueRef
    currency: CurrencyCode
    documents: tuple[CommercialDocument, ...] = Field(min_length=1, max_length=MAX_DOCUMENTS)
    status: ThreadStatus
    next_kind: DocumentKind | None = None
    next_from: OpaqueRef | None = None
    value: Decimal | None = None
    thread_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("documents", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("value", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="value")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ExchangeThread":
        if not skip_digests(info) and self.thread_digest != sealed_digest(ExchangeThread, self, "thread_digest"):
            raise ValueError("thread_digest must commit the exact thread")
        return self

    def last(self) -> CommercialDocument:
        return self.documents[-1]

    def document(self, kind: str) -> CommercialDocument | None:
        """The latest document of ``kind``: after a counter-offer, the revised quote is the one in force."""

        return next((document for document in reversed(self.documents) if document.kind == kind), None)

    def counters(self) -> int:
        return sum(1 for document in self.documents if document.kind == "counter")

    def render(self) -> str:
        head = f"**Exchange {self.exchange_ref}** ({self.buyer} buys from {self.seller}): {self.status}" + (f", {self.value} {self.currency}" if self.value is not None else "") + (f"; next: {self.next_from} sends the {self.next_kind.replace('_', ' ')}" if self.next_kind else "; closed")
        return "\n".join([head, *(f"- {document.sequence}. {document.render()}" for document in self.documents)])


def verify_thread(documents: Sequence[CommercialDocument | Mapping[str, Any]]) -> ExchangeThread:
    """Check a whole exchange and say where it stands; any break in the chain is refused with its reason."""

    chain = [verify_document(document) for document in documents]
    _require(bool(chain) and len(chain) <= MAX_DOCUMENTS, "THREAD_EMPTY", f"an exchange holds one to {MAX_DOCUMENTS} documents")
    first = chain[0]
    _require(first.kind == "rfq", "THREAD_NOT_OPENED", "an exchange opens with a request for quote")
    buyer, seller = first.from_party, first.to_party
    parties = {"buyer": buyer, "seller": seller}
    status = "requested"
    _require(sum(1 for document in chain if document.kind == "counter") <= MAX_COUNTERS, "TOO_MANY_COUNTERS", f"a buyer makes at most {MAX_COUNTERS} counter-offers in an exchange")
    for before, document in zip(chain, chain[1:]):
        countering = before.kind == COUNTER_ANSWERS and document.kind == "counter"
        _require(before.kind in NEXT_KIND and (document.kind == NEXT_KIND[before.kind] or countering), "OUT_OF_TURN", f"a {document.kind} does not answer a {before.kind}")
        _require(not (before.kind == "order_acknowledgement" and before.accepted is False), "ORDER_DECLINED", "a declined order closes the exchange")
        _require(document.exchange_ref == first.exchange_ref and document.currency == first.currency, "THREAD_MISMATCH", "every document keeps the exchange and its currency")
        _require(document.sequence == before.sequence + 1 and document.in_reply_to == before.document_digest, "NOT_A_REPLY", f"the {document.kind} does not answer the exact {before.kind}")
        role = FROM_ROLE[document.kind]
        other = "seller" if role == "buyer" else "buyer"
        _require(document.from_party == parties[role] and document.to_party == parties[other], "WRONG_PARTY", f"the {document.kind} goes from the {role} to the {other}")
        _require(parsed(document.issued_at) >= parsed(before.issued_at), "OUT_OF_ORDER", f"the {document.kind} is dated before the {before.kind}")
        if document.kind == "quote":
            asked = sorted((line.item_ref, str(line.quantity)) for line in before.lines)
            offered = sorted((line.item_ref, str(line.quantity)) for line in document.lines)
            _require(asked == offered, "QUOTE_NOT_THE_REQUEST", "a quote prices exactly the lines requested")
        elif document.kind == "counter":
            quoted = {line.item_ref: line for line in before.lines}
            _require(sorted((line.item_ref, str(line.quantity)) for line in document.lines) == sorted((line.item_ref, str(line.quantity)) for line in before.lines),
                     "COUNTER_NOT_THE_QUOTE", "a counter-offer names exactly the quote's lines")
            _require(all(line.unit_price is not None and quoted[line.item_ref].unit_price is not None and line.unit_price <= quoted[line.item_ref].unit_price for line in document.lines)
                     and any(line.unit_price < quoted[line.item_ref].unit_price for line in document.lines), "COUNTER_NOT_LOWER", "a counter-offer asks a lower price on some line and a higher one on none")
        else:
            _require(sorted(line.terms() for line in document.lines) == sorted(line.terms() for line in before.lines) and document.total == before.total, "TERMS_CHANGED", f"the {document.kind} keeps the {before.kind}'s lines and prices")
        if document.kind == "purchase_order":
            _require(parsed(document.issued_at) <= parsed(str(before.valid_until)), "QUOTE_LAPSED", f"the quote held until {str(before.valid_until)[:16]}")
        status = "accepted" if document.kind == "order_acknowledgement" and document.accepted else "declined" if document.kind == "order_acknowledgement" else STATUS_AFTER[document.kind]
    quotes = [document for document in chain if document.kind == "quote"]
    for earlier, later in zip(quotes, quotes[1:]):
        asked_before = {line.item_ref: line.unit_price for line in earlier.lines}
        _require(all(line.unit_price is not None and asked_before.get(line.item_ref) is not None and line.unit_price <= asked_before[line.item_ref] for line in later.lines),
                 "REQUOTE_HIGHER", "a revised quote asks no more on any line than the quote before it")
    last = chain[-1]
    open_next = last.kind in NEXT_KIND and not (last.kind == "order_acknowledgement" and last.accepted is False)
    next_kind = NEXT_KIND[last.kind] if open_next else None
    priced = [document.total for document in chain if document.total is not None]
    return seal(ExchangeThread, {"exchange_ref": first.exchange_ref, "buyer": buyer, "seller": seller, "currency": first.currency, "documents": [document.to_dict() for document in chain], "status": status, "next_kind": next_kind, "next_from": None if next_kind is None else parties[FROM_ROLE[next_kind]], "value": None if not priced else str(priced[-1])}, "thread_digest")


def quote_lines(card: CompanyCard | Mapping[str, Any], request: CommercialDocument | Mapping[str, Any]) -> list[dict[str, Any]]:
    """Price every requested line from the card's offers (their list prices); an item the company does not offer is refused."""

    parsed_card = verify_company_card(card)
    parsed_request = verify_document(request)
    _require(parsed_request.kind == "rfq", "NOT_A_REQUEST", "a quote answers a request for quote")
    _require(parsed_request.currency == parsed_card.currency, "CURRENCY_NOT_OFFERED", f"the company quotes in {parsed_card.currency}, the request asks for {parsed_request.currency}")
    lines = []
    for line in parsed_request.lines:
        offer = parsed_card.offer(line.item_ref)
        _require(offer is not None, "ITEM_NOT_OFFERED", f"{line.item_ref} is not in the catalog in force")
        assert offer is not None
        lines.append({"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": offer.unit, "unit_price": str(offer.list_price)})
    return lines


def exchange_ref_for(buyer: str, seller: str, seed: str) -> str:
    """A stable reference for a new exchange: the same buyer, seller and seed always name the same exchange."""

    return "x:" + stable_digest({"buyer": buyer, "seller": seller, "seed": seed})[:24]


__all__ = [
    "COMMERCIAL_DOCUMENT_SCHEMA",
    "COMPANY_CARD_SCHEMA",
    "DOCUMENT_ACTION",
    "DOCUMENT_KINDS",
    "EXCHANGE_MANIFEST",
    "EXCHANGE_THREAD_SCHEMA",
    "FROM_ROLE",
    "NEXT_KIND",
    "CardOffer",
    "CommercialDocument",
    "CompanyCard",
    "ExchangeError",
    "ExchangeLine",
    "ExchangeThread",
    "build_company_card",
    "exchange_ref_for",
    "issue_document",
    "quote_lines",
    "verify_company_card",
    "verify_document",
    "verify_thread",
]
