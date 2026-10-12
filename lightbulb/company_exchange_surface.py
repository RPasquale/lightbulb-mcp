"""The console side of trading with other businesses: the card, the threads, and every document issued under the mandate.

``card`` builds the company card from the catalog in force, the bundle and the
mandate, and keeps it.  ``receive`` takes a document another company's agent sent,
checks it is addressed to this company and answers the thread, and records it.
``request``, ``quote``, ``order``, ``acknowledge`` and ``invoice`` issue this
company's next document in a thread.  Each asks the mandate first, with the
document's value:

* ``never`` refuses it;
* ``act`` lets the agent send it;
* ``ask`` keeps it waiting until the owner approves it with ``send`` (``owner_ref``).

A document is sent through the host's transport (``console.exchange_transport``).
With no transport it is ready to deliver by hand, and ``send`` with
``delivered_by_hand`` records that it went.  On the platform the transport is
``company_exchange_transport.PlatformExchange``: ``directory`` publishes the card
under the company's exchange address, ``find`` reads another company's card by its
address, ``counterparty`` registers (or blocks) a company by its address and
``counterparties`` lists them, ``inbox`` takes in what other companies sent and settles
each delivery, and ``receipts`` checks the platform's signed receipt and each recipient's
signed settlement for what this company sent.  ``withdraw`` takes back a document not
yet sent.  ``status`` lists every exchange, whose turn it is, and what waits on the
owner.  What the agent sent alone is logged under the mandate like every other
unattended action.

What an exchange reaches goes in the books (``company_exchange_books``): the invoice
this company receives opens a bill in the payables chain, the order it accepts books a
sale in the revenue chain, and the invoice it sends issues that sale's invoice.  Each
happens as the document comes or goes; a hop the books refuse is reported with the
chain's code, and ``book`` puts in what is missing.  ``books`` shows what the exchange
put in the books, what is owed each way, and the reference a ledger posting of each
invoice carries.

Each invoice the books hold is then posted to the accounting ledger
(``company_exchange_ledger``).  ``ledger`` says who each trading partner is there and
where the lines go; once it names the partner, the posting is planned as an owner
action (``post_to_ledger`` under the mandate), and the act loop sends it through the
platform, whose financial reviewer approves the write.  ``post`` plans what is missing,
and ``books`` shows each posting, with the bill write receipt the payables chain
schedules a payment against once a QuickBooks bill is in the ledger.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any

from lightbulb.company_engine_core import detached, parsed, stable_digest, timestamp

EXCHANGE_ENGINE = "commercial_exchange"
EXCHANGE_RECORD_SCHEMA = "lightbulb.commercial_exchange_record.v1"
EXCHANGE_STATUS_SCHEMA = "lightbulb.commercial_exchange_status.v1"
DIRECTORY_SEARCH_SCHEMA = "lightbulb.commercial_exchange_directory_search.v1"
# how long a remittance holds back a reminder: the days a transfer may take to land before the invoice is chased again
REMITTANCE_GRACE_DAYS = 7
TRACK_RECORD_VIEW_SCHEMA = "lightbulb.commercial_exchange_track_record.v1"
CARD_ENTITY = "card:current"
DeliveryStatus = str  # prepared | waiting_for_owner | ready_to_deliver | sent | received | withdrawn


def _record_state(console: Any, entity_ref: str, *, key: str, document: Mapping[str, Any], digest: str, version: int, now: str, status: str, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {"schema": EXCHANGE_RECORD_SCHEMA, "status": status, "plan_digest": stable_digest({EXCHANGE_ENGINE: console.bundle.company_ref}), "version": version, "state_digest": digest, "scope": console.bundle.engine_scope(entity_ref), "as_of": timestamp(now, field_name="now"), key: dict(document), **dict(extra or {})}


def _put(console: Any, entity_ref: str, *, key: str, document: Mapping[str, Any], digest: str, now: str, status: str, existing: Mapping[str, Any] | None, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if existing is not None and str(existing["state_digest"]) == digest:
        return {"entity_ref": entity_ref, "version": int(existing["version"]), "unchanged": True}
    version = 1 if existing is None else int(existing["version"]) + 1
    console.store.put(EXCHANGE_ENGINE, entity_ref, _record_state(console, entity_ref, key=key, document=document, digest=digest, version=version, now=now, status=status, extra=extra), expected_version=None if existing is None else int(existing["version"]), expected_state_digest=None if existing is None else str(existing["state_digest"]))
    return {"entity_ref": entity_ref, "version": version, "unchanged": False}


# --------------------------------------------------------------------------- #
# The card
# --------------------------------------------------------------------------- #


def current_card(console: Any) -> Any | None:
    from lightbulb.company_exchange import verify_company_card

    record = console.store.get(EXCHANGE_ENGINE, CARD_ENTITY)
    return None if record is None else verify_company_card(dict(record["state"])["card"])


def _require_card(console: Any) -> Any:
    from lightbulb.company_exchange import ExchangeError

    card = current_card(console)
    if card is None:
        raise ExchangeError("CARD_REQUIRED", "the company trades under its card: build it first (company_exchange card)")
    return card


def _catalog_in_force(console: Any, at: str) -> tuple[list[dict[str, Any]], str | None, str | None]:
    """The published catalog version in force at ``at`` (the latest effective one): its items, version ref and state digest."""

    from lightbulb.company_operator_surface import _persisted

    best = None
    for _plan, state in _persisted(console, "price_catalog"):
        ledger = state.ledger
        effective = getattr(ledger, "effective_from", None)
        if state.status != "published" or effective is None or parsed(str(effective)) > parsed(at):
            continue
        if best is None or parsed(str(effective)) > parsed(str(best.ledger.effective_from)):
            best = state
    if best is None:
        return [], None, None
    items = [{"item_ref": item.item_ref, "kind": item.kind, "unit": item.unit, "list_price": str(item.list_price), "billing_period": item.billing_period} for item in best.ledger.items]
    return items, str(best.ledger.version_ref), str(best.state_digest)


def _answers_alone(console: Any) -> list[str]:
    """The documents this company's agent answers without asking: those whose answer the mandate lets it make alone."""

    from lightbulb.company_operator_surface import current_mandate

    mandate = current_mandate(console)
    if mandate is None:
        return []
    answers = {"rfq": "send_quote", "purchase_order": "accept_order", "quote": "place_order"}
    return [kind for kind, action in answers.items() if (rule := mandate.rule(action)) is not None and rule.autonomy == "act"]


def build_card_document(console: Any, *, now: str, party_ref: str | None = None, display_name: str | None = None, contact_ref: str | None = None, terms_days: Any = None, quote_valid_days: Any = 30,
                        about: str | None = None, keywords: Any = None, offer_names: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build the company card from the catalog in force, the bundle and the mandate, and keep it (a changed card amends it by one version).

    ``about`` (what the company does), ``keywords`` (a list, or a string split at its commas) and ``offer_names``
    ({item_ref: name}) are what a listed company is found by in the platform's directory. Each keeps its value from
    the card before unless given; an empty ``about``, an empty ``keywords`` or an empty name takes it off.
    """

    from lightbulb.company_exchange import DOCUMENT_KINDS, ExchangeError, build_company_card, normal_keywords

    at = timestamp(now, field_name="now")
    blueprint = console.bundle.operating_plan.blueprint
    previous = current_card(console)
    offers, version_ref, catalog_digest = _catalog_in_force(console, at)
    names = {offer.item_ref: offer.name for offer in (previous.offers if previous is not None else ()) if offer.name}
    if offer_names is not None and not isinstance(offer_names, Mapping):
        raise ExchangeError("OFFER_NAMES_INVALID", "offer_names maps an offer's item_ref to its name")
    for item_ref, name in dict(offer_names or {}).items():
        text = " ".join(str(name or "").split())
        if text:
            names[str(item_ref)] = text[:300]
        else:
            names.pop(str(item_ref), None)
    offers = [{**offer, "name": names[offer["item_ref"]]} if offer["item_ref"] in names else offer for offer in offers]
    about_text = (previous.about if previous is not None else None) if about is None else (" ".join(str(about).split())[:300] or None)
    keyword_list = list(previous.keywords or ()) if keywords is None and previous is not None else normal_keywords(keywords or ())
    if terms_days is None:
        ledger_plan = dict(console.bundle.supporting_plans.get("customer_ledger") or {})
        terms_days = ledger_plan.get("terms_days", previous.terms_days if previous is not None else 30)
    card = build_company_card(
        party_ref=str(party_ref or (previous.party_ref if previous is not None else f"party:{console.bundle.company_ref}")),
        display_name=str(display_name or (previous.display_name if previous is not None else getattr(blueprint, "name", None) or console.bundle.company_ref))[:300],
        country=getattr(blueprint, "country", None),
        currency=blueprint.currency,
        offers=offers,
        catalog_version_ref=version_ref,
        catalog_digest=catalog_digest,
        accepts=DOCUMENT_KINDS,
        answers_alone=_answers_alone(console),
        terms_days=int(terms_days),
        quote_valid_days=int(quote_valid_days),
        contact_ref=contact_ref or (previous.contact_ref if previous is not None else None),
        about=about_text,
        keywords=keyword_list,
        issued_at=at,
    )
    # the card's own issue time is left out of what decides whether it changed
    comparable = stable_digest({key: value for key, value in card.to_dict().items() if key not in {"issued_at", "card_digest"}})
    existing = console.store.get(EXCHANGE_ENGINE, CARD_ENTITY)
    if existing is not None and dict(existing["state"]).get("comparable_digest") == comparable:
        kept = current_card(console)
        return {**kept.to_dict(), "stored": {"entity_ref": CARD_ENTITY, "version": int(existing["version"]), "unchanged": True}, "summary": kept.render(), "provider_effect_executed": False}
    stored = _put(console, CARD_ENTITY, key="card", document=card.to_dict(), digest=card.card_digest, now=at, status="published", existing=existing, extra={"comparable_digest": comparable})
    return {**card.to_dict(), "stored": stored, "summary": card.render(), "provider_effect_executed": False}


# --------------------------------------------------------------------------- #
# Threads
# --------------------------------------------------------------------------- #


def _entity(exchange_ref: str) -> str:
    return f"thread:{exchange_ref}"


def _load_thread(console: Any, exchange_ref: str) -> tuple[Any | None, dict[str, Any], Mapping[str, Any] | None]:
    from lightbulb.company_exchange import verify_thread

    record = console.store.get(EXCHANGE_ENGINE, _entity(exchange_ref))
    if record is None:
        return None, {}, None
    state = dict(record["state"])
    return verify_thread(dict(state["thread"])["documents"]), dict(state.get("delivery") or {}), record


def _save_thread(console: Any, thread: Any, delivery: Mapping[str, Any], *, role: str, now: str, existing: Mapping[str, Any] | None, status: str | None = None) -> dict[str, Any]:
    digest = stable_digest({"thread": thread.thread_digest, "delivery": dict(delivery), "status": status})
    return _put(console, _entity(thread.exchange_ref), key="thread", document=thread.to_dict(), digest=digest, now=now, status=status or thread.status, existing=existing, extra={"delivery": dict(delivery), "role": role})


def _view(console: Any, thread: Any, delivery: Mapping[str, Any], *, now: str, card: Any, stored: Mapping[str, Any] | None = None, issued: Any = None) -> dict[str, Any]:
    role = "buyer" if thread.buyer == card.party_ref else "seller"
    ours = thread.next_from == card.party_ref
    waiting = [{"kind": document.kind, "document_digest": document.document_digest, **dict(delivery.get(document.document_digest) or {})} for document in thread.documents if dict(delivery.get(document.document_digest) or {}).get("status") in ("waiting_for_owner", "ready_to_deliver")]
    lines = [thread.render()]
    if waiting:
        lines.extend(f"- waiting: the {row['kind'].replace('_', ' ')} is {row['status'].replace('_', ' ')}" + (f" ({row.get('reason')})" if row.get("reason") else "") for row in waiting)
    elif ours and thread.next_kind:
        operation = "answer_counter" if thread.last().kind == "counter" else _OPERATION_FOR[thread.next_kind] + (", or counter" if thread.next_kind == "purchase_order" else "")
        lines.append(f"- this company's turn: the {thread.next_kind.replace('_', ' ')} (company_exchange {operation})")
    return {"schema": EXCHANGE_STATUS_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": timestamp(now, field_name="now"), "role": role, "our_turn": ours and not waiting, "thread": thread.to_dict(), "delivery": dict(delivery), "waiting": waiting, "document": None if issued is None else issued.to_dict(), "stored": None if stored is None else dict(stored), "summary": "\n".join(lines), "provider_effect_executed": bool(issued is not None and dict(delivery.get(issued.document_digest) or {}).get("status") == "sent")}


_OPERATION_FOR = {"rfq": "request", "quote": "quote", "purchase_order": "order", "order_acknowledgement": "acknowledge", "invoice": "invoice", "remittance": "remit, once the invoice is paid"}


def receive_document(console: Any, *, now: str, document: Mapping[str, Any], platform_receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Take a document another company's agent sent: it must be addressed to this company and answer the thread; the same document again changes nothing.

    ``platform_receipt`` is the platform's signed delivery receipt for it (``company_exchange_books.platform_evidence``),
    kept so the books can show where the document came from.
    """

    from lightbulb.company_exchange import ExchangeError, verify_document, verify_thread

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    received = verify_document(document)
    if received.to_party != card.party_ref:
        raise ExchangeError("NOT_ADDRESSED_HERE", f"the {received.kind} is for {received.to_party}, not {card.party_ref}")
    thread, delivery, record = _load_thread(console, received.exchange_ref)
    documents = [] if thread is None else list(thread.documents)
    if any(item.document_digest == received.document_digest for item in documents):
        return _view(console, thread, delivery, now=at, card=card, stored={"entity_ref": _entity(received.exchange_ref), "unchanged": True})
    updated = verify_thread([*documents, received])
    _order_within_quote(updated, received, at=at, side="arrived")
    delivery = {**delivery, received.document_digest: {"status": "received", "at": at}}
    role = "seller" if received.kind in ("rfq", "purchase_order") else "buyer"
    stored = _save_thread(console, updated, delivery, role=role, now=at, existing=record)
    return _with_books(console, _view(console, updated, delivery, now=at, card=card, stored=stored), updated, delivery, card=card, now=at, received=received, platform_receipt=platform_receipt)


def _deliver(console: Any, document: Any) -> dict[str, Any] | None:
    transport = getattr(console, "exchange_transport", None)
    if transport is None:
        return None
    return dict(transport(document.to_dict()) or {})


def _issue(console: Any, *, now: str, document: Any, previous: Sequence[Any], money: Any, action: str | None = None, owner_ref: str | None = None, hold: str | None = None) -> dict[str, Any]:
    """Issue this company's next document: the mandate decides whether the agent sends it, the owner approves it, or it is refused.

    ``hold`` names a reason the owner decides a document the mandate would let the agent send alone (a customer over
    its credit limit); the owner's approval still sends it.
    """

    from lightbulb.company_exchange import DOCUMENT_ACTION, ExchangeError, verify_thread
    from lightbulb.company_operator_surface import check_mandate, check_mandate_log, current_mandate, record_mandate_action

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    kind = action or DOCUMENT_ACTION[document.kind]
    # the subject names this document, so two documents issued at one instant are two decisions in the month's log
    decision = check_mandate(console, now=at, action_kind=kind, money=money, subject=f"{document.kind}:{document.exchange_ref}:{document.to_party}"[:300])
    if decision["autonomy"] == "never":
        raise ExchangeError("RULED_OUT", f"the owner ruled out {kind}: {decision['reason']}")
    home = console.bundle.operating_plan.blueprint.currency
    if decision["autonomy"] == "act" and document.currency != home and Decimal(str(money or "0")) != 0:
        # the mandate's caps and envelope are in the company's own currency: a sum in another is never judged against them
        decision = {"action_kind": kind, "autonomy": "ask", "reason": f"the {document.kind.replace('_', ' ')} is in {document.currency}; the mandate's caps and envelope are in {home}, so the owner decides it", "mandate_digest": decision.get("mandate_digest"), "provider_effect_executed": False}
    if decision["autonomy"] == "act" and hold:
        decision = {"action_kind": kind, "autonomy": "ask", "reason": hold[:300], "mandate_digest": decision.get("mandate_digest"), "provider_effect_executed": False}
    mandate = current_mandate(console)
    owner_approves = owner_ref is not None and mandate is not None and str(owner_ref) == mandate.owner_ref
    if owner_ref is not None and not owner_approves:
        raise ExchangeError("OWNER_ONLY", "only the mandate's owner approves a document the mandate asks about")
    thread = verify_thread([*previous, document])
    _, delivery, record = _load_thread(console, document.exchange_ref)
    entry: dict[str, Any] = {"status": "waiting_for_owner", "at": at, "action_kind": kind, "autonomy": decision["autonomy"], "reason": str(decision["reason"])[:300]}
    if decision["autonomy"] == "act" or owner_approves:
        if decision["autonomy"] == "act" and decision.get("decision_digest"):
            # the month's log must be able to take the entry before the document leaves: once it is sent it cannot be unsent
            check_mandate_log(console, now=at, decision=decision)
        receipt = _deliver(console, document)
        entry = {**entry, "status": "sent" if receipt is not None else "ready_to_deliver", "approved_by": str(owner_ref) if owner_approves else None, "receipt": receipt}
        if receipt is not None and decision["autonomy"] == "act" and decision.get("decision_digest"):
            logged = record_mandate_action(console, now=at, decision=decision, tool=f"exchange.{document.kind}", effect_ref=f"doc:{document.document_digest[:24]}", note=f"{document.kind} {document.exchange_ref}")
            entry["mandate_log"] = {"entity_ref": logged["entity_ref"], "version": logged["version"]}
    delivery = {**delivery, document.document_digest: {key: value for key, value in entry.items() if value is not None}}
    role = "buyer" if thread.buyer == card.party_ref else "seller"
    stored = _save_thread(console, thread, delivery, role=role, now=at, existing=record)
    return _with_books(console, _view(console, thread, delivery, now=at, card=card, stored=stored, issued=document), thread, delivery, card=card, now=at)


def quote_lapsed(thread: Any, *, at: str) -> bool:
    """The exchange waits for an order against a quote that no longer holds."""

    last = thread.last()
    return thread.next_kind == "purchase_order" and last.kind == "quote" and last.valid_until is not None and parsed(at) > parsed(str(last.valid_until))


def _order_within_quote(thread: Any, document: Any, *, at: str, side: str) -> None:
    """An order accepts a quote only while it holds: an order that reaches the seller after the quote lapsed is no acceptance, however early it was written."""

    from lightbulb.company_exchange import ExchangeError

    if document.kind != "purchase_order":
        return
    quote = thread.document("quote")
    if quote is not None and quote.valid_until is not None and parsed(at) > parsed(str(quote.valid_until)):
        raise ExchangeError("QUOTE_LAPSED", f"the order {side} at {at[:16]}, after the quote lapsed {str(quote.valid_until)[:16]}; withdraw it and ask for a new quote")


def _our_turn(console: Any, exchange_ref: str, kind: str) -> tuple[Any, Any, Any]:
    from lightbulb.company_exchange import ExchangeError

    card = _require_card(console)
    thread, delivery, _ = _load_thread(console, str(exchange_ref))
    if thread is None:
        raise LookupError(f"no exchange {exchange_ref}")
    pending = [digest for digest, row in delivery.items() if dict(row).get("status") in ("waiting_for_owner", "ready_to_deliver")]
    if pending:
        raise ExchangeError("DOCUMENT_PENDING", "this company's last document has not gone yet: send or withdraw it first")
    if thread.next_kind != kind or thread.next_from != card.party_ref:
        raise ExchangeError("NOT_OUR_TURN", f"the exchange waits for {thread.next_from or 'nobody'} to send the {thread.next_kind or 'nothing more'}")
    return card, thread, thread.last()


def request_quote(console: Any, *, now: str, to_party: str, lines: Sequence[Mapping[str, Any]], needed_by: str | None = None, reply_by: str | None = None, exchange_ref: str | None = None, owner_ref: str | None = None, currency: str | None = None) -> dict[str, Any]:
    """Ask another business for a quote (this company buys): a message to a supplier under the mandate.

    ``currency`` asks for the quote in the seller's currency, as its card states it; without it the request is in
    this company's own.  The whole exchange then keeps that currency.
    """

    from lightbulb.company_exchange import ExchangeError, exchange_ref_for, issue_document

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    ref = str(exchange_ref or exchange_ref_for(card.party_ref, str(to_party), stable_digest({"at": at, "lines": [dict(detached(line)) for line in lines]})))
    if _load_thread(console, ref)[0] is not None:
        raise ExchangeError("EXCHANGE_EXISTS", f"exchange {ref} is already open")
    shaped = [{"item_ref": str(line["item_ref"]), "quantity": str(line["quantity"]), "unit": str(line.get("unit") or "each")} for line in lines]
    document = issue_document("rfq", exchange_ref=ref, from_party=card.party_ref, to_party=str(to_party), issued_at=at, currency=str(currency or card.currency).upper(), lines=shaped, needed_by=needed_by, reply_by=reply_by)
    return _issue(console, now=at, document=document, previous=[], money="0", owner_ref=owner_ref)


def quote_request(console: Any, *, now: str, exchange_ref: str, valid_days: Any = None, terms_days: Any = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Answer a request for quote from the catalog in force (this company sells): a quote under the mandate's send_quote, capped by its value."""

    from lightbulb.company_exchange import issue_document, quote_lines

    at = timestamp(now, field_name="now")
    card, thread, request = _our_turn(console, exchange_ref, "quote")
    days = int(valid_days) if valid_days is not None else card.quote_valid_days
    valid_until = (parsed(at) + timedelta(days=days)).isoformat().replace("+00:00", "Z")
    document = issue_document("quote", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=request.from_party, issued_at=at, currency=card.currency, lines=quote_lines(card, request), previous=request, valid_until=valid_until, terms_days=int(terms_days) if terms_days is not None else card.terms_days)
    return _issue(console, now=at, document=document, previous=list(thread.documents), money=document.total, owner_ref=owner_ref)


def _same_lines(document: Any) -> list[dict[str, Any]]:
    return [{"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": line.unit, "unit_price": str(line.unit_price)} for line in document.lines]


def order_from_quote(console: Any, *, now: str, exchange_ref: str, owner_ref: str | None = None) -> dict[str, Any]:
    """Accept the quote received (this company buys): a purchase order under the mandate's place_order, which counts against the envelope."""

    from lightbulb.company_exchange import issue_document

    at = timestamp(now, field_name="now")
    card, thread, quote = _our_turn(console, exchange_ref, "purchase_order")
    document = issue_document("purchase_order", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=quote.from_party, issued_at=at, currency=quote.currency, lines=_same_lines(quote), previous=quote)
    return _issue(console, now=at, document=document, previous=list(thread.documents), money=document.total, owner_ref=owner_ref)


def acknowledge_order(console: Any, *, now: str, exchange_ref: str, accept: Any = True, reason: str | None = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Accept (under the mandate's accept_order) or decline (a message to the customer) the purchase order received.

    An order that would take the customer past its credit limit (``company_exchange credit``) is the owner's to accept.
    """

    from lightbulb.company_exchange import ExchangeError, issue_document
    from lightbulb.company_exchange_credit import credit_hold

    if not isinstance(accept, bool):
        raise ExchangeError("ACCEPT_INVALID", "accept is true or false")
    at = timestamp(now, field_name="now")
    card, thread, order = _our_turn(console, exchange_ref, "order_acknowledgement")
    document = issue_document("order_acknowledgement", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=order.from_party, issued_at=at, currency=order.currency, lines=_same_lines(order), previous=order, accepted=accept, reason=reason)
    hold = credit_hold(console, customer=order.from_party, money=order.total, currency=order.currency, exchange_ref=thread.exchange_ref) if accept else None
    return _issue(console, now=at, document=document, previous=list(thread.documents), money=document.total if accept else "0", action=None if accept else "message_customer", owner_ref=owner_ref, hold=hold)


def exchange_payment(console: Any, exchange_ref: str) -> dict[str, Any] | None:
    """What this company's books say about paying the exchange's invoice: its payables case (``bill:exchange:<ref>``), or None when it has none."""

    from lightbulb.company_exchange_books import ledger_reference
    from lightbulb.company_operator_surface import CompanyOperatorSurface

    engine, entity_ref = BOOKS_ENGINE_FOR["buyer"], _books_entity("buyer", exchange_ref)
    if console.store.get(engine, entity_ref) is None:
        return None
    state = CompanyOperatorSurface(console).runtime(engine).load(entity_ref)
    thread = _load_thread(console, exchange_ref)[0]
    invoice = None if thread is None else thread.document("invoice")
    return {"entity_ref": entity_ref, "status": state.status, "paid_at": state.ledger.paid_at, "paid": state.ledger.paid_at is not None,
            "reference": None if invoice is None else ledger_reference(invoice.document_digest, side="payable")}


def remit_invoice(console: Any, *, now: str, exchange_ref: str, paid_at: str | None = None, payment_reference: str | None = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Tell the seller its invoice is paid (this company buys): a remittance under the mandate's message_supplier.

    The agent remits alone only what the books show paid: the exchange's payables case, settled by the payment the
    platform observed, gives the date, and the bill's ledger reference (``LB-AP-``) is the reference. A payment the
    books do not show yet is the owner's to vouch for, with ``paid_at``, ``payment_reference`` and ``owner_ref``.
    """

    from lightbulb.company_exchange import ExchangeError, issue_document

    at = timestamp(now, field_name="now")
    card, thread, invoice = _our_turn(console, exchange_ref, "remittance")
    paid = exchange_payment(console, thread.exchange_ref)
    if paid is not None and paid["paid"]:
        when, reference = str(paid["paid_at"]), str(payment_reference or paid["reference"])
    else:
        if owner_ref is None or paid_at is None or not payment_reference:
            raise ExchangeError("NOT_PAID_IN_THE_BOOKS", "the books do not show this invoice paid yet: the agent remits once the payment is seen, or the owner remits with paid_at, payment_reference and owner_ref")
        when, reference = timestamp(paid_at, field_name="paid_at"), str(payment_reference)
    document = issue_document("remittance", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=invoice.from_party, issued_at=at, currency=invoice.currency,
                              lines=_same_lines(invoice), previous=invoice, paid_at=when, payment_reference=" ".join(reference.split())[:300])
    return _issue(console, now=at, document=document, previous=list(thread.documents), money="0", owner_ref=owner_ref)


def held_for_remittance(console: Any, *, now: str) -> dict[str, dict[str, Any]]:
    """The customers not to chase yet: those whose remittance for an exchange invoice came in within the grace days, keyed by their id in the ledger.

    The ledger map (``company_exchange ledger``) names each buyer's customer id in the accounting ledger, which is
    how the customer ledgers the reminders come from name the customer. A buyer the map does not name cannot be
    matched, so its reminders run as before.
    """

    at = parsed(timestamp(now, field_name="now"))
    ledger_map = current_ledger_map(console)
    card = current_card(console)
    if ledger_map is None or card is None:
        return {}
    held: dict[str, dict[str, Any]] = {}
    for thread, _delivery in _exchange_threads(console):
        remittance = thread.document("remittance")
        if thread.seller != card.party_ref or remittance is None or at - parsed(str(remittance.paid_at)) > timedelta(days=REMITTANCE_GRACE_DAYS):
            continue
        customer = dict(ledger_map.customers or {}).get(thread.buyer)
        if customer is None:
            continue
        entry = held.setdefault(str(customer), {"customer_ref": str(customer), "party_ref": thread.buyer, "amount": Decimal("0"), "exchanges": [], "paid_at": str(remittance.paid_at)})
        entry["amount"] += Decimal(str(remittance.total))
        entry["exchanges"].append({"exchange_ref": thread.exchange_ref, "total": str(remittance.total), "paid_at": remittance.paid_at, "payment_reference": remittance.payment_reference})
        entry["paid_at"] = max(entry["paid_at"], str(remittance.paid_at))
    return {key: {**value, "amount": str(value["amount"])} for key, value in held.items()}


def invoice_order(console: Any, *, now: str, exchange_ref: str, owner_ref: str | None = None) -> dict[str, Any]:
    """Invoice the accepted order in full (this company sells), under the mandate's send_invoice."""

    from lightbulb.company_exchange import issue_document

    at = timestamp(now, field_name="now")
    card, thread, acknowledgement = _our_turn(console, exchange_ref, "invoice")
    document = issue_document("invoice", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=acknowledgement.to_party, issued_at=at, currency=acknowledgement.currency, lines=_same_lines(acknowledgement), previous=acknowledgement, terms_days=card.terms_days)
    return _issue(console, now=at, document=document, previous=list(thread.documents), money=document.total, owner_ref=owner_ref)


def send_document(console: Any, *, now: str, exchange_ref: str, owner_ref: str | None = None, delivered_by_hand: Any = False) -> dict[str, Any]:
    """Send this company's waiting document: the owner approves one the mandate asked about; one ready to deliver by hand is recorded as delivered."""

    from lightbulb.company_exchange import ExchangeError
    from lightbulb.company_operator_surface import current_mandate

    if not isinstance(delivered_by_hand, bool):
        raise ExchangeError("DELIVERED_INVALID", "delivered_by_hand is true or false")
    at = timestamp(now, field_name="now")
    card = _require_card(console)
    thread, delivery, record = _load_thread(console, str(exchange_ref))
    if thread is None:
        raise LookupError(f"no exchange {exchange_ref}")
    last = thread.last()
    row = dict(delivery.get(last.document_digest) or {})
    if last.from_party != card.party_ref or row.get("status") not in ("waiting_for_owner", "ready_to_deliver"):
        raise ExchangeError("NOTHING_WAITING", "this company has no document waiting in this exchange")
    _order_within_quote(thread, last, at=at, side="would go")
    if row["status"] == "waiting_for_owner":
        mandate = current_mandate(console)
        if mandate is None:
            raise ExchangeError("MANDATE_REQUIRED", "the owner approves documents as the mandate's owner: give a mandate first (company_mandate set)")
        if owner_ref is None or str(owner_ref) != mandate.owner_ref:
            raise ExchangeError("OWNER_ONLY", f"the mandate asks the owner about this document: its owner ({mandate.owner_ref}) sends it")
        row["approved_by"] = str(owner_ref)
    if delivered_by_hand:
        row = {**row, "status": "sent", "receipt": {"delivered_by_hand": True, "at": at}}
    else:
        receipt = _deliver(console, last)
        row = {**row, "status": "sent" if receipt is not None else "ready_to_deliver", "receipt": receipt}
    delivery = {**delivery, last.document_digest: {key: value for key, value in row.items() if value is not None}}
    role = "buyer" if thread.buyer == card.party_ref else "seller"
    stored = _save_thread(console, thread, delivery, role=role, now=at, existing=record)
    return _with_books(console, _view(console, thread, delivery, now=at, card=card, stored=stored, issued=last), thread, delivery, card=card, now=at)


def withdraw_document(console: Any, *, now: str, exchange_ref: str, reason: str) -> dict[str, Any]:
    """Take back this company's document that has not gone yet; the exchange returns to the turn before it."""

    from lightbulb.company_exchange import ExchangeError, verify_thread

    if not str(reason).strip():
        raise ExchangeError("REASON_REQUIRED", "say why it is withdrawn")
    at = timestamp(now, field_name="now")
    card = _require_card(console)
    thread, delivery, record = _load_thread(console, str(exchange_ref))
    if thread is None:
        raise LookupError(f"no exchange {exchange_ref}")
    last = thread.last()
    row = dict(delivery.get(last.document_digest) or {})
    if last.from_party != card.party_ref or row.get("status") not in ("waiting_for_owner", "ready_to_deliver"):
        raise ExchangeError("NOTHING_TO_WITHDRAW", "only this company's document that has not gone yet can be withdrawn")
    delivery = {**delivery, last.document_digest: {**row, "status": "withdrawn", "withdrawn_at": at, "withdrawn_because": str(reason)[:300]}}
    if len(thread.documents) == 1:
        # the exchange never went out: it is closed as withdrawn, with its one document kept for the record
        stored = _save_thread(console, thread, delivery, role="buyer", now=at, existing=record, status="withdrawn")
        return {**_view(console, thread, delivery, now=at, card=card, stored=stored), "withdrawn": True}
    earlier = verify_thread(list(thread.documents[:-1]))
    role = "buyer" if earlier.buyer == card.party_ref else "seller"
    stored = _save_thread(console, earlier, delivery, role=role, now=at, existing=record)
    return {**_view(console, earlier, delivery, now=at, card=card, stored=stored), "withdrawn": True}


def _platform(console: Any) -> Any:
    from lightbulb.company_exchange import ExchangeError

    transport = getattr(console, "exchange_transport", None)
    if transport is None or not callable(getattr(transport, "drain", None)):
        raise ExchangeError("PLATFORM_EXCHANGE_REQUIRED", "this console is not joined to the platform exchange: run it where the platform is signed in (the MCP server or the hosted worker)")
    return transport


def publish_to_directory(console: Any, *, now: str, visibility: str = "platform", listed: Any = None) -> dict[str, Any]:
    """Publish the company's card in the platform's exchange directory; answers the company's exchange address.

    ``listed`` true puts the company in the directory's search, where other companies' agents find it by its name, what
    it does, its keywords and its offers; false takes it out, and leaving it out keeps it as it was (a first card is
    unlisted). Unlisted, other companies reach it only by its address. Listing is the owner's choice.
    """

    from lightbulb.company_exchange import ExchangeError

    if listed is not None and not isinstance(listed, bool):
        raise ExchangeError("LISTED_INVALID", "listed is true, false or left out")
    if listed:
        card = _require_card(console)
        if not (card.about or card.keywords):
            raise ExchangeError("LISTING_NEEDS_WORDS", "say what the company does before listing it: build the card with about or keywords (company_exchange card)")
    record = _platform(console).publish(console, visibility=str(visibility), listed=listed)
    reach = ("listed: companies searching the directory find it by what it does" if record.get("listed")
             else "not listed: other companies reach it only by that address")
    summary = f"**Card published** at {record.get('address')} ({record.get('visibility')}): other companies send to {record.get('party_ref')} by that address; {reach}"
    return {**record, "as_of": timestamp(now, field_name="now"), "summary": summary, "provider_effect_executed": False}


def describe_track_record(record: Mapping[str, Any] | None) -> str:
    """A company's track record on the exchange in a line: how it answers, accepts, sells and buys, or that it is new there.

    The platform computes the record over its window (180 days) from the documents it carried: volumes in ranges,
    rates only from three cases up, never naming who the company traded with.
    """

    if not record:
        return "no track record shown"
    if record.get("counterparties") in (None, "none"):
        return "new on the exchange"
    seller, buyer = dict(record.get("as_seller") or {}), dict(record.get("as_buyer") or {})
    parts = []
    if seller.get("requests") not in (None, "none"):
        if seller.get("answer_rate") is None:
            parts.append(f"{seller['requests']} request(s) for quote, too few to rate")
        else:
            hours = seller.get("median_hours_to_quote")
            parts.append(f"answers {seller['answer_rate']}% of requests for quote" + ("" if hours is None else f" in about {float(hours):g} h"))
    if seller.get("acceptance_rate") is not None:
        parts.append(f"accepts {seller['acceptance_rate']}% of orders")
    if seller.get("invoices") not in (None, "none"):
        parts.append(f"{seller['invoices']} sale(s) invoiced")
    if buyer.get("orders") not in (None, "none"):
        parts.append(f"{buyer['orders']} order(s) placed")
    if buyer.get("remittance_rate") is not None:
        parts.append(f"tells suppliers it paid {buyer['remittance_rate']}% of its invoices")
    if record.get("refused_rate"):
        parts.append(f"{record['refused_rate']}% of its documents refused")
    since = f"trading since {record['trading_since']}" if record.get("trading_since") else ""
    return "; ".join([*parts, since] if parts and since else parts or [since or "new on the exchange"])


def track_record_document(console: Any, *, now: str) -> dict[str, Any]:
    """This company's track record as other companies see it on the exchange, from its card on the platform."""

    card = _platform(console).own_card()
    record = None if card is None else card.get("track_record")
    if card is None:
        summary = "**Track record**: this company has no card on the exchange yet (company_exchange directory)"
    else:
        shown = "with its listing in the directory and with every document it sends" if card.get("listed") else "with every document it sends (it is not listed in the directory)"
        summary = (f"**Track record** ({console.bundle.company_ref}) over the last {dict(record or {}).get('window_days', 180)} days: {describe_track_record(record)}\n"
                   f"- other companies see it {shown}; volumes are shown in ranges and rates from three cases up, never who the company traded with")
    return {"schema": TRACK_RECORD_VIEW_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": timestamp(now, field_name="now"), "address": None if card is None else card.get("address"),
            "listed": None if card is None else bool(card.get("listed")), "track_record": record, "summary": summary, "provider_effect_executed": False}


def search_directory(console: Any, *, now: str, query: str, currency: str | None = None, country: str | None = None, kind: str | None = None, limit: Any = 20) -> dict[str, Any]:
    """Find companies that sell what this one needs: listed companies only, never this one, each with its address to register and ask for a quote.

    ``query`` is matched against a listed card's name, what the company does, its keywords and its offers, every word
    first and then any word; ``currency`` (ISO code), ``country`` and ``kind`` (plan, sku, service or rate) narrow it.
    Each card that comes back is checked against its own seal before it is shown.
    """

    from lightbulb.company_exchange import ExchangeError, verify_company_card

    at = timestamp(now, field_name="now")
    words = " ".join(str(query or "").split())[:200]
    if not words:
        raise ExchangeError("QUERY_REQUIRED", "say what to look for, in a few words")
    if kind is not None and kind not in ("plan", "sku", "service", "rate"):
        raise ExchangeError("KIND_INVALID", "kind is plan, sku, service or rate")
    platform = _platform(console)
    found = platform.search(words, currency=str(currency).upper() if currency else None, country=str(country).upper() if country else None, kind=kind, limit=max(1, min(50, int(limit))))
    registered = {str(row.get("address")): str(row.get("status")) for row in platform.counterparties()}
    ours = current_card(console)
    rows, unverified = [], 0
    for result in found.get("results") or []:
        try:
            card = verify_company_card(result.get("card"))
        except ValueError:
            unverified += 1
            continue
        if card.party_ref != result.get("party_ref") or card.card_digest != result.get("card_digest"):
            unverified += 1
            continue
        matched = [str(ref) for ref in result.get("matched_offers") or [] if card.offer(str(ref)) is not None]
        rows.append({"address": result.get("address"), "party_ref": card.party_ref, "display_name": card.display_name, "country": card.country, "currency": card.currency,
                     "about": card.about, "keywords": list(card.keywords or ()), "offers": [offer.to_dict() for offer in card.offers], "matched_offers": matched,
                     "accepts": list(card.accepts), "terms_days": card.terms_days, "quote_valid_days": card.quote_valid_days, "card_digest": card.card_digest,
                     "counterparty": registered.get(str(result.get("address"))), "track_record": result.get("track_record")})
    match = str(found.get("match") or "all") if rows else "none"
    heading = {"all": "", "any": " (none matched every word; these match some)", "none": ": none yet, so try other or fewer words, or leave out currency and country"}.get(match, "")
    lines = [f"**Directory**: {len(rows)} listed compan{'y' if len(rows) == 1 else 'ies'} for '{words[:80]}'{heading}"]
    for row in rows[:20]:
        shown = [offer for offer in row["offers"] if not row["matched_offers"] or offer["item_ref"] in row["matched_offers"]][:3]
        prices = "; ".join(f"{offer.get('name') or offer['item_ref']} {offer['list_price']} {row['currency']} per {offer['unit']}" + ("" if offer.get("billing_period", "once") == "once" else f" a {offer['billing_period']}") for offer in shown)
        if row["counterparty"] == "blocked":
            step = "this company blocked it"
        else:
            in_currency = f", in its currency (currency {row['currency']})" if ours is not None and row["currency"] != ours.currency else ""
            step = ("a counterparty already: request a quote" if row["counterparty"] == "active" else "register it (company_exchange counterparty with its address), then request a quote") + in_currency
        lines.append(f"- {row['display_name']} ({row['party_ref']}, {row['country'] or 'country not given'}, {row['currency']}) at {row['address']}" + (f": {row['about']}" if row["about"] else "")
                     + (f"; {prices}" if prices else "") + (f"; {describe_track_record(row['track_record'])}" if row["track_record"] else "") + f"; {step}")
    if unverified:
        lines.append(f"- {unverified} card(s) left out: they did not check out against their own seal")
    return {"schema": DIRECTORY_SEARCH_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "query": words, "match": match, "results": rows, "count": len(rows),
            "unverified": unverified, "summary": "\n".join(lines), "provider_effect_executed": False}


def find_in_directory(console: Any, *, now: str, address: str) -> dict[str, Any]:
    """Another company's published card, by its exchange address."""

    record = _platform(console).find(str(address))
    card = dict(record.get("card") or {})
    summary = f"**{card.get('display_name', record.get('party_ref'))}** at {record.get('address')}: trades as {record.get('party_ref')}, takes {', '.join(card.get('accepts') or []) or 'nothing yet'}" \
        + (f"; {describe_track_record(record['track_record'])}" if record.get("track_record") else "")
    return {**record, "as_of": timestamp(now, field_name="now"), "summary": summary, "provider_effect_executed": False}


def register_counterparty(console: Any, *, now: str, address: str, status: str = "active", note: str | None = None) -> dict[str, Any]:
    """Register a company to trade with by its address (its card must be published), or block its documents."""

    row = _platform(console).register(str(address), status=str(status), note=note)
    summary = (f"**{row.get('display_name') or row.get('party_ref')}** at {row.get('address')} is a counterparty: documents to {row.get('party_ref')} go to it"
               if row.get("status") == "active" else f"**{row.get('address')}** is blocked: the platform refuses its documents")
    return {**row, "as_of": timestamp(now, field_name="now"), "summary": summary, "provider_effect_executed": False}


def list_counterparties(console: Any, *, now: str) -> dict[str, Any]:
    rows = _platform(console).counterparties()
    lines = [f"**Counterparties**: {len(rows)}"]
    lines.extend(f"- {row.get('display_name') or row.get('party_ref') or row.get('address')} ({row.get('address')}): {row.get('status')}" for row in rows[:30])
    return {"counterparties": rows, "count": len(rows), "as_of": timestamp(now, field_name="now"), "summary": "\n".join(lines), "provider_effect_executed": False}


def welcome_new_customers(console: Any, *, now: str, taken: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Take on as customers the businesses whose request for quote just came in, when the mandate's ``take_new_customer`` lets the agent.

    Only a request for quote opens a customer, from a company the platform delivered from (its card is published and
    this company has not blocked it). Registering it is logged in the month's mandate log; the quote that answers it
    is its own decision under ``send_quote``, and an order from it is still held to ``accept_order``'s cap. When the
    mandate asks, the sender waits for the owner to register it, as before.
    """

    from lightbulb.company_operator_surface import check_mandate, check_mandate_log, record_mandate_action

    at = timestamp(now, field_name="now")
    platform = _platform(console)
    outcomes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in taken.get("received") or []:
        address = str(row.get("from_address") or "")
        if row.get("sender_registered") or row.get("kind") != "rfq" or not address or address in seen:
            continue
        seen.add(address)
        decision = check_mandate(console, now=at, action_kind="take_new_customer", money="0", subject=f"customer:{row.get('from_party')}"[:300])
        base = {"address": address, "party_ref": row.get("from_party"), "exchange_ref": row.get("exchange_ref"), "autonomy": decision["autonomy"], "reason": str(decision["reason"])[:300]}
        if decision["autonomy"] != "act":
            outcomes.append({**base, "outcome": "asked" if decision["autonomy"] == "ask" else "ruled_out"})
            continue
        try:
            if decision.get("decision_digest"):
                # the month's log must be able to take the entry before the customer is registered
                check_mandate_log(console, now=at, decision=decision)
            registered = platform.register(address, note=f"a new customer: it asked for a quote ({row.get('exchange_ref')})"[:300])
        except (ValueError, LookupError) as exc:
            outcomes.append({**base, "outcome": "failed", "code": getattr(exc, "code", type(exc).__name__), "detail": str(exc)[:300]})
            continue
        if decision.get("decision_digest"):
            record_mandate_action(console, now=at, decision=decision, tool="exchange.counterparty", effect_ref=f"customer:{address}", note=f"took on {row.get('from_party')} ({row.get('exchange_ref')})"[:300])
        outcomes.append({**base, "outcome": "registered", "display_name": registered.get("display_name"), "track_record": row.get("sender_track_record")})
    return outcomes


def take_in_inbox(console: Any, *, now: str, limit: Any = 50) -> dict[str, Any]:
    """Take in what other companies sent and settle each delivery, received or refused with the code.

    A business whose first request for quote came in is taken on as a customer when the mandate's
    ``take_new_customer`` lets the agent (``welcome_new_customers``); otherwise the owner registers it.
    """

    taken = _platform(console).drain(console, now=now, limit=int(limit))
    welcomed = welcome_new_customers(console, now=now, taken=taken)
    if not welcomed:
        return taken
    took = [row for row in welcomed if row["outcome"] == "registered"]
    summary = taken["summary"] + (f"\n- took on {len(took)} new customer(s) under the mandate: " + ", ".join(str(row.get("display_name") or row["party_ref"]) for row in took) if took else "")
    return {**taken, "new_customers": welcomed, "summary": summary}


def check_receipts(console: Any, *, now: str, exchange_ref: str | None = None, limit: Any = 50) -> dict[str, Any]:
    """What this company sent, with the platform's signed receipt and each recipient's signed settlement checked."""

    rows = _platform(console).receipts(exchange_ref=exchange_ref, limit=int(limit))
    signed = [row for row in rows if row["receipt"].get("verified")]
    failed = [row for row in rows if row["receipt"].get("code")]
    lines = [f"**Receipts**: {len(rows)} sent, {len(signed)} with a verified platform signature" + (f", {len(failed)} that did not check out" if failed else "")]
    for row in rows[:20]:
        settlement = row["settlement"]
        outcome = "waiting in their inbox" if settlement is None else f"{settlement['status']}" + (f" ({settlement['refusal_code']})" if settlement.get("refusal_code") else "") + (", signed" if settlement.get("verified") else "")
        lines.append(f"- {row['kind']} to {row['to_party']} ({row['exchange_ref']}): {outcome}")
    return {"receipts": rows, "count": len(rows), "as_of": timestamp(now, field_name="now"), "summary": "\n".join(lines), "provider_effect_executed": False}


def exchange_status_document(console: Any, *, now: str) -> dict[str, Any]:
    """Every exchange this company is in: where it stands, whose turn it is, and what waits on the owner."""

    from lightbulb.company_exchange import verify_thread

    at = timestamp(now, field_name="now")
    card = current_card(console)
    threads = []
    for record in console.store.list_all(engine=EXCHANGE_ENGINE):
        if not str(record.get("entity_ref", "")).startswith("thread:"):
            continue
        state = dict(record["state"])
        if state.get("schema") != EXCHANGE_RECORD_SCHEMA or state.get("status") == "withdrawn":
            continue
        thread = verify_thread(dict(state["thread"])["documents"])
        delivery = dict(state.get("delivery") or {})
        threads.append((thread, delivery))
    rows = []
    for thread, delivery in sorted(threads, key=lambda item: item[0].last().issued_at, reverse=True):
        waiting = [row["status"] for digest, row in delivery.items() if dict(row).get("status") in ("waiting_for_owner", "ready_to_deliver")]
        status, next_kind, next_from = thread.status, thread.next_kind, thread.next_from
        if quote_lapsed(thread, at=at) and not waiting:
            # nobody can order against it any more: the exchange is over, and a new quote starts a new one
            status, next_kind, next_from = "lapsed", None, None
        ours = card is not None and next_from == card.party_ref and not waiting
        if ours and next_kind == "remittance":
            # the remittance is owed once the books show the invoice paid; until then paying the bill is the payables chain's work
            ours = bool(dict(exchange_payment(console, thread.exchange_ref) or {}).get("paid"))
        rows.append({"exchange_ref": thread.exchange_ref, "buyer": thread.buyer, "seller": thread.seller, "status": status, "value": None if thread.value is None else str(thread.value), "next_kind": next_kind, "next_from": next_from, "our_turn": ours, "waiting": waiting, "last": thread.last().render()})
    lines = [f"**Exchanges** ({console.bundle.company_ref}, {at[:16]}): " + (f"{len(rows)} exchange(s) as {card.party_ref}" if card is not None else "no card yet (company_exchange card)")]
    lines.extend(f"- {row['exchange_ref']}: {row['status']}" + (f", {row['value']}" if row["value"] else "") + ("; waiting on the owner" if "waiting_for_owner" in row["waiting"] else "; ready to deliver by hand" if row["waiting"] else "; this company's turn" if row["our_turn"] else "") for row in rows[:20])
    return {"schema": EXCHANGE_STATUS_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "card": None if card is None else card.to_dict(), "exchanges": rows, "count": len(rows), "summary": "\n".join(lines), "provider_effect_executed": False}


# --------------------------------------------------------------------------- #
# The books
# --------------------------------------------------------------------------- #

EXCHANGE_BOOKS_SCHEMA = "lightbulb.commercial_exchange_books.v1"
#: The chain each side's books live in: the buyer's bill, the seller's sale and its invoice.
BOOKS_ENGINE_FOR: dict[str, str] = {"buyer": "payables_chain", "seller": "revenue_chain"}
_RECEIPTS_ENTITY = "receipts:"


def _books_entity(role: str, exchange_ref: str) -> str:
    return f"{'bill' if role == 'buyer' else 'sale'}:exchange:{exchange_ref}"


def _platform_receipts(console: Any, exchange_ref: str) -> tuple[dict[str, Any], Mapping[str, Any] | None]:
    record = console.store.get(EXCHANGE_ENGINE, f"{_RECEIPTS_ENTITY}{exchange_ref}")
    return ({} if record is None else dict(dict(record["state"]).get("receipts") or {})), record


def _keep_platform_receipt(console: Any, exchange_ref: str, document_digest: str, evidence: Mapping[str, Any], *, now: str) -> None:
    """The platform's receipt for a document received, kept beside the thread for the books' evidence."""

    receipts, record = _platform_receipts(console, exchange_ref)
    if receipts.get(document_digest) == dict(evidence):
        return
    receipts = {**receipts, document_digest: dict(evidence)}
    _put(console, f"{_RECEIPTS_ENTITY}{exchange_ref}", key="receipts", document=receipts, digest=stable_digest(receipts), now=now, status="kept", existing=record)


def _due_hops(thread: Any, delivery: Mapping[str, Any], role: str) -> list[tuple[str, Any]]:
    """The books hops an exchange has reached: the buyer's bill once the invoice is in; the seller's sale once its acceptance went, and its invoice once that went."""

    def status(document: Any) -> Any:
        return None if document is None else dict(delivery.get(document.document_digest) or {}).get("status")

    if role == "buyer":
        invoice = thread.document("invoice")
        return [("receive_bill", invoice)] if status(invoice) == "received" else []
    acknowledgement = thread.document("order_acknowledgement")
    if acknowledgement is None or acknowledgement.accepted is not True or status(acknowledgement) != "sent":
        return []
    invoice = thread.document("invoice")
    return [("hand_off", acknowledgement), ("execute_agreement", acknowledgement), *([("issue_invoice", invoice)] if status(invoice) == "sent" else [])]


def _book(console: Any, thread: Any, delivery: Mapping[str, Any], *, card: Any, now: str) -> dict[str, Any] | None:
    """Put what the exchange has reached in the books; a hop the books refuse is reported with the chain's code, never raised, since the document itself went or came."""

    from lightbulb.company_exchange_books import exchange_bill_receipt, exchange_sale_receipt, exchange_source
    from lightbulb.company_operator_surface import CompanyOperatorSurface

    role = "buyer" if thread.buyer == card.party_ref else "seller"
    hops = _due_hops(thread, delivery, role)
    if not hops:
        return None
    engine = BOOKS_ENGINE_FOR[role]
    entity_ref = _books_entity(role, thread.exchange_ref)
    outcome: dict[str, Any] = {"engine": engine, "entity_ref": entity_ref, "applied": [], "status": None}
    try:
        runtime = CompanyOperatorSurface(console).runtime(engine)
    except (LookupError, ValueError) as exc:
        return {**outcome, "code": "BOOKS_PLAN_MISSING", "detail": f"the company has no {engine} plan to book it in: {exc}"[:300]}
    receipts, _ = _platform_receipts(console, thread.exchange_ref)
    inbound = thread.document("invoice" if role == "buyer" else "purchase_order")
    evidence = None if inbound is None else receipts.get(inbound.document_digest)
    done: set[str] = set()
    if console.store.get(engine, entity_ref) is not None:
        state = runtime.load(entity_ref)
        done = {str(item.command.event) for item in state.transition_history}
        outcome["status"] = state.status
    at = timestamp(now, field_name="now")
    for event, document in hops:
        if event in done:
            continue
        try:
            source = exchange_source(list(thread.documents[: document.sequence]), party_ref=card.party_ref, platform_receipt=evidence)
            receipt = exchange_bill_receipt(source) if role == "buyer" else exchange_sale_receipt(source)
            if not done and not outcome["applied"]:
                scope = console.bundle.engine_scope(entity_ref)
                opening = receipt if role == "buyer" else {**receipt, "entity_scope": detached(scope)}
                state = runtime.spec.open(runtime.plan, scope, receipt=opening, opened_at=at, actor_ref=console.bundle.actor_ref)
                runtime.open(entity_ref, state)
            else:
                ref = f"exchange:{thread.exchange_ref}:{event}"
                command = runtime.command(runtime.load(entity_ref), event=event, transition_ref=ref, idempotency_key=ref, occurred_at=at, actor_ref=console.bundle.actor_ref, receipt=receipt)
                advanced = runtime.advance_and_persist(entity_ref, command)
                if not advanced.persisted:
                    refused = advanced.result.receipt
                    return {**outcome, "code": str(refused.rejection_code or "NOT_PERSISTED"), "detail": str(refused.recovery.instructions or "")[:300]}
                state = advanced.result.state
        except (ValueError, LookupError) as exc:
            return {**outcome, "code": str(getattr(exc, "code", None) or str(exc).split(":", 1)[0])[:60], "detail": str(exc)[:300]}
        outcome["applied"].append(event)
        outcome["status"] = state.status
    return outcome


def _with_books(console: Any, view: dict[str, Any], thread: Any, delivery: Mapping[str, Any], *, card: Any, now: str, received: Any = None, platform_receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if received is not None and platform_receipt is not None:
        _keep_platform_receipt(console, thread.exchange_ref, received.document_digest, platform_receipt, now=now)
    booked = _book(console, thread, delivery, card=card, now=now)
    if booked is not None and booked.get("applied") and _invoice_in_books(booked):
        booked["posting"] = _plan_posting(console, thread, card=card, now=now)
    view["books"] = booked
    return view


def _exchange_threads(console: Any) -> list[tuple[Any, dict[str, Any]]]:
    from lightbulb.company_exchange import verify_thread

    threads = []
    for record in console.store.list_all(engine=EXCHANGE_ENGINE):
        if not str(record.get("entity_ref", "")).startswith("thread:"):
            continue
        state = dict(record["state"])
        if state.get("schema") != EXCHANGE_RECORD_SCHEMA or state.get("status") == "withdrawn":
            continue
        threads.append((verify_thread(dict(state["thread"])["documents"]), dict(state.get("delivery") or {})))
    return sorted(threads, key=lambda item: item[0].last().issued_at, reverse=True)


def book_exchange(console: Any, *, now: str, exchange_ref: str | None = None) -> dict[str, Any]:
    """Put what an exchange (or every exchange) has reached in the books, where it is not there yet; nothing already booked is booked twice."""

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    if exchange_ref:
        thread, delivery, _ = _load_thread(console, str(exchange_ref))
        if thread is None:
            raise LookupError(f"no exchange {exchange_ref}")
        threads = [(thread, delivery)]
    else:
        threads = _exchange_threads(console)
    results = []
    for thread, delivery in threads:
        outcome = _book(console, thread, delivery, card=card, now=at)
        if outcome is not None:
            results.append({"exchange_ref": thread.exchange_ref, **outcome})
    booked = [row for row in results if row["applied"]]
    refused = [row for row in results if row.get("code")]
    lines = [f"**Exchange books**: {len(booked)} exchange(s) booked now, {len(results) - len(booked) - len(refused)} already in the books" + (f", {len(refused)} refused" if refused else "")]
    lines.extend(f"- {row['exchange_ref']}: {', '.join(row['applied'])} in the {row['engine'].replace('_', ' ')} ({row['status']})" for row in booked)
    lines.extend(f"- {row['exchange_ref']}: the {row['engine'].replace('_', ' ')} refused it ({row['code']}): {row['detail']}" for row in refused)
    return {"schema": EXCHANGE_BOOKS_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "results": results, "summary": "\n".join(lines), "provider_effect_executed": False}


LEDGER_MAP_ENTITY = "ledger:current"
#: The books statuses in which the case holds the exchange's invoice, so it can be posted.
_INVOICED_IN_BOOKS: frozenset[str] = frozenset({"bill_received", "approved", "scheduled", "paid", "cleared", "invoice_issued", "payment_applied", "cash_settled", "receivable_cleared"})


def _invoice_in_books(booked: Mapping[str, Any]) -> bool:
    return str(booked.get("status")) in _INVOICED_IN_BOOKS


def current_ledger_map(console: Any) -> Any | None:
    """The ledger map the owner set, or None."""

    from lightbulb.company_exchange_ledger import verify_ledger_map

    record = console.store.get(EXCHANGE_ENGINE, LEDGER_MAP_ENTITY)
    return None if record is None else verify_ledger_map(dict(record["state"])["ledger"])


def set_ledger_map(console: Any, *, now: str, provider: str | None = None, suppliers: Mapping[str, Any] | None = None, customers: Mapping[str, Any] | None = None, bill_account: str | None = None,
                   sales_item: str | None = None, sales_account: str | None = None, items: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Say who each trading partner is in the ledger and where a bill's and an invoice's lines go.

    What is not given keeps its current value; a partner or item given an empty id is taken out;
    naming another ledger starts the map afresh.  With nothing given, the map as it stands.
    """

    from lightbulb.company_exchange import ExchangeError
    from lightbulb.company_exchange_ledger import compile_ledger_map

    at = timestamp(now, field_name="now")
    current = current_ledger_map(console)
    record = console.store.get(EXCHANGE_ENGINE, LEDGER_MAP_ENTITY)
    given = [value for value in (provider, suppliers, customers, bill_account, sales_item, sales_account, items) if value is not None]
    if not given:
        if current is None:
            raise ExchangeError("LEDGER_MAP_MISSING", "no ledger map yet: name the ledger (provider quickbooks or xero) and the trading partners in it")
        return {**current.to_dict(), "stored": {"entity_ref": LEDGER_MAP_ENTITY, "unchanged": True}, "summary": current.render(), "provider_effect_executed": False}
    base = {} if current is None or (provider is not None and provider != current.provider) else current.to_dict()
    chosen = provider or base.get("provider")
    if chosen is None:
        raise ExchangeError("LEDGER_PROVIDER_REQUIRED", "name the ledger the exchange posts to: quickbooks or xero")

    def merged(field: str, update: Mapping[str, Any] | None) -> dict[str, Any]:
        kept = dict(base.get(field) or {})
        for key, value in dict(update or {}).items():
            if value in (None, ""):
                kept.pop(str(key), None)
            else:
                kept[str(key)] = value
        return kept

    def single(field: str, value: str | None) -> str | None:
        return base.get(field) if value is None else (str(value).strip() or None)

    ledger = compile_ledger_map(console.bundle.company_ref, provider=str(chosen), currency=console.bundle.operating_plan.blueprint.currency, now=at, suppliers=merged("suppliers", suppliers),
                                customers=merged("customers", customers), bill_account=single("bill_account", bill_account), sales_item=single("sales_item", sales_item),
                                sales_account=single("sales_account", sales_account), items=merged("items", items))
    content = stable_digest({key: value for key, value in ledger.to_dict().items() if key not in ("updated_at", "map_digest")})
    if current is not None and stable_digest({key: value for key, value in current.to_dict().items() if key not in ("updated_at", "map_digest")}) == content:
        return {**current.to_dict(), "stored": {"entity_ref": LEDGER_MAP_ENTITY, "unchanged": True}, "summary": current.render(), "provider_effect_executed": False}
    stored = _put(console, LEDGER_MAP_ENTITY, key="ledger", document=ledger.to_dict(), digest=ledger.map_digest, now=at, status="set", existing=record)
    return {**ledger.to_dict(), "stored": stored, "summary": ledger.render(), "provider_effect_executed": False}


def _posting_action(console: Any, thread: Any, *, card: Any) -> Any | None:
    """The owner action posting this exchange's invoice, if one was planned."""

    from lightbulb.company_act_surface import OWNER_ACTION_ENGINE
    from lightbulb.owner_actions import action_ref_for, verify_owner_action

    side = "payable" if thread.buyer == card.party_ref else "receivable"
    record = console.store.get(OWNER_ACTION_ENGINE, f"action:{action_ref_for(console.bundle.company_ref, 'exchange_books', f'ledger:{side}:{thread.exchange_ref}')}")
    return None if record is None else verify_owner_action(dict(record["state"])["action"])


def _plan_posting(console: Any, thread: Any, *, card: Any, now: str) -> dict[str, Any]:
    """Plan the ledger posting of an invoice the books hold, once, when the ledger map names the trading partner; the act loop sends it. What stops it is reported, never raised."""

    from lightbulb.company_act_surface import record_owner_actions
    from lightbulb.company_exchange_ledger import ledger_posting
    from lightbulb.company_operator_surface import check_mandate
    from lightbulb.owner_actions import action_from_ledger_posting

    existing = _posting_action(console, thread, card=card)
    if existing is not None:
        return {"action_ref": existing.action_ref, "tool": existing.tool, "status": existing.status, "planned": False}
    ledger = current_ledger_map(console)
    if ledger is None:
        return {"status": None, "code": "LEDGER_MAP_MISSING", "detail": "no ledger map yet: company_exchange ledger names the ledger and the trading partners in it"}
    try:
        posting = ledger_posting(thread, party_ref=card.party_ref, ledger_map=ledger)
        decision = check_mandate(console, now=now, action_kind="post_to_ledger", money=posting["total"], subject=f"{posting['side']}:{thread.exchange_ref}:{posting['counterparty']}"[:300])
        action = action_from_ledger_posting(posting, company_ref=console.bundle.company_ref, now=now, autonomy=str(decision["autonomy"]), authority=str(decision["reason"]))
    except (ValueError, LookupError) as exc:
        return {"status": None, "code": str(getattr(exc, "code", None) or str(exc).split(":", 1)[0])[:60], "detail": str(exc)[:300]}
    record_owner_actions(console, [action], now=now)
    return {"action_ref": action.action_ref, "tool": action.tool, "status": action.status, "planned": True, "reference": posting["reference"], "autonomy": action.autonomy}


def post_exchange_to_ledger(console: Any, *, now: str, exchange_ref: str | None = None) -> dict[str, Any]:
    """Plan the ledger posting of every invoice the books hold that has none yet (or of one exchange's); the act loop sends each through the platform."""

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    if exchange_ref:
        thread, delivery, _ = _load_thread(console, str(exchange_ref))
        if thread is None:
            raise LookupError(f"no exchange {exchange_ref}")
        threads = [(thread, delivery)]
    else:
        threads = _exchange_threads(console)
    results = []
    for thread, _delivery in threads:
        role = "buyer" if thread.buyer == card.party_ref else "seller"
        record = console.store.get(BOOKS_ENGINE_FOR[role], _books_entity(role, thread.exchange_ref))
        if record is None or not _invoice_in_books({"status": dict(record["state"]).get("status")}):
            continue
        results.append({"exchange_ref": thread.exchange_ref, **_plan_posting(console, thread, card=card, now=at)})
    planned = [row for row in results if row.get("planned")]
    stopped = [row for row in results if row.get("code")]
    lines = [f"**Ledger postings**: {len(planned)} planned now, {len(results) - len(planned) - len(stopped)} planned before" + (f", {len(stopped)} not planned" if stopped else "")]
    lines.extend(f"- {row['exchange_ref']}: {row['tool']} planned ({row['autonomy']} under the mandate)" for row in planned)
    lines.extend(f"- {row['exchange_ref']}: not planned ({row['code']}): {row['detail']}" for row in stopped)
    if planned:
        lines.append("- company_act dispatch (with the ledger tool's connector account) sends them; the platform's financial reviewer approves each write")
    return {"schema": EXCHANGE_BOOKS_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "results": results, "summary": "\n".join(lines), "provider_effect_executed": False}


def _posting_view(console: Any, thread: Any, *, card: Any) -> dict[str, Any] | None:
    from lightbulb.company_exchange_ledger import bill_write_receipt

    action = _posting_action(console, thread, card=card)
    if action is None:
        return None
    view: dict[str, Any] = {"action_ref": action.action_ref, "tool": action.tool, "status": action.status, "approval_ref": action.approval_ref, "journal_ref": (action.receipt or {}).get("journal_ref"), "note": action.note}
    if action.status == "done" and action.tool == "quickbooks.create_bill":
        view["bill_write"] = bill_write_receipt(action)
    return {key: value for key, value in view.items() if value is not None}


def exchange_books_document(console: Any, *, now: str) -> dict[str, Any]:
    """What the exchange put in the books: each sale and its invoice, each bill, what is owed each way, what is not booked yet, and the reference a ledger posting of each invoice carries."""

    from lightbulb.company_exchange_books import invoice_due_at, ledger_reference
    from lightbulb.payables_chain import OPEN_PAYABLE_STATUSES

    at = timestamp(now, field_name="now")
    card = current_card(console)
    rows: list[dict[str, Any]] = []
    owed_to_us: dict[str, Decimal] = {}
    owed_by_us: dict[str, Decimal] = {}
    booked_not_invoiced: dict[str, Decimal] = {}
    for thread, delivery in ([] if card is None else _exchange_threads(console)):
        role = "buyer" if thread.buyer == card.party_ref else "seller"
        hops = [event for event, _ in _due_hops(thread, delivery, role)]
        if not hops:
            continue
        engine = BOOKS_ENGINE_FOR[role]
        entity_ref = _books_entity(role, thread.exchange_ref)
        record = console.store.get(engine, entity_ref)
        state = {} if record is None else dict(record["state"])
        ledger = dict(state.get("ledger") or {})
        applied = {str(dict(item.get("command") or {}).get("event")) for item in state.get("transition_history") or ()}
        invoice = thread.document("invoice")
        invoiced = invoice is not None and ("issue_invoice" in hops or "receive_bill" in hops)
        status = state.get("status")
        if role == "seller" and status in ("invoice_issued", "payment_applied"):
            outstanding = Decimal(str(ledger.get("invoice_total", "0"))) - Decimal(str(ledger.get("applied_amount", "0")))
            owed_to_us[thread.currency] = owed_to_us.get(thread.currency, Decimal("0")) + outstanding
        elif role == "seller" and status == "agreement_executed":
            booked_not_invoiced[thread.currency] = booked_not_invoiced.get(thread.currency, Decimal("0")) + Decimal(str(ledger.get("accepted_amount", "0")))
        elif role == "buyer" and status in OPEN_PAYABLE_STATUSES:
            outstanding = Decimal(str(ledger.get("amount", "0"))) - Decimal(str(ledger.get("applied_amount", "0")))
            owed_by_us[thread.currency] = owed_by_us.get(thread.currency, Decimal("0")) + outstanding
        rows.append({"exchange_ref": thread.exchange_ref, "role": role, "counterparty": thread.seller if role == "buyer" else thread.buyer, "engine": engine, "entity_ref": entity_ref,
                     "books_status": status, "not_booked": [event for event in hops if event not in applied], "currency": thread.currency,
                     "value": None if thread.value is None else str(thread.value), "invoiced": invoiced, "due_at": invoice_due_at(invoice) if invoiced else None,
                     "ledger_reference": ledger_reference(invoice.document_digest, side="payable" if role == "buyer" else "receivable") if invoiced else None,
                     "posting": _posting_view(console, thread, card=card) if invoiced else None})

    def money(totals: Mapping[str, Decimal]) -> str:
        return ", ".join(f"{amount:.2f} {currency}" for currency, amount in sorted(totals.items())) or "nothing"

    sales = [row for row in rows if row["role"] == "seller"]
    bills = [row for row in rows if row["role"] == "buyer"]
    missing = [row for row in rows if row["not_booked"]]
    lines = [f"**The exchange in the books** ({console.bundle.company_ref}, {at[:16]}): " + (f"{len(sales)} sale(s), {len(bills)} bill(s); owed to this company {money(owed_to_us)}, owed by it {money(owed_by_us)}, booked not yet invoiced {money(booked_not_invoiced)}" if card is not None else "no card yet (company_exchange card)")]
    for row in rows[:20]:
        what = f"sale to {row['counterparty']}" if row["role"] == "seller" else f"bill from {row['counterparty']}"
        state_text = row["books_status"] or "not in the books"
        posting = dict(row.get("posting") or {})
        if posting.get("status") == "done":
            ledger_text = f"; in the ledger as {row['ledger_reference']} (journal {posting.get('journal_ref')})"
        elif posting.get("status") == "awaiting_approval":
            ledger_text = f"; posting {row['ledger_reference']} waits for the platform's approval ({posting.get('approval_ref')})"
        elif posting.get("status"):
            ledger_text = f"; posting {row['ledger_reference']} is {posting['status'].replace('_', ' ')}" + (f": {posting['note']}" if posting.get("note") else "")
        elif row["invoiced"]:
            ledger_text = f"; not in the ledger yet (its posting gives {row['ledger_reference']} as its number)"
        else:
            ledger_text = ""
        tail = f"; due {str(row['due_at'])[:10]}{ledger_text}" if row["invoiced"] else ""
        lines.append(f"- {row['exchange_ref']} ({what}, {row['value']} {row['currency']}): {state_text}{tail}")
    if missing:
        lines.append(f"- not in the books yet: {', '.join(row['exchange_ref'] for row in missing[:10])}; company_exchange book puts them in")
    return {"schema": EXCHANGE_BOOKS_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "books": rows, "count": len(rows),
            "owed_to_us": {currency: f"{amount:.2f}" for currency, amount in owed_to_us.items()}, "owed_by_us": {currency: f"{amount:.2f}" for currency, amount in owed_by_us.items()},
            "booked_not_invoiced": {currency: f"{amount:.2f}" for currency, amount in booked_not_invoiced.items()}, "summary": "\n".join(lines), "provider_effect_executed": False}


__all__ = [
    "BOOKS_ENGINE_FOR",
    "CARD_ENTITY",
    "EXCHANGE_BOOKS_SCHEMA",
    "EXCHANGE_ENGINE",
    "EXCHANGE_RECORD_SCHEMA",
    "EXCHANGE_STATUS_SCHEMA",
    "acknowledge_order",
    "book_exchange",
    "current_ledger_map",
    "build_card_document",
    "check_receipts",
    "current_card",
    "exchange_books_document",
    "exchange_status_document",
    "find_in_directory",
    "invoice_order",
    "list_counterparties",
    "order_from_quote",
    "post_exchange_to_ledger",
    "publish_to_directory",
    "quote_lapsed",
    "quote_request",
    "receive_document",
    "register_counterparty",
    "request_quote",
    "search_directory",
    "exchange_payment",
    "held_for_remittance",
    "remit_invoice",
    "describe_track_record",
    "track_record_document",
    "welcome_new_customers",
    "send_document",
    "set_ledger_map",
    "take_in_inbox",
    "withdraw_document",
]
