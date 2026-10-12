"""Sourcing: what the company needs, quoted by suppliers it finds in the platform's directory, and ordered from the best.

A sourcing request says what to buy (the words a buyer would search for, the quantity and the unit), in which
currency, by when, and at most at what price. From it the console:

* **finds** listed suppliers of it in the platform's directory and shortlists up to ``suppliers`` of them: on each
  card the offer that matches the most words (in the unit and kind asked for), the most relevant first, then those
  whose track record shows they answer requests for quote (a supplier new on the exchange before one that seldom
  answers), then the cheapest; never a company this one blocked, never one that takes no requests for quote;
* **asks** each for a quote, under the mandate's ``message_supplier``: when the owner lets the agent message suppliers
  alone it registers each supplier and sends the request; when the mandate asks, the shortlist waits for the owner,
  who approves it by sourcing again with ``owner_ref``;
* **compares** the quotes that come back, in the request's currency: those still valid and within the ceiling, the
  lowest total first and then the longest payment terms. The comparison is ready once every supplier has answered or
  the reply date has passed;
* **awards** the best, as a purchase order under the mandate's ``place_order``, so the cap and the month's envelope
  apply and the owner decides when the mandate asks. A quote over the budget, a choice other than the best, and an
  award before every answer is in are the owner's. When the supplier declines the order, the next best is ready.

The quotes not chosen are left to lapse. The autopilot awards a request that is ready and leaves its other quotes
alone: while a sourcing request owns an exchange, no quote in it is ordered on its own.

``shortlist`` and ``compare_quotes`` are pure; the console functions record the request (engine
``commercial_exchange``, entity ``sourcing:<ref>``) and act through the exchange surface.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
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

SOURCING_SCHEMA = "lightbulb.exchange_sourcing_request.v1"
SOURCING_VIEW_SCHEMA = "lightbulb.exchange_sourcing.v1"
SOURCING_LIST_SCHEMA = "lightbulb.exchange_sourcing_list.v1"
SOURCING_PREFIX = "sourcing:"
MAX_SUPPLIERS = 5
DEFAULT_SUPPLIERS = 3
DEFAULT_REPLY_DAYS = 3
MAX_REPLY_DAYS = 30
OFFER_KINDS: tuple[str, ...] = ("plan", "sku", "service", "rate")
# what the autopilot still decides: everything but a request that is ordered, dropped, expired or found nobody
OPEN_STATUSES: frozenset[str] = frozenset({"shortlisted", "asking", "ready", "over_budget", "no_quotes", "order_waiting", "declined"})
# the platform's refusals of an order that are about the supplier, so the next best is tried instead
SUPPLIER_REFUSALS: frozenset[str] = frozenset({"RECIPIENT_NOT_FOUND", "KIND_NOT_ACCEPTED", "SENDER_BLOCKED", "TO_PARTY_NOT_RECIPIENT", "COUNTERPARTY_CLOSED", "COUNTERPARTY_WINDING_DOWN",
                                               "COUNTERPARTY_UNKNOWN"})
_WORD = re.compile(r"[^\W_]+")


class SourcingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SourcingError(code, message)


def words(text: Any) -> list[str]:
    """The words of a text as the directory matches them: letters and digits in any script, composed and lowercase."""

    return _WORD.findall(unicodedata.normalize("NFC", str(text or "")).lower())


# --------------------------------------------------------------------------- #
# The request
# --------------------------------------------------------------------------- #


class SourcingRequest(StrictModel):
    """What the company needs to buy, sealed: the words, the quantity, the currency, the dates and the ceiling."""

    schema_id: str = Field(default=SOURCING_SCHEMA, alias="schema")
    sourcing_ref: OpaqueRef
    company_ref: OpaqueRef
    query: ShortText
    quantity: Decimal
    unit: ShortText | None = None
    kind: Literal["plan", "sku", "service", "rate"] | None = None
    currency: CurrencyCode
    country: ShortText | None = None
    needed_by: str | None = None
    reply_by: str
    max_unit_price: Decimal | None = None
    budget: Decimal | None = None
    suppliers: int = Field(default=DEFAULT_SUPPLIERS, ge=1, le=MAX_SUPPLIERS)
    for_ref: OpaqueRef | None = None
    requested_by: OpaqueRef | None = None
    created_at: str
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("quantity", "max_unit_price", "budget", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("created_at", "reply_by", "needed_by")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "SourcingRequest":
        if self.quantity <= 0:
            raise ValueError("a sourcing request asks for more than nothing")
        if not words(self.query):
            raise ValueError("a sourcing request says what to look for")
        for name in ("max_unit_price", "budget"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} is more than nothing")
        if parsed(self.reply_by) <= parsed(self.created_at) or parsed(self.reply_by) > parsed(self.created_at) + timedelta(days=MAX_REPLY_DAYS):
            raise ValueError(f"quotes are asked for within {MAX_REPLY_DAYS} days of the request")
        if self.needed_by is not None and parsed(self.needed_by) < parsed(self.reply_by):
            raise ValueError("the goods cannot be needed before the quotes are in")
        if not skip_digests(info) and self.request_digest != sealed_digest(SourcingRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self

    def render(self) -> str:
        head = f"{self.quantity} {self.unit or 'units'} of '{self.query}' in {self.currency}" + (f" (a {self.kind})" if self.kind else "") + (f" from {self.country}" if self.country else "")
        limits = [f"quotes by {self.reply_by[:16]}"] + ([f"needed by {self.needed_by[:10]}"] if self.needed_by else []) \
            + ([f"at most {self.max_unit_price} a unit"] if self.max_unit_price is not None else []) + ([f"at most {self.budget} in all"] if self.budget is not None else [])
        return f"{head}; {', '.join(limits)}" + (f"; for {self.for_ref}" if self.for_ref else "")


def build_sourcing_request(*, company_ref: str, query: str, quantity: Any, currency: str, created_at: str, reply_by: str | None = None, unit: str | None = None, kind: str | None = None,
                           country: str | None = None, needed_by: str | None = None, max_unit_price: Any = None, budget: Any = None, suppliers: Any = None,
                           for_ref: str | None = None, requested_by: str | None = None, sourcing_ref: str | None = None) -> SourcingRequest:
    at = timestamp(created_at, field_name="created_at")
    text = " ".join(str(query or "").split())[:300]
    _require(bool(words(text)), "QUERY_REQUIRED", "say what to buy, in the words a supplier's card would use")
    _require(kind is None or kind in OFFER_KINDS, "KIND_INVALID", "kind is plan, sku, service or rate")
    reply = reply_by or (parsed(at) + timedelta(days=DEFAULT_REPLY_DAYS)).isoformat().replace("+00:00", "Z")
    ref = sourcing_ref or "src:" + stable_digest({"company_ref": company_ref, "query": text, "quantity": str(quantity), "unit": unit, "at": at})[:20]
    try:
        return seal(SourcingRequest, {"sourcing_ref": ref, "company_ref": company_ref, "query": text, "quantity": str(quantity), "unit": unit or None, "kind": kind or None,
                                      "currency": str(currency).upper(), "country": str(country).upper() if country else None, "needed_by": needed_by, "reply_by": reply,
                                      "max_unit_price": None if max_unit_price in (None, "") else str(max_unit_price), "budget": None if budget in (None, "") else str(budget),
                                      "suppliers": DEFAULT_SUPPLIERS if suppliers in (None, "") else int(suppliers), "for_ref": for_ref, "requested_by": requested_by, "created_at": at}, "request_digest")
    except ValidationError as exc:
        raise SourcingError("SOURCING_INVALID", "; ".join(str(error["msg"]).removeprefix("Value error, ") for error in exc.errors())[:300]) from exc
    except ValueError as exc:
        raise SourcingError("SOURCING_INVALID", str(exc)[:300]) from exc


def verify_sourcing_request(value: Any) -> SourcingRequest:
    return value if isinstance(value, SourcingRequest) else SourcingRequest.model_validate(dict(detached(value)))


# --------------------------------------------------------------------------- #
# Shortlisting
# --------------------------------------------------------------------------- #


def offer_score(query_words: Sequence[str], offer: Mapping[str, Any]) -> int:
    """How many of the words a word of the offer's name or item reference begins."""

    offered = words(f"{offer.get('name') or ''} {offer.get('item_ref') or ''}")
    return sum(1 for word in query_words if any(candidate.startswith(word) for candidate in offered))


def pick_offer(request: SourcingRequest, offers: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    """The offer on a card that answers the request: in its kind and unit, matching the most words, then the cheapest."""

    query_words = words(request.query)
    scored = []
    for offer in offers:
        if request.kind is not None and offer.get("kind") != request.kind:
            continue
        if request.unit is not None and str(offer.get("unit") or "each") != request.unit:
            continue
        score = offer_score(query_words, offer)
        if score:
            scored.append((-score, Decimal(str(offer.get("list_price"))), str(offer.get("item_ref")), dict(offer), score))
    if not scored:
        return None
    best = min(scored, key=lambda row: row[:3])
    return {**best[3], "score": best[4]}


def reliability(record: Mapping[str, Any] | None) -> int:
    """How a supplier answers requests for quote, from its track record: 0 most of them (75% or more), 2 few (under 50%), 1 unknown or between."""

    rate = dict(dict(record or {}).get("as_seller") or {}).get("answer_rate")
    if rate is None:
        return 1
    return 0 if int(rate) >= 75 else 2 if int(rate) < 50 else 1


def shortlist(request: SourcingRequest | Mapping[str, Any], results: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The suppliers to ask, best first, and the ones left out with why, from the directory's search results.

    Each result is a row of ``search_directory``: the card's address, party, currency, terms, accepted documents, offers
    and whether the company is already a counterparty. A candidate names the offer to ask for and what the request would
    cost at its list price; the quote is what binds.
    """

    parsed_request = verify_sourcing_request(request)
    candidates, left_out = [], []
    for row in results:
        name = str(row.get("display_name") or row.get("party_ref"))
        out = {"party_ref": row.get("party_ref"), "display_name": name, "address": row.get("address")}
        if row.get("counterparty") == "blocked":
            left_out.append({**out, "why": "this company blocked it"})
            continue
        if "rfq" not in list(row.get("accepts") or []):
            left_out.append({**out, "why": "it takes no requests for quote"})
            continue
        if str(row.get("currency")) != parsed_request.currency:
            left_out.append({**out, "why": f"it sells in {row.get('currency')}, not {parsed_request.currency}"})
            continue
        offer = pick_offer(parsed_request, list(row.get("offers") or []))
        if offer is None:
            wanted = " ".join(filter(None, [parsed_request.kind, f"per {parsed_request.unit}" if parsed_request.unit else None]))
            left_out.append({**out, "why": "no offer on its card matches the words" + (f" ({wanted})" if wanted else "")})
            continue
        price = Decimal(str(offer["list_price"]))
        if parsed_request.max_unit_price is not None and price > parsed_request.max_unit_price:
            left_out.append({**out, "why": f"it lists {offer.get('name') or offer['item_ref']} at {price}, above the {parsed_request.max_unit_price} ceiling"})
            continue
        estimate = (price * parsed_request.quantity).quantize(Decimal("0.01"))
        candidates.append({**out, "item_ref": str(offer["item_ref"]), "offer_name": offer.get("name"), "unit": str(offer.get("unit") or "each"), "list_price": str(price),
                           "estimate": str(estimate), "score": int(offer["score"]), "terms_days": row.get("terms_days"), "counterparty": row.get("counterparty"),
                           "reliability": reliability(row.get("track_record")), "track_record": row.get("track_record")})
    candidates.sort(key=lambda row: (-row["score"], row["reliability"], Decimal(row["estimate"]), -int(row.get("terms_days") or 0), str(row["display_name"]), str(row["party_ref"])))
    for row in candidates[parsed_request.suppliers:]:
        rate = dict(dict(row.get("track_record") or {}).get("as_seller") or {}).get("answer_rate")
        why = f"it answers {rate}% of requests for quote" if row["reliability"] == 2 else f"the {parsed_request.suppliers} asked match better, answer more often or cost less"
        left_out.append({key: row[key] for key in ("party_ref", "display_name", "address")} | {"why": why})
    return candidates[:parsed_request.suppliers], left_out


# --------------------------------------------------------------------------- #
# Comparing
# --------------------------------------------------------------------------- #


def compare_quotes(request: SourcingRequest | Mapping[str, Any], asked: Sequence[Mapping[str, Any]], *, now: str) -> dict[str, Any]:
    """The quotes in, compared: eligible ones best first, those over the budget, those out with why, and who has not answered.

    ``asked`` rows carry ``party_ref``, ``display_name``, ``exchange_ref``, the verified ``thread`` (or None) and the
    ``order`` delivery status of this company's purchase order in it (or None). ``ready`` is true once every supplier
    asked has answered or the reply date has passed.
    """

    parsed_request = verify_sourcing_request(request)
    at = timestamp(now, field_name="now")
    eligible, over_budget, out, waiting, ordered = [], [], [], [], []
    for row in asked:
        thread = row.get("thread")
        base = {"party_ref": row.get("party_ref"), "display_name": row.get("display_name"), "exchange_ref": row.get("exchange_ref")}
        if thread is None:
            out.append({**base, "why": str(row.get("why") or "no request went to it")})
            continue
        quote = thread.document("quote")
        if quote is None:
            (waiting if row.get("sent") else out).append({**base, "why": "no quote yet" if row.get("sent") else "the request waits to be sent"})
            continue
        unit_price = quote.lines[0].unit_price
        entry = {**base, "total": str(quote.total), "unit_price": str(unit_price), "currency": quote.currency, "terms_days": quote.terms_days, "valid_until": quote.valid_until,
                 "item_ref": quote.lines[0].item_ref, "quoted_at": quote.issued_at}
        if thread.status == "declined":
            out.append({**entry, "why": "it declined this company's order"})
            continue
        if row.get("refused"):
            out.append({**entry, "why": f"the platform refused the order ({row['refused']})"})
            continue
        if row.get("order") in ("sent", "received"):
            ordered.append({**entry, "order": row.get("order"), "status": thread.status})
            continue
        if row.get("order") in ("waiting_for_owner", "ready_to_deliver"):
            ordered.append({**entry, "order": row.get("order"), "status": "order_waiting"})
            continue
        if quote.valid_until is not None and parsed(at) > parsed(str(quote.valid_until)):
            out.append({**entry, "why": f"the quote lapsed {str(quote.valid_until)[:16]}"})
            continue
        if quote.currency != parsed_request.currency:
            out.append({**entry, "why": f"quoted in {quote.currency}, not {parsed_request.currency}"})
            continue
        if parsed_request.max_unit_price is not None and unit_price is not None and unit_price > parsed_request.max_unit_price:
            over_budget.append({**entry, "why": f"{unit_price} a unit is above the {parsed_request.max_unit_price} ceiling"})
            continue
        if parsed_request.budget is not None and quote.total is not None and quote.total > parsed_request.budget:
            over_budget.append({**entry, "why": f"{quote.total} is above the {parsed_request.budget} budget"})
            continue
        eligible.append(entry)

    def rank(entry: Mapping[str, Any]) -> tuple[Any, ...]:
        return (Decimal(str(entry["total"])), -int(entry.get("terms_days") or 0), str(entry.get("quoted_at")), str(entry["party_ref"]))

    eligible.sort(key=rank)
    over_budget.sort(key=rank)
    past_reply_by = parsed(at) >= parsed(parsed_request.reply_by)
    return {"eligible": eligible, "over_budget": over_budget, "out": out, "waiting": waiting, "ordered": ordered, "ready": not waiting or past_reply_by,
            "past_reply_by": past_reply_by, "best": eligible[0] if eligible else None, "reply_by": parsed_request.reply_by}


def sourcing_status(compared: Mapping[str, Any], *, stored: str) -> str:
    """Where a sourcing request stands, from its stored step and the quotes compared now."""

    if stored == "shortlisted" and compared.get("past_reply_by"):
        return "expired"
    if stored in ("dropped", "no_suppliers", "shortlisted"):
        return stored
    ordered = list(compared.get("ordered") or [])
    if any(row.get("order") in ("sent", "received") for row in ordered):
        return "ordered"
    if ordered:
        return "order_waiting"
    if not compared.get("ready"):
        return "asking"
    if compared.get("eligible"):
        return "declined" if any("declined" in str(row.get("why")) or "refused the order" in str(row.get("why")) for row in compared.get("out") or []) else "ready"
    if compared.get("over_budget"):
        return "over_budget"
    return "no_quotes"


# --------------------------------------------------------------------------- #
# The console
# --------------------------------------------------------------------------- #


def _entity(sourcing_ref: str) -> str:
    return f"{SOURCING_PREFIX}{sourcing_ref}"


def _load(console: Any, sourcing_ref: str) -> tuple[SourcingRequest | None, dict[str, Any], Mapping[str, Any] | None]:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    record = console.store.get(EXCHANGE_ENGINE, _entity(sourcing_ref))
    if record is None:
        return None, {}, None
    state = dict(record["state"])
    return verify_sourcing_request(state["sourcing"]), state, record


def _save(console: Any, request: SourcingRequest, state: Mapping[str, Any], *, now: str, status: str, existing: Mapping[str, Any] | None) -> dict[str, Any]:
    from lightbulb.company_exchange_surface import _put

    extra = {key: state.get(key) for key in ("shortlist", "left_out", "asked", "awards", "refused", "search", "dropped") if key in state}
    digest = stable_digest({"request": request.request_digest, "status": status, **extra})
    return _put(console, _entity(request.sourcing_ref), key="sourcing", document=request.to_dict(), digest=digest, now=now, status=status, existing=existing, extra=extra)


def _owner_approves(console: Any, owner_ref: str | None) -> bool:
    from lightbulb.company_exchange import ExchangeError
    from lightbulb.company_operator_surface import current_mandate

    if owner_ref is None:
        return False
    mandate = current_mandate(console)
    if mandate is None or str(owner_ref) != mandate.owner_ref:
        raise ExchangeError("NOT_THE_OWNER", "only the mandate's owner approves on the owner's behalf")
    return True


def _asked_rows(console: Any, state: Mapping[str, Any]) -> list[dict[str, Any]]:
    from lightbulb.company_exchange_surface import _load_thread

    refused = {str(row["exchange_ref"]): str(row["code"]) for row in state.get("refused") or []}
    rows = []
    for asked in state.get("asked") or []:
        row = dict(asked)
        row["refused"] = refused.get(str(row.get("exchange_ref")))
        thread, delivery, record = _load_thread(console, str(row["exchange_ref"])) if row.get("exchange_ref") else (None, {}, None)
        if record is not None and dict(record["state"]).get("status") == "withdrawn":
            thread = None
            row["why"] = "the request was withdrawn"
        row["thread"] = thread
        if thread is not None:
            rfq = thread.document("rfq")
            row["sent"] = rfq is not None and dict(delivery.get(rfq.document_digest) or {}).get("status") in ("sent", "received")
            order = thread.document("purchase_order")
            row["order"] = None if order is None else dict(delivery.get(order.document_digest) or {}).get("status")
        rows.append(row)
    return rows


def _view(console: Any, request: SourcingRequest, state: Mapping[str, Any], *, now: str, stored: Mapping[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    at = timestamp(now, field_name="now")
    compared = compare_quotes(request, _asked_rows(console, state), now=at)
    status = sourcing_status(compared, stored=str(state.get("status")))
    best = compared["best"]
    lines = [f"**Sourcing {request.sourcing_ref}** ({status.replace('_', ' ')}): {request.render()}"]
    asked = list(state.get("asked") or [])
    if status == "no_suppliers":
        refused = [row for row in state.get("asked") or [] if not row.get("exchange_ref")]
        lines.append(f"- none of the {len(refused)} supplier(s) found could be asked ({', '.join(sorted({str(row.get('code')) for row in refused}))}): source again, or drop it" if refused
                     else "- no listed supplier matched: source again with other words, a wider currency or country, or none of the ceiling")
    if status == "shortlisted":
        names = ", ".join(f"{row['display_name']} ({row['offer_name'] or row['item_ref']} at {row['list_price']})" for row in state.get("shortlist") or [])
        lines.append(f"- shortlisted {names}; the mandate asks the owner before the agent messages suppliers: company_exchange source with sourcing_ref and owner_ref asks them")
    if asked and status != "shortlisted":
        sent = [row for row in asked if row.get("exchange_ref")]
        lines.append(f"- asked {len(sent)} of {len(asked)}: " + "; ".join(f"{row['display_name']}" + ("" if row.get("exchange_ref") else f" (not asked: {row.get('code') or 'refused'})") for row in asked))
    for row in compared["eligible"]:
        lines.append(f"- {row['display_name']}: {row['total']} {row['currency']} ({row['unit_price']} a unit), pay in {row.get('terms_days')} days, holds until {str(row.get('valid_until'))[:10]}")
    for row in compared["over_budget"]:
        lines.append(f"- {row['display_name']}: {row['total']} {row['currency']}: {row['why']}")
    for row in compared["waiting"]:
        lines.append(f"- {row['display_name']}: no quote yet (quotes by {request.reply_by[:16]})")
    for row in compared["out"]:
        if row.get("exchange_ref"):
            lines.append(f"- {row['display_name']}: out ({row['why']})")
    next_step = {
        "asking": f"waiting for quotes until {request.reply_by[:16]}; the best is ordered once every supplier has answered or then",
        "ready": None if best is None else f"best: {best['display_name']} at {best['total']} {best['currency']}; ordering it is next (company_exchange award; the autopilot does it under the mandate)",
        "declined": None if best is None else f"the supplier chosen declined the order or could not take it; next best: {best['display_name']} at {best['total']} {best['currency']} (company_exchange award)",
        "expired": "the owner did not approve the shortlist before its reply date: make a new sourcing request",
        "over_budget": "every quote in is over the budget or the ceiling: the owner decides (company_exchange award with exchange_ref and owner_ref, or drop)",
        "no_quotes": "no quote came in by the reply date: source again (other words or more suppliers) or drop it",
        "order_waiting": "the order is prepared and waits for the owner (company_exchange send with owner_ref)",
        "ordered": "ordered: the supplier's acknowledgement and invoice come through the inbox",
        "dropped": f"dropped: {dict(state.get('dropped') or {}).get('reason', '')}",
    }.get(status)
    if next_step:
        lines.append(f"- {next_step}")
    return {"schema": SOURCING_VIEW_SCHEMA, "sourcing_ref": request.sourcing_ref, "status": status, "request": request.to_dict(), "shortlist": list(state.get("shortlist") or []),
            "left_out": list(state.get("left_out") or []), "asked": [{key: value for key, value in row.items() if key != "thread"} for row in asked], "quotes": compared["eligible"],
            "over_budget": compared["over_budget"], "waiting": compared["waiting"], "out": compared["out"], "ordered": compared["ordered"], "best": best, "ready": compared["ready"],
            "awards": list(state.get("awards") or []), "as_of": at, "summary": "\n".join(lines), "provider_effect_executed": False,
            **({"stored": dict(stored)} if stored is not None else {}), **extra}


def _ask(console: Any, request: SourcingRequest, candidates: Sequence[Mapping[str, Any]], *, now: str, owner_ref: str | None) -> list[dict[str, Any]]:
    """Register each shortlisted supplier and send it the request for quote, under the mandate; a refusal stays with its supplier."""

    from lightbulb.company_exchange import ExchangeError, exchange_ref_for
    from lightbulb.company_exchange_surface import _platform, _require_card, request_quote

    card = _require_card(console)
    platform = _platform(console)
    asked = []
    for candidate in candidates:
        row = {key: candidate.get(key) for key in ("party_ref", "display_name", "address", "item_ref", "offer_name", "unit", "list_price")}
        ref = exchange_ref_for(card.party_ref, str(candidate["party_ref"]), request.sourcing_ref)
        try:
            if candidate.get("counterparty") != "active":
                platform.register(str(candidate["address"]), note=f"found by sourcing {request.sourcing_ref}"[:300])
            view = request_quote(console, now=now, to_party=str(candidate["party_ref"]), lines=[{"item_ref": candidate["item_ref"], "quantity": str(request.quantity), "unit": candidate["unit"]}],
                                 needed_by=request.needed_by, reply_by=request.reply_by, exchange_ref=ref, owner_ref=owner_ref, currency=request.currency)
        except (ExchangeError, SourcingError, LookupError) as exc:
            asked.append({**row, "exchange_ref": None, "code": getattr(exc, "code", type(exc).__name__), "detail": str(exc)[:300]})
            continue
        document = dict(view.get("document") or {})
        asked.append({**row, "exchange_ref": ref, "delivery": dict(view["delivery"].get(document.get("document_digest"), {})).get("status")})
    return asked


def source_supplies(console: Any, *, now: str, query: str | None = None, quantity: Any = None, unit: str | None = None, kind: str | None = None, currency: str | None = None,
                    country: str | None = None, needed_by: str | None = None, reply_by: str | None = None, max_unit_price: Any = None, budget: Any = None, suppliers: Any = None,
                    for_ref: str | None = None, sourcing_ref: str | None = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Source what the company needs: find listed suppliers of it, shortlist them and ask each for a quote under the mandate.

    A new request needs ``query`` (the words to look for) and ``quantity``. Given an existing ``sourcing_ref``, the
    owner (``owner_ref``) approves a shortlist that waits for them, and a request that found nobody searches again.
    """

    from lightbulb.company_exchange import ExchangeError
    from lightbulb.company_exchange_surface import _platform, _require_card, search_directory
    from lightbulb.company_operator_surface import check_mandate

    at = timestamp(now, field_name="now")
    card = _require_card(console)
    _platform(console)
    approves = _owner_approves(console, owner_ref)
    if sourcing_ref is not None and _load(console, str(sourcing_ref))[0] is not None:
        request, state, record = _load(console, str(sourcing_ref))
        assert request is not None
        stored = str(state.get("status"))
        _require(stored in ("shortlisted", "no_suppliers"), "SOURCING_UNDERWAY", f"{request.sourcing_ref} is {stored}: see company_exchange sourcing, award or drop")
        _require(parsed(at) < parsed(request.reply_by), "SOURCING_EXPIRED", f"its quotes were due by {request.reply_by[:16]}: make a new sourcing request")
        if stored == "shortlisted":
            _require(approves, "OWNER_APPROVAL_REQUIRED", "the shortlist waits for the owner: source again with the owner's owner_ref")
            candidates = list(state.get("shortlist") or [])
            state = {**state, "asked": _ask(console, request, candidates, now=at, owner_ref=owner_ref)}
            stored_now = _save(console, request, state, now=at, status="asking", existing=record)
            return _view(console, request, {**state, "status": "asking"}, now=at, stored=stored_now)
    else:
        _require(query is not None and quantity is not None, "SOURCING_INCOMPLETE", "a new sourcing request says what to buy (query) and how much (quantity)")
        request = build_sourcing_request(company_ref=console.bundle.company_ref, query=str(query), quantity=quantity, currency=currency or card.currency, created_at=at, reply_by=reply_by,
                                         unit=unit, kind=kind, country=country, needed_by=needed_by, max_unit_price=max_unit_price, budget=budget, suppliers=suppliers, for_ref=for_ref,
                                         requested_by=owner_ref, sourcing_ref=sourcing_ref)
        record, state = None, {}
    decision = check_mandate(console, now=at, action_kind="message_supplier", money="0", subject=f"sourcing:{request.sourcing_ref}")
    if decision["autonomy"] == "never":
        raise ExchangeError("RULED_OUT", f"the owner ruled out messaging suppliers ({decision['reason']}); only a new mandate changes that")
    found = search_directory(console, now=at, query=request.query, currency=request.currency, country=request.country, kind=request.kind, limit=20)
    candidates, left_out = shortlist(request, found["results"])
    state = {**state, "shortlist": candidates, "left_out": left_out, "asked": [], "search": {"match": found["match"], "count": found["count"], "unverified": found.get("unverified", 0), "at": at}}
    if not candidates:
        status = "no_suppliers"
    elif decision["autonomy"] == "act" or approves:
        state["asked"] = _ask(console, request, candidates, now=at, owner_ref=owner_ref if approves else None)
        status = "asking" if any(row.get("exchange_ref") for row in state["asked"]) else "no_suppliers"
    else:
        status = "shortlisted"
    stored_now = _save(console, request, state, now=at, status=status, existing=record)
    return _view(console, request, {**state, "status": status}, now=at, stored=stored_now, mandate={"action_kind": "message_supplier", "autonomy": decision["autonomy"], "reason": decision["reason"]})


def sourcing_requests(console: Any) -> list[tuple[SourcingRequest, dict[str, Any], Mapping[str, Any]]]:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    rows = []
    for record in console.store.list_all(engine=EXCHANGE_ENGINE):
        if not str(record.get("entity_ref", "")).startswith(SOURCING_PREFIX):
            continue
        state = dict(record["state"])
        rows.append((verify_sourcing_request(state["sourcing"]), state, record))
    return sorted(rows, key=lambda row: row[0].created_at, reverse=True)


def sourcing_document(console: Any, *, now: str, sourcing_ref: str | None = None) -> dict[str, Any]:
    """One sourcing request with its quotes compared, or every one, open first."""

    at = timestamp(now, field_name="now")
    if sourcing_ref is not None:
        request, state, record = _load(console, str(sourcing_ref))
        _require(request is not None, "SOURCING_NOT_FOUND", f"no sourcing request {sourcing_ref}")
        assert request is not None
        return _view(console, request, state, now=at)
    views = [_view(console, request, state, now=at) for request, state, _record in sourcing_requests(console)]
    views.sort(key=lambda view: (view["status"] not in OPEN_STATUSES, view["request"]["created_at"]), reverse=False)
    lines = [f"**Sourcing**: {len(views)} request(s), {sum(1 for view in views if view['status'] in OPEN_STATUSES)} open"]
    lines.extend(f"- {view['sourcing_ref']}: {view['status'].replace('_', ' ')}: '{view['request']['query']}' x {view['request']['quantity']}"
                 + (f"; best {view['best']['display_name']} at {view['best']['total']} {view['best']['currency']}" if view.get("best") else "") for view in views[:20])
    return {"schema": SOURCING_LIST_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "requests": views, "count": len(views), "summary": "\n".join(lines), "provider_effect_executed": False}


def award_sourcing(console: Any, *, now: str, sourcing_ref: str, exchange_ref: str | None = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Order from the best quote (or, the owner's call, the one named) as a purchase order under the mandate's place_order.

    The agent awards alone only the best quote within the budget once the comparison is ready; a quote over the budget,
    another than the best, or an award before every answer is in needs the owner's ``owner_ref``.
    """

    from lightbulb.company_exchange_surface import order_from_quote

    at = timestamp(now, field_name="now")
    request, state, record = _load(console, str(sourcing_ref))
    _require(request is not None, "SOURCING_NOT_FOUND", f"no sourcing request {sourcing_ref}")
    assert request is not None and record is not None
    approves = _owner_approves(console, owner_ref)
    compared = compare_quotes(request, _asked_rows(console, state), now=at)
    status = sourcing_status(compared, stored=str(state.get("status")))
    _require(status not in ("dropped", "no_suppliers", "shortlisted"), "NOTHING_TO_AWARD", f"{request.sourcing_ref} is {status}: nothing was asked, so nothing can be ordered")
    _require(status not in ("ordered", "order_waiting"), "ALREADY_AWARDED", f"{request.sourcing_ref} already has its order ({status.replace('_', ' ')})")
    choices = {row["exchange_ref"]: row for row in [*compared["eligible"], *compared["over_budget"]]}
    if exchange_ref is not None:
        _require(str(exchange_ref) in choices, "NOT_A_QUOTE_IN_THIS_SOURCING", f"{exchange_ref} is not a valid quote of {request.sourcing_ref}")
        chosen = choices[str(exchange_ref)]
        _require(approves or (compared["best"] is not None and chosen["exchange_ref"] == compared["best"]["exchange_ref"]), "OWNER_APPROVAL_REQUIRED",
                 "choosing another quote than the best is the owner's call: award with owner_ref")
    elif compared["best"] is not None:
        chosen = compared["best"]
    else:
        _require(bool(compared["over_budget"]), "NO_QUOTES", "no quote is in that can be ordered")
        _require(approves, "OVER_BUDGET", f"every quote in is over the budget or the ceiling: the owner decides (award with owner_ref); the lowest is {compared['over_budget'][0]['total']} {compared['over_budget'][0]['currency']}")
        chosen = compared["over_budget"][0]
    _require(compared["ready"] or approves, "QUOTES_STILL_COMING", f"waiting for {len(compared['waiting'])} quote(s) until {request.reply_by[:16]}; the owner may award now with owner_ref")
    try:
        order = order_from_quote(console, now=at, exchange_ref=str(chosen["exchange_ref"]), owner_ref=owner_ref if approves else None)
    except ValueError as exc:
        code = str(getattr(exc, "code", ""))
        if code in SUPPLIER_REFUSALS:
            # the supplier cannot take the order (it closed, is winding down, blocked this company or withdrew its card): the next best is tried instead
            refused = [*list(state.get("refused") or []), {"exchange_ref": chosen["exchange_ref"], "party_ref": chosen["party_ref"], "code": code, "at": at}]
            _save(console, request, {**state, "refused": refused}, now=at, status=str(state.get("status")), existing=record)
        raise
    document = dict(order.get("document") or {})
    delivery = dict(order["delivery"].get(document.get("document_digest"), {})).get("status")
    awards = [*list(state.get("awards") or []), {"exchange_ref": chosen["exchange_ref"], "party_ref": chosen["party_ref"], "total": chosen["total"], "at": at, "by": owner_ref or "agent", "delivery": delivery}]
    state = {**state, "awards": awards}
    stored_now = _save(console, request, state, now=at, status="awarded", existing=record)
    return _view(console, request, state, now=at, stored=stored_now, order=order, chosen=chosen)


def drop_sourcing(console: Any, *, now: str, sourcing_ref: str, reason: str) -> dict[str, Any]:
    """Stop a sourcing request: nothing more is asked or ordered for it, and the quotes already in are left to lapse."""

    at = timestamp(now, field_name="now")
    request, state, record = _load(console, str(sourcing_ref))
    _require(request is not None, "SOURCING_NOT_FOUND", f"no sourcing request {sourcing_ref}")
    assert request is not None
    text = " ".join(str(reason or "").split())[:300]
    _require(bool(text), "REASON_REQUIRED", "say why the request is dropped")
    compared = compare_quotes(request, _asked_rows(console, state), now=at)
    _require(sourcing_status(compared, stored=str(state.get("status"))) != "ordered", "ALREADY_ORDERED", "the order went out: withdraw it in the exchange instead")
    state = {**state, "dropped": {"at": at, "reason": text}}
    stored_now = _save(console, request, state, now=at, status="dropped", existing=record)
    return _view(console, request, {**state, "status": "dropped"}, now=at, stored=stored_now)


# --------------------------------------------------------------------------- #
# The autopilot
# --------------------------------------------------------------------------- #


def sourced_exchange_refs(console: Any) -> set[str]:
    """Every exchange a sourcing request asked for: its quote is ordered by the sourcing decision, never on its own."""

    return {str(row["exchange_ref"]) for _request, state, _record in sourcing_requests(console) for row in state.get("asked") or [] if row.get("exchange_ref")}


def sourcing_turns(console: Any, *, now: str) -> list[dict[str, Any]]:
    """What the autopilot does about each open sourcing request: award one that is ready, and tell the owner what waits for them."""

    at = timestamp(now, field_name="now")
    turns = []
    for request, state, _record in sourcing_requests(console):
        view = _view(console, request, state, now=at)
        status = view["status"]
        subject = f"sourcing: {request.query[:80]}"
        if status in ("ready", "declined"):
            turns.append({"sourcing_ref": request.sourcing_ref, "do": "award", "subject": subject, "value": view["best"]["total"] if view["best"] else "0"})
        elif status in ("shortlisted", "over_budget", "no_quotes", "order_waiting"):
            detail = view["summary"].splitlines()[-1].lstrip("- ")
            turns.append({"sourcing_ref": request.sourcing_ref, "do": "ask", "subject": subject, "detail": detail, "value": "0"})
    return turns


__all__ = [
    "MAX_SUPPLIERS",
    "OPEN_STATUSES",
    "SOURCING_LIST_SCHEMA",
    "SOURCING_SCHEMA",
    "SOURCING_VIEW_SCHEMA",
    "SUPPLIER_REFUSALS",
    "SourcingError",
    "SourcingRequest",
    "award_sourcing",
    "build_sourcing_request",
    "compare_quotes",
    "drop_sourcing",
    "offer_score",
    "pick_offer",
    "reliability",
    "shortlist",
    "source_supplies",
    "sourced_exchange_refs",
    "sourcing_document",
    "sourcing_requests",
    "sourcing_status",
    "sourcing_turns",
    "verify_sourcing_request",
    "words",
]
