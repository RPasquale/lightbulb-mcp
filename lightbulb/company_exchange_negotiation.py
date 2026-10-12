"""Negotiation: a buyer's counter-offer to a quote, and the seller's revised quote within the discount its owner allows.

A buyer that finds a quote too dear may answer it with a counter-offer instead of an order, at most twice in an
exchange (``company_exchange.MAX_COUNTERS``): the same lines at lower unit prices, with its reason, under the
mandate's ``message_supplier``. The seller answers with a revised quote:

* **within its owner's discount policy, alone.** The owner allows a largest discount off the list price (and, for a
  customer that has paid, optionally a larger one). The revised price of each line is the counter's price when that
  is within the allowed discount, and otherwise the lowest the policy allows: the agent meets the buyer as far as it
  may, never below its floor and never above what it quoted before;
* **by the owner** when no policy is set, or with prices of the owner's own choosing (``prices`` and ``owner_ref``).

The revised quote is a quote like any other: it goes under ``send_quote``, holds for the card's quote days, and the
buyer orders it, counters it again, or lets it lapse.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from pydantic import Field, ValidationError, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)

DISCOUNT_POLICY_SCHEMA = "lightbulb.exchange_discount_policy.v1"
DISCOUNT_ENTITY = "discount:policy"
_CENT = Decimal("0.01")
_HUNDRED = Decimal("100")


class NegotiationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise NegotiationError(code, message)


class DiscountPolicy(StrictModel):
    """How far below its list price the owner lets the agent go when a buyer counters, sealed."""

    schema_id: str = Field(default=DISCOUNT_POLICY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    max_discount_percent: Decimal
    trusted_max_discount_percent: Decimal | None = None
    set_by: OpaqueRef
    set_at: str
    policy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_discount_percent", "trusted_max_discount_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("set_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="set_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "DiscountPolicy":
        if not Decimal("0") <= self.max_discount_percent <= Decimal("50"):
            raise ValueError("the largest discount is 0 to 50 percent off the list price")
        if self.trusted_max_discount_percent is not None and not self.max_discount_percent <= self.trusted_max_discount_percent <= Decimal("50"):
            raise ValueError("a customer that has paid gets at least the discount a new one gets, and at most 50 percent")
        if not skip_digests(info) and self.policy_digest != sealed_digest(DiscountPolicy, self, "policy_digest"):
            raise ValueError("policy_digest must commit the exact policy")
        return self

    def allowed(self, *, trusted: bool) -> Decimal:
        return self.trusted_max_discount_percent if trusted and self.trusted_max_discount_percent is not None else self.max_discount_percent

    def render(self) -> str:
        return f"up to {self.max_discount_percent}% off the list price when a buyer counters" + (f", {self.trusted_max_discount_percent}% for a customer that has paid" if self.trusted_max_discount_percent is not None else "") + f"; set by {self.set_by} on {self.set_at[:10]}"


def verify_discount_policy(value: Any) -> DiscountPolicy:
    return value if isinstance(value, DiscountPolicy) else DiscountPolicy.model_validate(dict(detached(value)))


def current_discount_policy(console: Any) -> DiscountPolicy | None:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    record = console.store.get(EXCHANGE_ENGINE, DISCOUNT_ENTITY)
    return None if record is None else verify_discount_policy(dict(record["state"])["policy"])


def set_discount_policy(console: Any, *, now: str, max_discount_percent: Any, owner_ref: str | None = None, trusted_max_discount_percent: Any = None) -> dict[str, Any]:
    """The owner's largest discount off the list price for a buyer that counters (and, optionally, a larger one for a customer that has paid)."""

    from lightbulb.company_exchange_sourcing import _owner_approves
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE, _put

    at = timestamp(now, field_name="now")
    _require(owner_ref is not None, "OWNER_APPROVAL_REQUIRED", "the discount the agent may give is the owner's to set: give the owner's owner_ref")
    _owner_approves(console, owner_ref)
    try:
        policy = seal(DiscountPolicy, {"company_ref": console.bundle.company_ref, "max_discount_percent": str(max_discount_percent),
                                       "trusted_max_discount_percent": None if trusted_max_discount_percent in (None, "") else str(trusted_max_discount_percent), "set_by": str(owner_ref), "set_at": at}, "policy_digest")
    except ValidationError as exc:
        raise NegotiationError("DISCOUNT_POLICY_INVALID", "; ".join(str(error["msg"]).removeprefix("Value error, ") for error in exc.errors())[:300]) from exc
    existing = console.store.get(EXCHANGE_ENGINE, DISCOUNT_ENTITY)
    stored = _put(console, DISCOUNT_ENTITY, key="policy", document=policy.to_dict(), digest=policy.policy_digest, now=at, status="in_force", existing=existing)
    return {"policy": policy.to_dict(), "stored": stored, "as_of": at, "summary": f"**Discount policy** ({console.bundle.company_ref}): {policy.render()}", "provider_effect_executed": False}


def counter_quote(console: Any, *, now: str, exchange_ref: str, prices: Mapping[str, Any], reason: str | None = None, owner_ref: str | None = None) -> dict[str, Any]:
    """Answer the quote received with a counter-offer (this company buys): lower unit prices on the lines named, the rest as quoted.

    A message to the supplier under the mandate's ``message_supplier``; at most two in an exchange.
    """

    from lightbulb.company_exchange import MAX_COUNTERS, ExchangeError, issue_document
    from lightbulb.company_exchange_surface import _issue, _our_turn

    at = timestamp(now, field_name="now")
    card, thread, quote = _our_turn(console, exchange_ref, "purchase_order")
    _require(thread.counters() < MAX_COUNTERS, "TOO_MANY_COUNTERS", f"this exchange has had its {MAX_COUNTERS} counter-offers: order the quote or let it lapse")
    if not isinstance(prices, Mapping) or not prices:
        raise ExchangeError("PRICES_REQUIRED", "a counter-offer names the unit price it asks on at least one line: prices {item_ref: unit_price}")
    quoted = {line.item_ref: line for line in quote.lines}
    unknown = sorted(set(map(str, prices)) - set(quoted))
    _require(not unknown, "NOT_IN_THE_QUOTE", f"{', '.join(unknown)} is not in the quote")
    lines = [{"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": line.unit, "unit_price": str(decimal_value(prices.get(line.item_ref, line.unit_price), field_name="unit_price"))} for line in quote.lines]
    document = issue_document("counter", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=quote.from_party, issued_at=at, currency=quote.currency, lines=lines, previous=quote,
                              reason=" ".join(str(reason).split())[:300] if reason else None)
    return _issue(console, now=at, document=document, previous=list(thread.documents), money="0", owner_ref=owner_ref)


def revised_prices(policy: DiscountPolicy, *, card: Any, quote: Any, counter: Any, trusted: bool) -> dict[str, str]:
    """The price the agent answers on each line: the counter's when the policy allows that discount, else the policy's floor, never above what was quoted."""

    allowed = policy.allowed(trusted=trusted)
    quoted = {line.item_ref: Decimal(str(line.unit_price)) for line in quote.lines}
    prices = {}
    for line in counter.lines:
        offer = card.offer(line.item_ref)
        base = Decimal(str(offer.list_price)) if offer is not None else quoted[line.item_ref]
        floor = (base * (_HUNDRED - allowed) / _HUNDRED).quantize(_CENT, rounding=ROUND_HALF_UP)
        prices[line.item_ref] = str(min(quoted[line.item_ref], max(Decimal(str(line.unit_price)), floor)))
    return prices


def answer_counter(console: Any, *, now: str, exchange_ref: str, prices: Mapping[str, Any] | None = None, owner_ref: str | None = None, valid_days: Any = None) -> dict[str, Any]:
    """Answer the buyer's counter-offer with a revised quote (this company sells), under the mandate's send_quote.

    Without ``prices`` the discount policy sets them; with them, the owner's own (``owner_ref``). Either way no line is
    priced above what was quoted before.
    """

    from datetime import timedelta

    from lightbulb.company_exchange import ExchangeError, issue_document
    from lightbulb.company_exchange_credit import customer_credit, current_credit_policy
    from lightbulb.company_exchange_surface import _issue, _our_turn

    at = timestamp(now, field_name="now")
    card, thread, counter = _our_turn(console, exchange_ref, "quote")
    if counter.kind != "counter":
        raise ExchangeError("NO_COUNTER", "the buyer has asked for a first quote, not countered one: company_exchange quote answers it")
    previous = [document for document in thread.documents if document.kind == "quote"][-1]
    quoted = {line.item_ref: Decimal(str(line.unit_price)) for line in previous.lines}
    if prices is not None:
        _require(owner_ref is not None, "OWNER_APPROVAL_REQUIRED", "prices of the owner's own choosing go with the owner's owner_ref")
        chosen = {line.item_ref: str(decimal_value(prices.get(line.item_ref, quoted[line.item_ref]), field_name="unit_price")) for line in counter.lines}
        _require(all(Decimal(chosen[ref]) <= quoted[ref] for ref in chosen), "ABOVE_THE_QUOTE", "a revised quote asks no more on any line than the quote before it")
    else:
        policy = current_discount_policy(console)
        if policy is None:
            raise ExchangeError("NO_DISCOUNT_POLICY", "no discount policy: the owner answers the counter-offer (company_exchange answer_counter with prices and owner_ref), or sets one (company_exchange discount)")
        credit = current_credit_policy(console)
        trusted = credit is not None and customer_credit(console, counter.from_party, policy=credit)["tier"] == "trusted"
        chosen = revised_prices(policy, card=card, quote=previous, counter=counter, trusted=trusted)
    days = int(valid_days) if valid_days is not None else card.quote_valid_days
    lines = [{"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": line.unit, "unit_price": chosen[line.item_ref]} for line in counter.lines]
    document = issue_document("quote", exchange_ref=thread.exchange_ref, from_party=card.party_ref, to_party=counter.from_party, issued_at=at, currency=counter.currency, lines=lines, previous=counter,
                              valid_until=(parsed(at) + timedelta(days=days)).isoformat().replace("+00:00", "Z"), terms_days=previous.terms_days)
    return _issue(console, now=at, document=document, previous=list(thread.documents), money=document.total, owner_ref=owner_ref)


__all__ = [
    "DISCOUNT_POLICY_SCHEMA",
    "DiscountPolicy",
    "NegotiationError",
    "answer_counter",
    "counter_quote",
    "current_discount_policy",
    "revised_prices",
    "set_discount_policy",
    "verify_discount_policy",
]
