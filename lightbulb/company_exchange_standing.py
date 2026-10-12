"""Standing orders: what the company buys again and again, asked for and ordered on its schedule within the owner's ceilings.

The owner sets a standing order from a trade the company has made: the same supplier and the same lines, every
``every_days`` days until ``until``, and on each line a ceiling on the unit price (the price the company paid, plus
``tolerance_percent``). Setting it is the owner's approval of every order within it, so each cycle:

* when it falls due, the agent asks the supplier for a quote on the lines, giving it ``reply_days`` to answer;
* when the quote comes back within every ceiling, the agent orders it. Both go under the owner's standing approval,
  and through the mandate: what the mandate rules out stays ruled out, and once another owner gives the mandate the
  standing order stops ordering until that owner sets it again;
* a quote over a ceiling is countered once at the ceilings (the supplier may hold the price it had), and the revised
  quote is ordered when it comes back within them;
* a quote still over a ceiling, a supplier that does not answer in time, a declined order or a refusal is the owner's
  to decide; the next cycle falls due as usual.

A quote a standing order asked for is ordered by the standing order's decision, never on its own, and nothing is
asked for or ordered after ``until`` or once the owner stops it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

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

STANDING_SCHEMA = "lightbulb.exchange_standing_order.v1"
STANDING_VIEW_SCHEMA = "lightbulb.exchange_standing_orders.v1"
STANDING_PREFIX = "standing:"
MIN_EVERY_DAYS, MAX_EVERY_DAYS = 7, 92
MAX_TOLERANCE_PERCENT = Decimal("50")
# what a cycle came to: asked (waiting for the quote), ordered, or one of the owner's to decide
OWNER_OUTCOMES: frozenset[str] = frozenset({"over_ceiling", "unanswered", "declined", "refused"})
_CENT = Decimal("0.01")


class StandingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise StandingError(code, message)


def _stamp_after(at: str, days: int) -> str:
    return (parsed(at) + timedelta(days=days)).isoformat().replace("+00:00", "Z")


class StandingLine(StrictModel):
    item_ref: OpaqueRef
    quantity: Decimal
    unit: ShortText = "each"
    ceiling: Decimal

    @field_validator("quantity", "ceiling", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> "StandingLine":
        if self.quantity <= 0 or self.ceiling <= 0:
            raise ValueError("a standing line asks for more than nothing, at a price above nothing")
        return self


class StandingOrder(StrictModel):
    """What the owner approved buying again and again, sealed: the supplier, the lines and their ceilings, the schedule."""

    schema_id: str = Field(default=STANDING_SCHEMA, alias="schema")
    standing_ref: OpaqueRef
    company_ref: OpaqueRef
    supplier: OpaqueRef
    currency: CurrencyCode
    lines: tuple[StandingLine, ...] = Field(min_length=1, max_length=100)
    every_days: int = Field(ge=MIN_EVERY_DAYS, le=MAX_EVERY_DAYS)
    first_due_at: str
    until: str | None = None
    reply_days: int = Field(default=2, ge=1, le=14)
    from_exchange_ref: OpaqueRef
    approved_by: OpaqueRef
    created_at: str
    standing_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("first_due_at", "until", "created_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "StandingOrder":
        if self.reply_days >= self.every_days:
            raise ValueError("the supplier answers each cycle before the next one falls due")
        if parsed(self.first_due_at) < parsed(self.created_at):
            raise ValueError("the first cycle falls due after the standing order is set")
        if self.until is not None and parsed(self.until) <= parsed(self.first_due_at):
            raise ValueError("a standing order runs at least one cycle before it ends")
        if len({line.item_ref for line in self.lines}) != len(self.lines):
            raise ValueError("one standing line per item")
        if not skip_digests(info) and self.standing_digest != sealed_digest(StandingOrder, self, "standing_digest"):
            raise ValueError("standing_digest must commit the exact standing order")
        return self

    def due_at(self, cycle: int) -> str:
        """When cycle ``cycle`` (counted from zero) falls due."""

        return _stamp_after(self.first_due_at, self.every_days * cycle)

    def ceiling(self, item_ref: str) -> Decimal | None:
        return next((line.ceiling for line in self.lines if line.item_ref == item_ref), None)

    def render(self) -> str:
        lines = ", ".join(f"{line.quantity} {line.unit} of {line.item_ref} at most {line.ceiling}" for line in self.lines[:5])
        return f"every {self.every_days} days from {self.first_due_at[:10]}" + (f" until {self.until[:10]}" if self.until else "") + f", from {self.supplier} in {self.currency}: {lines}"


def verify_standing_order(value: Any) -> StandingOrder:
    return value if isinstance(value, StandingOrder) else StandingOrder.model_validate(dict(detached(value)))


def within_ceilings(order: StandingOrder, quote: Any) -> list[str]:
    """What in a quote goes over the standing order's ceilings: every line priced above its ceiling, or a line it does not name."""

    over = []
    for line in quote.lines:
        ceiling = order.ceiling(line.item_ref)
        if ceiling is None:
            over.append(f"{line.item_ref} is not in the standing order")
        elif line.unit_price is None or line.unit_price > ceiling:
            over.append(f"{line.item_ref} at {line.unit_price} is above its {ceiling} ceiling")
    if quote.currency != order.currency:
        over.append(f"quoted in {quote.currency}, not {order.currency}")
    return over


# --------------------------------------------------------------------------- #
# The console
# --------------------------------------------------------------------------- #


def _entity(standing_ref: str) -> str:
    return f"{STANDING_PREFIX}{standing_ref}"


def _load(console: Any, standing_ref: str) -> tuple[StandingOrder | None, dict[str, Any], Mapping[str, Any] | None]:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    record = console.store.get(EXCHANGE_ENGINE, _entity(standing_ref))
    if record is None:
        return None, {}, None
    state = dict(record["state"])
    return verify_standing_order(state["standing"]), state, record


def _save(console: Any, order: StandingOrder, state: Mapping[str, Any], *, now: str, status: str, existing: Mapping[str, Any] | None) -> dict[str, Any]:
    from lightbulb.company_exchange_surface import _put

    extra = {"cycles": list(state.get("cycles") or []), **({"stopped": state["stopped"]} if state.get("stopped") else {})}
    digest = stable_digest({"standing": order.standing_digest, "status": status, **extra})
    return _put(console, _entity(order.standing_ref), key="standing", document=order.to_dict(), digest=digest, now=now, status=status, existing=existing, extra=extra)


def standing_orders(console: Any) -> list[tuple[StandingOrder, dict[str, Any], Mapping[str, Any]]]:
    from lightbulb.company_exchange_surface import EXCHANGE_ENGINE

    rows = []
    for record in console.store.list_all(engine=EXCHANGE_ENGINE):
        if str(record.get("entity_ref", "")).startswith(STANDING_PREFIX):
            state = dict(record["state"])
            rows.append((verify_standing_order(state["standing"]), state, record))
    return sorted(rows, key=lambda row: row[0].created_at)


def standing_exchange_refs(console: Any) -> set[str]:
    """Every exchange a standing order asked for: its quote is ordered by the standing order's decision, never on its own."""

    return {str(cycle["exchange_ref"]) for _order, state, _record in standing_orders(console) for cycle in state.get("cycles") or [] if cycle.get("exchange_ref")}


def set_standing_order(console: Any, *, now: str, exchange_ref: str, every_days: Any, owner_ref: str | None = None, tolerance_percent: Any = 5, until: str | None = None,
                       reply_days: Any = 2, first_due_at: str | None = None) -> dict[str, Any]:
    """Buy what the exchange bought again and again: the owner approves the supplier, the lines, the schedule and each line's ceiling.

    The ceiling is the unit price the company paid in ``exchange_ref`` plus ``tolerance_percent`` (at most 50). The
    first cycle falls due ``every_days`` days from now unless ``first_due_at`` says otherwise.
    """

    from lightbulb.company_exchange_sourcing import _owner_approves
    from lightbulb.company_exchange_surface import _load_thread, _require_card

    at = timestamp(now, field_name="now")
    _require(owner_ref is not None, "OWNER_APPROVAL_REQUIRED", "a standing order is the owner's approval of every order within it: set it with the owner's owner_ref")
    _owner_approves(console, owner_ref)
    card = _require_card(console)
    thread = _load_thread(console, str(exchange_ref))[0]
    _require(thread is not None, "EXCHANGE_NOT_FOUND", f"no exchange {exchange_ref}")
    assert thread is not None
    _require(thread.buyer == card.party_ref, "NOT_A_PURCHASE", "a standing order repeats something this company bought")
    order_document = thread.document("purchase_order")
    _require(order_document is not None and thread.status != "declined", "NOT_ORDERED", "a standing order repeats an order the supplier took: this exchange has none")
    assert order_document is not None
    tolerance = decimal_value(tolerance_percent, field_name="tolerance_percent")
    _require(Decimal("0") <= tolerance <= MAX_TOLERANCE_PERCENT, "TOLERANCE_INVALID", f"the tolerance is 0 to {MAX_TOLERANCE_PERCENT} percent above the price paid")
    lines = [{"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": line.unit,
              "ceiling": str((Decimal(str(line.unit_price)) * (Decimal("100") + tolerance) / Decimal("100")).quantize(_CENT, rounding=ROUND_HALF_UP))} for line in order_document.lines]
    every = int(every_days)
    existing = standing_orders(console)
    _require(not any(order.from_exchange_ref == thread.exchange_ref and _status(order, state, now=at) == "active" for order, state, _record in existing),
             "STANDING_EXISTS", "a standing order for this trade already runs: stop it first (company_exchange stop_standing)")
    ref = "std:" + stable_digest({"company_ref": console.bundle.company_ref, "exchange_ref": thread.exchange_ref, "at": at, "n": len(existing)})[:20]
    try:
        order = seal(StandingOrder, {"standing_ref": ref, "company_ref": console.bundle.company_ref, "supplier": thread.seller, "currency": thread.currency, "lines": lines, "every_days": every,
                                     "first_due_at": first_due_at or _stamp_after(at, every), "until": until, "reply_days": int(reply_days), "from_exchange_ref": thread.exchange_ref,
                                     "approved_by": str(owner_ref), "created_at": at}, "standing_digest")
    except ValidationError as exc:
        raise StandingError("STANDING_INVALID", "; ".join(str(error["msg"]).removeprefix("Value error, ") for error in exc.errors())[:300]) from exc
    stored = _save(console, order, {"cycles": []}, now=at, status="active", existing=None)
    return _view(console, order, {"cycles": [], "status": "active"}, now=at, stored=stored)


def stop_standing_order(console: Any, *, now: str, standing_ref: str, reason: str) -> dict[str, Any]:
    """Stop a standing order: nothing more is asked for or ordered under it."""

    at = timestamp(now, field_name="now")
    order, state, record = _load(console, str(standing_ref))
    _require(order is not None, "STANDING_NOT_FOUND", f"no standing order {standing_ref}")
    assert order is not None
    text = " ".join(str(reason or "").split())[:300]
    _require(bool(text), "REASON_REQUIRED", "say why the standing order stops")
    state = {**state, "stopped": {"at": at, "reason": text}}
    stored = _save(console, order, state, now=at, status="stopped", existing=record)
    return _view(console, order, {**state, "status": "stopped"}, now=at, stored=stored)


def _status(order: StandingOrder, state: Mapping[str, Any], *, now: str) -> str:
    if state.get("stopped"):
        return "stopped"
    cycles = list(state.get("cycles") or [])
    if order.until is not None and parsed(now) >= parsed(order.until) and not any(cycle["outcome"] == "asked" for cycle in cycles):
        return "ended"
    return "active"


def _next_due(order: StandingOrder, state: Mapping[str, Any]) -> str | None:
    due = order.due_at(len(state.get("cycles") or []))
    return None if order.until is not None and parsed(due) >= parsed(order.until) else due


def _view(console: Any, order: StandingOrder, state: Mapping[str, Any], *, now: str, stored: Mapping[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    at = timestamp(now, field_name="now")
    status = _status(order, state, now=at)
    cycles = list(state.get("cycles") or [])
    due = None if status != "active" else _next_due(order, state)
    lines = [f"**Standing order {order.standing_ref}** ({status}): {order.render()}; set by {order.approved_by}"]
    lines.extend(f"- cycle {cycle['n'] + 1} ({cycle['due_at'][:10]}): {cycle['outcome'].replace('_', ' ')}" + (f": {cycle['detail']}" if cycle.get("detail") else "") for cycle in cycles[-5:])
    if due:
        lines.append(f"- next: {due[:10]}, a request for quote to {order.supplier}")
    if status == "stopped":
        lines.append(f"- stopped: {dict(state.get('stopped') or {}).get('reason', '')}")
    return {"schema": STANDING_VIEW_SCHEMA, "standing_ref": order.standing_ref, "status": status, "standing": order.to_dict(), "cycles": cycles, "next_due_at": due, "as_of": at,
            "summary": "\n".join(lines), "provider_effect_executed": False, **({"stored": dict(stored)} if stored is not None else {}), **extra}


def standing_orders_document(console: Any, *, now: str, standing_ref: str | None = None) -> dict[str, Any]:
    """One standing order with its cycles, or every one."""

    at = timestamp(now, field_name="now")
    if standing_ref is not None:
        order, state, _record = _load(console, str(standing_ref))
        _require(order is not None, "STANDING_NOT_FOUND", f"no standing order {standing_ref}")
        assert order is not None
        return _view(console, order, state, now=at)
    views = [_view(console, order, state, now=at) for order, state, _record in standing_orders(console)]
    lines = [f"**Standing orders**: {len(views)}, {sum(1 for view in views if view['status'] == 'active')} active"]
    lines.extend(f"- {view['standing_ref']}: {view['status']}; {view['standing']['supplier']}" + (f", next {view['next_due_at'][:10]}" if view["next_due_at"] else "") for view in views[:20])
    return {"schema": STANDING_VIEW_SCHEMA, "company_ref": console.bundle.company_ref, "as_of": at, "standing_orders": views, "count": len(views), "summary": "\n".join(lines), "provider_effect_executed": False}


def advance_standing_order(console: Any, *, now: str, standing_ref: str) -> dict[str, Any] | None:
    """Do what the standing order owes now, at most one step: settle the open cycle (order its quote, or hand it to the owner), or ask for the next.

    Answers None when nothing is due; otherwise ``{"step", "outcome", "detail", "cycle", "money"}``, where ``step`` is
    ``ask`` or ``order`` for what went to the supplier and ``owner`` for what the owner decides.
    """

    from lightbulb.company_exchange import ExchangeError, exchange_ref_for
    from lightbulb.company_exchange_surface import _load_thread, _require_card, order_from_quote, request_quote

    at = timestamp(now, field_name="now")
    order, state, record = _load(console, str(standing_ref))
    _require(order is not None, "STANDING_NOT_FOUND", f"no standing order {standing_ref}")
    assert order is not None and record is not None
    if _status(order, state, now=at) != "active":
        return None
    cycles = [dict(cycle) for cycle in state.get("cycles") or []]
    open_cycle = cycles[-1] if cycles and cycles[-1]["outcome"] == "asked" else None

    def finish(outcome: str, step: str, detail: str, money: Any = "0") -> dict[str, Any]:
        assert open_cycle is not None
        open_cycle.update({"outcome": outcome, "at": at, "detail": detail[:300]})
        _save(console, order, {**state, "cycles": cycles}, now=at, status="active", existing=record)
        return {"step": step, "outcome": outcome, "detail": detail[:300], "cycle": open_cycle["n"] + 1, "money": str(money)}

    if open_cycle is not None:
        thread, delivery, _ = _load_thread(console, str(open_cycle["exchange_ref"]))
        quote = None if thread is None else thread.document("quote")
        if thread is not None and thread.status == "declined":
            return finish("declined", "owner", f"{order.supplier} declined the order: {thread.last().reason or ''}".strip())
        if quote is not None and thread is not None and thread.document("purchase_order") is not None:
            return finish("ordered", "record", f"ordered at {quote.total} {quote.currency}", quote.total)
        if quote is None:
            if parsed(at) > parsed(str(open_cycle["reply_by"])):
                return finish("unanswered", "owner", f"{order.supplier} did not quote by {str(open_cycle['reply_by'])[:16]}")
            return None
        if thread is not None and thread.last().kind == "counter":
            # waiting for the supplier's revised quote, as long as it had to answer the request
            answer_by = _stamp_after(thread.last().issued_at, order.reply_days)
            if parsed(at) > parsed(answer_by):
                return finish("unanswered", "owner", f"{order.supplier} did not answer the counter-offer by {answer_by[:16]}")
            return None
        over = within_ceilings(order, quote)
        if over and thread is not None and thread.counters() == 0 and quote.currency == order.currency:
            from lightbulb.company_exchange_negotiation import counter_quote

            ceilings = {line.item_ref: str(order.ceiling(line.item_ref)) for line in quote.lines if order.ceiling(line.item_ref) is not None and line.unit_price is not None and line.unit_price > order.ceiling(line.item_ref)}
            if ceilings:
                try:
                    counter_quote(console, now=at, exchange_ref=thread.exchange_ref, prices=ceilings, reason="our standing order's price for these lines", owner_ref=order.approved_by)
                except (ValueError, LookupError) as exc:
                    return finish("refused", "owner", f"the counter-offer could not go: {exc}")
                return {"step": "counter", "outcome": "asked", "detail": f"countered {order.supplier} at the standing order's ceilings: " + "; ".join(over), "cycle": open_cycle["n"] + 1, "money": "0"}
        if over:
            return finish("over_ceiling", "owner", "; ".join(over))
        try:
            view = order_from_quote(console, now=at, exchange_ref=thread.exchange_ref, owner_ref=order.approved_by)
        except (ValueError, LookupError) as exc:
            return finish("refused", "owner", f"the order could not go: {exc}")
        document = dict(view.get("document") or {})
        sent = dict(view["delivery"].get(document.get("document_digest"), {})).get("status")
        return finish("ordered", "order", f"ordered at {quote.total} {quote.currency}" + ("" if sent == "sent" else f" ({str(sent).replace('_', ' ')})"), quote.total)

    due = _next_due(order, state)
    if due is None or parsed(at) < parsed(due):
        return None
    card = _require_card(console)
    n = len(cycles)
    ref = exchange_ref_for(card.party_ref, order.supplier, f"{order.standing_ref}:{n}")
    reply_by = _stamp_after(at, order.reply_days)
    cycle = {"n": n, "due_at": due, "exchange_ref": ref, "reply_by": reply_by, "outcome": "asked", "at": at}
    try:
        request_quote(console, now=at, to_party=order.supplier, lines=[{"item_ref": line.item_ref, "quantity": str(line.quantity), "unit": line.unit} for line in order.lines],
                      reply_by=reply_by, exchange_ref=ref, owner_ref=order.approved_by, currency=order.currency)
    except (ValueError, LookupError) as exc:
        cycle.update({"exchange_ref": None, "outcome": "refused", "detail": f"the request could not go: {exc}"[:300]})
        _save(console, order, {**state, "cycles": [*cycles, cycle]}, now=at, status="active", existing=record)
        return {"step": "owner", "outcome": "refused", "detail": cycle["detail"], "cycle": n + 1, "money": "0"}
    _save(console, order, {**state, "cycles": [*cycles, cycle]}, now=at, status="active", existing=record)
    return {"step": "ask", "outcome": "asked", "detail": f"asked {order.supplier} for a quote on {len(order.lines)} line(s), by {reply_by[:16]}", "cycle": n + 1, "money": "0"}


def standing_turns(console: Any) -> list[str]:
    """The standing orders still running: the autopilot advances each on every tick."""

    return [order.standing_ref for order, state, _record in standing_orders(console) if not state.get("stopped")]


__all__ = [
    "OWNER_OUTCOMES",
    "STANDING_SCHEMA",
    "STANDING_VIEW_SCHEMA",
    "StandingError",
    "StandingLine",
    "StandingOrder",
    "advance_standing_order",
    "set_standing_order",
    "standing_exchange_refs",
    "standing_orders",
    "standing_orders_document",
    "standing_turns",
    "stop_standing_order",
    "verify_standing_order",
    "within_ceilings",
]
