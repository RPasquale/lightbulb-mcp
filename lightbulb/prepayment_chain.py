"""The prepayment chain: one replay-fenced lifecycle per customer deposit, from the request to the last draw-down or the refund.

Services firms, trades, and anyone selling made-to-order take money before
the work.  Nothing held it: the deposit asked for, the cash that actually
arrived, which invoices it was drawn against and how much is still owed
back, and the deposits sitting unapplied long enough to be someone's
problem.  ``PREPAYMENT_LIFECYCLE`` does:

    requested -> held -> (draw_down)* -> exhausted        (terminal)
    held -> refunded | forfeited                          (terminal)
    requested -> cancelled                                (terminal, with a reason)

* ``deposit_request_receipt`` names the customer, the amount, and the
  purpose; ``deposit_receipt`` is a bank read for exactly that amount.
* ``draw_down_receipt`` binds a replayed revenue-chain or subscription-chain
  state with an issued invoice for the same customer; the amount drawn never
  exceeds what is held or what the invoice bills, and an invoice draws once.
* ``refund_receipt`` is a bank read for exactly the remaining balance;
  ``forfeit`` keeps it under a stated clause.

``invoice_credit`` tells the collections chain how much of an invoice the
deposit already covered; ``deposit_liability`` is what treasury carries as
unearned revenue; ``refund_expectation`` and ``signals.deposit_unapplied``
name the deposits held past the plan's window.  Nothing here moves money,
reads a provider, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)

PREPAYMENT_KIND = "prepayment_chain"
PREPAYMENT_GOLDEN_LOOP = "revenue.customer_deposit_to_drawn_down@0.1.0"
PREPAYMENT_PLAN_SCHEMA = "lightbulb.prepayment_plan.v1"
INVOICE_CREDIT_SCHEMA = "lightbulb.prepayment_invoice_credit.v1"
EXPECTED_OUTFLOW_SCHEMA = "lightbulb.prepayment_expected_outflow.v1"
MAX_PREPAYMENT_TRANSITIONS = 120
BANK_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "airwallex.list_transactions", "stripe.list_balance_transactions", "host.bank_balances"})
INVOICED_STATUSES: frozenset[str] = frozenset({"invoice_issued", "payment_applied", "cash_settled", "receivable_cleared", "invoiced", "paid", "active", "dunning", "past_due"})

PREPAYMENT_STATUSES: tuple[str, ...] = ("requested", "held", "exhausted", "refunded", "forfeited", "cancelled")
TERMINAL_PREPAYMENT_STATUSES: frozenset[str] = frozenset({"exhausted", "refunded", "forfeited", "cancelled"})
PREPAYMENT_EVENTS: tuple[str, ...] = ("request", "receive", "draw_down", "refund", "forfeit", "cancel")
_PREPAYMENT_TABLE: dict[tuple[str, str], str] = {
    ("new", "request"): "requested",
    ("requested", "receive"): "held",
    ("held", "draw_down"): "held",
    ("held", "refund"): "refunded",
    ("held", "forfeit"): "forfeited",
    ("requested", "cancel"): "cancelled",
}


class PrepaymentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PrepaymentError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def customer_of(source_state: Mapping[str, Any] | Any) -> str | None:
    """The customer identity a revenue-chain or subscription-chain state carries: customer, account, or prospect reference."""

    raw = detached(source_state)
    ledger = dict(raw.get("ledger") or {}) if isinstance(raw, Mapping) else {}
    for key in ("customer_ref", "account_ref", "prospect_ref"):
        value = ledger.get(key)
        if value:
            return str(value)
    return None


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PrepaymentPlan(StrictModel):
    """What the chain enforces: the smallest deposit worth holding and how long one may sit unapplied before it is someone's problem."""

    schema_id: str = Field(default=PREPAYMENT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    minimum_deposit: Decimal = Field(default=Decimal("0"), validate_default=True)
    max_hold_days: int = Field(default=180, ge=1, le=1095)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("minimum_deposit", mode="before")
    @classmethod
    def _minimum(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="minimum_deposit")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PrepaymentPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(PrepaymentPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_prepayment_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PrepaymentPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(PrepaymentPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class DrawDown(StrictModel):
    invoice_ref: OpaqueRef
    case_ref: OpaqueRef
    source_chain: OpaqueRef
    amount: Decimal
    drawn_at: str
    invoice_digest: Sha256Digest

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class PrepaymentReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    customer_ref: OpaqueRef | None = None
    amount: Decimal | None = None
    purpose: BoundedText | None = None
    requested_at: str | None = None
    agreement_ref: OpaqueRef | None = None
    terms_sha256: Sha256Digest | None = None
    bank_provenance: dict[str, Any] | None = None
    bank_digest: Sha256Digest | None = None
    observed_amount: Decimal | None = None
    observed_at: str | None = None
    invoice_source: dict[str, Any] | None = None
    invoice_plan: dict[str, Any] | None = None
    draw_amount: Decimal | None = None
    clause_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", "observed_amount", "draw_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("requested_at", "observed_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class PrepaymentLedger(StrictModel):
    customer_ref: str | None = None
    purpose: str | None = None
    agreement_ref: str | None = None
    terms_sha256: str | None = None
    requested_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    requested_at: str | None = None
    received_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    received_at: str | None = None
    receipt_digest: str | None = None
    hold_until: str | None = None
    draw_downs: tuple[DrawDown, ...] = Field(default_factory=tuple, max_length=100)
    drawn_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    remaining: Decimal = Field(default=Decimal("0"), validate_default=True)
    refunded_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    refunded_at: str | None = None
    refund_digest: str | None = None
    forfeited_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    forfeit_reason: str | None = None
    cancel_reason: str | None = None
    outcome: Literal["open", "exhausted", "refunded", "forfeited", "cancelled"] = "open"

    @field_validator("draw_downs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("requested_amount", "received_amount", "drawn_total", "remaining", "refunded_amount", "forfeited_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class PrepaymentEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    money_moved: Literal[False] = False
    invoice_written: Literal[False] = False
    provider_read: Literal[False] = False


def _bind_invoice(plan: PrepaymentPlan, r: PrepaymentReceipt) -> tuple[Any, str]:
    raw = dict(r.invoice_source or {})
    schema = str(raw.get("schema", ""))
    if schema.startswith("lightbulb.revenue_chain"):
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE as spec

        chain = "revenue_chain"
    elif schema.startswith("lightbulb.subscription_chain"):
        from lightbulb.subscription_chain import SUBSCRIPTION_CHAIN_LIFECYCLE as spec

        chain = "subscription_chain"
    else:
        require(False, "INVOICE_SOURCE_UNSUPPORTED", f"a deposit draws down against a revenue-chain or subscription-chain invoice, not {schema or 'an untyped record'}")
        raise AssertionError
    try:
        source_plan, state = spec.bind(r.invoice_plan, r.invoice_source)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, "INVOICE_NOT_PROVEN", f"the invoice must replay against its exact plan: {exc}"[:300])
        raise AssertionError from exc
    require(getattr(source_plan, "company_ref", plan.company_ref) == plan.company_ref and state.scope.currency == plan.currency, "INVOICE_SCOPE_MISMATCH", "the invoice belongs to another company or currency")
    return state, chain


def _apply_prepayment(plan: PrepaymentPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "request":
        require(r.customer_ref is not None and r.amount is not None and r.purpose is not None and r.requested_at is not None, "REQUEST_MISSING", "a deposit request names the customer, the amount, the purpose, and when it was asked for")
        assert r.amount is not None
        require(r.amount >= plan.minimum_deposit and r.amount > 0, "DEPOSIT_BELOW_MINIMUM", f"a deposit of {r.amount} is below the plan's minimum {plan.minimum_deposit}")
        require(parsed(str(r.requested_at)) <= parsed(at), "REQUEST_FROM_FUTURE", "the request cannot come from the future")
        data.update({"customer_ref": r.customer_ref, "purpose": r.purpose, "agreement_ref": r.agreement_ref, "terms_sha256": r.terms_sha256, "requested_amount": str(_money(r.amount)), "requested_at": r.requested_at})
    elif event == "receive":
        require(r.bank_provenance is not None and r.bank_digest is not None and r.observed_amount is not None and r.observed_at is not None, "DEPOSIT_NOT_PROVEN", "a deposit is received as a bank read")
        require(str(dict(r.bank_provenance or {}).get("output_digest")) == r.bank_digest, "DEPOSIT_NOT_PROVEN", "the provenance does not seal this bank read")
        assert r.observed_amount is not None
        require(_money(r.observed_amount) == Decimal(str(data["requested_amount"])), "DEPOSIT_AMOUNT_MISMATCH", f"{data['requested_amount']} was requested; the bank shows {r.observed_amount}")
        require(parsed(str(data["requested_at"])) <= parsed(str(r.observed_at)) <= parsed(at), "DEPOSIT_TIME_INVALID", "the deposit follows the request and precedes the recording")
        data.update({"received_amount": str(_money(r.observed_amount)), "received_at": r.observed_at, "receipt_digest": r.bank_digest, "remaining": str(_money(r.observed_amount)), "hold_until": iso(parsed(str(r.observed_at)) + timedelta(days=plan.max_hold_days))})
    elif event == "draw_down":
        require(r.invoice_source is not None and r.invoice_plan is not None, "INVOICE_NOT_PROVEN", "a draw-down binds the replayed chain state that issued the invoice")
        invoice, chain = _bind_invoice(plan, r)
        require(invoice.status in INVOICED_STATUSES, "INVOICE_NOT_ISSUED", f"the {chain} case is {invoice.status}; a deposit draws against an issued invoice")
        customer = customer_of(invoice.to_dict())
        require(customer == str(data["customer_ref"]), "CUSTOMER_MISMATCH", f"the invoice belongs to {customer}, not {data['customer_ref']}")
        invoice_ref = str(invoice.ledger.invoice_ref)
        require(invoice_ref not in (None, "None", ""), "INVOICE_REF_MISSING", "the case carries no invoice reference")
        require(all(invoice.scope.entity_ref != item["case_ref"] for item in data.get("draw_downs", ())), "INVOICE_ALREADY_DRAWN", f"{invoice_ref} ({invoice.scope.entity_ref}) already drew on this deposit")
        require(parsed(invoice.transition_history[-1].command.occurred_at) <= parsed(at), "INVOICE_FROM_FUTURE", "the invoice cannot come from the future")
        remaining = Decimal(str(data["remaining"]))
        invoice_total = _money(invoice.ledger.invoice_total)
        amount = _money(r.draw_amount) if r.draw_amount is not None else min(remaining, invoice_total)
        require(0 < amount <= remaining, "DRAW_EXCEEDS_DEPOSIT", f"{amount} requested; {remaining} held")
        require(amount <= invoice_total, "DRAW_EXCEEDS_INVOICE", f"{amount} requested against an invoice of {invoice_total}")
        record = DrawDown(invoice_ref=invoice_ref, case_ref=invoice.scope.entity_ref, source_chain=chain, amount=amount, drawn_at=at, invoice_digest=invoice.state_digest).to_dict()
        rows = [*[dict(item) for item in data.get("draw_downs", ())], record]
        left = _money(remaining - amount)
        data.update({"draw_downs": rows, "drawn_total": str(_money(sum(Decimal(str(item["amount"])) for item in rows))), "remaining": str(left)})
        if left == 0:
            data["outcome"] = "exhausted"
            return "exhausted", data
    elif event == "refund":
        require(r.bank_provenance is not None and r.bank_digest is not None and r.observed_amount is not None and r.observed_at is not None, "REFUND_NOT_PROVEN", "a refund is a bank read")
        require(str(dict(r.bank_provenance or {}).get("output_digest")) == r.bank_digest, "REFUND_NOT_PROVEN", "the provenance does not seal this bank read")
        assert r.observed_amount is not None
        remaining = Decimal(str(data["remaining"]))
        require(_money(r.observed_amount) == remaining, "REFUND_AMOUNT_MISMATCH", f"{remaining} is held; the bank shows {r.observed_amount} going back")
        require(parsed(str(data["received_at"])) <= parsed(str(r.observed_at)) <= parsed(at), "REFUND_TIME_INVALID", "the refund follows the deposit and precedes the recording")
        data.update({"refunded_amount": str(remaining), "refunded_at": r.observed_at, "refund_digest": r.bank_digest, "remaining": "0", "outcome": "refunded"})
    elif event == "forfeit":
        require(r.clause_sha256 is not None, "CLAUSE_MISSING", "a forfeiture names the digest of the clause it rests on")
        remaining = Decimal(str(data["remaining"]))
        data.update({"forfeited_amount": str(remaining), "forfeit_reason": str(command.reason)[:300], "remaining": "0", "outcome": "forfeited"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    return next_status, data


PREPAYMENT_LIFECYCLE = LifecycleSpec(entity="customer_deposit", schema_prefix=PREPAYMENT_KIND, statuses=PREPAYMENT_STATUSES, terminal=TERMINAL_PREPAYMENT_STATUSES, events=PREPAYMENT_EVENTS, table=_PREPAYMENT_TABLE, opening_event="request", reason_events=("forfeit", "cancel"), apply=_apply_prepayment, ledger_model=PrepaymentLedger, receipt_model=PrepaymentReceipt, effect_boundary_model=PrepaymentEffectBoundary, plan_model=PrepaymentPlan, max_transitions=MAX_PREPAYMENT_TRANSITIONS)
PrepaymentState = PREPAYMENT_LIFECYCLE.State


def open_customer_deposit(plan: PrepaymentPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return PREPAYMENT_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_customer_deposit(plan: PrepaymentPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PREPAYMENT_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def deposit_request_receipt(*, customer_ref: str, amount: Any, purpose: str, requested_at: str, agreement_ref: str | None = None, terms_sha256: str | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"customer_ref": customer_ref, "amount": str(_money(decimal_value(amount, field_name="amount"))), "purpose": purpose, "requested_at": timestamp(requested_at, field_name="requested_at"), "evidence_refs": [f"deposit_request:{customer_ref}"]}
    if agreement_ref is not None:
        receipt["agreement_ref"] = agreement_ref
    if terms_sha256 is not None:
        receipt["terms_sha256"] = terms_sha256
    return receipt


def _bank_read(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, code: str) -> dict[str, Any]:
    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in BANK_TOOLS, code, f"expected a read from {sorted(BANK_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), code, f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), code, "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, code.replace("NOT_PROVEN", "INCOMPLETE"), "a bank read carries the amount and the time")
    return {"bank_provenance": prov, "bank_digest": str(prov["output_digest"]), "observed_amount": str(_money(abs(decimal_value(amount, field_name="amount", allow_negative=True)))), "observed_at": timestamp(str(stamp), field_name="observed_at"), "evidence_refs": [f"bank:{prov['observation_ref']}"]}


def deposit_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a bank read: the customer's deposit arriving."""

    return _bank_read(provenance, payload, code="DEPOSIT_NOT_PROVEN")


def refund_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a bank read: the unapplied balance going back to the customer."""

    return _bank_read(provenance, payload, code="REFUND_NOT_PROVEN")


def draw_down_receipt(invoice_state: Any, *, source_plan: Any, amount: Any = None) -> dict[str, Any]:
    """The replayed chain state whose issued invoice the deposit pays; the amount defaults to the lesser of the balance held and the invoice."""

    raw = dict(detached(invoice_state))
    plan = detached(source_plan)
    receipt: dict[str, Any] = {"invoice_source": raw, "invoice_plan": dict(plan), "evidence_refs": [f"invoice:{dict(raw.get('ledger') or {}).get('invoice_ref')}:{str(raw.get('state_digest', ''))[:16]}"]}
    if amount is not None:
        receipt["draw_amount"] = str(_money(decimal_value(amount, field_name="amount")))
    return receipt


def forfeiture_receipt(*, clause_sha256: str) -> dict[str, Any]:
    return {"clause_sha256": clause_sha256, "evidence_refs": [f"clause:{clause_sha256[:16]}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def invoice_credit(state: Any, *, source_plan: Any, invoice_ref: str) -> dict[str, Any]:
    """What the collections chain nets off an invoice: the deposit already drawn against it, bound to the replayed deposit."""

    plan, bound = PREPAYMENT_LIFECYCLE.bind(source_plan, state)
    record = next((item for item in bound.ledger.draw_downs if invoice_ref in (item.invoice_ref, item.case_ref)), None)
    _require(record is not None, "INVOICE_NOT_DRAWN", f"{invoice_ref} drew nothing from this deposit")
    assert record is not None
    return {"schema": INVOICE_CREDIT_SCHEMA, "invoice_ref": record.invoice_ref, "case_ref": record.case_ref, "customer_ref": bound.ledger.customer_ref, "amount": str(record.amount), "currency": plan.currency, "drawn_at": record.drawn_at, "deposit_ref": bound.scope.entity_ref, "source_digest": bound.state_digest}


def deposit_liability(states: Sequence[Any]) -> dict[str, Any]:
    """Deposits held and not yet drawn: the unearned revenue treasury carries."""

    held = [state for state in states if state.status == "held"]
    return {"deposits_held": str(_money(sum((state.ledger.remaining for state in held), Decimal("0")))), "deposits_count": len(held), "by_customer": {ref: str(_money(sum((state.ledger.remaining for state in held if str(state.ledger.customer_ref) == ref), Decimal("0")))) for ref in sorted({str(state.ledger.customer_ref) for state in held})}, "drawn_total": str(_money(sum((state.ledger.drawn_total for state in states), Decimal("0")))), "refunded_total": str(_money(sum((state.ledger.refunded_amount for state in states), Decimal("0"))))}


def refund_expectation(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """A treasury ``payable`` for a deposit held past the plan's window with a balance left: the refund the company may owe."""

    plan, bound = PREPAYMENT_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status == "held" and ledger.remaining > 0 and ledger.hold_until is not None, "NO_OUTFLOW_EXPECTED", f"a deposit that is {bound.status} owes nothing back")
    return {"schema": EXPECTED_OUTFLOW_SCHEMA, "kind": "payable", "flow_ref": f"deposit_refund:{bound.scope.entity_ref}", "amount": str(ledger.remaining), "currency": plan.currency, "expected_at": ledger.hold_until, "basis": f"deposit from {ledger.customer_ref} unapplied at the end of its {plan.max_hold_days}-day window", "source_digest": bound.state_digest}


def stale_deposits(states: Sequence[Any], *, source_plan: Any, now: str) -> list[dict[str, Any]]:
    stamp = parsed(timestamp(now, field_name="now"))
    rows = []
    for state in states:
        _plan, bound = PREPAYMENT_LIFECYCLE.bind(source_plan, state)
        ledger = bound.ledger
        if bound.status == "held" and ledger.hold_until is not None and parsed(str(ledger.hold_until)) < stamp and ledger.remaining > 0:
            rows.append({"deposit_ref": bound.scope.entity_ref, "customer_ref": ledger.customer_ref, "remaining": str(ledger.remaining), "hold_until": ledger.hold_until, "days_over": (stamp - parsed(str(ledger.hold_until))).days})
    rows.sort(key=lambda row: (str(row["hold_until"]), str(row["deposit_ref"])))
    return rows


def deposit_unapplied_signal(states: Sequence[Any], *, source_plan: Any, now: str) -> dict[str, Any] | None:
    """``signals.deposit_unapplied`` naming the deposits held past the window with money still on them."""

    plan = PrepaymentPlan.model_validate(detached(source_plan)) if not isinstance(source_plan, PrepaymentPlan) else source_plan
    rows = stale_deposits(states, source_plan=source_plan, now=now)
    if not rows:
        return None
    return {"name": "signals.deposit_unapplied", "producer": PREPAYMENT_KIND, "emitted_at": timestamp(now, field_name="now"), "payload": {"deposit_refs": [row["deposit_ref"] for row in rows], "customer_refs": sorted({str(row["customer_ref"]) for row in rows}), "unapplied_total": str(_money(sum(Decimal(row["remaining"]) for row in rows))), "currency": plan.currency, "oldest_hold_until": rows[0]["hold_until"], "source_digest": stable_digest(rows)}}


def prepayment_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in PREPAYMENT_STATUSES}
    return {"deposits": len(states), "by_status": counts, **deposit_liability(states), "awaiting_receipt": [state.scope.entity_ref for state in states if state.status == "requested"]}


PREPAYMENT_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PREPAYMENT_KIND,
    "golden_loop": PREPAYMENT_GOLDEN_LOOP,
    "stages": ["request", "receive", "draw_down", "refund"],
    "statuses": list(PREPAYMENT_STATUSES),
    "events": list(PREPAYMENT_EVENTS),
    "hops": {"request": "the customer, the amount at or above the minimum, the purpose", "receive": "a bank read for exactly the requested amount", "draw_down": "a replayed revenue-chain or subscription-chain state with an issued invoice for the same customer; never above the balance held or the invoice; once per invoice", "refund": "a bank read for exactly the balance held"},
    "tools": {"bank": sorted(BANK_TOOLS)},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a deposit is held only when the bank shows exactly what was requested",
        "a deposit is drawn only against a replayed issued invoice for the same customer, once per invoice",
        "what is not drawn is refunded for exactly the balance or forfeited under a named clause",
        "nothing here moves money or writes an invoice",
    ],
}

__all__ = ["BANK_TOOLS", "EXPECTED_OUTFLOW_SCHEMA", "INVOICED_STATUSES", "INVOICE_CREDIT_SCHEMA", "PREPAYMENT_EVENTS", "PREPAYMENT_GOLDEN_LOOP", "PREPAYMENT_KIND", "PREPAYMENT_LIFECYCLE", "PREPAYMENT_MANIFEST", "PREPAYMENT_STATUSES", "TERMINAL_PREPAYMENT_STATUSES", "DrawDown", "PrepaymentEffectBoundary", "PrepaymentError", "PrepaymentLedger", "PrepaymentPlan", "PrepaymentReceipt", "PrepaymentState", "advance_customer_deposit", "compile_prepayment_chain", "customer_of", "deposit_liability", "deposit_receipt", "deposit_request_receipt", "deposit_unapplied_signal", "draw_down_receipt", "forfeiture_receipt", "invoice_credit", "open_customer_deposit", "prepayment_summary", "refund_expectation", "refund_receipt", "stale_deposits"]
