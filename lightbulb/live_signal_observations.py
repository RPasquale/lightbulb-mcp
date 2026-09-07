"""SaaS and service delivery on live signals: billing and usage into account rows and churn risk, tickets and threads into cases.

* ``billing_from_stripe_invoices`` reads the raw Stripe invoice list and
  derives, per customer, the monthly recurring revenue actually billed and
  paid in the window plus what is past due; ``merge_usage_with_billing``
  joins those rows with PostHog usage rows so ``saas_ops.observe_usage``
  sees real MRR next to real activity, and ``churn_risk_signals`` turns the
  snapshot's churn risks into ``signals.churn_risk`` for the operating
  system.  Past-due invoices raise ``signals.churn_risk`` on their own with
  the amount at risk and the days overdue.
* ``case_from_gmail_thread`` turns an inbound Gmail thread into the case
  ``intake`` receipt (customer ref hashed from the sender, never the address
  itself), ``verification_from_freshservice`` turns a customer confirmation
  observation with ``disposition == CONFIRMED`` into the ``verify`` receipt,
  and ``close_from_freshservice_status`` turns a closed ticket status into the
  ``close`` receipt.

Every function requires provenance for the read it converts and refuses a
payload from a different tool; nothing here replies, refunds, or closes on
the platform.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from pydantic import Field, ValidationInfo, field_validator

from lightbulb.company_engine_core import MONEY_QUANTUM, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, stable_digest, timestamp
from lightbulb.company_execution_bridge import BridgeError, ObservationProvenance
from lightbulb.company_operating_system import CompanySignal
from lightbulb.saas_operating_loop import UsageSnapshot

STRIPE_INVOICES_TOOL = "stripe.list_invoices"
GMAIL_THREAD_TOOL = "gmail.get_thread"
FRESHSERVICE_CONFIRMATION_TOOL = "freshservice.observe_customer_confirmation"
FRESHSERVICE_STATUS_TOOL = "freshservice.get_ticket_status"
_HUNDRED = Decimal("100")
_DAY = 86400


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BridgeError(code, message)


def _expect_tool(provenance: ObservationProvenance, *tools: str) -> None:
    _require(provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {tools}; provenance names {provenance.source_tool}")


def _stamp(epoch: Any) -> str:
    if isinstance(epoch, str):
        return timestamp(epoch, field_name="timestamp")
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Billing
# --------------------------------------------------------------------------- #


class AccountBilling(StrictModel):
    account_ref: OpaqueRef
    plan_ref: ShortText
    mrr: Decimal
    paid_in_window: Decimal
    past_due: Decimal
    days_past_due: int = Field(default=0, ge=0)
    last_paid_at: str | None = None
    invoices: int = Field(ge=0)

    @field_validator("mrr", "paid_in_window", "past_due", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(str(value), field_name=str(info.field_name))


class BillingObservation(StrictModel):
    source_tool: ShortText
    provenance_digest: Sha256Digest
    observed_at: str
    currency: ShortText
    accounts: tuple[AccountBilling, ...] = Field(default_factory=tuple, max_length=5000)

    @field_validator("accounts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


def _months(period_start: Any, period_end: Any) -> Decimal:
    try:
        seconds = int(period_end) - int(period_start)
    except (TypeError, ValueError):
        return Decimal("1")
    if seconds <= 0:
        return Decimal("1")
    months = Decimal(seconds) / Decimal(30 * _DAY)
    return months if months >= Decimal("0.5") else Decimal("1")


def billing_from_stripe_invoices(provenance: ObservationProvenance, invoices: Sequence[Mapping[str, Any]] | Mapping[str, Any], *, currency: str, now: str) -> BillingObservation:
    """Per-customer MRR, paid amount, and past-due amount from the raw Stripe invoice list."""

    _expect_tool(provenance, STRIPE_INVOICES_TOOL)
    rows = invoices.get("data") if isinstance(invoices, Mapping) else invoices
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "PAYLOAD_INCONSISTENT", "Stripe invoices arrive as a list (or {data: [...]})")
    stamp = timestamp(now, field_name="now")
    now_at = parsed(stamp)
    accounts: dict[str, dict[str, Any]] = {}
    for raw in rows:  # type: ignore[union-attr]
        item = dict(detached(raw))
        _require(str(item.get("currency", "")).upper() == currency.upper(), "PAYLOAD_CURRENCY_MISMATCH", f"invoice currency differs from {currency}")
        customer = item.get("customer")
        customer_ref = str(customer.get("id") if isinstance(customer, Mapping) else customer or "")
        _require(bool(customer_ref), "PAYLOAD_FIELD_INVALID", "each invoice names its customer")
        status = str(item.get("status", "")).lower()
        entry = accounts.setdefault(customer_ref, {"account_ref": customer_ref, "plan_ref": "", "mrr": Decimal("0"), "paid_in_window": Decimal("0"), "past_due": Decimal("0"), "days_past_due": 0, "last_paid_at": None, "invoices": 0})
        entry["invoices"] += 1
        lines = ((item.get("lines") or {}).get("data") or []) if isinstance(item.get("lines"), Mapping) else []
        plan_ref = ""
        for line in lines:
            price = (line or {}).get("price") or {}
            plan_ref = str(price.get("nickname") or price.get("lookup_key") or price.get("id") or plan_ref)
            period = (line or {}).get("period") or {}
            if str(item.get("status", "")).lower() in ("paid", "open") and price.get("recurring"):
                entry["mrr"] += (Decimal(int((line or {}).get("amount", 0))) / _HUNDRED) / _months(period.get("start"), period.get("end"))
        if plan_ref:
            entry["plan_ref"] = plan_ref
        if status == "paid":
            entry["paid_in_window"] += Decimal(int(item.get("amount_paid", 0))) / _HUNDRED
            paid_at = ((item.get("status_transitions") or {}).get("paid_at")) or item.get("created")
            if paid_at is not None:
                entry["last_paid_at"] = _stamp(paid_at)
        elif status in ("open", "uncollectible"):
            due = item.get("due_date")
            if due is not None and parsed(_stamp(due)) < now_at:
                entry["past_due"] += Decimal(int(item.get("amount_due", item.get("amount_remaining", 0)))) / _HUNDRED
                entry["days_past_due"] = max(entry["days_past_due"], int((now_at - parsed(_stamp(due))).total_seconds() // _DAY))
    rows_out = [{**entry, "plan_ref": entry["plan_ref"] or "unknown", "mrr": str(entry["mrr"].quantize(MONEY_QUANTUM)), "paid_in_window": str(entry["paid_in_window"].quantize(MONEY_QUANTUM)), "past_due": str(entry["past_due"].quantize(MONEY_QUANTUM))} for entry in accounts.values()]
    return BillingObservation.model_validate({"source_tool": provenance.source_tool, "provenance_digest": provenance.provenance_digest, "observed_at": provenance.observed_through, "currency": currency.upper(), "accounts": sorted(rows_out, key=lambda row: row["account_ref"])})


def merge_usage_with_billing(usage_rows: Sequence[Mapping[str, Any]], billing: BillingObservation, *, default_signed_up_at: str | None = None) -> list[dict[str, Any]]:
    """PostHog usage rows plus Stripe billing into ``AccountUsage`` inputs; an account on only one side is kept with what is known."""

    by_ref: dict[str, dict[str, Any]] = {}
    for raw in usage_rows:
        item = dict(detached(raw))
        ref = str(item.get("account_ref") or "")
        _require(bool(ref), "PAYLOAD_FIELD_INVALID", "each usage row names an account_ref")
        by_ref[ref] = {**item, "account_ref": ref}
    for account in billing.accounts:
        entry = by_ref.setdefault(account.account_ref, {"account_ref": account.account_ref, "events": []})
        entry["mrr"] = str(account.mrr)
        if account.plan_ref != "unknown":
            entry.setdefault("plan_ref", account.plan_ref)
        if account.last_paid_at and not entry.get("last_active_at"):
            entry.setdefault("last_billed_at", account.last_paid_at)
    out: list[dict[str, Any]] = []
    for ref, entry in sorted(by_ref.items()):
        row = {key: value for key, value in entry.items() if key != "last_billed_at"}
        row.setdefault("plan_ref", "unknown")
        if not row.get("signed_up_at"):
            _require(default_signed_up_at is not None, "SIGNED_UP_AT_MISSING", f"{ref} has no signed_up_at from usage; supply default_signed_up_at or the usage row")
            row["signed_up_at"] = default_signed_up_at
        out.append(row)
    return out


def churn_risk_signals(snapshot: UsageSnapshot | Mapping[str, Any], *, emitted_at: str) -> list[CompanySignal]:
    parsed_snapshot = snapshot if isinstance(snapshot, UsageSnapshot) else UsageSnapshot.model_validate(dict(detached(snapshot)))
    stamp = timestamp(emitted_at, field_name="emitted_at")
    return [CompanySignal(name="signals.churn_risk", producer="saas_operating_engine", emitted_at=stamp, payload={"account_ref": risk.account_ref, "mrr_at_risk": str(risk.mrr_at_risk), "inactive_days": int(risk.inactive_days), "plan_ref": risk.plan_ref, "snapshot_digest": parsed_snapshot.snapshot_digest}) for risk in parsed_snapshot.churn_risks]


def past_due_signals(billing: BillingObservation, *, emitted_at: str) -> list[CompanySignal]:
    stamp = timestamp(emitted_at, field_name="emitted_at")
    return [CompanySignal(name="signals.churn_risk", producer="saas_operating_engine", emitted_at=stamp, payload={"account_ref": account.account_ref, "mrr_at_risk": str(account.past_due if account.mrr == 0 else account.mrr), "inactive_days": account.days_past_due, "past_due": str(account.past_due), "billing_digest": billing.provenance_digest}) for account in billing.accounts if account.past_due > 0]


# --------------------------------------------------------------------------- #
# Service cases from threads and tickets
# --------------------------------------------------------------------------- #


def case_from_gmail_thread(provenance: ObservationProvenance, thread: Mapping[str, Any], *, our_addresses: Sequence[str]) -> dict[str, Any]:
    """The ``intake`` receipt for an inbound Gmail thread; the customer ref is a digest of the sender, never the address."""

    _expect_tool(provenance, GMAIL_THREAD_TOOL)
    raw = dict(detached(thread))
    _require(raw.get("schema") in (None, "lightbulb.gmail_thread.v1"), "PAYLOAD_SCHEMA_MISMATCH", "expected a Gmail thread payload")
    messages = raw.get("messages")
    _require(isinstance(messages, Sequence) and len(messages) >= 1, "PAYLOAD_INCONSISTENT", "a thread carries at least one message")
    ours = {item.strip().lower() for item in our_addresses if item and item.strip()}
    _require(bool(ours), "PAYLOAD_FIELD_INVALID", "our_addresses must name at least one address")
    inbound = None
    for message in messages:  # type: ignore[union-attr]
        headers = dict((message or {}).get("headers") or {})
        sender = str(headers.get("from") or headers.get("From") or "").strip().lower()
        if sender and not any(address in sender for address in ours):
            inbound = (sender, str(headers.get("subject") or headers.get("Subject") or "").strip())
            break
    _require(inbound is not None, "NO_INBOUND_MESSAGE", "the thread has no message from a customer")
    assert inbound is not None
    sender, subject = inbound
    thread_id = str(raw.get("threadId") or raw.get("thread_id") or provenance.observation_ref)
    return {"case_ref": f"gmail:{thread_id}", "customer_ref": f"customer:{stable_digest({'sender': sender})[:16]}", "channel": "email", "subject": (subject or "(no subject)")[:200], "evidence_refs": [f"thread:{thread_id}", f"provenance:{provenance.provenance_digest[:24]}"]}


def verification_from_freshservice(provenance: ObservationProvenance, observation: Mapping[str, Any], *, customer_ref: str) -> dict[str, Any]:
    """The ``verify`` receipt from a customer confirmation observation; only a unique CONFIRMED match counts."""

    _expect_tool(provenance, FRESHSERVICE_CONFIRMATION_TOOL)
    raw = dict(detached(observation))
    _require(raw.get("schema") == "lightbulb.freshservice_customer_confirmation_observation.v1", "PAYLOAD_SCHEMA_MISMATCH", "expected a Freshservice customer confirmation observation")
    disposition = str(raw.get("disposition", "")).upper()
    _require(disposition == "CONFIRMED", "CONFIRMATION_NOT_RECEIVED", f"the observation disposition is {disposition or 'missing'}; only CONFIRMED verifies the resolution")
    _require(bool(raw.get("uniqueMatch", False)), "CONFIRMATION_NOT_UNIQUE", "the confirmation must match exactly one reply")
    code = str(raw.get("confirmationCodeSha256") or "")
    _require(bool(code), "PAYLOAD_FIELD_INVALID", "the observation carries the confirmation code digest")
    return {"verifier_ref": customer_ref, "verification_ref": f"freshservice-confirmation:{code[:24]}", "evidence_refs": [f"confirmation:{provenance.observation_ref}", f"provenance:{provenance.provenance_digest[:24]}"]}


def close_from_freshservice_status(provenance: ObservationProvenance, observation: Mapping[str, Any]) -> dict[str, Any]:
    """The ``close`` receipt from a ticket status observation that reports the ticket closed."""

    _expect_tool(provenance, FRESHSERVICE_STATUS_TOOL)
    raw = dict(detached(observation))
    _require(raw.get("schema") == "lightbulb.freshservice_ticket_status_observation.v1", "PAYLOAD_SCHEMA_MISMATCH", "expected a Freshservice ticket status observation")
    _require(bool(raw.get("closed", False)), "TICKET_NOT_CLOSED", f"the ticket status is {raw.get('status') or 'unknown'}; not closed")
    return {"evidence_refs": [f"ticket_status:{provenance.observation_ref}", f"provenance:{provenance.provenance_digest[:24]}"]}


LIVE_SIGNALS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "live_signal_observations",
    "golden_loop": "saas.launched_product_to_compounding_revenue@0.1.0",
    "stages": ["read_billing", "merge_usage", "observe_usage", "raise_churn_risk", "intake_from_thread", "verify_from_confirmation", "close_from_status"],
    "tools": {"billing": STRIPE_INVOICES_TOOL, "intake": GMAIL_THREAD_TOOL, "verification": FRESHSERVICE_CONFIRMATION_TOOL, "closure": FRESHSERVICE_STATUS_TOOL},
    "required_connectors": ["stripe", "posthog", "gmail", "freshservice"],
    "hard_rules": [
        "MRR comes from recurring invoice lines actually billed; past-due amounts raise churn risk with the days overdue",
        "the customer ref on an inbound thread is a digest of the sender, never the address",
        "a resolution is verified only by a unique CONFIRMED customer confirmation observation",
        "a case closes from a ticket status observation that reports closed, never from elapsed time",
    ],
}

__all__ = [
    "FRESHSERVICE_CONFIRMATION_TOOL",
    "FRESHSERVICE_STATUS_TOOL",
    "GMAIL_THREAD_TOOL",
    "LIVE_SIGNALS_MANIFEST",
    "STRIPE_INVOICES_TOOL",
    "AccountBilling",
    "BillingObservation",
    "billing_from_stripe_invoices",
    "case_from_gmail_thread",
    "churn_risk_signals",
    "close_from_freshservice_status",
    "merge_usage_with_billing",
    "past_due_signals",
    "verification_from_freshservice",
]
