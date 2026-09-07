"""The collections chain: what happens to an issued invoice that is not paid on the day the revenue chain expected.

``revenue_chain`` refuses a payment that is not the whole invoice
(``PAYMENT_NOT_FULL``) and refuses one that arrives after
``max_days_invoice_to_payment`` (``PAYMENT_TOO_LATE``).  Both refusals land in
``reconciliation_required``, a terminal status, so a partial payment, a payment
plan, a late payer, a dispute or a write-off had exactly one exit and nothing
chased them: ``cash_receivables`` is an aging snapshot and ``cash_collection``
is a set of observe primitives.  Meanwhile ``company_treasury`` dates a
receivable from the invoice's terms with a thirty-day fallback, so the
thirteen-week forecast assumes everyone pays on time.

This repairs that dead end rather than duplicating it:

    outstanding -> due -> reminded -> promised -> recovered            (terminal)
    due|reminded|promised -> partially_paid -> ... -> recovered        (terminal)
    reminded|promised|partially_paid -> escalated -> written_off|referred
    any non-terminal -> disputed -> reminded | recovered
    any non-terminal -> reconciliation_required                        (terminal)

Every hop consumes the sealed artifact of the thing that produced it:

* ``open_receivable_receipt`` opens the case from a ``revenue_chain`` case in
  ``invoice_issued`` or a ``subscription_chain`` case in ``invoiced`` -- never
  from an invoice a caller typed.
* ``aging_receipt`` reads the balance and due date from a governed
  ``xero.list_invoices`` / ``quickbooks.list_invoices`` page, or from the aged
  receivable report on the host lane (no governed aged-receivable contract
  exists; see ``MISSING_GOVERNED_READS``).
* ``reminder_receipt`` consumes a bound ``ExecutionReceipt`` for the approved
  send: a rung advances on proof a message left, never on the intent to send
  one, and an ``sms``/``voice`` rung additionally carries the
  ``permission_register`` eligibility commitment that covered the moment.
* ``promise_receipt`` consumes the governed ``gmail.get_thread`` /
  ``microsoft.get_conversation`` the customer actually wrote in, plus an
  operator input that names itself as the recorded date and amount.  The SDK
  never infers a promise from silence.
* ``partial_receipt`` and ``recovery_receipt`` consume the same governed
  ``quickbooks.observe_invoice_payment_applied`` observation the revenue chain
  reads, split by ``invoice_balance_zero``.  ``revenue_chain_payment_receipt``
  hands that one observation to ``revenue_chain.apply_payment`` unchanged, so
  one payment on one correlation closes both chains and the cash is counted
  once.
* ``write_off_receipt`` consumes an ``AuthorityMatrix`` ``AuthorizationProof``
  for the ``write_off`` category together with an observed credit note; the
  ledger and the provider cannot disagree about what was forgiven.

What it hands to other engines: ``receivable_flows`` dates a treasury
``ScheduledFlow(kind='receivable')`` by the recorded promise instead of by the
terms; ``provision_rows`` proposes the bad-debt adjustment candidates for the
finance close; ``receivable_exception`` opens exceptions-desk cases for overdue
and disputed invoices; ``collections_summary`` carries DSO for unit economics
and the brief.  Nothing here reads a provider, sends a message, or writes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
import re
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    EngineScope,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    pct,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance
from lightbulb.company_treasury import ScheduledFlow
from lightbulb.governed_connector_contracts import GOVERNED_CONNECTOR_READ_TOOLS
from lightbulb.permission_register import EligibilityCommitment

COLLECTIONS_CHAIN_KIND = "collections_chain"
COLLECTIONS_CHAIN_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
COLLECTIONS_CHAIN_PLAN_SCHEMA = "lightbulb.collections_chain_plan.v1"
CREDIT_NOTE_OBSERVATION_SCHEMA = "lightbulb.collections_credit_note_observation.v1"
INVOICE_PAYMENT_OBSERVATION_SCHEMA = "lightbulb.quickbooks_invoice_payment_observation.v1"
MAX_COLLECTIONS_TRANSITIONS = 24

#: Pages this chain normalizes for the aged balance.  The two report tools are
#: not in ``GOVERNED_CONNECTOR_READ_TOOLS``; they reach the SDK on the host lane
#: as the normalized close source page the finance close already consumes.
AGING_TOOLS: tuple[str, ...] = ("xero.aged_receivable_report", "quickbooks.aged_receivable_report", "xero.list_invoices", "quickbooks.list_invoices")
#: Credit-note reads that match a write-off.  Neither is governed today.
CREDIT_NOTE_TOOLS: tuple[str, ...] = ("xero.list_credit_notes", "quickbooks.list_credit_memos")
#: Governed communication reads a promise or a dispute may come from.
THREAD_TOOLS: tuple[str, ...] = ("gmail.get_thread", "microsoft.get_conversation")
MISSING_GOVERNED_READS: tuple[str, ...] = tuple(tool for tool in (*AGING_TOOLS, *CREDIT_NOTE_TOOLS) if tool not in GOVERNED_CONNECTOR_READ_TOOLS)
#: The approved writes that prove a rung's message actually left, by channel.
SEND_TOOLS: dict[str, str] = {"gmail.send_email": "email", "microsoft.send_email": "email", "xero.create_statement": "letter", "twilio.send_sms_turn": "sms", "twilio.place_call_turn": "voice"}
#: Sealed lifecycle states a receivable may open from: schema -> (chain, status).
INVOICE_SOURCES: dict[str, tuple[str, str]] = {
    "lightbulb.revenue_chain_state.v1": ("revenue_chain", "invoice_issued"),
    "lightbulb.subscription_chain_state.v1": ("subscription_chain", "invoiced"),
    "lightbulb.wip_billing_state.v1": ("wip_billing", "invoiced"),
}
#: Exceptions-desk kinds.  ``receivable_overdue`` and ``disputed_invoice`` are
#: not registered in ``exceptions_desk.RESOLUTION_PATHS`` yet; until they are,
#: both open as a chain reconciliation.
RECEIVABLE_OVERDUE_EXCEPTION_KIND = "chain_reconciliation"
DISPUTED_INVOICE_EXCEPTION_KIND = "chain_reconciliation"

AGING_BUCKETS: tuple[str, ...] = ("0-30", "31-60", "61-90", "90+")
DEFAULT_PROVISION_PERCENT: dict[str, str] = {"0-30": "0", "31-60": "5", "61-90": "20", "90+": "50"}
Channel = Literal["email", "sms", "voice", "letter"]
CONSENTED_CHANNELS: frozenset[str] = frozenset({"sms", "voice"})

COLLECTIONS_STATUSES: tuple[str, ...] = ("outstanding", "due", "reminded", "promised", "partially_paid", "escalated", "disputed", "recovered", "written_off", "referred", "reconciliation_required")
TERMINAL_COLLECTIONS_STATUSES: frozenset[str] = frozenset({"recovered", "written_off", "referred", "reconciliation_required"})
COLLECTIONS_EVENTS: tuple[str, ...] = ("open_receivable", "mark_due", "send_reminder", "record_promise", "break_promise", "apply_partial", "apply_payment", "raise_dispute", "resolve_dispute", "escalate", "write_off", "refer", "require_reconciliation")
_OPEN_STATUSES: tuple[str, ...] = ("outstanding", "due", "reminded", "promised", "partially_paid", "escalated", "disputed")
_COLLECTIONS_TABLE: dict[tuple[str, str], str] = {
    ("new", "open_receivable"): "outstanding",
    ("outstanding", "mark_due"): "due",
    **{(status, "send_reminder"): "reminded" for status in ("due", "reminded", "promised", "partially_paid")},
    ("reminded", "record_promise"): "promised",
    ("promised", "break_promise"): "reminded",
    **{(status, "apply_partial"): "partially_paid" for status in ("due", "reminded", "promised")},
    **{(status, "apply_payment"): "recovered" for status in ("due", "reminded", "promised", "partially_paid", "escalated", "disputed")},
    **{(status, "escalate"): "escalated" for status in ("reminded", "promised", "partially_paid", "disputed")},
    **{(status, "raise_dispute"): "disputed" for status in ("due", "reminded", "promised", "partially_paid", "escalated")},
    ("disputed", "resolve_dispute"): "reminded",
    ("escalated", "write_off"): "written_off",
    ("escalated", "refer"): "referred",
    **{(status, "require_reconciliation"): "reconciliation_required" for status in _OPEN_STATUSES},
}

RECOVERY_BY_CODE: dict[str, str] = {
    "RECEIVABLE_MISSING": "correct_input",
    "INVOICE_TOTAL_INVALID": "correct_input",
    "AGING_MISSING": "correct_input",
    "AGING_INVOICE_MISMATCH": "manual_reconciliation",
    "AGING_BALANCE_EXCEEDS_INVOICE": "manual_reconciliation",
    "NOT_YET_DUE": "correct_input",
    "LADDER_STEP_SKIPPED": "correct_input",
    "REMINDER_TOO_SOON": "correct_input",
    "REMINDER_NOT_SENT": "correct_input",
    "CONSENT_MISSING": "correct_input",
    "PROMISE_UNEVIDENCED": "correct_input",
    "PROMISE_DATE_IN_PAST": "correct_input",
    "PROMISE_BEYOND_HORIZON": "correct_input",
    "PROMISE_NOT_DUE": "correct_input",
    "PROMISE_LIMIT_EXCEEDED": "manual_reconciliation",
    "PARTIAL_MISSING": "correct_input",
    "PARTIAL_EXCEEDS_BALANCE": "correct_input",
    "PAYMENT_CORRELATION_MISMATCH": "manual_reconciliation",
    "RECOVERY_MISSING": "correct_input",
    "RECOVERY_AMOUNT_MISMATCH": "manual_reconciliation",
    "DISPUTE_UNEVIDENCED": "correct_input",
    "DISPUTE_BLOCKS_ESCALATION": "correct_input",
    "ESCALATION_BEFORE_LADDER": "correct_input",
    "ESCALATION_BELOW_THRESHOLD": "correct_input",
    "WRITE_OFF_NOT_AUTHORIZED": "await_approval",
    "WRITE_OFF_WITHOUT_CREDIT_NOTE": "manual_reconciliation",
    "WRITE_OFF_BEFORE_LADDER": "correct_input",
    "REFERRAL_MISSING": "correct_input",
    # receipt-builder refusals: the artifact does not prove what the caller claims
    "INVOICE_SOURCE_UNSUPPORTED": "correct_input",
    "INVOICE_SOURCE_INCOMPLETE": "correct_input",
    "INVOICE_NOT_ISSUED": "correct_input",
    "READ_PROVENANCE_INVALID": "correct_input",
    "AGING_TOOL_MISMATCH": "correct_input",
    "AGING_DIGEST_MISMATCH": "manual_reconciliation",
    "AGING_INVOICE_NOT_FOUND": "correct_input",
    "AGING_INVOICE_AMBIGUOUS": "manual_reconciliation",
    "AGING_ROW_INCOMPLETE": "correct_input",
    "PAYMENT_OBSERVATION_SCHEMA_MISMATCH": "correct_input",
    "PAYMENT_NOT_APPLIED": "correct_input",
    "PAYMENT_READ_NOT_EXHAUSTIVE": "correct_input",
    "INVOICE_BALANCE_OPEN": "correct_input",
    "INVOICE_BALANCE_CLEARED": "correct_input",
    "CREDIT_NOTE_TOOL_MISMATCH": "correct_input",
    "CREDIT_NOTE_DIGEST_MISMATCH": "manual_reconciliation",
    "CREDIT_NOTE_NOT_FOUND": "manual_reconciliation",
    "CREDIT_NOTE_AMBIGUOUS": "manual_reconciliation",
    "CREDIT_NOTE_INCOMPLETE": "correct_input",
}
RECOVERY_BY_CODE.update({code: "correct_input" for code in ("SOURCE_NOT_SEALED", "SOURCE_PLAN_MISSING", "SOURCE_PROJECTION_MISMATCH", "SCOPE_MISMATCH", "SOURCE_FROM_FUTURE", "PAYMENT_OBSERVATION_DIGEST_MISMATCH", "PAYMENT_ALREADY_USED", "PAYMENT_HISTORY_REGRESSED", "REMINDER_ALREADY_USED", "PROMISE_EXCEEDS_BALANCE", "THREAD_INVOICE_MISMATCH", "COLLECTIONS_NOT_RECOVERED", "CASE_DUPLICATED")})
COLLECTIONS_CODES: tuple[str, ...] = tuple(sorted(RECOVERY_BY_CODE))


# --------------------------------------------------------------------------- #
# The sealed plan
# --------------------------------------------------------------------------- #


class LadderStep(StrictModel):
    """One rung of the dunning ladder: when it may run, on which channel, and how long after the previous rung."""

    rung: int = Field(ge=1, le=16)
    days_past_due: int = Field(ge=0, le=365)
    channel: Channel = "email"
    template_ref: OpaqueRef
    requires_approval: bool = False
    min_lead_days: int = Field(default=0, ge=0, le=90)


DEFAULT_LADDER: tuple[LadderStep, ...] = (
    LadderStep(rung=1, days_past_due=3, channel="email", template_ref="collections:rung:1", min_lead_days=0),
    LadderStep(rung=2, days_past_due=14, channel="email", template_ref="collections:rung:2", min_lead_days=7),
    LadderStep(rung=3, days_past_due=30, channel="email", template_ref="collections:rung:3", requires_approval=True, min_lead_days=7),
    LadderStep(rung=4, days_past_due=45, channel="letter", template_ref="collections:rung:4", requires_approval=True, min_lead_days=10),
)


class CollectionsChainPlan(StrictModel):
    """What the chain enforces: the terms, the ladder, how many promises a debtor gets, and what a bucket is provisioned at."""

    schema_id: Literal["lightbulb.collections_chain_plan.v1"] = Field(default=COLLECTIONS_CHAIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    terms_days: int = Field(default=30, ge=0, le=365)
    ladder: tuple[LadderStep, ...] = Field(default=DEFAULT_LADDER, min_length=1, max_length=8)
    min_reminders_before_escalation: int = Field(default=3, ge=0, le=16)
    max_promises: int = Field(default=2, ge=1, le=8)
    max_promise_horizon_days: int = Field(default=60, ge=1, le=365)
    escalation_threshold_amount: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    write_off_requires_approval: bool = True
    bad_debt_provision_percent_by_bucket: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_PROVISION_PERCENT))
    require_consent_for_sms_voice: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("escalation_threshold_amount", mode="before")
    @classmethod
    def _threshold(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="escalation_threshold_amount")

    @field_validator("ladder", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("bad_debt_provision_percent_by_bucket", mode="before")
    @classmethod
    def _buckets(cls, value: Any) -> dict[str, str]:
        out = {str(key): str(item) for key, item in dict(value or {}).items()}
        if set(out) != set(AGING_BUCKETS):
            raise ValueError(f"bad_debt_provision_percent_by_bucket must name exactly {list(AGING_BUCKETS)}")
        for key, percent in out.items():
            parsed_percent = decimal_value(percent, field_name=f"bad_debt_provision_percent_by_bucket.{key}")
            if parsed_percent > 100:
                raise ValueError(f"bad_debt_provision_percent_by_bucket.{key} must be between 0 and 100")
        return out

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CollectionsChainPlan:
        unique([str(item.rung) for item in self.ladder], label="ladder rungs")
        if [item.rung for item in self.ladder] != list(range(1, len(self.ladder) + 1)):
            raise ValueError("ladder rungs must run 1..n without gaps")
        if any(later.days_past_due <= earlier.days_past_due for earlier, later in zip(self.ladder, self.ladder[1:])):
            raise ValueError("each ladder rung must run later past due than the one before it")
        if self.min_reminders_before_escalation > len(self.ladder):
            raise ValueError("min_reminders_before_escalation cannot exceed the ladder length")
        if not skip_digests(info) and self.plan_digest != sealed_digest(CollectionsChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def step(self, rung: int | None) -> LadderStep | None:
        return next((item for item in self.ladder if item.rung == rung), None)

    def provision_percent(self, bucket: str | None) -> Decimal:
        if bucket is None or bucket not in self.bad_debt_provision_percent_by_bucket:
            return Decimal("0")
        return decimal_value(self.bad_debt_provision_percent_by_bucket[bucket], field_name="provision_percent")


def compile_collections_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> CollectionsChainPlan:
    return seal(CollectionsChainPlan, {"company_ref": company_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipt, ledger, effect boundary
# --------------------------------------------------------------------------- #


class CollectionsReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    source_provenance: ObservationProvenance | None = None
    source_payload: dict[str, Any] | None = None
    payment_observation: dict[str, Any] | None = None
    credit_note_source: dict[str, Any] | None = None
    execution_source: dict[str, Any] | None = None
    execution_request: dict[str, Any] | None = None
    execution_output: dict[str, Any] | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: dict[str, Any] | None = None
    own_addresses: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    currency: CurrencyCode | None = None
    endpoint_digest: Sha256Digest | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    invoice_ref: OpaqueRef | None = None
    source_chain: ShortText | None = None
    source_state_digest: Sha256Digest | None = None
    invoice_total: Decimal | None = None
    issued_at: str | None = None
    correlation_sha256: Sha256Digest | None = None
    due_at: str | None = None
    amount_due: Decimal | None = None
    days_overdue: int | None = Field(default=None, ge=0, le=100000)
    aging_source: ShortText | None = None
    rung: int | None = Field(default=None, ge=1, le=16)
    channel: ShortText | None = None
    template_ref: OpaqueRef | None = None
    sent_at: str | None = None
    execution_digest: Sha256Digest | None = None
    journal_ref: OpaqueRef | None = None
    consent_commitment: dict[str, Any] | None = None
    promised_at: str | None = None
    promised_amount: Decimal | None = None
    operator_supplied: bool | None = None
    thread_ref: OpaqueRef | None = None
    thread_digest: Sha256Digest | None = None
    applied_amount: Decimal | None = None
    payment_count: int | None = Field(default=None, ge=1, le=1000)
    applied_at: str | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    dispute_ref: OpaqueRef | None = None
    resolution_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    approval_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    approved_amount: Decimal | None = None
    credit_note_ref: OpaqueRef | None = None
    credit_note_amount: Decimal | None = None
    credit_note_digest: Sha256Digest | None = None
    credit_note_at: str | None = None
    referral_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("invoice_total", "amount_due", "promised_amount", "applied_amount", "approved_amount", "credit_note_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("issued_at", "due_at", "sent_at", "promised_at", "applied_at", "approved_at", "credit_note_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class CollectionsLedger(StrictModel):
    entity_scope: EngineScope | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    requester_ref: OpaqueRef | None = None
    currency: CurrencyCode | None = None
    endpoint_digest: Sha256Digest | None = None
    issued_at: str | None = None
    applied_at: str | None = None
    payment_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=30)
    execution_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=20)
    authorization_proof_digest: Sha256Digest | None = None
    invoice_ref: str | None = None
    source_chain: str | None = None
    source_state_digest: str | None = None
    correlation_sha256: str | None = None
    invoice_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    terms_days: int = Field(default=0, ge=0)
    due_at: str | None = None
    days_past_due: int = Field(default=0, ge=0)
    aging_bucket: str | None = None
    rung: int = Field(default=0, ge=0)
    reminders_sent: int = Field(default=0, ge=0)
    last_reminder_at: str | None = None
    promise_at: str | None = None
    promises_made: int = Field(default=0, ge=0)
    promises_broken: int = Field(default=0, ge=0)
    partial_payments: int = Field(default=0, ge=0)
    recovered_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    dispute_ref: str | None = None
    write_off_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    credit_note_ref: str | None = None
    provision_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    write_off_reason: str | None = None
    referral_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "recovered", "written_off", "referred", "reconciliation_required"] = "open"

    @field_validator("invoice_total", "balance", "recovered_amount", "write_off_amount", "provision_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class CollectionsEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    payment_collected: Literal[False] = False
    credit_note_created: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


# --------------------------------------------------------------------------- #
# Aging and the apply rule
# --------------------------------------------------------------------------- #


def _days(start: str | None, end: str) -> int:
    if not start:
        return 0
    return (parsed(end) - parsed(start)).days


def aging_bucket(days_past_due: int) -> str:
    if days_past_due <= 0:
        return "current"
    if days_past_due <= 30:
        return "0-30"
    if days_past_due <= 60:
        return "31-60"
    if days_past_due <= 90:
        return "61-90"
    return "90+"


def _age(plan: CollectionsChainPlan, data: dict[str, Any], at: str) -> None:
    """Re-derive the age, the bucket, and the bad-debt provision from the balance the ledger holds."""

    due = data.get("due_at")
    if not due:
        return
    raw = _days(str(due), at)
    bucket = aging_bucket(raw)
    balance = Decimal(str(data.get("balance", "0")))
    data["days_past_due"] = max(0, raw)
    data["aging_bucket"] = bucket
    data["provision_amount"] = str(pct(balance, plan.provision_percent(bucket)))


def _money_of(data: Mapping[str, Any], key: str) -> Decimal:
    return Decimal(str(data.get(key, "0")))


def _consent(plan: CollectionsChainPlan, step: LadderStep, receipt: Any) -> None:
    if step.channel not in CONSENTED_CHANNELS or not plan.require_consent_for_sms_voice:
        return
    require(receipt.consent_commitment is not None, "CONSENT_MISSING", f"a {step.channel} rung carries the permission_register eligibility commitment that covered the send; none is bound")
    try:
        commitment = EligibilityCommitment.model_validate(detached(receipt.consent_commitment))
    except (TypeError, ValueError) as exc:
        raise Rejected("CONSENT_MISSING", f"the bound consent is not a sealed permission_register commitment: {exc}"[:300], "correct_input") from exc
    require(commitment.channel == step.channel, "CONSENT_MISSING", f"the bound consent covers {commitment.channel}; this rung is a {step.channel} rung")
    require(parsed(commitment.as_of) <= parsed(str(receipt.sent_at)) < parsed(commitment.valid_until), "CONSENT_MISSING", "the bound consent did not cover the moment the message was sent")


def _apply_receivable(plan: CollectionsChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "open_receivable":
        require(r.entity_scope is not None and r.entity_scope.currency == plan.currency, "SCOPE_MISMATCH", "receivable binds its opening company execution scope")
        data.update(entity_scope=r.entity_scope.to_dict(), requester_ref=command.actor_ref, currency=plan.currency, source_state=r.source_state, source_plan=r.source_plan, issued_at=r.issued_at, endpoint_digest=r.endpoint_digest)
        require(r.invoice_ref is not None and r.invoice_total is not None and r.issued_at is not None and r.source_chain is not None and r.source_state_digest is not None, "RECEIVABLE_MISSING", "a receivable names the invoice, its total, when it issued, and the sealed chain state it came from")
        require(r.invoice_total > 0, "INVOICE_TOTAL_INVALID", "an invoice with no value is not a receivable")
        due = r.due_at or add_days(r.issued_at, plan.terms_days)
        data.update({"invoice_ref": r.invoice_ref, "source_chain": r.source_chain, "source_state_digest": r.source_state_digest, "correlation_sha256": r.correlation_sha256, "invoice_total": str(r.invoice_total), "balance": str(r.invoice_total), "terms_days": plan.terms_days, "due_at": due})
    elif event == "mark_due":
        require(r.invoice_ref is not None and r.due_at is not None and r.amount_due is not None, "AGING_MISSING", "a due receivable names the invoice, its due date, and the balance the provider still shows")
        require(r.invoice_ref == data.get("invoice_ref"), "AGING_INVOICE_MISMATCH", f"the aged row is for {r.invoice_ref}; this case is on {data.get('invoice_ref')}", "manual_reconciliation")
        require(Decimal("0") < r.amount_due <= _money_of(data, "invoice_total"), "AGING_BALANCE_EXCEEDS_INVOICE", f"the provider shows {r.amount_due} outstanding against an invoice of {data.get('invoice_total')}", "manual_reconciliation")
        require(parsed(at) >= parsed(r.due_at), "NOT_YET_DUE", f"the invoice is not due until {r.due_at}")
        data.update({"due_at": r.due_at, "balance": str(r.amount_due)})
    elif event == "send_reminder":
        step = plan.step(r.rung)
        require(step is not None, "LADDER_STEP_SKIPPED", f"rung {r.rung} is not on this plan's ladder")
        assert step is not None
        require(r.rung == int(data.get("rung", 0)) + 1, "LADDER_STEP_SKIPPED", f"the case is on rung {data.get('rung', 0)}; the ladder runs in order and the next rung is {int(data.get('rung', 0)) + 1}")
        require(r.execution_digest is not None and r.journal_ref is not None and r.sent_at is not None and r.channel is not None, "REMINDER_NOT_SENT", "a rung advances on a bound execution receipt proving the message left, never on the intent to send one")
        require(r.channel == step.channel and r.template_ref == step.template_ref, "REMINDER_NOT_SENT", f"the proven send was a {r.channel} on {r.template_ref}; rung {r.rung} is a {step.channel} on {step.template_ref}")
        require(parsed(r.sent_at) <= parsed(at), "REMINDER_NOT_SENT", "the send has not happened yet")
        _consent(plan, step, r)
        require(_days(data.get("due_at"), r.sent_at) >= step.days_past_due, "REMINDER_TOO_SOON", f"rung {r.rung} runs {step.days_past_due} day(s) past due; the send was {_days(data.get('due_at'), r.sent_at)} day(s) past due")
        since = data.get("last_reminder_at") or data.get("due_at")
        require(_days(since, r.sent_at) >= step.min_lead_days, "REMINDER_TOO_SOON", f"rung {r.rung} allows a send {step.min_lead_days} day(s) after {since}; this one was {_days(since, r.sent_at)} day(s) later")
        data.update({"rung": r.rung, "reminders_sent": int(data.get("reminders_sent", 0)) + 1, "last_reminder_at": r.sent_at})
    elif event == "record_promise":
        require(r.promised_at is not None and r.promised_amount is not None and r.thread_digest is not None and bool(r.operator_supplied), "PROMISE_UNEVIDENCED", "a promise is the counterparty's own thread plus an operator-recorded date and amount; silence is never a promise")
        require(r.promised_amount > 0, "PROMISE_UNEVIDENCED", "a promise names an amount above zero")
        require(parsed(r.promised_at) > parsed(at), "PROMISE_DATE_IN_PAST", f"the promise names {r.promised_at}, which is not later than {at}")
        require((parsed(r.promised_at) - parsed(at)).days <= plan.max_promise_horizon_days, "PROMISE_BEYOND_HORIZON", f"the promise is {(parsed(r.promised_at) - parsed(at)).days} day(s) out; the plan allows {plan.max_promise_horizon_days}")
        require(int(data.get("promises_made", 0)) < plan.max_promises, "PROMISE_LIMIT_EXCEEDED", f"this debtor has already made {data.get('promises_made', 0)} of {plan.max_promises} promises", "manual_reconciliation")
        data.update({"promise_at": r.promised_at, "promises_made": int(data.get("promises_made", 0)) + 1})
    elif event == "break_promise":
        require(data.get("promise_at") is not None, "PROMISE_UNEVIDENCED", "no promise is recorded on this case")
        require(parsed(at) > parsed(str(data["promise_at"])), "PROMISE_NOT_DUE", f"the promise names {data['promise_at']}; it is not broken before that date")
        require(int(data.get("promises_broken", 0)) + 1 < plan.max_promises, "PROMISE_LIMIT_EXCEEDED", f"this is broken promise {int(data.get('promises_broken', 0)) + 1} against a limit of {plan.max_promises}; escalate rather than loop", "manual_reconciliation")
        data.update({"promises_broken": int(data.get("promises_broken", 0)) + 1, "promise_at": None})
    elif event == "apply_partial":
        require(r.applied_amount is not None and r.payment_evidence_sha256 is not None and r.applied_at is not None and r.correlation_sha256 is not None, "PARTIAL_MISSING", "a partial payment names the amount applied, its evidence digest, when it applied, and the correlation")
        require(data.get("correlation_sha256") is None or r.correlation_sha256 == data.get("correlation_sha256"), "PAYMENT_CORRELATION_MISMATCH", "the payment observation must carry the invoice's correlation", "manual_reconciliation")
        balance, total = _money_of(data, "balance"), _money_of(data, "invoice_total")
        increment = (r.applied_amount - (total - balance)).quantize(MONEY_QUANTUM)
        require(Decimal("0") < increment <= balance, "PARTIAL_EXCEEDS_BALANCE", f"the observation applies {r.applied_amount} in total, which is {increment} new against an outstanding balance of {balance}")
        data.update({"balance": str((balance - increment).quantize(MONEY_QUANTUM)), "partial_payments": int(data.get("partial_payments", 0)) + 1})
    elif event == "apply_payment":
        require(r.applied_amount is not None and r.payment_evidence_sha256 is not None and r.applied_at is not None and r.correlation_sha256 is not None and r.payment_count is not None, "RECOVERY_MISSING", "a recovery names the amount applied, its evidence digest, the payment count, when it applied, and the correlation")
        require(data.get("correlation_sha256") is None or r.correlation_sha256 == data.get("correlation_sha256"), "PAYMENT_CORRELATION_MISMATCH", "the payment observation must carry the invoice's correlation", "manual_reconciliation")
        require(r.applied_amount == _money_of(data, "invoice_total"), "RECOVERY_AMOUNT_MISMATCH", f"the observation applied {r.applied_amount} against an invoice of {data.get('invoice_total')}; a recovery clears the invoice exactly once", "manual_reconciliation")
        data.update({"recovered_amount": str(r.applied_amount), "balance": "0", "outcome": "recovered"})
    elif event == "raise_dispute":
        require(r.dispute_ref is not None and r.thread_digest is not None, "DISPUTE_UNEVIDENCED", "a dispute is the counterparty's own thread, never an inference from a missed payment")
        data.update({"dispute_ref": r.dispute_ref})
    elif event == "resolve_dispute":
        require(r.resolution_ref is not None and r.thread_digest is not None, "DISPUTE_UNEVIDENCED", "a resolution names the counterparty thread that closed the dispute")
        data.update({"dispute_ref": None})
    elif event == "escalate":
        require(data.get("dispute_ref") is None, "DISPUTE_BLOCKS_ESCALATION", f"dispute {data.get('dispute_ref')} is open; resolve it before the case escalates")
        require(int(data.get("reminders_sent", 0)) >= plan.min_reminders_before_escalation, "ESCALATION_BEFORE_LADDER", f"the ladder has run {data.get('reminders_sent', 0)} of the {plan.min_reminders_before_escalation} reminders escalation requires")
        require(_money_of(data, "balance") >= plan.escalation_threshold_amount, "ESCALATION_BELOW_THRESHOLD", f"the outstanding balance {data.get('balance')} is below the escalation threshold {plan.escalation_threshold_amount}")
    elif event == "write_off":
        require(data.get("dispute_ref") is None, "DISPUTE_BLOCKS_ESCALATION", f"dispute {data.get('dispute_ref')} is open; a disputed invoice is not written off")
        require(int(data.get("rung", 0)) >= len(plan.ladder), "WRITE_OFF_BEFORE_LADDER", f"the ladder has {len(plan.ladder)} rungs; this case reached rung {data.get('rung', 0)}")
        balance = _money_of(data, "balance")
        from lightbulb.authority_matrix import require_authorization_proof

        require(r.authorization_proof is not None, "WRITE_OFF_NOT_AUTHORIZED", "a write-off consumes a sealed AuthorizationProof for the write_off category; an approval reference is never authority", "await_approval")
        proof = require_authorization_proof(r.authorization_proof, category="write_off", amount=balance, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_scope"]["entity_ref"], requester_ref=data["requester_ref"])
        data["authorization_proof_digest"] = proof.proof_digest
        require(r.approved_amount is None or r.approved_amount == proof.amount, "WRITE_OFF_NOT_AUTHORIZED", "the approval metadata differs from the verified proof", "await_approval")
        require(r.credit_note_ref is not None and r.credit_note_amount is not None and r.credit_note_digest is not None, "WRITE_OFF_WITHOUT_CREDIT_NOTE", "a write-off is matched by an observed credit note; the ledger and the provider cannot disagree", "manual_reconciliation")
        require(r.credit_note_amount == balance, "WRITE_OFF_WITHOUT_CREDIT_NOTE", f"the observed credit note is {r.credit_note_amount}; the balance being written off is {balance}", "manual_reconciliation")
        data.update({"write_off_amount": str(balance), "credit_note_ref": r.credit_note_ref, "balance": "0", "write_off_reason": str(command.reason)[:300], "outcome": "written_off"})
    elif event == "refer":
        require(data.get("dispute_ref") is None, "DISPUTE_BLOCKS_ESCALATION", f"dispute {data.get('dispute_ref')} is open; a disputed invoice is not referred")
        require(r.referral_ref is not None, "REFERRAL_MISSING", "a referral names the agency or counsel the debt was referred to")
        data.update({"referral_reason": str(command.reason)[:300], "outcome": "referred"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    try:
        _verify_sources(plan, data, command)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, getattr(exc, "code", "SOURCE_NOT_SEALED"), str(exc))
    _age(plan, data, at)
    return next_status, data


class _CollectionsLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope)}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope.to_dict() != self.ledger.entity_scope.to_dict():
                    raise ValueError("SCOPE_MISMATCH: receivable scope differs from replayed opening scope")
                return self
        self.State = ScopedState

COLLECTIONS_LIFECYCLE = _CollectionsLifecycle(entity="receivable_case", schema_prefix=COLLECTIONS_CHAIN_KIND, statuses=COLLECTIONS_STATUSES, terminal=TERMINAL_COLLECTIONS_STATUSES, events=COLLECTIONS_EVENTS, table=_COLLECTIONS_TABLE, opening_event="open_receivable", reason_events=("write_off", "refer", "require_reconciliation"), apply=_apply_receivable, ledger_model=CollectionsLedger, receipt_model=CollectionsReceipt, effect_boundary_model=CollectionsEffectBoundary, plan_model=CollectionsChainPlan, max_transitions=MAX_COLLECTIONS_TRANSITIONS)
ReceivableCaseState = COLLECTIONS_LIFECYCLE.State


def open_receivable(plan: CollectionsChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return COLLECTIONS_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_receivable(plan: CollectionsChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return COLLECTIONS_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


class CollectionsChainError(ValueError):
    """A refusal to build a receipt; carries the rejection code and its recovery disposition."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message
        self.recovery = RECOVERY_BY_CODE.get(code, "correct_input")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CollectionsChainError(code, message)


def _provenance(value: ObservationProvenance | Mapping[str, Any]) -> ObservationProvenance:
    try:
        result = ObservationProvenance.model_validate(dict(detached(value)))
        _require(result.provenance_digest != GENESIS_DIGEST, "READ_PROVENANCE_INVALID", "a provider read needs its actual provenance")
        return result
    except (TypeError, ValueError) as exc:
        raise CollectionsChainError("READ_PROVENANCE_INVALID", "a sealed observation provenance is required") from exc


def _lane(prov: ObservationProvenance, tools: Sequence[str], *, code: str) -> None:
    _require(prov.source_tool in tools, code, f"this adapter reads {tuple(tools)}; the provenance names {prov.source_tool}")
    _require(prov.lane != "governed_read" or prov.source_tool in GOVERNED_CONNECTOR_READ_TOOLS, code, f"{prov.source_tool} is not a governed read; it must arrive on the host lane")


def _payload(prov: ObservationProvenance, payload: Mapping[str, Any], *, code: str) -> dict[str, Any]:
    raw = dict(detached(payload))
    _require(stable_digest(raw) == prov.output_digest, code, "the payload does not match the output digest of the read that produced it")
    return raw


def _provider_timestamp(value: Any) -> str:
    text = str(value)
    match = re.fullmatch(r"/Date\((\d{13})(?:[+-]\d{4})?\)/", text)
    if match:
        value = datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
        _require(2000 <= value.year <= 2200, "SOURCE_NOT_SEALED", "native provider date is outside its documented supported epoch")
        text = value.isoformat().replace("+00:00", "Z")
    return timestamp(text if "T" in text else f"{text}T00:00:00Z", field_name="provider timestamp")


def open_receivable_receipt(chain_state: Mapping[str, Any] | Any, *, source_plan: Any) -> dict[str, Any]:
    """The opening receipt from a sealed ``revenue_chain`` or ``subscription_chain`` state that has an issued invoice.

    A typed invoice is never accepted: the receivable exists because another
    chain proved the invoice issued, and it carries that chain's state digest.
    """

    raw = dict(detached(chain_state))
    source = INVOICE_SOURCES.get(str(raw.get("schema")))
    _require(source is not None, "INVOICE_SOURCE_UNSUPPORTED", f"a receivable opens from {sorted(INVOICE_SOURCES)}, never from an invoice a caller typed")
    assert source is not None
    chain, wanted = source
    if chain == "revenue_chain":
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE as spec
    elif chain == "subscription_chain":
        from lightbulb.subscription_chain import SUBSCRIPTION_CHAIN_LIFECYCLE as spec
    else:
        from lightbulb.wip_billing import WIP_BILLING_LIFECYCLE as spec
    bound_plan, bound_state = spec.bind(source_plan, chain_state)
    raw = bound_state.to_dict()
    _require(str(raw.get("status")) == wanted, "INVOICE_NOT_ISSUED", f"the {chain} case is {raw.get('status')}; a receivable opens from {wanted}")
    ledger = dict(raw.get("ledger") or {})
    for key in ("invoice_ref", "invoice_total", "issued_at"):
        _require(bool(ledger.get(key)), "INVOICE_SOURCE_INCOMPLETE", f"the {chain} ledger lacks {key}")
    total = decimal_value(str(ledger["invoice_total"]), field_name="invoice_total")
    _require(total > 0, "INVOICE_SOURCE_INCOMPLETE", f"the {chain} case carries no invoice value")
    entity_ref = str(dict(raw.get("scope") or {}).get("entity_ref") or chain)
    digest = str(raw["state_digest"])
    return {
        "source_state": raw, "source_plan": detached(bound_plan), "currency": str(bound_state.scope.currency), "endpoint_digest": ledger.get("endpoint_digest"),
        "invoice_ref": str(ledger["invoice_ref"]),
        "invoice_total": str(total),
        "issued_at": str(ledger["issued_at"]),
        "correlation_sha256": ledger.get("correlation_sha256") or stable_digest({"stripe_invoice_ref": ledger["invoice_ref"]}),
        "source_chain": chain,
        "source_state_digest": digest,
        "evidence_refs": [f"{chain}:{entity_ref}", f"state:{digest[:24]}"],
    }


def _aged_rows(tool: str, raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalized ``(invoice_ref, due_at, amount_due, days_overdue)`` rows from the pages this chain reads."""

    if raw.get("schema") == "lightbulb.xero_close_source_page.v1":
        rows = []
        for record in raw.get("records") or []:
            item = dict(detached(record))
            rows.append({"invoice_ref": item.get("source_ref"), "due_at": item.get("due_date") or item.get("due_at"), "amount_due": item.get("open_balance"), "days_overdue": item.get("days_overdue"), "currency": item.get("currency")})
        return rows
    if tool.startswith("xero."):
        return [{"invoice_ref": item.get("InvoiceID"), "due_at": item.get("DueDate") or item.get("DueDateString"), "amount_due": item.get("AmountDue"), "days_overdue": item.get("DaysOverdue"), "currency": item.get("CurrencyCode")} for item in (dict(detached(row)) for row in (raw.get("Invoices") or []))]
    query = raw.get("QueryResponse") if isinstance(raw.get("QueryResponse"), Mapping) else raw
    return [{"invoice_ref": item.get("Id"), "due_at": item.get("DueDate") or item.get("TxnDate"), "amount_due": item.get("Balance"), "days_overdue": None, "currency": (dict(item.get("CurrencyRef") or {})).get("value")} for item in (dict(detached(row)) for row in (query.get("Invoice") or []))]


def aging_receipt(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any], *, invoice_ref: str) -> dict[str, Any]:
    """The ``mark_due`` receipt: the balance and due date the provider itself still shows for this invoice.

    The two aged-receivable reports are not governed reads; they arrive on the
    host lane already normalized as the close source page the finance close
    consumes, because the SDK does not parse a provider report layout.
    """

    prov = _provenance(provenance)
    _lane(prov, AGING_TOOLS, code="AGING_TOOL_MISMATCH")
    raw = _payload(prov, payload, code="AGING_DIGEST_MISMATCH")
    _require(raw.get("has_more") is not True, "AGING_ROW_INCOMPLETE", "the aged receivable page must be complete")
    rows = [row for row in _aged_rows(prov.source_tool, raw) if str(row.get("invoice_ref")) == invoice_ref]
    _require(bool(rows), "AGING_INVOICE_NOT_FOUND", f"the page carries no row for invoice {invoice_ref}")
    _require(len(rows) == 1, "AGING_INVOICE_AMBIGUOUS", f"the page carries {len(rows)} rows for invoice {invoice_ref}; an aged balance must be unique")
    row = rows[0]
    _require(row.get("amount_due") is not None and bool(row.get("due_at")), "AGING_ROW_INCOMPLETE", "an aged row names the amount due and the due date")
    due = str(row["due_at"])
    due_at = _provider_timestamp(due)
    amount = decimal_value(str(row["amount_due"]), field_name="amount_due")
    overdue = row.get("days_overdue")
    return {
        "source_provenance": prov.to_dict(), "source_payload": raw, "currency": str(row.get("currency") or "").upper(),
        "invoice_ref": invoice_ref,
        "due_at": due_at,
        "amount_due": str(amount),
        "days_overdue": None if overdue is None else max(0, int(overdue)),
        "aging_source": prov.source_tool,
        "evidence_refs": [f"aging:{prov.observation_ref}", f"provenance:{prov.provenance_digest[:24]}"],
    }


def reminder_receipt(plan: CollectionsChainPlan | Mapping[str, Any], execution_receipt: ExecutionReceipt | Mapping[str, Any], *, rung: int, request: Any, output: Mapping[str, Any], consent: Mapping[str, Any] | Any | None = None, eligibility: Any = None, suppression: Any = None) -> dict[str, Any]:
    """The ``send_reminder`` receipt from the approved write that proves the rung's message left.

    The rung selects the channel and template from the plan's ladder; the
    execution receipt has to agree with both, and an ``sms`` or ``voice`` rung
    carries the ``permission_register`` commitment that covered the send.
    """

    parsed_plan = plan if isinstance(plan, CollectionsChainPlan) else CollectionsChainPlan.model_validate(detached(plan))
    step = parsed_plan.step(rung)
    _require(step is not None, "LADDER_STEP_SKIPPED", f"rung {rung} is not on this plan's ladder")
    assert step is not None
    try:
        execution = ExecutionReceipt.model_validate(dict(detached(execution_receipt)))
    except (TypeError, ValueError) as exc:
        raise CollectionsChainError("REMINDER_NOT_SENT", "a rung advances on a sealed execution receipt for the send") from exc
    _require(execution.effect == "write", "REMINDER_NOT_SENT", f"the receipt proves a {execution.effect}; a reminder is an approved write")
    _require(execution.approval_ref is not None, "REMINDER_NOT_SENT", "the send write carries the approval it ran under")
    channel = SEND_TOOLS.get(execution.tool)
    _require(channel is not None, "REMINDER_NOT_SENT", f"{execution.tool} does not prove a collections message was sent; expected one of {sorted(SEND_TOOLS)}")
    _require(channel == step.channel, "REMINDER_NOT_SENT", f"the proven send was a {channel}; rung {rung} is a {step.channel} rung")
    from lightbulb.connector_execution import ConnectorExecutionRequest
    request = ConnectorExecutionRequest.model_validate(detached(request))
    _require(execution.request_digest == request.custody_fingerprint() and execution.tool == request.tool and execution.output_digest == stable_digest(detached(output)) and execution.approval_ref == request.approval_ref and not request.preview_only and execution.project_id == str(request.scope.project_id) and execution.connector_account_ref == request.connector_account_ref, "REMINDER_NOT_SENT", "the execution must bind its exact approved request, account and returned send output")
    _require(request.arguments.get("template_ref") == step.template_ref, "REMINDER_NOT_SENT", "the actual request must prove this ladder template")
    if channel not in {"sms", "voice"}:
        _require(output.get("invoice_ref") == request.arguments.get("invoice_ref") and output.get("sent_at") == execution.completed_at, "REMINDER_NOT_SENT", "the actual output must prove this invoice's send and completion time")
    commitment = None
    if consent is not None:
        try:
            commitment = EligibilityCommitment.model_validate(detached(consent))
        except (TypeError, ValueError) as exc:
            raise CollectionsChainError("CONSENT_MISSING", "the bound consent is not a sealed permission_register eligibility commitment") from exc
    if channel in {"sms", "voice"}:
        from lightbulb import permission_register as P
        _require(eligibility is not None and suppression is not None, "CONSENT_MISSING", "SMS and voice require complete eligibility and suppression snapshots")
        suppression = P.SuppressionDigest.model_validate(detached(suppression))
        eligibility = P.verify_eligibility(eligibility, suppression_digest=suppression.suppression_digest, channel=channel, endpoints=[request.arguments.get("endpoint_digest")], company_ref=parsed_plan.company_ref, at=execution.completed_at)
        effect = P.permission_execution(execution, output)
        source = next(item for item in eligibility.source_states if item.state["ledger"]["endpoint_digest"] == request.arguments["endpoint_digest"])
        send = P.send_receipt(effect, eligibility=eligibility)
        commitment = EligibilityCommitment.model_validate(send["eligibility"])
        cmd = P.CONSENT_LIFECYCLE.seal_command({"event": "record_send", "transition_ref": f"collections:{execution.execution_digest[:24]}", "idempotency_key": f"collections:{execution.execution_digest[:24]}", "expected_version": source.state["version"], "expected_state_digest": source.state["state_digest"], "occurred_at": execution.completed_at, "actor_ref": request.scope.actor_ref or "collections-host", "receipt": send})
        result = P.CONSENT_LIFECYCLE.advance(source.source_plan, source.state, cmd)
        _require(result.candidate_validated, "CONSENT_MISSING", "the real permission register refused this message")
    return {
        "execution_source": execution.to_dict(), "execution_request": detached(request), "execution_output": detached(output),
        "eligibility_receipt": detached(eligibility), "suppression_digest": detached(suppression),
        "rung": rung,
        "channel": step.channel,
        "template_ref": step.template_ref,
        "sent_at": execution.completed_at,
        "execution_digest": execution.execution_digest,
        "journal_ref": execution.journal_ref,
        "consent_commitment": None if commitment is None else commitment.to_dict(),
        "evidence_refs": [f"reminder:{execution.journal_ref}", f"receipt:{execution.receipt_digest[:24]}"],
    }


def _thread(provenance: ObservationProvenance | Mapping[str, Any], thread: Mapping[str, Any], *, our_addresses: Sequence[str], code: str) -> tuple[ObservationProvenance, dict[str, Any]]:
    """The counterparty's own words: a governed thread carrying at least one message that is not ours."""

    prov = _provenance(provenance)
    _lane(prov, THREAD_TOOLS, code=code)
    raw = _payload(prov, thread, code=code)
    messages = raw.get("messages")
    _require(isinstance(messages, (list, tuple)) and bool(messages), code, "a thread carries at least one message")
    ours = {item.strip().lower() for item in our_addresses if item and item.strip()}
    _require(bool(ours), code, "name at least one of our own sending addresses so an inbound message can be told from ours")
    inbound = False
    for message in messages:  # type: ignore[union-attr]
        headers = dict(dict(detached(message)).get("headers") or {})
        sender = str(headers.get("from") or headers.get("From") or "").lower()
        inbound = inbound or (bool(sender) and not any(address in sender for address in ours))
    _require(inbound, code, "the thread carries nothing the counterparty wrote; the SDK never infers a promise or a dispute from silence")
    return prov, raw


def promise_receipt(provenance: ObservationProvenance | Mapping[str, Any], thread: Mapping[str, Any], *, promised_at: str, promised_amount: Any, our_addresses: Sequence[str]) -> dict[str, Any]:
    """The ``record_promise`` receipt: the customer's own thread plus the date and amount an operator recorded.

    ``promised_at`` and ``promised_amount`` are explicit operator inputs and the
    receipt says so; nothing here reads a promise out of the message body.
    """

    prov, raw = _thread(provenance, thread, our_addresses=our_addresses, code="PROMISE_UNEVIDENCED")
    amount = decimal_value(promised_amount, field_name="promised_amount")
    _require(amount > 0, "PROMISE_UNEVIDENCED", "a promise names an amount above zero")
    return {
        "source_provenance": prov.to_dict(), "source_payload": raw, "own_addresses": list(our_addresses),
        "promised_at": timestamp(promised_at, field_name="promised_at"),
        "promised_amount": str(amount),
        "operator_supplied": True,
        "thread_ref": prov.observation_ref,
        "thread_digest": prov.provenance_digest,
        "evidence_refs": [f"thread:{prov.observation_ref}", f"provenance:{prov.provenance_digest[:24]}"],
    }


def dispute_receipt(provenance: ObservationProvenance | Mapping[str, Any], thread: Mapping[str, Any], *, dispute_ref: str, our_addresses: Sequence[str]) -> dict[str, Any]:
    """The ``raise_dispute`` receipt: a dispute exists because the counterparty said so in a governed thread."""

    prov, _ = _thread(provenance, thread, our_addresses=our_addresses, code="DISPUTE_UNEVIDENCED")
    return {"source_provenance": prov.to_dict(), "source_payload": detached(thread), "own_addresses": list(our_addresses), "dispute_ref": dispute_ref, "thread_ref": prov.observation_ref, "thread_digest": prov.provenance_digest, "evidence_refs": [f"dispute:{dispute_ref}", f"thread:{prov.observation_ref}"]}


def dispute_resolution_receipt(provenance: ObservationProvenance | Mapping[str, Any], thread: Mapping[str, Any], *, resolution_ref: str, our_addresses: Sequence[str]) -> dict[str, Any]:
    """The ``resolve_dispute`` receipt: the thread in which the dispute closed."""

    prov, _ = _thread(provenance, thread, our_addresses=our_addresses, code="DISPUTE_UNEVIDENCED")
    return {"source_provenance": prov.to_dict(), "source_payload": detached(thread), "own_addresses": list(our_addresses), "resolution_ref": resolution_ref, "thread_ref": prov.observation_ref, "thread_digest": prov.provenance_digest, "evidence_refs": [f"resolution:{resolution_ref}", f"thread:{prov.observation_ref}"]}


def _payment_observation(observation: Mapping[str, Any] | Any, *, provenance: Any, balance_zero: bool, code: str) -> dict[str, Any]:
    observed = dict(detached(observation))
    _require(observed.get("schema") == INVOICE_PAYMENT_OBSERVATION_SCHEMA, "PAYMENT_OBSERVATION_SCHEMA_MISMATCH", "expected a quickbooks.observe_invoice_payment_applied observation")
    from lightbulb.cash_collection import QuickBooksInvoicePaymentObservation
    observed = QuickBooksInvoicePaymentObservation.model_validate(observed).to_dict()
    prov = _provenance(provenance)
    _lane(prov, ("quickbooks.observe_invoice_payment_applied",), code="PAYMENT_OBSERVATION_SCHEMA_MISMATCH")
    _payload(prov, observed, code="PAYMENT_OBSERVATION_DIGEST_MISMATCH")
    native = observed.get("query_sha256") is not None
    expected_disposition = "APPLIED" if balance_zero else ("PARTIAL" if native else "INCOMPLETE")
    _require(str(observed.get("disposition")) == expected_disposition, "PAYMENT_NOT_APPLIED", f"payment disposition is {observed.get('disposition')}; a partial payment is an exhaustive incomplete invoice")
    linked = (observed.get("match_count") == 1 and observed.get("unique_match") is True and bool(observed.get("observed_effect_sha256")) and observed.get("invoice_total") is not None and 0 < observed.get("payment_count", 0) <= 10) if native else (bool(observed.get("invoice_id_sha256")) and bool(observed.get("payment_query_sha256")))
    _require(linked and observed.get("payment_count", 0) > 0 and Decimal(str(observed.get("applied_amount", "0"))) > 0, "PAYMENT_NOT_APPLIED", "a partial or complete payment needs positive linked payment evidence")
    _require(bool(observed.get("exhaustive_read")), "PAYMENT_READ_NOT_EXHAUSTIVE", "the observer did not read every payment linked to the invoice")
    _require(bool(observed.get("invoice_balance_zero")) == balance_zero, code, f"the observation reports invoice_balance_zero={observed.get('invoice_balance_zero')}")
    return {
        "source_provenance": prov.to_dict(), "payment_observation": observed, "currency": str(observed["currency"]).upper(),
        "correlation_sha256": str(observed["provider_correlation_sha256"]),
        "payment_evidence_sha256": str(observed["evidence_sha256"]),
        "applied_amount": str(decimal_value(observed.get("applied_amount"), field_name="applied_amount")),
        "payment_count": int(observed.get("payment_count", 1)),
        "applied_at": timestamp(str(observed["observed_at"]), field_name="applied_at"),
        "evidence_refs": [f"payment:{str(observed['evidence_sha256'])[:24]}"],
    }


def partial_receipt(payment_observation: Mapping[str, Any] | Any, *, provenance: Any) -> dict[str, Any]:
    """The ``apply_partial`` receipt from a governed payment observation whose invoice still carries a balance."""

    return _payment_observation(payment_observation, provenance=provenance, balance_zero=False, code="INVOICE_BALANCE_CLEARED")


def recovery_receipt(payment_observation: Mapping[str, Any] | Any, *, provenance: Any) -> dict[str, Any]:
    """The ``apply_payment`` receipt from a governed payment observation that cleared the invoice."""

    return _payment_observation(payment_observation, provenance=provenance, balance_zero=True, code="INVOICE_BALANCE_OPEN")


def revenue_chain_payment_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The same observation as ``revenue_chain.apply_payment``'s receipt, so one payment closes both chains once."""

    from lightbulb.revenue_chain import collections_payment_receipt

    return collections_payment_receipt(verify_recovered_receivable(state, source_plan=source_plan), source_plan=source_plan)


class CreditNoteObservation(StrictModel):
    """One observed credit note allocated to one invoice; the artifact a write-off has to match."""

    schema_id: Literal["lightbulb.collections_credit_note_observation.v1"] = Field(default=CREDIT_NOTE_OBSERVATION_SCHEMA, alias="schema")
    provenance: ObservationProvenance
    source_payload: dict[str, Any]
    invoice_ref: OpaqueRef
    credit_note_ref: OpaqueRef
    amount: Decimal
    currency: ShortText
    issued_at: str
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")

    @field_validator("issued_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="issued_at")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> CreditNoteObservation:
        if not skip_digests(info) and self.observation_digest != sealed_digest(CreditNoteObservation, self, "observation_digest"):
            raise ValueError("observation_digest must commit the exact credit note observation")
        raw = _payload(_provenance(self.provenance), self.source_payload, code="CREDIT_NOTE_DIGEST_MISMATCH")
        rows = [row for row in _credit_note_rows(self.provenance.source_tool, raw) if str(row.get("invoice_ref")) == self.invoice_ref]
        _require(len(rows) == 1, "CREDIT_NOTE_AMBIGUOUS", "one complete source must allocate exactly one credit note to the invoice")
        row = rows[0]
        issued = str(row["issued_at"])
        expected = (str(row["credit_note_ref"]), decimal_value(str(row["amount"]), field_name="amount"), str(row["currency"]).upper(), _provider_timestamp(issued))
        _require((self.credit_note_ref, self.amount, self.currency, self.issued_at) == expected, "SOURCE_PROJECTION_MISMATCH", "credit values must rederive from their retained source allocation")
        return self


def _credit_note_rows(tool: str, raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if tool.startswith("xero."):
        for record in raw.get("CreditNotes") or []:
            item = dict(detached(record))
            for allocation in item.get("Allocations") or []:
                link = dict(detached(allocation))
                invoice = dict(link.get("Invoice") or {})
                rows.append({"credit_note_ref": item.get("CreditNoteID"), "invoice_ref": invoice.get("InvoiceID"), "amount": link.get("Amount"), "currency": item.get("CurrencyCode"), "issued_at": item.get("Date")})
        return rows
    query = raw.get("QueryResponse") if isinstance(raw.get("QueryResponse"), Mapping) else raw
    for record in query.get("CreditMemo") or []:
        item = dict(detached(record))
        _require(sum(str(link.get("TxnType")) == "Invoice" for link in item.get("LinkedTxn") or []) <= 1, "CREDIT_NOTE_AMBIGUOUS", "a total credit memo cannot be allocated in full to multiple invoices")
        for link in item.get("LinkedTxn") or []:
            linked = dict(detached(link))
            if str(linked.get("TxnType")) == "Invoice":
                rows.append({"credit_note_ref": item.get("Id"), "invoice_ref": linked.get("TxnId"), "amount": item.get("TotalAmt"), "currency": (dict(item.get("CurrencyRef") or {})).get("value"), "issued_at": item.get("TxnDate")})
    return rows


def credit_note_observation(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any], *, invoice_ref: str) -> CreditNoteObservation:
    """Seal the credit note the provider shows against this invoice; neither credit-note read is governed today."""

    prov = _provenance(provenance)
    _lane(prov, CREDIT_NOTE_TOOLS, code="CREDIT_NOTE_TOOL_MISMATCH")
    raw = _payload(prov, payload, code="CREDIT_NOTE_DIGEST_MISMATCH")
    rows = [row for row in _credit_note_rows(prov.source_tool, raw) if str(row.get("invoice_ref")) == invoice_ref]
    _require(bool(rows), "CREDIT_NOTE_NOT_FOUND", f"the page carries no credit note allocated to invoice {invoice_ref}")
    _require(len(rows) == 1, "CREDIT_NOTE_AMBIGUOUS", f"the page allocates {len(rows)} credit notes to invoice {invoice_ref}; a write-off matches exactly one")
    row = rows[0]
    for key in ("credit_note_ref", "amount", "currency", "issued_at"):
        _require(row.get(key) is not None, "CREDIT_NOTE_INCOMPLETE", f"the credit note row lacks {key}")
    issued = str(row["issued_at"])
    return seal(CreditNoteObservation, {"provenance": prov.to_dict(), "source_payload": raw, "invoice_ref": invoice_ref, "credit_note_ref": str(row["credit_note_ref"]), "amount": str(decimal_value(str(row["amount"]), field_name="amount")), "currency": str(row["currency"]).upper(), "issued_at": _provider_timestamp(issued)}, "observation_digest")


def credit_note_receipt(observation: CreditNoteObservation | Mapping[str, Any]) -> dict[str, Any]:
    """The credit-note half of a write-off receipt, on its own so the approval can be raised against it."""

    try:
        note = CreditNoteObservation.model_validate(detached(observation))
    except (TypeError, ValueError) as exc:
        raise CollectionsChainError("WRITE_OFF_WITHOUT_CREDIT_NOTE", "a write-off requires a sealed credit note observation") from exc
    return {"credit_note_source": note.to_dict(), "credit_note_ref": note.credit_note_ref, "credit_note_amount": str(note.amount), "credit_note_digest": note.observation_digest, "credit_note_at": note.issued_at, "evidence_refs": [f"credit_note:{note.credit_note_ref}", f"observation:{note.observation_digest[:24]}"]}


def write_off_receipt(authorization_proof: Any, observation: CreditNoteObservation | Mapping[str, Any]) -> dict[str, Any]:
    """The ``write_off`` receipt: an authorized decision matched by an observed credit note for the same money."""

    from lightbulb.authority_matrix import AuthorityMatrixError, AuthorizationProof, authorization_evidence

    note = credit_note_receipt(observation)
    try:
        proof = AuthorizationProof.model_validate(detached(authorization_proof))
    except (TypeError, ValueError) as exc:
        raise CollectionsChainError("WRITE_OFF_NOT_AUTHORIZED", "a write-off consumes a sealed AuthorizationProof, never an approval reference") from exc
    _require(proof.category == "write_off", "WRITE_OFF_NOT_AUTHORIZED", f"the proof grants {proof.category} authority, not write_off")
    _require(proof.amount == decimal_value(note["credit_note_amount"], field_name="credit_note_amount"), "WRITE_OFF_WITHOUT_CREDIT_NOTE", f"the approval authorized {proof.amount}; the observed credit note is {note['credit_note_amount']}")
    try:
        approval = authorization_evidence(proof)
    except AuthorityMatrixError as exc:  # pragma: no cover - defensive
        raise CollectionsChainError("WRITE_OFF_NOT_AUTHORIZED", exc.message) from exc
    return {**note, **approval, "evidence_refs": [*note["evidence_refs"], *approval["evidence_refs"]]}


def _same_scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(key) == b.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _verify_sources(plan: Any, data: dict[str, Any], command: Any) -> None:
    r, event, at = command.receipt, command.event, command.occurred_at
    derived: dict[str, Any] = {}
    if event == "open_receivable":
        _require(r.source_state is not None and r.source_plan is not None, "SOURCE_NOT_SEALED", "a receivable retains its actual source state and plan")
        derived = open_receivable_receipt(r.source_state, source_plan=r.source_plan)
        _require(r.source_plan.get("company_ref") == plan.company_ref and _same_scope(r.source_state["scope"], data["entity_scope"]) and r.currency == plan.currency, "SCOPE_MISMATCH", "invoice belongs to another company, tenant, project or currency")
        _require(parsed(r.source_state["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at) and parsed(r.issued_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the source invoice must have issued before this receivable opens")
        _require(r.due_at is None or r.due_at == r.source_state["ledger"].get("due_at"), "SOURCE_PROJECTION_MISMATCH", "a custom due date must come from the actual source invoice")
    elif event == "mark_due":
        derived = aging_receipt(r.source_provenance, r.source_payload, invoice_ref=data["invoice_ref"])
        _require(r.currency == plan.currency, "SCOPE_MISMATCH", "the aged invoice belongs to another currency")
    elif event in {"apply_partial", "apply_payment"}:
        derived = (partial_receipt if event == "apply_partial" else recovery_receipt)(r.payment_observation, provenance=r.source_provenance)
        observation = r.payment_observation
        if observation.get("query_sha256") is not None:
            _require(Decimal(observation["invoice_total"]) == Decimal(str(data["invoice_total"])), "RECOVERY_AMOUNT_MISMATCH", "the native observed invoice total must equal the original receivable total")
        else:
            _require(observation["invoice_id_sha256"] == stable_digest(data["invoice_ref"]), "PAYMENT_CORRELATION_MISMATCH", "payment must bind this exact provider invoice")
        _require(r.correlation_sha256 == data["correlation_sha256"], "PAYMENT_CORRELATION_MISMATCH", "payment must bind the original retained invoice correlation")
        _require(r.currency == plan.currency, "SCOPE_MISMATCH", "payment belongs to another currency")
        _require(parsed(data["issued_at"]) <= parsed(r.applied_at) <= parsed(r.source_provenance.completed_at), "SOURCE_FROM_FUTURE", "payment must follow the invoice and precede its completed read")
        previous = data.get("payment_sources", ())
        _require(not any(item["observation"]["evidence_sha256"] == r.payment_evidence_sha256 for item in previous), "PAYMENT_ALREADY_USED", "one payment evidence result cannot be applied twice")
        _require(not previous or observation["payment_count"] >= previous[-1]["observation"]["payment_count"], "PAYMENT_HISTORY_REGRESSED", "an exhaustive cumulative payment read cannot lose earlier payments")
        data["payment_sources"] = [*previous, {"provenance": r.source_provenance.to_dict(), "observation": observation}]
        data["applied_at"] = r.applied_at
    elif event == "send_reminder":
        derived = reminder_receipt(plan, r.execution_source, rung=r.rung, request=r.execution_request, output=r.execution_output, consent=r.consent_commitment, eligibility=r.eligibility_receipt, suppression=r.suppression_digest)
        request = r.execution_request
        _require(request["arguments"].get("receivable_state_digest") == command.expected_state_digest and request["arguments"].get("invoice_ref") == data["invoice_ref"], "REMINDER_NOT_SENT", "the executed request must bind this exact current receivable and invoice")
        _require(all(str(request["scope"].get(key)) == str(data["entity_scope"].get(key)) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "SCOPE_MISMATCH", "the reminder executed in another company, tenant or project")
        if r.eligibility_receipt is not None:
            from lightbulb.permission_register import verify_eligibility
            _require(data.get("endpoint_digest") is not None and request["arguments"].get("endpoint_digest") == data["endpoint_digest"], "CONSENT_MISSING", "SMS and voice endpoint must be associated with this invoice's actual source customer")
            verify_eligibility(r.eligibility_receipt, suppression_digest=r.suppression_digest["suppression_digest"], channel=r.channel, endpoints=[request["arguments"]["endpoint_digest"]], company_ref=plan.company_ref, at=r.sent_at, expected_scope=data["entity_scope"])
        _require(r.execution_digest not in data.get("execution_digests", ()), "REMINDER_ALREADY_USED", "one completed send cannot advance the collections ladder twice")
        data["execution_digests"] = [*data.get("execution_digests", ()), r.execution_digest]
    elif event == "record_promise":
        derived = promise_receipt(r.source_provenance, r.source_payload, promised_at=r.promised_at, promised_amount=r.promised_amount, our_addresses=r.own_addresses)
        _require(r.promised_amount <= _money_of(data, "balance"), "PROMISE_EXCEEDS_BALANCE", "a promise concerns at most the remaining receivable")
    elif event == "raise_dispute":
        derived = dispute_receipt(r.source_provenance, r.source_payload, dispute_ref=r.dispute_ref, our_addresses=r.own_addresses)
    elif event == "resolve_dispute":
        derived = dispute_resolution_receipt(r.source_provenance, r.source_payload, resolution_ref=r.resolution_ref, our_addresses=r.own_addresses)
    elif event == "write_off":
        _require(r.credit_note_source is not None, "WRITE_OFF_WITHOUT_CREDIT_NOTE", "the credit note retains its complete provider source")
        derived = credit_note_receipt(r.credit_note_source)
        note = CreditNoteObservation.model_validate(r.credit_note_source)
        _require(note.invoice_ref == data["invoice_ref"] and note.currency == plan.currency, "WRITE_OFF_WITHOUT_CREDIT_NOTE", "the credit note must allocate this invoice in its actual currency")
        _require(parsed(note.issued_at) <= parsed(note.provenance.completed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the issued credit note must have been read before write-off")
    if r.source_provenance is not None:
        _require(parsed(r.source_provenance.completed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the provider read must finish before the consuming command")
        raw = r.source_payload or {}
        _require(raw.get("company_ref", plan.company_ref) == plan.company_ref, "SCOPE_MISMATCH", "the provider page names another company")
        if raw.get("scope") is not None:
            _require(_same_scope(raw["scope"], data["entity_scope"]), "SCOPE_MISMATCH", "the provider page names another execution scope")
    if event in {"record_promise", "raise_dispute", "resolve_dispute"}:
        _require(r.source_payload.get("invoice_ref") == data["invoice_ref"], "THREAD_INVOICE_MISMATCH", "the counterparty thread must carry this invoice's normalized reference")
    raw = r.to_dict()
    for key, value in derived.items():
        if key not in {"evidence_refs", "detail"}:
            _require(raw.get(key) == detached(value), "SOURCE_PROJECTION_MISMATCH", f"{key} must rederive from retained source evidence")


def verify_recovered_receivable(state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, source = COLLECTIONS_LIFECYCLE.bind(source_plan, state)
    _require(source.status == "recovered" and source.ledger.balance == 0, "COLLECTIONS_NOT_RECOVERED", "a recovered invoice has its full payment history and zero balance")
    _require((company_ref is None or plan.company_ref == company_ref) and (currency is None or plan.currency == currency) and (expected_scope is None or _same_scope(source.scope, expected_scope)), "SCOPE_MISMATCH", "the receivable belongs to another company, tenant, project or currency")
    _require(at is None or parsed(source.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the collection cannot postdate its consumer")
    return source


# --------------------------------------------------------------------------- #
# What the chain hands the other engines
# --------------------------------------------------------------------------- #


def _bound(state: Any, plan: CollectionsChainPlan | Mapping[str, Any] | None = None) -> Any:
    _require(plan is not None, "SOURCE_PLAN_MISSING", "cross-state helpers require the actual source plan for full replay")
    _, parsed_state = COLLECTIONS_LIFECYCLE.bind(plan, state)
    return parsed_state


def receivable_flows(states: Sequence[Any], *, plan: CollectionsChainPlan | Mapping[str, Any] | None = None) -> list[ScheduledFlow]:
    """Treasury inflows dated by the recorded promise where there is one, and by the due date where there is not.

    A promise is the only thing anyone actually said about when the money
    arrives; dating the forecast by the invoice terms assumes everybody pays on
    time, which is exactly the assumption this chain exists to break.
    """

    flows: list[ScheduledFlow] = []
    _require(len({str(detached(value)["scope"]["entity_ref"]) for value in states}) == len(states), "CASE_DUPLICATED", "one receivable enters the cash forecast once")
    for value in states:
        state = _bound(value, plan)
        ledger = state.ledger
        if state.status in TERMINAL_COLLECTIONS_STATUSES or ledger.balance <= 0 or not ledger.due_at:
            continue
        promised = ledger.promise_at is not None
        flows.append(ScheduledFlow(kind="receivable", ref=f"receivable:{state.scope.entity_ref}", due_at=str(ledger.promise_at or ledger.due_at), amount=str(ledger.balance), source="collections_chain:promise" if promised else "collections_chain:terms"))
    return flows


def provision_rows(states: Sequence[Any], plan: CollectionsChainPlan | Mapping[str, Any]) -> list[dict[str, Any]]:
    """Bad-debt adjustment candidates for the finance close: one row per open receivable, at the plan's rate for its bucket."""

    parsed_plan = plan if isinstance(plan, CollectionsChainPlan) else CollectionsChainPlan.model_validate(detached(plan))
    rows: list[dict[str, Any]] = []
    _require(len({str(detached(value)["scope"]["entity_ref"]) for value in states}) == len(states), "CASE_DUPLICATED", "one receivable enters the bad-debt provision once")
    for value in states:
        state = _bound(value, parsed_plan)
        ledger = state.ledger
        if state.status in TERMINAL_COLLECTIONS_STATUSES or ledger.balance <= 0:
            continue
        percent = parsed_plan.provision_percent(ledger.aging_bucket)
        rows.append({
            "adjustment_kind": "bad_debt_provision",
            "case_ref": str(state.scope.entity_ref),
            "invoice_ref": ledger.invoice_ref,
            "currency": state.scope.currency,
            "aging_bucket": ledger.aging_bucket,
            "days_past_due": ledger.days_past_due,
            "balance": str(ledger.balance),
            "provision_percent": str(percent),
            "provision_amount": str(ledger.provision_amount),
            "source_digest": state.state_digest,
            "evidence_refs": [f"receivable:{state.scope.entity_ref}", f"state:{state.state_digest[:24]}"],
        })
    return rows


def receivable_exception(state: Any, *, now: str, overdue_days: int = 30, plan: CollectionsChainPlan | Mapping[str, Any] | None = None) -> dict[str, Any] | None:
    """An exceptions-desk opening receipt for a disputed or badly overdue receivable; ``None`` when neither applies."""

    case = _bound(state, plan)
    ledger = case.ledger
    at = timestamp(now, field_name="now")
    if case.status == "disputed":
        return {"kind": DISPUTED_INVOICE_EXCEPTION_KIND, "source_engine": COLLECTIONS_CHAIN_KIND, "source_ref": f"{COLLECTIONS_CHAIN_KIND}:{case.scope.entity_ref}", "source_digest": case.state_digest, "code": "INVOICE_DISPUTED", "detail": f"invoice {ledger.invoice_ref} is disputed under {ledger.dispute_ref}; {ledger.balance} is not collectible until the dispute resolves", "evidence_refs": [f"receivable:{case.scope.entity_ref}", f"state:{case.state_digest[:24]}"]}
    if case.status in _OPEN_STATUSES and ledger.due_at and _days(ledger.due_at, at) > overdue_days and ledger.balance > 0:
        return {"kind": RECEIVABLE_OVERDUE_EXCEPTION_KIND, "source_engine": COLLECTIONS_CHAIN_KIND, "source_ref": f"{COLLECTIONS_CHAIN_KIND}:{case.scope.entity_ref}", "source_digest": case.state_digest, "code": "RECEIVABLE_OVERDUE", "detail": f"invoice {ledger.invoice_ref} is {_days(ledger.due_at, at)} day(s) past due with {ledger.balance} outstanding after {ledger.reminders_sent} reminder(s)", "evidence_refs": [f"receivable:{case.scope.entity_ref}", f"state:{case.state_digest[:24]}"]}
    return None


def case_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    state = _bound(state, source_plan)
    ledger = state.ledger
    return {"case_ref": str(state.scope.entity_ref), "status": state.status, "invoice_ref": ledger.invoice_ref, "source_chain": ledger.source_chain, "invoice_total": str(ledger.invoice_total), "balance": str(ledger.balance), "days_past_due": ledger.days_past_due, "aging_bucket": ledger.aging_bucket, "rung": ledger.rung, "reminders_sent": ledger.reminders_sent, "promise_at": ledger.promise_at, "promises_broken": ledger.promises_broken, "recovered_amount": str(ledger.recovered_amount), "write_off_amount": str(ledger.write_off_amount), "provision_amount": str(ledger.provision_amount), "outcome": ledger.outcome, "state_digest": state.state_digest}


def collections_summary(states: Sequence[Any], *, as_of: str, period_days: int = 90, plan: CollectionsChainPlan | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The operator view: what is outstanding, what was recovered or forgiven, what a promise says is coming, and DSO."""

    at = timestamp(as_of, field_name="as_of")
    cases = [_bound(value, plan) for value in states]
    _require(len({case.scope.entity_ref for case in cases}) == len(cases), "CASE_DUPLICATED", "one receivable enters the collection book once")
    _require(all(not cases or _same_scope(case.scope, cases[0].scope) for case in cases), "SCOPE_MISMATCH", "a collections book cannot combine authenticated company scopes")
    _require(all(parsed(case.transition_history[-1].command.occurred_at) <= parsed(at) for case in cases), "SOURCE_FROM_FUTURE", "collection summary cannot precede its source histories")
    outstanding = sum((case.ledger.balance for case in cases if case.status in _OPEN_STATUSES), Decimal("0")).quantize(MONEY_QUANTUM)
    invoiced = sum((case.ledger.invoice_total for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)
    recovered = sum((case.ledger.recovered_amount for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)
    written_off = sum((case.ledger.write_off_amount for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)
    provision = sum((case.ledger.provision_amount for case in cases if case.status in _OPEN_STATUSES), Decimal("0")).quantize(MONEY_QUANTUM)
    promised = sum((case.ledger.balance for case in cases if case.status in _OPEN_STATUSES and case.ledger.promise_at), Decimal("0")).quantize(MONEY_QUANTUM)
    dso = None if invoiced <= 0 else (outstanding / invoiced * Decimal(period_days)).quantize(MONEY_QUANTUM)
    return {
        "as_of": at,
        "cases": len(cases),
        "by_status": {status: sum(1 for case in cases if case.status == status) for status in COLLECTIONS_STATUSES if any(case.status == status for case in cases)},
        "by_bucket": {bucket: str(sum((case.ledger.balance for case in cases if case.status in _OPEN_STATUSES and case.ledger.aging_bucket == bucket), Decimal("0")).quantize(MONEY_QUANTUM)) for bucket in ("current", *AGING_BUCKETS)},
        "invoiced": str(invoiced),
        "outstanding": str(outstanding),
        "promised_inflow": str(promised),
        "recovered": str(recovered),
        "written_off": str(written_off),
        "provision": str(provision),
        "period_days": period_days,
        "days_sales_outstanding": None if dso is None else str(dso),
    }


COLLECTIONS_CHAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": COLLECTIONS_CHAIN_KIND,
    "golden_loop": COLLECTIONS_CHAIN_GOLDEN_LOOP,
    "stages": ["open_receivable", "mark_due", "send_reminder", "record_promise", "apply_partial", "apply_payment", "escalate", "write_off"],
    "statuses": list(COLLECTIONS_STATUSES),
    "terminal": sorted(TERMINAL_COLLECTIONS_STATUSES),
    "events": list(COLLECTIONS_EVENTS),
    "hops": {
        "open_receivable": "a revenue_chain case in invoice_issued or a subscription_chain case in invoiced",
        "mark_due": f"an aged balance from {', '.join(AGING_TOOLS)}",
        "send_reminder": f"a bound ExecutionReceipt for an approved send ({', '.join(sorted(SEND_TOOLS))})",
        "record_promise": f"a governed communication thread ({', '.join(THREAD_TOOLS)}) plus an operator-recorded date and amount",
        "apply_partial": "quickbooks.observe_invoice_payment_applied APPLIED with a balance still open",
        "apply_payment": "the same observation with a zero invoice balance, also handed to revenue_chain.apply_payment",
        "raise_dispute": "the counterparty's own governed thread",
        "write_off": "an authority_matrix AuthorizationProof for write_off plus an observed credit note",
    },
    "read_lane": {
        "governed_reads": sorted(tool for tool in (*AGING_TOOLS, *CREDIT_NOTE_TOOLS, *THREAD_TOOLS) if tool in GOVERNED_CONNECTOR_READ_TOOLS),
        "missing_governed_reads": list(MISSING_GOVERNED_READS),
        "detail": "the aged receivable reports and both credit-note reads have no governed contract; they arrive through provenance_from_host_read",
    },
    "produces": {
        "revenue_chain": "apply_payment receipts on the same correlation, so one payment closes both chains",
        "company_treasury": "ScheduledFlow(kind='receivable') dated by the recorded promise",
        "finance_close": "bad-debt provision adjustment candidates and accounts_receivable reconciliation input",
        "exceptions_desk": f"overdue and disputed receivables (as {RECEIVABLE_OVERDUE_EXCEPTION_KIND} until receivable_overdue and disputed_invoice are registered)",
        "company_unit_economics": "days sales outstanding and the aged balance by bucket",
    },
    "required_connectors": ["xero", "quickbooks", "gmail", "microsoft", "twilio", "lightbulb.sdk_engine_state"],
    "rejection_codes": list(COLLECTIONS_CODES),
    "hard_rules": [
        "a rung advances on proof a message was sent, never on the intent to send one",
        "a promise is the customer's words plus a date an operator recorded, never an inference",
        "a write-off is an authorized decision matched by an observed credit note",
        "the forecast dates a receivable by the promise, not by the terms",
        "one payment observation closes this case and its revenue_chain parent; the cash is counted once",
    ],
}

__all__ = [
    "AGING_BUCKETS",
    "AGING_TOOLS",
    "COLLECTIONS_CHAIN_GOLDEN_LOOP",
    "COLLECTIONS_CHAIN_KIND",
    "COLLECTIONS_CHAIN_MANIFEST",
    "COLLECTIONS_CHAIN_PLAN_SCHEMA",
    "COLLECTIONS_CODES",
    "COLLECTIONS_EVENTS",
    "COLLECTIONS_LIFECYCLE",
    "COLLECTIONS_STATUSES",
    "CREDIT_NOTE_OBSERVATION_SCHEMA",
    "CREDIT_NOTE_TOOLS",
    "DEFAULT_LADDER",
    "DEFAULT_PROVISION_PERCENT",
    "DISPUTED_INVOICE_EXCEPTION_KIND",
    "INVOICE_SOURCES",
    "MAX_COLLECTIONS_TRANSITIONS",
    "MISSING_GOVERNED_READS",
    "RECEIVABLE_OVERDUE_EXCEPTION_KIND",
    "SEND_TOOLS",
    "TERMINAL_COLLECTIONS_STATUSES",
    "THREAD_TOOLS",
    "CollectionsChainError",
    "CollectionsChainPlan",
    "CollectionsEffectBoundary",
    "CollectionsLedger",
    "CollectionsReceipt",
    "CreditNoteObservation",
    "LadderStep",
    "ReceivableCaseState",
    "advance_receivable",
    "aging_bucket",
    "aging_receipt",
    "case_summary",
    "collections_summary",
    "compile_collections_chain",
    "credit_note_observation",
    "credit_note_receipt",
    "dispute_receipt",
    "dispute_resolution_receipt",
    "open_receivable",
    "open_receivable_receipt",
    "partial_receipt",
    "promise_receipt",
    "provision_rows",
    "receivable_exception",
    "receivable_flows",
    "recovery_receipt",
    "reminder_receipt",
    "revenue_chain_payment_receipt",
    "write_off_receipt",
    "verify_recovered_receivable",
]
