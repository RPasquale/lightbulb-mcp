"""The subscription chain: one replay-fenced lifecycle from a self-serve trial to recognized subscription revenue, dunning included.

The revenue chain opens on a pipeline hand-off and demands a signed
agreement, so a Stripe subscription had no path to cash at all: the SaaS
operating engine could observe usage and MRR and never prove a dollar of it,
and ``live_signal_observations.past_due_signals`` derived past-due rows that
no lifecycle consumed.  ``SUBSCRIPTION_CHAIN_LIFECYCLE`` is that path, with
the dunning arc as a recovery branch rather than a second lifecycle:

    trialing -> activated -> subscribed -> invoiced -> paid -> cash_settled
             -> revenue_recognized -> invoiced (the next billing cycle) ...
    invoiced | paid -> payment_failed -> retry_scheduled -> outreach_sent
             -> recovered -> cash_settled
    payment_failed | retry_scheduled | outreach_sent -> written_off  (terminal)
    trialing -> trial_lapsed; any billing status -> cancelled
             | reconciliation_required                              (terminal)

Every hop consumes the sealed artifact of the read that produced it.
``billing_rows`` and ``charge_rows`` seal one Stripe invoice or charge each,
carrying the ``ObservationProvenance`` of the read they came from, and the
builders parse those rows: ``trial_receipt`` matches the governed PostHog
event page against the sealed SaaS plan's activation policy,
``subscription_receipt`` prices the tier from that plan (MRR is the sealed
tier price times the seats on the line, never the invoice's own number),
``invoice_receipt`` / ``payment_receipt`` / ``failure_receipt`` /
``retry_receipt`` read the invoice and charge rows, ``settlement_receipt`` is
``revenue_chain.settlement_receipt`` verbatim, ``recognition_receipt``
consumes a closed finance period that reconciled the revenue subledger, and
``outreach_receipt`` consumes a bound write ``ExecutionReceipt`` plus a dated
consent record.

``RECOGNITION_BEFORE_SERVICE`` is what makes deferred revenue real rather
than a cash-basis lie: recognized revenue never exceeds the elapsed fraction
of the billing term the close covers.  ``period_evidence_receipt`` attributes
the settled cash to ``saas_operating_engine`` — the engine that earned it —
and ``hand_off_receipt`` opens the retention chain at renewal.  Nothing here
reads a provider, sends a message, or asks anyone to retry a charge.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
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
    Sha256Digest,
    ShortText,
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
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance
from lightbulb.revenue_chain import settlement_receipt as _revenue_settlement_receipt
from lightbulb.saas_operating_loop import SaasOperatingLoopPlan

SUBSCRIPTION_CHAIN_KIND = "subscription_chain"
SUBSCRIPTION_CHAIN_GOLDEN_LOOP = "saas.launched_product_to_compounding_revenue@0.1.0"
SUBSCRIPTION_CHAIN_PLAN_SCHEMA = "lightbulb.subscription_chain_plan.v1"
BILLING_ROW_SCHEMA = "lightbulb.subscription_billing_row.v1"
CHARGE_ROW_SCHEMA = "lightbulb.subscription_charge_row.v1"
POSTHOG_EVENT_PAGE_SCHEMA = "lightbulb.posthog_event_page.v1"
STRIPE_INVOICE_TOOLS = ("stripe.list_invoices", "host.stripe_invoices")
STRIPE_CHARGE_TOOLS = ("stripe.list_charges", "host.stripe_charges")
POSTHOG_USAGE_TOOLS = ("posthog.query_events", "host.posthog_usage")
OUTREACH_TOOLS = ("gmail.send_email", "microsoft.send_email")
MAX_SUBSCRIPTION_TRANSITIONS = 40
_HUNDRED = Decimal("100")

SUBSCRIPTION_STATUSES: tuple[str, ...] = ("trialing", "activated", "subscribed", "invoiced", "paid", "cash_settled", "revenue_recognized", "payment_failed", "retry_scheduled", "outreach_sent", "recovered", "trial_lapsed", "cancelled", "written_off", "reconciliation_required")
TERMINAL_SUBSCRIPTION_STATUSES: frozenset[str] = frozenset({"trial_lapsed", "cancelled", "written_off", "reconciliation_required"})
SUBSCRIPTION_EVENTS: tuple[str, ...] = ("start_trial", "record_activation", "subscribe", "issue_invoice", "apply_payment", "settle_cash", "recognize_revenue", "fail_payment", "schedule_retry", "send_outreach", "record_recovery", "lapse_trial", "cancel", "write_off", "require_reconciliation")
_SUBSCRIPTION_TABLE: dict[tuple[str, str], str] = {
    ("new", "start_trial"): "trialing",
    ("trialing", "record_activation"): "activated",
    ("trialing", "subscribe"): "subscribed",
    ("activated", "subscribe"): "subscribed",
    ("subscribed", "issue_invoice"): "invoiced",
    ("revenue_recognized", "issue_invoice"): "invoiced",
    ("invoiced", "apply_payment"): "paid",
    ("paid", "settle_cash"): "cash_settled",
    ("recovered", "settle_cash"): "cash_settled",
    ("cash_settled", "recognize_revenue"): "revenue_recognized",
    ("invoiced", "fail_payment"): "payment_failed",
    ("paid", "fail_payment"): "payment_failed",
    ("payment_failed", "schedule_retry"): "retry_scheduled",
    ("retry_scheduled", "schedule_retry"): "retry_scheduled",
    ("outreach_sent", "schedule_retry"): "retry_scheduled",
    ("retry_scheduled", "send_outreach"): "outreach_sent",
    ("outreach_sent", "send_outreach"): "outreach_sent",
    ("retry_scheduled", "record_recovery"): "recovered",
    ("outreach_sent", "record_recovery"): "recovered",
    ("trialing", "lapse_trial"): "trial_lapsed",
    **{(status, "write_off"): "written_off" for status in ("payment_failed", "retry_scheduled", "outreach_sent")},
    **{(status, "cancel"): "cancelled" for status in ("activated", "subscribed", "invoiced", "revenue_recognized")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("invoiced", "paid", "cash_settled", "payment_failed", "retry_scheduled", "outreach_sent")},
}


class RetryStep(StrictModel):
    attempt: int = Field(ge=1, le=10)
    day_offset: int = Field(ge=0, le=90)


class SubscriptionChainPlan(StrictModel):
    """What the chain enforces: the trial, how much an invoice may differ from the subscription's value, how revenue is recognized, and the dunning cadence."""

    schema_id: Literal["lightbulb.subscription_chain_plan.v1"] = Field(default=SUBSCRIPTION_CHAIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    saas_plan_digest: Sha256Digest
    trial_days: int = Field(default=14, ge=1, le=90)
    invoice_tolerance_percent: Decimal = Field(default=Decimal("2.00"), validate_default=True)
    min_reversal_window_days: int = Field(default=7, ge=1, le=180)
    recognition_method: Literal["ratable", "point_in_time"] = "ratable"
    retry_schedule: tuple[RetryStep, ...] = Field(default=({"attempt": 1, "day_offset": 1}, {"attempt": 2, "day_offset": 3}, {"attempt": 3, "day_offset": 7}), validate_default=True, min_length=1, max_length=10)  # type: ignore[assignment]
    min_hours_between_outreach: int = Field(default=48, ge=0, le=720)
    max_outreach: int = Field(default=3, ge=1, le=10)
    grace_days: int = Field(default=21, ge=0, le=180)
    require_consent_for_outreach: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("retry_schedule", mode="before")
    @classmethod
    def _schedule(cls, value: Any) -> Any:
        return tuple({"attempt": item[0], "day_offset": item[1]} if isinstance(item, (list, tuple)) else item for item in (value or ()))

    @field_validator("invoice_tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="invoice_tolerance_percent")
        if result > Decimal("25"):
            raise ValueError("invoice_tolerance_percent must be at most 25")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SubscriptionChainPlan:
        if [step.attempt for step in self.retry_schedule] != list(range(1, len(self.retry_schedule) + 1)):
            raise ValueError("retry attempts must be numbered 1..n in order")
        if any(later.day_offset < earlier.day_offset for earlier, later in zip(self.retry_schedule, self.retry_schedule[1:])):
            raise ValueError("retry day offsets must not decrease")
        if not skip_digests(info) and self.plan_digest != sealed_digest(SubscriptionChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_subscription_chain(company_ref: str, *, saas_plan: SaasOperatingLoopPlan | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> SubscriptionChainPlan:
    """The currency and the bound SaaS plan digest come from the sealed operating plan; the caller may override the windows only."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(saas_plan))
    raw = {"company_ref": company_ref, "currency": str(parsed_plan.blueprint.currency).upper(), "saas_plan_digest": parsed_plan.plan_digest, **dict(overrides or {})}
    raw.update(saas_plan_digest=parsed_plan.plan_digest, currency=parsed_plan.blueprint.currency)
    return seal(SubscriptionChainPlan, raw, "plan_digest")


class SubscriptionReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    entity_scope: EngineScope | None = None
    saas_source: dict[str, Any] | None = None
    usage_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    billing_source: dict[str, Any] | None = None
    charge_source: dict[str, Any] | None = None
    settlement_source: dict[str, Any] | None = None
    settlement_provenance: ObservationProvenance | None = None
    close_source: dict[str, Any] | None = None
    issuance_source: dict[str, Any] | None = None
    execution_request: dict[str, Any] | None = None
    execution_source: dict[str, Any] | None = None
    execution_output: dict[str, Any] | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    endpoint_digest: Sha256Digest | None = None
    account_ref: OpaqueRef | None = None
    usage_digest: Sha256Digest | None = None
    trial_started_at: str | None = None
    activation_events: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    required_events: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    activation_window_days: int | None = Field(default=None, ge=1, le=90)
    activated_at: str | None = None
    saas_plan_digest: Sha256Digest | None = None
    billing_digest: Sha256Digest | None = None
    plan_ref: ShortText | None = None
    seats: int | None = Field(default=None, ge=1, le=1_000_000)
    tier_monthly_price: Decimal | None = None
    mrr: Decimal | None = None
    term_months: int | None = Field(default=None, ge=1, le=60)
    currency: ShortText | None = None
    invoice_ref: OpaqueRef | None = None
    invoice_total: Decimal | None = None
    invoice_status: ShortText | None = None
    issued_at: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    issuance_evidence_sha256: Sha256Digest | None = None
    applied_amount: Decimal | None = None
    applied_at: str | None = None
    correlation_sha256: Sha256Digest | None = None
    settlement_evidence_sha256: Sha256Digest | None = None
    settled_amount: Decimal | None = None
    reversal_window_days: int | None = Field(default=None, ge=1, le=180)
    payout_arrival_at: str | None = None
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    close_period_end: str | None = None
    decline_code: ShortText | None = None
    failed_at: str | None = None
    charge_digest: Sha256Digest | None = None
    outstanding_amount: Decimal | None = None
    attempt: int | None = Field(default=None, ge=1, le=10)
    attempted_at: str | None = None
    offset_days: int | None = Field(default=None, ge=0, le=365)
    touch_ref: OpaqueRef | None = None
    channel: ShortText | None = None
    sent_at: str | None = None
    approval_ref: OpaqueRef | None = None
    approval_receipt_digest: Sha256Digest | None = None
    execution_digest: Sha256Digest | None = None
    consent_ref: OpaqueRef | None = None
    consent_status: ShortText | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "activation_events", "required_events", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("tier_monthly_price", "mrr", "invoice_total", "applied_amount", "settled_amount", "outstanding_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("trial_started_at", "activated_at", "issued_at", "period_start", "period_end", "applied_at", "payout_arrival_at", "close_period_end", "failed_at", "attempted_at", "sent_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class SubscriptionLedger(StrictModel):
    entity_scope: EngineScope | None = None
    requester_ref: OpaqueRef | None = None
    endpoint_digest: Sha256Digest | None = None
    authorization_proof_digest: Sha256Digest | None = None
    billed_invoice_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    settlement_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=40)
    settlement_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    account_ref: str | None = None
    usage_ref: str | None = None
    plan_ref: str | None = None
    seats: int = Field(default=0, ge=0)
    trial_started_at: str | None = None
    usage_digest: str | None = None
    activation_events: tuple[str, ...] = Field(default_factory=tuple)
    activated_at: str | None = None
    mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    term_months: int = Field(default=0, ge=0)
    billing_cycles: int = Field(default=0, ge=0)
    period_start: str | None = None
    period_end: str | None = None
    invoice_ref: str | None = None
    invoice_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    issued_at: str | None = None
    applied_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    applied_at: str | None = None
    settled_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    settled_at: str | None = None
    cash_settled_to_date: Decimal = Field(default=Decimal("0"), validate_default=True)
    recognized_to_date: Decimal = Field(default=Decimal("0"), validate_default=True)
    deferred_balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    decline_code: str | None = None
    failed_at: str | None = None
    outstanding_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    retry_attempts: int = Field(default=0, ge=0)
    retry_charge_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=10)
    retry_charge_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=40)
    last_retry_at: str | None = None
    last_outreach_at: str | None = None
    outreach_count: int = Field(default=0, ge=0)
    recovered_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    written_off_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    days_trial_to_cash: int | None = None
    lapse_reason: str | None = None
    cancel_reason: str | None = None
    write_off_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "recognized", "trial_lapsed", "cancelled", "written_off", "reconciliation_required"] = "open"

    @field_validator("activation_events", "retry_charge_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("mrr", "invoice_total", "applied_amount", "settled_amount", "cash_settled_to_date", "recognized_to_date", "deferred_balance", "outstanding_amount", "recovered_amount", "written_off_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class SubscriptionEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    invoice_created: Literal[False] = False
    payment_collected: Literal[False] = False
    charge_retried: Literal[False] = False
    message_sent: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _days(start: str | None, end: str) -> int:
    return 0 if not start else (parsed(end) - parsed(start)).days


def _hours(start: str, end: str) -> int:
    return int((parsed(end) - parsed(start)).total_seconds() // 3600)


def _within(value: Decimal, reference: Decimal, tolerance_percent: Decimal) -> bool:
    if reference <= 0:
        return value == reference
    return (value - reference).copy_abs() <= (reference * tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)


def _money_of(data: Mapping[str, Any], key: str) -> Decimal:
    return Decimal(str(data.get(key, "0") or "0"))


def _earned(settled: Decimal, period_start: str, period_end: str, through: str) -> tuple[Decimal, int, int]:
    """The ratable ceiling: the fraction of the billing term elapsed at ``through``, of the cash settled for it."""

    term_days = max((parsed(period_end) - parsed(period_start)).days, 0)
    elapsed = min(max((parsed(through) - parsed(period_start)).days, 0), term_days)
    if term_days == 0:
        return settled, 0, 0
    return (settled * Decimal(elapsed) / Decimal(term_days)).quantize(MONEY_QUANTUM), elapsed, term_days


def _apply_subscription(plan: SubscriptionChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "start_trial":
        require(r.entity_scope is not None and r.entity_scope.currency == plan.currency, "SCOPE_MISMATCH", "the subscription must bind its opening execution scope and currency")
        data.update(entity_scope=r.entity_scope.to_dict(), requester_ref=command.actor_ref)
        require(r.account_ref is not None and r.trial_started_at is not None and r.usage_digest is not None, "TRIAL_MISSING", "a trial names the account, when it started, and the usage observation digest")
        require(r.saas_plan_digest == plan.saas_plan_digest, "SAAS_PLAN_MISMATCH", "the trial's activation policy came from a different sealed SaaS operating plan", "manual_reconciliation")
        data.update({"account_ref": r.account_ref, "usage_ref": r.account_ref, "trial_started_at": r.trial_started_at, "usage_digest": r.usage_digest})
    elif event == "record_activation":
        require(r.usage_digest is not None and len(r.required_events) >= 1, "ACTIVATION_MISSING", "an activation names the plan's required events, when the last of them landed, and the usage digest")
        require(r.saas_plan_digest == plan.saas_plan_digest, "SAAS_PLAN_MISMATCH", "the required events came from a different sealed SaaS operating plan", "manual_reconciliation")
        missing = [name for name in r.required_events if name not in r.activation_events]
        require(not missing, "ACTIVATION_EVENTS_INCOMPLETE", f"the SaaS plan requires {list(r.required_events)} inside {r.activation_window_days} day(s); {missing} were not observed")
        require(r.activated_at is not None, "ACTIVATION_MISSING", "an activation names when the last required event landed")
        require(_days(data.get("trial_started_at"), r.activated_at) <= plan.trial_days, "TRIAL_WINDOW_EXPIRED", f"activation landed more than {plan.trial_days} days after the trial started; lapse the trial instead")
        data.update({"activation_events": tuple(r.activation_events), "activated_at": r.activated_at, "usage_digest": r.usage_digest})
    elif event == "subscribe":
        data["endpoint_digest"] = r.endpoint_digest
        require(r.account_ref is not None and r.plan_ref is not None and r.seats is not None and r.term_months is not None and r.billing_digest is not None and r.saas_plan_digest is not None, "SUBSCRIPTION_MISSING", "a subscription names the billing account, the tier, the seats, the term, the billing row digest, and the SaaS plan it was priced from")
        require(r.saas_plan_digest == plan.saas_plan_digest, "SAAS_PLAN_MISMATCH", "the tier was priced from a different SaaS operating plan", "manual_reconciliation")
        require(r.tier_monthly_price is not None, "PLAN_REF_UNKNOWN", f"{r.plan_ref} is not a priced tier on the bound SaaS plan")
        require(r.mrr is not None and r.mrr == (r.tier_monthly_price * r.seats).quantize(MONEY_QUANTUM), "MRR_NOT_TIER_PRICE", f"MRR is the sealed tier price {r.tier_monthly_price} times {r.seats} seat(s), never the invoice's own number", "manual_reconciliation")
        require(_days(data.get("trial_started_at"), at) <= plan.trial_days, "TRIAL_WINDOW_EXPIRED", f"the subscription starts more than {plan.trial_days} days after the trial started")
        data.update({"account_ref": r.account_ref, "plan_ref": r.plan_ref, "seats": r.seats, "mrr": str(r.mrr), "term_months": r.term_months})
    elif event == "issue_invoice":
        require(r.invoice_ref not in data.get("billed_invoice_refs", ()), "INVOICE_ALREADY_BILLED", "an invoice can enter this subscription once", "do_not_replay")
        require(not data.get("billing_cycles") or r.period_start is None or parsed(r.period_start) >= parsed(data["period_end"]), "BILLING_TERM_OVERLAP", "a later billing cycle must start after the previous billed term")
        data["billed_invoice_refs"] = [*data.get("billed_invoice_refs", ()), r.invoice_ref] if r.invoice_ref else data.get("billed_invoice_refs", ())
        require(r.invoice_ref is not None and r.invoice_total is not None and r.issued_at is not None and r.period_start is not None and r.period_end is not None and r.billing_digest is not None and r.term_months is not None and r.account_ref is not None and r.plan_ref is not None, "INVOICE_MISSING", "an invoice names its ref, total, issue time, billing period, term, billing account, tier, and the billing row digest")
        require((r.account_ref, r.plan_ref) == (data.get("account_ref"), data.get("plan_ref")), "INVOICE_CORRELATION_MISMATCH", f"the invoice bills {r.account_ref} on {r.plan_ref}; the case subscribed {data.get('account_ref')} on {data.get('plan_ref')}", "manual_reconciliation")
        expected = (_money_of(data, "mrr") * r.term_months).quantize(MONEY_QUANTUM)
        require(_within(r.invoice_total, expected, plan.invoice_tolerance_percent), "INVOICE_NOT_SUBSCRIPTION_VALUE", f"invoice total {r.invoice_total} differs from the subscription value {expected} ({r.term_months} month(s) of MRR) by more than {plan.invoice_tolerance_percent}%", "manual_reconciliation")
        data.update({"invoice_ref": r.invoice_ref, "invoice_total": str(r.invoice_total), "issued_at": r.issued_at, "period_start": r.period_start, "period_end": r.period_end, "term_months": r.term_months, "billing_cycles": int(data.get("billing_cycles", 0)) + 1, "outcome": "open", "applied_amount": None, "applied_at": None, "settled_amount": None, "settled_at": None, "decline_code": None, "failed_at": None, "outstanding_amount": None, "retry_attempts": None, "retry_charge_digests": None, "last_retry_at": None, "last_outreach_at": None, "outreach_count": None, "recovered_amount": None})
    elif event == "apply_payment":
        require(r.invoice_ref is not None and r.applied_amount is not None and r.applied_at is not None and r.billing_digest is not None, "PAYMENT_MISSING", "an applied payment names the invoice, the amount, the time, and the billing row digest")
        require(r.invoice_ref == data.get("invoice_ref"), "PAYMENT_CORRELATION_MISMATCH", f"the payment is for invoice {r.invoice_ref}, the case is on {data.get('invoice_ref')}", "manual_reconciliation")
        require(r.applied_amount == _money_of(data, "invoice_total"), "PAYMENT_NOT_FULL", f"applied {r.applied_amount} does not settle the invoice total {data.get('invoice_total')}", "manual_reconciliation")
        data.update({"applied_amount": str(r.applied_amount), "applied_at": r.applied_at})
    elif event == "settle_cash":
        require(r.settled_amount is not None and r.settlement_evidence_sha256 is not None and r.reversal_window_days is not None and r.payout_arrival_at is not None, "SETTLEMENT_MISSING", "a settlement names its evidence, amount, reversal window, and payout arrival")
        expected = _money_of(data, "recovered_amount") if status == "recovered" else _money_of(data, "applied_amount")
        require(r.settled_amount == expected, "SETTLEMENT_AMOUNT_MISMATCH", f"settled {r.settled_amount} differs from the {'recovered' if status == 'recovered' else 'applied'} amount {expected}", "manual_reconciliation")
        require(r.reversal_window_days >= plan.min_reversal_window_days, "REVERSAL_WINDOW_SHORT", f"the reversal window observed ({r.reversal_window_days}d) is shorter than the plan's {plan.min_reversal_window_days}d", "manual_reconciliation")
        require(parsed(r.payout_arrival_at) <= parsed(at), "PAYOUT_IN_FUTURE", "a payout that has not arrived cannot settle cash")
        cash = (_money_of(data, "cash_settled_to_date") + r.settled_amount).quantize(MONEY_QUANTUM)
        data.update({"settled_amount": str(r.settled_amount), "settled_at": at, "cash_settled_to_date": str(cash), "deferred_balance": str(cash - _money_of(data, "recognized_to_date"))})
        if data.get("days_trial_to_cash") is None:
            data["days_trial_to_cash"] = _days(data.get("trial_started_at"), at)
    elif event == "recognize_revenue":
        require(r.close_ref is not None and r.close_state_digest is not None and r.close_period_end is not None, "RECOGNITION_WITHOUT_CLOSE", "recognition consumes a closed finance period that reconciled the revenue subledger")
        require(parsed(r.close_period_end) >= parsed(str(data.get("settled_at"))), "CLOSE_BEFORE_SETTLEMENT", "the close must cover the settlement date", "manual_reconciliation")
        settled = _money_of(data, "settled_amount")
        ceiling, elapsed, term_days = _earned(settled, str(data["period_start"]), str(data["period_end"]), r.close_period_end)
        recognized = settled if plan.recognition_method == "point_in_time" else ceiling
        require(recognized <= ceiling, "RECOGNITION_BEFORE_SERVICE", f"{recognized} of a {term_days}-day term may not be recognized {elapsed} day(s) in; the service earned {ceiling}")
        to_date = (_money_of(data, "recognized_to_date") + recognized).quantize(MONEY_QUANTUM)
        data.update({"recognized_to_date": str(to_date), "deferred_balance": str(_money_of(data, "cash_settled_to_date") - to_date), "outcome": "recognized"})
    elif event == "fail_payment":
        require(r.decline_code is not None and r.failed_at is not None and r.charge_digest is not None and r.invoice_ref is not None and r.outstanding_amount is not None, "FAILURE_MISSING", "a failed payment names the invoice, the decline code, the charge digest, the time, and what is outstanding")
        require(r.invoice_ref == data.get("invoice_ref"), "PAYMENT_CORRELATION_MISMATCH", f"the failed charge is for invoice {r.invoice_ref}, the case is on {data.get('invoice_ref')}", "manual_reconciliation")
        data.update({"decline_code": r.decline_code, "failed_at": r.failed_at, "outstanding_amount": str(r.outstanding_amount)})
    elif event == "schedule_retry":
        require(r.attempted_at is not None and r.charge_digest is not None, "RETRY_MISSING", "a retry names the observed charge and when it was attempted")
        seen = tuple(str(item) for item in (data.get("retry_charge_digests") or ()))
        require(r.charge_digest not in seen, "RETRY_CHARGE_REPLAYED", "this charge already counted as a scheduled attempt; each attempt is a distinct observed charge", "manual_reconciliation")
        attempt = int(data.get("retry_attempts", 0)) + 1
        require(attempt <= len(plan.retry_schedule), "RETRY_SCHEDULE_EXHAUSTED", f"the plan schedules {len(plan.retry_schedule)} attempt(s); attempt {attempt} is past the schedule", "manual_reconciliation")
        offset = _days(data.get("failed_at"), r.attempted_at)
        require(offset >= plan.retry_schedule[attempt - 1].day_offset, "RETRY_TOO_SOON", f"attempt {attempt} was observed {offset} day(s) after the failure; the plan schedules it at {plan.retry_schedule[attempt - 1].day_offset} day(s)")
        data.update({"retry_attempts": attempt, "retry_charge_digests": [*seen, r.charge_digest], "last_retry_at": r.attempted_at, "decline_code": r.decline_code or data.get("decline_code")})
    elif event == "send_outreach":
        require(r.touch_ref is not None and r.channel is not None and r.sent_at is not None and r.execution_digest is not None, "OUTREACH_MISSING", "an outreach names the touch, the channel, when it was sent, and the execution digest")
        require(not plan.require_consent_for_outreach or (r.consent_ref is not None and r.consent_status in ("express", "implied")), "OUTREACH_WITHOUT_CONSENT", f"this plan sends no dunning message without a dated consent record on an express or implied basis; this receipt carries {r.consent_status or 'no basis'}")
        require(r.approval_ref is not None and r.approval_receipt_digest is not None, "OUTREACH_NOT_APPROVED", "a dunning message needs a bound approval before it is sent", "await_approval")
        count = int(data.get("outreach_count", 0))
        require(count < plan.max_outreach, "OUTREACH_CADENCE_VIOLATED", f"the plan allows {plan.max_outreach} dunning message(s) per failure")
        last = data.get("last_outreach_at")
        require(last is None or _hours(str(last), r.sent_at) >= plan.min_hours_between_outreach, "OUTREACH_CADENCE_VIOLATED", f"the plan leaves {plan.min_hours_between_outreach}h between dunning messages")
        data.update({"outreach_count": count + 1, "last_outreach_at": r.sent_at})
    elif event == "record_recovery":
        require(r.invoice_ref is not None and r.applied_amount is not None and r.applied_at is not None and r.billing_digest is not None, "RECOVERY_MISSING", "a recovery names the invoice, the amount recovered, the time, and the billing row digest")
        require(r.invoice_ref == data.get("invoice_ref"), "PAYMENT_CORRELATION_MISMATCH", f"the recovery is for invoice {r.invoice_ref}, the case is on {data.get('invoice_ref')}", "manual_reconciliation")
        outstanding = _money_of(data, "outstanding_amount") or _money_of(data, "invoice_total")
        require(r.applied_amount == outstanding, "RECOVERY_AMOUNT_MISMATCH", f"recovered {r.applied_amount} does not clear the outstanding {outstanding}", "manual_reconciliation")
        data.update({"recovered_amount": str(r.applied_amount), "applied_amount": str(r.applied_amount), "applied_at": r.applied_at})
    elif event == "write_off":
        exhausted = int(data.get("retry_attempts", 0)) >= len(plan.retry_schedule)
        overdue = _days(data.get("failed_at"), at) > plan.grace_days
        require(exhausted or overdue, "WRITE_OFF_BEFORE_SCHEDULE_EXHAUSTED", f"{data.get('retry_attempts', 0)} of {len(plan.retry_schedule)} scheduled retries are observed and the {plan.grace_days}-day grace has not elapsed")
        from lightbulb.authority_matrix import require_authorization_proof
        require(r.authorization_proof is not None, "APPROVAL_NOT_BOUND", "write-off requires an independently bound decision for this exact outstanding amount", "await_approval")
        proof = require_authorization_proof(r.authorization_proof, category="write_off", amount=_money_of(data, "outstanding_amount") or _money_of(data, "invoice_total"), currency=plan.currency, company_ref=plan.company_ref, plan_digest=plan.plan_digest, entity_ref=data["entity_scope"]["entity_ref"], requester_ref=data["requester_ref"], command=command)
        data["authorization_proof_digest"] = proof.proof_digest
        data.update({"written_off_amount": str(_money_of(data, "outstanding_amount") or _money_of(data, "invoice_total")), "write_off_reason": str(command.reason)[:300], "outcome": "written_off"})
    elif event == "lapse_trial":
        data.update({"lapse_reason": str(command.reason)[:300], "outcome": "trial_lapsed"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    try:
        _verify_subscription_sources(plan, data, command)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, getattr(exc, "code", "SOURCE_NOT_SEALED"), str(exc))
    return next_status, data


class _SubscriptionLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope)}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope.to_dict() != self.ledger.entity_scope.to_dict():
                    raise ValueError("SCOPE_MISMATCH: subscription state must equal its replayed opening scope")
                return self
        self.State = ScopedState


SUBSCRIPTION_CHAIN_LIFECYCLE = _SubscriptionLifecycle(entity="subscription_case", schema_prefix=SUBSCRIPTION_CHAIN_KIND, statuses=SUBSCRIPTION_STATUSES, terminal=TERMINAL_SUBSCRIPTION_STATUSES, events=SUBSCRIPTION_EVENTS, table=_SUBSCRIPTION_TABLE, opening_event="start_trial", reason_events=("lapse_trial", "cancel", "write_off", "require_reconciliation"), apply=_apply_subscription, ledger_model=SubscriptionLedger, receipt_model=SubscriptionReceipt, effect_boundary_model=SubscriptionEffectBoundary, plan_model=SubscriptionChainPlan, max_transitions=MAX_SUBSCRIPTION_TRANSITIONS)
SubscriptionCaseState = SUBSCRIPTION_CHAIN_LIFECYCLE.State


def open_subscription_case(plan: SubscriptionChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return SUBSCRIPTION_CHAIN_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_subscription_case(plan: SubscriptionChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return SUBSCRIPTION_CHAIN_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# The sealed provider rows the hops are built from
# --------------------------------------------------------------------------- #


class SubscriptionChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SubscriptionChainError(code, message)


def _stamp(value: Any, *, field_name: str) -> str:
    if isinstance(value, str):
        return timestamp(value, field_name=field_name)
    return iso(datetime.fromtimestamp(int(value), tz=timezone.utc).replace(microsecond=0))


def _minor(value: Any, *, field_name: str) -> Decimal:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "PROVIDER_AMOUNT_INVALID", f"{field_name} must be nonnegative integer minor units")
    return (Decimal(value) / _HUNDRED).quantize(MONEY_QUANTUM)


def _term_months(period_start: str, period_end: str) -> int:
    days = max((parsed(period_end) - parsed(period_start)).days, 1)
    return max(1, min(60, int(Decimal(days) / Decimal(30) + Decimal("0.5"))))


class BillingRow(StrictModel):
    """One Stripe invoice, normalized and sealed with the provenance of the read it came from."""

    schema_id: Literal["lightbulb.subscription_billing_row.v1"] = Field(default=BILLING_ROW_SCHEMA, alias="schema")
    source_provenance: ObservationProvenance
    source_payload: dict[str, Any] | tuple[dict[str, Any], ...]
    usage_ref: OpaqueRef | None = None
    endpoint_digest: Sha256Digest | None = None
    account_ref: OpaqueRef
    invoice_ref: OpaqueRef
    plan_ref: ShortText
    seats: int = Field(ge=1, le=1_000_000)
    currency: ShortText
    status: ShortText
    amount_due: Decimal
    amount_paid: Decimal
    created_at: str
    paid_at: str | None = None
    period_start: str
    period_end: str
    source_tool: ShortText
    provenance_digest: Sha256Digest
    observed_at: str
    row_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount_due", "amount_paid", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> BillingRow:
        if not skip_digests(info) and self.row_digest != sealed_digest(BillingRow, self, "row_digest"):
            raise ValueError("row_digest must commit the exact billing row")
        _verify_provider_row(self, billing_rows, "invoice_ref")
        return self


class ChargeRow(StrictModel):
    """One Stripe charge, normalized and sealed with the provenance of the read it came from."""

    schema_id: Literal["lightbulb.subscription_charge_row.v1"] = Field(default=CHARGE_ROW_SCHEMA, alias="schema")
    source_provenance: ObservationProvenance
    source_payload: dict[str, Any] | tuple[dict[str, Any], ...]
    charge_ref: OpaqueRef
    invoice_ref: OpaqueRef | None = None
    status: ShortText
    amount: Decimal
    currency: ShortText
    created_at: str
    failure_code: ShortText | None = None
    failure_detail: BoundedText | None = None
    source_tool: ShortText
    provenance_digest: Sha256Digest
    observed_at: str
    row_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ChargeRow:
        if not skip_digests(info) and self.row_digest != sealed_digest(ChargeRow, self, "row_digest"):
            raise ValueError("row_digest must commit the exact charge row")
        _verify_provider_row(self, charge_rows, "charge_ref")
        return self


def _provenance(provenance: ObservationProvenance | Mapping[str, Any], *tools: str) -> ObservationProvenance:
    parsed_provenance = ObservationProvenance.model_validate(detached(provenance))
    _require(parsed_provenance.schema_id == "lightbulb.engine_observation_provenance.v1" and parsed_provenance.provenance_digest != GENESIS_DIGEST, "SOURCE_NOT_SEALED", "the read requires real sealed observation provenance")
    _require(parsed_provenance.source_tool in tools, "OBSERVATION_TOOL_MISMATCH", f"this adapter reads {list(tools)}; the provenance names {parsed_provenance.source_tool}")
    return parsed_provenance


def _rows(payload: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = payload.get("data") if isinstance(payload, Mapping) else payload
    _require(isinstance(rows, Sequence) and not isinstance(rows, str), "PROVIDER_PAGE_INCONSISTENT", "the page arrives as a list (or {data: [...]})")
    return [dict(detached(item)) for item in rows]  # type: ignore[union-attr]


def _private_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require(str(key).lower() not in {"email", "customer_email", "customer_name", "phone", "customer_phone", "billing_details", "shipping", "tax_id", "address", "card_number"} or item in (None, "", {}), "SOURCE_PRIVACY_VIOLATION", "provider evidence must omit raw contact, payment and identity details")
            _private_fields(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _private_fields(item)


def _source_scope(payload: Any, scope: Any, company_ref: str, currency: str) -> None:
    if not isinstance(payload, Mapping):
        return
    _require(payload.get("company_ref", company_ref) == company_ref and str(payload.get("currency", currency)).upper() == currency, "SCOPE_MISMATCH", "provider evidence names another company or currency")
    if payload.get("scope") is not None:
        _require(_same_scope(payload["scope"], scope), "SCOPE_MISMATCH", "provider evidence names another authenticated scope")


def billing_rows(provenance: ObservationProvenance | Mapping[str, Any], invoices: Sequence[Mapping[str, Any]] | Mapping[str, Any], *, currency: str, _derive_only: bool = False) -> tuple[dict[str, Any], ...]:
    """Seal one ``BillingRow`` per subscription invoice on the ``stripe.list_invoices`` page the read returned."""

    parsed_provenance = _provenance(provenance, *STRIPE_INVOICE_TOOLS)
    _private_fields(invoices)
    _require(stable_digest(detached(invoices)) == parsed_provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "the invoice page must be the exact output committed by its read")
    _require(not isinstance(invoices, Mapping) or invoices.get("has_more") is not True, "PROVIDER_PAGE_INCONSISTENT", "finish the invoice page before deriving subscription evidence")
    out: list[dict[str, Any]] = []
    for item in _rows(invoices):
        _require(str(item.get("currency", "")).upper() == currency.upper(), "BILLING_CURRENCY_MISMATCH", f"invoice {item.get('id')} is in {item.get('currency')}, the chain runs in {currency}")
        customer = item.get("customer")
        account_ref = str(customer.get("id") if isinstance(customer, Mapping) else customer or "")
        _require(bool(account_ref) and bool(item.get("id")), "BILLING_ROW_INCOMPLETE", "each invoice names its id and its customer")
        lines = ((item.get("lines") or {}).get("data") or []) if isinstance(item.get("lines"), Mapping) else []
        _require((item.get("lines") or {}).get("has_more") is not True and sum(bool((line.get("price") or {}).get("recurring")) for line in lines) == 1, "BILLING_ROW_INCOMPLETE", "subscription evidence needs one unambiguous recurring line and its complete page")
        plan_ref, seats, period = "", 1, {}
        for line in lines:
            price = (line or {}).get("price") or {}
            if not price.get("recurring"):
                continue
            plan_ref = str(price.get("nickname") or price.get("lookup_key") or price.get("id") or plan_ref)
            seats = (line or {}).get("quantity", 1)
            _require(isinstance(seats, int) and not isinstance(seats, bool) and seats >= 1, "BILLING_ROW_INCOMPLETE", "seats must be a positive integer")
            period = (line or {}).get("period") or {}
        _require(bool(plan_ref), "BILLING_ROW_INCOMPLETE", f"invoice {item.get('id')} carries no recurring subscription line")
        start, end = period.get("start", item.get("period_start")), period.get("end", item.get("period_end"))
        _require(start is not None and end is not None, "BILLING_ROW_INCOMPLETE", f"invoice {item.get('id')} carries no billing period")
        _require(parsed(_stamp(start, field_name="period_start")) < parsed(_stamp(end, field_name="period_end")), "BILLING_ROW_INCOMPLETE", "the recurring invoice term must have positive duration")
        transitions = item.get("status_transitions") or {}
        paid_at = transitions.get("paid_at") if isinstance(transitions, Mapping) else None
        payload = {
            "usage_ref": (item.get("metadata") or {}).get("usage_ref"), "endpoint_digest": (item.get("metadata") or {}).get("endpoint_digest"),
            "account_ref": account_ref, "invoice_ref": str(item["id"]), "plan_ref": plan_ref, "seats": seats, "currency": currency.upper(), "status": str(item.get("status", "")).lower(),
            "amount_due": str(_minor(item.get("amount_due"), field_name="amount_due")), "amount_paid": str(_minor(item.get("amount_paid"), field_name="amount_paid")),
            "created_at": _stamp(item.get("created"), field_name="created"), "paid_at": None if paid_at is None else _stamp(paid_at, field_name="paid_at"),
            "period_start": _stamp(start, field_name="period_start"), "period_end": _stamp(end, field_name="period_end"),
            "source_tool": parsed_provenance.source_tool, "provenance_digest": parsed_provenance.provenance_digest, "observed_at": parsed_provenance.observed_through,
        }
        out.append(payload if _derive_only else seal(BillingRow, {**payload, "source_provenance": parsed_provenance.to_dict(), "source_payload": detached(invoices)}, "row_digest").to_dict())
    return tuple(out)


def charge_rows(provenance: ObservationProvenance | Mapping[str, Any], charges: Sequence[Mapping[str, Any]] | Mapping[str, Any], *, currency: str, _derive_only: bool = False) -> tuple[dict[str, Any], ...]:
    """Seal one ``ChargeRow`` per charge on the ``stripe.list_charges`` page; this is the read that carries the decline code."""

    parsed_provenance = _provenance(provenance, *STRIPE_CHARGE_TOOLS)
    _private_fields(charges)
    _require(stable_digest(detached(charges)) == parsed_provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "the charge page must be the exact output committed by its read")
    _require(not isinstance(charges, Mapping) or charges.get("has_more") is not True, "PROVIDER_PAGE_INCONSISTENT", "finish the charge page before deriving retry evidence")
    out: list[dict[str, Any]] = []
    for item in _rows(charges):
        _require(str(item.get("currency", "")).upper() == currency.upper(), "BILLING_CURRENCY_MISMATCH", f"charge {item.get('id')} is in {item.get('currency')}, the chain runs in {currency}")
        _require(bool(item.get("id")), "CHARGE_ROW_INCOMPLETE", "each charge names its id")
        invoice = item.get("invoice")
        payload = {
            "charge_ref": str(item["id"]), "invoice_ref": None if invoice is None else str(invoice.get("id") if isinstance(invoice, Mapping) else invoice), "status": str(item.get("status", "")).lower(),
            "amount": str(_minor(item.get("amount"), field_name="amount")), "currency": currency.upper(), "created_at": _stamp(item.get("created"), field_name="created"),
            "failure_code": None if item.get("failure_code") is None else str(item["failure_code"])[:300], "failure_detail": None if item.get("failure_message") is None else str(item["failure_message"])[:4000],
            "source_tool": parsed_provenance.source_tool, "provenance_digest": parsed_provenance.provenance_digest, "observed_at": parsed_provenance.observed_through,
        }
        out.append(payload if _derive_only else seal(ChargeRow, {**payload, "source_provenance": parsed_provenance.to_dict(), "source_payload": detached(charges)}, "row_digest").to_dict())
    return tuple(out)


def _verify_provider_row(row: Any, builder: Any, identity: str) -> None:
    rows = builder(row.source_provenance, detached(row.source_payload), currency=row.currency, _derive_only=True)
    matched = [item for item in rows if item[identity] == getattr(row, identity)]
    _require(len(matched) == 1, "PROVIDER_PAGE_INCONSISTENT", "one source page identifies each invoice or charge once")
    actual = row.to_dict()
    _require(all(actual.get(key) == value for key, value in matched[0].items()), "SOURCE_PROJECTION_MISMATCH", "normalized provider values must rederive from their complete retained source page")


def _billing_row(row: Mapping[str, Any] | Any) -> BillingRow:
    _require(isinstance(detached(row), Mapping), "BILLING_ROW_SCHEMA_MISMATCH", "billing evidence must retain a sealed row")
    raw = dict(detached(row))
    _require(raw.get("schema") == BILLING_ROW_SCHEMA, "BILLING_ROW_SCHEMA_MISMATCH", "expected a sealed subscription billing row from billing_rows()")
    return BillingRow.model_validate(raw)


def _charge_row(row: Mapping[str, Any] | Any) -> ChargeRow:
    _require(isinstance(detached(row), Mapping), "CHARGE_ROW_SCHEMA_MISMATCH", "charge evidence must retain a sealed row")
    raw = dict(detached(row))
    _require(raw.get("schema") == CHARGE_ROW_SCHEMA, "CHARGE_ROW_SCHEMA_MISMATCH", "expected a sealed subscription charge row from charge_rows()")
    return ChargeRow.model_validate(raw)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def trial_receipt(usage_observation: Mapping[str, Any] | Sequence[Mapping[str, Any]], saas_plan: SaasOperatingLoopPlan | Mapping[str, Any], *, provenances: Sequence[Any] = (), account_ref: str | None = None, trial_started_at: str | None = None) -> dict[str, Any]:
    """From the governed ``posthog.query_events`` page(s): the account's activation events, matched against the sealed SaaS plan's activation policy.

    The governed page carries one event name and hashed identities, so the
    account is the ``distinct_id_sha256`` the contract already hashed and one
    page is supplied per required event.
    """

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(saas_plan))
    pages = [dict(detached(page)) for page in (usage_observation if isinstance(usage_observation, Sequence) and not isinstance(usage_observation, (str, Mapping)) else [usage_observation])]
    observed: list[tuple[str, str]] = []
    identities: set[str] = set()
    _require(len(provenances) == len(pages), "SOURCE_NOT_SEALED", "each usage page retains its actual governed read provenance")
    sources = []
    for page, source in zip(pages, provenances):
        _require(page.get("schema") == POSTHOG_EVENT_PAGE_SCHEMA, "USAGE_PAGE_SCHEMA_MISMATCH", "expected a governed PostHog event page")
        provenance = _provenance(source, *POSTHOG_USAGE_TOOLS)
        _require(stable_digest(page) == provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", "usage events must be the read's exact output")
        _require(page.get("has_more") is False and page.get("record_count") == len(page.get("events") or []), "PROVIDER_PAGE_INCONSISTENT", "usage evidence must retain complete counted pages")
        sources.append({"provenance": provenance.to_dict(), "payload": page})
        for item in page.get("events") or []:
            row = dict(detached(item))
            identity = str(row.get("distinct_id_sha256") or "")
            _require(len(identity) == 64 and all(char in "0123456789abcdef" for char in identity) and identity != GENESIS_DIGEST, "USAGE_IDENTITY_MISSING", "the governed page hashes each identity; a row without one is not evidence")
            identities.add(identity)
            if account_ref is None or identity == account_ref:
                _require(parsed(timestamp(str(row["timestamp"]), field_name="timestamp")) <= parsed(provenance.completed_at), "SOURCE_FROM_FUTURE", "usage cannot postdate the completed read")
                observed.append((str(row.get("event") or page.get("event") or ""), timestamp(str(row["timestamp"]), field_name="timestamp")))
    ref = account_ref or (next(iter(identities)) if len(identities) == 1 else None)
    _require(ref is not None, "ACCOUNT_NOT_OBSERVED", "name the account_ref; the pages carry more than one identity")
    _require(bool(observed), "ACCOUNT_NOT_OBSERVED", f"{ref} has no events on the governed page(s)")
    earliest = min(stamp for _, stamp in observed)
    started = timestamp(trial_started_at, field_name="trial_started_at") if trial_started_at else earliest
    _require(parsed(started) <= parsed(earliest), "TRIAL_START_AFTER_USAGE", f"a trial named as starting {started} cannot precede {earliest}, the account's earliest observed event; the window anchor is corroborated, not typed")
    window = parsed_plan.blueprint.activation
    inside = [(name, stamp) for name, stamp in observed if 0 <= (parsed(stamp) - parsed(started)).days <= window.within_days]
    matched = [name for name in window.required_events if any(name == event for event, _ in inside)]
    digest = stable_digest([{"page": page.get("event"), "digest": stable_digest(page)} for page in pages])
    return {
        "usage_sources": sources, "saas_source": parsed_plan.to_dict(),
        "account_ref": ref, "trial_started_at": started, "usage_digest": digest, "activation_events": matched, "required_events": list(window.required_events), "activation_window_days": window.within_days,
        "activated_at": max((stamp for name, stamp in inside if name in matched), default=None),
        "saas_plan_digest": parsed_plan.plan_digest, "evidence_refs": [f"usage:{digest[:16]}", f"account:{str(ref)[:24]}"],
    }


def subscription_receipt(saas_plan: SaasOperatingLoopPlan | Mapping[str, Any], billing_row: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From the sealed SaaS plan and one sealed billing row: MRR is the tier's monthly price times the seats on the line, never the invoice's own number."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(saas_plan))
    row = _billing_row(billing_row)
    _require(str(row.currency).upper() == str(parsed_plan.blueprint.currency).upper(), "BILLING_CURRENCY_MISMATCH", f"the billing row is in {row.currency}; the SaaS plan prices in {parsed_plan.blueprint.currency}")
    tier = parsed_plan.blueprint.plan(row.plan_ref)
    price = None if tier is None else tier.monthly_price
    return {
        "billing_source": row.to_dict(), "saas_source": parsed_plan.to_dict(), "endpoint_digest": row.endpoint_digest,
        "account_ref": row.account_ref, "plan_ref": row.plan_ref, "seats": row.seats, "currency": row.currency,
        "tier_monthly_price": None if price is None else str(price), "mrr": None if price is None else str((price * row.seats).quantize(MONEY_QUANTUM)),
        "term_months": _term_months(row.period_start, row.period_end), "period_start": row.period_start, "period_end": row.period_end,
        "saas_plan_digest": parsed_plan.plan_digest, "billing_digest": row.row_digest, "evidence_refs": [f"billing:{row.row_digest[:16]}", f"invoice:{row.invoice_ref}"],
    }


def invoice_receipt(billing_row: Mapping[str, Any] | Any, issued_observation: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    """From a sealed billing row whose invoice is issued (optionally corroborated by an APPLIED ``quickbooks.observe_invoice_issued``)."""

    row = _billing_row(billing_row)
    _require(row.status in ("open", "paid"), "INVOICE_NOT_ISSUED", f"invoice {row.invoice_ref} is {row.status}; a draft or void invoice is not issued")
    evidence = [f"billing:{row.row_digest[:16]}", f"invoice:{row.invoice_ref}"]
    issuance = None
    if issued_observation is not None:
        observed = dict(detached(issued_observation))
        _require(observed.get("schema") == "lightbulb.quickbooks_invoice_issued_observation.v1" and str(observed.get("disposition")) == "APPLIED", "ISSUANCE_OBSERVATION_INVALID", "expected an APPLIED invoice issued observation")
        issuance = str(observed["evidence_sha256"])
        evidence.append(f"issuance:{issuance[:24]}")
    return {"billing_source": row.to_dict(), "issuance_source": detached(issued_observation), "account_ref": row.account_ref, "plan_ref": row.plan_ref, "invoice_ref": row.invoice_ref, "invoice_total": str(row.amount_due), "invoice_status": row.status, "issued_at": row.created_at, "period_start": row.period_start, "period_end": row.period_end, "term_months": _term_months(row.period_start, row.period_end), "billing_digest": row.row_digest, "issuance_evidence_sha256": issuance, "evidence_refs": evidence}


def payment_receipt(billing_row: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a sealed billing row the provider reports as paid; the amount is ``amount_paid`` and the time is the paid transition."""

    row = _billing_row(billing_row)
    _require(row.status == "paid" and row.paid_at is not None, "INVOICE_NOT_PAID", f"invoice {row.invoice_ref} is {row.status}; only a paid invoice applies a payment")
    _require(row.amount_paid > 0, "INVOICE_NOT_PAID", f"invoice {row.invoice_ref} reports no amount paid")
    return {"billing_source": row.to_dict(), "account_ref": row.account_ref, "currency": row.currency, "invoice_ref": row.invoice_ref, "applied_amount": str(row.amount_paid), "applied_at": row.paid_at, "billing_digest": row.row_digest, "evidence_refs": [f"billing:{row.row_digest[:16]}", f"payment:{row.invoice_ref}"]}


def settlement_receipt(settlement_observation: Mapping[str, Any] | Any, *, currency: str, provenance: Any = None) -> dict[str, Any]:
    """``revenue_chain.settlement_receipt`` verbatim: a SETTLED ``stripe.observe_cash_settlement`` past its reversal window (raises ``RevenueChainError``)."""

    receipt = _revenue_settlement_receipt(settlement_observation, currency=currency)
    _require(provenance is not None, "SOURCE_NOT_SEALED", "a cash settlement retains its actual read provenance")
    read = _provenance(provenance, "stripe.observe_cash_settlement")
    raw = detached(settlement_observation)
    _require(stable_digest(raw) == read.output_digest, "OBSERVATION_DIGEST_MISMATCH", "cash settlement must be the read's exact output")
    return {**receipt, "settlement_source": raw, "settlement_provenance": read.to_dict(), "currency": currency}


def recognition_receipt(close_state: Any, *, source_plan: Any, period_end: str | None = None) -> dict[str, Any]:
    """From a closed finance period that reconciled the revenue subledger and covers the recognition window."""

    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
    _, close_state = CLOSE_LIFECYCLE.bind(source_plan, close_state)
    _require(close_state.status == "closed", "CLOSE_NOT_CLOSED", f"the close is {close_state.status}")
    ledger = close_state.ledger
    _require("revenue_subledger" in list(getattr(ledger, "reconciled_accounts", ()) or ()), "REVENUE_NOT_RECONCILED", "the close did not reconcile the revenue subledger")
    end = timestamp(period_end, field_name="period_end") if period_end else str(ledger.period_end)
    _require(parsed(end) <= parsed(str(ledger.period_end)), "RECOGNITION_WINDOW_UNCOVERED", f"the close covers to {ledger.period_end}; it cannot prove service through {end}")
    return {"close_source": {"state": close_state.to_dict(), "source_plan": detached(source_plan)}, "close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "close_period_end": end, "evidence_refs": [f"close:{close_state.scope.entity_ref}", f"state:{close_state.state_digest[:24]}"]}


def failure_receipt(billing_row: Mapping[str, Any] | Any, charge_row: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From an unpaid sealed billing row plus the failed charge that names the decline code."""

    row, charge = _billing_row(billing_row), _charge_row(charge_row)
    _require(row.status in ("open", "uncollectible"), "INVOICE_NOT_FAILING", f"invoice {row.invoice_ref} is {row.status}; a failure needs an open or uncollectible invoice")
    _require(charge.status == "failed" and charge.failure_code is not None, "CHARGE_NOT_FAILED", f"charge {charge.charge_ref} is {charge.status} and carries no failure code")
    _require(charge.invoice_ref == row.invoice_ref, "CHARGE_INVOICE_MISMATCH", f"charge {charge.charge_ref} belongs to invoice {charge.invoice_ref}, not {row.invoice_ref}")
    _require(charge.amount == row.amount_due - row.amount_paid, "CHARGE_AMOUNT_MISMATCH", "the failed charge must concern this exact unpaid invoice amount")
    return {"billing_source": row.to_dict(), "charge_source": charge.to_dict(), "account_ref": row.account_ref, "currency": row.currency, "invoice_ref": row.invoice_ref, "decline_code": charge.failure_code, "failed_at": charge.created_at, "charge_digest": charge.row_digest, "outstanding_amount": str((row.amount_due - row.amount_paid).quantize(MONEY_QUANTUM)), "detail": charge.failure_detail, "billing_digest": row.row_digest, "evidence_refs": [f"charge:{charge.row_digest[:16]}", f"billing:{row.row_digest[:16]}"]}


def retry_receipt(charge_row: Mapping[str, Any] | Any, plan: SubscriptionChainPlan | Mapping[str, Any], *, case_state: Any) -> dict[str, Any]:
    """Which SCHEDULED attempt an observed charge corresponds to; the attempt number comes from the case's own sealed ledger, and the SDK never asks a provider to retry."""

    parsed_plan, case_state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(plan, case_state)
    charge = _charge_row(charge_row)
    ledger = case_state.ledger
    _require(case_state.status in ("payment_failed", "retry_scheduled", "outreach_sent"), "CASE_NOT_FAILING", f"the case is {case_state.status}; a retry belongs to a failed payment")
    _require(charge.invoice_ref == ledger.invoice_ref, "CHARGE_INVOICE_MISMATCH", f"charge {charge.charge_ref} belongs to invoice {charge.invoice_ref}, not {ledger.invoice_ref}")
    attempt = int(ledger.retry_attempts) + 1
    scheduled = parsed_plan.retry_schedule[min(attempt, len(parsed_plan.retry_schedule)) - 1]
    _require(charge.currency == parsed_plan.currency and charge.amount == ledger.outstanding_amount and charge.status == "failed", "CHARGE_AMOUNT_MISMATCH", "retry evidence must match the exact outstanding invoice and failed outcome")
    return {"charge_source": charge.to_dict(), "attempt": min(attempt, 10), "attempted_at": charge.created_at, "offset_days": max(_days(ledger.failed_at, charge.created_at), 0), "charge_digest": charge.row_digest, "decline_code": charge.failure_code, "detail": f"attempt {attempt} of {len(parsed_plan.retry_schedule)}; the plan schedules it at day {scheduled.day_offset}", "evidence_refs": [f"charge:{charge.row_digest[:16]}"]}


def _outreach_request(plan: Any, data: Mapping[str, Any], state_digest: str, *, eligibility: Any, suppression: Any, touch_ref: str, channel: str, creative_digest: str, approval_ref: str | None = None) -> Any:
    from lightbulb.connector_execution import ConnectorExecutionRequest
    scope = data["entity_scope"]
    return ConnectorExecutionRequest(tool="gmail.send_email", arguments={"company_ref": plan.company_ref, "account_ref": data["account_ref"], "invoice_ref": data["invoice_ref"], "endpoint_digest": data["endpoint_digest"], "subscription_state_digest": state_digest, "plan_digest": plan.plan_digest, "eligibility_digest": eligibility.eligibility_digest, "suppression_digest": suppression.suppression_digest, "touch_ref": touch_ref, "channel": channel, "creative_digest": creative_digest}, scope={"tenant_ref": scope["tenant_ref"], "company_ref": scope["company_ref"], "project_ref": scope["project_ref"], "project_id": scope.get("project_id"), "actor_ref": data["requester_ref"]}, connector_account_ref="outreach:primary", effect="write", approval_required=True, approval_ref=approval_ref, preview_only=approval_ref is None, idempotency_key=f"dunning:{scope['entity_ref']}:{state_digest}:{touch_ref}")


def outreach_request(case_state: Any, *, source_plan: Any, eligibility: Any, suppression: Any, touch_ref: str, channel: str = "email", creative_digest: str) -> Any:
    """Build an approval preview for the host's opaque-endpoint send adapter."""
    from lightbulb import permission_register as P
    plan, state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(source_plan, case_state)
    _require(state.status in {"retry_scheduled", "outreach_sent"}, "CASE_NOT_FAILING", "dunning sends belong to a scheduled retry")
    suppression = P.SuppressionDigest.model_validate(detached(suppression))
    proof = P.EligibilityReceipt.model_validate(detached(eligibility))
    P.verify_eligibility(proof, suppression_digest=suppression.suppression_digest, channel=channel, endpoints=[state.ledger.endpoint_digest], at=proof.as_of, company_ref=plan.company_ref, expected_scope=state.scope)
    return _outreach_request(plan, state.ledger.to_dict(), state.state_digest, eligibility=proof, suppression=suppression, touch_ref=touch_ref, channel=channel, creative_digest=creative_digest)


def outreach_receipt(execution_receipt: ExecutionReceipt | Mapping[str, Any], consent_record: Mapping[str, Any] | None = None, *, touch_ref: str, channel: str = "email", request: Any = None, output: Any = None, eligibility: Any = None, suppression: Any = None) -> dict[str, Any]:
    """From a bound write ``ExecutionReceipt`` for an approved send, plus the dated consent record that permitted it."""

    receipt = ExecutionReceipt.model_validate(dict(detached(execution_receipt)))
    _require(receipt.effect == "write" and receipt.tool in OUTREACH_TOOLS, "OUTREACH_NOT_A_SEND", f"a dunning message is a write on {list(OUTREACH_TOOLS)}; this receipt is a {receipt.effect} on {receipt.tool}")
    consent_ref, consent_status = None, None
    if consent_record is not None:
        raw = dict(detached(consent_record))
        consent_ref = str(raw.get("consent_ref") or raw.get("endpoint_digest") or "")
        consent_status = str(raw.get("status") or raw.get("basis") or "").lower()
        _require(bool(consent_ref) and bool(raw.get("captured_at") or raw.get("confirmed_at")), "CONSENT_RECORD_INVALID", "a consent record names its ref and the date it was captured")
        _require(consent_status in ("express", "implied"), "CONSENT_RECORD_INVALID", f"consent is {consent_status or 'unrecorded'}; only express or implied consent permits a send")
        _require(str(raw.get("channel", channel)).lower() == channel.lower(), "CONSENT_RECORD_INVALID", f"the consent covers {raw.get('channel')}, not {channel}")
        expires = raw.get("expires_at")
        _require(expires is None or parsed(timestamp(str(expires), field_name="expires_at")) >= parsed(receipt.completed_at), "CONSENT_RECORD_INVALID", f"the consent expired at {expires}, before the send at {receipt.completed_at}")
    _require(all(value is not None for value in (request, output, eligibility, suppression)), "CONSENT_RECORD_INVALID", "the send retains its exact request, execution output, eligibility and suppression snapshot")
    from lightbulb import permission_register as P
    from lightbulb.connector_execution import ConnectorExecutionRequest
    req = ConnectorExecutionRequest.model_validate(detached(request))
    facts = P.EffectFacts.model_validate(detached(output))
    suppressed = P.SuppressionDigest.model_validate(detached(suppression))
    proof = P.verify_eligibility(eligibility, suppression_digest=suppressed.suppression_digest, channel=channel, at=receipt.completed_at, endpoints=[facts.endpoint_digest], company_ref=facts.company_ref)
    _require(receipt.output_digest == stable_digest(detached(output)) and receipt.request_digest == req.custody_fingerprint() and receipt.approval_ref == req.approval_ref and receipt.tool == req.tool and receipt.project_id == str(req.scope.project_id) and receipt.connector_account_ref == req.connector_account_ref and not req.preview_only, "EXECUTION_MISMATCH", "the retained execution must bind the approved request and exact returned send payload")
    snapshot = next(item for item in proof.source_states if item.state["ledger"]["endpoint_digest"] == facts.endpoint_digest)
    consent_ref = snapshot.state["ledger"]["endpoint_digest"]
    consent_status = snapshot.state["status"]
    # Execute the real permission transition as a pure candidate. This rechecks
    # confirmation, quiet hours, sender/unsubscribe evidence and frequency caps.
    permission_receipt = P.send_receipt(P.permission_execution(receipt, output), eligibility=proof)
    permission_command = P.CONSENT_LIFECYCLE.seal_command({"event": "record_send", "transition_ref": f"dunning:{receipt.execution_digest[:32]}", "idempotency_key": f"dunning:{receipt.execution_digest[:32]}", "expected_version": snapshot.state["version"], "expected_state_digest": snapshot.state["state_digest"], "occurred_at": receipt.completed_at, "actor_ref": req.scope.actor_ref, "receipt": permission_receipt})
    outcome = P.CONSENT_LIFECYCLE.advance(snapshot.source_plan, snapshot.state, permission_command)
    _require(outcome.candidate_validated, outcome.receipt.rejection_code or "CONSENT_RECORD_INVALID", "the actual permission register refused this send")
    return {"execution_request": detached(req), "execution_source": receipt.to_dict(), "execution_output": detached(output), "eligibility_receipt": proof.to_dict(), "suppression_digest": suppressed.to_dict(), "endpoint_digest": facts.endpoint_digest, "touch_ref": touch_ref, "channel": channel, "sent_at": receipt.completed_at, "approval_ref": receipt.approval_ref, "approval_receipt_digest": receipt.approval_receipt_digest, "execution_digest": receipt.execution_digest, "consent_ref": consent_ref, "consent_status": consent_status, "evidence_refs": [f"execution:{receipt.journal_ref}", f"receipt:{receipt.receipt_digest[:24]}"]}


def _same_scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(key) == b.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _verify_subscription_sources(plan: Any, data: dict[str, Any], command: Any) -> None:
    r, event, at = command.receipt, command.event, command.occurred_at
    derived: dict[str, Any] = {}
    if event in {"start_trial", "record_activation"}:
        _require(bool(r.usage_sources) and r.saas_source is not None, "SOURCE_NOT_SEALED", "usage retains each source page and its SaaS plan")
        derived = trial_receipt([source["payload"] for source in r.usage_sources], r.saas_source, provenances=[source["provenance"] for source in r.usage_sources], account_ref=r.account_ref, trial_started_at=r.trial_started_at)
        _require(r.account_ref == data["usage_ref"] and r.trial_started_at == data["trial_started_at"], "ACCOUNT_NOT_OBSERVED", "activation must belong to this exact trial identity and start")
        for source in r.usage_sources:
            _source_scope(source["payload"], data["entity_scope"], plan.company_ref, plan.currency)
            _require(parsed(source["provenance"]["completed_at"]) <= parsed(at), "SOURCE_FROM_FUTURE", "usage reads must complete before the lifecycle command")
    if event in {"subscribe", "issue_invoice", "apply_payment", "record_recovery", "fail_payment"}:
        _require(r.billing_source is not None, "SOURCE_NOT_SEALED", "billing retains the exact invoice read")
        row = _billing_row(r.billing_source)
        _source_scope(row.source_payload, data["entity_scope"], plan.company_ref, plan.currency)
        for item in _rows(row.source_payload):
            _source_scope(item, data["entity_scope"], plan.company_ref, plan.currency)
        _require(row.currency == plan.currency and row.account_ref == data["account_ref"], "BILLING_CURRENCY_MISMATCH", "billing belongs to this subscription account and currency")
        _require(parsed(row.created_at) <= parsed(row.observed_at) <= parsed(at) and (row.paid_at is None or parsed(row.paid_at) <= parsed(row.observed_at)), "SOURCE_FROM_FUTURE", "invoice facts must precede the actual read and consuming command")
        if event == "subscribe":
            _require(row.usage_ref == data["usage_ref"], "ACCOUNT_NOT_OBSERVED", "Stripe metadata must bind the subscription to its observed usage identity")
            derived = subscription_receipt(r.saas_source, row)
        elif event == "issue_invoice":
            derived = invoice_receipt(row, r.issuance_source)
        elif event in {"apply_payment", "record_recovery"}:
            _require((row.amount_due, row.period_start, row.period_end, row.seats, row.plan_ref) == (_money_of(data, "invoice_total"), data["period_start"], data["period_end"], data["seats"], data["plan_ref"]), "PAYMENT_CORRELATION_MISMATCH", "paid invoice must retain its originally issued amount, term and priced subscription")
            derived = payment_receipt(row)
            _require(parsed(row.paid_at) >= parsed(data["issued_at"]), "PAYMENT_CORRELATION_MISMATCH", "payment cannot precede invoice issuance")
        else:
            derived = failure_receipt(row, r.charge_source)
            _require(row.amount_due == _money_of(data, "invoice_total"), "CHARGE_AMOUNT_MISMATCH", "failure must concern the originally billed amount")
    if event in {"fail_payment", "schedule_retry"}:
        charge = _charge_row(r.charge_source)
        _source_scope(charge.source_payload, data["entity_scope"], plan.company_ref, plan.currency)
        _require(charge.currency == plan.currency and charge.invoice_ref == data["invoice_ref"] and charge.amount == _money_of(data, "outstanding_amount") and charge.status == "failed", "CHARGE_AMOUNT_MISMATCH", "charge must prove this exact unpaid invoice")
        _require(parsed(charge.created_at) <= parsed(charge.observed_at) <= parsed(at), "SOURCE_FROM_FUTURE", "a charge must precede its read and the command")
        if event == "schedule_retry":
            _require(charge.charge_ref not in data.get("retry_charge_refs", ()), "RETRY_CHARGE_REPLAYED", "a fresh read of the same charge cannot count as a second retry")
            data["retry_charge_refs"] = [*data.get("retry_charge_refs", ()), charge.charge_ref]
            derived = {"attempt": data["retry_attempts"], "attempted_at": charge.created_at, "charge_digest": charge.row_digest, "offset_days": max(_days(data["failed_at"], charge.created_at), 0), "decline_code": charge.failure_code}
    if event == "settle_cash":
        _require(r.settlement_source is not None, "SOURCE_NOT_SEALED", "settlement retains the exact provider output")
        _source_scope(r.settlement_source, data["entity_scope"], plan.company_ref, plan.currency)
        derived = settlement_receipt(r.settlement_source, currency=plan.currency, provenance=r.settlement_provenance)
        _require(parsed(r.settlement_provenance.completed_at) <= parsed(at) and parsed(r.settlement_source["observed_at"]) <= parsed(r.settlement_provenance.completed_at), "SOURCE_FROM_FUTURE", "settlement must be observed before the command")
        _require(r.settlement_source.get("invoice_correlation_sha256") == stable_digest({"stripe_invoice_ref": data["invoice_ref"]}), "SETTLEMENT_CORRELATION_MISMATCH", "settlement must name the current Stripe invoice correlation")
        ref = str(r.settlement_source.get("balance_transaction_ref") or r.settlement_source.get("payout_ref") or r.settlement_evidence_sha256)
        _require(r.settlement_evidence_sha256 not in data.get("settlement_digests", ()) and ref not in data.get("settlement_refs", ()), "SETTLEMENT_ALREADY_USED", "a cash movement settles one billing cycle")
        data["settlement_digests"] = [*data.get("settlement_digests", ()), r.settlement_evidence_sha256]
        data["settlement_refs"] = [*data.get("settlement_refs", ()), ref]
    if event == "recognize_revenue":
        _require(r.close_source is not None, "SOURCE_NOT_SEALED", "recognition retains the complete close and source plan")
        from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
        close_plan, close = CLOSE_LIFECYCLE.bind(r.close_source["source_plan"], r.close_source["state"])
        _require(_same_scope(close.scope, data["entity_scope"]), "SCOPE_MISMATCH", "close belongs to another company, tenant, project or currency")
        _require(parsed(close.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "close must finish before recognition")
        derived = recognition_receipt(close, source_plan=close_plan, period_end=r.close_period_end)
    if event == "send_outreach":
        from lightbulb import permission_register as P
        derived = outreach_receipt(r.execution_source, touch_ref=r.touch_ref, channel=r.channel, request=r.execution_request, output=r.execution_output, eligibility=r.eligibility_receipt, suppression=r.suppression_digest)
        proof, suppression = P.EligibilityReceipt.model_validate(r.eligibility_receipt), P.SuppressionDigest.model_validate(r.suppression_digest)
        P.verify_eligibility(proof, suppression_digest=suppression.suppression_digest, channel=r.channel, at=r.sent_at, endpoints=[data["endpoint_digest"]], company_ref=plan.company_ref, expected_scope=data["entity_scope"])
        _require(parsed(r.sent_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the actual send must finish before recording outreach")
        expected = _outreach_request(plan, data, command.expected_state_digest, eligibility=proof, suppression=suppression, touch_ref=r.touch_ref, channel=r.channel, creative_digest=r.execution_output["creative_digest"], approval_ref=r.approval_ref)
        _require(detached(expected) == r.execution_request, "EXECUTION_MISMATCH", "dunning must execute this exact invoice, endpoint, subscription state, actor and approved request")
    raw = r.to_dict()
    for key, value in derived.items():
        if key not in {"evidence_refs", "detail"}:
            _require(raw.get(key) == detached(value), "SOURCE_PROJECTION_MISMATCH", f"{key} must be rederived from retained source evidence")


def verify_subscription_case(case_state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, state = SUBSCRIPTION_CHAIN_LIFECYCLE.bind(source_plan, case_state)
    _require((company_ref is None or plan.company_ref == company_ref) and (currency is None or plan.currency == currency) and (expected_scope is None or _same_scope(state.scope, expected_scope)), "SCOPE_MISMATCH", "subscription source belongs to another company, tenant, project or currency")
    _require(at is None or parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "subscription evidence cannot postdate its consumer")
    return state


def period_evidence_receipt(case_state: Any, *, source_plan: Any, engine: str = "saas_operating_engine", evidence_ref: str | None = None) -> dict[str, Any]:
    """The company operating system's ``record_evidence`` receipt: settled subscription cash as the SaaS engine's revenue, not the pipeline engine's.

    ``engine`` names the attribution this module is allowed to make; it is not
    a caller's choice, so typing another engine is refused rather than routing
    self-serve cash to the engine that did not earn it.
    """

    _require(engine == "saas_operating_engine", "ENGINE_NOT_BOUND", f"subscription cash is the SaaS operating engine's revenue; this chain cannot attribute it to {engine}")
    case_state = verify_subscription_case(case_state, source_plan=source_plan)
    _require(case_state.status in ("cash_settled", "revenue_recognized"), "CASE_NOT_SETTLED", f"the case is {case_state.status}; only settled cash becomes period revenue")
    return {"engine": engine, "evidence_ref": evidence_ref or f"subscription_case:{case_state.scope.entity_ref}:{case_state.state_digest[:16]}", "source_kind": "subscription_case", "source_digest": case_state.state_digest, "revenue_only": True, "spend": "0", "revenue": str(case_state.ledger.settled_amount), "signals": []}


def hand_off_receipt(case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The retention chain's ``flag_renewal`` receipt from a recognized case: the renewal falls due at the end of the term the cash paid for."""

    case_state = verify_subscription_case(case_state, source_plan=source_plan)
    _require(case_state.status in ("cash_settled", "revenue_recognized"), "CASE_NOT_RECOGNIZED", f"the case is {case_state.status}; hand a renewal off once its cash is proven")
    ledger = case_state.ledger
    _require(ledger.period_end is not None and ledger.plan_ref is not None, "CASE_NOT_RECOGNIZED", "the case carries no billed term to renew")
    return {"account_ref": str(ledger.account_ref), "plan_ref": str(ledger.plan_ref), "renews_at": str(ledger.period_end), "billing_digest": case_state.state_digest, "evidence_refs": [f"subscription_case:{case_state.scope.entity_ref}:{case_state.state_digest[:16]}"]}


def expansion_candidate_signal(case_state: Any, *, source_plan: Any, suggested_plan_ref: str, emitted_at: str) -> dict[str, Any]:
    """``signals.expansion_candidate`` for the pipeline engine, from a case that is paying today."""

    case_state = verify_subscription_case(case_state, source_plan=source_plan, at=emitted_at)
    _require(case_state.status in ("paid", "cash_settled", "revenue_recognized", "recovered"), "CASE_NOT_PAYING", f"the case is {case_state.status}; it is not an expansion candidate")
    ledger = case_state.ledger
    return {"name": "signals.expansion_candidate", "producer": "saas_operating_engine", "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"account_ref": str(ledger.account_ref), "suggested_plan_ref": suggested_plan_ref, "plan_ref": str(ledger.plan_ref), "mrr": str(ledger.mrr), "seats": int(ledger.seats)}}


def past_due_signal(case_state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any]:
    """``signals.churn_risk`` from the dunning arc: the MRR at risk is this case's own, and the days are since the observed failure."""

    case_state = verify_subscription_case(case_state, source_plan=source_plan, at=emitted_at)
    _require(case_state.status in ("payment_failed", "retry_scheduled", "outreach_sent", "written_off"), "CASE_NOT_PAST_DUE", f"the case is {case_state.status}; nothing is past due")
    ledger = case_state.ledger
    stamp = timestamp(emitted_at, field_name="emitted_at")
    return {"name": "signals.churn_risk", "producer": "saas_operating_engine", "emitted_at": stamp, "payload": {"account_ref": str(ledger.account_ref), "mrr_at_risk": str(ledger.mrr), "inactive_days": _days(ledger.failed_at, stamp), "past_due": str(ledger.outstanding_amount), "decline_code": str(ledger.decline_code or "unknown")}}


def chain_summary(case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    case_state = verify_subscription_case(case_state, source_plan=source_plan)
    ledger = case_state.ledger
    return {"case_ref": str(case_state.scope.entity_ref), "status": case_state.status, "account_ref": ledger.account_ref, "plan_ref": ledger.plan_ref, "seats": ledger.seats, "mrr": str(ledger.mrr), "invoice_total": str(ledger.invoice_total), "settled_amount": str(ledger.settled_amount), "recognized_to_date": str(ledger.recognized_to_date), "deferred_balance": str(ledger.deferred_balance), "billing_cycles": ledger.billing_cycles, "days_trial_to_cash": ledger.days_trial_to_cash, "outcome": ledger.outcome, "state_digest": case_state.state_digest}


def recognition_source_balances(case_state: Any, *, source_plan: Any) -> tuple[Any, Any]:
    """Replayed recognized and deferred balances for the finance close."""
    from lightbulb.finance_close_observations import SourceBalance
    state = verify_subscription_case(case_state, source_plan=source_plan)
    _require(state.status == "revenue_recognized", "REVENUE_NOT_RECOGNIZED", "recognize delivered service before projecting the two subledger balances")
    recognition_end = next(item.command.receipt.close_period_end for item in reversed(state.transition_history) if item.command.event == "recognize_revenue")
    common = {"source_ref": f"subscription:{state.scope.entity_ref}", "source_tool": "subscription_chain.recognize_revenue", "provenance_digest": state.state_digest, "items": 1, "window_end": recognition_end}
    return tuple(SourceBalance.model_validate({**common, "kind": kind, "balance": str(amount)}) for kind, amount in (("revenue_subledger", state.ledger.recognized_to_date), ("deferred_revenue", state.ledger.deferred_balance)))


def write_off_exception(case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """A written-off subscription enters the existing reconciliation desk."""
    state = verify_subscription_case(case_state, source_plan=source_plan)
    _require(state.status == "written_off" and state.ledger.authorization_proof_digest is not None, "CASE_NOT_WRITTEN_OFF", "only an authorized written-off subscription opens this exception")
    return {"kind": "chain_reconciliation", "source_engine": "subscription_chain", "source_ref": f"subscription_chain:{state.scope.entity_ref}", "source_digest": state.state_digest, "code": "SUBSCRIPTION_WRITTEN_OFF", "detail": f"Reconcile the authorized write-off of {state.ledger.written_off_amount} {state.scope.currency} on invoice {state.ledger.invoice_ref}", "evidence_refs": [f"subscription:{state.state_digest[:24]}", f"authority:{state.ledger.authorization_proof_digest[:24]}"]}


def dunning_summary(cases: Sequence[Any], *, source_plans: Mapping[str, Any]) -> dict[str, Any]:
    """What the operator sees on the dunning desk: the failed cases, what they owe, and how far each is through the schedule."""

    cases = [verify_subscription_case(case, source_plan=source_plans[case.plan_digest]) for case in cases]
    _require(len({case.scope.entity_ref for case in cases}) == len(cases), "CASE_DUPLICATED", "one case enters the dunning book once")
    failing = [case for case in cases if case.status in ("payment_failed", "retry_scheduled", "outreach_sent", "recovered", "written_off")]
    outstanding = sum((Decimal(str(case.ledger.outstanding_amount)) for case in failing if case.status not in ("recovered", "written_off")), Decimal("0"))
    recovered = sum((Decimal(str(case.ledger.recovered_amount)) for case in cases), Decimal("0"))
    written_off = sum((Decimal(str(case.ledger.written_off_amount)) for case in cases), Decimal("0"))
    return {
        "cases": len(failing), "amount_outstanding": str(outstanding.quantize(MONEY_QUANTUM)), "amount_recovered": str(recovered.quantize(MONEY_QUANTUM)), "amount_written_off": str(written_off.quantize(MONEY_QUANTUM)),
        "by_status": {status: sum(1 for case in cases if case.status == status) for status in SUBSCRIPTION_STATUSES if any(case.status == status for case in cases)},
        "rows": [{"case_ref": str(case.scope.entity_ref), "status": case.status, "decline_code": case.ledger.decline_code, "retry_attempts": case.ledger.retry_attempts, "outreach_count": case.ledger.outreach_count, "outstanding": str(case.ledger.outstanding_amount)} for case in failing],
    }


def subscriptions_summary(cases: Sequence[Any], *, source_plans: Mapping[str, Any]) -> dict[str, Any]:
    """The book: committed MRR, cash settled, revenue recognized, and what is still deferred."""

    cases = [verify_subscription_case(case, source_plan=source_plans[case.plan_digest]) for case in cases]
    _require(len({case.scope.entity_ref for case in cases}) == len(cases), "CASE_DUPLICATED", "one case enters the subscription book once")
    live = [case for case in cases if case.status not in ("trial_lapsed", "cancelled", "written_off")]
    return {
        "cases": len(cases), "live": len(live),
        "mrr": str(sum((Decimal(str(case.ledger.mrr)) for case in live), Decimal("0")).quantize(MONEY_QUANTUM)),
        "cash_settled": str(sum((Decimal(str(case.ledger.cash_settled_to_date)) for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)),
        "recognized": str(sum((Decimal(str(case.ledger.recognized_to_date)) for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)),
        "deferred": str(sum((Decimal(str(case.ledger.deferred_balance)) for case in cases), Decimal("0")).quantize(MONEY_QUANTUM)),
        "by_status": {status: sum(1 for case in cases if case.status == status) for status in SUBSCRIPTION_STATUSES if any(case.status == status for case in cases)},
    }


SUBSCRIPTION_CHAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": SUBSCRIPTION_CHAIN_KIND,
    "golden_loop": SUBSCRIPTION_CHAIN_GOLDEN_LOOP,
    "stages": ["start_trial", "record_activation", "subscribe", "issue_invoice", "apply_payment", "settle_cash", "recognize_revenue", "dunning"],
    "statuses": list(SUBSCRIPTION_STATUSES),
    "terminal": sorted(TERMINAL_SUBSCRIPTION_STATUSES),
    "events": list(SUBSCRIPTION_EVENTS),
    "hops": {
        "start_trial": "governed posthog.query_events page (hashed identities)",
        "record_activation": "the same page(s) matched against the sealed SaaS plan's activation policy",
        "subscribe": "sealed billing row + the SaaS plan's tier price",
        "issue_invoice": "sealed billing row (optionally quickbooks.observe_invoice_issued APPLIED)",
        "apply_payment": "sealed billing row reported paid",
        "settle_cash": "stripe.observe_cash_settlement SETTLED after the reversal window",
        "recognize_revenue": "finance_close closed with revenue_subledger reconciled",
        "fail_payment": "sealed billing row open/uncollectible + the failed charge row",
        "schedule_retry": "the observed retry charge, matched to the plan's schedule",
        "send_outreach": "exact approved request and execution output + replayed permission eligibility and suppression snapshots",
        "record_recovery": "the billing row reported paid after the failure",
    },
    "required_connectors": ["stripe", "posthog", "quickbooks", "gmail", "lightbulb.sdk_engine_state"],
    "missing_reads": [
        "stripe.list_charges carries the decline code and is on no governed lane; this ships host-lane against pinned fixtures and proposes a governed contract",
        "stripe.list_customers carries the tier and seat metadata and is on no governed lane; seats are read from the invoice line instead",
        "the governed posthog.query_events page returns one event name with hashed identities, which is not what company_execution_bridge.posthog_usage_to_accounts consumes; trial_receipt is written against the governed shape",
    ],
    "scope_note": "subscription_business_loop.py runs a private trialing/active/past_due table with no provenance, no settlement, and no period evidence; this module is the authority for self-serve cash and that pack is a preview scaffold",
    "hard_rules": [
        "MRR is the sealed tier price times seats, never the invoice's own number",
        "recognized revenue never runs ahead of service delivered",
        "the SDK proves which scheduled retry an observed charge was; it never asks a provider to retry",
        "no dunning message without replayed permission evidence and an execution bound to this exact invoice and subscription state",
        "settled cash is period revenue for saas_operating_engine, the engine that earned it",
    ],
}

__all__ = [
    "BILLING_ROW_SCHEMA",
    "CHARGE_ROW_SCHEMA",
    "MAX_SUBSCRIPTION_TRANSITIONS",
    "SUBSCRIPTION_CHAIN_GOLDEN_LOOP",
    "SUBSCRIPTION_CHAIN_KIND",
    "SUBSCRIPTION_CHAIN_LIFECYCLE",
    "SUBSCRIPTION_CHAIN_MANIFEST",
    "SUBSCRIPTION_EVENTS",
    "SUBSCRIPTION_STATUSES",
    "BillingRow",
    "ChargeRow",
    "RetryStep",
    "SubscriptionCaseState",
    "SubscriptionChainError",
    "SubscriptionChainPlan",
    "advance_subscription_case",
    "billing_rows",
    "chain_summary",
    "charge_rows",
    "compile_subscription_chain",
    "dunning_summary",
    "expansion_candidate_signal",
    "failure_receipt",
    "hand_off_receipt",
    "invoice_receipt",
    "open_subscription_case",
    "past_due_signal",
    "payment_receipt",
    "period_evidence_receipt",
    "recognition_receipt",
    "recognition_source_balances",
    "retry_receipt",
    "settlement_receipt",
    "subscription_receipt",
    "subscriptions_summary",
    "trial_receipt",
    "outreach_request",
    "outreach_receipt",
    "verify_subscription_case",
    "write_off_exception",
]
