"""Exception and recovery branches for the Service Business Golden Operating Loop.

At almost every node of ``service.market_to_renewal_business`` something other
than the happy path can happen.  This module types those branches as
replay-fenced **exception cases** bound to a cycle and its stage::

    quote            -> quote_revision        (customer negotiates, declines, asks for changes)
    agreement/deliver-> scope_change          (variance -> change order -> approved ceiling)
    verify_acceptance-> acceptance_rework     (rejected work -> bounded rework rounds -> escalation)
    invoice/collect  -> invoice_dispute       (disputed amount -> investigation -> credit note)
    collect          -> collection_delinquency(overdue -> dunning ladder -> promise, plan, collections, write-off)
    support_renew    -> warranty_claim        (defect inside the support window -> remedy or re-quote)
    support_renew    -> churn_winback         (declined renewal -> bounded offer -> renewed or lost)

Each case has its own state machine, a policy with finite limits, and a
resolution that says how the cycle resumes (which stage, which ledger
adjustments).  Nothing here issues a credit note, sends a reminder, writes off
a balance, or grants a discount; those are Spring-authorized effects executed
by the bound primitives (``finance.create_invoice``,
``communication.write_email``, ``commercial.propose_contract_change_order``,
``finance.collect_payment``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.service_business_loop import (
    SERVICE_BUSINESS_GOLDEN_LOOP,
    STAGE_ORDER,
    TERMINAL_CYCLE_STATUSES,
    BoundedText,
    CurrencyCode,
    LoopStage,
    OpaqueRef,
    ServiceBusinessCycleState,
    ServiceBusinessLoopPlan,
    Sha256Digest,
    ShortText,
    _decimal,
    _detached,
    _parsed_timestamp,
    _sealed_digest,
    _skip,
    _stable_digest,
    _StrictModel,
    _timestamp,
)


SERVICE_EXCEPTIONS_LOOP_EXTENSION = "service.market_to_renewal_business.exceptions@0.1.0"
EXCEPTION_POLICY_SCHEMA = "lightbulb.service_exception_policy.v1"
EXCEPTION_COMMAND_SCHEMA = "lightbulb.service_exception_command.v1"
EXCEPTION_CASE_SCHEMA = "lightbulb.service_exception_case.v1"
EXCEPTION_RESULT_SCHEMA = "lightbulb.service_exception_transition_result.v1"
EXCEPTION_PORTFOLIO_SCHEMA = "lightbulb.service_exception_portfolio_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_CASE_TRANSITIONS = 40

ExceptionKind = Literal["quote_revision", "scope_change", "acceptance_rework", "invoice_dispute", "collection_delinquency", "warranty_claim", "churn_winback"]
CaseStatus = Literal[
    "opened",
    "revised", "customer_accepted", "customer_declined",
    "change_order_proposed", "change_approved", "change_rejected",
    "rework_planned", "resubmitted", "accepted", "rejected_again", "escalated",
    "investigated", "resolved_credit_note", "resolved_upheld",
    "reminder_sent", "promise_to_pay", "payment_plan_agreed", "paid", "escalated_to_collections", "written_off",
    "assessed_covered", "assessed_not_covered", "remedy_scheduled", "remedied", "requoted",
    "offer_made", "won_back", "lost",
    "withdrawn",
]
TERMINAL_CASE_STATUSES: frozenset[str] = frozenset(
    {"customer_accepted", "customer_declined", "change_approved", "change_rejected", "accepted", "escalated", "resolved_credit_note", "resolved_upheld", "paid", "escalated_to_collections", "written_off", "remedied", "requoted", "won_back", "lost", "withdrawn"}
)
CaseEvent = Literal[
    "revise_quote", "customer_accept", "customer_decline",
    "propose_change_order", "approve_change", "reject_change",
    "plan_rework", "resubmit", "accept_rework", "reject_rework", "escalate",
    "investigate", "resolve_credit_note", "uphold_invoice",
    "send_reminder", "record_promise", "agree_payment_plan", "record_payment", "escalate_to_collections", "write_off",
    "assess_claim", "schedule_remedy", "complete_remedy", "requote",
    "make_offer", "accept_offer", "decline_offer",
    "withdraw",
]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]
ResumeStage = Literal["quote", "agreement", "deliver", "verify_acceptance", "invoice", "collect", "support_renew", "learn"]

_ORIGIN_STAGE_BY_KIND: dict[str, tuple[str, ...]] = {
    "quote_revision": ("quote",),
    "scope_change": ("agreement", "deliver"),
    "acceptance_rework": ("verify_acceptance",),
    "invoice_dispute": ("invoice", "collect"),
    "collection_delinquency": ("collect",),
    "warranty_claim": ("support_renew",),
    "churn_winback": ("support_renew",),
}
_BOUND_PRIMITIVES_BY_KIND: dict[str, tuple[str, ...]] = {
    "quote_revision": ("commercial.evaluate_quote_order_contract_controls", "commercial.propose_operations_transition", "documents.generate_business_artifact"),
    "scope_change": ("commercial.propose_contract_change_order", "commercial.compile_legal_review_packet", "commercial.reconcile_executed_agreement"),
    "acceptance_rework": ("project.create_work_packet", "project.evaluate_contractual_delivery_evidence", "project.compile_customer_acceptance_candidate"),
    "invoice_dispute": ("service.intake_and_classify_case", "finance.create_invoice", "communication.write_email"),
    "collection_delinquency": ("communication.write_email", "finance.collect_payment", "accounting.assess_receivables"),
    "warranty_claim": ("service.intake_and_classify_case", "project.create_work_packet", "service.verify_case_resolution"),
    "churn_winback": ("growth.review_customer_value", "commercial.propose_contract_change_order", "communication.write_email"),
}
# (from_status, event) -> to_status, per kind
_TABLES: dict[str, dict[tuple[str, str], str]] = {
    "quote_revision": {("opened", "revise_quote"): "revised", ("revised", "revise_quote"): "revised", ("revised", "customer_accept"): "customer_accepted", ("opened", "customer_decline"): "customer_declined", ("revised", "customer_decline"): "customer_declined"},
    "scope_change": {("opened", "propose_change_order"): "change_order_proposed", ("change_order_proposed", "approve_change"): "change_approved", ("change_order_proposed", "reject_change"): "change_rejected"},
    "acceptance_rework": {("opened", "plan_rework"): "rework_planned", ("rejected_again", "plan_rework"): "rework_planned", ("rework_planned", "resubmit"): "resubmitted", ("resubmitted", "accept_rework"): "accepted", ("resubmitted", "reject_rework"): "rejected_again", ("rejected_again", "escalate"): "escalated", ("opened", "escalate"): "escalated"},
    "invoice_dispute": {("opened", "investigate"): "investigated", ("investigated", "resolve_credit_note"): "resolved_credit_note", ("investigated", "uphold_invoice"): "resolved_upheld"},
    "collection_delinquency": {("opened", "send_reminder"): "reminder_sent", ("reminder_sent", "send_reminder"): "reminder_sent", ("opened", "record_promise"): "promise_to_pay", ("reminder_sent", "record_promise"): "promise_to_pay", ("promise_to_pay", "send_reminder"): "reminder_sent", ("opened", "record_payment"): "paid", ("reminder_sent", "record_payment"): "paid", ("promise_to_pay", "record_payment"): "paid", ("payment_plan_agreed", "record_payment"): "paid", ("reminder_sent", "agree_payment_plan"): "payment_plan_agreed", ("promise_to_pay", "agree_payment_plan"): "payment_plan_agreed", ("reminder_sent", "escalate_to_collections"): "escalated_to_collections", ("promise_to_pay", "escalate_to_collections"): "escalated_to_collections", ("payment_plan_agreed", "escalate_to_collections"): "escalated_to_collections", ("reminder_sent", "write_off"): "written_off", ("promise_to_pay", "write_off"): "written_off", ("payment_plan_agreed", "write_off"): "written_off"},
    "warranty_claim": {("opened", "assess_claim"): "assessed_covered", ("assessed_covered", "schedule_remedy"): "remedy_scheduled", ("remedy_scheduled", "complete_remedy"): "remedied", ("assessed_not_covered", "requote"): "requoted"},
    "churn_winback": {("opened", "make_offer"): "offer_made", ("offer_made", "make_offer"): "offer_made", ("offer_made", "accept_offer"): "won_back", ("offer_made", "decline_offer"): "lost", ("opened", "decline_offer"): "lost"},
}


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


class DunningStep(_StrictModel):
    days_overdue: int = Field(ge=0, le=365)
    channel: Literal["email", "call", "letter"]
    tone: Literal["friendly", "firm", "final_notice"]


class ServiceExceptionPolicy(_StrictModel):
    schema_id: Literal["lightbulb.service_exception_policy.v1"] = Field(default=EXCEPTION_POLICY_SCHEMA, alias="schema")
    max_quote_revisions: int = Field(default=3, ge=1, le=20)
    max_rework_rounds: int = Field(default=2, ge=1, le=10)
    max_change_order_percent: Decimal = Field(default=Decimal("50"), validate_default=True)
    dunning_ladder: tuple[DunningStep, ...] = Field(default=(DunningStep(days_overdue=3, channel="email", tone="friendly"), DunningStep(days_overdue=14, channel="email", tone="firm"), DunningStep(days_overdue=30, channel="call", tone="final_notice")), min_length=1, max_length=8)
    collections_after_days: int = Field(default=60, ge=1, le=365)
    max_write_off_amount: Decimal = Field(default=Decimal("500"), validate_default=True)
    max_payment_plan_installments: int = Field(default=6, ge=1, le=36)
    max_winback_discount_percent: Decimal = Field(default=Decimal("15"), validate_default=True)
    max_winback_offers: int = Field(default=2, ge=1, le=5)
    warranty_window_days: int = Field(default=30, ge=0, le=730)
    currency: CurrencyCode = "USD"
    policy_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_change_order_percent", "max_write_off_amount", "max_winback_discount_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name))
        if info.field_name != "max_write_off_amount" and parsed > 100:
            raise ValueError(f"{info.field_name} must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _policy_is_exact(self, info: ValidationInfo) -> "ServiceExceptionPolicy":
        days = [step.days_overdue for step in self.dunning_ladder]
        if days != sorted(days) or len(set(days)) != len(days):
            raise ValueError("dunning ladder steps must have strictly increasing days overdue")
        if self.collections_after_days <= days[-1]:
            raise ValueError("collections escalation must follow the last dunning step")
        if _skip(info):
            return self
        if self.policy_digest != _sealed_digest(ServiceExceptionPolicy, self, "policy_digest"):
            raise ValueError("policy_digest must commit the exact policy")
        return self


def seal_service_exception_policy(policy: Mapping[str, Any] | None = None) -> ServiceExceptionPolicy:
    raw = dict(_detached(policy or {}))
    raw["policy_digest"] = _sealed_digest(ServiceExceptionPolicy, raw, "policy_digest")
    return ServiceExceptionPolicy.model_validate(raw)


def policy_for_plan(plan: ServiceBusinessLoopPlan | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> ServiceExceptionPolicy:
    """Derive the exception policy from a loop plan (warranty window = blueprint support window, currency = blueprint currency)."""

    parsed = ServiceBusinessLoopPlan.model_validate(_detached(plan))
    raw: dict[str, Any] = {"warranty_window_days": parsed.blueprint.support_window_days, "currency": parsed.blueprint.currency}
    raw.update(dict(overrides or {}))
    return seal_service_exception_policy(raw)


# --------------------------------------------------------------------------- #
# Commands and cases
# --------------------------------------------------------------------------- #


class ExceptionReceipt(_StrictModel):
    """Evidence and amounts linked by a case transition; references, never bodies."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    quote_ref: OpaqueRef | None = None
    quote_revision: int | None = Field(default=None, ge=1, le=100)
    quote_total: Decimal | None = None
    change_order_proposal_digest: Sha256Digest | None = None
    change_order_ref: OpaqueRef | None = None
    delta_amount: Decimal | None = None
    customer_approval_ref: OpaqueRef | None = None
    internal_approval_ref: OpaqueRef | None = None
    work_packet_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    rejection_reasons: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    evaluator_ref: OpaqueRef | None = None
    disputed_amount: Decimal | None = None
    credit_note_ref: OpaqueRef | None = None
    credit_amount: Decimal | None = None
    reminder_channel: Literal["email", "call", "letter"] | None = None
    days_overdue: int | None = Field(default=None, ge=0, le=3650)
    promised_payment_date: str | None = None
    installment_count: int | None = Field(default=None, ge=1, le=36)
    installment_amounts: tuple[Decimal, ...] = Field(default_factory=tuple, max_length=36)
    payment_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    paid_amount: Decimal | None = None
    collections_agency_ref: OpaqueRef | None = None
    write_off_approval_ref: OpaqueRef | None = None
    defect_description: BoundedText | None = None
    covered: bool | None = None
    remedy_ref: OpaqueRef | None = None
    new_lead_ref: OpaqueRef | None = None
    offer_ref: OpaqueRef | None = None
    discount_percent: Decimal | None = None
    renewal_offer_ref: OpaqueRef | None = None

    @field_validator("quote_total", "delta_amount", "disputed_amount", "credit_amount", "paid_amount", "discount_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            return None
        return _decimal(value, field_name=str(info.field_name), ) if info.field_name != "delta_amount" else _signed(value, "delta_amount")

    @field_validator("installment_amounts", mode="before")
    @classmethod
    def _installments(cls, value: Any) -> Any:
        return tuple(_decimal(item, field_name="installment_amounts") for item in (value or ()))

    @field_validator("promised_payment_date")
    @classmethod
    def _promise(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="promised_payment_date")


def _signed(value: Any, field_name: str) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string or Decimal")
    try:
        parsed = Decimal(str(value))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or abs(parsed) > Decimal("1000000000000"):
        raise ValueError(f"{field_name} must be a finite bounded decimal")
    return parsed.quantize(Decimal("0.01"))


class ServiceExceptionCommand(_StrictModel):
    schema_id: Literal["lightbulb.service_exception_command.v1"] = Field(default=EXCEPTION_COMMAND_SCHEMA, alias="schema")
    event: CaseEvent
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_CASE_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: ExceptionReceipt = Field(default_factory=ExceptionReceipt)
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "ServiceExceptionCommand":
        if self.event in {"withdraw", "customer_decline", "reject_change", "escalate", "uphold_invoice", "write_off", "decline_offer", "reject_rework"} and self.reason is None:
            raise ValueError(f"{self.event} requires a reason")
        if _skip(info):
            return self
        if self.request_digest != exception_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def exception_command_digest(command: ServiceExceptionCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(ServiceExceptionCommand, command, "request_digest")


def seal_exception_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = exception_command_digest(raw)
    return ServiceExceptionCommand.model_validate(raw).to_dict()


class CaseLedger(_StrictModel):
    round: int = Field(default=0, ge=0)
    reminders_sent: int = Field(default=0, ge=0)
    offers_made: int = Field(default=0, ge=0)
    quote_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    at_risk_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    resolved_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    credit_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    delta_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    discount_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    latest_ref: OpaqueRef | None = None
    covered: bool | None = None

    @field_validator("quote_total", "at_risk_amount", "resolved_amount", "credit_amount", "discount_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("delta_amount", mode="before")
    @classmethod
    def _delta(cls, value: Any) -> Decimal:
        return _signed(value, "delta_amount")


class CaseTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_CASE_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: CaseStatus
    transition_digest: Sha256Digest
    command: ServiceExceptionCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "CaseTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: ServiceExceptionCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


class CaseBinding(_StrictModel):
    """What the case was opened against: the cycle, its stage, and the facts that justified it."""

    cycle_ref: OpaqueRef
    cycle_state_digest: Sha256Digest
    cycle_status: str = Field(min_length=1, max_length=40)
    origin_stage: LoopStage
    customer_ref: OpaqueRef
    currency: CurrencyCode
    quote_total: Decimal
    outstanding_receivable: Decimal
    invoiced_amount: Decimal
    accepted_amount: Decimal
    renewal_decision: str | None = None
    acceptance_verified_at: str | None = None

    @field_validator("quote_total", "outstanding_receivable", "invoiced_amount", "accepted_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


def _state_digest(policy_digest: str, binding: CaseBinding, kind: str, case_ref: str, history: Sequence[CaseTransition]) -> str:
    return _stable_digest({"policy_digest": policy_digest, "binding": binding.to_dict(), "kind": kind, "case_ref": case_ref, "transitions": [item.transition_digest for item in history]})


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _apply(policy: ServiceExceptionPolicy, kind: str, binding: CaseBinding, status: str, ledger: CaseLedger, command: ServiceExceptionCommand) -> tuple[str, CaseLedger]:
    if status in TERMINAL_CASE_STATUSES:
        raise _Rejected("CASE_TERMINAL", f"case is {status}; no further transitions", "do_not_replay")
    if command.event == "withdraw":
        return "withdrawn", ledger
    next_status = _TABLES[kind].get((status, command.event))
    if next_status is None:
        raise _Rejected("ILLEGAL_TRANSITION", f"{command.event} is not a legal {kind} transition from {status}", "correct_input")
    r = command.receipt
    data = ledger.to_dict()
    event = command.event
    if event == "revise_quote":
        if r.quote_ref is None or r.quote_revision is None or r.quote_total is None or r.quote_total <= 0:
            raise _Rejected("QUOTE_REVISION_MISSING", "a revision links the quote reference, the advanced revision number, and a positive total", "correct_input")
        if ledger.round + 1 > policy.max_quote_revisions:
            raise _Rejected("REVISION_LIMIT_REACHED", f"policy allows {policy.max_quote_revisions} quote revisions; decline or escalate", "manual_reconciliation")
        data.update({"round": ledger.round + 1, "quote_total": str(r.quote_total), "latest_ref": r.quote_ref})
    elif event == "customer_accept":
        if r.customer_approval_ref is None:
            raise _Rejected("CUSTOMER_APPROVAL_MISSING", "customer acceptance of a revision links the customer's approval reference", "correct_input")
        data["resolved_amount"] = data["quote_total"]
    elif event == "propose_change_order":
        if r.change_order_proposal_digest is None or r.delta_amount is None:
            raise _Rejected("CHANGE_ORDER_MISSING", "a scope change links the contract change-order proposal digest and the delta amount", "correct_input")
        ceiling = (binding.quote_total * policy.max_change_order_percent / Decimal(100)).quantize(Decimal("0.01"))
        if abs(r.delta_amount) > ceiling:
            raise _Rejected("CHANGE_EXCEEDS_POLICY", f"change of {r.delta_amount} exceeds {policy.max_change_order_percent}% of the quote ({ceiling}); re-quote instead", "correct_input")
        data.update({"delta_amount": str(r.delta_amount), "latest_ref": r.change_order_ref})
    elif event == "approve_change":
        if r.customer_approval_ref is None or r.internal_approval_ref is None:
            raise _Rejected("CHANGE_APPROVALS_MISSING", "a change order is approved by both the customer and an internal approver", "await_approval")
        data["resolved_amount"] = str(binding.quote_total + Decimal(data["delta_amount"]))
    elif event == "plan_rework":
        if not r.work_packet_refs:
            raise _Rejected("REWORK_PACKET_MISSING", "rework binds at least one work packet", "correct_input")
        if ledger.round + 1 > policy.max_rework_rounds:
            raise _Rejected("REWORK_LIMIT_REACHED", f"policy allows {policy.max_rework_rounds} rework rounds; escalate", "manual_reconciliation")
        data["round"] = ledger.round + 1
    elif event == "resubmit":
        if not r.evidence_refs:
            raise _Rejected("RESUBMISSION_EVIDENCE_MISSING", "a resubmission links delivery evidence", "correct_input")
    elif event == "accept_rework":
        if r.evaluator_ref is None or r.customer_approval_ref is None:
            raise _Rejected("ACCEPTANCE_MISSING", "accepting rework links the evaluator and the customer's acceptance", "correct_input")
        data["resolved_amount"] = str(binding.accepted_amount)
    elif event == "reject_rework":
        if not r.rejection_reasons:
            raise _Rejected("REJECTION_REASONS_MISSING", "a rejection lists its reasons", "correct_input")
    elif event == "investigate":
        if not r.evidence_refs:
            raise _Rejected("INVESTIGATION_EVIDENCE_MISSING", "an investigation links its evidence", "correct_input")
    elif event == "resolve_credit_note":
        if r.credit_note_ref is None or r.credit_amount is None or r.credit_amount <= 0:
            raise _Rejected("CREDIT_NOTE_MISSING", "a credit-note resolution links the credit note and a positive credit amount", "correct_input")
        if r.credit_amount > ledger.at_risk_amount:
            raise _Rejected("CREDIT_EXCEEDS_DISPUTE", f"credit {r.credit_amount} exceeds the disputed amount {ledger.at_risk_amount}", "correct_input")
        data.update({"credit_amount": str(r.credit_amount), "resolved_amount": str(r.credit_amount), "latest_ref": r.credit_note_ref})
    elif event == "send_reminder":
        step_index = ledger.reminders_sent
        if step_index >= len(policy.dunning_ladder):
            raise _Rejected("DUNNING_LADDER_EXHAUSTED", "every dunning step was sent; agree a plan, escalate to collections, or write off", "manual_reconciliation")
        step = policy.dunning_ladder[step_index]
        if r.days_overdue is None or r.days_overdue < step.days_overdue:
            raise _Rejected("REMINDER_TOO_EARLY", f"step {step_index + 1} fires at {step.days_overdue} days overdue", "correct_input")
        if r.reminder_channel != step.channel:
            raise _Rejected("REMINDER_CHANNEL_MISMATCH", f"step {step_index + 1} uses {step.channel}", "correct_input")
        data["reminders_sent"] = step_index + 1
    elif event == "record_promise":
        if r.promised_payment_date is None or _parsed_timestamp(r.promised_payment_date) <= _parsed_timestamp(command.occurred_at):
            raise _Rejected("PROMISE_DATE_INVALID", "a promise to pay carries a future date", "correct_input")
    elif event == "agree_payment_plan":
        if r.installment_count is None or r.installment_count > policy.max_payment_plan_installments or len(r.installment_amounts) != r.installment_count:
            raise _Rejected("PAYMENT_PLAN_INVALID", f"a plan lists each installment, at most {policy.max_payment_plan_installments}", "correct_input")
        if sum(r.installment_amounts, Decimal("0")) != ledger.at_risk_amount:
            raise _Rejected("PAYMENT_PLAN_TOTAL_MISMATCH", "installments must sum to the outstanding amount", "correct_input")
    elif event == "record_payment":
        if not r.payment_refs or r.paid_amount is None or r.paid_amount <= 0:
            raise _Rejected("PAYMENT_MISSING", "payment links payment references and a positive amount", "correct_input")
        if r.paid_amount < ledger.at_risk_amount:
            raise _Rejected("PAYMENT_SHORT", f"paid {r.paid_amount} is below the outstanding {ledger.at_risk_amount}; record a plan instead", "correct_input")
        data["resolved_amount"] = str(r.paid_amount)
    elif event == "escalate_to_collections":
        if r.collections_agency_ref is None or r.days_overdue is None or r.days_overdue < policy.collections_after_days:
            raise _Rejected("COLLECTIONS_TOO_EARLY", f"collections escalation needs the agency reference and {policy.collections_after_days}+ days overdue", "correct_input")
        data["latest_ref"] = r.collections_agency_ref
    elif event == "write_off":
        if r.write_off_approval_ref is None:
            raise _Rejected("WRITE_OFF_APPROVAL_MISSING", "a write-off carries its approval reference", "await_approval")
        if ledger.at_risk_amount > policy.max_write_off_amount:
            raise _Rejected("WRITE_OFF_EXCEEDS_POLICY", f"{ledger.at_risk_amount} exceeds the {policy.max_write_off_amount} write-off limit; escalate to collections", "manual_reconciliation")
        data["resolved_amount"] = str(ledger.at_risk_amount)
    elif event == "assess_claim":
        if r.covered is None or not r.evidence_refs:
            raise _Rejected("CLAIM_ASSESSMENT_MISSING", "a claim assessment states coverage and links evidence", "correct_input")
        next_status = "assessed_covered" if r.covered else "assessed_not_covered"
        data["covered"] = r.covered
    elif event == "schedule_remedy":
        if not r.work_packet_refs:
            raise _Rejected("REMEDY_PACKET_MISSING", "a remedy binds a work packet", "correct_input")
    elif event == "complete_remedy":
        if r.remedy_ref is None or not r.evidence_refs:
            raise _Rejected("REMEDY_EVIDENCE_MISSING", "a completed remedy links the remedy reference and evidence", "correct_input")
        data["latest_ref"] = r.remedy_ref
    elif event == "requote":
        if r.new_lead_ref is None:
            raise _Rejected("LEAD_MISSING", "an uncovered claim is re-quoted as a new lead", "correct_input")
        data["latest_ref"] = r.new_lead_ref
    elif event == "make_offer":
        if r.offer_ref is None or r.discount_percent is None:
            raise _Rejected("OFFER_MISSING", "a win-back offer links the offer reference and discount percent", "correct_input")
        if r.discount_percent > policy.max_winback_discount_percent:
            raise _Rejected("DISCOUNT_EXCEEDS_POLICY", f"discount {r.discount_percent}% exceeds the {policy.max_winback_discount_percent}% limit", "await_approval")
        if ledger.offers_made + 1 > policy.max_winback_offers:
            raise _Rejected("OFFER_LIMIT_REACHED", f"policy allows {policy.max_winback_offers} win-back offers", "manual_reconciliation")
        data.update({"offers_made": ledger.offers_made + 1, "discount_percent": str(r.discount_percent), "latest_ref": r.offer_ref})
    elif event == "accept_offer":
        if r.renewal_offer_ref is None or r.customer_approval_ref is None:
            raise _Rejected("RENEWAL_MISSING", "a won-back renewal links the renewal offer and the customer's acceptance", "correct_input")
        data["latest_ref"] = r.renewal_offer_ref
    return next_status, CaseLedger.model_validate(data)


class ServiceExceptionCase(_StrictModel):
    schema_id: Literal["lightbulb.service_exception_case.v1"] = Field(default=EXCEPTION_CASE_SCHEMA, alias="schema")
    case_ref: OpaqueRef
    kind: ExceptionKind
    policy_digest: Sha256Digest
    binding: CaseBinding
    status: CaseStatus
    version: int = Field(ge=1, le=MAX_CASE_TRANSITIONS)
    transition_history: tuple[CaseTransition, ...] = Field(min_length=1, max_length=MAX_CASE_TRANSITIONS)
    ledger: CaseLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _case_is_exact(self, info: ValidationInfo) -> "ServiceExceptionCase":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("case version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            values = [str(getattr(item.command, field_name)) for item in history]
            if len(values) != len(set(values)):
                raise ValueError(f"historical {field_name} values must be unique")
        prefix: tuple[CaseTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.policy_digest, self.binding, self.kind, self.case_ref, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.policy_digest, self.binding, self.kind, self.case_ref, history):
            raise ValueError("state_digest must commit the exact case")
        policy: ServiceExceptionPolicy | None = (info.context or {}).get("service_exception_policy")
        if policy is not None:
            if policy.policy_digest != self.policy_digest:
                raise ValueError("case belongs to a different exception policy")
            status, ledger = "opened", _opening_ledger(self.kind, self.binding, history[0].command)
            for transition in history[1:]:
                try:
                    status, ledger = _apply(policy, self.kind, self.binding, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the case table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("case status and ledger must be derived from history")
        return self

    def resolution(self) -> "CaseResolution":
        return resolve_case(self)


def _opening_ledger(kind: str, binding: CaseBinding, command: ServiceExceptionCommand) -> CaseLedger:
    r = command.receipt
    at_risk = {
        "quote_revision": binding.quote_total,
        "scope_change": binding.quote_total,
        "acceptance_rework": binding.accepted_amount if binding.accepted_amount > 0 else binding.quote_total,
        "invoice_dispute": r.disputed_amount or Decimal("0"),
        "collection_delinquency": binding.outstanding_receivable,
        "warranty_claim": Decimal("0"),
        "churn_winback": binding.quote_total,
    }[kind]
    return CaseLedger(quote_total=binding.quote_total, at_risk_amount=at_risk)


def _binding_from_cycle(state: ServiceBusinessCycleState, origin_stage: str) -> CaseBinding:
    ledger = state.ledger
    acceptance_at = next((item.command.occurred_at for item in state.transition_history if item.command.stage == "verify_acceptance"), None)
    return CaseBinding(cycle_ref=state.scope.cycle_ref, cycle_state_digest=state.state_digest, cycle_status=state.status, origin_stage=origin_stage, customer_ref=state.scope.customer_ref, currency=state.scope.currency, quote_total=ledger.quote_total, outstanding_receivable=max(ledger.invoiced_amount - ledger.collected_amount, Decimal("0")), invoiced_amount=ledger.invoiced_amount, accepted_amount=ledger.accepted_amount, renewal_decision=ledger.renewal_decision, acceptance_verified_at=acceptance_at)


def open_exception_case(policy: ServiceExceptionPolicy | Mapping[str, Any], cycle: ServiceBusinessCycleState | Mapping[str, Any], *, kind: str, case_ref: str, opened_at: str, actor_ref: str, receipt: ExceptionReceipt | Mapping[str, Any] | None = None, reason: str | None = None) -> ServiceExceptionCase:
    """Open a case against a cycle; the cycle's own facts decide whether the kind is admissible now."""

    parsed_policy = ServiceExceptionPolicy.model_validate(_detached(policy))
    parsed_cycle = ServiceBusinessCycleState.model_validate(_detached(cycle))
    if kind not in _TABLES:
        raise ValueError(f"unknown exception kind {kind!r}")
    completed = [str(item.command.stage) for item in parsed_cycle.transition_history if item.command.event == "complete_stage"]
    current = STAGE_ORDER[len(completed)] if parsed_cycle.status not in TERMINAL_CYCLE_STATUSES and len(completed) < len(STAGE_ORDER) else None
    reached = set(completed) | ({current} if current else set())
    origins = [stage for stage in _ORIGIN_STAGE_BY_KIND[kind] if stage in reached]
    if not origins:
        raise ValueError(f"{kind} can only be opened once the cycle reaches {', '.join(_ORIGIN_STAGE_BY_KIND[kind])}; it is at {parsed_cycle.status}")
    if parsed_policy.currency != parsed_cycle.scope.currency:
        raise ValueError("exception policy currency must match the cycle currency")
    origin = origins[-1]
    binding = _binding_from_cycle(parsed_cycle, origin)
    parsed_receipt = ExceptionReceipt.model_validate(_detached(receipt) if receipt is not None else {})
    if kind == "invoice_dispute":
        if parsed_receipt.disputed_amount is None or parsed_receipt.disputed_amount <= 0 or parsed_receipt.disputed_amount > binding.invoiced_amount:
            raise ValueError("an invoice dispute states a disputed amount within the invoiced total")
    if kind == "collection_delinquency" and binding.outstanding_receivable <= 0:
        raise ValueError("nothing is outstanding; there is no delinquency to pursue")
    if kind == "churn_winback" and binding.renewal_decision != "declined":
        raise ValueError("win-back applies only after the customer declined renewal")
    if kind == "warranty_claim":
        if binding.acceptance_verified_at is None:
            raise ValueError("a warranty claim needs an accepted delivery")
        age_days = (_parsed_timestamp(_timestamp(opened_at, field_name="opened_at")) - _parsed_timestamp(binding.acceptance_verified_at)).days
        if age_days > parsed_policy.warranty_window_days:
            raise ValueError(f"claim opened {age_days} days after acceptance; the warranty window is {parsed_policy.warranty_window_days} days")
        if parsed_receipt.defect_description is None:
            raise ValueError("a warranty claim describes the defect")
    if kind == "acceptance_rework" and not parsed_receipt.rejection_reasons:
        raise ValueError("rework starts from the customer's or evaluator's rejection reasons")
    genesis = _state_digest(parsed_policy.policy_digest, binding, kind, case_ref, ())
    command = ServiceExceptionCommand.model_validate(seal_exception_command({"event": _OPEN_EVENT[kind],"transition_ref": f"open:{case_ref}", "idempotency_key": f"{case_ref}:open", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": parsed_receipt.to_dict(), "reason": reason}))
    transition = CaseTransition(to_version=1, prior_state_digest=genesis, to_status="opened", transition_digest=_transition_digest(1, genesis, "opened", command), command=command)
    ledger = _opening_ledger(kind, binding, command)
    return ServiceExceptionCase.model_validate({"case_ref": case_ref, "kind": kind, "policy_digest": parsed_policy.policy_digest, "binding": binding.to_dict(), "status": "opened", "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_policy.policy_digest, binding, kind, case_ref, (transition,))}, context={"service_exception_policy": parsed_policy})


# The opening transition reuses the kind's first legal event name purely as a label; it never advances the table.
_OPEN_EVENT: dict[str, str] = {"quote_revision": "revise_quote", "scope_change": "propose_change_order", "acceptance_rework": "plan_rework", "invoice_dispute": "investigate", "collection_delinquency": "send_reminder", "warranty_claim": "assess_claim", "churn_winback": "make_offer"}


class CaseRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "CaseRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class CaseTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: CaseEvent
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: CaseStatus
    to_status: CaseStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: CaseRecovery


class CaseEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    reminder_sent: Literal[False] = False
    credit_note_issued: Literal[False] = False
    balance_written_off: Literal[False] = False
    discount_granted: Literal[False] = False


class CaseTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.service_exception_transition_result.v1"] = Field(default=EXCEPTION_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    case: ServiceExceptionCase | None = None
    receipt: CaseTransitionReceipt
    resolution: "CaseResolution | None" = None
    effect_boundary: CaseEffectBoundary = Field(default_factory=CaseEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "CaseTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.case is None):
            raise ValueError("result must carry a case exactly when a candidate was materialized")
        return self


def advance_exception_case(policy: ServiceExceptionPolicy | Mapping[str, Any], case: ServiceExceptionCase | Mapping[str, Any], command: ServiceExceptionCommand | Mapping[str, Any]) -> CaseTransitionResult:
    """Materialize one replay-fenced case transition; never sends, issues, grants, or writes off anything."""

    parsed_policy = ServiceExceptionPolicy.model_validate(_detached(policy))
    parsed_case = ServiceExceptionCase.model_validate(_detached(case), context={"service_exception_policy": parsed_policy})
    parsed_command = ServiceExceptionCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_case.version, parsed_case.status, parsed_case.state_digest

    def rejected(exc: _Rejected) -> CaseTransitionResult:
        receipt = CaseTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=CaseRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return CaseTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_case.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current case", "refresh_state")
        if _parsed_timestamp(parsed_command.occurred_at) < _parsed_timestamp(parsed_case.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_CASE_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the case reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_policy, parsed_case.kind, parsed_case.binding, from_status, parsed_case.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = CaseTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_case.transition_history, transition)
    new_case = ServiceExceptionCase.model_validate({"case_ref": parsed_case.case_ref, "kind": parsed_case.kind, "policy_digest": parsed_case.policy_digest, "binding": parsed_case.binding.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_case.policy_digest, parsed_case.binding, parsed_case.kind, parsed_case.case_ref, history)}, context={"service_exception_policy": parsed_policy})
    receipt = CaseTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, status="candidate_materialized", from_version=from_version, to_version=new_case.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_case.state_digest, recovery=CaseRecovery(disposition="not_required"))
    return CaseTransitionResult(candidate_validated=True, case=new_case, receipt=receipt, resolution=resolve_case(new_case) if next_status in TERMINAL_CASE_STATUSES else None)


# --------------------------------------------------------------------------- #
# Resolution back into the loop
# --------------------------------------------------------------------------- #


class CaseResolution(_StrictModel):
    """How the cycle continues after a terminal case: which stage resumes and which ledger facts change."""

    case_ref: OpaqueRef
    kind: ExceptionKind
    outcome: CaseStatus
    cycle_ref: OpaqueRef
    resume_stage: ResumeStage | None = None
    cycle_disposition: Literal["resume", "disqualify", "cancel", "complete", "new_cycle"]
    quote_total_after: Decimal | None = None
    receivable_adjustment: Decimal = Field(default=Decimal("0"), validate_default=True)
    accepted_amount_after: Decimal | None = None
    renewal_decision_after: str | None = None
    new_lead_ref: OpaqueRef | None = None
    learning: BoundedText

    @field_validator("quote_total_after", "accepted_amount_after", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("receivable_adjustment", mode="before")
    @classmethod
    def _adjustment(cls, value: Any) -> Decimal:
        return _signed(value, "receivable_adjustment")


CaseTransitionResult.model_rebuild()


def resolve_case(case: ServiceExceptionCase | Mapping[str, Any]) -> CaseResolution:
    parsed = ServiceExceptionCase.model_validate(_detached(case))
    if parsed.status not in TERMINAL_CASE_STATUSES:
        raise ValueError(f"case {parsed.case_ref} is {parsed.status}; only terminal cases resolve")
    kind, status, ledger, binding = parsed.kind, parsed.status, parsed.ledger, parsed.binding
    base = {"case_ref": parsed.case_ref, "kind": kind, "outcome": status, "cycle_ref": binding.cycle_ref}
    if status == "withdrawn":
        return CaseResolution(**base, resume_stage=binding.origin_stage if binding.origin_stage != "market" else None, cycle_disposition="resume", learning=f"{kind} withdrawn without effect")  # type: ignore[arg-type]
    if kind == "quote_revision":
        if status == "customer_accepted":
            return CaseResolution(**base, resume_stage="quote", cycle_disposition="resume", quote_total_after=ledger.quote_total, learning=f"quote accepted after {ledger.round} revision(s); revised total {ledger.quote_total}")
        return CaseResolution(**base, cycle_disposition="disqualify", learning=f"customer declined after {ledger.round} revision(s)")
    if kind == "scope_change":
        if status == "change_approved":
            return CaseResolution(**base, resume_stage="deliver", cycle_disposition="resume", quote_total_after=ledger.resolved_amount, learning=f"scope change of {ledger.delta_amount} approved; ceiling now {ledger.resolved_amount}")
        return CaseResolution(**base, resume_stage="deliver", cycle_disposition="resume", learning="scope change rejected; deliver within the original scope")
    if kind == "acceptance_rework":
        if status == "accepted":
            return CaseResolution(**base, resume_stage="verify_acceptance", cycle_disposition="resume", accepted_amount_after=ledger.resolved_amount, learning=f"work accepted after {ledger.round} rework round(s)")
        return CaseResolution(**base, cycle_disposition="cancel", learning=f"acceptance escalated after {ledger.round} rework round(s); dispute outside the loop")
    if kind == "invoice_dispute":
        if status == "resolved_credit_note":
            return CaseResolution(**base, resume_stage="collect", cycle_disposition="resume", receivable_adjustment=-ledger.credit_amount, learning=f"credit note of {ledger.credit_amount} against a {ledger.at_risk_amount} dispute")
        return CaseResolution(**base, resume_stage="collect", cycle_disposition="resume", learning="invoice upheld; collect in full")
    if kind == "collection_delinquency":
        if status == "paid":
            return CaseResolution(**base, resume_stage="collect", cycle_disposition="resume", learning=f"collected {ledger.resolved_amount} after {ledger.reminders_sent} reminder(s)")
        if status == "written_off":
            return CaseResolution(**base, resume_stage="support_renew", cycle_disposition="resume", receivable_adjustment=-ledger.resolved_amount, learning=f"wrote off {ledger.resolved_amount} after {ledger.reminders_sent} reminder(s)")
        return CaseResolution(**base, cycle_disposition="cancel", learning=f"{ledger.at_risk_amount} escalated to collections after {ledger.reminders_sent} reminder(s)")
    if kind == "warranty_claim":
        if status == "remedied":
            return CaseResolution(**base, resume_stage="support_renew", cycle_disposition="resume", learning="warranty defect remedied inside the support window")
        if status == "requoted":
            return CaseResolution(**base, resume_stage="support_renew", cycle_disposition="new_cycle", new_lead_ref=ledger.latest_ref, learning="claim outside coverage; re-quoted as new work")
        return CaseResolution(**base, resume_stage="support_renew", cycle_disposition="resume", learning="claim assessed as not covered")
    if status == "won_back":
        return CaseResolution(**base, resume_stage="support_renew", cycle_disposition="resume", renewal_decision_after="renewed", learning=f"customer won back with a {ledger.discount_percent}% offer after {ledger.offers_made} offer(s)")
    return CaseResolution(**base, resume_stage="learn", cycle_disposition="resume", renewal_decision_after="declined", learning=f"customer lost after {ledger.offers_made} win-back offer(s)")


# --------------------------------------------------------------------------- #
# Portfolio assessment
# --------------------------------------------------------------------------- #


class ExceptionPortfolioAssessment(_StrictModel):
    schema_id: Literal["lightbulb.service_exception_portfolio_assessment.v1"] = Field(default=EXCEPTION_PORTFOLIO_SCHEMA, alias="schema")
    loop_extension: Literal["service.market_to_renewal_business.exceptions@0.1.0"] = SERVICE_EXCEPTIONS_LOOP_EXTENSION
    case_count: int = Field(ge=0)
    open_count: int = Field(ge=0)
    by_kind: dict[str, int] = Field(default_factory=dict)
    receivable_at_risk: Decimal
    credited_amount: Decimal
    written_off_amount: Decimal
    rework_rate_percent: Decimal | None = None
    dispute_rate_percent: Decimal | None = None
    winback_rate_percent: Decimal | None = None
    overdue_cases_past_ladder: int = Field(ge=0)
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=30)
    recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    effect_boundary: CaseEffectBoundary = Field(default_factory=CaseEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("receivable_at_risk", "credited_amount", "written_off_amount", "rework_rate_percent", "dispute_rate_percent", "winback_rate_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ExceptionPortfolioAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ExceptionPortfolioAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_exception_portfolio(policy: ServiceExceptionPolicy | Mapping[str, Any], cases: Sequence[ServiceExceptionCase | Mapping[str, Any]], *, cycles_completed: int, assessed_at: str) -> ExceptionPortfolioAssessment:
    parsed_policy = ServiceExceptionPolicy.model_validate(_detached(policy))
    parsed = [ServiceExceptionCase.model_validate(_detached(item), context={"service_exception_policy": parsed_policy}) for item in cases]
    if cycles_completed < 0:
        raise ValueError("cycles_completed cannot be negative")
    by_kind: dict[str, int] = {}
    for case in parsed:
        by_kind[case.kind] = by_kind.get(case.kind, 0) + 1
    open_cases = [case for case in parsed if case.status not in TERMINAL_CASE_STATUSES]
    at_risk = sum((case.ledger.at_risk_amount for case in open_cases if case.kind in {"collection_delinquency", "invoice_dispute"}), Decimal("0"))
    credited = sum((case.ledger.credit_amount for case in parsed if case.status == "resolved_credit_note"), Decimal("0"))
    written_off = sum((case.ledger.resolved_amount for case in parsed if case.status == "written_off"), Decimal("0"))
    quantum = Decimal("0.01")
    denominator = Decimal(max(cycles_completed, 1))
    rework = (Decimal(by_kind.get("acceptance_rework", 0)) / denominator * 100).quantize(quantum) if cycles_completed else None
    dispute = (Decimal(by_kind.get("invoice_dispute", 0)) / denominator * 100).quantize(quantum) if cycles_completed else None
    winbacks = [case for case in parsed if case.kind == "churn_winback" and case.status in {"won_back", "lost"}]
    winback = (Decimal(sum(1 for case in winbacks if case.status == "won_back")) / Decimal(len(winbacks)) * 100).quantize(quantum) if winbacks else None
    past_ladder = sum(1 for case in open_cases if case.kind == "collection_delinquency" and case.ledger.reminders_sent >= len(parsed_policy.dunning_ladder))
    learnings: list[str] = []
    recommendations: list[str] = []
    if rework is not None and rework > Decimal("25"):
        learnings.append(f"rework opened on {rework}% of cycles")
        recommendations.append("tighten acceptance criteria at quote time and add an independent evaluator before customer review")
    if dispute is not None and dispute > Decimal("10"):
        learnings.append(f"invoices disputed on {dispute}% of cycles")
        recommendations.append("bind every invoice line to an accepted deliverable and send the acceptance record with the invoice")
    if at_risk > 0:
        learnings.append(f"{at_risk.quantize(quantum)} {parsed_policy.currency} receivable sits in open disputes or delinquencies")
    if past_ladder:
        learnings.append(f"{past_ladder} delinquency case(s) exhausted the dunning ladder")
        recommendations.append("raise the deposit percent or shorten net terms for this profile; escalate exhausted cases")
    if written_off > 0:
        learnings.append(f"{written_off.quantize(quantum)} {parsed_policy.currency} written off")
    if winback is not None:
        learnings.append(f"win-back succeeded on {winback}% of declined renewals")
        if winback < Decimal("30"):
            recommendations.append("capture decline reasons before offering discounts; the offer is not the problem")
    if not learnings:
        learnings.append("no exception pressure on the loop")
    payload = {"case_count": len(parsed), "open_count": len(open_cases), "by_kind": dict(sorted(by_kind.items())), "receivable_at_risk": str(at_risk.quantize(quantum)), "credited_amount": str(credited.quantize(quantum)), "written_off_amount": str(written_off.quantize(quantum)), "rework_rate_percent": None if rework is None else str(rework), "dispute_rate_percent": None if dispute is None else str(dispute), "winback_rate_percent": None if winback is None else str(winback), "overdue_cases_past_ladder": past_ladder, "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at}
    payload["assessment_digest"] = _sealed_digest(ExceptionPortfolioAssessment, payload, "assessment_digest")
    return ExceptionPortfolioAssessment.model_validate(payload)


SERVICE_EXCEPTION_CATALOG: dict[str, dict[str, Any]] = {
    kind: {"origin_stages": list(_ORIGIN_STAGE_BY_KIND[kind]), "events": sorted({event for (_, event) in _TABLES[kind]}), "terminal_statuses": sorted({status for status in {to for to in _TABLES[kind].values()} if status in TERMINAL_CASE_STATUSES} | {"withdrawn"}), "bound_primitives": list(_BOUND_PRIMITIVES_BY_KIND[kind])}
    for kind in _TABLES
}

__all__ = [
    "EXCEPTION_CASE_SCHEMA",
    "EXCEPTION_COMMAND_SCHEMA",
    "EXCEPTION_POLICY_SCHEMA",
    "EXCEPTION_PORTFOLIO_SCHEMA",
    "EXCEPTION_RESULT_SCHEMA",
    "MAX_CASE_TRANSITIONS",
    "SERVICE_EXCEPTION_CATALOG",
    "SERVICE_EXCEPTIONS_LOOP_EXTENSION",
    "TERMINAL_CASE_STATUSES",
    "CaseBinding",
    "CaseEffectBoundary",
    "CaseLedger",
    "CaseRecovery",
    "CaseResolution",
    "CaseTransition",
    "CaseTransitionReceipt",
    "CaseTransitionResult",
    "DunningStep",
    "ExceptionPortfolioAssessment",
    "ExceptionReceipt",
    "ServiceExceptionCase",
    "ServiceExceptionCommand",
    "ServiceExceptionPolicy",
    "advance_exception_case",
    "assess_exception_portfolio",
    "exception_command_digest",
    "open_exception_case",
    "policy_for_plan",
    "resolve_case",
    "seal_exception_command",
    "seal_service_exception_policy",
]

SERVICE_BUSINESS_GOLDEN_LOOP_REF = SERVICE_BUSINESS_GOLDEN_LOOP
