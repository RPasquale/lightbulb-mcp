"""The wind-down chain: one replay-fenced lifecycle from a directors' resolution to closed books.

Killing a company is the one operation nobody had fenced.  Every other chain
proves how a piece of money ends -- a refund clears, a subscription cancels, a
receivable is recovered or written off, a payable is paid, a worker is
offboarded and paid out, a registration is surrendered, a bank account
reconciles to zero -- and a stop button ignores all of them.
``WIND_DOWN_LIFECYCLE`` makes the shutdown consume those endings in order:

    decided -> customers_notified -> refunds_settled -> subscriptions_cancelled
            -> receivables_closed -> payables_settled -> final_pay_run_done
            -> deregistered -> accounts_closed -> closed        (terminal)
    decided | customers_notified -> abandoned                   (terminal)
    any non-terminal             -> halted                      (terminal)

Every hop consumes the sealed terminal state of the chain that already owns
that money (``refund_and_dispute_chain``, ``spend_control_chain``
commitments, ``subscription_chain``, ``collections_chain`` with its write-off
proofs, ``payables_chain`` plus ``disbursement_run``, ``employment_chain``
plus ``payroll_run_chain``, ``obligation_paper`` standing items,
``compliance_calendar``, ``bank_reconciliation``, ``finance_close`` and the
cost register), the platform's own lifecycle receipts
(``client.wind_down_company`` / ``client.close_company``), bound
communication execution receipts with ``permission_register`` eligibility, or
an operator-held lodgement receipt for the steps only a director can perform
(ASIC Form 6010, CRA RC145).

The opening hop is deliberately the hardest: a wind-down is a two-person
``wind_down`` authority decision bound to a self-naming directors' or
members' resolution *and* the platform's ``WINDING_DOWN`` lifecycle receipt,
raised on a task the platform is structurally unable to auto-accept.  An
auto-accepted task cannot start one.

What it hands to the rest of the runtime: :func:`cadence_stop_receipt` -- the
only reason ``CadenceWorker.control("stop")`` accepts once a wind-down state
exists; :func:`wind_down_flows` for the treasury; :func:`wind_down_exception`
for the exceptions desk's ``wind_down_blocked`` kind; and
:func:`wind_down_summary` / :func:`narrate_wind_down` for the brief and the
board pack.  Nothing here sends, refunds, cancels, files, revokes or closes
anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.ai_operator import AuthorizationProof, money
from lightbulb.company_bring_up import normalize_provider
from lightbulb.company_cadence_runner import CADENCE_LIFECYCLE
from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    EngineScope,
    BoundedText,
    CurrencyCode,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import ApprovalBinding, ExecutionReceipt, bind_approval
from lightbulb.compliance_calendar import ObligationKind
from lightbulb.employment_chain import (
    EMPLOYMENT_LIFECYCLE,
    HEADCOUNT_PROOF_SCHEMA,
    EmploymentPlan,
    authorization_evidence,
    headcount_receipt,
    require_authorization_proof,
)

WIND_DOWN_KIND = "wind_down_chain"
WIND_DOWN_GOLDEN_LOOP = "company.decision_to_closed_books@0.1.0"
WIND_DOWN_PLAN_SCHEMA = "lightbulb.wind_down_plan.v1"
RESOLUTION_SCHEMA = "lightbulb.wind_down_resolution.v1"
SOURCE_FACTS_SCHEMA = "lightbulb.wind_down_source_facts.v1"
MAX_WIND_DOWN_TRANSITIONS = 24
_HUNDRED = Decimal("100")
_EMPTY_LISTING_DIGEST = stable_digest([])

#: The audiences a wind-down must reach before any money moves.
NOTICE_AUDIENCES: tuple[str, ...] = ("customers", "staff", "suppliers")
#: The governed communication writes a notice may have been sent through.
NOTICE_TOOLS: frozenset[str] = frozenset({"gmail.send_email", "microsoft.send_email", "twilio.send_sms_turn"})
#: Cancelling a customer subscription is still the legacy ``stripe_dispatch``
#: HITL lane; it is not a governed catalog row yet.  Named, not pretended.
SUBSCRIPTION_CANCEL_TOOL = "stripe.subscriptions.cancel"
#: What each source chain's terminal state must say before the hop is allowed.
CLEARED_REFUND_STATUSES: frozenset[str] = frozenset({"cleared", "denied"})
TERMINATED_COMMITMENT_STATUSES: frozenset[str] = frozenset({"terminated"})
CLOSED_SUBSCRIPTION_STATUSES: frozenset[str] = frozenset({"cancelled", "trial_lapsed", "written_off"})
CLOSED_RECEIVABLE_STATUSES: frozenset[str] = frozenset({"recovered", "written_off"})
SETTLED_PAYABLE_STATUSES: frozenset[str] = frozenset({"paid", "cleared", "rejected"})
SETTLED_DISBURSEMENT_STATUSES: frozenset[str] = frozenset({"settled", "reconciled"})
LODGED_OBLIGATION_STATUSES: frozenset[str] = frozenset({"lodged", "paid"})
#: The employment statuses ``employment_chain.headcount_receipt`` does not count
#: as still employed; the engine re-derives the head count with the same rule.
LEFT_EMPLOYMENT_STATUSES: frozenset[str] = frozenset({"offboarded", "withdrawn"})
RESERVED_FINAL_LIABILITIES: tuple[str, ...] = ("payg_withholding", "superannuation")
#: A job or engagement in one of these is finished; anything else is still open.
CLOSED_JOB_STATUSES: frozenset[str] = frozenset({"reconciled", "cancelled"})
CLOSED_ENGAGEMENT_STATUSES: frozenset[str] = frozenset({"completed", "cancelled"})

StandingItemKind = Literal["business_registration", "tax_registration", "licence", "insurance_policy", "domain_name", "trademark"]

WIND_DOWN_STATUSES: tuple[str, ...] = ("decided", "customers_notified", "refunds_settled", "subscriptions_cancelled", "receivables_closed", "payables_settled", "final_pay_run_done", "deregistered", "accounts_closed", "closed", "abandoned", "halted")
TERMINAL_WIND_DOWN_STATUSES: frozenset[str] = frozenset({"closed", "abandoned", "halted"})
WIND_DOWN_EVENTS: tuple[str, ...] = ("decide", "notify", "settle_refunds", "cancel_subscriptions", "close_receivables", "settle_payables", "run_final_pay", "deregister", "close_accounts", "close", "abandon", "halt")
_LINEAR: tuple[tuple[str, str, str], ...] = (
    ("new", "decide", "decided"),
    ("decided", "notify", "customers_notified"),
    ("customers_notified", "settle_refunds", "refunds_settled"),
    ("refunds_settled", "cancel_subscriptions", "subscriptions_cancelled"),
    ("subscriptions_cancelled", "close_receivables", "receivables_closed"),
    ("receivables_closed", "settle_payables", "payables_settled"),
    ("payables_settled", "run_final_pay", "final_pay_run_done"),
    ("final_pay_run_done", "deregister", "deregistered"),
    ("deregistered", "close_accounts", "accounts_closed"),
    ("accounts_closed", "close", "closed"),
)
_WIND_DOWN_TABLE: dict[tuple[str, str], str] = {
    **{(status, event): to_status for status, event, to_status in _LINEAR},
    **{(status, "abandon"): "abandoned" for status in ("decided", "customers_notified")},
    **{(status, "halt"): "halted" for status in WIND_DOWN_STATUSES if status not in TERMINAL_WIND_DOWN_STATUSES},
}


class WindDownError(ValueError):
    """A receipt builder refusing an artifact that does not line up; carries the code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WindDownError(code, message)


# --------------------------------------------------------------------------- #
# Wind-down evidence adapters. Financial sources replay their owning lifecycle.
# --------------------------------------------------------------------------- #

ELIGIBILITY_FACTS_SCHEMA = "lightbulb.permission_register_eligibility.v1"
PERMISSION_REGISTER_ENTITY = "permission_register"
EXECUTION_REQUEST_SCHEMA = "lightbulb.governed_execution_request.v1"
#: ``entity`` of every sealed source state this chain consumes, by hop.
REFUND_ENTITY = "refund_case"
COMMITMENT_ENTITY = "commitment"
SUBSCRIPTION_ENTITY = "subscription"
RECEIVABLE_ENTITY = "receivable_case"
PAYABLE_ENTITY = "payable_case"
DISBURSEMENT_ENTITY = "disbursement_run"
STANDING_ENTITY = "standing_paper"
PAY_RUN_ENTITY = "pay_run"
OBLIGATION_ENTITY = "obligation"
BANK_ENTITY = "bank_reconciliation"
CLOSE_ENTITY = "period_close"
COST_REGISTER_ENTITY = "cost_register"


class SourceFacts(StrictModel):
    """One sealed terminal state of a chain that owns a piece of this company.

    The same shape carries every source: what engine sealed it, which entity
    it is, where it ended, and the one number or instant the wind-down guard
    needs from it.  Nothing is copied out of a source that a guard does not
    read.
    """

    schema_id: Literal["lightbulb.wind_down_source_facts.v1"] = Field(default=SOURCE_FACTS_SCHEMA, alias="schema")
    engine: ShortText
    entity_ref: OpaqueRef
    status: ShortText
    state_digest: Sha256Digest
    plan_digest: Sha256Digest
    kind: ShortText | None = None
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    opened_at: str | None = None
    settled_at: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    reserved: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    detail: ShortText | None = None

    @field_validator("reserved", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="amount")

    @field_validator("opened_at", "settled_at", "period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class EligibilityFacts(StrictModel):
    """``_permission_gates.eligibility``: the register's own answer for one channel and audience at one instant."""

    schema_id: Literal["lightbulb.permission_register_eligibility.v1"] = Field(default=ELIGIBILITY_FACTS_SCHEMA, alias="schema")
    channel: Literal["email", "sms", "post"]
    company_ref: OpaqueRef
    scope: ShortText
    assessed_at: str
    eligible_count: int = Field(ge=0, le=1000000)
    suppressed_count: int = Field(ge=0, le=1000000)
    register_state_digest: Sha256Digest
    suppression_digest: Sha256Digest
    permission_receipt: dict[str, Any]

    @field_validator("assessed_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")


def _plan_digest(value: Any) -> str | None:
    if value is None:
        return None
    raw = detached(value)
    if isinstance(raw, Mapping):
        return None if raw.get("plan_digest") is None else str(raw["plan_digest"])
    return None


def _sealed(state: Mapping[str, Any] | Any, *, entity: str, engine: str, plan: Any, code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The sealed state's envelope and ledger, or a refusal naming the artifact that did not line up."""

    raw = dict(detached(state))
    _require(str(raw.get("entity", "")) == entity, code, f"expected a sealed {engine} {entity} state, got {raw.get('entity')!r}")
    for key in ("status", "state_digest", "plan_digest"):
        _require(bool(raw.get(key)), code, f"the {entity} state lacks {key}")
    digest = _plan_digest(plan)
    _require(digest is None or digest == str(raw["plan_digest"]), code, f"the {entity} state belongs to a different {engine} plan")
    return raw, dict(raw.get("ledger") or {})


def _plan_at(plans: Sequence[Any] | None, index: int) -> Any:
    """The source plan for one state: aligned by position, or a single plan applied to all."""

    items = list(plans or ())
    if not items:
        return None
    return items[0] if len(items) == 1 else items[index] if index < len(items) else None


def eligibility(register_state: Mapping[str, Any] | Any, *, channel: str, at: str, company_ref: str, scope: str) -> dict[str, Any]:
    """Project the canonical permission receipt after replaying its consent sources."""
    from lightbulb.permission_register import EligibilityReceipt, verify_eligibility
    _require(scope=="wind_down_notice","PERMISSION_SCOPE_MISSING","this adapter admits wind-down notices only")
    try:
        proof=EligibilityReceipt.model_validate(detached(register_state))
        proof=verify_eligibility(proof,suppression_digest=proof.suppression_digest,channel=channel,at=at,company_ref=company_ref)
    except (ValueError,TypeError,KeyError) as exc:
        raise WindDownError("PERMISSION_REGISTER_INVALID","retain current eligibility over full canonical consent sources") from exc
    return EligibilityFacts(channel=channel,company_ref=company_ref,scope=scope,assessed_at=proof.as_of,
        eligible_count=len(proof.eligible_endpoints),suppressed_count=len(proof.endpoints)-len(proof.eligible_endpoints),
        register_state_digest=stable_digest(sorted(item.state["state_digest"] for item in proof.source_states)),
        suppression_digest=proof.suppression_digest,permission_receipt=proof.to_dict()).to_dict()


def exact_request(execution: Mapping[str, Any] | Any, request: Mapping[str, Any] | Any, *, tools: frozenset[str] | set[str], effect: str = "write") -> dict[str, Any]:
    """Replay a canonical connector request and its executed custody fingerprint."""
    from lightbulb.connector_execution import ConnectorExecutionRequest
    from lightbulb._execution_gates import exact_request as check_request
    receipt=ExecutionReceipt.model_validate(detached(execution))
    try:
        call=ConnectorExecutionRequest.model_validate(detached(request))
    except (ValueError,TypeError) as exc:
        raise WindDownError("EXECUTION_REQUEST_SCHEMA_MISMATCH","retain the full canonical connector request") from exc
    _require(receipt.tool==call.tool and receipt.tool in tools,"EXECUTION_TOOL_MISMATCH","execution must use the requested admitted tool")
    _require(receipt.effect==effect,"EXECUTION_EFFECT_MISMATCH","execution must prove this effect")
    try:
        check_request(call,receipt,tool=call.tool,arguments=call.arguments,idempotency_key=call.idempotency_key)
    except ValueError as exc:
        raise WindDownError("EXECUTION_NOT_BOUND","execution must bind the approved exact request and scope") from exc
    return {"tool":receipt.tool,"execution_receipt_digest":receipt.execution_digest,"request_digest":receipt.request_digest,
        "journal_ref":receipt.journal_ref,"approval_ref":receipt.approval_ref,"sent_at":receipt.completed_at,
        "request":{**call.to_dict(),**call.arguments},"source_request":call.to_dict(),"source_execution":receipt.to_dict()}


def verify_authorization(proof: AuthorizationProof | Mapping[str, Any], *, category: str, entity_ref: str | None = None) -> dict[str, Any]:
    """``authority_matrix.verify_authorization``: a standing proof of one category, for one entity, without binding this command."""

    parsed_proof = AuthorizationProof.model_validate(detached(proof))
    _require(parsed_proof.category == category, "AUTHORIZATION_CATEGORY_MISMATCH", f"the proof carries {parsed_proof.category} authority, not {category}")
    _require(entity_ref is None or parsed_proof.entity_ref == entity_ref, "AUTHORIZATION_ENTITY_MISMATCH", f"the proof authorizes {parsed_proof.entity_ref}, not {entity_ref}")
    return {"category": parsed_proof.category, "entity_ref": parsed_proof.entity_ref, "amount": str(parsed_proof.amount), "currency": parsed_proof.currency, "approval_task_id": parsed_proof.approval_task_id, "approver_ref": parsed_proof.approver_ref, "proof_digest": parsed_proof.proof_digest, "decided_at": parsed_proof.decided_at}


def verify_paid_pay_run(run_state: Mapping[str, Any] | Any, *, source_plan: Any = None) -> dict[str, Any]:
    from lightbulb._wind_down_sources import source_facts
    try:
        return SourceFacts(**source_facts("payroll_run_chain", source_plan, run_state)).to_dict()
    except (ValueError,TypeError,KeyError) as exc:
        raise WindDownError("PAY_RUN_STATE_INVALID","retain a full canonical payroll plan and replayable run") from exc


def filing_receipt(lodgement: Mapping[str, Any] | Any) -> dict[str, Any]:
    """``obligation_paper.filing_receipt``: an operator-held lodgement, reduced to the four facts a guard reads."""

    raw = dict(detached(lodgement))
    for key in ("lodgement_ref", "lodged_at", "lodged_by"):
        _require(bool(raw.get(key)), "LODGEMENT_INCOMPLETE", f"a lodgement receipt lacks {key}")
    return {
        "lodgement_ref": str(raw["lodgement_ref"]),
        "lodged_at": timestamp(str(raw["lodged_at"]), field_name="lodged_at"),
        "lodged_by": str(raw["lodged_by"]),
        "amount": str(decimal_value(raw.get("amount", "0"), field_name="amount")),
        "kind": str(raw.get("kind") or "business_registration"),
        "operator_supplied": True,
    }


# --------------------------------------------------------------------------- #
# end evidence adapters
# --------------------------------------------------------------------------- #


class WindDownPlan(StrictModel):
    """What the shutdown enforces: the notice floors, the refund window, the registrations to surrender, and the money the decision authorises."""

    schema_id: str = Field(default=WIND_DOWN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: Literal["AU", "CA", "NZ", "UK", "US"]
    bundle_digest: Sha256Digest
    inventory_tenant_commitment: Sha256Digest | None = None
    inventory_company_commitment: Sha256Digest | None = None
    inventory_max_age_hours: int = Field(default=24, ge=1, le=168)
    customer_notice_days: int = Field(default=30, ge=0, le=180)
    staff_notice_days: int = Field(default=28, ge=0, le=90)
    refund_window_days: int = Field(default=30, ge=0, le=180)
    max_days_decision_to_close: int = Field(default=180, ge=30, le=730)
    settlement_reserve: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    require_second_approver: Literal[True] = True
    require_human_decision: Literal[True] = True
    registrations_to_surrender: tuple[StandingItemKind, ...] = ("business_registration",)
    required_final_obligations: tuple[ObligationKind, ...] = ("gst_bas", "payg_withholding", "superannuation", "annual_return")
    registrar_ref_pattern: ShortText = "^(asic:6010:[0-9]{6,12}|cra:rc145:[0-9A-Z]{6,20})$"
    employment_plan_digest: Sha256Digest | None = None
    payroll_plan_digest: Sha256Digest | None = None
    obligation_paper_plan_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("settlement_reserve", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="settlement_reserve")

    @field_validator("registrations_to_surrender", "required_final_obligations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> WindDownPlan:
        if len(self.registrations_to_surrender) != len(set(self.registrations_to_surrender)):
            raise ValueError("registrations_to_surrender must be unique")
        try:
            re.compile(self.registrar_ref_pattern)
        except re.error as exc:
            raise ValueError("registrar_ref_pattern must be a regular expression") from exc
        if not skip_digests(info) and self.plan_digest != sealed_digest(WindDownPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_wind_down(company_ref: str, *, currency: str, jurisdiction: str, bundle: Any, settlement_reserve: Any, tenant_id: str | None = None, company_id: str | None = None, overrides: Mapping[str, Any] | None = None) -> WindDownPlan:
    """Compile the plan against the cadence bundle being wound down; the bundle digest is the fence the decision hop checks."""

    # ``CadenceBundle.plan_digest`` is a property over ``bundle_digest``, so it
    # never survives ``to_dict``; both names are read, and neither is invented.
    raw_bundle = dict(detached(bundle))
    digest = getattr(bundle, "plan_digest", None) or raw_bundle.get("plan_digest") or raw_bundle.get("bundle_digest")
    _require(digest is not None, "BUNDLE_MISSING", "a wind-down names the sealed cadence bundle it is shutting down")
    digest = str(digest)
    payload = {
        "company_ref": company_ref,
        "currency": str(currency).upper(),
        "jurisdiction": str(jurisdiction).upper(),
        "bundle_digest": digest,
        "settlement_reserve": str(decimal_value(settlement_reserve, field_name="settlement_reserve")),
        **dict(overrides or {}),
    }
    if tenant_id is not None or company_id is not None:
        from hashlib import sha256
        from uuid import UUID
        _require(tenant_id is not None and company_id is not None,"WIND_DOWN_INVENTORY_SCOPE_REQUIRED","both authenticated tenant and company IDs are required")
        for key,value in (("inventory_tenant_commitment",tenant_id),("inventory_company_commitment",company_id)):
            commitment=sha256(str(UUID(str(value))).encode()).hexdigest()
            _require(payload.get(key,commitment)==commitment,"WIND_DOWN_INVENTORY_SCOPE_MISMATCH","scope overrides must agree with the authenticated IDs")
            payload[key]=commitment
    return seal(WindDownPlan, {key: value for key, value in payload.items() if value is not None}, "plan_digest")


class NoticeRef(StrictModel):
    """One notice actually sent: the bound execution, the request it was bound to, and how many it reached."""

    audience: Literal["customers", "staff", "suppliers", "regulators"]
    tool: ShortText
    execution_receipt_digest: Sha256Digest
    request_digest: Sha256Digest
    sent_at: str
    count: int = Field(ge=0, le=1000000)
    binding_digest: Sha256Digest
    request: dict[str, Any]
    execution: dict[str, Any]

    @field_validator("sent_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="sent_at")


class ConnectionRow(StrictModel):
    """One ``GET /api/oauth/connections`` row, reduced exactly as ``company_bring_up.ConnectedProvider`` reduces it."""

    provider: ShortText
    status: ShortText
    connection_digest: Sha256Digest


def notice_binding_digest(audience: str, tool: str, execution_receipt_digest: str, request_digest: str) -> str:
    """The digest a notice row commits, so the engine re-checks the pairing the builder bound."""

    return stable_digest({"audience": str(audience), "tool": str(tool), "execution": str(execution_receipt_digest), "request": str(request_digest)})


def second_approval_digest(*, transition_ref: str, plan_digest: str, first_approval_task_id: str, approval_task_id: str, approver_ref: str) -> str:
    """The digest the second approval commits, so the engine re-checks the platform decision the builder bound.

    Without it ``second_approver_ref`` would be a name a caller could type
    beside the receipt; with it the field is only accepted next to a second
    decision bound to the *same* transition and plan as the sealed proof, taken
    on a different task.
    """

    return stable_digest({"transition": str(transition_ref), "plan": str(plan_digest), "first_task": str(first_approval_task_id), "task": str(approval_task_id), "approver": str(approver_ref)})


class WindDownReceipt(StrictModel):
    inventory_reads: tuple[dict[str, Any], ...] = ()
    entity_scope: dict[str, Any] | None = None
    """What one hop proves; every field is derived from a sealed artifact, never typed beside it."""

    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    # decide
    resolution: dict[str, Any] | None = None
    #: The sealed ``AuthorizationFacts``.  Named ``authorization_proof`` and not
    #: ``authorization_proof`` because the boundary refuses any key containing
    #: ``authorization``, whatever it holds.
    authorization_proof: dict[str, Any] | None = None
    second_approver_ref: OpaqueRef | None = None
    second_approval: dict[str, Any] | None = None
    decision_task: dict[str, Any] | None = None
    lifecycle_response: dict[str, Any] | None = None
    cadence_state_digest: Sha256Digest | None = None
    cadence_bundle_digest: Sha256Digest | None = None
    cadence_status: ShortText | None = None
    open_job_count: int | None = Field(default=None, ge=0, le=100000)
    open_engagement_count: int | None = Field(default=None, ge=0, le=100000)
    job_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    engagement_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    # notify
    notices: tuple[NoticeRef, ...] = Field(default_factory=tuple, max_length=20)
    eligibility: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    none_applicable: bool = False
    none_applicable_audiences: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=3)
    listing_digest: Sha256Digest | None = None
    # settle_refunds
    refund_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    refund_total: Decimal | None = None
    # cancel_subscriptions
    commitment_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    customer_subscription_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    subscription_cancel_executions: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    subscription_cancel_requests: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    # close_receivables
    collections_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    write_off_proofs: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    # settle_payables
    payable_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    disbursement_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    # run_final_pay
    headcount: dict[str, Any] | None = None
    employment_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    payroll_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    # deregister
    standing_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    lodgements: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    compliance_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=10000)
    registry_confirmation: dict[str, Any] | None = None
    # close_accounts
    bank_source: dict[str, Any] | None = None
    close_source: dict[str, Any] | None = None
    register_source: dict[str, Any] | None = None
    connections: tuple[ConnectionRow, ...] = Field(default_factory=tuple, max_length=60)
    closing_balance: Decimal | None = None
    detail: BoundedText | None = None

    @field_validator(
        "none_applicable_audiences", "evidence_refs", "job_sources", "engagement_sources", "notices", "refund_sources", "commitment_sources", "customer_subscription_sources",
        "subscription_cancel_executions", "subscription_cancel_requests", "collections_sources", "write_off_proofs",
        "payable_sources", "disbursement_sources", "employment_sources", "payroll_sources", "standing_sources",
        "lodgements", "compliance_sources", "connections",
        mode="before",
    )
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("refund_total", "closing_balance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class WindDownLedger(StrictModel):
    inventory_records: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    entity_scope: dict[str, Any] | None = None
    """Derived state only: every number here came off a receipt that came off a sealed artifact."""

    decided_at: str | None = None
    proof_digest: str | None = None
    resolution_digest: str | None = None
    decided_by_refs: tuple[str, ...] = ()
    settlement_reserve: Decimal = Field(default=Decimal("0"), validate_default=True)
    lifecycle_receipt_sha256: str | None = None
    notified_at: str | None = None
    notified_by_audience: dict[str, int] = Field(default_factory=dict)
    staff_notice_at: str | None = None
    refunds_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    refunds_settled_at: str | None = None
    commitments_terminated: int = 0
    subscriptions_cancelled: int = 0
    subscriptions_cancelled_at: str | None = None
    receivables_recovered: Decimal = Field(default=Decimal("0"), validate_default=True)
    receivables_written_off: Decimal = Field(default=Decimal("0"), validate_default=True)
    receivables_closed_at: str | None = None
    payables_settled: Decimal = Field(default=Decimal("0"), validate_default=True)
    payables_settled_at: str | None = None
    employees_offboarded: int = 0
    last_working_at: str | None = None
    final_pay_run_refs: tuple[str, ...] = ()
    final_pay_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    final_pay_done_at: str | None = None
    surrendered_kinds: tuple[str, ...] = ()
    lodgement_refs: tuple[str, ...] = ()
    registry_confirmed_at: str | None = None
    deregistered_at: str | None = None
    closing_balance: Decimal = Field(default=Decimal("0"), validate_default=True)
    books_closed_through: str | None = None
    connections_revoked: int = 0
    accounts_closed_at: str | None = None
    closed_at: str | None = None
    days_decision_to_close: int | None = None
    halt_reason: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "closed", "abandoned", "halted"] = "open"

    @field_validator("decided_by_refs", "final_pay_run_refs", "surrendered_kinds", "lodgement_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("settlement_reserve", "refunds_total", "receivables_recovered", "receivables_written_off", "payables_settled", "final_pay_total", "closing_balance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class WindDownEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    message_sent: Literal[False] = False
    refund_issued: Literal[False] = False
    subscription_cancelled: Literal[False] = False
    payment_sent: Literal[False] = False
    filing_lodged: Literal[False] = False
    account_closed: Literal[False] = False
    connection_revoked: Literal[False] = False
    provider_read: Literal[False] = False


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #


def _days(start: str | None, end: str) -> int:
    return 0 if not start else (parsed(end) - parsed(start)).days


def _amount(data: Mapping[str, Any], key: str) -> Decimal:
    return decimal_value(data.get(key, "0"), field_name=key, allow_negative=True)


def _facts(source: Mapping[str, Any] | None) -> dict[str, Any]:
    from lightbulb._wind_down_sources import source_facts
    source = dict(source or {})
    claimed = SourceFacts.model_validate(source.get("state") or {}).to_dict()
    actual = SourceFacts(**source_facts(claimed["engine"], source.get("plan"), source.get("source_state"))).to_dict()
    require(claimed == actual, "WIND_DOWN_SOURCE_MISMATCH", "source facts must be derived from the retained canonical lifecycle")
    return actual


def _totals(sources: Sequence[Mapping[str, Any]], *, statuses: frozenset[str] | set[str] | None = None) -> Decimal:
    total = Decimal("0.00")
    for source in sources:
        facts = _facts(source)
        if statuses is not None and str(facts.get("status")) not in statuses:
            continue
        total += decimal_value(facts.get("amount", "0"), field_name="amount", allow_negative=True)
    return total


def _empty_listing(receipt: Any, *, label: str) -> None:
    """``none_applicable`` is only ever accepted with the console's own empty listing behind it."""

    require(not receipt.none_applicable or receipt.listing_digest == _EMPTY_LISTING_DIGEST, "NONE_APPLICABLE_UNPROVEN", f"{label} claims nothing is open, but the listing digest is not the digest of an empty listing", "correct_input")


def _apply_wind_down(plan: WindDownPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    from lightbulb._wind_down_sources import validate_scope
    groups = {
        "job_sources":"job_chain", "engagement_sources":"engagement_engine",
        "refund_sources":"refund_and_dispute_chain", "commitment_sources":"spend_control_chain",
        "customer_subscription_sources":"subscription_chain", "collections_sources":"collections_chain",
        "payable_sources":"payables_chain", "disbursement_sources":"disbursement_run",
        "employment_sources":"employment_chain", "payroll_sources":"payroll_run_chain",
        "standing_sources":"obligation_paper", "compliance_sources":"compliance_calendar",
        "bank_source":"bank_reconciliation", "close_source":"finance_close", "register_source":"company_cost_centres",
    }
    for field, engine in groups.items():
        supplied = getattr(r, field)
        rows = (supplied,) if field.endswith("_source") and supplied else supplied or ()
        seen = set()
        for source in rows:
            try:
                facts = _facts(source)
                require(facts["engine"] == engine, "WIND_DOWN_SOURCE_ENGINE_MISMATCH", "the source must come from this step's owning lifecycle")
                bound = validate_scope(engine, source["plan"], source["source_state"],
                    company_ref=plan.company_ref, scope=r.entity_scope if event == "decide" else data.get("entity_scope"), at=at)
                require(bound.scope.entity_ref not in seen, "WIND_DOWN_SOURCE_DUPLICATE", "each source entity is counted once")
                seen.add(bound.scope.entity_ref)
            except (ValueError, KeyError) as exc:
                require(False, "WIND_DOWN_SOURCE_INVALID", str(exc), "correct_input")
    inventory_groups = {
        "settle_refunds": ("refund_sources",),
        "cancel_subscriptions": ("commitment_sources", "customer_subscription_sources"),
        "close_receivables": ("collections_sources",),
        "settle_payables": ("payable_sources", "disbursement_sources"),
        "run_final_pay": ("employment_sources", "payroll_sources"),
        "deregister": ("standing_sources", "compliance_sources"),
        "close_accounts": ("bank_source", "close_source", "register_source"),
    }
    if event in inventory_groups:
        from lightbulb._wind_down_sources import TARGETS
        expected = {TARGETS[groups[field]]: getattr(r, field) for field in inventory_groups[event]}
        _validate_inventories(plan, r.inventory_reads, expected, data["entity_scope"], at)
        data["inventory_records"] = {**data.get("inventory_records",{}), **{read["output"]["engine"]:read["output"]["records"] for read in r.inventory_reads}}
    if event == "decide":
        require(r.entity_scope is not None, "WIND_DOWN_SCOPE_REQUIRED", "retain the company execution scope from the paused cadence")
        require(r.authorization_proof is not None, "WIND_DOWN_NOT_AUTHORIZED", f"winding this company down commits {plan.settlement_reserve} {plan.currency} of wind_down authority; two humans decide it", "await_approval")
        facts = require_authorization_proof(r.authorization_proof, category="wind_down", amount=plan.settlement_reserve, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, engine=WIND_DOWN_KIND)
        second = dict(r.second_approval or {})
        second_task = str(second.get("approval_task_id") or "")
        require(
            r.second_approver_ref is not None
            and str(second.get("approver_ref") or "") == str(r.second_approver_ref)
            and second_task not in ("", str(facts.approval_task_id))
            and str(second.get("binding_digest") or "") == second_approval_digest(transition_ref=facts.transition_ref, plan_digest=facts.plan_digest, first_approval_task_id=facts.approval_task_id, approval_task_id=second_task, approver_ref=str(r.second_approver_ref)),
            "WIND_DOWN_SECOND_APPROVER_REQUIRED",
            "a wind-down is a two-person decision; the second approver is a platform decision bound to this same transition on its own task, not a name written beside the receipt",
            "await_approval",
        )
        require(r.second_approver_ref != facts.approver_ref, "WIND_DOWN_SECOND_APPROVER_REQUIRED", f"{facts.approver_ref} decided both approvals; the second approver is somebody else", "await_approval")
        task = dict(r.decision_task or {})
        require(str(task.get("status")) == "APPROVED" and bool(task.get("id")) and bool(task.get("decided_by_ref")), "WIND_DOWN_NOT_HUMAN_DECIDED", "a wind-down starts from an APPROVED, attributed sdk_engine_transition task")
        require(not bool(task.get("auto_accepted")), "WIND_DOWN_NOT_HUMAN_DECIDED", "the decision task was auto-accepted; wind_down is human-only and the platform refuses it too", "correct_input")
        resolution = dict(r.resolution or {})
        require(str(resolution.get("schema")) == RESOLUTION_SCHEMA and bool(resolution.get("resolution_ref")) and bool(resolution.get("document_sha256")) and int(resolution.get("signatory_count") or 0) >= 1 and str(resolution.get("document_kind")) in ("directors_resolution", "members_resolution"), "RESOLUTION_MISSING", "a wind-down is bound to a signed directors' or members' resolution naming itself, its document digest, and its signatories")
        lifecycle = dict(r.lifecycle_response or {})
        require(str(lifecycle.get("lifecycle_status")) == "WINDING_DOWN" and str(lifecycle.get("approval_task_id")) == str(task.get("id")) and bool(lifecycle.get("receipt_sha256")), "LIFECYCLE_NOT_WINDING_DOWN", f"the platform reports {lifecycle.get('lifecycle_status')!r} for task {lifecycle.get('approval_task_id')!r}; the company must already be WINDING_DOWN under this exact decision", "manual_reconciliation")
        require(str(lifecycle.get("resolution_sha256")) == str(resolution.get("document_sha256")), "LIFECYCLE_NOT_WINDING_DOWN", "the platform's lifecycle receipt commits a different resolution document", "manual_reconciliation")
        require(str(r.cadence_status or "") in ("paused", "stopped"), "CADENCE_NOT_PAUSED", f"the operating cadence is {r.cadence_status!r}; it stops selling before the wind-down is recorded", "correct_input")
        require(r.cadence_bundle_digest == plan.bundle_digest, "CADENCE_BUNDLE_MISMATCH", "the paused cadence runs a different bundle from the one this plan winds down", "manual_reconciliation")
        require(r.open_job_count is not None and r.open_engagement_count is not None, "JOBS_STILL_OPEN", "the decision names how many jobs and engagements the console listed as open")
        _validate_inventories(plan, r.inventory_reads, {"job_chain": r.job_sources, "engagement_engine": r.engagement_sources}, r.entity_scope, at)
        require(r.open_job_count == sum(_facts(source)["status"] not in CLOSED_JOB_STATUSES for source in r.job_sources)
            and r.open_engagement_count == sum(_facts(source)["status"] not in CLOSED_ENGAGEMENT_STATUSES for source in r.engagement_sources),
            "WIND_DOWN_SOURCE_MISMATCH", "open-work counts must replay the retained owning lifecycles")
        data["inventory_records"] = {read["output"]["engine"]:read["output"]["records"] for read in r.inventory_reads}
        require(r.open_job_count == 0 and r.open_engagement_count == 0, "JOBS_STILL_OPEN", f"{r.open_job_count} jobs and {r.open_engagement_count} engagements are still open; finish or cancel them before deciding", "correct_input")
        data.update({
            "entity_scope": r.entity_scope,
            "decided_at": at,
            "proof_digest": facts.proof_digest,
            "resolution_digest": str(resolution["document_sha256"]),
            "decided_by_refs": sorted({str(facts.approver_ref), str(r.second_approver_ref)}),
            "settlement_reserve": str(plan.settlement_reserve),
            "lifecycle_receipt_sha256": str(lifecycle["receipt_sha256"]),
        })
    elif event == "notify":
        elig = dict(r.eligibility or {})
        require(bool(elig) and r.suppression_digest is not None, "NOTIFY_WITHOUT_ELIGIBILITY", "a notice is sent behind the permission register's own eligibility answer and the suppression list it was assessed against", "correct_input")
        require(str(elig.get("schema")) == ELIGIBILITY_FACTS_SCHEMA and str(elig.get("channel")) == "email" and str(elig.get("company_ref")) == plan.company_ref, "NOTIFY_WITHOUT_ELIGIBILITY", "the eligibility does not name this company's email channel", "correct_input")
        require(str(elig.get("suppression_digest")) == r.suppression_digest, "NOTIFY_WITHOUT_ELIGIBILITY", "the suppression digest on the receipt is not the one the register was assessed against", "manual_reconciliation")
        require(parsed(str(elig.get("assessed_at"))) <= parsed(at), "NOTIFY_WITHOUT_ELIGIBILITY", "the eligibility was assessed after the notices went out", "manual_reconciliation")
        from lightbulb.permission_register import verify_eligibility
        try:
            rebuilt=eligibility(elig.get("permission_receipt"),channel="email",at=at,company_ref=plan.company_ref,scope="wind_down_notice")
            require(rebuilt==elig,"NOTIFY_WITHOUT_ELIGIBILITY","eligibility facts must replay the exact consent sources")
            verify_eligibility(elig["permission_receipt"],suppression_digest=r.suppression_digest,channel="email",at=at,
                company_ref=plan.company_ref,expected_scope=data["entity_scope"])
        except (ValueError,TypeError,KeyError) as exc:
            require(False,"NOTIFY_WITHOUT_ELIGIBILITY",str(exc))
        require(len(r.notices) >= 1, "NOTICE_AUDIENCE_MISSING", "a wind-down notice hop sends at least one notice")
        decided = str(data.get("decided_at") or at)
        for notice in r.notices:
            try:
                rebuilt=notice_receipt([notice.execution],[notice.request],audience=notice.audience,eligibility=elig,suppression_digest=r.suppression_digest)
                require(rebuilt["notices"][0]==notice.to_dict(),"NOTICE_EXECUTION_MISMATCH","notice facts must replay the exact request and execution")
                from lightbulb.company_engine_core import same_scope
                require(same_scope(EngineScope.model_validate(data["entity_scope"]),EngineScope.model_validate({**{key:notice.request["scope"][key] for key in ("tenant_ref","company_ref","project_ref","project_id")},"entity_ref":"notice","currency":plan.currency})),
                    "NOTICE_EXECUTION_MISMATCH","notice must belong to the company execution scope")
            except (ValueError,TypeError,KeyError) as exc:
                require(False,"NOTICE_EXECUTION_MISMATCH",str(exc))
            require(notice.tool in NOTICE_TOOLS, "NOTICE_EXECUTION_MISMATCH", f"{notice.tool} is not a governed communication write")
            require(notice.binding_digest == notice_binding_digest(notice.audience, notice.tool, notice.execution_receipt_digest, notice.request_digest), "NOTICE_EXECUTION_MISMATCH", f"the {notice.audience} notice does not commit the execution and request it claims", "manual_reconciliation")
            require(parsed(notice.sent_at) >= parsed(decided), "NOTICE_EXECUTION_MISMATCH", f"the {notice.audience} notice was sent before the wind-down was decided", "manual_reconciliation")
        _empty_listing(r, label="the notice hop")
        sent = {notice.audience for notice in r.notices}
        missing = [audience for audience in NOTICE_AUDIENCES if audience not in sent]
        require(not missing or r.none_applicable, "NOTICE_AUDIENCE_MISSING", f"nothing was sent to {missing}; notify them or prove the console listed none", "correct_input")
        if missing:
            require(set(r.none_applicable_audiences) == set(missing), "NONE_APPLICABLE_UNPROVEN", "empty evidence must explicitly cover each missing audience")
            engines = {"customers": ("job_chain", "engagement_engine", "subscription_chain"),
                "staff": ("employment_chain",), "suppliers": ("vendor_commitment", "payables_chain")}
            _validate_inventories(plan, r.inventory_reads, {engine: () for audience in missing for engine in engines[audience]}, data["entity_scope"], at)
        counts: dict[str, int] = {}
        for notice in r.notices:
            counts[notice.audience] = counts.get(notice.audience, 0) + notice.count
        staff = sorted(notice.sent_at for notice in r.notices if notice.audience == "staff")
        data.update({"notified_at": at, "notified_by_audience": counts, "staff_notice_at": staff[0] if staff else None})
    elif event == "settle_refunds":
        _empty_listing(r, label="the refund hop")
        require(r.refund_total is not None, "REFUNDS_OPEN", "a refund hop names the total the sealed refund cases actually carry")
        for source in r.refund_sources:
            facts = _facts(source)
            require(str(facts.get("status")) in CLEARED_REFUND_STATUSES, "REFUNDS_OPEN", f"refund {facts.get('entity_ref')} is {facts.get('status')!r}; every refund clears or is denied before the money stops moving", "manual_reconciliation")
        require(bool(r.refund_sources) or r.none_applicable, "REFUNDS_OPEN", "name the refund cases, or prove the console listed none")
        if r.refund_sources:
            due = add_days(str(data.get("notified_at") or at), plan.refund_window_days)
            require(parsed(at) >= parsed(due), "REFUND_WINDOW_OPEN", f"the {plan.refund_window_days}-day refund window runs to {due}; refunds cannot be closed before it", "correct_input")
        require(r.refund_total == _totals(r.refund_sources), "REFUNDS_OPEN", f"the receipt claims {r.refund_total}; the sealed refund cases carry {_totals(r.refund_sources)}", "manual_reconciliation")
        require(r.refund_total <= plan.settlement_reserve, "REFUND_TOTAL_ABOVE_RESERVE", f"refunds total {r.refund_total}; the decision authorised a {plan.settlement_reserve} reserve", "await_approval")
        data.update({"refunds_total": str(r.refund_total), "refunds_settled_at": at})
    elif event == "cancel_subscriptions":
        for source in r.commitment_sources:
            facts = _facts(source)
            require(str(facts.get("status")) in TERMINATED_COMMITMENT_STATUSES, "COMMITMENT_NOT_TERMINATED", f"vendor commitment {facts.get('entity_ref')} is {facts.get('status')!r}; terminate it before the company closes", "manual_reconciliation")
        for source in r.customer_subscription_sources:
            facts = _facts(source)
            require(str(facts.get("status")) in CLOSED_SUBSCRIPTION_STATUSES, "CUSTOMER_SUBSCRIPTION_OPEN", f"subscription {facts.get('entity_ref')} is {facts.get('status')!r}; a closing company bills nobody again", "manual_reconciliation")
        for execution in r.subscription_cancel_executions:
            row = dict(execution)
            try:
                bound = exact_request(row.get("source_execution"), row.get("source_request"), tools=frozenset({SUBSCRIPTION_CANCEL_TOOL}))
                require(all(row.get(key) == bound[key] for key in ("tool", "execution_receipt_digest", "request_digest", "approval_ref")),
                    "SUBSCRIPTION_SCOPE_MISMATCH", "cancellation facts must replay the exact approved request")
                require(row.get("cancelled_at") == bound["sent_at"] and parsed(bound["sent_at"]) <= parsed(at),
                    "SUBSCRIPTION_SCOPE_MISMATCH", "cancellation must have executed before settlement")
                require(row.get("subscription_ref") == bound["request"].get("subscription_ref"),
                    "SUBSCRIPTION_SCOPE_MISMATCH", "cancellation must name the requested subscription")
                require(all(bound["source_request"]["scope"].get(key) == data["entity_scope"].get(key)
                    for key in ("tenant_ref", "company_ref", "project_ref", "project_id")),
                    "SUBSCRIPTION_SCOPE_MISMATCH", "cancellation must belong to this company execution scope")
            except (ValueError, TypeError, KeyError) as exc:
                require(False, "SUBSCRIPTION_SCOPE_MISMATCH", str(exc))
            require(str(row.get("tool")) == SUBSCRIPTION_CANCEL_TOOL, "SUBSCRIPTION_SCOPE_MISMATCH", f"{row.get('tool')!r} is not the subscription cancel lane")
            require(bool(row.get("approval_ref")), "SUBSCRIPTION_SCOPE_MISMATCH", "a subscription cancellation is an approved write")
            require(str(row.get("binding_digest")) == notice_binding_digest(str(row.get("subscription_ref")), str(row.get("tool")), str(row.get("execution_receipt_digest")), str(row.get("request_digest"))), "SUBSCRIPTION_SCOPE_MISMATCH", f"the cancellation of {row.get('subscription_ref')} does not commit the execution and request it claims", "manual_reconciliation")
        cancelled = {str(_facts(source).get("entity_ref")) for source in r.customer_subscription_sources if str(_facts(source).get("status")) == "cancelled"}
        executed = {str(dict(execution).get("subscription_ref")) for execution in r.subscription_cancel_executions}
        require(executed == cancelled, "SUBSCRIPTION_SCOPE_MISMATCH", f"the cancellations name {sorted(executed)}; the sealed cancelled subscriptions are {sorted(cancelled)}", "manual_reconciliation")
        require(len(r.subscription_cancel_requests) == len(r.subscription_cancel_executions), "SUBSCRIPTION_SCOPE_MISMATCH", "every cancellation execution carries the request it was bound to")
        data.update({"commitments_terminated": len(r.commitment_sources), "subscriptions_cancelled": len(r.customer_subscription_sources), "subscriptions_cancelled_at": at})
    elif event == "close_receivables":
        proofs = {str(dict(proof).get("entity_ref")): dict(proof) for proof in r.write_off_proofs}
        for source in r.collections_sources:
            facts = _facts(source)
            state = str(facts.get("status"))
            require(state in CLOSED_RECEIVABLE_STATUSES, "RECEIVABLES_OPEN", f"receivable {facts.get('entity_ref')} is {state!r}; recover it, refer it, or write it off", "manual_reconciliation")
            if state == "written_off":
                proof = proofs.get(str(facts.get("entity_ref")))
                require(proof is not None and str(proof.get("category")) == "write_off", "RECEIVABLES_OPEN", f"receivable {facts.get('entity_ref')} was written off without a write_off authority proof", "await_approval")
        data.update({
            "receivables_recovered": str(_totals(r.collections_sources, statuses=frozenset({"recovered"}))),
            "receivables_written_off": str(_totals(r.collections_sources, statuses=frozenset({"written_off"}))),
            "receivables_closed_at": at,
        })
    elif event == "settle_payables":
        for source in r.payable_sources:
            facts = _facts(source)
            require(str(facts.get("status")) in SETTLED_PAYABLE_STATUSES, "PAYABLES_OPEN", f"payable {facts.get('entity_ref')} is {facts.get('status')!r}; every bill is paid, cleared, or refused before the accounts close", "manual_reconciliation")
        for source in r.disbursement_sources:
            facts = _facts(source)
            require(str(facts.get("status")) in SETTLED_DISBURSEMENT_STATUSES, "PAYABLES_OPEN", f"disbursement run {facts.get('entity_ref')} is {facts.get('status')!r}; a run in flight is money that has not landed", "manual_reconciliation")
        data.update({"payables_settled": str(_totals(r.payable_sources, statuses=frozenset({"paid", "cleared"}))), "payables_settled_at": at})
    elif event == "run_final_pay":
        head = dict(r.headcount or {})
        require(str(head.get("schema")) == HEADCOUNT_PROOF_SCHEMA, "EMPLOYEES_NOT_OFFBOARDED", "the final pay hop consumes employment_chain's own headcount proof")
        require(str(head.get("states_digest")) == stable_digest(sorted(str(_facts(source).get("state_digest")) for source in r.employment_sources)), "EMPLOYEES_NOT_OFFBOARDED", "the headcount proof was taken over a different set of employment states", "manual_reconciliation")
        # The proof is re-derived from the sealed states it was taken over:
        # ``all_offboarded``, the head count and the last working day are the
        # employment chain's own answer, never a number typed beside it.
        gone = [_facts(source) for source in r.employment_sources if str(_facts(source).get("status")) == "offboarded"]
        still = [_facts(source) for source in r.employment_sources if str(_facts(source).get("status")) not in LEFT_EMPLOYMENT_STATUSES]
        require(not still, "EMPLOYEES_NOT_OFFBOARDED", f"{len(still)} workers are still employed; nobody is deregistered while a worker is on the books", "manual_reconciliation")
        require(bool(head.get("all_offboarded")) == bool(gone), "EMPLOYEES_NOT_OFFBOARDED", "the headcount proof must match the actual offboarded workforce", "manual_reconciliation")
        last_working = max((str(item["settled_at"]) for item in gone if item.get("settled_at")), key=parsed, default=None)
        require(str(head.get("last_working_at") or "") == str(last_working or ""), "EMPLOYEES_NOT_OFFBOARDED", f"the headcount proof claims a last working day of {head.get('last_working_at')}; the sealed employment states end at {last_working}", "manual_reconciliation")
        for source in r.employment_sources:
            facts = _facts(source)
            require(plan.employment_plan_digest is None or str(facts.get("plan_digest")) == plan.employment_plan_digest, "EMPLOYEES_NOT_OFFBOARDED", f"employee {facts.get('entity_ref')} belongs to a different employment plan", "manual_reconciliation")
        floor = max(plan.staff_notice_days, int(head.get("notice_floor_days") or 0))
        for source in r.employment_sources:
            facts = _facts(source)
            if str(facts.get("status")) != "offboarded":
                continue
            given = _days(str(facts.get("opened_at") or ""), str(facts.get("settled_at") or "")) if facts.get("opened_at") and facts.get("settled_at") else -1
            require(given >= floor, "EMPLOYEE_NOTICE_SHORT", f"{facts.get('entity_ref')} was given {given} days notice; the floor is {floor}. A human decides a shortfall, the engine does not", "await_approval")
        require(not gone or len(r.payroll_sources) >= 1, "FINAL_PAY_NOT_RECONCILED", "a final pay hop names the payroll runs that paid the workers out")
        for source in r.payroll_sources:
            facts = _facts(source)
            require(str(facts.get("status")) == "reconciled", "FINAL_PAY_NOT_RECONCILED", f"pay run {facts.get('entity_ref')} is {facts.get('status')!r}; a final pay run is reconciled before the company deregisters", "manual_reconciliation")
            require(plan.payroll_plan_digest is None or str(facts.get("plan_digest")) == plan.payroll_plan_digest, "FINAL_PAY_NOT_RECONCILED", f"pay run {facts.get('entity_ref')} belongs to a different payroll plan", "manual_reconciliation")
            require(last_working is None or parsed(str(facts.get("period_end"))) >= parsed(last_working), "FINAL_PAY_NOT_RECONCILED", f"pay run {facts.get('entity_ref')} closes before the last working day {last_working}", "manual_reconciliation")
            reserved = set(facts.get("reserved") or ())
            from lightbulb.payroll_run_chain import _LIABILITY_FIELDS
            payroll_ledger = source["source_state"]["ledger"]
            required = {kind for kind, field in _LIABILITY_FIELDS.items() if Decimal(str(payroll_ledger[field])) > 0}
            require(required.issubset(reserved), "SUPER_UNRESERVED", f"pay run {facts.get('entity_ref')} reserves {sorted(reserved)}; {sorted(required - reserved)} is unreserved and the company cannot deregister owing it", "manual_reconciliation")
        final_refs = {str(_facts(source)["entity_ref"]) for source in r.payroll_sources}
        require(all(item.get("detail") in final_refs for item in gone), "FINAL_PAY_NOT_RECONCILED", "each offboarded employee must name a retained reconciled final run")
        workers = {str(worker) for source in r.payroll_sources for worker in source["source_state"]["ledger"]["worker_refs"]}
        require(all(item["entity_ref"] in workers for item in gone), "FINAL_PAY_NOT_RECONCILED", "every offboarded worker must be in the final payroll source")
        data.update({
            "employees_offboarded": len(gone),
            "last_working_at": last_working,
            "final_pay_run_refs": sorted(str(_facts(source).get("entity_ref")) for source in r.payroll_sources),
            "final_pay_total": str(_totals(r.payroll_sources)),
            "final_pay_done_at": at,
        })
    elif event == "deregister":
        require(data.get("final_pay_done_at") is not None, "DEREGISTER_BEFORE_PAYROLL", "nothing is deregistered before the final pay run is recorded", "manual_reconciliation")
        surrendered = {str(_facts(source).get("kind")): _facts(source) for source in r.standing_sources}
        for kind in plan.registrations_to_surrender:
            facts = surrendered.get(kind)
            require(facts is not None and str(facts.get("status")) == "surrendered", "REGISTRATION_NOT_SURRENDERED", f"the {kind} registration is {None if facts is None else facts.get('status')!r}; every registration this plan names is surrendered first", "manual_reconciliation")
        require(len(r.lodgements) >= 1, "LODGEMENT_MISSING", "deregistration is proven by an operator-held lodgement receipt; there is no registry connector")
        pattern = re.compile(plan.registrar_ref_pattern)
        for lodgement in r.lodgements:
            row = dict(lodgement)
            ref = str(row.get("lodgement_ref", ""))
            require(bool(pattern.match(ref)), "LODGEMENT_REF_INVALID", f"{ref!r} is not a {plan.jurisdiction} registrar reference matching {plan.registrar_ref_pattern}", "correct_input")
            require(bool(row.get("lodged_at")) and parsed(str(row["lodged_at"])) >= parsed(str(data["final_pay_done_at"])), "DEREGISTER_BEFORE_PAYROLL", f"lodgement {ref} predates the final pay run", "manual_reconciliation")
        by_kind = {str(_facts(source).get("kind")): _facts(source) for source in r.compliance_sources}
        for kind in plan.required_final_obligations:
            facts = by_kind.get(kind)
            require(facts is not None and str(facts.get("status")) in LODGED_OBLIGATION_STATUSES, "OBLIGATIONS_OUTSTANDING", f"the final {kind} obligation is {None if facts is None else facts.get('status')!r}; every final return is lodged or paid before deregistration", "manual_reconciliation")
            assert facts is not None
            require(facts.get("period_end") is not None and parsed(str(facts["period_end"])) >= parsed(str(data["final_pay_done_at"])), "OBLIGATIONS_OUTSTANDING", f"the {kind} obligation covers to {facts.get('period_end')}, which does not reach the final pay run", "manual_reconciliation")
        confirmation = dict(r.registry_confirmation or {})
        require(bool(confirmation.get("observation_digest")) and bool(confirmation.get("confirmed_at")), "REGISTRY_CONFIRMATION_MISSING", "deregistration is only recorded once the registrar's own confirmation is observed", "manual_reconciliation")
        data.update({
            "surrendered_kinds": sorted(str(_facts(source).get("kind")) for source in r.standing_sources if str(_facts(source).get("status")) == "surrendered"),
            "lodgement_refs": sorted(str(dict(item).get("lodgement_ref")) for item in r.lodgements),
            "registry_confirmed_at": timestamp(str(confirmation["confirmed_at"]), field_name="confirmed_at"),
            "deregistered_at": at,
        })
    elif event == "close_accounts":
        bank = _facts(r.bank_source)
        require(str(bank.get("status")) == "reconciled" and bank.get("amount") is not None and decimal_value(bank.get("amount"), field_name="amount", allow_negative=True) == Decimal("0.00"), "BANK_BALANCE_NONZERO", f"the bank reconciliation is {bank.get('status')!r} with a closing balance of {bank.get('amount')}; accounts close at zero", "manual_reconciliation")
        close = _facts(r.close_source)
        register = _facts(r.register_source)
        require(str(close.get("status")) == "closed" and str(register.get("status")) == "closed", "BOOKS_NOT_CLOSED", f"the final close is {close.get('status')!r} and the cost register is {register.get('status')!r}; both are closed before the accounts are", "manual_reconciliation")
        require(len(r.connections) >= 1, "CONNECTION_STILL_ACTIVE", "closing the accounts is proven against the account's own connection rows")
        live = [row.provider for row in r.connections if row.status != "revoked"]
        require(not live, "CONNECTION_STILL_ACTIVE", f"{sorted(live)} are still connected; a closed company holds no provider authority", "manual_reconciliation")
        task = dict(r.decision_task or {})
        require(str(task.get("status")) == "APPROVED" and bool(task.get("id")) and not bool(task.get("auto_accepted")), "LIFECYCLE_NOT_CLOSED", "the platform close is a human decision on its own approved task", "await_approval")
        lifecycle = dict(r.lifecycle_response or {})
        require(str(lifecycle.get("lifecycle_status")) == "CLOSED" and str(lifecycle.get("approval_task_id")) == str(task.get("id")) and bool(lifecycle.get("receipt_sha256")), "LIFECYCLE_NOT_CLOSED", f"the platform reports {lifecycle.get('lifecycle_status')!r}; the company must already be CLOSED under this exact decision", "manual_reconciliation")
        require(bool(lifecycle.get("occurred_at")) and parsed(str(lifecycle["occurred_at"])) >= parsed(str(data["deregistered_at"])), "ACCOUNTS_BEFORE_DEREGISTRATION", "the platform close predates the deregistration it is supposed to follow", "manual_reconciliation")
        data.update({
            "closing_balance": str(decimal_value(bank.get("amount"), field_name="closing_balance", allow_negative=True)),
            "books_closed_through": close.get("period_end"),
            "connections_revoked": len(r.connections),
            "accounts_closed_at": at,
        })
    elif event == "close":
        _validate_inventories(plan, r.inventory_reads, data["inventory_records"], data["entity_scope"], at, records_only=True)
        elapsed = _days(data.get("decided_at"), at)
        require(elapsed <= plan.max_days_decision_to_close, "WIND_DOWN_OVERDUE", f"the wind-down took {elapsed} days; the plan allows {plan.max_days_decision_to_close}", "manual_reconciliation")
        data.update({"closed_at": at, "days_decision_to_close": elapsed, "outcome": "closed"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    elif event == "halt":
        data.update({"halt_reason": str(command.reason)[:300], "outcome": "halted"})
    return next_status, data


class _WindDownLifecycle(LifecycleSpec):
    def bind(self, plan, state):
        from lightbulb.company_engine_core import EngineScope, same_scope
        policy, bound = super().bind(plan, state)
        if bound.ledger.entity_scope is None or not same_scope(bound.scope, EngineScope.model_validate(bound.ledger.entity_scope)):
            raise ValueError("WIND_DOWN_SCOPE_MISMATCH: decision scope must match this company execution")
        return policy, bound

    def open(self, plan, scope, **kwargs):
        state = super().open(plan, scope, **kwargs)
        return self.bind(plan, state)[1]


WIND_DOWN_LIFECYCLE = _WindDownLifecycle(
    entity="wind_down",
    schema_prefix="wind_down",
    statuses=WIND_DOWN_STATUSES,
    terminal=TERMINAL_WIND_DOWN_STATUSES,
    events=WIND_DOWN_EVENTS,
    table=_WIND_DOWN_TABLE,
    opening_event="decide",
    reason_events=("abandon", "halt"),
    apply=_apply_wind_down,
    ledger_model=WindDownLedger,
    receipt_model=WindDownReceipt,
    effect_boundary_model=WindDownEffectBoundary,
    plan_model=WindDownPlan,
    max_transitions=MAX_WIND_DOWN_TRANSITIONS,
)
WindDownState = WIND_DOWN_LIFECYCLE.State


def open_wind_down(plan: WindDownPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return WIND_DOWN_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_wind_down(plan: WindDownPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return WIND_DOWN_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


def _lifecycle_facts(response: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The platform's wind-down / close receipt, reduced to what a guard reads; ``companyId`` never crosses."""

    raw = dict(detached(response))
    picked = {
        "lifecycle_status": str(raw.get("lifecycleStatus") or raw.get("lifecycle_status") or ""),
        "approval_task_id": str(raw.get("approvalTaskId") or raw.get("approval_task_id") or ""),
        "resolution_sha256": str(raw.get("resolutionSha256") or raw.get("resolution_sha256") or ""),
        "decided_by_ref": str(raw.get("decidedBy") or raw.get("decided_by") or raw.get("decided_by_ref") or ""),
        "occurred_at": str(raw.get("occurredAt") or raw.get("occurred_at") or ""),
        "receipt_sha256": str(raw.get("receiptSha256") or raw.get("receipt_sha256") or ""),
        "event_ref": str(raw.get("eventId") or raw.get("event_id") or raw.get("event_ref") or ""),
    }
    for key in ("lifecycle_status", "approval_task_id", "receipt_sha256", "occurred_at"):
        _require(bool(picked[key]), "LIFECYCLE_RESPONSE_INCOMPLETE", f"the lifecycle receipt lacks {key}")
    picked["occurred_at"] = timestamp(picked["occurred_at"], field_name="occurred_at")
    return {key: value for key, value in picked.items() if value}


def _task_facts(task: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The decision task, reduced: whether a human decided it is the only thing the guard asks."""

    raw = dict(detached(task))
    context = dict(raw.get("contextData") or raw.get("context") or {})
    decided_by = raw.get("decidedByRef") or raw.get("decided_by_ref") or raw.get("decidedBy") or raw.get("decided_by")
    decided_at = raw.get("decidedAt") or raw.get("decided_at")
    _require(bool(raw.get("id")) and bool(decided_by) and bool(decided_at), "DECISION_TASK_INCOMPLETE", "an approved task names its id, who decided it, and when")
    return {
        "id": str(raw["id"]),
        "status": str(raw.get("status", "")).upper(),
        "decided_by_ref": str(decided_by),
        "decided_at": timestamp(str(decided_at), field_name="decided_at"),
        "auto_accepted": bool(context.get("auto_accepted") or raw.get("autoAccepted") or False),
        "human_only": bool(context.get("human_only") or False),
        "category": str(context.get("category") or ""),
    }


def _resolution_facts(resolution: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The directors'/members' resolution: an operator-held document that names itself."""

    raw = dict(detached(resolution))
    _require(str(raw.get("schema")) == RESOLUTION_SCHEMA, "RESOLUTION_SCHEMA_MISMATCH", f"a resolution names itself {RESOLUTION_SCHEMA}, got {raw.get('schema')!r}")
    for key in ("resolution_ref", "resolved_at", "document_sha256", "signatory_count", "document_kind"):
        _require(raw.get(key) is not None, "RESOLUTION_INCOMPLETE", f"the resolution lacks {key}")
    return {
        "schema": RESOLUTION_SCHEMA,
        "operator_supplied": True,
        "resolution_ref": str(raw["resolution_ref"]),
        "resolved_at": timestamp(str(raw["resolved_at"]), field_name="resolved_at"),
        "document_sha256": str(raw["document_sha256"]),
        "signatory_count": int(raw["signatory_count"]),
        "document_kind": str(raw["document_kind"]),
    }


def decision_receipt(
    task: Mapping[str, Any] | Any,
    request: Any,
    *,
    proof: AuthorizationProof | Mapping[str, Any] | None,
    resolution: Mapping[str, Any] | Any,
    lifecycle_response: Mapping[str, Any] | Any,
    cadence_state: Mapping[str, Any] | Any,
    job_states: Sequence[Any] = (),
    engagement_states: Sequence[Any] = (),
    job_plans: Sequence[Any] = (),
    engagement_plans: Sequence[Any] = (),
    inventory_reads: Sequence[Mapping[str, Any]] = (),
    second_approval: ApprovalBinding | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The opening receipt: a bound human decision, a second approver, a signed resolution, the platform's WINDING_DOWN receipt, and a paused cadence.

    ``proof`` is ``None`` while the wind-down is still being *asked for*: the
    receipt is then the body of the approval request and the guard refuses it
    with ``WIND_DOWN_NOT_AUTHORIZED`` until the approver's decision comes back
    as a sealed proof.  ``second_approval`` is the second bound platform
    decision; ``authority_matrix.authorize`` does not yet carry the second
    approver on the proof itself, so it is bound here instead.
    """

    binding = bind_approval(task, request)
    facts = _task_facts(task)
    evidence = authorization_evidence(proof) if proof is not None else {"evidence_refs": []}
    second_ref: str | None = None
    second: dict[str, Any] | None = None
    if proof is not None:
        parsed_proof = AuthorizationProof.model_validate(detached(proof))
        _require(parsed_proof.approval_task_id == binding.approval_ref, "PROOF_TASK_MISMATCH", f"the proof was minted on task {parsed_proof.approval_task_id}, not {binding.approval_ref}")
        second_ref = parsed_proof.second_approver_ref
        if second_ref is not None:
            task_id = str(parsed_proof.second_approval_task_id or "")
            _require(task_id not in ("", parsed_proof.approval_task_id), "SECOND_APPROVAL_REUSED", "the proof names a second approver without a second task; one task cannot be both approvals")
            second = {
                "approver_ref": str(second_ref),
                "approval_task_id": task_id,
                "decided_at": parsed_proof.decided_at,
                "binding_digest": second_approval_digest(transition_ref=parsed_proof.transition_ref, plan_digest=parsed_proof.plan_digest, first_approval_task_id=parsed_proof.approval_task_id, approval_task_id=task_id, approver_ref=str(second_ref)),
            }
    if second_approval is not None:
        supplied_second = ApprovalBinding.model_validate(detached(second_approval))
        _require(supplied_second.approval_ref != binding.approval_ref, "SECOND_APPROVAL_REUSED", "one task cannot be both approvals")
        _require((supplied_second.transition_ref, supplied_second.request_digest, supplied_second.plan_digest) == (binding.transition_ref, binding.request_digest, binding.plan_digest)
            and supplied_second.decided_by_ref != binding.decided_by_ref, "SECOND_APPROVAL_UNBOUND", "both independent decisions must bind the same request")
        if proof is not None:
            _require(supplied_second.approval_ref == parsed_proof.second_approval_task_id and supplied_second.decided_by_ref == parsed_proof.second_approver_ref,
                "SECOND_APPROVAL_UNBOUND", "the supplied second decision must be the decision retained by the authority proof")
    if second_ref is None and second_approval is not None:
        other = ApprovalBinding.model_validate(detached(second_approval))
        _require(other.approval_ref != binding.approval_ref, "SECOND_APPROVAL_REUSED", "one task cannot be both approvals of a two-person decision")
        _require((other.transition_ref, other.request_digest, other.plan_digest) == (binding.transition_ref, binding.request_digest, binding.plan_digest), "SECOND_APPROVAL_UNBOUND", "the second approval binds a different transition")
        _require(other.decided_by_ref != binding.decided_by_ref, "SECOND_APPROVAL_UNBOUND", f"{other.decided_by_ref} decided both approvals; a second approver is somebody else")
        second_ref = other.decided_by_ref
        second = {
            "approver_ref": str(other.decided_by_ref),
            "approval_task_id": str(other.approval_ref),
            "decided_at": other.decided_at,
            "binding_digest": second_approval_digest(transition_ref=other.transition_ref, plan_digest=other.plan_digest, first_approval_task_id=binding.approval_ref, approval_task_id=str(other.approval_ref), approver_ref=str(other.decided_by_ref)),
        }
    cadence = CADENCE_LIFECYCLE.State.model_validate(detached(cadence_state))
    jobs = [_source(state, engine="job_chain", entity="job", plan=_plan_at(job_plans, index), code="JOB_STATE_INVALID", entity_key="job_ref") for index, state in enumerate(job_states)]
    engagements = [_source(state, engine="engagement_engine", entity="engagement", plan=_plan_at(engagement_plans, index), code="ENGAGEMENT_STATE_INVALID", entity_key="engagement_ref") for index, state in enumerate(engagement_states)]
    open_jobs = [source for source in jobs if _facts(source)["status"] not in CLOSED_JOB_STATUSES]
    open_engagements = [source for source in engagements if _facts(source)["status"] not in CLOSED_ENGAGEMENT_STATUSES]
    listing = [_facts(source)["state_digest"] for source in (*jobs, *engagements)]
    return {
        **evidence,
        "resolution": _resolution_facts(resolution),
        "second_approver_ref": second_ref,
        "second_approval": second,
        "decision_task": facts,
        "lifecycle_response": _lifecycle_facts(lifecycle_response),
        "entity_scope": detached(cadence.scope),
        "cadence_state_digest": cadence.state_digest,
        "cadence_bundle_digest": cadence.plan_digest,
        "cadence_status": cadence.status,
        "job_sources": jobs, "engagement_sources": engagements,
        "inventory_reads": detached(inventory_reads),
        "open_job_count": len(open_jobs),
        "open_engagement_count": len(open_engagements),
        "listing_digest": stable_digest(sorted(listing)),
        "evidence_refs": [*evidence["evidence_refs"], f"decision:{facts['id']}", f"resolution:{dict(detached(resolution)).get('resolution_ref')}", f"cadence:{cadence.state_digest[:24]}"],
    }


def notice_receipt(executions: Sequence[Any], requests: Sequence[Any], *, audience: str, eligibility: Mapping[str, Any] | Any, suppression_digest: str) -> dict[str, Any]:
    """One audience's notices: each bound execution paired with the exact request it ran for."""

    _require(len(executions) == len(requests) and len(executions) >= 1, "NOTICE_REQUEST_UNPAIRED", "every notice execution carries the exact request it was bound to")
    rows: list[dict[str, Any]] = []
    for execution, request in zip(executions, requests):
        bound = exact_request(execution, request, tools=NOTICE_TOOLS)
        raw = bound["request"]
        endpoints=raw.get("endpoint_digests") or []
        _require(bool(endpoints) and len(endpoints)==len(set(endpoints)) and raw.get("recipient_count")==len(endpoints),
            "NOTICE_REQUEST_UNPAIRED","notice counts must equal the exact unique requested endpoints")
        _require(str(raw.get("audience")) == audience, "NOTICE_AUDIENCE_MISMATCH", f"the request names the {raw.get('audience')!r} audience, not {audience!r}")
        rows.append(
            NoticeRef(
                audience=audience,
                tool=bound["tool"],
                execution_receipt_digest=bound["execution_receipt_digest"],
                request_digest=bound["request_digest"],
                sent_at=bound["sent_at"],
                count=len(raw.get("endpoint_digests") or ()),
                request=bound["source_request"],execution=bound["source_execution"],
                binding_digest=notice_binding_digest(audience, bound["tool"], bound["execution_receipt_digest"], bound["request_digest"]),
            ).to_dict()
        )
    facts = dict(detached(eligibility))
    _require(str(facts.get("schema")) == ELIGIBILITY_FACTS_SCHEMA, "ELIGIBILITY_SCHEMA_MISMATCH", f"expected {ELIGIBILITY_FACTS_SCHEMA}, got {facts.get('schema')!r}")
    _require(str(facts.get("suppression_digest")) == str(suppression_digest), "SUPPRESSION_DIGEST_MISMATCH", "the suppression digest is not the one the eligibility was assessed against")
    from lightbulb.permission_register import verify_eligibility
    for row in rows:
        verify_eligibility(facts.get("permission_receipt"),suppression_digest=suppression_digest,channel="email",at=row["sent_at"],
            company_ref=facts.get("company_ref"),endpoints=row["request"]["arguments"]["endpoint_digests"])
    return {"notices": rows, "eligibility": facts, "suppression_digest": str(suppression_digest), "evidence_refs": [f"notice:{audience}:{row['execution_receipt_digest'][:16]}" for row in rows]}


def merge_notices(*receipts: Mapping[str, Any]) -> dict[str, Any]:
    """One notify receipt from one per audience; the eligibility and suppression list must be the same assessment."""

    items = [dict(receipt) for receipt in receipts]
    _require(bool(items), "NOTICE_REQUEST_UNPAIRED", "a notify hop merges at least one audience")
    digests = {str(item.get("suppression_digest")) for item in items}
    _require(len(digests) == 1, "SUPPRESSION_DIGEST_MISMATCH", "the audiences were assessed against different suppression lists")
    return {
        "notices": [row for item in items for row in item.get("notices") or []],
        "eligibility": items[0]["eligibility"],
        "suppression_digest": items[0]["suppression_digest"],
        "evidence_refs": [ref for item in items for ref in item.get("evidence_refs") or []][:50],
    }


def none_applicable_receipt(kind: str, listing: Sequence[Any], *, inventory_reads: Sequence[Any]) -> dict[str, Any]:
    """An empty caller list is insufficient: retain exhaustive authenticated inventories."""
    rows = [detached(item) for item in listing]
    _require(not rows and bool(inventory_reads), "NONE_APPLICABLE_UNPROVEN", "retain the full empty host inventories")
    return {"none_applicable": True, "none_applicable_audiences": [kind] if kind in NOTICE_AUDIENCES else [], "listing_digest": stable_digest(rows),
        "inventory_reads": detached(inventory_reads), "detail": f"{kind}: no entities in the exhaustive host inventory"}


def _validate_inventories(plan, reads, expected, scope, at, *, records_only=False):
    from datetime import timedelta
    from lightbulb._engine_inventory import validate_inventory
    from lightbulb.company_execution_bridge import ObservationProvenance
    require(plan.inventory_tenant_commitment is not None and plan.inventory_company_commitment is not None,
        "WIND_DOWN_INVENTORY_SCOPE_REQUIRED", "the plan must pin the authenticated tenant and company inventory commitments")
    actual = {}
    for read in reads:
        output = validate_inventory(read["output"], project_id=scope["project_id"])
        provenance = ObservationProvenance.model_validate(read["provenance"])
        require(provenance.lane == "host_read" and provenance.source_tool == "lightbulb.get_engine_inventory"
            and provenance.output_digest == stable_digest(output), "WIND_DOWN_INVENTORY_UNPROVEN", "retain the authenticated inventory response and provenance")
        require(output["tenant_sha256"] == plan.inventory_tenant_commitment
            and output["company_sha256"] == plan.inventory_company_commitment,
            "WIND_DOWN_INVENTORY_SCOPE_MISMATCH", "inventory must belong to this tenant and company")
        require(output["exhaustive_read"] and not output["truncated"], "WIND_DOWN_INVENTORY_TRUNCATED", "a partial list cannot establish closure")
        require(parsed(output["observed_at"]) <= parsed(provenance.completed_at) <= parsed(at),
            "WIND_DOWN_INVENTORY_IN_FUTURE", "inventory must be available at this transition")
        require(parsed(output["observed_at"]) >= parsed(at)-timedelta(hours=plan.inventory_max_age_hours),
            "WIND_DOWN_INVENTORY_STALE", "refresh the inventory within the plan freshness window")
        require(output["engine"] not in actual, "WIND_DOWN_INVENTORY_DUPLICATE", "one complete snapshot per source engine")
        actual[output["engine"]] = output
    require(set(actual) == set(expected), "WIND_DOWN_INVENTORY_MISSING", "retain exactly the source engines needed for this step")
    for engine, sources in expected.items():
        sources = (sources,) if isinstance(sources, Mapping) else sources or ()
        listed = {row["entity_ref"]: (row["state_digest"], row["plan_digest"],row["status"],row["version"]) for row in actual[engine]["records"]}
        if records_only:
            retained = {row["entity_ref"]:(row["state_digest"],row["plan_digest"],row["status"],row["version"]) for row in sources}
        else:
            retained = {s["source_state"]["scope"]["entity_ref"]: (s["source_state"]["state_digest"],s["source_state"]["plan_digest"],s["source_state"]["status"],s["source_state"]["version"]) for s in sources}
            require(all(parsed(s["source_state"]["transition_history"][-1]["command"]["occurred_at"]) <= parsed(actual[engine]["observed_at"]) for s in sources),
                "WIND_DOWN_INVENTORY_STALE", "inventory cannot predate its source states")
        require(listed == retained, "WIND_DOWN_INVENTORY_MISMATCH", "every host-listed entity must be retained at its exact current version")


def _source(state: Mapping[str, Any] | Any, *, engine: str, entity: str, plan: Any, code: str, entity_key: str, **fields: str) -> dict[str, Any]:
    """Retain and replay the owning lifecycle; projections alone never close books."""
    from lightbulb._wind_down_sources import source_facts
    try:
        facts = SourceFacts(**source_facts(engine, plan, state)).to_dict()
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise WindDownError(code, "retain a valid full source plan and replayable state from the owning lifecycle") from exc
    return {"state": facts, "plan": detached(plan), "source_state": detached(state)}


def refunds_receipt(states: Sequence[Any], *, source_plans: Sequence[Any] = ()) -> dict[str, Any]:
    """From ``refund_and_dispute_chain`` refund cases; the status travels through so the guard, not the builder, refuses an open one."""

    sources = [_source(state, engine="refund_and_dispute_chain", entity=REFUND_ENTITY, plan=_plan_at(source_plans, index), code="REFUND_STATE_INVALID", entity_key="refund_ref", amount="refunded_amount", settled_at="cleared_at") for index, state in enumerate(states)]
    total = _totals(sources)
    return {"refund_sources": sources, "refund_total": str(total), "evidence_refs": [f"refund:{item['state']['entity_ref']}" for item in sources][:50]}


def subscriptions_receipt(
    commitment_states: Sequence[Any],
    customer_states: Sequence[Any],
    *,
    source_plans: Sequence[Any] = (),
    cancel_executions: Sequence[Any] = (),
    cancel_requests: Sequence[Any] = (),
) -> dict[str, Any]:
    """From ``spend_control_chain`` commitments and ``subscription_chain`` subscriptions, plus the bound provider cancellations."""

    commitments = [_source(state, engine="spend_control_chain", entity=COMMITMENT_ENTITY, plan=_plan_at(source_plans, 0), code="COMMITMENT_STATE_INVALID", entity_key="commitment_ref", amount="committed_amount", settled_at="terminated_at") for state in commitment_states]
    customers = [_source(state, engine="subscription_chain", entity=SUBSCRIPTION_ENTITY, plan=_plan_at(source_plans, 1), code="SUBSCRIPTION_STATE_INVALID", entity_key="subscription_ref", amount="mrr", settled_at="cancelled_at") for state in customer_states]
    _require(len(cancel_executions) == len(cancel_requests), "SUBSCRIPTION_REQUEST_UNPAIRED", "every cancellation execution carries the exact request it was bound to")
    rows: list[dict[str, Any]] = []
    for execution, request in zip(cancel_executions, cancel_requests):
        bound = exact_request(execution, request, tools=frozenset({SUBSCRIPTION_CANCEL_TOOL}))
        raw = bound["request"]
        _require(bool(raw.get("subscription_ref")), "SUBSCRIPTION_REQUEST_UNPAIRED", "a cancellation request names the subscription it cancels")
        rows.append({
            "subscription_ref": str(raw["subscription_ref"]),
            "source_request":bound["source_request"],"source_execution":bound["source_execution"],
            "tool": bound["tool"],
            "execution_receipt_digest": bound["execution_receipt_digest"],
            "request_digest": bound["request_digest"],
            "approval_ref": bound["approval_ref"],
            "cancelled_at": bound["sent_at"],
            "binding_digest": notice_binding_digest(str(raw["subscription_ref"]), bound["tool"], bound["execution_receipt_digest"], bound["request_digest"]),
        })
    return {
        "commitment_sources": commitments,
        "customer_subscription_sources": customers,
        "subscription_cancel_executions": rows,
        "subscription_cancel_requests": [{"subscription_ref": row["subscription_ref"], "request_digest": row["request_digest"]} for row in rows],
        "evidence_refs": [*[f"commitment:{item['state']['entity_ref']}" for item in commitments], *[f"subscription:{item['state']['entity_ref']}" for item in customers]][:50],
    }


def receivables_receipt(states: Sequence[Any], *, source_plans: Sequence[Any] = (), write_off_proofs: Sequence[Any] = ()) -> dict[str, Any]:
    """From ``collections_chain`` cases, with a ``write_off`` authority proof for every case that was written off."""

    sources = [_source(state, engine="collections_chain", entity=RECEIVABLE_ENTITY, plan=_plan_at(source_plans, index), code="RECEIVABLE_STATE_INVALID", entity_key="receivable_ref", amount="outstanding_amount", settled_at="closed_at") for index, state in enumerate(states)]
    proofs = [verify_authorization(proof, category="write_off") for proof in write_off_proofs]
    return {"collections_sources": sources, "write_off_proofs": proofs, "evidence_refs": [*[f"receivable:{item['state']['entity_ref']}" for item in sources], *[f"write_off:{item['approval_task_id']}" for item in proofs]][:50]}


def payables_receipt(payable_states: Sequence[Any], disbursement_states: Sequence[Any], *, source_plans: Sequence[Any] = ()) -> dict[str, Any]:
    """From ``payables_chain`` cases and the ``disbursement_run`` states that actually moved the money."""

    payables = [_source(state, engine="payables_chain", entity=PAYABLE_ENTITY, plan=_plan_at(source_plans, 0), code="PAYABLE_STATE_INVALID", entity_key="bill_ref", amount="paid_amount", settled_at="paid_at") for state in payable_states]
    runs = [_source(state, engine="disbursement_run", entity=DISBURSEMENT_ENTITY, plan=_plan_at(source_plans, 1), code="DISBURSEMENT_STATE_INVALID", entity_key="run_ref", amount="settled_amount", settled_at="settled_at") for state in disbursement_states]
    return {"payable_sources": payables, "disbursement_sources": runs, "evidence_refs": [*[f"payable:{item['state']['entity_ref']}" for item in payables], *[f"disbursement:{item['state']['entity_ref']}" for item in runs]][:50]}


def final_pay_receipt(employment_states: Sequence[Any], *, employment_plan: EmploymentPlan | Mapping[str, Any], payroll_states: Sequence[Any] = (), payroll_plans: Sequence[Any] = ()) -> dict[str, Any]:
    """From ``employment_chain``'s headcount proof (states rebound through its own lifecycle) and the reconciled final pay runs."""

    plan = EmploymentPlan.model_validate(detached(employment_plan))
    bound = [EMPLOYMENT_LIFECYCLE.bind(plan, state)[1] for state in employment_states]
    head = headcount_receipt(bound, plan=plan)
    sources = [_source(state, engine="employment_chain", entity="employee", plan=plan,
        code="EMPLOYMENT_STATE_INVALID", entity_key="worker_ref") for state in bound]
    runs = [_source(state, engine="payroll_run_chain", entity=PAY_RUN_ENTITY,
        plan=_plan_at(payroll_plans, index), code="PAY_RUN_STATE_INVALID", entity_key="run_ref")
        for index, state in enumerate(payroll_states)]
    return {
        "headcount": {**head, "notice_floor_days": plan.min_notice_days},
        "employment_sources": sources,
        "payroll_sources": runs,
        "evidence_refs": [*[f"employee:{item['state']['entity_ref']}" for item in sources], *[f"payrun:{run['state']['entity_ref']}" for run in runs]][:50],
    }


def deregistration_receipt(
    standing_states: Sequence[Any],
    *,
    source_plans: Sequence[Any] = (),
    lodgements: Sequence[Any] = (),
    compliance_states: Sequence[Any] = (),
    compliance_plans: Sequence[Any] = (),
    registry_confirmation: Mapping[str, Any] | Any | None = None,
) -> dict[str, Any]:
    """From surrendered ``obligation_paper`` standing items, operator-held lodgement receipts, and the final ``compliance_calendar`` obligations."""

    standing = [_source(state, engine="obligation_paper", entity=STANDING_ENTITY, plan=_plan_at(source_plans, index), code="STANDING_STATE_INVALID", entity_key="item_ref", kind="kind", settled_at="surrendered_at") for index, state in enumerate(standing_states)]
    filings = [filing_receipt(item) for item in lodgements]
    obligations = [_source(state, engine="compliance_calendar", entity=OBLIGATION_ENTITY, plan=_plan_at(compliance_plans, index), code="OBLIGATION_STATE_INVALID", entity_key="obligation_ref", kind="kind", period_end="period_end", settled_at="lodged_at") for index, state in enumerate(compliance_states)]
    confirmation = None
    if registry_confirmation is not None:
        raw = dict(detached(registry_confirmation))
        for key in ("source", "observation_digest", "confirmed_at"):
            _require(bool(raw.get(key)), "REGISTRY_CONFIRMATION_INCOMPLETE", f"the registrar confirmation lacks {key}")
        confirmation = {"source": str(raw["source"]), "observation_digest": str(raw["observation_digest"]), "confirmed_at": timestamp(str(raw["confirmed_at"]), field_name="confirmed_at"), "reference": str(raw.get("reference") or "")}
    return {
        "standing_sources": standing,
        "lodgements": filings,
        "compliance_sources": obligations,
        "registry_confirmation": confirmation,
        "evidence_refs": [*[f"standing:{item['state']['entity_ref']}" for item in standing], *[f"lodgement:{item['lodgement_ref']}" for item in filings]][:50],
    }


def accounts_receipt(
    bank_state: Mapping[str, Any] | Any,
    *,
    bank_plan: Any = None,
    close_state: Mapping[str, Any] | Any,
    close_plan: Any = None,
    register_state: Mapping[str, Any] | Any,
    register_plan: Any = None,
    connection_rows: Sequence[Mapping[str, Any]] = (),
    lifecycle_response: Mapping[str, Any] | Any,
    task: Mapping[str, Any] | Any | None = None,
) -> dict[str, Any]:
    """From the reconciled bank account, the closed books, the closed cost register, the account's connection rows, and the platform's CLOSED receipt."""

    bank = _source(bank_state, engine="bank_reconciliation", entity=BANK_ENTITY, plan=bank_plan, code="BANK_STATE_INVALID", entity_key="account_ref", amount="statement_closing", settled_at="reconciled_at")
    close = _source(close_state, engine="finance_close", entity=CLOSE_ENTITY, plan=close_plan, code="CLOSE_STATE_INVALID", entity_key="close_ref", period_end="period_end", settled_at="closed_at")
    register = _source(register_state, engine="company_cost_centres", entity=COST_REGISTER_ENTITY, plan=register_plan, code="REGISTER_STATE_INVALID", entity_key="register_ref", period_end="period_end", settled_at="closed_at")
    rows: list[dict[str, Any]] = []
    for row in connection_rows:
        raw = dict(detached(row))
        provider = normalize_provider(raw.get("provider"))
        _require(bool(provider), "CONNECTION_ROW_INVALID", "a connection row names its provider")
        scope = str(raw.get("connectionScope") or raw.get("connection_scope") or "unknown").lower()
        rows.append(ConnectionRow(provider=provider, status=str(raw.get("status", "")).lower(), connection_digest=stable_digest({"provider": provider, "scope": scope, "id": str(raw.get("id", ""))})).to_dict())
    return {
        "bank_source": bank,
        "close_source": close,
        "register_source": register,
        "connections": rows,
        "closing_balance": str(decimal_value(bank["state"].get("amount", "0"), field_name="closing_balance", allow_negative=True)),
        "lifecycle_response": _lifecycle_facts(lifecycle_response),
        "decision_task": None if task is None else _task_facts(task),
        "evidence_refs": [f"bank:{bank['state']['entity_ref']}", f"close:{close['state']['entity_ref']}", f"register:{register['state']['entity_ref']}"],
    }


# --------------------------------------------------------------------------- #
# What the chain hands to the rest of the runtime
# --------------------------------------------------------------------------- #


def _bound(state: Any, plan: WindDownPlan | Mapping[str, Any] | None = None) -> Any:
    parsed_state = state if isinstance(state, WindDownState) else WindDownState.model_validate(detached(state))
    if plan is not None:
        parsed_plan = WindDownPlan.model_validate(detached(plan))
        _require(parsed_state.plan_digest == parsed_plan.plan_digest, "WIND_DOWN_PLAN_MISMATCH", "the wind-down belongs to a different plan")
    return parsed_state


#: The hops from which the cadence may be stopped for good: the workers are paid.
CADENCE_STOP_STATUSES: frozenset[str] = frozenset({"final_pay_run_done", "deregistered", "accounts_closed", "closed"})


def cadence_stop_receipt(state: Any) -> str:
    """The only reason ``CadenceWorker.control('stop')`` accepts once a wind-down exists: this exact state, at this exact version."""

    parsed_state = _bound(state)
    _require(parsed_state.status in CADENCE_STOP_STATUSES, "CADENCE_STOP_TOO_EARLY", f"the wind-down is {parsed_state.status}; the cadence stops for good once the final pay run is done, not before")
    return f"wind_down:{parsed_state.scope.entity_ref}:{parsed_state.state_digest[:16]}"


def wind_down_flows(state: Any) -> tuple[dict[str, Any], ...]:
    """The outflows the treasury has to cover: the refunds the chain settled and the final pay run it proved."""

    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    rows: list[dict[str, Any]] = []
    if ledger.refunds_total > 0 and ledger.refunds_settled_at is not None:
        rows.append({"kind": "payable", "ref": f"{parsed_state.scope.entity_ref}:refunds", "due_at": ledger.refunds_settled_at, "amount": str(ledger.refunds_total), "source": WIND_DOWN_KIND})
    if ledger.final_pay_total > 0 and ledger.final_pay_done_at is not None:
        rows.append({"kind": "payroll", "ref": f"{parsed_state.scope.entity_ref}:final_pay", "due_at": ledger.final_pay_done_at, "amount": str(ledger.final_pay_total), "source": WIND_DOWN_KIND})
    return tuple(rows)


def wind_down_exception(error: Exception, *, source_ref: str, hop: str | None = None) -> dict[str, Any]:
    """An exceptions-desk ``wind_down_blocked`` opening receipt for a refused hop."""

    code = str(getattr(error, "code", None) or getattr(error, "rejection_code", None) or "WIND_DOWN_BLOCKED")
    detail = str(getattr(error, "message", None) or getattr(error, "instructions", None) or error)
    return {
        "kind": "wind_down_blocked",
        "source_engine": WIND_DOWN_KIND,
        "source_ref": source_ref,
        "source_digest": stable_digest({"source_ref": source_ref, "code": code, "detail": detail}),
        "code": code,
        "detail": (f"{hop}: {detail}" if hop else detail)[:900],
        "evidence_refs": [f"wind_down:{code.lower()}"],
    }


def _day(stamp: str | None) -> str:
    if not stamp:
        return "?"
    when = parsed(stamp)
    return f"{when.day} {when.strftime('%b')}"


def narrate_wind_down(state: Any, *, currency: str | None = None) -> str:
    """One line an operator reads: who decided it, what was settled, and where it stands."""

    parsed_state = _bound(state)
    ledger = parsed_state.ledger
    unit = currency or "AUD"
    parts = [f"{parsed_state.scope.entity_ref}: decided {_day(ledger.decided_at)} by {len(ledger.decided_by_refs)} approvers (reserve {money(ledger.settlement_reserve, unit)})"]
    if ledger.notified_at is not None:
        parts.append(f"notified {'/'.join(sorted(ledger.notified_by_audience))} {_day(ledger.notified_at)}")
    if ledger.refunds_settled_at is not None:
        parts.append(f"refunds {money(ledger.refunds_total, unit)}")
    if ledger.subscriptions_cancelled_at is not None:
        parts.append(f"{ledger.subscriptions_cancelled} subscriptions cancelled")
    if ledger.receivables_closed_at is not None:
        parts.append(f"receivables {money(ledger.receivables_recovered, unit)} recovered, {money(ledger.receivables_written_off, unit)} written off")
    if ledger.payables_settled_at is not None:
        parts.append(f"payables {money(ledger.payables_settled, unit)}")
    if ledger.final_pay_done_at is not None:
        parts.append(f"{ledger.employees_offboarded} offboarded, final pay {_day(ledger.final_pay_done_at)}")
    if ledger.deregistered_at is not None:
        parts.append(f"deregistered {_day(ledger.deregistered_at)} ({', '.join(ledger.lodgement_refs)})")
    if ledger.accounts_closed_at is not None:
        parts.append(f"{ledger.connections_revoked} connections revoked, balance {money(ledger.closing_balance, unit)}")
    if ledger.closed_at is not None:
        parts.append(f"closed {_day(ledger.closed_at)} after {ledger.days_decision_to_close} days")
    else:
        parts.append(f"status {parsed_state.status}")
    return " · ".join(parts)


def wind_down_summary(state: Any, *, plan: WindDownPlan | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The brief's and the board pack's row for one wind-down.

    A caller that holds the plan it compiled passes it, and the row is refused
    if the state belongs to another one; the brief renders many companies.
    """

    parsed_state = _bound(state, plan)
    ledger = parsed_state.ledger
    return {
        "inventory_source_coverage": "persisted_sdk_engine_states_only",
        "external_source_coverage": "not_established_by_sdk_inventory",
        "inventory_counts": {engine: len(rows) for engine, rows in ledger.inventory_records.items()},
        "wind_down_ref": str(parsed_state.scope.entity_ref),
        "status": parsed_state.status,
        "decided_at": ledger.decided_at,
        "decided_by_refs": list(ledger.decided_by_refs),
        "settlement_reserve": str(ledger.settlement_reserve),
        "refunds_total": str(ledger.refunds_total),
        "subscriptions_cancelled": ledger.subscriptions_cancelled,
        "receivables_recovered": str(ledger.receivables_recovered),
        "receivables_written_off": str(ledger.receivables_written_off),
        "payables_settled": str(ledger.payables_settled),
        "employees_offboarded": ledger.employees_offboarded,
        "lodgement_refs": list(ledger.lodgement_refs),
        "closing_balance": str(ledger.closing_balance),
        "connections_revoked": ledger.connections_revoked,
        "days_decision_to_close": ledger.days_decision_to_close,
        "outcome": ledger.outcome,
        "state_digest": parsed_state.state_digest,
    }


WIND_DOWN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": WIND_DOWN_KIND,
    "golden_loop": WIND_DOWN_GOLDEN_LOOP,
    "stages": ["decide", "notify", "settle_refunds", "cancel_subscriptions", "close_receivables", "settle_payables", "run_final_pay", "deregister", "close_accounts", "close"],
    "statuses": list(WIND_DOWN_STATUSES),
    "events": list(WIND_DOWN_EVENTS),
    "hops": {
        "decide": "a human-decided sdk_engine_transition task + a two-person wind_down AuthorizationProof + a signed directors'/members' resolution + client.wind_down_company's WINDING_DOWN receipt + a paused cadence",
        "notify": "bound gmail/microsoft/twilio write execution receipts with permission_register eligibility, per audience",
        "settle_refunds": "refund_and_dispute_chain cases cleared or denied, after the refund window",
        "cancel_subscriptions": "spend_control_chain commitments terminated + subscription_chain subscriptions closed + the bound provider cancellations",
        "close_receivables": "collections_chain cases recovered or written off under a write_off authority proof",
        "settle_payables": "payables_chain cases settled + disbursement_run runs settled or reconciled",
        "run_final_pay": "employment_chain headcount proof (all offboarded) + reconciled payroll_run_chain runs reserving every positive statutory liability",
        "deregister": "obligation_paper standing items surrendered + operator-held ASIC/CRA lodgement receipts + the final compliance_calendar obligations + the registrar's confirmation",
        "close_accounts": "bank_reconciliation reconciled at zero + finance_close closed + cost register closed + every OAuth connection revoked + client.close_company's CLOSED receipt",
        "close": "the whole sequence, inside the plan's decision-to-close ceiling",
    },
    "required_connectors": ["xero", "stripe", "square", "gmail", "operator_filing", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a wind-down is a two-person money decision bound to a directors resolution and the platform's lifecycle receipt, never a stop command",
        "an auto-accepted task cannot start a wind-down",
        "every settlement hop consumes the terminal state of the chain that owns that money",
        "nothing is deregistered while a worker is unpaid or a statutory liability is unreserved",
        "the platform stops selling the moment the company is winding down; the SDK cannot talk it back into a campaign",
        "accounts close at zero with every connection revoked",
    ],
}

__all__ = [
    "CADENCE_STOP_STATUSES",
    "CLEARED_REFUND_STATUSES",
    "CLOSED_RECEIVABLE_STATUSES",
    "CLOSED_SUBSCRIPTION_STATUSES",
    "ELIGIBILITY_FACTS_SCHEMA",
    "EXECUTION_REQUEST_SCHEMA",
    "LEFT_EMPLOYMENT_STATUSES",
    "MAX_WIND_DOWN_TRANSITIONS",
    "NOTICE_AUDIENCES",
    "NOTICE_TOOLS",
    "RESOLUTION_SCHEMA",
    "SETTLED_DISBURSEMENT_STATUSES",
    "SETTLED_PAYABLE_STATUSES",
    "SOURCE_FACTS_SCHEMA",
    "SUBSCRIPTION_CANCEL_TOOL",
    "TERMINAL_WIND_DOWN_STATUSES",
    "TERMINATED_COMMITMENT_STATUSES",
    "WIND_DOWN_EVENTS",
    "WIND_DOWN_GOLDEN_LOOP",
    "WIND_DOWN_KIND",
    "WIND_DOWN_LIFECYCLE",
    "WIND_DOWN_MANIFEST",
    "WIND_DOWN_PLAN_SCHEMA",
    "WIND_DOWN_STATUSES",
    "ConnectionRow",
    "EligibilityFacts",
    "NoticeRef",
    "SourceFacts",
    "WindDownEffectBoundary",
    "WindDownError",
    "WindDownLedger",
    "WindDownPlan",
    "WindDownReceipt",
    "WindDownState",
    "accounts_receipt",
    "advance_wind_down",
    "cadence_stop_receipt",
    "compile_wind_down",
    "decision_receipt",
    "deregistration_receipt",
    "eligibility",
    "exact_request",
    "filing_receipt",
    "final_pay_receipt",
    "merge_notices",
    "narrate_wind_down",
    "none_applicable_receipt",
    "notice_binding_digest",
    "notice_receipt",
    "open_wind_down",
    "payables_receipt",
    "receivables_receipt",
    "refunds_receipt",
    "second_approval_digest",
    "subscriptions_receipt",
    "verify_authorization",
    "verify_paid_pay_run",
    "wind_down_exception",
    "wind_down_flows",
    "wind_down_summary",
]
