"""The partner commission chain: one replay-fenced lifecycle per partner and period, from an in-force agreement to the commission paid.

Customer referrals were tracked, and a partner agreement could sit in
obligation paper, but nothing connected a partner's agreement to the
settled revenue it brought in, accrued what was owed under the program's
rate, or proved the commission was paid.  ``PARTNER_COMMISSION_LIFECYCLE``
does:

    agreed -> attributed -> accrued -> approved -> paid        (terminal)
    attributed | accrued -> disputed -> attributed
    agreed | attributed | accrued | disputed -> voided         (terminal, with a reason)

* ``agreement_receipt`` opens the case from the partner's replayed
  ``AgreementState`` in obligation paper: in force, and naming the partner
  as its counterparty.
* ``attribution_receipt`` consumes a settled or cleared ``RevenueCaseState``
  replayed against its plan plus the referral that names the partner; the
  settled amount is the chain's, never typed, and a case attributes once.
* ``accrue`` computes the commission from the program's rate over the
  attributed settled cash, capped when the program caps it.
* ``approve`` consumes a ``payout`` authority proof for the exact accrual.
* ``payment_receipt`` consumes a bank read of the exact transfer to the
  partner after approval.

Nothing here pays a partner, posts a journal, or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

PARTNER_COMMISSION_KIND = "partner_commission_chain"
PARTNER_COMMISSION_GOLDEN_LOOP = "partner.agreement_to_paid_commission@0.1.0"
PARTNER_COMMISSION_PLAN_SCHEMA = "lightbulb.partner_commission_plan.v1"
REFERRAL_SCHEMA = "lightbulb.partner_referral.v1"
MAX_COMMISSION_TRANSITIONS = 60
IN_FORCE_AGREEMENT_STATUSES: frozenset[str] = frozenset({"registered", "in_force", "renewed", "amended", "notice_window"})
SETTLED_REVENUE_STATUSES: frozenset[str] = frozenset({"cash_settled", "cleared"})
PAYMENT_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_purchases", "host.bank_transfer", "airwallex.list_payouts", "stripe.list_payouts"})
_HUNDRED = Decimal("100")

COMMISSION_STATUSES: tuple[str, ...] = ("agreed", "attributed", "accrued", "approved", "paid", "disputed", "voided")
TERMINAL_COMMISSION_STATUSES: frozenset[str] = frozenset({"paid", "voided"})
COMMISSION_EVENTS: tuple[str, ...] = ("agree", "attribute", "accrue", "approve", "pay", "dispute", "resolve_dispute", "void")
_COMMISSION_TABLE: dict[tuple[str, str], str] = {
    ("new", "agree"): "agreed",
    ("agreed", "attribute"): "attributed",
    ("attributed", "attribute"): "attributed",
    ("attributed", "accrue"): "accrued",
    ("accrued", "approve"): "approved",
    ("approved", "pay"): "paid",
    ("attributed", "dispute"): "disputed",
    ("accrued", "dispute"): "disputed",
    ("disputed", "resolve_dispute"): "attributed",
    **{(status, "void"): "voided" for status in ("agreed", "attributed", "accrued", "disputed")},
}


class PartnerCommissionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PartnerCommissionError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class PartnerProgram(StrictModel):
    partner_ref: OpaqueRef
    rate_percent: Decimal
    basis: Literal["settled_revenue"] = "settled_revenue"
    payout_terms_days: int = Field(default=30, ge=0, le=180)
    cap_per_period: Decimal | None = None

    @field_validator("rate_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="rate_percent")
        if result <= 0 or result > Decimal("50"):
            raise ValueError("a commission rate is above zero and at most 50 percent")
        return result

    @field_validator("cap_per_period", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="cap_per_period")


class PartnerCommissionPlan(StrictModel):
    """What the chain enforces: the programs by partner, whether agreement paper is required, and the reads that prove payment."""

    schema_id: str = Field(default=PARTNER_COMMISSION_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    programs: tuple[PartnerProgram, ...] = Field(min_length=1, max_length=200)
    require_agreement_paper: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("programs", mode="before")
    @classmethod
    def _programs(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "PartnerCommissionPlan":
        unique([item.partner_ref for item in self.programs], label="partner programs")
        if not skip_digests(info) and self.plan_digest != sealed_digest(PartnerCommissionPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def program(self, partner_ref: str) -> PartnerProgram | None:
        return next((item for item in self.programs if item.partner_ref == partner_ref), None)


def compile_partner_commission_chain(company_ref: str, *, currency: str, programs: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> PartnerCommissionPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "programs": [dict(detached(item)) for item in programs], **dict(overrides or {})}
    return seal(PartnerCommissionPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class Attribution(StrictModel):
    case_ref: OpaqueRef
    case_digest: Sha256Digest
    referral_ref: OpaqueRef
    settled_amount: Decimal
    settled_at: str

    @field_validator("settled_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="settled_amount")


class CommissionReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    partner_ref: OpaqueRef | None = None
    period_ref: OpaqueRef | None = None
    agreement_source: dict[str, Any] | None = None
    agreement_plan: dict[str, Any] | None = None
    agreement_ref: OpaqueRef | None = None
    revenue_source: dict[str, Any] | None = None
    revenue_plan: dict[str, Any] | None = None
    referral_ref: OpaqueRef | None = None
    referral_digest: Sha256Digest | None = None
    authorization_proof: dict[str, Any] | None = None
    payment_provenance: dict[str, Any] | None = None
    payment_digest: Sha256Digest | None = None
    paid_amount: Decimal | None = None
    paid_at: str | None = None
    payee_ref: OpaqueRef | None = None
    resolution_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="paid_amount")

    @field_validator("paid_at")
    @classmethod
    def _stamp(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="paid_at")


class CommissionLedger(StrictModel):
    partner_ref: str | None = None
    period_ref: str | None = None
    agreement_ref: str | None = None
    agreement_digest: str | None = None
    agreed_at: str | None = None
    rate_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    attributions: tuple[Attribution, ...] = Field(default_factory=tuple, max_length=500)
    attributed_settled: Decimal = Field(default=Decimal("0"), validate_default=True)
    accrued_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    capped: bool = False
    accrued_at: str | None = None
    approved_at: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    paid_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_at: str | None = None
    payment_digest: str | None = None
    disputes: int = Field(default=0, ge=0)
    dispute_reason: str | None = None
    resolution_sha256: str | None = None
    void_reason: str | None = None
    outcome: Literal["open", "paid", "voided"] = "open"

    @field_validator("attributions", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("rate_percent", "attributed_settled", "accrued_amount", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class CommissionEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    partner_paid: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_commission(plan: PartnerCommissionPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "agree":
        require(r.partner_ref is not None and r.period_ref is not None, "AGREEMENT_MISSING", "a commission case names the partner and the period")
        program = plan.program(str(r.partner_ref))
        require(program is not None, "PARTNER_UNKNOWN", f"{r.partner_ref} has no program in this plan")
        assert program is not None
        agreement_digest = None
        if plan.require_agreement_paper:
            require(r.agreement_source is not None and r.agreement_plan is not None, "AGREEMENT_NOT_PROVEN", "the partner's agreement must be the replayed obligation-paper state and its plan")
            from lightbulb.obligation_paper import AGREEMENT_LIFECYCLE

            try:
                paper_plan, agreement = AGREEMENT_LIFECYCLE.bind(r.agreement_plan, r.agreement_source)
            except (ValueError, TypeError, KeyError) as exc:
                require(False, "AGREEMENT_NOT_PROVEN", f"the agreement must replay against its exact plan: {exc}"[:300])
                raise AssertionError from exc
            require(paper_plan.company_ref == plan.company_ref, "AGREEMENT_SCOPE_MISMATCH", "the agreement belongs to another company")
            require(agreement.status in IN_FORCE_AGREEMENT_STATUSES, "AGREEMENT_NOT_IN_FORCE", f"the agreement is {agreement.status}")
            require(str(agreement.ledger.counterparty_ref) == str(r.partner_ref), "COUNTERPARTY_MISMATCH", f"the agreement's counterparty is {agreement.ledger.counterparty_ref}, not {r.partner_ref}")
            require(parsed(agreement.transition_history[-1].command.occurred_at) <= parsed(at), "AGREEMENT_FROM_FUTURE", "the agreement cannot come from the future")
            agreement_digest = agreement.state_digest
            data["agreement_ref"] = agreement.ledger.agreement_ref
        else:
            require(r.agreement_ref is not None, "AGREEMENT_MISSING", "a commission case names the partner agreement")
            data["agreement_ref"] = r.agreement_ref
        data.update({"partner_ref": r.partner_ref, "period_ref": r.period_ref, "agreement_digest": agreement_digest, "agreed_at": at, "rate_percent": str(program.rate_percent)})
    elif event == "attribute":
        require(r.revenue_source is not None and r.revenue_plan is not None and r.referral_ref is not None and r.referral_digest is not None, "ATTRIBUTION_NOT_PROVEN", "an attribution carries the replayed revenue case, its plan, and the referral that names the partner")
        from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE

        try:
            revenue_plan, case = REVENUE_CHAIN_LIFECYCLE.bind(r.revenue_plan, r.revenue_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "ATTRIBUTION_NOT_PROVEN", f"the revenue case must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(revenue_plan.company_ref == plan.company_ref and case.scope.currency == plan.currency, "REVENUE_SCOPE_MISMATCH", "the revenue case belongs to another company or currency")
        require(case.status in SETTLED_REVENUE_STATUSES, "REVENUE_NOT_SETTLED", f"the revenue case is {case.status}; commission accrues on settled cash only")
        require(all(str(dict(item)["case_digest"]) != case.state_digest and str(dict(item)["case_ref"]) != case.scope.entity_ref for item in data.get("attributions", ())), "CASE_ALREADY_ATTRIBUTED", "this revenue case already earned commission on this partner")
        require(parsed(case.transition_history[-1].command.occurred_at) <= parsed(at), "REVENUE_FROM_FUTURE", "the revenue case cannot come from the future")
        require(r.referral_digest == stable_digest({"schema": REFERRAL_SCHEMA, "referral_ref": r.referral_ref, "partner_ref": data.get("partner_ref"), "prospect_ref": case.ledger.prospect_ref}), "REFERRAL_MISMATCH", "the referral does not bind this partner to the prospect the case was won from")
        settled = _money(case.ledger.settled_amount)
        require(settled > 0, "REVENUE_NOT_SETTLED", "the revenue case settled nothing")
        attribution = Attribution(case_ref=case.scope.entity_ref, case_digest=case.state_digest, referral_ref=str(r.referral_ref), settled_amount=settled, settled_at=str(case.ledger.settled_at or case.transition_history[-1].command.occurred_at))
        data.update({"attributions": [*[dict(item) for item in data.get("attributions", ())], attribution.to_dict()], "attributed_settled": str(_money(Decimal(str(data["attributed_settled"])) + settled))})
    elif event == "accrue":
        program = plan.program(str(data["partner_ref"]))
        assert program is not None
        base = Decimal(str(data["attributed_settled"]))
        require(base > 0, "NOTHING_ATTRIBUTED", "no settled revenue is attributed to this partner")
        amount = _money(base * program.rate_percent / _HUNDRED)
        capped = program.cap_per_period is not None and amount > program.cap_per_period
        if capped:
            amount = _money(program.cap_per_period)
        data.update({"accrued_amount": str(amount), "capped": capped, "accrued_at": at})
    elif event == "approve":
        require(r.authorization_proof is not None, "COMMISSION_NOT_AUTHORIZED", f"paying {data['accrued_amount']} {plan.currency} to {data['partner_ref']} is a payout decision; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof

        proof = require_authorization_proof(r.authorization_proof, category="payout", amount=Decimal(str(data["accrued_amount"])), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
        require(proof.engine == PARTNER_COMMISSION_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        data.update({"approved_at": at, "approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref})
    elif event == "pay":
        require(r.payment_provenance is not None and r.payment_digest is not None and r.paid_amount is not None and r.paid_at is not None and r.payee_ref is not None, "PAYMENT_EVIDENCE_MISSING", "a payment carries the read provenance, its digest, the amount, the time, and the payee")
        require(str(dict(r.payment_provenance or {}).get("output_digest")) == r.payment_digest, "PAYMENT_NOT_BOUND", "the provenance does not seal this payment")
        require(r.payee_ref == data.get("partner_ref"), "PAYEE_MISMATCH", "the money reached someone other than the partner")
        require(_money(r.paid_amount) == Decimal(str(data["accrued_amount"])), "PAYMENT_AMOUNT_MISMATCH", f"the accrual is {data['accrued_amount']}; the transfer was {r.paid_amount}")
        program = plan.program(str(data["partner_ref"]))
        assert program is not None
        require(parsed(str(data["approved_at"])) <= parsed(str(r.paid_at)) <= parsed(at), "PAYMENT_TIME_INVALID", "a payment follows the approval and precedes its recording")
        days = (parsed(str(r.paid_at)) - parsed(str(data["approved_at"]))).days
        require(days <= program.payout_terms_days, "PAYMENT_LATE", f"the transfer landed {days} days after approval; the program's terms are {program.payout_terms_days} days", "manual_reconciliation")
        data.update({"paid_amount": str(_money(r.paid_amount)), "paid_at": r.paid_at, "payment_digest": r.payment_digest, "outcome": "paid"})
    elif event == "dispute":
        data.update({"disputes": int(data.get("disputes", 0)) + 1, "dispute_reason": str(command.reason)[:300], "accrued_amount": "0", "capped": False, "accrued_at": None})
    elif event == "resolve_dispute":
        require(r.resolution_sha256 is not None, "RESOLUTION_MISSING", "a dispute resolves with the digest of the agreed resolution")
        data.update({"resolution_sha256": r.resolution_sha256})
    elif event == "void":
        data.update({"void_reason": str(command.reason)[:300], "outcome": "voided"})
    return next_status, data


PARTNER_COMMISSION_LIFECYCLE = LifecycleSpec(entity="partner_commission", schema_prefix=PARTNER_COMMISSION_KIND, statuses=COMMISSION_STATUSES, terminal=TERMINAL_COMMISSION_STATUSES, events=COMMISSION_EVENTS, table=_COMMISSION_TABLE, opening_event="agree", reason_events=("dispute", "void"), apply=_apply_commission, ledger_model=CommissionLedger, receipt_model=CommissionReceipt, effect_boundary_model=CommissionEffectBoundary, plan_model=PartnerCommissionPlan, max_transitions=MAX_COMMISSION_TRANSITIONS)
PartnerCommissionState = PARTNER_COMMISSION_LIFECYCLE.State


def open_partner_commission(plan: PartnerCommissionPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return PARTNER_COMMISSION_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_partner_commission(plan: PartnerCommissionPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PARTNER_COMMISSION_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def agreement_receipt(agreement_state: Any, *, source_plan: Any, partner_ref: str, period_ref: str) -> dict[str, Any]:
    """The opening receipt from the partner's replayed obligation-paper agreement."""

    from lightbulb.obligation_paper import AGREEMENT_LIFECYCLE

    try:
        plan, state = AGREEMENT_LIFECYCLE.bind(source_plan, agreement_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise PartnerCommissionError("AGREEMENT_NOT_PROVEN", "retain the original agreement state and its sealed plan") from exc
    _require(state.status in IN_FORCE_AGREEMENT_STATUSES, "AGREEMENT_NOT_IN_FORCE", f"the agreement is {state.status}")
    return {"partner_ref": partner_ref, "period_ref": period_ref, "agreement_source": state.to_dict(), "agreement_plan": plan.to_dict(), "evidence_refs": [f"agreement:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def referral_digest(*, referral_ref: str, partner_ref: str, prospect_ref: str) -> str:
    """The digest a referral registration commits to: partner, referral, and the prospect it introduced."""

    return stable_digest({"schema": REFERRAL_SCHEMA, "referral_ref": referral_ref, "partner_ref": partner_ref, "prospect_ref": prospect_ref})


def attribution_receipt(revenue_state: Any, *, source_plan: Any, referral_ref: str, partner_ref: str) -> dict[str, Any]:
    """From a settled revenue case and the referral that names the partner for its prospect."""

    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE

    try:
        plan, state = REVENUE_CHAIN_LIFECYCLE.bind(source_plan, revenue_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise PartnerCommissionError("ATTRIBUTION_NOT_PROVEN", "retain the original revenue case and its sealed plan") from exc
    _require(state.status in SETTLED_REVENUE_STATUSES, "REVENUE_NOT_SETTLED", f"the revenue case is {state.status}")
    return {"revenue_source": state.to_dict(), "revenue_plan": plan.to_dict(), "referral_ref": referral_ref, "referral_digest": referral_digest(referral_ref=referral_ref, partner_ref=partner_ref, prospect_ref=str(state.ledger.prospect_ref)), "evidence_refs": [f"revenue_case:{state.scope.entity_ref}:{state.state_digest[:16]}", f"referral:{referral_ref}"]}


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def payment_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, payee_ref: str) -> dict[str, Any]:
    """From a bank or payout read: the transfer of the accrued commission to the partner."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in PAYMENT_TOOLS, "PAYMENT_NOT_BOUND", f"expected a read from {sorted(PAYMENT_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "PAYMENT_NOT_BOUND", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "PAYMENT_NOT_BOUND", "the provenance does not seal this exact transfer")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("paid_at") or raw.get("date") or raw.get("arrival_date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "PAYMENT_INCOMPLETE", "a transfer carries its amount and its time")
    return {"payment_provenance": prov, "payment_digest": str(prov["output_digest"]), "paid_amount": str(_money(decimal_value(amount, field_name="amount"))), "paid_at": timestamp(str(stamp), field_name="paid_at"), "payee_ref": payee_ref, "evidence_refs": [f"transfer:{prov['observation_ref']}"]}


EXPECTED_OUTFLOW_SCHEMA = "lightbulb.commission_expected_outflow.v1"


def commission_expectation(state: Any, *, source_plan: Any, expected_at: str) -> dict[str, Any]:
    """The cash position chain's hand-off for one accrued or approved commission: what is owed and not yet paid, bound to the replayed state."""

    plan, bound = PARTNER_COMMISSION_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("accrued", "approved"), "NO_OUTFLOW_EXPECTED", f"a commission that is {bound.status} is not owed")
    owed = _money(ledger.accrued_amount - ledger.paid_amount)
    _require(owed > 0, "NO_OUTFLOW_EXPECTED", "nothing is owed on this commission")
    return {"schema": EXPECTED_OUTFLOW_SCHEMA, "kind": "payable", "flow_ref": f"commission:{bound.scope.entity_ref}", "amount": str(owed), "currency": plan.currency, "expected_at": timestamp(expected_at, field_name="expected_at"), "basis": "approved commission" if bound.status == "approved" else "accrued commission awaiting approval", "source_digest": bound.state_digest}


def commission_liability(states: Sequence[Any]) -> dict[str, Any]:
    """Commission accrued or approved and not yet paid: the liability treasury carries."""

    outstanding = sum((state.ledger.accrued_amount for state in states if state.status in ("accrued", "approved")), Decimal("0"))
    return {"commission_outstanding": str(_money(outstanding)), "commission_paid": str(_money(sum((state.ledger.paid_amount for state in states), Decimal("0")))), "cases_outstanding": [state.scope.entity_ref for state in states if state.status in ("accrued", "approved")]}


def commission_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in COMMISSION_STATUSES}
    by_partner: dict[str, dict[str, str]] = {}
    for state in states:
        partner = str(state.ledger.partner_ref)
        row = by_partner.setdefault(partner, {"attributed_settled": "0.00", "paid": "0.00"})
        row["attributed_settled"] = str(_money(Decimal(row["attributed_settled"]) + state.ledger.attributed_settled))
        row["paid"] = str(_money(Decimal(row["paid"]) + state.ledger.paid_amount))
    return {"cases": len(states), "by_status": counts, "by_partner": by_partner, "attributed_settled": str(_money(sum((state.ledger.attributed_settled for state in states), Decimal("0")))), "disputes": sum(state.ledger.disputes for state in states), **commission_liability(states)}


PARTNER_COMMISSION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PARTNER_COMMISSION_KIND,
    "golden_loop": PARTNER_COMMISSION_GOLDEN_LOOP,
    "stages": ["agree", "attribute", "accrue", "approve", "pay"],
    "statuses": list(COMMISSION_STATUSES),
    "events": list(COMMISSION_EVENTS),
    "hops": {"agree": "the partner's replayed obligation-paper agreement, in force, naming the partner as counterparty", "attribute": "a settled revenue case replayed against its plan plus the referral binding the partner to its prospect", "accrue": "the program's rate over attributed settled cash, capped when the program caps it", "approve": "payout authority proof for the exact accrual", "pay": "bank or payout read of the exact transfer to the partner after approval"},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "commission accrues on settled revenue-chain cash only, and each case earns once per partner",
        "the referral is a digest binding the partner, the referral, and the prospect; a case won from another prospect earns nothing",
        "the accrual is computed from the program's rate; the caller cannot type it",
        "payment is proven by an observed transfer of the exact accrual to the partner, after payout authority",
    ],
}

__all__ = ["COMMISSION_EVENTS", "COMMISSION_STATUSES", "IN_FORCE_AGREEMENT_STATUSES", "PARTNER_COMMISSION_GOLDEN_LOOP", "PARTNER_COMMISSION_KIND", "PARTNER_COMMISSION_LIFECYCLE", "PARTNER_COMMISSION_MANIFEST", "PAYMENT_TOOLS", "REFERRAL_SCHEMA", "SETTLED_REVENUE_STATUSES", "TERMINAL_COMMISSION_STATUSES", "Attribution", "CommissionLedger", "CommissionReceipt", "PartnerCommissionError", "PartnerCommissionPlan", "PartnerCommissionState", "PartnerProgram", "advance_partner_commission", "agreement_receipt", "approval_receipt", "attribution_receipt", "commission_liability", "commission_summary", "compile_partner_commission_chain", "open_partner_commission", "payment_receipt", "referral_digest"]
