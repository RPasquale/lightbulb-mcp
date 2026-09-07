"""Seller liabilities become approved instructions, then bank-cleared payouts.

The host supplies current seller/transaction inventory and payout terms with
provenance; source lifecycles derive the money. One payout groups transactions
for one beneficiary so an Airwallex payment remains one actual instruction.
The platform executes requests and supplies complete prior payout inventory.
No function performs I/O, holds bank details, or grants payment authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from decimal import Decimal
from functools import lru_cache
import json
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec,
    OpaqueRef, Sha256Digest, StrictModel, decimal_value, detached, parsed,
    require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)
from lightbulb.company_execution_bridge import ObservationProvenance
from lightbulb.connector_execution import ConnectorExecutionRequest

PAYOUT_KIND = "payout_chain"
PAYOUT_GOLDEN_LOOP = "marketplace.supply_demand_to_settled_transaction@0.1.0"
PAYOUT_STATUSES = ("accrued", "held", "batched", "approved", "released", "settled", "cleared", "cancelled", "reconciliation_required")
PAYOUT_EVENTS = ("accrue", "hold", "release_hold", "batch", "approve", "instruct", "confirm", "confirm_settlement", "clear", "cancel", "require_reconciliation")
PAYOUT_CODES = ("TRANSACTION_NOT_SETTLED", "PAYOUT_SCOPE_MISMATCH", "DUPLICATE_TRANSACTION", "PAYOUT_ALREADY_ALLOCATED", "LIABILITY_EMPTY", "MIXED_SELLER_BATCH", "BATCH_TOTAL_EXCEEDED", "PAYOUT_NOT_AVAILABLE", "ELIGIBILITY_NOT_EVIDENCED", "ELIGIBILITY_STALE", "PAYOUT_TERMS_EXPIRED", "SELLER_NOT_ACTIVE", "BENEFICIARY_CHANGED", "REFUND_NOT_RECONCILED", "PAYOUT_HELD", "APPROVAL_NOT_BOUND", "APPROVER_LACKS_AUTHORITY", "SELF_APPROVAL", "APPROVAL_STALE", "RELEASE_NOT_EXECUTED", "SETTLEMENT_NOT_MATCHED", "PAYOUT_NOT_CLEARED")


class PayoutError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PayoutError(code, message)


def _money(value: Any, name: str) -> Decimal:
    result = decimal_value(value, field_name=name).quantize(MONEY_QUANTUM)
    if result < 0:
        raise ValueError(f"{name} must be nonnegative")
    return result


def _scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(k) == b.get(k) for k in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


class PayoutPlan(StrictModel):
    schema_id: Literal["lightbulb.payout_chain_plan.v1"] = Field(default="lightbulb.payout_chain_plan.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    max_batch_total: Decimal = Decimal("100000.00")
    max_transactions: int = Field(default=100, ge=1, le=500)
    max_eligibility_age_hours: int = Field(default=24, ge=1, le=168)
    max_approval_age_hours: int = Field(default=24, ge=1, le=168)
    connector_account_ref: OpaqueRef = "airwallex:primary"
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_batch_total", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        value = _money(value, "max_batch_total")
        if value <= 0:
            raise ValueError("max_batch_total must be positive")
        return value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> PayoutPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(PayoutPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact payout policy")
        return self


def compile_payout_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PayoutPlan:
    return seal(PayoutPlan, {**detached(overrides or {}), "company_ref": company_ref, "currency": currency}, "plan_digest")


class PayoutSource(StrictModel):
    plan: dict[str, Any]
    state: dict[str, Any]


def _source(state: Any, plan: Any) -> PayoutSource:
    _require(plan is not None, "TRANSACTION_NOT_SETTLED", "retain the source plan to replay the ledger")
    return PayoutSource(plan=detached(plan), state=detached(state))


@lru_cache(maxsize=128)
def _replayed(spec: LifecycleSpec, canonical_source: str) -> tuple[Any, Any]:
    # The key includes every ledger field and the source plan, not only the
    # state digest (which excludes ledger). Only actual successful replay is
    # memoized. Callers receive detached copies, so nested dictionaries cannot
    # poison a prior result. This bounds repeated nested bank/custody replay.
    source = PayoutSource.model_validate(json.loads(canonical_source))
    return spec.bind(source.plan, source.state)


def _replay(source: Any, spec: LifecycleSpec, code: str) -> tuple[Any, Any]:
    try:
        source = PayoutSource.model_validate(detached(source))
        return deepcopy(_replayed(spec, json.dumps(source.to_dict(), sort_keys=True, separators=(",", ":"))))
    except (ValueError, TypeError) as exc:
        raise PayoutError(code, f"the retained source must replay through its own lifecycle: {exc}") from exc


class PayoutEligibilityRow(StrictModel):
    transaction_ref: OpaqueRef
    transaction_state_digest: Sha256Digest
    seller_ref: OpaqueRef
    seller_state_digest: Sha256Digest
    payout_account_ref: OpaqueRef
    available_at: str
    unpaid_liability: Decimal
    refund_amount: Decimal
    cleared_refund_refs: tuple[OpaqueRef, ...]
    already_paid: Decimal
    dispute_open: bool
    payout_blocked: bool
    terms_ref: OpaqueRef
    terms_digest: Sha256Digest
    terms_effective_from: str
    terms_expires_at: str

    @field_validator("unpaid_liability", "refund_amount", "already_paid", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("available_at", "terms_effective_from", "terms_expires_at")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))


class PayoutEligibilityFacts(StrictModel):
    schema_id: Literal["lightbulb.marketplace_payout_eligibility.v1"] = Field(default="lightbulb.marketplace_payout_eligibility.v1", alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    currency: CurrencyCode
    observed_at: str
    valid_until: str
    complete: bool
    rows: tuple[PayoutEligibilityRow, ...] = Field(min_length=1, max_length=500)

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))


class PayoutEligibility(StrictModel):
    provenance: ObservationProvenance
    output: dict[str, Any]

    @model_validator(mode="after")
    def _guard(self) -> PayoutEligibility:
        facts = PayoutEligibilityFacts.model_validate(self.output)
        _require(self.provenance.lane == "host_read" and self.provenance.source_tool == "host.marketplace_payout_eligibility", "ELIGIBILITY_NOT_EVIDENCED", "current payout terms and refunds require the named host observation")
        _require(stable_digest(self.output) == self.provenance.output_digest, "ELIGIBILITY_NOT_EVIDENCED", "the original output must match its provenance digest")
        _require(parsed(facts.observed_at) <= parsed(self.provenance.completed_at) < parsed(facts.valid_until), "ELIGIBILITY_STALE", "the observation must be current when the host completed it")
        return self


def payout_eligibility(provenance: Any, output: Mapping[str, Any]) -> PayoutEligibility:
    return PayoutEligibility(provenance=provenance, output=detached(output))


class PayoutAllocation(StrictModel):
    transaction_ref: OpaqueRef
    seller_ref: OpaqueRef
    amount: Decimal
    original_liability: Decimal
    seller_refund_adjustment: Decimal
    transaction_source_digest: Sha256Digest
    payout_account_ref: OpaqueRef
    refund_amount: Decimal
    cleared_refund_refs: tuple[OpaqueRef, ...] = ()
    available_at: str

    @field_validator("amount", "original_liability", "seller_refund_adjustment", "refund_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("available_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return timestamp(value, field_name="available_at")


class PayoutReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    transaction_sources: tuple[PayoutSource, ...] = ()
    refund_sources: tuple[PayoutSource, ...] = ()
    seller_sources: tuple[PayoutSource, ...] = ()
    prior_payouts: tuple[PayoutSource, ...] = ()
    eligibility: PayoutEligibility | None = None
    authorization_proof: dict[str, Any] | None = None
    approval_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    approved_amount: Decimal | None = None
    execution_request: dict[str, Any] | None = None
    execution_result: dict[str, Any] | None = None
    bank_sources: tuple[PayoutSource, ...] = ()
    evidence_refs: tuple[OpaqueRef, ...] = ()

    @field_validator("approved_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value, "approved_amount")

    @field_validator("approved_at")
    @classmethod
    def _time(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="approved_at")


class PayoutLedger(StrictModel):
    entity_scope: EngineScope | None = None
    currency: CurrencyCode | None = None
    preparer_ref: OpaqueRef | None = None
    seller_ref: OpaqueRef | None = None
    payout_account_ref: OpaqueRef | None = None
    allocations: tuple[PayoutAllocation, ...] = ()
    transaction_sources: tuple[PayoutSource, ...] = ()
    refund_sources: tuple[PayoutSource, ...] = ()
    seller_sources: tuple[PayoutSource, ...] = ()
    prior_payouts: tuple[PayoutSource, ...] = ()
    eligibility: PayoutEligibility | None = None
    amount: Decimal = Decimal("0.00")
    released_amount: Decimal = Decimal("0.00")
    settled_amount: Decimal = Decimal("0.00")
    correlation: OpaqueRef | None = None
    payout_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    approved_at: str | None = None
    released_at: str | None = None
    settled_at: str | None = None
    cleared_at: str | None = None
    release_journal_ref: OpaqueRef | None = None
    release_request_digest: Sha256Digest | None = None
    released_state_digest: Sha256Digest | None = None
    bank_sources: tuple[PayoutSource, ...] = ()
    bank_match_digests: tuple[Sha256Digest, ...] = ()
    outcome: Literal["cleared", "cancelled", "reconciliation_required"] | None = None

    @field_validator("amount", "released_amount", "settled_amount", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("approved_at", "released_at", "settled_at", "cleared_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class PayoutEffectBoundary(StrictModel):
    provider_read: Literal[False] = False
    payout_sent: Literal[False] = False
    seller_balance_written: Literal[False] = False
    custody_cash_transferred: Literal[False] = False


def accrue_receipt(transactions: Sequence[Any], *, source_plans: Mapping[str, Any], refunds: Sequence[Any] = (), refund_plans: Mapping[str, Any] | None = None, prior_payouts: Sequence[Any] = (), prior_plans: Mapping[str, Any] | None = None) -> dict[str, Any]:
    from lightbulb.marketplace_supply_engine import verify_settled_transaction
    sources = []
    for value in transactions:
        raw = detached(value)
        source = _source(value, source_plans.get(raw.get("plan_digest")))
        state = verify_settled_transaction(source.state, source_plan=source.plan)
        sources.append(_source(state, source.plan).to_dict())
    prior = [_source(s, (prior_plans or {}).get(detached(s).get("plan_digest"))).to_dict() for s in prior_payouts]
    refund_sources = [_source(s, (refund_plans or {}).get(detached(s).get("plan_digest"))).to_dict() for s in refunds]
    return {"transaction_sources": sources, "refund_sources": refund_sources, "prior_payouts": prior, "evidence_refs": [f"transaction:{s['state']['state_digest']}" for s in sources]}


def batch_receipt(eligibility: Any, sellers: Sequence[Any], *, seller_plans: Mapping[str, Any], prior_payouts: Sequence[Any] = (), prior_plans: Mapping[str, Any] | None = None) -> dict[str, Any]:
    from lightbulb.marketplace_supply_engine import SELLER_LIFECYCLE
    observation = PayoutEligibility.model_validate(detached(eligibility))
    sources = []
    for value in sellers:
        source = _source(value, seller_plans.get(detached(value).get("plan_digest")))
        _, state = _replay(source, SELLER_LIFECYCLE, "SELLER_NOT_ACTIVE")
        sources.append(_source(state, source.plan).to_dict())
    return {"eligibility": observation.to_dict(), "seller_sources": sources,
            "prior_payouts": [_source(s, (prior_plans or {}).get(detached(s).get("plan_digest"))).to_dict() for s in prior_payouts],
            "evidence_refs": [f"payout-eligibility:{observation.provenance.output_digest}"]}


def approval_receipt(proof: Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence
    return authorization_evidence(proof)


def _prior(sources: Sequence[Any], plan: PayoutPlan, scope: Any, allocations: Sequence[Any], at: str) -> None:
    transactions = {detached(a)["transaction_ref"] for a in allocations}
    for source in sources:
        pp, state = _replay(source, PAYOUT_LIFECYCLE, "PAYOUT_ALREADY_ALLOCATED")
        _require(pp.company_ref == plan.company_ref and pp.currency == plan.currency and _scope(state.scope, scope), "PAYOUT_SCOPE_MISMATCH", "prior payout inventory belongs to this company and authenticated scope")
        _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "PAYOUT_ALREADY_ALLOCATED", "prior payout inventory cannot come from the future")
        _require(state.status == "cancelled" or not transactions.intersection(a.transaction_ref for a in state.ledger.allocations), "PAYOUT_ALREADY_ALLOCATED", "a transaction cannot be reserved or paid by a sibling payout")


def _eligible(plan: PayoutPlan, data: dict[str, Any], at: str) -> None:
    from lightbulb.marketplace_supply_engine import SELLER_LIFECYCLE
    _require(data.get("eligibility") is not None, "ELIGIBILITY_NOT_EVIDENCED", "supply the current host payout eligibility observation")
    evidence = PayoutEligibility.model_validate(data["eligibility"])
    facts = PayoutEligibilityFacts.model_validate(evidence.output)
    _require(facts.company_ref == plan.company_ref and facts.currency == plan.currency and _scope(facts.scope, data["entity_scope"]), "PAYOUT_SCOPE_MISMATCH", "payout eligibility must bind both the logical company and authenticated scope")
    age = (parsed(at)-parsed(facts.observed_at)).total_seconds()
    _require(0 <= age <= plan.max_eligibility_age_hours*3600 and parsed(evidence.provenance.completed_at) <= parsed(at) < parsed(facts.valid_until), "ELIGIBILITY_STALE", "refresh payout eligibility before a money decision")
    rows = {row.transaction_ref: row for row in facts.rows}
    allocations = data["allocations"]
    _require(facts.complete and len(rows) == len(facts.rows) and set(rows) == {a["transaction_ref"] for a in allocations}, "ELIGIBILITY_NOT_EVIDENCED", "the complete read must cover every allocated transaction exactly once")
    sellers = {}
    for source in data.get("seller_sources", ()):
        sp, seller = _replay(source, SELLER_LIFECYCLE, "SELLER_NOT_ACTIVE")
        _require(sp.company_ref == plan.company_ref and sp.currency == plan.currency and _scope(seller.scope, data["entity_scope"]), "PAYOUT_SCOPE_MISMATCH", "seller control belongs to this payout company and scope")
        _require(seller.status == "active" and parsed(seller.transition_history[-1].command.occurred_at) <= parsed(at), "SELLER_NOT_ACTIVE", "only a currently active seller may receive a payout")
        _require(seller.scope.entity_ref not in sellers, "SELLER_NOT_ACTIVE", "provide each current seller once")
        sellers[seller.scope.entity_ref] = seller
    _require(set(sellers) == {a["seller_ref"] for a in allocations}, "SELLER_NOT_ACTIVE", "every payee must have a replayed current seller state")
    for allocation in allocations:
        row, seller = rows[allocation["transaction_ref"]], sellers[allocation["seller_ref"]]
        _require(row.transaction_state_digest == allocation["transaction_source_digest"] and row.seller_ref == allocation["seller_ref"] and row.seller_state_digest == seller.state_digest, "ELIGIBILITY_NOT_EVIDENCED", "current host inventory must identify these exact source states")
        _require(row.payout_account_ref == allocation["payout_account_ref"] == seller.ledger.payout_account_ref, "BENEFICIARY_CHANGED", "a changed payout account requires new source evidence and approval")
        _require(row.refund_amount == Decimal(allocation["refund_amount"]) and row.unpaid_liability == Decimal(allocation["amount"]) and len(row.cleared_refund_refs) == len(set(row.cleared_refund_refs)) and set(row.cleared_refund_refs) == set(allocation["cleared_refund_refs"]), "REFUND_NOT_RECONCILED", "current refunds and unpaid liability must reconcile with the exact cleared refund sources")
        _require(row.already_paid == 0, "PAYOUT_ALREADY_ALLOCATED", "the host reports this transaction was already paid")
        _require(not row.dispute_open and not row.payout_blocked, "PAYOUT_HELD", "resolve the current dispute or payout hold before release")
        _require(parsed(row.terms_effective_from) <= parsed(at) < parsed(row.terms_expires_at), "PAYOUT_TERMS_EXPIRED", "seller payout terms must be effective at the money decision")
        _require(parsed(at) >= max(parsed(row.available_at), parsed(allocation["available_at"])), "PAYOUT_NOT_AVAILABLE", "both marketplace and current contractual payout windows must have opened")


def _request(plan: PayoutPlan, data: Mapping[str, Any], state_digest: str, *, approved: bool) -> ConnectorExecutionRequest:
    proof = data.get("authorization_proof") if approved else None
    scope = detached(data["entity_scope"])
    return ConnectorExecutionRequest(tool="airwallex.create_payment", arguments={"amount": str(data["amount"]), "currency": plan.currency,
        "beneficiary_ref": data["payout_account_ref"], "correlation": data["correlation"],
        "allocations": detached(data["allocations"]), "payout_state_digest": state_digest, "plan_digest": plan.plan_digest},
        scope={"project_ref": scope["project_ref"], "project_id": scope.get("project_id"), "actor_ref": data["preparer_ref"]},
        connector_account_ref=plan.connector_account_ref, effect="write", approval_required=True,
        approval_ref=proof["approval_task_id"] if proof else None, preview_only=not bool(proof),
        idempotency_key=f"payout:{scope['entity_ref']}:{state_digest}")


def payout_request(state: Any, *, source_plan: Any) -> ConnectorExecutionRequest:
    plan, item = _replay(_source(state, source_plan), PAYOUT_LIFECYCLE, "RELEASE_NOT_EXECUTED")
    _require(item.status in ("batched", "approved"), "RELEASE_NOT_EXECUTED", "only a batched or approved payout has an instruction preview")
    return _request(plan, item.ledger.to_dict(), item.state_digest, approved=item.status == "approved")


def release_receipt(result: Any, *, request: Any) -> dict[str, Any]:
    from lightbulb.company_execution_bridge import execution_receipt_from_connector
    from lightbulb.connector_execution import ConnectorExecutionResult
    try:
        req = ConnectorExecutionRequest.model_validate(detached(request))
        res = ConnectorExecutionResult.model_validate(detached(result))
        execution = execution_receipt_from_connector(res, req)
        output = detached(res.output)
        _require(req.tool == "airwallex.create_payment" and req.effect.value == "write" and req.approval_required and not req.preview_only and req.approval_ref is not None, "RELEASE_NOT_EXECUTED", "only an approved payout instruction can establish release")
        _require(output.get("status") in ("completed", "paid") and output.get("payout_ref") and _money(output.get("amount"), "amount") == _money(req.arguments["amount"], "amount") and output.get("currency") == req.arguments["currency"] and output.get("correlation") == req.arguments["correlation"] and output.get("beneficiary_ref") == req.arguments["beneficiary_ref"], "RELEASE_NOT_EXECUTED", "the completed output must prove the exact amount, currency, beneficiary and payout correlation")
        return {"execution_request": req.to_dict(), "execution_result": res.to_dict(), "evidence_refs": [f"execution:{execution.receipt_digest}"]}
    except PayoutError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise PayoutError("RELEASE_NOT_EXECUTED", f"a completed bound connector result is required: {exc}") from exc


def settlement_receipt(bank_states: Sequence[Any], *, bank_plans: Mapping[str, Any]) -> dict[str, Any]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    sources = []
    for value in bank_states:
        source = _source(value, bank_plans.get(detached(value).get("plan_digest")))
        _, bank = _replay(source, BANK_REC_LIFECYCLE, "SETTLEMENT_NOT_MATCHED")
        sources.append(_source(bank, source.plan).to_dict())
    return {"bank_sources": sources, "evidence_refs": [f"bank:{s['state']['state_digest']}" for s in sources]}


def _settled(plan: PayoutPlan, data: dict[str, Any], sources: Sequence[Any], digest: str, at: str) -> tuple[Decimal, str, list[str]]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    total, moments, seen, matches = Decimal("0.00"), [], set(), []
    for source in sources:
        bp, bank = _replay(source, BANK_REC_LIFECYCLE, "SETTLEMENT_NOT_MATCHED")
        _require(bp.company_ref == plan.company_ref and bp.currency == plan.currency and _scope(bank.scope, data["entity_scope"]), "PAYOUT_SCOPE_MISMATCH", "bank evidence belongs to the payout company and scope")
        _require(parsed(bank.transition_history[-1].command.occurred_at) <= parsed(at), "SETTLEMENT_NOT_MATCHED", "bank evidence cannot come from the future")
        rows = {line.line_ref: line for line in bank.ledger.lines}
        for match in bank.ledger.matches:
            if match.counterpart_kind != PAYOUT_KIND or match.counterpart_state_digest != digest:
                continue
            _require(match.amount < 0, "SETTLEMENT_NOT_MATCHED", "a seller payout is a bank debit")
            for ref in match.line_refs:
                line = rows[ref]
                identity = (bp.account_ref, ref)
                _require(identity not in seen, "SETTLEMENT_NOT_MATCHED", "a bank debit may prove the payout only once")
                _require(line.reference == data["correlation"] and line.amount < 0 and parsed(data["released_at"]) <= parsed(line.occurred_at) <= parsed(at), "SETTLEMENT_NOT_MATCHED", "bank lines must match the exact released payout and chronology")
                seen.add(identity)
                total -= line.amount
                moments.append(line.occurred_at)
            matches.append(stable_digest({"bank_state_digest": bank.state_digest, "match": match.to_dict()}))
    _require(bool(moments) and total == Decimal(data["released_amount"]), "SETTLEMENT_NOT_MATCHED", "bank-cleared debits must equal the release to the cent")
    return total, max(moments, key=parsed), sorted(matches)


def _refunds(sources: Sequence[PayoutSource], allocations: list[dict[str, Any]], *, plan: PayoutPlan, scope: Any, at: str) -> None:
    if not sources:
        return
    from lightbulb.refund_and_dispute_chain import verify_cleared_refund
    rows = {a["transaction_ref"]: a for a in allocations}
    seen = set()
    for source in sources:
        try:
            refund = verify_cleared_refund(source.state, source_plan=source.plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
        except ValueError as exc:
            raise PayoutError("REFUND_NOT_RECONCILED", f"late refunds must retain cleared same-company source proofs: {exc}") from exc
        led = refund.ledger
        _require(led.origin_kind == "marketplace" and led.transaction_ref in rows and led.refund_ref not in seen, "REFUND_NOT_RECONCILED", "each cleared refund must name one allocated marketplace transaction once")
        row = rows[led.transaction_ref]
        _require(led.source_transaction_digest == row["transaction_source_digest"] and led.seller_ref == row["seller_ref"], "REFUND_NOT_RECONCILED", "refunds must reduce their exact source seller transaction")
        seen.add(led.refund_ref)
        adjustment = Decimal(row["seller_refund_adjustment"]) + led.seller_share_adjustment
        amount = Decimal(row["original_liability"]) - adjustment
        _require(amount >= 0, "REFUND_NOT_RECONCILED", "cleared refunds cannot reduce the seller share beyond its original liability")
        row.update(amount=str(amount), seller_refund_adjustment=str(adjustment), refund_amount=str(Decimal(row["refund_amount"]) + led.cash_out), cleared_refund_refs=sorted([*row["cleared_refund_refs"], led.refund_ref]))


def _apply(plan: PayoutPlan, nxt: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    from lightbulb.marketplace_supply_engine import verify_settled_transaction
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "accrue":
        _require(r.entity_scope is not None and command.expected_state_digest == PAYOUT_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "PAYOUT_SCOPE_MISMATCH", "opening must bind the actual payout scope")
        _require(r.entity_scope.currency == plan.currency, "PAYOUT_SCOPE_MISMATCH", "payout currency must match its scope")
        _require(0 < len(r.transaction_sources) <= plan.max_transactions, "LIABILITY_EMPTY", "a payout accrues a bounded set of settled transactions")
        allocations = []
        for source in r.transaction_sources:
            try:
                state = verify_settled_transaction(source.state, source_plan=source.plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=r.entity_scope, at=at)
            except ValueError as exc:
                code = "PAYOUT_SCOPE_MISMATCH" if getattr(exc, "code", None) == "SCOPE_MISMATCH" else "TRANSACTION_NOT_SETTLED"
                raise PayoutError(code, f"settled seller liability must replay in this scope: {exc}") from exc
            _require(state.ledger.seller_liability > 0, "LIABILITY_EMPTY", "fully refunded transactions have no seller payout")
            allocations.append({"transaction_ref": state.scope.entity_ref, "seller_ref": state.ledger.seller_ref, "amount": str(state.ledger.seller_liability), "original_liability": str(state.ledger.seller_liability), "seller_refund_adjustment": "0.00", "transaction_source_digest": state.state_digest, "payout_account_ref": state.ledger.payout_account_ref, "refund_amount": str(state.ledger.refund_amount), "cleared_refund_refs": [], "available_at": state.ledger.payout_available_at})
        _require(len({a['transaction_ref'] for a in allocations}) == len(allocations), "DUPLICATE_TRANSACTION", "a transaction is allocated once within the batch")
        _require(len({(a['seller_ref'], a['payout_account_ref']) for a in allocations}) == 1, "MIXED_SELLER_BATCH", "each payment instruction names one seller beneficiary")
        _refunds(r.refund_sources, allocations, plan=plan, scope=r.entity_scope, at=at)
        total = sum((Decimal(a["amount"]) for a in allocations), Decimal("0.00"))
        _require(total > 0 and all(Decimal(a["amount"]) > 0 for a in allocations), "LIABILITY_EMPTY", "fully refunded seller liabilities cannot enter a payout instruction")
        _require(total <= plan.max_batch_total, "BATCH_TOTAL_EXCEEDED", "the seller payout exceeds the plan ceiling")
        _prior(r.prior_payouts, plan, r.entity_scope, allocations, at)
        data.update(entity_scope=r.entity_scope.to_dict(), preparer_ref=command.actor_ref, currency=plan.currency, allocations=allocations,
                    transaction_sources=detached(r.transaction_sources), refund_sources=detached(r.refund_sources), prior_payouts=detached(r.prior_payouts), amount=str(total),
                    seller_ref=allocations[0]["seller_ref"], payout_account_ref=allocations[0]["payout_account_ref"],
                    correlation="LB-PO-" + stable_digest({"scope": r.entity_scope.to_dict(), "allocations": allocations})[:32])
    elif event in ("batch", "approve", "instruct", "release_hold"):
        if r.eligibility is not None:
            if event == "instruct" and data.get("eligibility") is not None:
                old = PayoutEligibilityFacts.model_validate(data["eligibility"]["output"])
                new = PayoutEligibilityFacts.model_validate(r.eligibility.output)
                terms = lambda rows: {v.transaction_ref: (v.terms_ref, v.terms_digest, v.terms_effective_from, v.terms_expires_at) for v in rows}
                _require(terms(old.rows) == terms(new.rows), "PAYOUT_TERMS_EXPIRED", "changed terms require re-batching and a fresh approval")
            data["eligibility"] = r.eligibility.to_dict()
        if r.seller_sources:
            data["seller_sources"] = detached(r.seller_sources)
        _eligible(plan, data, at)
        _prior([*data.get("prior_payouts", ()), *r.prior_payouts], plan, data["entity_scope"], data["allocations"], at)
        if event == "approve":
            from lightbulb.authority_matrix import require_authorization_proof
            _require(r.authorization_proof is not None, "APPROVAL_NOT_BOUND", "seller funds require an exact payout authorization proof")
            proof = require_authorization_proof(r.authorization_proof, category="payout", amount=data["amount"], currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_scope"]["entity_ref"], preparer_ref=data["preparer_ref"], payee_ref=data["seller_ref"])
            _require(proof.approver_ref not in (data["preparer_ref"], data["seller_ref"]), "SELF_APPROVAL", "the preparer and seller cannot approve their own payout")
            data.update(authorization_proof=proof.to_dict(), approved_at=proof.decided_at)
        elif event == "instruct":
            _require(0 <= (parsed(at)-parsed(data["approved_at"])).total_seconds() <= plan.max_approval_age_hours*3600, "APPROVAL_STALE", "refresh approval before a delayed release")
            _require(r.execution_request is not None and r.execution_result is not None, "RELEASE_NOT_EXECUTED", "record the actual completed payout execution")
            release_receipt(r.execution_result, request=r.execution_request)
            from lightbulb.company_execution_bridge import execution_receipt_from_connector
            expected = _request(plan, data, command.expected_state_digest, approved=True)
            execution = execution_receipt_from_connector(r.execution_result, r.execution_request)
            _eligible(plan, data, execution.completed_at)
            _require(execution.request_digest == expected.custody_fingerprint() and execution.approval_ref == data["authorization_proof"]["approval_task_id"] and execution.project_id == data["entity_scope"]["project_id"], "RELEASE_NOT_EXECUTED", "execution must bind the exact approved payout and authenticated project")
            _require(parsed(data["approved_at"]) <= parsed(execution.completed_at) <= parsed(at), "RELEASE_NOT_EXECUTED", "the execution must follow approval and predate its recording")
            data.update(payout_ref=r.execution_result["output"]["payout_ref"], released_amount=data["amount"], released_at=execution.completed_at, release_journal_ref=execution.journal_ref, release_request_digest=execution.request_digest)
        elif event == "release_hold":
            data.update(authorization_proof=None, approved_at=None)
    elif event == "hold":
        data.update(authorization_proof=None, approved_at=None)
    elif event in ("confirm", "confirm_settlement"):
        amount, settled_at, digests = _settled(plan, data, r.bank_sources, command.expected_state_digest, at)
        data.update(settled_amount=str(amount), settled_at=settled_at, bank_sources=detached(r.bank_sources), bank_match_digests=digests, released_state_digest=command.expected_state_digest)
    elif event == "clear":
        amount, settled_at, _ = _settled(plan, data, data["bank_sources"], data["released_state_digest"], at)
        _require(amount == Decimal(data["amount"]) == Decimal(data["settled_amount"]) and settled_at == data["settled_at"], "PAYOUT_NOT_CLEARED", "clearance requires the retained exact bank proof")
        data.update(cleared_at=at, outcome="cleared")
    elif event in ("cancel", "require_reconciliation"):
        data["outcome"] = nxt
    return nxt, data


def _guarded(*args: Any) -> Any:
    try:
        return _apply(*args)
    except PayoutError as exc:
        recovery = "do_not_replay" if exc.code in ("PAYOUT_ALREADY_ALLOCATED", "DUPLICATE_TRANSACTION") else "manual_reconciliation" if exc.code in ("SETTLEMENT_NOT_MATCHED", "REFUND_NOT_RECONCILED", "BENEFICIARY_CHANGED") else "await_approval" if exc.code in ("APPROVAL_NOT_BOUND", "APPROVAL_STALE", "PAYOUT_HELD") else "correct_input"
        require(False, exc.code, str(exc), recovery)


class _PayoutLifecycle(LifecycleSpec):
    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope != self.ledger.entity_scope:
                    raise ValueError("PAYOUT_SCOPE_MISMATCH: the retained opening scope must equal the actual state scope")
                return self
        ScopedState.__name__ = self.State.__name__
        self.State = ScopedState


_TABLE = {("new", "accrue"): "accrued", ("accrued", "batch"): "batched", ("held", "release_hold"): "batched", ("batched", "approve"): "approved", ("approved", "instruct"): "released", ("released", "confirm"): "settled", ("released", "confirm_settlement"): "settled", ("settled", "clear"): "cleared",
          **{(s, "hold"): "held" for s in ("accrued", "batched", "approved")},
          **{(s, "cancel"): "cancelled" for s in ("accrued", "batched", "approved", "held")},
          **{(s, "require_reconciliation"): "reconciliation_required" for s in ("released", "settled")}}
PAYOUT_LIFECYCLE = _PayoutLifecycle(entity="seller_payout", schema_prefix="payout_chain", statuses=PAYOUT_STATUSES, terminal=("cleared", "cancelled", "reconciliation_required"), events=PAYOUT_EVENTS, table=_TABLE, opening_event="accrue", reason_events=("hold", "cancel", "require_reconciliation"), apply=_guarded, ledger_model=PayoutLedger, receipt_model=PayoutReceipt, effect_boundary_model=PayoutEffectBoundary, plan_model=PayoutPlan, max_transitions=24)
PayoutState = PAYOUT_LIFECYCLE.State


def open_payout(plan: Any, scope: Any, *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    plan = PayoutPlan.model_validate(detached(plan))
    scope = EngineScope.model_validate(detached(scope))
    _require(scope.currency == plan.currency, "PAYOUT_SCOPE_MISMATCH", "payout currency must match its authenticated scope")
    return PAYOUT_LIFECYCLE.open(plan, scope, receipt={**detached(receipt), "entity_scope": scope.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_payout(plan: Any, state: Any, command: Any) -> Any:
    return PAYOUT_LIFECYCLE.advance(plan, state, command)


def verify_payout_cleared(state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, proven = _replay(_source(state, source_plan), PAYOUT_LIFECYCLE, "PAYOUT_NOT_CLEARED")
    _require(proven.status == "cleared" and proven.ledger.settled_at is not None and proven.ledger.payout_ref is not None, "PAYOUT_NOT_CLEARED", "seller funds leave custody only after payout clearance")
    _require((company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency) and (expected_scope is None or _scope(proven.scope, expected_scope)), "PAYOUT_SCOPE_MISMATCH", "payout belongs to another logical company or authenticated scope")
    _require(at is None or parsed(proven.transition_history[-1].command.occurred_at) <= parsed(timestamp(at, field_name="at")), "PAYOUT_NOT_CLEARED", "a cleared payout cannot be consumed before its last transition")
    return proven


def payout_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    plan, item = _replay(_source(state, source_plan), PAYOUT_LIFECYCLE, "PAYOUT_NOT_CLEARED")
    return {"payout_ref": item.scope.entity_ref, "company_ref": plan.company_ref, "status": item.status, "seller_ref": item.ledger.seller_ref, "currency": plan.currency, "amount": str(item.ledger.amount), "settled_amount": str(item.ledger.settled_amount), "transaction_count": len(item.ledger.allocations), "state_digest": item.state_digest}


PAYOUT_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": PAYOUT_KIND, "golden_loop": PAYOUT_GOLDEN_LOOP, "stages": ["accrue", "batch", "approve", "instruct", "confirm", "clear"], "statuses": list(PAYOUT_STATUSES), "events": list(PAYOUT_EVENTS), "hops": {"accrue": "replayed settled marketplace liabilities", "batch": "current host payout terms, refund balance and seller control", "approve": "exact payout authority proof", "instruct": "approved Airwallex execution request and completed result", "confirm": "bank match against the released payout", "clear": "custodial_funds.record_payout"}, "required_connectors": ["host.marketplace_payout_eligibility", "airwallex.create_payment", "lightbulb.sdk_engine_state"], "missing_reads": ["host.marketplace_payout_eligibility requires a pinned platform inventory contract; no hosted route is claimed"], "hard_rules": ["seller liabilities are never company revenue", "each transaction can be allocated once across the supplied payout inventory", "only observed current terms and refunds may release seller funds", "a bank match is required before a payout reduces custody liability", "one beneficiary per actual payment instruction"], "guards": list(PAYOUT_CODES)}

__all__ = ["PAYOUT_KIND", "PAYOUT_GOLDEN_LOOP", "PAYOUT_STATUSES", "PAYOUT_EVENTS", "PAYOUT_CODES", "PAYOUT_MANIFEST", "PayoutError", "PayoutPlan", "PayoutSource", "PayoutEligibilityRow", "PayoutEligibilityFacts", "PayoutEligibility", "PayoutAllocation", "PayoutReceipt", "PayoutLedger", "PayoutEffectBoundary", "PAYOUT_LIFECYCLE", "PayoutState", "compile_payout_chain", "payout_eligibility", "accrue_receipt", "batch_receipt", "approval_receipt", "payout_request", "release_receipt", "settlement_receipt", "open_payout", "advance_payout", "verify_payout_cleared", "payout_summary"]
