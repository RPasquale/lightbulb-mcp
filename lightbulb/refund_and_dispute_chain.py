"""Refunds and representments backed by original sales, authority and bank rows.

The original settled state and plan are retained and replayed. A remedy needs
an independently bound approval; provider disputes may instead be represented.
Completed effects and final observations are followed by exact bank evidence.
Corrections distinguish company revenue, unpaid seller liabilities and amounts
recoverable from sellers already paid. No effect, approval or I/O occurs here.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from decimal import Decimal
from functools import lru_cache
import json
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec, OpaqueRef, Rejected, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp, unique
from lightbulb.company_execution_bridge import ExecutionReceipt, ObservationProvenance
from lightbulb.connector_execution import ConnectorExecutionRequest

REFUND_AND_DISPUTE_KIND = "refund_and_dispute_chain"
REFUND_PLAN_SCHEMA = "lightbulb.refund_and_dispute_plan.v1"
REFUND_GOLDEN_LOOP = "service.case_intake_to_verified_resolution@0.1.0"
REFUND_STATUSES = ("notified", "authorized", "evidenced", "instructed", "represented", "settled", "cleared", "abandoned")
REFUND_EVENTS = ("notify", "authorize_remedy", "gather_evidence", "issue_credit", "submit_representment", "settle", "clear", "abandon")
REFUND_CODES = ("SOURCE_NOT_SEALED", "SOURCE_NOT_SETTLED", "SCOPE_MISMATCH", "SOURCE_FROM_FUTURE", "CUSTOMER_MISMATCH", "REMEDY_NOT_VERIFIED", "REMEDY_MISMATCH", "REFUND_AMOUNT_INVALID", "REFUND_EXCEEDS_REMAINING", "REFUND_ALREADY_RECORDED", "HISTORY_INCOMPLETE", "AUTHORITY_MISSING", "EVIDENCE_MISSING", "DISPUTE_DEADLINE_PASSED", "EXECUTION_MISMATCH", "SETTLEMENT_MISMATCH", "BANK_EVIDENCE_MISSING", "BANK_AMOUNT_MISMATCH", "BANK_LINE_ALREADY_USED", "REFUND_NOT_CLEARED", "PAYOUT_SOURCE_MISMATCH")


class RefundAndDisputeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RefundAndDisputeError(code, message)


def _parse(model: Any, value: Any, code: str = "SOURCE_NOT_SEALED") -> Any:
    try:
        return model.model_validate(detached(value))
    except (ValueError, TypeError) as exc:
        raise RefundAndDisputeError(code, f"a valid retained {model.__name__} is required") from exc


def _money(value: Any, field: str) -> Decimal:
    return decimal_value(value, field_name=field).quantize(MONEY_QUANTUM)


def _same_scope(a: Any, b: Any, *, entity: bool = False) -> bool:
    left, right = detached(a), detached(b)
    keys = ("tenant_ref", "company_ref", "project_ref", "project_id", "currency") + (("entity_ref",) if entity else ())
    return all(left.get(key) == right.get(key) for key in keys)


class RefundAndDisputePlan(StrictModel):
    schema_id: Literal["lightbulb.refund_and_dispute_plan.v1"] = Field(default=REFUND_PLAN_SCHEMA, alias="schema")
    operator_supplied: Literal[True] = True
    company_ref: OpaqueRef
    currency: CurrencyCode
    connector_account_ref: OpaqueRef = "payments:primary"
    refund_tool: Literal["stripe.create_refund", "shopify.refund_order", "square.refund_payment"] = "stripe.create_refund"
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RefundAndDisputePlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(RefundAndDisputePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the refund plan")
        return self


def compile_refund_and_dispute_chain(company_ref: str, *, currency: str, connector_account_ref: str = "payments:primary", refund_tool: str = "stripe.create_refund") -> RefundAndDisputePlan:
    return seal(RefundAndDisputePlan, {"company_ref": company_ref, "currency": currency, "connector_account_ref": connector_account_ref, "refund_tool": refund_tool}, "plan_digest")


class RefundFacts(StrictModel):
    schema_id: Literal["lightbulb.refund_dispute_source_record.v1"] = Field(default="lightbulb.refund_dispute_source_record.v1", alias="schema")
    company_ref: OpaqueRef
    scope: EngineScope
    event: Literal["purchase", "notify", "evidence", "issue_credit", "submit_representment", "settle"]
    disposition: Literal["paid", "requested", "disputed", "complete", "refunded", "submitted", "won", "lost", "settled"]
    occurred_at: str
    kind: Literal["refund", "chargeback"] = "refund"
    refund_ref: OpaqueRef
    transaction_ref: OpaqueRef
    customer_ref: OpaqueRef
    payment_ref: OpaqueRef
    amount: Decimal
    source_transaction_digest: Sha256Digest
    correlation_ref: OpaqueRef | None = None
    case_ref: OpaqueRef | None = None
    due_at: str | None = None
    document_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=32)
    history_complete: bool = False
    prior_refund_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=64)
    prior_refund_total: Decimal = Decimal("0.00")
    prior_payout_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=64)
    seller_paid_total: Decimal = Decimal("0.00")

    @field_validator("amount", "prior_refund_total", "seller_paid_total", mode="before")
    @classmethod
    def _amount(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("occurred_at", "due_at")
    @classmethod
    def _at(cls, value: str | None, info: ValidationInfo) -> Any:
        return None if value is None else timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _unique(self) -> RefundFacts:
        unique(self.prior_refund_refs, label="prior refunds")
        unique(self.prior_payout_refs, label="prior payouts")
        unique(self.document_digests, label="evidence documents")
        return self


class RefundObservation(StrictModel):
    schema_id: Literal["lightbulb.refund_dispute_observation.v1"] = Field(default="lightbulb.refund_dispute_observation.v1", alias="schema")
    provenance: ObservationProvenance
    output: dict[str, Any]
    observation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RefundObservation:
        if self.provenance.schema_id != "lightbulb.engine_observation_provenance.v1" or self.provenance.provenance_digest == GENESIS_DIGEST or self.provenance.output_digest != stable_digest(self.output):
            raise ValueError("observation provenance must commit this exact output")
        if not skip_digests(info) and self.observation_digest != sealed_digest(RefundObservation, self, "observation_digest"):
            raise ValueError("observation_digest must commit the retained source")
        return self


class RefundExecution(StrictModel):
    schema_id: Literal["lightbulb.refund_dispute_execution.v1"] = Field(default="lightbulb.refund_dispute_execution.v1", alias="schema")
    execution: ExecutionReceipt
    request: ConnectorExecutionRequest
    output: dict[str, Any]
    effect_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RefundExecution:
        if self.execution.schema_id != "lightbulb.engine_execution_receipt.v1" or self.execution.effect != "write" or self.execution.output_digest != stable_digest(self.output):
            raise ValueError("completed governed write evidence must commit the exact output")
        if any(getattr(self.execution, key) == GENESIS_DIGEST for key in ("request_digest", "receipt_digest", "route_digest", "approval_receipt_digest")):
            raise ValueError("execution provenance cannot use genesis digests")
        if self.request.effect.value != "write" or not self.request.approval_required or self.request.preview_only or self.request.approval_ref is None:
            raise ValueError("the completed request must carry platform approval")
        if (self.execution.request_digest, self.execution.tool, self.execution.project_id, self.execution.connector_account_ref, self.execution.approval_ref) != (self.request.custody_fingerprint(), self.request.tool, str(self.request.scope.project_id), self.request.connector_account_ref, self.request.approval_ref):
            raise ValueError("execution must bind the retained exact request, account, project and approval")
        if not skip_digests(info) and self.effect_digest != sealed_digest(RefundExecution, self, "effect_digest"):
            raise ValueError("effect_digest must commit the execution")
        return self


def refund_observation(provenance: Any, output: Mapping[str, Any]) -> RefundObservation:
    return seal(RefundObservation, {"provenance": detached(provenance), "output": dict(detached(output))}, "observation_digest")


def refund_execution(execution: Any, output: Mapping[str, Any], *, request: Any) -> RefundExecution:
    return seal(RefundExecution, {"execution": detached(execution), "request": detached(request), "output": dict(detached(output))}, "effect_digest")


class RetainedState(StrictModel):
    source_plan: dict[str, Any]
    state: dict[str, Any]


class RefundOrigin(RetainedState):
    kind: Literal["marketplace", "revenue", "commerce"]
    purchase: RefundObservation | None = None
    order_page: RefundObservation | None = None
    refund_page: RefundObservation | None = None


class RefundReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=32)
    register_scope: EngineScope | None = None
    origin: RefundOrigin | None = None
    observation: RefundObservation | None = None
    execution: RefundExecution | None = None
    service_source: RetainedState | None = None
    prior_refunds: tuple[RetainedState, ...] = Field(default_factory=tuple, max_length=64)
    payouts: tuple[RetainedState, ...] = Field(default_factory=tuple, max_length=64)
    authorization_proof: dict[str, Any] | None = None
    bank_source: RetainedState | None = None


class RefundLedger(StrictModel):
    register_scope: EngineScope | None = None
    entity_ref: OpaqueRef | None = None
    requester_ref: OpaqueRef | None = None
    origin: RefundOrigin | None = None
    origin_kind: Literal["marketplace", "revenue", "commerce"] | None = None
    transaction_ref: OpaqueRef | None = None
    source_transaction_digest: Sha256Digest | None = None
    origin_identity: Sha256Digest | None = None
    customer_ref: OpaqueRef | None = None
    seller_ref: OpaqueRef | None = None
    refund_ref: OpaqueRef | None = None
    payment_ref: OpaqueRef | None = None
    kind: Literal["refund", "chargeback"] | None = None
    amount: Decimal = Decimal("0.00")
    source_amount: Decimal = Decimal("0.00")
    source_settled_at: str | None = None
    original_seller_liability: Decimal = Decimal("0.00")
    original_company_revenue: Decimal = Decimal("0.00")
    prior_refund_total: Decimal = Decimal("0.00")
    prior_seller_adjustments: Decimal = Decimal("0.00")
    seller_paid_total: Decimal = Decimal("0.00")
    prior_refunds: tuple[RetainedState, ...] = Field(default_factory=tuple, max_length=64)
    payouts: tuple[RetainedState, ...] = Field(default_factory=tuple, max_length=64)
    notified_at: str | None = None
    due_at: str | None = None
    authorization_proof_digest: Sha256Digest | None = None
    approval_task_ref: OpaqueRef | None = None
    authorized_at: str | None = None
    evidence_digest: Sha256Digest | None = None
    evidenced_at: str | None = None
    document_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=32)
    effect_digest: Sha256Digest | None = None
    executed_at: str | None = None
    correlation_ref: OpaqueRef | None = None
    settled_at: str | None = None
    cleared_at: str | None = None
    cash_out: Decimal = Decimal("0.00")
    company_revenue_reversal: Decimal = Decimal("0.00")
    seller_share_adjustment: Decimal = Decimal("0.00")
    seller_liability_reduction: Decimal = Decimal("0.00")
    seller_recovery_receivable: Decimal = Decimal("0.00")
    bank_line_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    bank_source_digest: Sha256Digest | None = None
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=64)
    outcome: Literal["refunded", "won", "lost", "abandoned"] | None = None

    @field_validator("amount", "source_amount", "original_seller_liability", "original_company_revenue", "prior_refund_total", "prior_seller_adjustments", "seller_paid_total", "cash_out", "company_revenue_reversal", "seller_share_adjustment", "seller_liability_reduction", "seller_recovery_receivable", mode="before")
    @classmethod
    def _amount(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("notified_at", "due_at", "authorized_at", "evidenced_at", "executed_at", "settled_at", "cleared_at", "source_settled_at")
    @classmethod
    def _at(cls, value: str | None, info: ValidationInfo) -> Any:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class RefundEffectBoundary(StrictModel):
    provider_read: Literal[False] = False
    refund_issued: Literal[False] = False
    dispute_submitted: Literal[False] = False
    approval_granted: Literal[False] = False
    ledger_written: Literal[False] = False


_READ_TOOLS = {"purchase": {"stripe.list_charges", "ecommerce.get_order", "square.list_orders"}, "notify": {"host.remedy_register", "stripe.list_refunds", "stripe.list_disputes", "shopify.list_refunds", "square.list_refunds"}, "evidence": {"host.dispute_evidence"}, "settle": {"stripe.list_refunds", "stripe.list_disputes", "shopify.list_refunds", "square.list_refunds"}}
_WRITE_TOOLS = {"issue_credit": {"stripe.create_refund", "shopify.refund_order", "square.refund_payment"}, "submit_representment": {"stripe.update_dispute"}}


def _facts(value: Any, *, event: str, plan: RefundAndDisputePlan, scope: Any, at: str, write: bool = False, code: str = "SOURCE_NOT_SEALED") -> tuple[RefundFacts, Any]:
    source = _parse(RefundExecution if write else RefundObservation, value, code)
    facts = _parse(RefundFacts, source.output, code)
    tool = source.execution.tool if write else source.provenance.source_tool
    _require(tool in (_WRITE_TOOLS if write else _READ_TOOLS).get(event, set()), code, "the source tool cannot attest this refund event")
    if event in {"notify", "settle"}:
        _require((tool == "stripe.list_disputes") == (facts.kind == "chargeback"), code, "dispute evidence must come from the dispute source")
    if write:
        _require(source.execution.project_id == facts.scope.project_id, "SCOPE_MISMATCH", "execution and normalized output must name the same project")
    else:
        _require((source.provenance.lane == "host_read") == tool.startswith("host."), code, "the observation must retain its admitted source lane")
    _require(facts.company_ref == plan.company_ref and facts.scope.currency == plan.currency and _same_scope(facts.scope, scope, entity=event != "purchase"), "SCOPE_MISMATCH", "refund evidence must remain in its authenticated company and execution scope")
    completed = source.execution.completed_at if write else source.provenance.completed_at
    _require(facts.event == event, code, "the source proves a different event")
    _require(parsed(facts.occurred_at) <= parsed(completed) <= parsed(at), "SOURCE_FROM_FUTURE", "events must precede their observations and current command")
    return facts, source


def _origin_uncached(value: Any, *, plan: RefundAndDisputePlan, scope: Any, at: str) -> tuple[RefundOrigin, dict[str, Any]]:
    source = _parse(RefundOrigin, value)
    try:
        if source.kind == "marketplace":
            from lightbulb.marketplace_supply_engine import verify_settled_transaction
            _require(source.state.get("status") in {"settled", "closed"}, "SOURCE_NOT_SETTLED", "marketplace cash must settle before a later reversal")
            state = verify_settled_transaction(source.state, source_plan=source.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
            values = {"customer_ref": state.ledger.buyer_ref, "payment_ref": state.ledger.payment_ref, "source_amount": state.ledger.cash_settled, "original_seller_liability": state.ledger.seller_liability, "original_company_revenue": state.ledger.company_take_revenue, "seller_ref": state.ledger.seller_ref, "settled_at": state.ledger.settled_at}
        elif source.kind == "revenue":
            from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
            bound_plan, state = REVENUE_CHAIN_LIFECYCLE.bind(source.source_plan, source.state)
            _require(state.status in {"cash_settled", "receivable_cleared"}, "SOURCE_NOT_SETTLED", "the invoiced sale must already have settled")
            _require(bound_plan.company_ref == plan.company_ref and bound_plan.currency == plan.currency, "SCOPE_MISMATCH", "the invoiced sale belongs to another company")
            purchase, _ = _facts(source.purchase, event="purchase", plan=plan, scope=scope, at=at)
            _require(purchase.disposition == "paid" and purchase.transaction_ref == state.ledger.invoice_ref and purchase.amount == state.ledger.settled_amount and purchase.source_transaction_digest == state.state_digest, "SOURCE_NOT_SEALED", "the provider purchase must bind this settled invoice and value")
            values = {"customer_ref": purchase.customer_ref, "payment_ref": purchase.payment_ref, "source_amount": state.ledger.settled_amount, "original_seller_liability": Decimal("0.00"), "original_company_revenue": state.ledger.settled_amount, "settled_at": state.ledger.settled_at}
        else:
            from lightbulb.storefront_settlement_chain import STOREFRONT_SETTLEMENT_LIFECYCLE, orders_receipt, refunds_receipt
            bound_plan, state = STOREFRONT_SETTLEMENT_LIFECYCLE.bind(source.source_plan, source.state)
            _require(state.status in {"payout_settled", "net_revenue_recorded", "reconciled"}, "SOURCE_NOT_SETTLED", "the order batch must already have settled")
            _require(bound_plan.company_ref == plan.company_ref and bound_plan.currency == plan.currency, "SCOPE_MISMATCH", "the order batch belongs to another company")
            purchase, _ = _facts(source.purchase, event="purchase", plan=plan, scope=scope, at=at)
            page = _parse(RefundObservation, source.order_page)
            original = orders_receipt(page.provenance, page.output, window_start=state.ledger.window_start, window_end=state.ledger.window_end)
            _require(original["orders_digest"] == state.ledger.orders_digest and Decimal(original["gross_sales"]) == state.ledger.gross_sales and original["order_count"] == state.ledger.order_count, "SOURCE_NOT_SEALED", "the retained order page must reproduce the original batch")
            rows = page.output.get("orders", page.output.get("data", []))
            order = next((row for row in rows if str(row.get("id")) == purchase.transaction_ref.removeprefix("order:")), None)
            _require(order is not None and purchase.disposition == "paid" and purchase.amount == _money(order["total_price"], "total_price") and purchase.source_transaction_digest == state.state_digest, "SOURCE_NOT_SEALED", "the paid customer order must be present in the original committed batch")
            page = _parse(RefundObservation, source.refund_page)
            returned = refunds_receipt(page.provenance, page.output)
            committed = next(entry.command.receipt for entry in state.transition_history if entry.command.event == "record_refunds")
            _require(returned["refunds_digest"] == committed.refunds_digest and Decimal(returned["refunds"]) == state.ledger.refunds and set(returned["refund_refs"]) == set(state.ledger.refund_refs), "SOURCE_NOT_SEALED", "the original refund page must reproduce the batch's committed returns")
            already_returned = Decimal("0.00")
            for row in page.output.get("refunds", page.output.get("data", [])):
                if str(row.get("order_id")) != str(order["id"]):
                    continue
                if "amount_money" in row:
                    already_returned += Decimal(str(row["amount_money"]["amount"])) / 100
                else:
                    already_returned += sum((Decimal(str(item.get("amount", item.get("subtotal", "0")))) for item in row.get("transactions", [])), Decimal("0.00"))
            remaining = purchase.amount - already_returned
            _require(remaining > 0 and remaining <= state.ledger.net_settled, "REFUND_EXCEEDS_REMAINING", "the order must have cash remaining after the returns already included in its batch")
            values = {"customer_ref": purchase.customer_ref, "payment_ref": purchase.payment_ref, "source_amount": remaining, "original_seller_liability": Decimal("0.00"), "original_company_revenue": remaining, "settled_at": state.ledger.settled_at or state.ledger.payout_arrival_at}
    except RefundAndDisputeError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise RefundAndDisputeError("SOURCE_NOT_SEALED", "the original settled sale must replay from its retained artifacts") from exc
    _require(_same_scope(state.scope, scope), "SCOPE_MISMATCH", "the original sale belongs to another authenticated scope")
    _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the original sale cannot come from the future")
    identity = stable_digest({"kind": source.kind, "scope": state.scope.to_dict(), "payment_ref": values["payment_ref"]})
    values["source_settled_at"] = values.pop("settled_at")
    return source, {**values, "transaction_ref": state.scope.entity_ref, "source_transaction_digest": state.state_digest, "origin_identity": identity, "origin_kind": source.kind}


@lru_cache(maxsize=16)
def _origin_replay(serialized: str) -> tuple[RefundOrigin, dict[str, Any]]:
    payload = json.loads(serialized)
    return _origin_uncached(payload["origin"], plan=RefundAndDisputePlan.model_validate(payload["plan"]), scope=payload["scope"], at=payload["at"])


def _origin(value: Any, *, plan: RefundAndDisputePlan, scope: Any, at: str) -> tuple[RefundOrigin, dict[str, Any]]:
    # Memoize only identical full documents, including the derived source ledger,
    # consumer policy, authenticated scope and time. State digest alone excludes
    # the ledger and is deliberately insufficient as a cache key. Return copies
    # so downstream code cannot mutate a previously verified result.
    serialized = json.dumps({"origin": detached(value), "plan": plan.to_dict(), "scope": detached(scope), "at": at}, sort_keys=True, separators=(",", ":"))
    return deepcopy(_origin_replay(serialized))


def _service(value: Any, *, data: Mapping[str, Any], scope: Any, at: str) -> None:
    from lightbulb.service_delivery_engine import CASE_LIFECYCLE
    source = _parse(RetainedState, value, "REMEDY_NOT_VERIFIED")
    try:
        _, state = CASE_LIFECYCLE.bind(source.source_plan, source.state)
    except (ValueError, TypeError) as exc:
        raise RefundAndDisputeError("REMEDY_NOT_VERIFIED", "the service source must replay") from exc
    _require(_same_scope(state.scope, scope), "SCOPE_MISMATCH", "the verified service case belongs to another scope")
    _require(state.status in {"verified", "closed"} and state.ledger.verified and not state.ledger.unreachable and state.ledger.verification_ref is not None, "REMEDY_NOT_VERIFIED", "an unreachable or unverified service close cannot authorize a refund")
    _require(state.ledger.customer_ref == data["customer_ref"], "CUSTOMER_MISMATCH", "the verified remedy belongs to another customer")
    _require(state.ledger.remedy_kind in {"refund", "credit"} and state.ledger.remedy_value == Decimal(str(data["amount"])), "REMEDY_MISMATCH", "the verified remedy must equal the requested refund")
    _require(parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "service evidence cannot come from the future")


def _remember(data: dict[str, Any], source: Any) -> None:
    digest = getattr(source, "observation_digest", None) or source.effect_digest
    _require(digest not in data.get("source_digests", ()), "REFUND_ALREADY_RECORDED", "the same provider result cannot satisfy two transitions")
    data["source_digests"] = [*data.get("source_digests", ()), digest]


def _history(receipt: RefundReceipt, facts: RefundFacts, data: dict[str, Any], plan: RefundAndDisputePlan, scope: Any, at: str) -> None:
    refs, total, seller_adjustments = [], Decimal("0.00"), Decimal("0.00")
    for source in receipt.prior_refunds:
        prior = verify_cleared_refund(source.state, source_plan=source.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
        _require(prior.ledger.origin_identity == data["origin_identity"], "HISTORY_INCOMPLETE", "refund history must concern this exact original payment")
        refs.append(prior.ledger.refund_ref)
        total += prior.ledger.cash_out
        seller_adjustments += prior.ledger.seller_share_adjustment
    _require(len(refs) == len(set(refs)) and facts.refund_ref not in refs, "REFUND_ALREADY_RECORDED", "a provider refund can be recorded once")
    _require(facts.history_complete and set(refs) == set(facts.prior_refund_refs) and total == facts.prior_refund_total, "HISTORY_INCOMPLETE", "the complete provider refund history must match retained cleared sources")
    payout_refs, paid = [], Decimal("0.00")
    for source in receipt.payouts:
        from lightbulb.payout_chain import verify_payout_cleared
        payout = verify_payout_cleared(source.state, source_plan=source.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope, at=at)
        rows = [row for row in payout.ledger.allocations if row.transaction_ref == data["transaction_ref"]]
        _require(bool(rows) and all(row.seller_ref == data.get("seller_ref") and row.transaction_source_digest == data["source_transaction_digest"] for row in rows), "PAYOUT_SOURCE_MISMATCH", "seller payment must allocate this exact source transaction")
        paid += sum((row.amount for row in rows), Decimal("0.00"))
        payout_refs.append(payout.ledger.payout_ref)
    _require(len(payout_refs) == len(set(payout_refs)) and set(payout_refs) == set(facts.prior_payout_refs) and paid == facts.seller_paid_total and paid <= Decimal(str(data["original_seller_liability"])), "PAYOUT_SOURCE_MISMATCH", "paid seller balances must equal the observed complete payout history")
    data.update(prior_refund_total=total, prior_seller_adjustments=seller_adjustments, seller_paid_total=paid, prior_refunds=[item.to_dict() for item in receipt.prior_refunds], payouts=[item.to_dict() for item in receipt.payouts])


def _same_refund(facts: RefundFacts, data: Mapping[str, Any], code: str) -> None:
    _require((facts.refund_ref, facts.transaction_ref, facts.customer_ref, facts.payment_ref, facts.amount, facts.source_transaction_digest, facts.kind) == (data["refund_ref"], data["transaction_ref"], data["customer_ref"], data["payment_ref"], Decimal(str(data["amount"])), data["source_transaction_digest"], data["kind"]), code, "the provider evidence must identify the original refund, customer, payment, value, kind and source")


def _effect_request(plan: RefundAndDisputePlan, data: Mapping[str, Any], state_digest: str, event: str, *, approval_ref: str | None = None) -> ConnectorExecutionRequest:
    _require(event in {"issue_credit", "submit_representment"}, "EXECUTION_MISMATCH", "only a refund or representation produces a write request")
    scope = detached(data["register_scope"])
    approval_ref = data.get("approval_task_ref") if event == "issue_credit" else approval_ref
    return ConnectorExecutionRequest(tool=plan.refund_tool if event == "issue_credit" else "stripe.update_dispute", arguments={"refund_ref": data["refund_ref"], "transaction_ref": data["transaction_ref"], "customer_ref": data["customer_ref"], "payment_ref": data["payment_ref"], "amount": str(data["amount"]), "currency": plan.currency, "correlation": data["correlation_ref"], "source_transaction_digest": data["source_transaction_digest"], "refund_state_digest": state_digest, "plan_digest": plan.plan_digest, "document_digests": list(data["document_digests"])}, scope={"project_ref": scope["project_ref"], "project_id": scope.get("project_id"), "actor_ref": data["requester_ref"]}, connector_account_ref=plan.connector_account_ref, effect="write", approval_required=True, approval_ref=approval_ref, preview_only=approval_ref is None, idempotency_key=f"refund:{scope['entity_ref']}:{event}:{state_digest}")


def _current_history(facts: RefundFacts, data: Mapping[str, Any]) -> None:
    refs = {source["state"]["ledger"]["refund_ref"] for source in data.get("prior_refunds", ())}
    payout_refs = {source["state"]["ledger"]["payout_ref"] for source in data.get("payouts", ())}
    _require(facts.history_complete and set(facts.prior_refund_refs) == refs and facts.prior_refund_total == Decimal(str(data["prior_refund_total"])), "HISTORY_INCOMPLETE", "changed refund history needs newly retained sources before execution or settlement")
    _require(set(facts.prior_payout_refs) == payout_refs and facts.seller_paid_total == Decimal(str(data["seller_paid_total"])), "PAYOUT_SOURCE_MISMATCH", "changed seller payment history must be reconciled before execution or settlement")


def _clearance(value: Any, data: dict[str, Any], plan: RefundAndDisputePlan, at: str) -> tuple[Any, list[str]]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    source = _parse(RetainedState, value, "BANK_EVIDENCE_MISSING")
    try:
        bank_plan, bank = BANK_REC_LIFECYCLE.bind(source.source_plan, source.state)
    except (ValueError, TypeError) as exc:
        raise RefundAndDisputeError("BANK_EVIDENCE_MISSING", "bank evidence must replay its complete statement and balance reads") from exc
    _require(bank_plan.company_ref == plan.company_ref and bank_plan.currency == plan.currency and _same_scope(bank.scope, data["register_scope"]), "SCOPE_MISMATCH", "refund bank evidence belongs to another company, currency or scope")
    _require(bank.status in {"lines_loaded", "matched", "variance_resolved", "reconciled", "exception_raised"} and parsed(bank.transition_history[-1].command.occurred_at) <= parsed(at), "BANK_EVIDENCE_MISSING", "bank evidence must include a current observed statement")
    rows = [row for row in bank.ledger.lines if row.reference == data["correlation_ref"]]
    _require(bool(rows), "BANK_EVIDENCE_MISSING", "the bank statement has no exact refund correlation")
    earliest = data["notified_at"] if data["kind"] == "chargeback" else data["executed_at"]
    _require(all(parsed(earliest) <= parsed(row.occurred_at) <= parsed(at) for row in rows), "BANK_EVIDENCE_MISSING", "bank movements must follow the recorded refund or initial dispute")
    debit = sum((-row.amount for row in rows if row.amount < 0), Decimal("0.00"))
    credit = sum((row.amount for row in rows if row.amount > 0), Decimal("0.00"))
    expected = Decimal(data["amount"])
    _require((debit == expected and credit == 0) if data["outcome"] != "won" else (debit == expected and credit == expected), "BANK_AMOUNT_MISMATCH", "the bank must prove the exact cash out, or both the dispute debit and recovery")
    refs = [row.line_ref for row in rows]
    prior_refs = {ref for previous in data.get("prior_refunds", ()) for ref in previous["state"]["ledger"].get("bank_line_refs", ())}
    _require(not set(refs) & prior_refs, "BANK_LINE_ALREADY_USED", "one bank movement cannot clear two refunds")
    return bank, refs


def _apply(plan: RefundAndDisputePlan, nxt: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    receipt, event, at = command.receipt, command.event, command.occurred_at
    try:
        if event == "notify":
            scope = _parse(EngineScope, receipt.register_scope, "SCOPE_MISMATCH")
            source, original = _origin(receipt.origin, plan=plan, scope=scope, at=at)
            facts, observation = _facts(receipt.observation, event="notify", plan=plan, scope=scope, at=at)
            _require(facts.source_transaction_digest == original["source_transaction_digest"] and facts.transaction_ref == original["transaction_ref"] and facts.payment_ref == original["payment_ref"], "SOURCE_NOT_SEALED", "notification must bind its retained original sale")
            _require(facts.customer_ref == original["customer_ref"], "CUSTOMER_MISMATCH", "notification belongs to another buyer")
            _require(facts.amount > 0, "REFUND_AMOUNT_INVALID", "refund and dispute amounts must be positive")
            _require(facts.disposition == ("requested" if facts.kind == "refund" else "disputed"), "SOURCE_NOT_SEALED", "notification must carry the provider's current disposition")
            data.update(**original, register_scope=scope.to_dict(), entity_ref=scope.entity_ref, requester_ref=command.actor_ref, origin=source.to_dict(), kind=facts.kind, refund_ref=facts.refund_ref, amount=facts.amount, notified_at=facts.occurred_at, due_at=facts.due_at, correlation_ref=facts.correlation_ref or "LB-RF-" + stable_digest({"scope": scope.to_dict(), "refund_ref": facts.refund_ref})[:24])
            _require(parsed(facts.occurred_at) >= parsed(original["source_settled_at"]), "SOURCE_FROM_FUTURE", "a reversal cannot precede the original settlement")
            _history(receipt, facts, data, plan, scope, at)
            _require(facts.amount <= original["source_amount"] - data["prior_refund_total"], "REFUND_EXCEEDS_REMAINING", "the refund exceeds the original payment remaining after proven reversals")
            if observation.provenance.source_tool == "host.remedy_register":
                _service(receipt.service_source, data=data, scope=scope, at=at)
                _require(facts.case_ref == receipt.service_source.state["ledger"]["case_ref"], "REMEDY_MISMATCH", "remedy notification must name its verified service case")
            if facts.kind == "chargeback":
                _require(facts.due_at is not None and parsed(facts.due_at) >= parsed(at), "DISPUTE_DEADLINE_PASSED", "a representable dispute needs its current provider deadline")
            _remember(data, observation)
        elif event == "authorize_remedy":
            from lightbulb.authority_matrix import require_authorization_proof
            _require(receipt.authorization_proof is not None, "AUTHORITY_MISSING", "refund execution needs the independently bound remedy approval")
            proof = require_authorization_proof(receipt.authorization_proof, category="remedy", amount=data["amount"], currency=plan.currency, company_ref=plan.company_ref, plan_digest=plan.plan_digest, entity_ref=data["entity_ref"], requester_ref=data["requester_ref"], command=command)
            data.update(authorization_proof_digest=proof.proof_digest, approval_task_ref=proof.approval_task_id, authorized_at=proof.decided_at)
        elif event == "gather_evidence":
            _require(data["kind"] == "chargeback" or data.get("authorization_proof_digest") is not None, "AUTHORITY_MISSING", "refund evidence cannot bypass the remedy approval")
            facts, observation = _facts(receipt.observation, event="evidence", plan=plan, scope=data["register_scope"], at=at, code="EVIDENCE_MISSING")
            _same_refund(facts, data, "EVIDENCE_MISSING")
            _require(facts.disposition == "complete" and bool(facts.document_digests) and GENESIS_DIGEST not in facts.document_digests, "EVIDENCE_MISSING", "evidence must retain the submitted documents' exact digests")
            data.update(evidence_digest=observation.observation_digest, evidenced_at=facts.occurred_at, document_digests=list(facts.document_digests))
            _remember(data, observation)
        elif event in {"issue_credit", "submit_representment"}:
            if event == "issue_credit":
                _require(data.get("authorization_proof_digest") is not None, "AUTHORITY_MISSING", "a provider write approval alone cannot replace remedy authority")
            else:
                _require(data["kind"] == "chargeback" and data.get("due_at") is not None and parsed(at) <= parsed(data["due_at"]), "DISPUTE_DEADLINE_PASSED", "representation must reach the provider by its deadline")
            facts, effect = _facts(receipt.execution, event=event, plan=plan, scope=data["register_scope"], at=at, code="EXECUTION_MISMATCH", write=True)
            _same_refund(facts, data, "EXECUTION_MISMATCH")
            _current_history(facts, data)
            expected = _effect_request(plan, data, command.expected_state_digest, event, approval_ref=effect.execution.approval_ref)
            _require(effect.execution.request_digest == expected.custody_fingerprint() and effect.execution.approval_ref == expected.approval_ref and effect.request.scope.actor_ref == expected.scope.actor_ref and effect.request.schema_id == expected.schema_id, "EXECUTION_MISMATCH", "execution must bind the exact approved refund state, source, amount, actor and evidence")
            if event == "submit_representment":
                _require(tuple(facts.document_digests) == tuple(data["document_digests"]), "EXECUTION_MISMATCH", "representation must submit exactly the gathered evidence documents")
            _require(facts.correlation_ref == data["correlation_ref"] and facts.disposition == ("refunded" if event == "issue_credit" else "submitted"), "EXECUTION_MISMATCH", "execution must prove the exact refund correlation and final disposition")
            _require(parsed(facts.occurred_at) >= max(parsed(data.get("authorized_at") or data["notified_at"]), parsed(data["evidenced_at"])), "EXECUTION_MISMATCH", "execution cannot precede its authorization, dispute or evidence")
            data.update(effect_digest=effect.effect_digest, executed_at=facts.occurred_at)
            _remember(data, effect)
        elif event == "settle":
            facts, observation = _facts(receipt.observation, event="settle", plan=plan, scope=data["register_scope"], at=at, code="SETTLEMENT_MISMATCH")
            _same_refund(facts, data, "SETTLEMENT_MISMATCH")
            _current_history(facts, data)
            _require(facts.correlation_ref == data["correlation_ref"] and parsed(facts.occurred_at) >= parsed(data["executed_at"]), "SETTLEMENT_MISMATCH", "final provider result must follow the exact refund or representation")
            _require(facts.disposition in ({"won", "lost"} if status == "represented" else {"settled", "refunded"}), "SETTLEMENT_MISMATCH", "the provider has not finally settled this outcome")
            cash = Decimal("0.00") if facts.disposition == "won" else Decimal(data["amount"])
            seller_adjust = min(cash, max(Decimal(data["original_seller_liability"]) - Decimal(data["prior_seller_adjustments"]), Decimal("0.00")))
            unpaid = max(Decimal(data["original_seller_liability"]) - Decimal(data["prior_seller_adjustments"]) - Decimal(data["seller_paid_total"]), Decimal("0.00"))
            liability_reduction = min(seller_adjust, unpaid)
            data.update(cash_out=cash, seller_share_adjustment=seller_adjust, seller_liability_reduction=liability_reduction, seller_recovery_receivable=seller_adjust - liability_reduction, company_revenue_reversal=cash - seller_adjust, settled_at=facts.occurred_at, outcome=facts.disposition if facts.disposition in {"won", "lost"} else "refunded")
            _remember(data, observation)
        elif event == "clear":
            bank, refs = _clearance(receipt.bank_source, data, plan, at)
            data.update(bank_line_refs=refs, bank_source_digest=bank.state_digest, cleared_at=at)
        elif event == "abandon":
            data["outcome"] = "abandoned"
    except RefundAndDisputeError as exc:
        raise Rejected(exc.code, exc.message, "await_approval" if exc.code == "AUTHORITY_MISSING" else "correct_input") from exc
    return nxt, data


class _RefundLifecycle(LifecycleSpec):
    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.register_scope is None or not _same_scope(self.scope, self.ledger.register_scope, entity=True):
                    raise ValueError("SCOPE_MISMATCH: state scope must equal the replayed opening scope")
                return self
        self.State = ScopedState


_TABLE = {("new", "notify"): "notified", ("notified", "authorize_remedy"): "authorized", ("notified", "gather_evidence"): "evidenced", ("authorized", "gather_evidence"): "evidenced", ("evidenced", "issue_credit"): "instructed", ("evidenced", "submit_representment"): "represented", ("instructed", "settle"): "settled", ("represented", "settle"): "settled", ("settled", "clear"): "cleared", **{(status, "abandon"): "abandoned" for status in ("notified", "authorized", "evidenced")}}
REFUND_LIFECYCLE = _RefundLifecycle(entity="refund_case", schema_prefix="refund_and_dispute_case", statuses=REFUND_STATUSES, terminal={"cleared", "abandoned"}, events=REFUND_EVENTS, table=_TABLE, opening_event="notify", reason_events=("abandon",), apply=_apply, ledger_model=RefundLedger, receipt_model=RefundReceipt, effect_boundary_model=RefundEffectBoundary, plan_model=RefundAndDisputePlan, max_transitions=16)
RefundState = REFUND_LIFECYCLE.State


def notification_receipt(observation: Any, *, origin_kind: str, original_state: Any, source_plan: Any, purchase: Any = None, order_page: Any = None, refund_page: Any = None, service_state: Any = None, service_plan: Any = None, prior_refunds: Sequence[Any] = (), payouts: Sequence[Any] = ()) -> dict[str, Any]:
    origin = RefundOrigin.model_validate({"kind": origin_kind, "state": detached(original_state), "source_plan": detached(source_plan), "purchase": detached(purchase), "order_page": detached(order_page), "refund_page": detached(refund_page)})
    return RefundReceipt.model_validate({"origin": origin, "observation": _parse(RefundObservation, observation), "service_source": {"source_plan": detached(service_plan), "state": detached(service_state)} if service_state is not None else None, "prior_refunds": [detached(item) for item in prior_refunds], "payouts": [detached(item) for item in payouts]}).to_dict()


def evidence_receipt(observation: Any) -> dict[str, Any]:
    return {"observation": _parse(RefundObservation, observation, "EVIDENCE_MISSING").to_dict()}


def execution_receipt(execution: Any) -> dict[str, Any]:
    return {"execution": _parse(RefundExecution, execution, "EXECUTION_MISMATCH").to_dict()}


def refund_request(state: Any, *, source_plan: Any, event: str = "issue_credit") -> ConnectorExecutionRequest:
    plan, proven = REFUND_LIFECYCLE.bind(source_plan, state)
    _require(proven.status == "evidenced", "EVIDENCE_MISSING", "only an evidenced refund or dispute produces an instruction")
    _require(event != "issue_credit" or proven.ledger.approval_task_ref is not None, "AUTHORITY_MISSING", "refund requests require the independently bound remedy approval")
    _require(event != "submit_representment" or proven.ledger.kind == "chargeback", "EXECUTION_MISMATCH", "only provider disputes may be represented")
    return _effect_request(plan, proven.ledger.to_dict(), proven.state_digest, event)


def settlement_receipt(observation: Any) -> dict[str, Any]:
    return {"observation": _parse(RefundObservation, observation, "SETTLEMENT_MISMATCH").to_dict()}


def clearance_receipt(bank_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    plan, state = BANK_REC_LIFECYCLE.bind(source_plan, bank_state)
    return {"bank_source": {"source_plan": plan.to_dict(), "state": state.to_dict()}}


def open_refund_case(plan: Any, scope: Any, *, receipt: Any, opened_at: str, actor_ref: str) -> Any:
    scope = _parse(EngineScope, scope, "SCOPE_MISMATCH")
    return REFUND_LIFECYCLE.open(plan, scope, receipt={**detached(receipt), "register_scope": scope.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_refund_case(plan: Any, state: Any, command: Any) -> Any:
    return REFUND_LIFECYCLE.advance(plan, state, command)


def verify_cleared_refund(state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    try:
        plan, proven = REFUND_LIFECYCLE.bind(source_plan, state)
    except (ValueError, TypeError) as exc:
        raise RefundAndDisputeError("SOURCE_NOT_SEALED", "the refund must replay its original sale, authority, effects and bank evidence") from exc
    _require(proven.status == "cleared", "REFUND_NOT_CLEARED", "corrections require a cleared refund")
    _require((company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency) and (expected_scope is None or _same_scope(expected_scope, proven.scope)), "SCOPE_MISMATCH", "the refund belongs to another company, currency or execution scope")
    _require(at is None or parsed(proven.ledger.cleared_at) <= parsed(timestamp(at, field_name="at")), "SOURCE_FROM_FUTURE", "refund clearance cannot come from the future")
    _require(proven.ledger.cash_out == proven.ledger.company_revenue_reversal + proven.ledger.seller_liability_reduction + proven.ledger.seller_recovery_receivable, "SETTLEMENT_MISMATCH", "the cash reversal must conserve company and seller shares")
    return proven


class RefundAdjustment(StrictModel):
    schema_id: Literal["lightbulb.refund_adjustment.v1"] = Field(default="lightbulb.refund_adjustment.v1", alias="schema")
    source: RetainedState
    company_ref: OpaqueRef
    currency: CurrencyCode
    refund_ref: OpaqueRef
    transaction_ref: OpaqueRef
    source_transaction_digest: Sha256Digest
    cash_out: Decimal
    company_revenue_reversal: Decimal
    seller_share_adjustment: Decimal
    seller_liability_reduction: Decimal
    seller_recovery_receivable: Decimal
    adjustment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("cash_out", "company_revenue_reversal", "seller_share_adjustment", "seller_liability_reduction", "seller_recovery_receivable", mode="before")
    @classmethod
    def _amount(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RefundAdjustment:
        state = verify_cleared_refund(self.source.state, source_plan=self.source.source_plan, company_ref=self.company_ref, currency=self.currency)
        keys = ("refund_ref", "transaction_ref", "source_transaction_digest", "cash_out", "company_revenue_reversal", "seller_share_adjustment", "seller_liability_reduction", "seller_recovery_receivable")
        if any(getattr(self, key) != getattr(state.ledger, key) for key in keys):
            raise ValueError("adjustment values must come from the replayed cleared refund")
        if not skip_digests(info) and self.adjustment_digest != sealed_digest(RefundAdjustment, self, "adjustment_digest"):
            raise ValueError("adjustment_digest must commit its complete source")
        return self


def refund_adjustment(state: Any, *, source_plan: Any) -> RefundAdjustment:
    plan = _parse(RefundAndDisputePlan, source_plan)
    proven = verify_cleared_refund(state, source_plan=plan)
    keys = ("refund_ref", "transaction_ref", "source_transaction_digest", "cash_out", "company_revenue_reversal", "seller_share_adjustment", "seller_liability_reduction", "seller_recovery_receivable")
    return seal(RefundAdjustment, {"source": {"state": proven.to_dict(), "source_plan": plan.to_dict()}, "company_ref": plan.company_ref, "currency": plan.currency, **{key: getattr(proven.ledger, key) for key in keys}}, "adjustment_digest")


def revenue_reversal_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    proven = verify_cleared_refund(state, source_plan=source_plan)
    _require(proven.ledger.origin_kind == "revenue", "SOURCE_NOT_SEALED", "invoice reversals require the original revenue chain source")
    return {"refund_source": {"state": proven.to_dict(), "source_plan": detached(source_plan)}, "refund_ref": proven.ledger.refund_ref, "refund_amount": str(proven.ledger.company_revenue_reversal), "against_source_digest": proven.ledger.source_transaction_digest, "refund_source_digest": proven.state_digest}


def cost_return_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    plan = _parse(RefundAndDisputePlan, source_plan)
    proven = verify_cleared_refund(state, source_plan=plan)
    return {"refund_source": {"state": proven.to_dict(), "source_plan": plan.to_dict()}, "source_kind": "refund_case", "source_ref": f"refund:{proven.ledger.refund_ref}", "source_digest": proven.state_digest, "against_source_digest": proven.ledger.source_transaction_digest, "amount": str(proven.ledger.company_revenue_reversal), "currency": plan.currency, "occurred_at": proven.ledger.cleared_at, "evidence_refs": [f"refund:{proven.ledger.refund_ref}", f"bank:{proven.ledger.bank_source_digest[:24]}"]}


def contra_revenue_source_balance(state: Any, *, source_plan: Any) -> Any:
    """The company's earned-revenue correction, excluding the seller share."""
    from lightbulb.finance_close_observations import SourceBalance

    proven = verify_cleared_refund(state, source_plan=source_plan)
    return SourceBalance(kind="contra_revenue", source_ref=f"refund:{proven.ledger.refund_ref}",
                         source_tool=REFUND_AND_DISPUTE_KIND, provenance_digest=proven.state_digest,
                         balance=proven.ledger.company_revenue_reversal, items=1,
                         window_end=proven.ledger.cleared_at)


def refund_summary(state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, proven = REFUND_LIFECYCLE.bind(source_plan, state)
    return {"status": proven.status, "state_digest": proven.state_digest, **proven.ledger.to_dict()}


REFUND_AND_DISPUTE_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": REFUND_AND_DISPUTE_KIND, "golden_loop": REFUND_GOLDEN_LOOP, "stages": list(REFUND_EVENTS), "statuses": list(REFUND_STATUSES), "events": list(REFUND_EVENTS), "hops": {"cleared": "revenue_chain.reverse_settlement / company_cost_centres.record_return / custodial_funds.record_liability / payout_chain"}, "required_connectors": ["stripe.list_refunds", "stripe.list_disputes", "stripe.create_refund", "stripe.update_dispute", "xero.list_bank_transactions"], "hard_rules": ["every correction replays its original sale and its bank cash", "refund authority is bound to the exact remedy command", "paid seller money becomes a recovery receivable, never a fictitious unpaid liability", "one provider refund and bank row corrects one original payment once"]}
__all__ = ["REFUND_AND_DISPUTE_KIND", "REFUND_PLAN_SCHEMA", "REFUND_GOLDEN_LOOP", "REFUND_STATUSES", "REFUND_EVENTS", "REFUND_CODES", "REFUND_AND_DISPUTE_MANIFEST", "RefundAndDisputeError", "RefundAndDisputePlan", "RefundFacts", "RefundObservation", "RefundExecution", "RefundOrigin", "RefundReceipt", "RefundLedger", "RefundEffectBoundary", "RefundState", "RefundAdjustment", "RetainedState", "REFUND_LIFECYCLE", "compile_refund_and_dispute_chain", "refund_observation", "refund_execution", "notification_receipt", "evidence_receipt", "refund_request", "execution_receipt", "settlement_receipt", "clearance_receipt", "open_refund_case", "advance_refund_case", "verify_cleared_refund", "refund_adjustment", "revenue_reversal_receipt", "cost_return_receipt", "contra_revenue_source_balance", "refund_summary"]
