"""The revenue chain: one replay-fenced lifecycle from a handed-off deal to cash cleared in the books.

Every engine reported revenue; none of them proved it end to end.  The packs
for each hop already exist and each is fenced on its own: the pipeline
engine's ``hand_off``, the commercial-legal handoff's executed agreement
custody candidate, the contract-to-cash continuation's invoice write receipt,
the governed ``observe_invoice_issued`` / ``observe_invoice_payment_applied``
/ ``observe_cash_settlement`` observations, and the finance close's
receivables reconciliation.  ``REVENUE_CHAIN_LIFECYCLE`` links them into one
case:

    handed_off -> agreement_executed -> invoice_issued -> payment_applied
               -> cash_settled -> receivable_cleared          (terminal)
    any non-terminal -> cancelled | reconciliation_required   (terminal)

Each transition consumes a receipt derived from the sealed artifact of that
hop (``agreement_receipt`` from a custody candidate, ``invoice_receipt`` from
the write receipt plus the APPLIED issuance observation, ``payment_receipt``
from an APPLIED payment observation, ``settlement_receipt`` from a SETTLED
settlement observation, ``clearance_receipt`` from a close reconciliation of
receivables) and the guards refuse the hops that do not line up: the invoice
must match the accepted value, the payment must be for the invoice, the
settlement must equal the payment inside its reversal window, the clearance
must come from a close that covers the settlement date.  An ambiguous invoice
write moves the case to ``reconciliation_required`` instead of guessing.

``period_evidence_receipt`` turns a settled case into the company operating
system's ``record_evidence`` receipt for the pipeline engine, so the revenue
the period records is the cash the chain proved.  Nothing here writes to a
provider or the ledger.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
)
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan

REVENUE_CHAIN_KIND = "revenue_chain"
REVENUE_CHAIN_GOLDEN_LOOP = "revenue.icp_to_qualified_pipeline@0.1.0"
REVENUE_CHAIN_PLAN_SCHEMA = "lightbulb.revenue_chain_plan.v1"
MAX_CHAIN_TRANSITIONS = 64
_HUNDRED = Decimal("100")

CHAIN_STATUSES: tuple[str, ...] = ("handed_off", "agreement_executed", "invoice_issued", "payment_applied", "cash_settled", "receivable_cleared", "cancelled", "reconciliation_required")
TERMINAL_CHAIN_STATUSES: frozenset[str] = frozenset({"cancelled", "reconciliation_required"})
CHAIN_EVENTS: tuple[str, ...] = ("hand_off", "execute_agreement", "issue_invoice", "apply_payment", "settle_cash", "reverse_settlement", "clear_receivable", "cancel", "require_reconciliation")
_CHAIN_TABLE: dict[tuple[str, str], str] = {
    ("new", "hand_off"): "handed_off",
    ("handed_off", "execute_agreement"): "agreement_executed",
    ("agreement_executed", "issue_invoice"): "invoice_issued",
    ("invoice_issued", "apply_payment"): "payment_applied",
    ("payment_applied", "settle_cash"): "cash_settled",
    ("cash_settled", "clear_receivable"): "receivable_cleared",
    ("cash_settled", "reverse_settlement"): "cash_settled",
    ("receivable_cleared", "reverse_settlement"): "cash_settled",
    **{(status, "cancel"): "cancelled" for status in ("handed_off", "agreement_executed", "invoice_issued")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("agreement_executed", "invoice_issued", "payment_applied", "cash_settled")},
}


class RevenueChainPlan(StrictModel):
    """What the chain enforces: the currency, how much the invoice may differ from the deal, and how long each hop may take."""

    schema_id: str = Field(default=REVENUE_CHAIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: ShortText
    invoice_tolerance_percent: Decimal = Field(default=Decimal("5.00"), validate_default=True)
    max_days_deal_to_agreement: int = Field(default=90, ge=1, le=730)
    max_days_agreement_to_invoice: int = Field(default=60, ge=1, le=730)
    max_days_invoice_to_payment: int = Field(default=90, ge=1, le=730)
    min_reversal_window_days: int = Field(default=7, ge=1, le=180)
    pipeline_plan_digest: Sha256Digest | None = None
    require_agreement_paper: bool = False
    required_cover_limit: Decimal | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("required_cover_limit", mode="before")
    @classmethod
    def _cover_limit(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="required_cover_limit")

    @field_validator("invoice_tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="invoice_tolerance_percent")
        if result > Decimal("50"):
            raise ValueError("invoice_tolerance_percent must be at most 50")
        return result

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> RevenueChainPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(RevenueChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_revenue_chain(company_ref: str, *, currency: str, pipeline_plan: PipelineEngineLoopPlan | Mapping[str, Any] | None = None, overrides: Mapping[str, Any] | None = None) -> RevenueChainPlan:
    digest = PipelineEngineLoopPlan.model_validate(detached(pipeline_plan)).plan_digest if pipeline_plan is not None else None
    return seal(RevenueChainPlan, {"company_ref": company_ref, "currency": currency.upper(), "pipeline_plan_digest": digest, **dict(overrides or {})}, "plan_digest")


class ChainReceipt(StrictModel):
    custody_source: dict[str, Any] | None = None
    invoice_source: dict[str, Any] | None = None
    payment_source: dict[str, Any] | None = None
    settlement_source: dict[str, Any] | None = None
    close_source: dict[str, Any] | None = None
    pipeline_source: dict[str, Any] | None = None
    retention_source: dict[str, Any] | None = None
    deal_source: dict[str, Any] | None = None
    wip_source: dict[str, Any] | None = None
    collections_source: dict[str, Any] | None = None
    refund_source: dict[str, Any] | None = None
    refund_ref: OpaqueRef | None = None
    refund_amount: Decimal | None = None
    against_source_digest: Sha256Digest | None = None
    refund_source_digest: Sha256Digest | None = None
    entity_scope: EngineScope | None = None
    agreement_source: dict[str, Any] | None = None
    cover_source: dict[str, Any] | None = None
    cover_sources: tuple[dict[str, Any], ...] = ()
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    prospect_ref: OpaqueRef | None = None
    deal_ref: OpaqueRef | None = None
    deal_value: Decimal | None = None
    prospect_state_digest: Sha256Digest | None = None
    agreement_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    custody_candidate_digest: Sha256Digest | None = None
    executed_at: str | None = None
    contract_value: Decimal | None = None
    accepted_amount: Decimal | None = None
    acceptance_ref: OpaqueRef | None = None
    continuation_ref: OpaqueRef | None = None
    correlation_sha256: Sha256Digest | None = None
    invoice_ref: OpaqueRef | None = None
    invoice_total: Decimal | None = None
    invoice_evidence_sha256: Sha256Digest | None = None
    write_journal_ref: OpaqueRef | None = None
    issued_at: str | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    applied_amount: Decimal | None = None
    payment_count: int | None = Field(default=None, ge=1, le=1000)
    applied_at: str | None = None
    settlement_evidence_sha256: Sha256Digest | None = None
    settled_amount: Decimal | None = None
    reversal_window_days: int | None = Field(default=None, ge=1, le=180)
    payout_arrival_at: str | None = None
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    reconciliation_ref: OpaqueRef | None = None
    period_end: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("deal_value", "contract_value", "accepted_amount", "invoice_total", "applied_amount", "settled_amount", "refund_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("executed_at", "issued_at", "applied_at", "payout_arrival_at", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ChainLedger(StrictModel):
    signed_document_digests: tuple[Sha256Digest, ...] = ()
    wip_source_digest: Sha256Digest | None = None
    accrual_ref: OpaqueRef | None = None
    accepted_value_digest: Sha256Digest | None = None
    collections_source_digest: Sha256Digest | None = None
    refund_base_digest: Sha256Digest | None = None
    refund_source_digests: tuple[Sha256Digest, ...] = ()
    refund_refs: tuple[OpaqueRef, ...] = ()
    refunded_amount: Decimal = Decimal("0.00")
    gross_settled_amount: Decimal = Decimal("0.00")
    entity_scope: dict[str, Any] | None = None
    paper_source_digests: tuple[Sha256Digest, ...] = ()
    prospect_ref: str | None = None
    deal_ref: str | None = None
    deal_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    handed_off_at: str | None = None
    agreement_ref: str | None = None
    contract_ref: str | None = None
    custody_candidate_digest: str | None = None
    executed_at: str | None = None
    contract_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    accepted_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    continuation_ref: str | None = None
    correlation_sha256: str | None = None
    invoice_ref: str | None = None
    invoice_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    issued_at: str | None = None
    applied_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    applied_at: str | None = None
    settled_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    settled_at: str | None = None
    payout_arrival_at: str | None = None
    close_ref: str | None = None
    cleared_at: str | None = None
    days_deal_to_cash: int | None = None
    cancel_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "cleared", "cancelled", "reconciliation_required"] = "open"

    @field_validator("deal_value", "contract_value", "accepted_amount", "invoice_total", "applied_amount", "settled_amount", "refunded_amount", "gross_settled_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ChainEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    invoice_created: Literal[False] = False
    payment_collected: Literal[False] = False
    journal_posted: Literal[False] = False
    message_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _days(start: str | None, end: str) -> int:
    if not start:
        return 0
    return (parsed(end) - parsed(start)).days


def _within(value: Decimal, reference: Decimal, tolerance_percent: Decimal) -> bool:
    if reference <= 0:
        return value == reference
    return (value - reference).copy_abs() <= (reference * tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)


def _paper_call(function: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return function(*args, **kwargs)
    except ValueError as exc:
        require(False, getattr(exc, "code", "AGREEMENT_NOT_IN_FORCE"), str(exc))


def _rederive_native_sources(plan: RevenueChainPlan, receipt: ChainReceipt, data: dict[str, Any], scope: dict[str, Any], at: str) -> ChainReceipt:
    """Keep native provider custody and portable lifecycle replay as explicit boundaries."""
    r = receipt
    for name in ("custody_source", "invoice_source", "payment_source", "settlement_source", "close_source"):
        source = getattr(r, name)
        if source is None:
            continue
        if name == "custody_source":
            facts = _paper_call(agreement_receipt, source.get("custody_candidate"), accepted_value=source.get("accepted_value"), review_packet=source.get("review_packet"))
            native = source["custody_candidate"]
            require(all(native["scope"]["commercial"].get(key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "SCOPE_MISMATCH", "signed custody must share the execution scope")
            value = source["accepted_value"]
            value_currency = value["source_plan"]["currency"] if "source_state" in value else value["currency"]
            value_at = value["source_state"]["transition_history"][-1]["command"]["occurred_at"] if "source_state" in value else value["accepted_at"]
            require(value_currency == plan.currency, "SCOPE_MISMATCH", "the accepted contract currency must match")
            require(parsed(value_at) <= parsed(at) and parsed(native["executed_at"]) <= parsed(at), "AGREEMENT_FROM_FUTURE", "custody and acceptance must already exist")
            data["signed_document_digests"] = [item["artifact_digest"] for item in native["executed_documents"]]
        elif name == "invoice_source":
            facts = _paper_call(invoice_receipt, source.get("write_receipt"), source.get("issued_observation"), admission=source.get("admission"), invoice_ref=source.get("invoice_ref"), invoice_total=source.get("invoice_total"))
            admission = source["admission"]
            require(admission["currency"] == plan.currency and admission["contract_ref"] == data.get("contract_ref"), "INVOICE_CONTRACT_MISMATCH", "the admitted invoice belongs to this contract and currency")
            # A custody candidate precedes Spring registration; in that native
            # path the admission proves the exact signed document. Registered
            # deal and paper paths already have the final agreement reference.
            if data.get("signed_document_digests"):
                require(admission["signed_document_sha256"] in data["signed_document_digests"], "INVOICE_CONTRACT_MISMATCH", "registration must retain this signed document")
            else:
                require(admission["agreement_ref"] == data.get("agreement_ref"), "INVOICE_CONTRACT_MISMATCH", "the admitted invoice uses this registered agreement")
            require(parsed(facts["issued_at"]) <= parsed(at), "INVOICE_IN_FUTURE", "the invoice must already be observed")
        elif name == "payment_source":
            facts = _paper_call(payment_receipt, source.get("observation"))
            require(source["observation"]["currency"] == plan.currency, "PAYMENT_CURRENCY_MISMATCH", "the payment uses this invoice currency")
            if source["observation"].get("query_sha256") is not None:
                require(Decimal(source["observation"]["invoice_total"]) == Decimal(str(data.get("invoice_total", "0"))), "PAYMENT_NOT_FULL", "the native observed invoice total must equal the admitted invoice total")
            require(parsed(facts["applied_at"]) <= parsed(at), "PAYMENT_IN_FUTURE", "the payment must already be observed")
        elif name == "settlement_source":
            facts = _paper_call(settlement_receipt, source.get("observation"), currency=plan.currency)
            require(parsed(source["observation"]["observed_at"]) <= parsed(at), "SETTLEMENT_IN_FUTURE", "the reversal observation must already exist")
        else:
            facts = _paper_call(clearance_receipt, source.get("state"), source_plan=source.get("source_plan"))
            close = source["state"]
            require(all(close["scope"].get(key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "the close must share the execution scope")
            require(parsed(close["ledger"]["closed_at"]) <= parsed(at), "CLOSE_FROM_FUTURE", "the books must already be closed")
            require(parsed(close["ledger"]["period_start"]) <= parsed(data["settled_at"]), "CLOSE_AFTER_SETTLEMENT", "the close window must include settlement")
        normalized = ChainReceipt.model_validate(facts)
        for key in facts:
            if key != "evidence_refs" and key != name:
                require(getattr(r, key) in (None, getattr(normalized, key)), "REVENUE_SOURCE_MISMATCH", "receipt fields must reproduce retained native artifacts")
        r = ChainReceipt.model_validate({**r.to_dict(), **facts})
    return r


def _apply_chain(plan: RevenueChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    scope = dict(detached(r.entity_scope or data.get("entity_scope") or {}))
    require(scope.get("currency") == plan.currency, "SCOPE_MISMATCH", "the revenue case currency must equal its plan")
    r = _rederive_native_sources(plan, r, data, scope, at)
    if r.pipeline_source is not None:
        source = r.pipeline_source
        pipeline, prospect = PROSPECT_LIFECYCLE.bind(source.get("source_plan"), source.get("state"))
        require(plan.pipeline_plan_digest in (None, pipeline.plan_digest), "PIPELINE_PLAN_MISMATCH", "the hand-off uses this company's bound pipeline plan")
        scope = dict(detached(r.entity_scope or data.get("entity_scope") or {}))
        require(all(scope.get(key) == getattr(prospect.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "the prospect must share this revenue case's actual scope")
        require(parsed(prospect.transition_history[-1].command.occurred_at) <= parsed(at), "HAND_OFF_FROM_FUTURE", "the prospect hand-off must already have happened")
        facts = ChainReceipt.model_validate(hand_off_receipt(pipeline, prospect))
        for key in ("prospect_ref", "deal_ref", "deal_value", "prospect_state_digest"):
            require(getattr(r, key) in (None, getattr(facts, key)), "HAND_OFF_SOURCE_MISMATCH", "hand-off values must reproduce the retained pipeline history")
        r = ChainReceipt.model_validate({**r.to_dict(), **facts.to_dict()})
    if r.retention_source is not None:
        from lightbulb.retention_chain import hand_off_receipt as renewal_hand_off_receipt
        require(r.pipeline_source is None and r.wip_source is None, "HAND_OFF_SOURCE_MISMATCH", "one hand-off must name one original source")
        source = r.retention_source
        facts = ChainReceipt.model_validate(_paper_call(renewal_hand_off_receipt, source.get("state"), source_plan=source.get("source_plan")))
        retained = facts.retention_source
        require(retained["source_plan"]["company_ref"] == plan.company_ref and retained["source_plan"]["currency"] == plan.currency,
                "SCOPE_MISMATCH", "the renewal must name this logical company and currency")
        require(all(scope.get(key) == retained["state"]["scope"].get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")),
                "SCOPE_MISMATCH", "the renewal must share this revenue case's actual scope")
        require(parsed(retained["state"]["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at),
                "HAND_OFF_FROM_FUTURE", "the renewal hand-off must already have happened")
        for key in ("prospect_ref", "deal_ref", "deal_value", "prospect_state_digest"):
            require(getattr(r, key) in (None, getattr(facts, key)), "HAND_OFF_SOURCE_MISMATCH", "hand-off values must reproduce the retained renewal history")
        r = ChainReceipt.model_validate({**r.to_dict(), **facts.to_dict()})
    if r.deal_source is not None:
        source = r.deal_source
        paper = r.agreement_source or {}
        facts = ChainReceipt.model_validate(_paper_call(deal_agreement_receipt, source.get("state"), source_plan=source.get("source_plan"), agreement_state=paper.get("state"), agreement_plan=paper.get("plan"), at=at))
        scope = dict(detached(r.entity_scope or data.get("entity_scope") or {}))
        require(all(scope.get(key) == source["state"]["scope"].get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "the deal must share this revenue case's actual scope")
        require(source["source_plan"]["company_ref"] == plan.company_ref, "SCOPE_MISMATCH", "the deal must name this logical company")
        for key in ("agreement_ref", "contract_ref", "custody_candidate_digest", "executed_at", "contract_value", "accepted_amount", "acceptance_ref"):
            require(getattr(r, key) in (None, getattr(facts, key)), "DEAL_SOURCE_MISMATCH", "agreement economics must reproduce the signed deal and paper")
        r = ChainReceipt.model_validate({**r.to_dict(), **facts.to_dict()})
    if r.wip_source is not None:
        from lightbulb.wip_billing import verify_billing_source
        source = _paper_call(verify_billing_source, r.wip_source, company_ref=plan.company_ref, currency=plan.currency, expected_scope=r.entity_scope or data.get("entity_scope"))
        facts = _paper_call(wip_invoice_receipt, source["source_state"], source_plan=source["source_plan"])
        normalized_facts = ChainReceipt.model_validate(facts)
        for key, value in facts.items():
            if key != "evidence_refs" and getattr(r, key, None) is not None:
                require(detached(getattr(r, key)) == detached(getattr(normalized_facts, key)), "WIP_SOURCE_MISMATCH", "invoice fields must match the actual accrued work and issued invoice")
        require(parsed(source["issued_at"]) <= parsed(at), "INVOICE_IN_FUTURE", "the WIP invoice must already be observed")
        r = ChainReceipt.model_validate({**r.to_dict(), **facts})
        wip_ledger = source["source_state"]["ledger"]
        data.update(wip_source_digest=source["source_digest"], accrual_ref=source["accrual_ref"], accepted_value_digest=wip_ledger["accepted_value_digest"])
    if event == "hand_off":
        require(r.pipeline_source is not None or r.wip_source is not None or r.retention_source is not None, "HAND_OFF_SOURCE_REQUIRED", "hand-off requires the replayable prospect, won renewal, or billed engagement")
        if r.entity_scope is not None:
            require(command.expected_state_digest == REVENUE_CHAIN_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the paper scope must be this revenue case's actual scope")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.prospect_ref is not None and r.deal_ref is not None and r.deal_value is not None and r.prospect_state_digest is not None, "HAND_OFF_MISSING", "a hand-off names the prospect, the deal, its value, and the prospect state digest it came from")
        require(r.deal_value > 0, "DEAL_VALUE_INVALID", "the deal value is positive")
        data.update({"prospect_ref": r.prospect_ref, "deal_ref": r.deal_ref, "deal_value": str(r.deal_value), "handed_off_at": at})
    elif event == "execute_agreement":
        require(r.custody_source is not None or r.deal_source is not None or r.wip_source is not None, "AGREEMENT_SOURCE_REQUIRED", "agreement economics require signed custody and accepted value")
        require(r.agreement_ref is not None and r.contract_ref is not None and r.custody_candidate_digest is not None and r.executed_at is not None and r.contract_value is not None, "AGREEMENT_MISSING", "an executed agreement names its custody candidate digest, contract, value, and execution time")
        require(_days(data.get("handed_off_at"), at) <= plan.max_days_deal_to_agreement, "AGREEMENT_TOO_LATE", f"the agreement executed more than {plan.max_days_deal_to_agreement} days after hand-off", "manual_reconciliation")
        accepted = r.accepted_amount if r.accepted_amount is not None else r.contract_value
        require(accepted <= r.contract_value, "ACCEPTED_EXCEEDS_CONTRACT", "the accepted value cannot exceed the contract value")
        data.update({"agreement_ref": r.agreement_ref, "contract_ref": r.contract_ref, "custody_candidate_digest": r.custody_candidate_digest, "executed_at": r.executed_at, "contract_value": str(r.contract_value), "accepted_amount": str(accepted)})
    elif event == "issue_invoice":
        require(r.invoice_source is not None or r.wip_source is not None, "INVOICE_SOURCE_REQUIRED", "invoice issuance requires its admitted write and exhaustive observation")
        if plan.require_agreement_paper or r.agreement_source is not None:
            from lightbulb.obligation_paper import verify_agreement_in_force, verify_cover_current
            require(r.agreement_source is not None, "AGREEMENT_NOT_IN_FORCE", "this invoice requires the current replayable agreement")
            source = r.agreement_source
            require(data.get("entity_scope") is not None, "SCOPE_MISMATCH", "the protected invoice requires its retained execution scope")
            paper = _paper_call(verify_agreement_in_force, source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.currency, at=at, agreement_ref=data.get("agreement_ref"), contract_ref=data.get("contract_ref"), expected_scope=data.get("entity_scope"))
            digests = [paper.state_digest]
            minimum = plan.required_cover_limit
            for kind, limit in paper.ledger.insurance_minima.items():
                source = next((item for item in r.cover_sources if item.get("state", {}).get("ledger", {}).get("kind") == kind), r.cover_source)
                require(source is not None, "COI_NOT_CURRENT", "the contracted certificate must be current at invoice time")
                cover = _paper_call(verify_cover_current, source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.currency, at=at, kind=kind, required_limit=limit, expected_scope=data.get("entity_scope"))
                digests.append(cover.state_digest)
            if minimum is not None:
                source = r.cover_source
                require(source is not None, "COI_NOT_CURRENT", "the invoice policy requires a current certificate")
                cover = _paper_call(verify_cover_current, source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.currency, at=at, required_limit=minimum, expected_scope=data.get("entity_scope"))
                digests.append(cover.state_digest)
            data["paper_source_digests"] = list(dict.fromkeys(digests))
        require(r.invoice_ref is not None and r.invoice_total is not None and r.invoice_evidence_sha256 is not None and r.correlation_sha256 is not None and r.write_journal_ref is not None and r.issued_at is not None, "INVOICE_MISSING", "an issued invoice names its ref, total, correlation, write journal, issuance evidence, and issue time")
        require(_days(data.get("executed_at"), at) <= plan.max_days_agreement_to_invoice, "INVOICE_TOO_LATE", f"the invoice issued more than {plan.max_days_agreement_to_invoice} days after execution", "manual_reconciliation")
        accepted = Decimal(str(data.get("accepted_amount", "0")))
        require(_within(r.invoice_total, accepted, plan.invoice_tolerance_percent), "INVOICE_NOT_ACCEPTED_VALUE", f"invoice total {r.invoice_total} differs from the accepted value {accepted} by more than {plan.invoice_tolerance_percent}%", "manual_reconciliation")
        data.update({"continuation_ref": r.continuation_ref, "correlation_sha256": r.correlation_sha256, "invoice_ref": r.invoice_ref, "invoice_total": str(r.invoice_total), "issued_at": r.issued_at})
    elif event == "apply_payment":
        require(r.payment_source is not None or r.collections_source is not None, "PAYMENT_SOURCE_REQUIRED", "payment requires its complete observation or recovered collections history")
        recovered = False
        if r.collections_source is not None:
            source = r.collections_source
            facts = _paper_call(collections_payment_receipt, source.get("state"), source_plan=source.get("source_plan"))
            case = source["state"]
            scope = data.get("entity_scope") or {}
            require(all(case["scope"].get(key) == scope.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "SCOPE_MISMATCH", "the collections case belongs to this company execution scope")
            require(case["ledger"]["invoice_ref"] == data.get("invoice_ref"), "PAYMENT_CORRELATION_MISMATCH", "the recovered receivable must be this invoice")
            for key, value in facts.items():
                if key not in {"evidence_refs", "collections_source"}:
                    require(getattr(r, key, None) is None or str(getattr(r, key)) == str(value), "PAYMENT_CORRELATION_MISMATCH", "payment fields must reproduce the recovered receivable")
            r = ChainReceipt.model_validate({**r.to_dict(), **facts})
            data["collections_source_digest"] = case["state_digest"]
            recovered = True
        require(r.payment_evidence_sha256 is not None and r.applied_amount is not None and r.payment_count is not None and r.applied_at is not None and r.correlation_sha256 is not None, "PAYMENT_MISSING", "an applied payment names its evidence, amount, count, time, and correlation")
        require(r.correlation_sha256 == data.get("correlation_sha256"), "PAYMENT_CORRELATION_MISMATCH", "the payment observation must carry the invoice's correlation", "manual_reconciliation")
        require(r.applied_amount == Decimal(str(data.get("invoice_total", "0"))), "PAYMENT_NOT_FULL", f"applied {r.applied_amount} does not settle the invoice total {data.get('invoice_total')}", "manual_reconciliation")
        require(recovered or _days(data.get("issued_at"), at) <= plan.max_days_invoice_to_payment, "PAYMENT_TOO_LATE", f"late payment requires a replayed collections recovery after {plan.max_days_invoice_to_payment} days", "manual_reconciliation")
        require(parsed(r.applied_at) <= parsed(at), "PAYMENT_IN_FUTURE", "a payment must have occurred before this transition")
        data.update({"applied_amount": str(r.applied_amount), "applied_at": r.applied_at})
    elif event == "settle_cash":
        require(r.settlement_source is not None, "SETTLEMENT_SOURCE_REQUIRED", "cash settlement requires its complete canonical observation")
        require(r.settlement_evidence_sha256 is not None and r.settled_amount is not None and r.reversal_window_days is not None and r.payout_arrival_at is not None and r.correlation_sha256 is not None, "SETTLEMENT_MISSING", "a settlement names its evidence, amount, reversal window, payout arrival, and correlation")
        require(r.correlation_sha256 == data.get("correlation_sha256"), "SETTLEMENT_CORRELATION_MISMATCH", "the settlement observation must carry the invoice's correlation", "manual_reconciliation")
        require(r.settled_amount == Decimal(str(data.get("applied_amount", "0"))), "SETTLEMENT_AMOUNT_MISMATCH", f"settled {r.settled_amount} differs from the applied payment {data.get('applied_amount')}", "manual_reconciliation")
        require(r.reversal_window_days >= plan.min_reversal_window_days, "REVERSAL_WINDOW_SHORT", f"the reversal window observed ({r.reversal_window_days}d) is shorter than the plan's {plan.min_reversal_window_days}d", "manual_reconciliation")
        require(parsed(r.payout_arrival_at) <= parsed(at), "PAYOUT_IN_FUTURE", "a payout that has not arrived cannot settle cash")
        data.update({"settled_amount": str(r.settled_amount), "gross_settled_amount": str(r.settled_amount), "settled_at": at, "payout_arrival_at": r.payout_arrival_at})
    elif event == "reverse_settlement":
        from lightbulb.refund_and_dispute_chain import verify_cleared_refund
        require(r.refund_source is not None, "REFUND_NOT_PROVEN", "a reversal requires the cleared refund and its source plan")
        source = r.refund_source
        refund = _paper_call(verify_cleared_refund, source.get("state"), source_plan=source.get("source_plan"), company_ref=plan.company_ref, currency=plan.currency, expected_scope=data.get("entity_scope"), at=at)
        require(refund.ledger.origin_kind == "revenue" and refund.ledger.origin.state["scope"]["entity_ref"] == (data.get("entity_scope") or {}).get("entity_ref"), "REFUND_SOURCE_MISMATCH", "the refund must reverse this exact revenue case")
        base = refund.ledger.source_transaction_digest
        require(base in {command.expected_state_digest, data.get("refund_base_digest")}, "REFUND_SOURCE_MISMATCH", "the refund must bind the current case or its retained pre-refund state")
        refs = list(data.get("refund_refs") or ())
        digests = list(data.get("refund_source_digests") or ())
        require(refund.ledger.refund_ref not in refs and refund.state_digest not in digests, "REFUND_ALREADY_RECORDED", "one cleared refund reverses revenue once", "do_not_replay")
        amount = refund.ledger.company_revenue_reversal
        require(amount > 0 and amount <= Decimal(str(data.get("settled_amount", "0"))), "REFUND_EXCEEDS_SETTLEMENT", "a revenue reversal cannot exceed remaining settled cash")
        for actual, expected in ((r.refund_amount, amount), (r.refund_ref, refund.ledger.refund_ref), (r.against_source_digest, base), (r.refund_source_digest, refund.state_digest)):
            require(actual is None or str(actual) == str(expected), "REFUND_SOURCE_MISMATCH", "refund projections must reproduce the cleared source")
        data.update(refund_base_digest=data.get("refund_base_digest") or base, refund_refs=[*refs, refund.ledger.refund_ref], refund_source_digests=[*digests, refund.state_digest],
            refunded_amount=str(Decimal(str(data.get("refunded_amount", "0"))) + amount), settled_amount=str(Decimal(str(data["settled_amount"])) - amount), outcome="open", cleared_at=None, close_ref=None)
    elif event == "clear_receivable":
        require(r.close_source is not None, "CLOSE_SOURCE_REQUIRED", "clearance requires the replayable close and its plan")
        require(r.close_ref is not None and r.close_state_digest is not None and r.reconciliation_ref is not None and r.period_end is not None, "CLEARANCE_MISSING", "a clearance names the close, its state digest, the receivables reconciliation, and the period end")
        require(parsed(r.period_end) >= parsed(str(data.get("settled_at"))), "CLOSE_BEFORE_SETTLEMENT", "the close must cover the settlement date", "manual_reconciliation")
        data.update({"close_ref": r.close_ref, "cleared_at": at, "days_deal_to_cash": _days(data.get("handed_off_at"), str(data.get("settled_at") or at)), "outcome": "cleared"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    return next_status, data


REVENUE_CHAIN_LIFECYCLE = LifecycleSpec(entity="revenue_case", schema_prefix=REVENUE_CHAIN_KIND, statuses=CHAIN_STATUSES, terminal=TERMINAL_CHAIN_STATUSES, events=CHAIN_EVENTS, table=_CHAIN_TABLE, opening_event="hand_off", reason_events=("cancel", "require_reconciliation"), apply=_apply_chain, ledger_model=ChainLedger, receipt_model=ChainReceipt, effect_boundary_model=ChainEffectBoundary, plan_model=RevenueChainPlan, max_transitions=MAX_CHAIN_TRANSITIONS)
RevenueCaseState = REVENUE_CHAIN_LIFECYCLE.State


def open_revenue_case(plan: RevenueChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return REVENUE_CHAIN_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_scope": detached(scope)})


def advance_revenue_case(plan: RevenueChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return REVENUE_CHAIN_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


class RevenueChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise RevenueChainError(code, message)


def hand_off_receipt(pipeline_plan: PipelineEngineLoopPlan | Mapping[str, Any], prospect_state: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The opening receipt from a handed-off prospect state; refuses prospects that were not handed off."""

    _, state = PROSPECT_LIFECYCLE.bind(pipeline_plan, prospect_state)
    _require(state.status == "handed_off" and state.ledger.deal_ref is not None, "PROSPECT_NOT_HANDED_OFF", f"prospect {state.scope.entity_ref} is {state.status}")
    return {"pipeline_source": {"state": state.to_dict(), "source_plan": detached(pipeline_plan)}, "prospect_ref": str(state.scope.entity_ref), "deal_ref": str(state.ledger.deal_ref), "deal_value": str(state.ledger.deal_value), "prospect_state_digest": state.state_digest, "evidence_refs": [f"prospect:{state.scope.entity_ref}", f"state:{state.state_digest[:24]}"]}


def deal_agreement_receipt(state: Any, *, source_plan: Any, agreement_state: Any, agreement_plan: Any, at: str | None = None) -> dict[str, Any]:
    """Bind executed priced scope to the actual platform-registered signed paper."""
    from lightbulb.deal_desk_engine import accepted_value_binding, DEAL_DESK_LIFECYCLE
    from lightbulb.obligation_paper import verify_agreement_in_force

    plan, deal = DEAL_DESK_LIFECYCLE.bind(source_plan, state)
    value = accepted_value_binding(deal, source_plan=plan)
    paper_raw = dict(detached(agreement_state))
    at = at or max(deal.transition_history[-1].command.occurred_at, paper_raw["transition_history"][-1]["command"]["occurred_at"])
    _require(parsed(deal.transition_history[-1].command.occurred_at) <= parsed(at), "DEAL_FROM_FUTURE", "the signed deal must already exist")
    paper = verify_agreement_in_force(agreement_state, source_plan=agreement_plan, company_ref=plan.company_ref, currency=plan.currency, at=at, contract_ref=deal.ledger.contract_ref, expected_scope=deal.scope)
    custody = next(item.command.receipt.custody_candidate for item in reversed(deal.transition_history) if item.command.event == "execute")
    _require(paper.ledger.signed_document_sha256 in {item["artifact_digest"] for item in custody["executed_documents"]}, "SIGNED_DIGEST_MISMATCH", "the registered paper must be one of this deal's executed documents")
    _require(paper.ledger.counterparty_ref == deal.ledger.customer_ref and paper.ledger.amount == deal.ledger.contract_value, "DEAL_SOURCE_MISMATCH", "the signed paper and priced deal must name the same customer and contract value")
    return {"deal_source": {"state": deal.to_dict(), "source_plan": plan.to_dict()},
        "agreement_source": {"state": paper.to_dict(), "plan": detached(agreement_plan)},
        "agreement_ref": paper.ledger.agreement_ref, "contract_ref": deal.ledger.contract_ref,
        "custody_candidate_digest": deal.ledger.custody_candidate_digest,
        "executed_at": paper.ledger.executed_at, "contract_value": value["contract_value"],
        "accepted_amount": value["accepted_amount"], "acceptance_ref": value["acceptance_ref"],
        "evidence_refs": [f"deal:{deal.state_digest[:24]}", f"paper:{paper.state_digest[:24]}"]}


def agreement_receipt(custody_candidate: Any, *, accepted_value: Any, review_packet: Any) -> dict[str, Any]:
    """Derive signed economics from full custody, review packet and independent acceptance."""
    from lightbulb.commercial_legal_handoff import ExecutedCommercialAgreementCustodyCandidate, LegalReviewPacket
    from lightbulb.contract_to_cash import AcceptedValueBinding
    custody = ExecutedCommercialAgreementCustodyCandidate.model_validate(detached(custody_candidate))
    packet = LegalReviewPacket.model_validate(detached(review_packet))
    _require(custody.packet_digest == packet.packet_digest and custody.scope == packet.scope, "CUSTODY_PACKET_MISMATCH", "the signed custody must bind this exact review packet")
    billing = packet.commercial_terms.billing
    value = detached(accepted_value)
    if "source_state" in value:
        from lightbulb.deal_desk_engine import verify_accepted_value_binding
        value = verify_accepted_value_binding(value, contract_ref=custody.contract_ref, currency=billing.currency, expected_scope=custody.scope.commercial)
        ledger = value["source_state"]["ledger"]
        _require(ledger["custody_candidate_digest"] == custody.custody_candidate_digest and ledger["customer_ref"] == custody.customer_ref and Decimal(value["contract_value"]) == billing.total, "ACCEPTANCE_CONTRACT_MISMATCH", "the replayed priced deal must be this signed contract and total")
        amount, ref = Decimal(value["accepted_amount"]), value["acceptance_ref"]
    else:
        accepted = AcceptedValueBinding.model_validate(value)
        for key in ("contract_ref", "order_ref", "customer_ref"):
            _require(getattr(custody, key) == getattr(accepted, key), "ACCEPTANCE_CONTRACT_MISMATCH", "accepted value must name the signed customer, contract and order")
        _require(accepted.currency == billing.currency, "ACCEPTANCE_CURRENCY_MISMATCH", "acceptance uses the signed contract currency")
        value = detached(accepted)
        amount, ref = accepted.accepted_amount, accepted.acceptance_ref
    _require(amount <= billing.total, "ACCEPTED_EXCEEDS_CONTRACT", "acceptance cannot exceed the signed contract")
    raw = detached(custody)
    return {"custody_source": {"custody_candidate": raw, "review_packet": detached(packet), "accepted_value": value},
        "agreement_ref": f"agreement:{custody.contract_ref}:{custody.agreement_version}", "contract_ref": custody.contract_ref,
        "custody_candidate_digest": custody.custody_candidate_digest, "executed_at": custody.executed_at,
        "contract_value": str(billing.total), "accepted_amount": str(amount), "acceptance_ref": ref,
        "evidence_refs": [f"custody:{custody.custody_candidate_digest[:24]}", f"acceptance:{ref}"]}


def invoice_receipt(write_receipt: Mapping[str, Any] | Any, issued_observation: Mapping[str, Any] | Any, *, admission: Any, invoice_ref: str, invoice_total: Any, continuation_ref: str | None = None) -> dict[str, Any]:
    """From the contract-to-cash invoice write receipt plus an APPLIED ``observe_invoice_issued`` observation."""

    from lightbulb.contract_to_cash import ContractToCashInvoiceAdmission, ContractToCashInvoiceWriteReceipt
    from lightbulb.invoice_issuance import QuickBooksInvoiceIssuedObservation
    admitted = ContractToCashInvoiceAdmission.model_validate(detached(admission))
    write = detached(ContractToCashInvoiceWriteReceipt.model_validate(detached(write_receipt)))
    observed = detached(QuickBooksInvoiceIssuedObservation.model_validate(detached(issued_observation)))
    _require(str(write.get("state")) == "awaiting_invoice_issued_observation", "INVOICE_WRITE_NOT_SETTLED", f"the write receipt is {write.get('state')}; an ambiguous write requires reconciliation, not an invoice")
    _require(observed.get("schema") == "lightbulb.quickbooks_invoice_issued_observation.v1", "ISSUANCE_OBSERVATION_SCHEMA_MISMATCH", "expected an invoice issued observation")
    _require(str(observed.get("disposition")) == "APPLIED", "INVOICE_NOT_ISSUED", f"issuance disposition is {observed.get('disposition')}")
    _require(str(observed.get("provider_correlation_sha256")) == str(write.get("provider_correlation_sha256")), "ISSUANCE_CORRELATION_MISMATCH", "the issuance observation does not carry the write's correlation")
    _require(observed["observed_effect_sha256"] == write["expected_effect_sha256"], "ISSUANCE_EFFECT_MISMATCH", "the provider must observe the exact admitted write effect")
    for key in ("admission_sha256", "agreement_ref", "agreement_custody_record_id", "agreement_custody_record_digest", "continuation_ref"):
        _require(str(write[key]) == str(getattr(admitted, key)), "INVOICE_ADMISSION_MISMATCH", "the write must consume this exact admitted invoice")
    _require(decimal_value(invoice_total, field_name="invoice_total") == admitted.invoice.total, "INVOICE_ADMISSION_MISMATCH", "invoice amount must derive from admitted line items")
    _require(continuation_ref in (None, admitted.continuation_ref), "INVOICE_ADMISSION_MISMATCH", "continuation must match the write")
    return {"invoice_source": {"write_receipt": write, "issued_observation": observed, "admission": detached(admitted), "invoice_ref": invoice_ref, "invoice_total": str(admitted.invoice.total)},
        "continuation_ref": admitted.continuation_ref, "correlation_sha256": str(write["provider_correlation_sha256"]), "invoice_ref": invoice_ref, "invoice_total": str(admitted.invoice.total), "invoice_evidence_sha256": str(observed["evidence_sha256"]), "write_journal_ref": str(write["write_journal_ref"]), "issued_at": str(observed["observed_at"]), "evidence_refs": [f"invoice:{invoice_ref}", f"write:{write['write_journal_ref']}", f"issuance:{str(observed['evidence_sha256'])[:24]}"]}


def ambiguous_write_reason(write_receipt: Mapping[str, Any] | Any) -> str | None:
    write = dict(detached(write_receipt))
    if str(write.get("state")) == "invoice_write_outcome_ambiguous":
        return f"invoice write outcome ambiguous (journal {write.get('write_journal_ref')}); observe the exact effect before any redispatch"
    return None


def payment_receipt(payment_observation: Mapping[str, Any] | Any) -> dict[str, Any]:
    observed = dict(detached(payment_observation))
    _require(observed.get("schema") == "lightbulb.quickbooks_invoice_payment_observation.v1", "PAYMENT_OBSERVATION_SCHEMA_MISMATCH", "expected an invoice payment observation")
    _require(str(observed.get("disposition")) == "APPLIED", "PAYMENT_NOT_APPLIED", f"payment disposition is {observed.get('disposition')}")
    _require(bool(observed.get("invoice_balance_zero")), "INVOICE_BALANCE_OPEN", "the invoice still carries a balance")
    from lightbulb.cash_collection import QuickBooksInvoicePaymentObservation
    validated = QuickBooksInvoicePaymentObservation.model_validate(observed)
    observed = validated.to_dict()
    return {"payment_source": {"observation": observed}, "correlation_sha256": str(observed["provider_correlation_sha256"]), "payment_evidence_sha256": str(observed["evidence_sha256"]), "applied_amount": str(decimal_value(observed.get("applied_amount"), field_name="applied_amount")), "payment_count": int(observed.get("payment_count", 1)), "applied_at": str(observed["observed_at"]), "evidence_refs": [f"payment:{str(observed['evidence_sha256'])[:24]}"]}


def settlement_receipt(settlement_observation: Mapping[str, Any] | Any, *, currency: str) -> dict[str, Any]:
    observed = dict(detached(settlement_observation))
    _require(observed.get("schema") == "lightbulb.stripe_cash_settlement_observation.v1", "SETTLEMENT_OBSERVATION_SCHEMA_MISMATCH", "expected a cash settlement observation")
    _require(str(observed.get("disposition")) == "SETTLED", "CASH_NOT_SETTLED", f"settlement disposition is {observed.get('disposition')}")
    _require(str(observed.get("currency", "")).upper() == currency.upper(), "SETTLEMENT_CURRENCY_MISMATCH", f"settlement currency differs from {currency}")
    _require(bool(observed.get("reversal_window_observed")), "REVERSAL_WINDOW_NOT_OBSERVED", "the reversal window has not elapsed")
    from lightbulb.cash_collection import StripeCashSettlementObservation
    validated = StripeCashSettlementObservation.model_validate(observed)
    observed = validated.to_dict()
    if validated.query_sha256 is None:
        _require(parsed(observed["charge_created_at"]) <= parsed(observed["payout_arrival_at"]), "REVERSAL_WINDOW_NOT_OBSERVED", "the observed charge must precede payout")
    _require(_days(observed["payout_arrival_at"], observed["observed_at"]) >= observed["reversal_window_days"], "REVERSAL_WINDOW_NOT_OBSERVED", "the complete reversal window must actually elapse after payout")
    amount = (Decimal(int(observed["amount_minor"])) / _HUNDRED).quantize(MONEY_QUANTUM)
    return {"settlement_source": {"observation": observed}, "correlation_sha256": str(observed["invoice_correlation_sha256"]), "settlement_evidence_sha256": str(observed["evidence_sha256"]), "settled_amount": str(amount), "reversal_window_days": int(observed["reversal_window_days"]), "payout_arrival_at": str(observed["payout_arrival_at"]), "evidence_refs": [f"settlement:{str(observed['evidence_sha256'])[:24]}"]}


def clearance_receipt(close_state: Any, *, source_plan: Any, reconciliation_ref: str | None = None) -> dict[str, Any]:
    """From a closed finance period whose receivables reconciliation is retained."""

    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, verify_books
    close_plan, close_state = CLOSE_LIFECYCLE.bind(source_plan, close_state)
    _require(verify_books(close_plan, close_state).verified, "CLOSE_NOT_CLOSED", "the original close must replay to verified books")
    ledger = close_state.ledger
    reconciled = list(getattr(ledger, "reconciled_accounts", ()) or ())
    _require("accounts_receivable" in reconciled, "RECEIVABLES_NOT_RECONCILED", "the close did not reconcile accounts receivable")
    ref = next((str(item.command.receipt.reconciliation_ref) for item in reversed(close_state.transition_history) if item.command.event == "reconcile_account" and item.command.receipt.account_kind == "accounts_receivable"), None)
    _require(ref is not None and reconciliation_ref in (None, ref), "RECEIVABLES_NOT_RECONCILED", "the receipt must name the actual receivables reconciliation")
    return {"close_source": {"state": close_state.to_dict(), "source_plan": close_plan.to_dict()}, "close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "reconciliation_ref": ref, "period_end": str(ledger.period_end), "evidence_refs": [f"close:{close_state.scope.entity_ref}", f"state:{close_state.state_digest[:24]}"]}


def wip_invoice_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """Carry one observed WIP invoice through hand-off, agreement and invoice hops."""
    from lightbulb.wip_billing import billing_source, verify_wip
    wip = verify_wip(state, source_plan=source_plan)
    source = billing_source(wip, source_plan=source_plan)
    engagement = wip.ledger.engagement_state["ledger"]
    paper = engagement["agreement_state"]
    facts = paper["ledger"]
    issuance = next(item.command.receipt for item in reversed(wip.transition_history) if item.command.event == "issue_invoice")
    execution = detached(issuance.invoice_execution)
    return {"wip_source": source, "prospect_ref": f"work:{wip.scope.entity_ref}", "deal_ref": wip.ledger.contract_ref,
        "deal_value": str(wip.ledger.recognized_revenue), "prospect_state_digest": wip.state_digest,
        "agreement_ref": wip.ledger.agreement_ref, "contract_ref": wip.ledger.contract_ref,
        "custody_candidate_digest": paper["state_digest"], "executed_at": facts["executed_at"],
        "contract_value": str(engagement["contract_value"]), "accepted_amount": str(wip.ledger.recognized_revenue),
        "agreement_source": {"state": paper, "plan": engagement["agreement_plan"]},
        "invoice_ref": wip.ledger.invoice_ref, "invoice_total": str(wip.ledger.invoice_total),
        "invoice_evidence_sha256": wip.ledger.invoice_source_digest, "correlation_sha256": wip.ledger.correlation_sha256,
        "write_journal_ref": execution["journal_ref"], "issued_at": wip.ledger.issued_at,
        "evidence_refs": [f"wip:{wip.state_digest[:24]}"]}


def collections_payment_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The recovered collections history proves a late payment on the same invoice."""
    from lightbulb.collections_chain import COLLECTIONS_LIFECYCLE
    plan, case = COLLECTIONS_LIFECYCLE.bind(source_plan, state)
    _require(case.status == "recovered" and case.ledger.balance == 0, "COLLECTIONS_NOT_RECOVERED", "the complete invoice must have recovered")
    payment = next(item.command.receipt for item in reversed(case.transition_history) if item.command.event == "apply_payment")
    fields = ("correlation_sha256", "payment_evidence_sha256", "applied_amount", "payment_count", "applied_at")
    return {**{key: detached(getattr(payment, key)) for key in fields}, "collections_source": {"state": case.to_dict(), "source_plan": plan.to_dict()}, "evidence_refs": [f"collections:{case.state_digest[:24]}"]}


def reversal_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.refund_and_dispute_chain import revenue_reversal_receipt
    return revenue_reversal_receipt(state, source_plan=source_plan)


def period_evidence_receipt(case_state: Any, *, engine: str = "pipeline_engine", evidence_ref: str | None = None, source_plan: Any = None) -> dict[str, Any]:
    """The company operating system's ``record_evidence`` receipt: settled cash as pipeline revenue, with the chain as evidence."""

    from lightbulb.company_operating_system import ENGINE_KINDS
    _require(source_plan is not None, "SOURCE_PLAN_REQUIRED", "period evidence must replay the case under its retained source plan")
    _, case_state = REVENUE_CHAIN_LIFECYCLE.bind(source_plan, case_state)
    _require(engine in ENGINE_KINDS, "ENGINE_NOT_BOUND", "name the operating engine that earned the cash")
    _require(case_state.status in ("cash_settled", "receivable_cleared"), "CASE_NOT_SETTLED", f"the case is {case_state.status}; only settled cash becomes period revenue")
    ledger = case_state.ledger
    return {"engine": engine, "evidence_ref": evidence_ref or f"revenue_case:{case_state.scope.entity_ref}:{case_state.state_digest[:16]}", "source_digest": case_state.state_digest, "source_kind": "revenue_case", "revenue_only": True, "spend": "0", "revenue": str(ledger.settled_amount), "signals": []}


def chain_summary(case_state: Any) -> dict[str, Any]:
    ledger = case_state.ledger
    return {"case_ref": str(case_state.scope.entity_ref), "status": case_state.status, "deal_value": str(ledger.deal_value), "accepted_amount": str(ledger.accepted_amount), "invoice_total": str(ledger.invoice_total), "settled_amount": str(ledger.settled_amount), "days_deal_to_cash": ledger.days_deal_to_cash, "outcome": ledger.outcome, "state_digest": case_state.state_digest}


REVENUE_CHAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": REVENUE_CHAIN_KIND,
    "golden_loop": REVENUE_CHAIN_GOLDEN_LOOP,
    "stages": ["hand_off", "execute_agreement", "issue_invoice", "apply_payment", "settle_cash", "clear_receivable"],
    "statuses": list(CHAIN_STATUSES),
    "events": list(CHAIN_EVENTS),
    "hops": {"hand_off": "pipeline_engine handed_off state", "execute_agreement": "commercial.reconcile_executed_agreement custody candidate (+ accepted value binding)", "issue_invoice": "contract_to_cash invoice write receipt + finance.observe_invoice_issued APPLIED", "apply_payment": "finance.observe_invoice_payment_applied APPLIED with zero balance", "settle_cash": "finance.observe_cash_settlement SETTLED after the reversal window", "clear_receivable": "finance_close closed with accounts_receivable reconciled"},
    "required_connectors": ["quickbooks", "xero", "stripe", "docusign", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "every hop consumes the sealed artifact of the pack that produced it; nothing is asserted by the caller",
        "the invoice must equal the accepted value inside the plan's tolerance, the payment must settle the invoice in full, and the settlement must match the payment inside an observed reversal window",
        "an ambiguous invoice write moves the case to reconciliation_required; it is never redispatched from here",
        "period revenue for the pipeline engine is the settled cash of cleared cases, not the deal value",
    ],
}

__all__ = ["CHAIN_EVENTS", "CHAIN_STATUSES", "REVENUE_CHAIN_GOLDEN_LOOP", "REVENUE_CHAIN_KIND", "REVENUE_CHAIN_LIFECYCLE", "REVENUE_CHAIN_MANIFEST", "RevenueCaseState", "RevenueChainError", "RevenueChainPlan", "advance_revenue_case", "agreement_receipt", "ambiguous_write_reason", "chain_summary", "clearance_receipt", "compile_revenue_chain", "hand_off_receipt", "invoice_receipt", "open_revenue_case", "payment_receipt", "period_evidence_receipt", "settlement_receipt"]
__all__ += ["deal_agreement_receipt", "wip_invoice_receipt", "collections_payment_receipt", "reversal_receipt"]
