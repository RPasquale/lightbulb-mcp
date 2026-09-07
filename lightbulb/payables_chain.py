"""The payables chain: one replay-fenced lifecycle from a received supplier bill to the payable cleared in the books.

The revenue chain proves cash in; this proves cash out.  Every hop consumes
the sealed artifact of the pack that produced it and nothing is asserted by
the caller:

    bill_received -> approved -> scheduled -> paid -> cleared        (terminal)
    any non-terminal -> rejected | reconciliation_required           (terminal)

* ``bill_receipt`` opens the case from a supplier invoice intake (the
  procure-to-pay ``SupplierInvoice`` or the ``finance.ingest_supplier_invoice``
  output); duplicates and exceptions are refused before the case exists.
* ``approval_receipt`` consumes the platform's approved task: the approved
  amount must equal the bill and the approver must not be the requester.
* ``schedule_receipt`` consumes a treasury ``CashCover``: the payment is
  scheduled only when the worst subsequent week still clears the floor, and
  the bill write receipt binds the provider correlation (``LB-AP-``).
* ``payment_receipt`` consumes an APPLIED ``observe_bill_payment_applied``
  observation on the same correlation with a zero bill balance.
* ``clearance_receipt`` consumes a closed finance period that reconciled
  accounts payable and covers the payment date.

``period_evidence_receipt`` turns a paid case into the operating period's
``record_evidence`` receipt as spend for the engine the bill belongs to, so
the cost the period records is the cash the chain proved left.  Nothing here
writes to a provider or the ledger.
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
    CurrencyCode,
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
    stable_digest,
    timestamp,
)

PAYABLES_CHAIN_KIND = "payables_chain"
PAYABLES_CHAIN_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
PAYABLES_CHAIN_PLAN_SCHEMA = "lightbulb.payables_chain_plan.v1"
BILL_PAYMENT_OBSERVATION_SCHEMA = "lightbulb.quickbooks_bill_payment_observation.v1"
MAX_CHAIN_TRANSITIONS = 16

PAYABLE_STATUSES: tuple[str, ...] = ("bill_received", "approved", "scheduled", "paid", "cleared", "rejected", "reconciliation_required")
TERMINAL_PAYABLE_STATUSES: frozenset[str] = frozenset({"cleared", "rejected", "reconciliation_required"})
PAYABLE_EVENTS: tuple[str, ...] = ("receive_bill", "approve", "schedule_payment", "apply_payment", "clear_payable", "reject", "require_reconciliation")
_PAYABLE_TABLE: dict[tuple[str, str], str] = {
    ("new", "receive_bill"): "bill_received",
    ("bill_received", "approve"): "approved",
    ("approved", "schedule_payment"): "scheduled",
    ("scheduled", "apply_payment"): "paid",
    ("paid", "clear_payable"): "cleared",
    **{(status, "reject"): "rejected" for status in ("bill_received", "approved", "scheduled")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("approved", "scheduled", "paid")},
}
from lightbulb.company_operating_system import ENGINE_KINDS as _ENGINES


class PayablesChainPlan(StrictModel):
    """What the chain enforces: currency, when approval is needed, whether cash cover is required, and how long each hop may take."""

    schema_id: Literal["lightbulb.payables_chain_plan.v1"] = Field(default=PAYABLES_CHAIN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    approval_threshold: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    require_cash_cover: bool = True
    require_vendor_paper: bool = False
    cost_centre_map: dict[str, Any] | None = None
    max_days_receipt_to_approval: int = Field(default=14, ge=1, le=365)
    max_days_approval_to_payment: int = Field(default=45, ge=1, le=365)
    max_days_past_due: int = Field(default=0, ge=0, le=90)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("approval_threshold", mode="before")
    @classmethod
    def _threshold(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="approval_threshold")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PayablesChainPlan:
        if self.cost_centre_map is not None:
            from lightbulb.company_cost_centres import CostCentreMap
            centres = CostCentreMap.model_validate(self.cost_centre_map)
            if centres.company_ref != self.company_ref or centres.currency != self.currency:
                raise ValueError("COST_MAP_SCOPE_MISMATCH: the cost map must belong to this company and currency")
        if not skip_digests(info) and self.plan_digest != sealed_digest(PayablesChainPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_payables_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PayablesChainPlan:
    return seal(PayablesChainPlan, {"company_ref": company_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class PayableReceipt(StrictModel):
    intake_source: dict[str, Any] | None = None
    source_provenance: dict[str, Any] | None = None
    cover_source: dict[str, Any] | None = None
    forecast_source: dict[str, Any] | None = None
    bill_write_source: dict[str, Any] | None = None
    payment_source: dict[str, Any] | None = None
    commitment_source: dict[str, Any] | None = None
    close_source: dict[str, Any] | None = None
    period_start: str | None = None
    entity_scope: EngineScope | None = None
    vendor_paper_source: dict[str, Any] | None = None
    entity_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    supplier_ref: OpaqueRef | None = None
    bill_ref: OpaqueRef | None = None
    invoice_number: ShortText | None = None
    amount: Decimal | None = None
    currency: ShortText | None = None
    due_at: str | None = None
    engine: ShortText | None = None
    intake_digest: Sha256Digest | None = None
    approval_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    approver_ref: OpaqueRef | None = None
    requester_ref: OpaqueRef | None = None
    approved_at: str | None = None
    approved_amount: Decimal | None = None
    cover_digest: Sha256Digest | None = None
    forecast_digest: Sha256Digest | None = None
    pay_at: str | None = None
    correlation_sha256: Sha256Digest | None = None
    write_journal_ref: OpaqueRef | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    disbursement_source: dict[str, Any] | None = None
    applied_amount: Decimal | None = None
    payment_count: int | None = Field(default=None, ge=1, le=1000)
    applied_at: str | None = None
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    reconciliation_ref: OpaqueRef | None = None
    period_end: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("amount", "approved_amount", "applied_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("due_at", "approved_at", "pay_at", "applied_at", "period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class PayableLedger(StrictModel):
    entity_scope: dict[str, Any] | None = None
    vendor_paper_digest: Sha256Digest | None = None
    entity_ref: OpaqueRef | None = None
    requester_ref: OpaqueRef | None = None
    authorization_proof_digest: Sha256Digest | None = None
    supplier_ref: str | None = None
    bill_ref: str | None = None
    invoice_number: str | None = None
    amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    due_at: str | None = None
    engine: str | None = None
    received_at: str | None = None
    intake_digest: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    approved_at: str | None = None
    cover_digest: str | None = None
    pay_at: str | None = None
    correlation_sha256: str | None = None
    applied_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_at: str | None = None
    close_ref: str | None = None
    cleared_at: str | None = None
    days_receipt_to_cash: int | None = None
    paid_days_past_due: int | None = None
    reject_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "cleared", "rejected", "reconciliation_required"] = "open"

    @field_validator("amount", "applied_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class PayableEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    bill_created: Literal[False] = False
    payment_sent: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _days(start: str | None, end: str) -> int:
    if not start:
        return 0
    return (parsed(end) - parsed(start)).days


def _apply_payable(plan: PayablesChainPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "receive_bill":
        if r.entity_scope is not None:
            require(command.expected_state_digest == PAYABLES_CHAIN_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the paper scope must be this payable's actual scope")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.supplier_ref is not None and r.bill_ref is not None and r.amount is not None and r.currency is not None and r.due_at is not None and r.intake_digest is not None, "BILL_MISSING", "a received bill names the supplier, the bill, its amount, currency, due date, and the intake digest")
        require(r.amount > 0, "BILL_AMOUNT_INVALID", "the bill amount is positive")
        require(r.currency.upper() == plan.currency, "BILL_CURRENCY_MISMATCH", f"the bill is in {r.currency}; the chain runs in {plan.currency}")
        require(r.engine is None or r.engine in _ENGINES, "BILL_ENGINE_UNKNOWN", f"{r.engine} is not an operating engine")
        if r.engine is not None and plan.cost_centre_map is not None:
            require(any(item.get("engine") == r.engine for item in plan.cost_centre_map["centres"]), "ENGINE_NOT_BOUND", "attribute the payable to an engine in this company's sealed cost map")
        data.update({"entity_ref": r.entity_ref, "requester_ref": command.actor_ref, "supplier_ref": r.supplier_ref, "bill_ref": r.bill_ref, "invoice_number": r.invoice_number, "amount": str(r.amount), "due_at": r.due_at, "engine": r.engine, "received_at": at, "intake_digest": r.intake_digest, "correlation_sha256": r.correlation_sha256})
    elif event == "approve":
        from lightbulb.authority_matrix import require_authorization_proof

        if plan.require_vendor_paper or r.vendor_paper_source is not None:
            from lightbulb.obligation_paper import verify_agreement_in_force
            require(r.vendor_paper_source is not None, "VENDOR_PAPER_MISSING", "the vendor policy requires a current replayable agreement")
            source = r.vendor_paper_source
            require(data.get("entity_scope") is not None, "VENDOR_PAPER_MISSING", "the protected bill requires its retained company scope")
            try:
                paper = verify_agreement_in_force(source.get("state"), source_plan=source.get("plan"), company_ref=plan.company_ref, currency=plan.currency, at=at, expected_scope=data.get("entity_scope"))
            except ValueError:
                require(False, "VENDOR_PAPER_MISSING", "the supplier agreement must be in force in this company scope")
            require(paper.ledger.counterparty_ref == data.get("supplier_ref") and paper.ledger.amount >= Decimal(str(data.get("amount", "0"))), "VENDOR_PAPER_MISSING", "the current paper must cover this supplier and bill amount")
            data["vendor_paper_digest"] = paper.state_digest

        require(r.approved_amount is None or r.approved_amount == Decimal(str(data.get("amount", "0"))), "APPROVED_AMOUNT_MISMATCH", "approval metadata differs from the bill amount", "manual_reconciliation")
        proof = require_authorization_proof(r.authorization_proof, category="payable", amount=Decimal(str(data.get("amount", "0"))), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data.get("entity_ref"))
        require(proof.approver_ref != data.get("requester_ref"), "SELF_APPROVAL", "the requester cannot approve their own bill", "manual_reconciliation")
        require(r.approved_amount is None or r.approved_amount == proof.amount, "APPROVED_AMOUNT_MISMATCH", "approval metadata differs from the verified proof", "manual_reconciliation")
        require(_days(data.get("received_at"), at) <= plan.max_days_receipt_to_approval, "APPROVAL_TOO_LATE", f"approval came more than {plan.max_days_receipt_to_approval} days after receipt", "manual_reconciliation")
        data.update({"approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref, "approved_at": proof.decided_at, "authorization_proof_digest": proof.proof_digest})
    elif event == "schedule_payment":
        require(r.pay_at is not None, "SCHEDULE_MISSING", "a schedule names the payment date")
        if plan.require_cash_cover:
            require(r.cover_digest is not None and r.forecast_digest is not None, "CASH_COVER_MISSING", "the plan requires a treasury cash cover before a payment is scheduled")
        correlation = r.correlation_sha256 or data.get("correlation_sha256")
        require(correlation is not None, "BILL_CORRELATION_MISSING", "the provider bill must carry a payables correlation before payment is scheduled", "manual_reconciliation")
        allowed_until = parsed(str(data["due_at"])).timestamp() + plan.max_days_past_due * 86400
        require(parsed(r.pay_at).timestamp() <= allowed_until, "PAYMENT_PAST_DUE", f"pay_at {r.pay_at} is later than the due date plus {plan.max_days_past_due} day(s)", "manual_reconciliation")
        require(_days(data.get("approved_at"), r.pay_at) <= plan.max_days_approval_to_payment, "SCHEDULE_TOO_LATE", f"the payment is scheduled more than {plan.max_days_approval_to_payment} days after approval", "manual_reconciliation")
        data.update({"cover_digest": r.cover_digest, "pay_at": r.pay_at, "correlation_sha256": correlation})
    elif event == "apply_payment":
        if r.disbursement_source is not None:
            from lightbulb.disbursement_run import DISBURSEMENT_LIFECYCLE, payable_payment_receipts

            source = r.disbursement_source
            run = DISBURSEMENT_LIFECYCLE.bind(source["plan"], source["state"])[1]
            expected = payable_payment_receipts(run, plan=source["plan"]).get(str(data.get("entity_ref")))
            require(expected is not None, "PAYMENT_CORRELATION_MISMATCH", "the settled batch must contain this exact payable", "manual_reconciliation")
            require(all(detached(r).get(key) == expected[key] for key in ("payment_evidence_sha256", "correlation_sha256", "applied_amount", "payment_count", "applied_at")), "PAYMENT_CORRELATION_MISMATCH", "payment fields must equal the replayed batch allocation", "manual_reconciliation")
            require(source["plan"]["company_ref"] == plan.company_ref and source["plan"]["currency"] == plan.currency, "PAYMENT_CORRELATION_MISMATCH", "the batch must belong to the same company and currency", "manual_reconciliation")
        require(r.payment_evidence_sha256 is not None and r.applied_amount is not None and r.payment_count is not None and r.applied_at is not None and r.correlation_sha256 is not None, "PAYMENT_MISSING", "an applied payment carries the evidence digest, the applied amount, the payment count, the time, and the correlation")
        require(r.correlation_sha256 == data.get("correlation_sha256"), "PAYMENT_CORRELATION_MISMATCH", "the payment observation must carry the bill's correlation", "manual_reconciliation")
        require(r.applied_amount == Decimal(str(data.get("amount", "0"))), "PAYMENT_NOT_FULL", f"applied {r.applied_amount} does not settle the bill {data.get('amount')}", "manual_reconciliation")
        past_due = max(0, _days(data.get("due_at"), r.applied_at))
        data.update({"applied_amount": str(r.applied_amount), "paid_at": r.applied_at, "paid_days_past_due": past_due, "days_receipt_to_cash": _days(data.get("received_at"), r.applied_at)})
    elif event == "clear_payable":
        require(r.close_ref is not None and r.close_state_digest is not None and r.reconciliation_ref is not None and r.period_end is not None, "CLEARANCE_MISSING", "a clearance names the close, its state digest, the reconciliation, and the period end")
        require(parsed(r.period_end) >= parsed(str(data.get("paid_at"))), "CLOSE_BEFORE_PAYMENT", "the close must cover the payment date", "manual_reconciliation")
        data.update({"close_ref": r.close_ref, "cleared_at": at, "outcome": "cleared"})
    elif event == "reject":
        data.update({"reject_reason": str(command.reason)[:300], "outcome": "rejected"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    try:
        _verify_sources(plan, data, command)
    except (ValueError, TypeError, KeyError) as error:
        require(False, getattr(error, "code", "SOURCE_NOT_SEALED"), str(error))
    return next_status, data


class _PayablesLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope), "entity_ref": detached(scope)["entity_ref"]}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope.to_dict() != self.ledger.entity_scope:
                    raise ValueError("SCOPE_MISMATCH: payable state must equal its replayed opening scope")
                return self
        self.State = ScopedState


PAYABLES_CHAIN_LIFECYCLE = _PayablesLifecycle(entity="payable_case", schema_prefix=PAYABLES_CHAIN_KIND, statuses=PAYABLE_STATUSES, terminal=TERMINAL_PAYABLE_STATUSES, events=PAYABLE_EVENTS, table=_PAYABLE_TABLE, opening_event="receive_bill", reason_events=("reject", "require_reconciliation"), apply=_apply_payable, ledger_model=PayableLedger, receipt_model=PayableReceipt, effect_boundary_model=PayableEffectBoundary, plan_model=PayablesChainPlan, max_transitions=MAX_CHAIN_TRANSITIONS)
PayableCaseState = PAYABLES_CHAIN_LIFECYCLE.State


def open_payable_case(plan: PayablesChainPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return PAYABLES_CHAIN_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_ref": dict(detached(scope))["entity_ref"], "entity_scope": detached(scope)})


def advance_payable_case(plan: PayablesChainPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PAYABLES_CHAIN_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


class PayablesChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PayablesChainError(code, message)


class BillPaymentObservation(StrictModel):
    """The exact digest-only output of Spring's bill-payment observer."""

    schema_id: Literal["lightbulb.quickbooks_bill_payment_observation.v1"] = Field(alias="schema")
    disposition: Literal["APPLIED"]
    provider_correlation_sha256: Sha256Digest
    match_count: Literal[1]
    unique_match: Literal[True]
    exhaustive_read: Literal[True]
    currency: CurrencyCode
    bill_total: Decimal = Field(gt=0)
    applied_amount: Decimal = Field(gt=0)
    payment_count: int = Field(ge=1, le=10)
    bill_balance_zero: Literal[True]
    query_sha256: Sha256Digest
    observed_effect_sha256: Sha256Digest
    evidence_sha256: Sha256Digest
    observed_at: str

    @field_validator("bill_total", "applied_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="before")
    @classmethod
    def _canonical_evidence(cls, value: Any) -> Any:
        raw = dict(detached(value))
        _require(raw.get("evidence_sha256") == stable_digest({key: item for key, item in raw.items() if key not in ("evidence_sha256", "observed_at")}), "PAYMENT_OBSERVATION_DIGEST_MISMATCH", "the observer evidence digest must commit every original output field")
        return value

    @field_validator("observed_at")
    @classmethod
    def _stamp(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")

    @model_validator(mode="after")
    def _complete(self) -> Any:
        _require(self.applied_amount >= self.bill_total, "PAYMENT_NOT_FULL", "an applied observation must settle the bill total")
        return self


def _source_read(provenance: Any, payload: Any, tools: tuple[str, ...]) -> Any:
    from lightbulb.company_execution_bridge import ObservationProvenance
    _require(provenance is not None, "SOURCE_NOT_SEALED", "retain the actual source provenance with its original payload")
    read = ObservationProvenance.model_validate(detached(provenance))
    _require(read.schema_id == "lightbulb.engine_observation_provenance.v1" and read.provenance_digest != GENESIS_DIGEST and read.source_tool in tools, "SOURCE_TOOL_MISMATCH", "the receipt must retain the admitted source tool's read provenance")
    _require(read.output_digest == stable_digest(detached(payload)), "SOURCE_DIGEST_MISMATCH", "the retained payload must equal the original source output")
    return read


def _same_scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(key) == b.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _verify_sources(plan: Any, data: dict[str, Any], command: Any) -> None:
    r, event, at = command.receipt, command.event, command.occurred_at
    expected = None
    if event == "receive_bill":
        _require(r.entity_scope is not None and r.entity_scope.currency == plan.currency and r.entity_ref == r.entity_scope.entity_ref, "SCOPE_MISMATCH", "the received bill must bind its actual execution scope")
        if r.commitment_source is not None:
            from lightbulb.spend_control_chain import COMMITMENT_LIFECYCLE, renewal_bill_receipt
            source = r.commitment_source
            source_plan, commitment = COMMITMENT_LIFECYCLE.bind(source.get("source_plan"), source.get("state"))
            _require(source_plan.company_ref == plan.company_ref and _same_scope(commitment.scope, r.entity_scope), "SCOPE_MISMATCH", "the renewed commitment must belong to the payable's logical company and exact execution scope")
            _require(parsed(commitment.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the completed renewal must predate its payable")
            expected = renewal_bill_receipt(commitment, source_plan=source_plan)
            _require(r.intake_source == expected["intake_source"] and r.source_provenance == expected["source_provenance"], "SOURCE_PROJECTION_MISMATCH", "the intake and provenance must be the original vendor-bill page retained by the renewal")
        else:
            _require(r.intake_source is not None, "SOURCE_NOT_SEALED", "retain the actual supplier invoice intake")
            expected = bill_receipt(r.intake_source, provenance=r.source_provenance, engine=r.engine, correlation_sha256=r.correlation_sha256, due_at=r.due_at)
    elif event == "schedule_payment":
        _require(parsed(r.pay_at) >= parsed(at), "SCHEDULE_IN_PAST", "a payment cannot be scheduled in the past")
        if plan.require_cash_cover or r.cover_source is not None:
            _require(r.cover_source is not None, "SOURCE_NOT_SEALED", "retain the actual cover and forecast")
            expected = schedule_receipt(r.cover_source, forecast=r.forecast_source, pay_at=r.pay_at, amount=data["amount"], bill_write=r.bill_write_source)
            _require(r.forecast_source["currency"] == plan.currency, "SCOPE_MISMATCH", "the cash forecast must use the bill currency")
            _require(parsed(r.forecast_source["as_of"]) <= parsed(at), "SOURCE_FROM_FUTURE", "a scheduling decision cannot use a future forecast")
    elif event == "apply_payment":
        _require(parsed(data["pay_at"]) <= parsed(r.applied_at) <= parsed(at), "SOURCE_FROM_FUTURE", "payment must occur after its schedule and before consumption")
        if r.disbursement_source is not None:
            from lightbulb.disbursement_run import DISBURSEMENT_LIFECYCLE
            run = DISBURSEMENT_LIFECYCLE.bind(r.disbursement_source["plan"], r.disbursement_source["state"])[1]
            _require(_same_scope(run.scope, data["entity_scope"]), "SCOPE_MISMATCH", "the settled batch must belong to this tenant, company, project and currency")
            _require(parsed(run.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the retained batch cannot postdate payment consumption")
        else:
            _require(r.payment_source is not None, "SOURCE_NOT_SEALED", "retain the complete bill-payment observation and provenance")
            expected = payment_receipt(r.payment_source, provenance=r.source_provenance)
            _require(r.payment_source["currency"] == plan.currency, "SCOPE_MISMATCH", "the bill payment must use the bill currency")
            _require(decimal_value(r.payment_source["bill_total"], field_name="bill_total") == decimal_value(data["amount"], field_name="amount"), "PAYMENT_NOT_FULL", "the provider must observe this bill total")
    elif event == "clear_payable":
        _require(r.close_source is not None, "SOURCE_NOT_SEALED", "retain the closed finance period and source plan")
        expected = clearance_receipt(r.close_source["state"], source_plan=r.close_source["plan"], reconciliation_ref=r.reconciliation_ref)
        _require(_same_scope(r.close_source["state"]["scope"], data["entity_scope"]), "SCOPE_MISMATCH", "the finance close must belong to this tenant, company, project and currency")
        _require(parsed(expected["period_start"]) <= parsed(data["paid_at"]), "CLOSE_BEFORE_PAYMENT", "the closed period must contain the actual payment")
        _require(parsed(r.close_source["state"]["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "SOURCE_FROM_FUTURE", "the close cannot postdate its consumption")
    if r.source_provenance is not None:
        _require(parsed(r.source_provenance["completed_at"]) <= parsed(at), "SOURCE_FROM_FUTURE", "the source read cannot postdate its consumption")
    if expected is not None:
        actual = detached(r)
        ignored = {"evidence_refs", "intake_source", "source_provenance", "cover_source", "forecast_source", "bill_write_source", "payment_source", "close_source"}
        _require(all(actual.get(key) == value for key, value in expected.items() if key not in ignored), "SOURCE_PROJECTION_MISMATCH", "every receipt field must be rederived from its retained original source")


def verify_paid_payable(case_state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, case_state)
    _require(state.status in ("paid", "cleared"), "CASE_NOT_PAID", "only a replayed paid or cleared payable proves cash spend")
    _require((company_ref is None or plan.company_ref == company_ref) and (currency is None or plan.currency == currency) and (expected_scope is None or _same_scope(state.scope, expected_scope)), "SCOPE_MISMATCH", "the payable source belongs to another company, tenant, project or currency")
    _require(at is None or parsed(state.transition_history[-1].command.occurred_at) <= parsed(at), "SOURCE_FROM_FUTURE", "the payable cannot postdate its consumer")
    return state


def bill_receipt(intake: Mapping[str, Any] | Any, *, provenance: Any = None, engine: str | None = None, correlation_sha256: str | None = None, due_at: str | None = None) -> dict[str, Any]:
    """The opening receipt from a supplier invoice intake; duplicates, exceptions, and unextracted intakes are refused."""

    raw = dict(detached(intake))
    if "supplier_invoice_ref" in raw:  # procure-to-pay SupplierInvoice
        _require(str(raw.get("duplicate_check")) == "clear", "BILL_DUPLICATE", f"duplicate check is {raw.get('duplicate_check')}")
        from lightbulb.procure_to_pay_lifecycle import SupplierInvoice
        SupplierInvoice.model_validate({key: value for key, value in raw.items() if key != "due_date"})
        supplier, bill_ref, number = str(raw["vendor_ref"]), str(raw["supplier_invoice_ref"]), str(raw.get("invoice_number") or raw["supplier_invoice_ref"])
        total, currency = raw.get("total"), str(raw.get("currency", ""))
        due = due_at or raw.get("due_date")
    else:  # finance.ingest_supplier_invoice output
        _require(not bool(raw.get("duplicate")), "BILL_DUPLICATE", "the intake flagged a duplicate")
        _require(not list(raw.get("exceptions") or []), "BILL_HAS_EXCEPTIONS", f"the intake carries exceptions: {list(raw.get('exceptions') or [])[:3]}")
        _require(str(raw.get("state")) in ("extracted", "preview", "pending_approval", "bill_created"), "BILL_INTAKE_STATE", f"intake state {raw.get('state')} is not a received bill")
        from lightbulb.domain_primitives import SupplierInvoiceOutput
        SupplierInvoiceOutput.model_validate(raw)
        vendor_name, number = str(raw.get("vendor") or ""), str(raw.get("invoice_number") or "")
        supplier = str(raw.get("vendor_ref") or (f"vendor:{stable_digest(vendor_name)[:16]}" if vendor_name else ""))
        bill_ref = str(raw.get("bill_ref") or f"intake:{supplier}:{number}")
        total, currency = raw.get("total"), str(raw.get("currency", ""))
        due = raw.get("due_date")
    _require(bool(supplier) and bool(number), "BILL_INCOMPLETE", "the intake names the supplier and the invoice number")
    _require(total is not None, "BILL_TOTAL_MISSING", "the intake carries a total")
    _require(bool(due), "BILL_DUE_MISSING", "the intake carries a due date")
    stamp = timestamp(str(due) if "T" in str(due) else f"{due}T00:00:00Z", field_name="due_at")
    invoice_at = timestamp(str(raw["invoice_date"]) if "T" in str(raw["invoice_date"]) else f"{raw['invoice_date']}T00:00:00Z", field_name="invoice_date")
    _require(parsed(stamp) >= parsed(invoice_at), "BILL_DUE_MISSING", "the invoice cannot fall due before its issue date")
    if raw.get("subtotal") is not None and raw.get("tax") is not None:
        _require(decimal_value(raw["subtotal"], field_name="subtotal") + decimal_value(raw["tax"], field_name="tax") == decimal_value(total, field_name="total"), "BILL_HAS_EXCEPTIONS", "the source subtotal and tax must equal its total")
    read = _source_read(provenance, raw, ("finance.ingest_supplier_invoice", "procurement.ingest_supplier_invoice"))
    _require(parsed(invoice_at) <= parsed(read.completed_at), "SOURCE_FROM_FUTURE", "the intake cannot observe a future invoice")
    return {"intake_source": raw, "source_provenance": read.to_dict(), "supplier_ref": supplier, "bill_ref": bill_ref, "invoice_number": number, "amount": str(decimal_value(total, field_name="total")), "currency": currency.upper(), "due_at": stamp, "engine": engine, "intake_digest": stable_digest(raw), "correlation_sha256": correlation_sha256, "evidence_refs": [f"intake:{bill_ref}"]}


def approval_receipt(task: Mapping[str, Any] | Any, *, requester_ref: str | None = None) -> dict[str, Any]:
    """From the platform's approved task; anything other than an approved status is refused."""

    raw = dict(detached(task))
    status = str(raw.get("status") or "").lower()
    _require(status == "approved", "TASK_NOT_APPROVED", f"the task is {status or 'missing'}")
    approver = raw.get("approved_by") or raw.get("approver_ref") or raw.get("decided_by")
    _require(bool(approver), "APPROVER_MISSING", "the approved task names its approver")
    approved_at = raw.get("approved_at") or raw.get("decided_at") or raw.get("updated_at")
    _require(bool(approved_at), "APPROVAL_TIME_MISSING", "the approved task carries its decision time")
    action = raw.get("proposed_action") if isinstance(raw.get("proposed_action"), Mapping) else {}
    inputs = action.get("inputs") if isinstance(action.get("inputs"), Mapping) else {}
    amount = raw.get("approved_amount")
    if amount is None:
        amount = action.get("amount", inputs.get("amount"))
    _require(amount is not None, "APPROVED_AMOUNT_MISSING", "the approved task carries the amount it approved")
    return {"approval_ref": str(raw.get("id") or raw.get("task_id")), "approver_ref": str(approver), "requester_ref": requester_ref or (str(raw.get("requested_by")) if raw.get("requested_by") else None), "approved_at": str(approved_at), "approved_amount": str(decimal_value(amount, field_name="approved_amount")), "evidence_refs": [f"approval:{raw.get('id') or raw.get('task_id')}"]}


def schedule_receipt(cover: Mapping[str, Any] | Any, *, forecast: Any = None, pay_at: str, amount: Any, bill_write: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    """From a treasury ``CashCover`` (and optionally the bill write receipt that carries the provider correlation)."""

    raw = dict(detached(cover))
    _require(raw.get("schema") == "lightbulb.company_cash_cover.v1", "COVER_SCHEMA_MISMATCH", "expected a treasury cash cover")
    _require(bool(raw.get("covered")), "CASH_NOT_COVERED", str(raw.get("detail") or "the outflow breaches the floor"))
    expected = decimal_value(amount, field_name="amount")
    _require(decimal_value(raw.get("amount"), field_name="cover.amount") == expected, "COVER_AMOUNT_MISMATCH", f"the cover judged {raw.get('amount')}, the bill is {expected}")
    stamp = timestamp(pay_at, field_name="pay_at")
    _require(parsed(str(raw.get("at"))) == parsed(stamp), "COVER_DATE_MISMATCH", "the cover must judge the exact scheduled payment date")
    from lightbulb.company_treasury import CashCover, CashForecast, assess_cash_cover
    canonical = CashCover.model_validate(raw)
    _require(forecast is not None, "SOURCE_NOT_SEALED", "retain the actual cash forecast used to judge cover")
    basis = CashForecast.model_validate(detached(forecast))
    _require(basis.schema_id == "lightbulb.company_cash_forecast.v1" and canonical == assess_cash_cover(basis, amount=expected, at=stamp), "COVER_PROJECTION_MISMATCH", "cover must be exactly rederived from the retained forecast")
    from datetime import timedelta
    _require(parsed(stamp) < parsed(basis.as_of) + timedelta(weeks=basis.horizon_weeks), "COVER_DATE_MISMATCH", "payment must fall within the forecast horizon")
    out: dict[str, Any] = {"cover_source": raw, "forecast_source": basis.to_dict(), "cover_digest": str(raw["cover_digest"]), "forecast_digest": str(raw["forecast_digest"]), "pay_at": stamp, "evidence_refs": [f"cover:{str(raw['cover_digest'])[:16]}"]}
    if bill_write is not None:
        write = dict(detached(bill_write))
        out["bill_write_source"] = write
        _require(bool(write.get("provider_correlation_sha256")), "BILL_WRITE_CORRELATION_MISSING", "the bill write receipt carries no provider correlation")
        _require(str(write.get("state", "")) not in ("bill_write_outcome_ambiguous", "ambiguous"), "BILL_WRITE_AMBIGUOUS", "an ambiguous bill write requires reconciliation before payment")
        out.update({"correlation_sha256": str(write["provider_correlation_sha256"]), "write_journal_ref": str(write.get("write_journal_ref") or "")[:200] or None})
        out["evidence_refs"].append(f"journal:{write.get('write_journal_ref')}")
    return out


def payment_receipt(observation: Mapping[str, Any] | Any, *, provenance: Any = None) -> dict[str, Any]:
    """From an APPLIED ``observe_bill_payment_applied`` observation with a zero bill balance."""

    observed = dict(detached(observation))
    _require(observed.get("schema") == BILL_PAYMENT_OBSERVATION_SCHEMA, "PAYMENT_OBSERVATION_SCHEMA_MISMATCH", "expected a bill payment observation")
    _require(str(observed.get("disposition")) == "APPLIED", "PAYMENT_NOT_APPLIED", f"payment disposition is {observed.get('disposition')}")
    _require(bool(observed.get("bill_balance_zero")), "BILL_BALANCE_OPEN", "the bill still carries a balance")
    _require(bool(observed.get("exhaustive_read")), "PAYMENT_READ_NOT_EXHAUSTIVE", "the observer did not read every linked payment")
    BillPaymentObservation.model_validate(observed)
    read = _source_read(provenance, observed, ("quickbooks.observe_bill_payment_applied",))
    _require(parsed(observed["observed_at"]) <= parsed(read.completed_at), "SOURCE_FROM_FUTURE", "the payment observation cannot postdate its read")
    return {"payment_source": observed, "source_provenance": read.to_dict(), "currency": observed["currency"], "correlation_sha256": str(observed["provider_correlation_sha256"]), "payment_evidence_sha256": str(observed["evidence_sha256"]), "applied_amount": str(decimal_value(observed.get("applied_amount"), field_name="applied_amount")), "payment_count": int(observed.get("payment_count", 0)), "applied_at": str(observed["observed_at"]), "evidence_refs": [f"observation:{str(observed['evidence_sha256'])[:16]}"]}


def clearance_receipt(close_state: Any, *, source_plan: Any, reconciliation_ref: str | None = None) -> dict[str, Any]:
    """From a closed finance period whose payables reconciliation is retained."""

    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, verify_books
    plan, close_state = CLOSE_LIFECYCLE.bind(source_plan, close_state)
    _require(close_state.status == "closed" and verify_books(plan, close_state).verified, "CLOSE_NOT_CLOSED", f"the close is {close_state.status}")
    ledger = close_state.ledger
    reconciled = list(getattr(ledger, "reconciled_accounts", ()) or ())
    _require("accounts_payable" in reconciled, "PAYABLES_NOT_RECONCILED", "the close did not reconcile accounts payable")
    rows = [item.command.receipt for item in close_state.transition_history if item.command.event == "reconcile_account" and item.command.receipt.account_kind == "accounts_payable"]
    ref = reconciliation_ref or (rows[-1].reconciliation_ref if rows else None)
    _require(bool(ref) and any(item.reconciliation_ref == ref for item in rows), "PAYABLES_NOT_RECONCILED", "the named reconciliation must be in this closed period")
    return {"close_source": {"state": close_state.to_dict(), "plan": plan.to_dict()}, "close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "reconciliation_ref": ref, "period_start": str(ledger.period_start), "period_end": str(ledger.period_end), "evidence_refs": [f"close:{close_state.scope.entity_ref}:{close_state.state_digest[:16]}"]}


def period_evidence_receipt(case_state: Any, *, source_plan: Any, engine: str | None = None, evidence_ref: str | None = None) -> dict[str, Any]:
    """The operating period's ``record_evidence`` receipt: paid cash as the engine's spend, with the chain as evidence."""

    case_state = verify_paid_payable(case_state, source_plan=source_plan)
    ledger = case_state.ledger
    kind = engine or ledger.engine
    _require(kind in _ENGINES, "ENGINE_REQUIRED", "name the operating engine the bill belongs to")
    _require(ledger.engine is None or kind == ledger.engine, "ENGINE_NOT_BOUND", "the paid bill cannot move to another engine in a projection")
    return {"engine": kind, "evidence_ref": evidence_ref or f"payable_case:{case_state.scope.entity_ref}:{case_state.state_digest[:16]}", "spend": str(ledger.applied_amount), "revenue": "0", "signals": []}


def chain_summary(case_state: Any, *, source_plan: Any) -> dict[str, Any]:
    case_state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, case_state)[1]
    ledger = case_state.ledger
    return {"case_ref": str(case_state.scope.entity_ref), "status": case_state.status, "supplier_ref": ledger.supplier_ref, "amount": str(ledger.amount), "due_at": ledger.due_at, "pay_at": ledger.pay_at, "applied_amount": str(ledger.applied_amount), "paid_days_past_due": ledger.paid_days_past_due, "days_receipt_to_cash": ledger.days_receipt_to_cash, "outcome": ledger.outcome}


PAYABLES_CHAIN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PAYABLES_CHAIN_KIND,
    "golden_loop": PAYABLES_CHAIN_GOLDEN_LOOP,
    "stages": ["receive_bill", "approve", "schedule_payment", "apply_payment", "clear_payable"],
    "statuses": list(PAYABLE_STATUSES),
    "events": list(PAYABLE_EVENTS),
    "hops": {"receive_bill": "finance.ingest_supplier_invoice output or procure-to-pay SupplierInvoice", "approve": "the platform's approved task", "schedule_payment": "treasury CashCover (+ bill write receipt carrying the LB-AP correlation)", "apply_payment": "quickbooks.observe_bill_payment_applied APPLIED observation", "clear_payable": "finance close with accounts_payable reconciled"},
    "required_connectors": ["quickbooks", "xero", "billcom", "airwallex", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a duplicate or exception-bearing intake never becomes a case",
        "the approved amount equals the bill and the requester cannot approve their own bill",
        "a payment is scheduled only inside a treasury cash cover, never past the due date plus the plan's grace",
        "the payment observation must carry the bill's correlation and settle it in full with a zero balance",
        "period spend for the engine is the paid cash of the case, not the bill amount",
    ],
}

__all__ = ["BILL_PAYMENT_OBSERVATION_SCHEMA", "BillPaymentObservation", "PAYABLE_EVENTS", "PAYABLE_STATUSES", "PAYABLES_CHAIN_GOLDEN_LOOP", "PAYABLES_CHAIN_KIND", "PAYABLES_CHAIN_LIFECYCLE", "PAYABLES_CHAIN_MANIFEST", "PayableCaseState", "PayablesChainError", "PayablesChainPlan", "advance_payable_case", "approval_receipt", "bill_receipt", "chain_summary", "clearance_receipt", "compile_payables_chain", "open_payable_case", "payment_receipt", "period_evidence_receipt", "schedule_receipt", "verify_paid_payable"]
