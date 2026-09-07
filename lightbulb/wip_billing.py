"""Accepted service work, unbilled accrual and observed invoices.

Accrual proves earned work; invoicing transfers unbilled value to receivables.
Neither event proves operating cash. Revenue-chain payment and settlement
observations remain responsible for cash evidence and its invoice correlation.
"""
from decimal import Decimal
from typing import Any, Literal
from pydantic import Field, ValidationInfo, field_validator, model_validator
from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, EngineScope, LifecycleSpec, OpaqueRef, Rejected, Sha256Digest, StrictModel, decimal_value, detached, parsed, require, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.company_execution_bridge import ExecutionReceipt
from lightbulb.connector_execution import ConnectorExecutionRequest
from lightbulb.contract_delivery_acceptance import AcceptedValueBinding
from lightbulb.deal_desk_engine import ReadEvidence
from lightbulb.engagement_engine import verify_engagement
from lightbulb.obligation_paper import verify_agreement_in_force

WIP_BILLING_KIND = "wip_billing"
WIP_BILLING_GOLDEN_LOOP = "service.marketing_to_cash_engagement@0.1.0"
WIP_STATUSES = ("accrued", "approved", "invoice_drafted", "invoiced", "reconciliation_required")
WIP_EVENTS = ("accrue", "approve", "draft_invoice", "issue_invoice", "require_reconciliation")


class WipBillingError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition, code, message):
    if not condition:
        raise WipBillingError(code, message)


class WipBillingPlan(StrictModel):
    schema_id: Literal["lightbulb.wip_billing_plan.v1"] = Field(default="lightbulb.wip_billing_plan.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo):
        if not skip_digests(info) and self.plan_digest != sealed_digest(type(self), self, "plan_digest"):
            raise ValueError("plan_digest must commit WIP billing policy")
        return self


def compile_wip_billing(company_ref, *, currency):
    return seal(WipBillingPlan, {"company_ref": company_ref, "currency": currency.upper()}, "plan_digest")


class WipReceipt(StrictModel):
    scope_binding: dict[str, Any] | None = None
    engagement_state: dict[str, Any] | None = None
    engagement_plan: dict[str, Any] | None = None
    accepted_value_read: ReadEvidence | None = None
    authorization_proof: dict[str, Any] | None = None
    invoice_execution: dict[str, Any] | None = None
    invoice_request: dict[str, Any] | None = None
    invoice_read: ReadEvidence | None = None
    evidence_refs: tuple[OpaqueRef, ...] = ()


class WipLedger(StrictModel):
    scope: dict[str, Any] = {}
    company_ref: OpaqueRef | None = None
    customer_ref: OpaqueRef | None = None
    engagement_ref: OpaqueRef | None = None
    contract_ref: OpaqueRef | None = None
    agreement_ref: OpaqueRef | None = None
    engagement_state: dict[str, Any] | None = None
    engagement_plan: dict[str, Any] | None = None
    accepted_value_digest: Sha256Digest | None = None
    accrual_ref: OpaqueRef | None = None
    accrued_at: str | None = None
    recognized_revenue: Decimal = Decimal("0.00")
    actual_cost: Decimal = Decimal("0.00")
    unbilled_value: Decimal = Decimal("0.00")
    billed_value: Decimal = Decimal("0.00")
    invoice_candidate: dict[str, Any] | None = None
    invoice_ref: OpaqueRef | None = None
    invoice_number: OpaqueRef | None = None
    invoice_total: Decimal = Decimal("0.00")
    issued_at: str | None = None
    due_at: str | None = None
    correlation_sha256: Sha256Digest | None = None
    invoice_source_digest: Sha256Digest | None = None
    outcome: str = "unbilled"

    @field_validator("recognized_revenue", "actual_cost", "unbilled_value", "billed_value", "invoice_total", mode="before")
    @classmethod
    def _money(cls, value, info: ValidationInfo):
        return decimal_value(value, field_name=str(info.field_name))


class WipEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    invoice_created: Literal[False] = False
    ledger_posted: Literal[False] = False
    cash_received: Literal[False] = False


def delivery_acceptance_projection(accepted_value):
    """Validate the existing artifact and omit raw workflow identities.

    The host attests this exact portable projection. Its original acceptance
    digest remains the deduplication identity; its read digest binds economics.
    """
    try:
        accepted = AcceptedValueBinding.model_validate(detached(accepted_value))
    except ValueError as exc:
        raise WipBillingError("WORK_NOT_ACCEPTED", "accrual requires the existing sealed delivery acceptance artifact") from exc
    _require(accepted.invoice_eligible and accepted.accepted_amount > 0, "WORK_NOT_ACCEPTED", "only independently accepted invoice-eligible work accrues")
    result = accepted.to_dict()
    result["scope"]["workflow_scope_digest"] = stable_digest(result["scope"].pop("workflow_scope"))
    return result


def _acceptance(observation):
    try:
        source = ReadEvidence.model_validate(detached(observation))
    except ValueError as exc:
        raise WipBillingError("WORK_NOT_ACCEPTED", "retain the exact portable host acceptance observation") from exc
    value = source.payload
    _require(source.provenance.source_tool == "host.contract_delivery_acceptance" and source.provenance.lane == "host_read" and value.get("schema") == "lightbulb.accepted_value_binding.v1" and value.get("invoice_eligible") is True and value.get("acceptance_state") in {"accepted_full", "accepted_partial"} and decimal_value(value.get("accepted_amount"), field_name="accepted amount") > 0, "WORK_NOT_ACCEPTED", "only a host-validated projection of actual delivery acceptance proves earned value")
    return source


def accrual_receipt(engagement_state, *, source_plan, accepted_value, acceptance_provenance):
    source = verify_engagement(engagement_state, source_plan=source_plan)
    accepted = delivery_acceptance_projection(accepted_value)
    observation = _acceptance({"provenance": detached(acceptance_provenance), "payload": accepted})
    return {"engagement_state": source.to_dict(), "engagement_plan": detached(source_plan), "accepted_value_read": observation.to_dict(), "evidence_refs": [f"delivery:{accepted['accepted_value_digest'][:24]}"]}


def wip_case_ref(accepted_value):
    raw = detached(accepted_value)
    if "workflow_scope" in raw["scope"]:
        raw = delivery_acceptance_projection(raw)
    return f"wip:{raw['accepted_value_digest'][:32]}"


def _paper(plan, data, at):
    source = verify_engagement(data["engagement_state"], source_plan=data["engagement_plan"], company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["scope"])
    verify_agreement_in_force(source.ledger.agreement_state, source_plan=source.ledger.agreement_plan, company_ref=plan.company_ref, currency=plan.currency, agreement_ref=data["agreement_ref"], at=at, expected_scope=data["scope"])
    return source


def invoice_receipt(execution, confirming_read, *, request):
    _invoice_facts(execution, request, confirming_read)
    return {"invoice_execution": detached(execution), "invoice_request": detached(request), "invoice_read": detached(confirming_read)}


def _invoice_facts(execution, request, observation):
    try:
        write = ExecutionReceipt.model_validate(detached(execution))
        call = ConnectorExecutionRequest.model_validate(detached(request))
        read = ReadEvidence.model_validate(detached(observation))
    except ValueError as exc:
        raise WipBillingError("INVOICE_NOT_OBSERVED", "retain the bound approved write and its exact confirming read") from exc
    _require(write.schema_id == "lightbulb.engine_execution_receipt.v1" and write.tool == call.tool == "xero.create_invoice" and write.effect == "write" and call.approval_required and write.request_digest == call.custody_fingerprint() and write.project_id == str(call.scope.project_id), "INVOICE_NOT_OBSERVED", "invoice execution must bind the exact approved request")
    _require(read.provenance.source_tool == "xero.list_invoices" and read.provenance.lane == "host_read" and parsed(read.provenance.completed_at) >= parsed(write.completed_at), "INVOICE_NOT_OBSERVED", "observe provider issuance after the write")
    targets = call.arguments.get("Invoices", [])
    _require(len(targets) == 1, "INVOICE_NOT_OBSERVED", "one request issues one accrued scope")
    target = targets[0]
    rows = [row for row in read.payload.get("Invoices", []) if row.get("InvoiceNumber") == target.get("InvoiceNumber")]
    _require(len(rows) == 1, "INVOICE_NOT_OBSERVED", "confirm one exact provider invoice")
    row = rows[0]
    _require(row.get("Status") in {"AUTHORISED", "PAID"} and all(row.get(key) == target.get(key) for key in ("Reference", "Contact", "CurrencyCode", "Total")), "INVOICE_NOT_OBSERVED", "invoice must reproduce approved customer, value and reference")
    reference = f"invoice:xero:{stable_digest(row['InvoiceID'])[:32]}"
    due = row["DueDate"]
    return {"invoice_ref": reference, "invoice_number": row["InvoiceNumber"], "invoice_total": str(decimal_value(row["Total"], field_name="invoice total")), "issued_at": read.provenance.completed_at, "due_at": timestamp(due + "T00:00:00Z" if len(due) == 10 else due, field_name="due date"), "correlation_sha256": stable_digest({"invoice_ref": reference, "accrual_ref": row["Reference"]}), "invoice_source_digest": read.provenance.output_digest, "customer_ref": row["Contact"]["ContactID"], "currency": row["CurrencyCode"], "accrual_ref": row["Reference"]}


def _apply(plan, next_status, status, data, cmd):
    r, event, at = cmd.receipt, cmd.event, cmd.occurred_at
    try:
        if event == "accrue":
            require(r.scope_binding is not None and r.engagement_state is not None and r.engagement_plan is not None and r.accepted_value_read is not None, "WORK_NOT_ACCEPTED", "accrue from actual engagement and accepted delivery")
            scope = r.scope_binding
            require(scope["company_ref"] in {plan.company_ref, "selected"} and scope["currency"] == plan.currency, "WIP_SCOPE_MISMATCH", "WIP scope must match its company plan")
            source = verify_engagement(r.engagement_state, source_plan=r.engagement_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=scope)
            observed = _acceptance(r.accepted_value_read)
            accepted = observed.payload
            require(source.status in {"delivering", "at_risk", "completed"} and bool(source.ledger.entry_refs), "EFFORT_UNEVIDENCED", "accrue from actual performed work")
            require(accepted["agreement_ref"] == source.ledger.agreement_ref and accepted["currency"] == plan.currency and all(str(accepted["scope"][key]) == str(scope[key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")), "WIP_SCOPE_MISMATCH", "delivery acceptance belongs to this signed agreement and company")
            require(Decimal(accepted["accepted_amount"]) <= source.ledger.contract_value and parsed(accepted["accepted_at"]) <= parsed(observed.provenance.completed_at) <= parsed(at) and parsed(source.transition_history[-1].command.occurred_at) <= parsed(at), "ACCRUAL_EXCEEDS_SCOPE", "earned value and evidence time must fit accepted scope")
            require(scope["entity_ref"] == wip_case_ref(accepted), "ACCRUAL_ALREADY_BOUND", "one deterministic WIP case per immutable delivery acceptance")
            data.update(scope=scope, company_ref=plan.company_ref, customer_ref=source.ledger.customer_ref, engagement_ref=source.scope.entity_ref, agreement_ref=source.ledger.agreement_ref, contract_ref=source.ledger.contract_ref, engagement_state=r.engagement_state, engagement_plan=r.engagement_plan, accepted_value_digest=accepted["accepted_value_digest"], accrual_ref=scope["entity_ref"], accrued_at=at, recognized_revenue=accepted["accepted_amount"], unbilled_value=accepted["accepted_amount"], actual_cost=str(source.ledger.actual_cost))
            _paper(plan, data, at)
        elif event == "approve":
            require(r.authorization_proof is not None, "BILLING_APPROVAL_REQUIRED", "approve the exact accepted billable amount", "await_approval")
            from lightbulb.authority_matrix import verify_authorization
            verify_authorization(r.authorization_proof, category="pricing", amount=data["recognized_revenue"], currency=plan.currency, command=cmd, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["scope"]["entity_ref"])
            _paper(plan, data, at)
        elif event == "draft_invoice":
            _paper(plan, data, at)
            data["invoice_candidate"] = {"schema": "lightbulb.wip_invoice_candidate.v1", "customer_ref": data["customer_ref"], "agreement_ref": data["agreement_ref"], "contract_ref": data["contract_ref"], "reference": data["accrual_ref"], "currency": plan.currency, "amount": data["unbilled_value"], "accepted_value_digest": data["accepted_value_digest"], "external_effect_authorized": False}
        elif event == "issue_invoice":
            facts = _invoice_facts(r.invoice_execution, r.invoice_request, r.invoice_read)
            require(facts["customer_ref"] == data["customer_ref"] and facts["currency"] == plan.currency and facts["accrual_ref"] == data["accrual_ref"] and Decimal(facts["invoice_total"]) == Decimal(data["unbilled_value"]), "INVOICE_EXCEEDS_ACCRUAL", "invoice exactly the accepted unbilled accrual")
            require(all(str(r.invoice_request["scope"][key]) == str(data["scope"][key]) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")) and parsed(facts["issued_at"]) <= parsed(at), "WIP_SCOPE_MISMATCH", "provider invoice scope and time must match WIP")
            _paper(plan, data, at)
            data.update({key: value for key, value in facts.items() if key not in {"customer_ref", "currency", "accrual_ref"}})
            data.update(unbilled_value="0.00", billed_value=data["recognized_revenue"], outcome="invoiced")
        elif event == "require_reconciliation":
            data["outcome"] = "reconciliation_required"
    except Rejected:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise Rejected(getattr(exc, "code", "WIP_SOURCE_INVALID"), str(exc), "correct_input") from exc
    return next_status, data


WIP_BILLING_LIFECYCLE = LifecycleSpec(entity="wip_invoice", schema_prefix="wip_billing", statuses=WIP_STATUSES, terminal=("invoiced", "reconciliation_required"), events=WIP_EVENTS, table={("new", "accrue"): "accrued", ("accrued", "approve"): "approved", ("approved", "draft_invoice"): "invoice_drafted", ("invoice_drafted", "issue_invoice"): "invoiced", **{(s, "require_reconciliation"): "reconciliation_required" for s in ("accrued", "approved", "invoice_drafted")}}, opening_event="accrue", reason_events=("require_reconciliation",), apply=_apply, ledger_model=WipLedger, receipt_model=WipReceipt, effect_boundary_model=WipEffectBoundary, plan_model=WipBillingPlan, max_transitions=12)
WipState, WipCommand, WipTransitionResult = WIP_BILLING_LIFECYCLE.State, WIP_BILLING_LIFECYCLE.Command, WIP_BILLING_LIFECYCLE.TransitionResult


def open_wip_invoice(plan, scope, *, receipt, opened_at, actor_ref):
    bound = EngineScope.model_validate(detached(scope))
    return WIP_BILLING_LIFECYCLE.open(plan, bound, receipt={**detached(receipt), "scope_binding": bound.to_dict()}, opened_at=opened_at, actor_ref=actor_ref)


def advance_wip_invoice(plan, state, command):
    return WIP_BILLING_LIFECYCLE.advance(plan, state, command)


def verify_wip(state, *, source_plan):
    try:
        _, source = WIP_BILLING_LIFECYCLE.bind(source_plan, state)
    except ValueError as exc:
        raise WipBillingError("WIP_SOURCE_INVALID", "replay the exact WIP source with its plan") from exc
    _require(source.ledger.scope == source.scope.to_dict(), "WIP_SCOPE_MISMATCH", "ledger must retain exact WIP scope")
    return source


def billing_source(state, *, source_plan):
    source = verify_wip(state, source_plan=source_plan)
    _require(source.status == "invoiced", "INVOICE_NOT_OBSERVED", "billing source requires observed provider issuance")
    result = {key: getattr(source.ledger, key) for key in ("invoice_ref", "invoice_number", "invoice_total", "issued_at", "due_at", "correlation_sha256", "contract_ref", "agreement_ref", "accrual_ref")}
    result["invoice_total"] = str(source.ledger.invoice_total)
    return {**detached(result), "source_state": source.to_dict(), "source_plan": detached(source_plan), "source_digest": source.state_digest}


def verify_billing_source(value, *, company_ref=None, currency=None, expected_scope=None):
    raw = detached(value)
    source = verify_wip(raw.get("source_state"), source_plan=raw.get("source_plan"))
    derived = billing_source(source, source_plan=raw["source_plan"])
    _require(raw == derived, "INVOICE_NOT_OBSERVED", "invoice fields must reproduce the retained WIP source")
    plan = WipBillingPlan.model_validate(raw["source_plan"])
    _require((company_ref is None or plan.company_ref == company_ref) and (currency is None or plan.currency == currency), "WIP_SCOPE_MISMATCH", "invoice belongs to another company or currency")
    if expected_scope is not None:
        scope = detached(expected_scope)
        _require(all(scope.get(key) == getattr(source.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "WIP_SCOPE_MISMATCH", "invoice belongs to another tenant or project")
    return derived


def accrual_source_balance(state, *, source_plan):
    from lightbulb.finance_close_observations import SourceBalance
    source = verify_wip(state, source_plan=source_plan)
    return SourceBalance(kind="work_in_progress", source_ref=source.ledger.accrual_ref, source_tool="wip_billing.accrual", provenance_digest=source.state_digest, balance=source.ledger.unbilled_value, items=1, window_end=source.transition_history[-1].command.occurred_at)


def recognized_revenue_source_balance(state, *, source_plan):
    from lightbulb.finance_close_observations import SourceBalance
    source = verify_wip(state, source_plan=source_plan)
    return SourceBalance(kind="revenue_subledger", source_ref=source.ledger.accrual_ref, source_tool="wip_billing.recognized_revenue", provenance_digest=source.state_digest, balance=source.ledger.recognized_revenue, items=1, window_end=source.ledger.accrued_at)


def wip(state, *, source_plan):
    source = verify_wip(state, source_plan=source_plan)
    return {"status": source.status, "source_digest": source.state_digest, **source.ledger.to_dict()}


WIP_BILLING_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": WIP_BILLING_KIND, "golden_loop": WIP_BILLING_GOLDEN_LOOP, "statuses": list(WIP_STATUSES), "events": list(WIP_EVENTS), "missing_reads": ["xero.list_invoices remains a host-lane read", "host.contract_delivery_acceptance validates the existing acceptance binding and attests its portable projection without raw workflow identities"], "hard_rules": ["effort alone does not prove earned revenue", "one immutable delivery acceptance has one deterministic WIP case", "invoicing transfers unbilled work to receivables without earning the revenue twice", "cash remains a revenue-chain payment and settlement proof"]}
__all__ = ["WIP_BILLING_KIND", "WIP_BILLING_GOLDEN_LOOP", "WIP_BILLING_MANIFEST", "WIP_STATUSES", "WIP_EVENTS", "WIP_BILLING_LIFECYCLE", "WipBillingError", "WipBillingPlan", "WipReceipt", "WipLedger", "WipState", "WipCommand", "WipTransitionResult", "compile_wip_billing", "delivery_acceptance_projection", "accrual_receipt", "wip_case_ref", "invoice_receipt", "open_wip_invoice", "advance_wip_invoice", "verify_wip", "billing_source", "verify_billing_source", "accrual_source_balance", "recognized_revenue_source_balance", "wip"]
