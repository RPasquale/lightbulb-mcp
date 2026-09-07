"""Replay-fenced batches from approved liabilities to bank-proven cash out.

Retained payable, payroll and obligation plans replay their source states.
Vendor onboarding snapshots bind beneficiaries, authority proofs bind a batch
approval as one total by someone who did not prepare it, completed connector
results bind its exact release request, and bank reconciliation matches (or
the paying rail's own payout rows, with the provenance of the read that
produced them) prove settlement. Derived receipts let the originating payables
and statutory engines consume that cash fact, and a payee whose bank custody
moved after approval opens an exception instead of being paid. Nothing here
executes provider work, reads a provider, or grants hosted authority.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from datetime import timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec,
    OpaqueRef, Sha256Digest, StrictModel, decimal_value, detached, parsed,
    require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)
from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionRequest

DISBURSEMENT_KIND = "disbursement_run"
DISBURSEMENT_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
DISBURSEMENT_STATUSES = ("assembled", "covered", "approved", "held", "released", "settled", "reconciled", "cancelled", "reconciliation_required")
DISBURSEMENT_EVENTS = ("assemble", "confirm_cover", "approve", "hold", "release_hold", "release", "settle", "reconcile", "cancel", "require_reconciliation")
_TABLE = {
    ("new", "assemble"): "assembled", ("assembled", "confirm_cover"): "covered",
    ("covered", "approve"): "approved", ("held", "release_hold"): "approved",
    ("approved", "release"): "released", ("released", "settle"): "settled",
    ("settled", "reconcile"): "reconciled",
    **{(s, "hold"): "held" for s in ("assembled", "covered", "approved")},
    **{(s, "cancel"): "cancelled" for s in ("assembled", "covered", "approved", "held")},
    **{(s, "require_reconciliation"): "reconciliation_required" for s in ("released", "settled")},
}
_TOOLS = {"xero": "xero.pay_bill", "quickbooks": "quickbooks.pay_bill", "billcom": "billcom.approve_bill", "airwallex": "airwallex.create_payment"}
#: Rail reads whose rows are the paying account's own record of the money
#: leaving; ``bank_reconciliation.BANK_LINE_TOOLS`` carries neither, so a
#: batch paid on these rails settles on its rail statement or not at all.
PAYOUT_ROW_TOOLS: tuple[str, ...] = ("airwallex.list_payouts", "billcom.list_payments")
#: Exceptions-desk kinds for a moved beneficiary and a batch the bank never
#: proved.  ``beneficiary_changed`` and ``disbursement_unsettled`` are not
#: registered in ``exceptions_desk.RESOLUTION_PATHS`` yet; until they are, both
#: open as a chain reconciliation.
BENEFICIARY_EXCEPTION_KIND = "chain_reconciliation"
UNSETTLED_EXCEPTION_KIND = "chain_reconciliation"
#: What the operator does about each refusal.  Authority codes keep the
#: dispositions ``authority_matrix.RECOVERY_BY_CODE`` gives them.
RECOVERY_BY_CODE: dict[str, str] = {
    "CASE_NOT_APPROVED": "correct_input",
    "DUPLICATE_IN_BATCH": "do_not_replay",
    "MIXED_CURRENCY_BATCH": "correct_input",
    "BATCH_TOTAL_EXCEEDED": "await_approval",
    "COVER_INSUFFICIENT": "await_approval",
    "APPROVAL_NOT_BOUND": "await_approval",
    "APPROVED_TOTAL_MISMATCH": "manual_reconciliation",
    "SELF_APPROVAL": "manual_reconciliation",
    "BENEFICIARY_CHANGED": "manual_reconciliation",
    "NEW_PAYEE_COOLING": "await_approval",
    "BANK_CONTROL_UNVERIFIED": "manual_reconciliation",
    "RELEASE_NOT_EXECUTED": "correct_input",
    "RELEASE_TOO_LATE": "manual_reconciliation",
    "SETTLEMENT_SHORT": "manual_reconciliation",
    "CLOSE_BEFORE_PAYMENT": "manual_reconciliation",
    "FUNDED_BEFORE_CLIENT_FUNDS": "await_approval",
}
DISBURSEMENT_CODES: tuple[str, ...] = tuple(sorted(RECOVERY_BY_CODE))


class DisbursementError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise DisbursementError(code, message)


class DisbursementPlan(StrictModel):
    schema_id: Literal["lightbulb.disbursement_run_plan.v1"] = Field(default="lightbulb.disbursement_run_plan.v1", alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    rail: Literal["xero", "quickbooks", "billcom", "airwallex"] = "xero"
    max_batch_total: Decimal = Field(default=Decimal("100000.00"), validate_default=True)
    new_payee_cooling_days: int = Field(default=5, ge=0, le=365)
    require_bank_control: bool = True
    require_dual_control: bool = True
    settlement_tolerance: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    max_days_approval_to_release: int = Field(default=7, ge=1, le=90)
    # Operator policy names which payees must be funded from client receipts.
    pass_through_payees: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_batch_total", "settlement_tolerance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> DisbursementPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(DisbursementPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_disbursement_run(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> DisbursementPlan:
    return seal(DisbursementPlan, {"company_ref": company_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class DisbursementReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)
    entity_scope: dict[str, Any] | None = None
    sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    bank_controls: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    funding_bindings: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    prior_runs: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    cover: dict[str, Any] | None = None
    cover_forecast: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    approval_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    approved_amount: Decimal | None = None
    approved_total: Decimal | None = None
    execution_request: dict[str, Any] | None = None
    execution_result: dict[str, Any] | None = None
    bank_states: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    payout_reads: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=20)
    close_source: dict[str, Any] | None = None
    hold_payee_ref: OpaqueRef | None = None

    @field_validator("approved_amount", "approved_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("approved_at")
    @classmethod
    def _time(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="approved_at")


class DisbursementLedger(StrictModel):
    entity_scope: dict[str, Any] = Field(default_factory=dict)
    assembler_ref: OpaqueRef | None = None
    payee_count: int = Field(default=0, ge=0)
    cases: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    case_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=100)
    batch_total: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    currency: CurrencyCode | None = None
    bank_controls: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    funding_bindings: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    cover_digest: Sha256Digest | None = None
    pay_at: str | None = None
    authorization_proof_digest: Sha256Digest | None = None
    authorization_proof: dict[str, Any] | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    holds: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=100)
    released_total: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    release_journal_ref: OpaqueRef | None = None
    release_request_digest: Sha256Digest | None = None
    released_at: str | None = None
    correlation: OpaqueRef | None = None
    correlation_sha256: Sha256Digest | None = None
    settled_total: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    unsettled: Decimal = Field(default=Decimal("0.00"), validate_default=True)
    settled_at: str | None = None
    settlement_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=100)
    close_ref: OpaqueRef | None = None
    days_approval_to_settlement: int | None = Field(default=None, ge=0)
    outcome: Literal["open", "reconciled", "cancelled", "reconciliation_required"] = "open"

    @field_validator("batch_total", "released_total", "settled_total", "unsettled", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("pay_at", "approved_at", "released_at", "settled_at")
    @classmethod
    def _time(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class DisbursementEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    payment_sent: Literal[False] = False
    provider_read: Literal[False] = False
    journal_posted: Literal[False] = False


def _artifact(state: Any, plan: Any) -> dict[str, Any]:
    return {"state": detached(state), "plan": detached(plan)}


def _same_scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(key) == b.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id"))


def _replay(source: Mapping[str, Any], lifecycle: Any, code: str) -> tuple[Any, Any]:
    try:
        return lifecycle.bind(source["plan"], source["state"])
    except (ValueError, TypeError, KeyError) as exc:
        raise DisbursementError(code, "a source requires its exact sealed plan and replay-valid state") from exc


def _case(source: Mapping[str, Any]) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE
    from lightbulb.payroll_run_chain import PAYROLL_LIFECYCLE
    from lightbulb.compliance_calendar import COMPLIANCE_LIFECYCLE

    raw = source.get("state") or {}
    schema = raw.get("schema")
    choices = {
        "lightbulb.payables_chain_state.v1": (PAYABLES_CHAIN_LIFECYCLE, "approved", "amount", "supplier_ref", "payables_chain"),
        "lightbulb.payroll_run_state.v1": (PAYROLL_LIFECYCLE, "approved", "net", "run_ref", "payroll_run_chain"),
        "lightbulb.compliance_obligation_state.v1": (COMPLIANCE_LIFECYCLE, "reserved", "reserved_amount", "kind", "compliance_calendar"),
    }
    _require(schema in choices, "CASE_NOT_APPROVED", "expected an approved payable, approved payroll run, or reserved statutory obligation")
    spec, required_status, amount_field, payee_field, kind = choices[schema]
    plan, state = _replay(source, spec, "CASE_NOT_APPROVED")
    _require(state.status == required_status, "CASE_NOT_APPROVED", f"{kind} must be {required_status}")
    _require(plan.currency == state.scope.currency, "MIXED_CURRENCY_BATCH", "the source scope must use its sealed plan currency")
    ledger = state.ledger.to_dict()
    amount = decimal_value(ledger.get(amount_field), field_name=amount_field)
    _require(amount > 0, "CASE_NOT_APPROVED", "a batch liability must have positive value")
    correlation = ledger.get("correlation_sha256") or ledger.get("payment_correlation")
    ref = state.scope.entity_ref
    _require(bool(ledger.get(payee_field)), "CASE_NOT_APPROVED", "the source identifies its payable beneficiary group")
    return {"kind": kind, "case_ref": ref, "company_ref": state.scope.company_ref, "tenant_ref": state.scope.tenant_ref,
            "project_ref": state.scope.project_ref, "project_id": state.scope.project_id,
            "plan_company_ref": getattr(plan, "company_ref", state.scope.company_ref),
            "currency": state.scope.currency, "amount": str(amount),
            "payee_ref": ledger[payee_field], "invoice_number": ledger.get("invoice_number") or ref,
            "correlation": correlation or f"{kind}:{ref}", "state_digest": state.state_digest,
            "approved_at": ledger.get("approved_at") or ledger.get("reserved_at"),
            "requester_ref": ledger.get("requester_ref") or ledger.get("preparer_ref") or state.transition_history[0].command.actor_ref}


def _control(snapshot: Any) -> dict[str, Any]:
    from lightbulb.vendor_onboarding_lifecycle import VendorOnboardingSnapshot, VerifyVendorBankControlCommand

    try:
        vendor = VendorOnboardingSnapshot.model_validate(detached(snapshot))
        records = [r for r in vendor.history if r.command.kind == "verify_vendor_bank_control"]
        _require(bool(records), "BANK_CONTROL_UNVERIFIED", "vendor onboarding has no verified bank control")
        command = VerifyVendorBankControlCommand.model_validate(detached(records[-1].command))
    except (ValueError, TypeError, AttributeError) as exc:
        if isinstance(exc, DisbursementError):
            raise
        raise DisbursementError("BANK_CONTROL_UNVERIFIED", "expected a replay-valid vendor onboarding snapshot with independent bank verification") from exc
    # Restated here rather than inherited: the SDK sees digests of the account, never its number.
    _require(command.bank_submitter_ref != command.bank_verifier_ref and command.verification_method in ("independent_callback", "microdeposit", "verified_bank_letter"), "BANK_CONTROL_UNVERIFIED", "bank custody is verified independently of whoever submitted it")
    return {"payee_ref": vendor.scope.vendor_ref, "company_ref": vendor.scope.company_ref, "tenant_ref": vendor.scope.tenant_ref,
            "project_ref": vendor.scope.project_ref, "project_id": str(vendor.scope.project_id),
            "bank_account_digest": command.bank_account_digest,
            "prior_bank_account_digest": command.prior_bank_account_digest,
            "created_at": vendor.history[0].command.captured_at,
            "verified_at": command.verified_at,
            "submitter_ref": command.bank_submitter_ref, "verifier_ref": command.bank_verifier_ref,
            "verification_method": command.verification_method, "source_digest": vendor.state_digest,
            "source_state": vendor.model_dump(mode="json", by_alias=True, exclude_none=True)}


def bank_control_receipt(vendor_state: Any) -> dict[str, Any]:
    """Retain the vendor snapshot, never accept an unattached verification command."""
    control = _control(vendor_state)
    return {"bank_controls": [control["source_state"]], "evidence_refs": [f"vendor:{control['source_digest']}"]}


def assemble_receipt(states: Any, *, source_plans: Mapping[str, Any], bank_controls: Sequence[Any] = (), funding_bindings: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Read amounts and correlations from replayed approved source liabilities.

    ``source_plans`` maps each source plan_digest to its sealed plan. Funding
    bindings name ``payee_ref`` and retain a revenue ``state`` plus ``plan``.
    Bank controls are whole vendor onboarding snapshots.
    """
    items = [states] if isinstance(states, Mapping) or hasattr(states, "state_digest") else list(states)
    sources = []
    for state in items:
        raw = detached(state)
        source = _artifact(raw, source_plans.get(raw.get("plan_digest")))
        _case(source)
        sources.append(source)
    for vendor in bank_controls:
        _control(vendor)
    return {"sources": sources, "bank_controls": [detached(v) for v in bank_controls],
            "funding_bindings": list(detached(funding_bindings)),
            "evidence_refs": [f"case:{s['state']['state_digest']}" for s in sources]}


def cover_receipt(cash_cover: Any, *, forecast: Any = None) -> dict[str, Any]:
    from lightbulb.company_treasury import CashCover, CashForecast, assess_cash_cover
    try:
        cover = CashCover.model_validate(detached(cash_cover))
        _require(cover.schema_id == "lightbulb.company_cash_cover.v1", "COVER_INSUFFICIENT", "expected a treasury cash cover")
        timestamp(cover.at, field_name="pay_at")
        _require(forecast is not None, "COVER_INSUFFICIENT", "retain the actual cash forecast used to assess this batch")
        basis = CashForecast.model_validate(detached(forecast))
        _require(basis.schema_id == "lightbulb.company_cash_forecast.v1" and cover == assess_cash_cover(basis, amount=cover.amount, at=cover.at), "COVER_INSUFFICIENT", "the cash cover must be exactly rederived from its retained forecast")
        _require(parsed(cover.at) < parsed(basis.as_of) + timedelta(weeks=basis.horizon_weeks), "COVER_INSUFFICIENT", "the payment must fall within the retained forecast horizon")
    except (ValueError, TypeError) as exc:
        raise DisbursementError("COVER_INSUFFICIENT", "expected a sealed treasury cash cover") from exc
    return {"cover": cover.to_dict(), "cover_forecast": basis.to_dict(), "evidence_refs": [f"cover:{cover.cover_digest}"]}


def _funding(bindings: Sequence[Mapping[str, Any]], cases: Sequence[Mapping[str, Any]], plan: DisbursementPlan, *, at: str, execution_scope: Any) -> None:
    from lightbulb.revenue_chain import REVENUE_CHAIN_LIFECYCLE
    used: set[str] = set()
    for payee in set(plan.pass_through_payees) & {str(c['payee_ref']) for c in cases}:
        rows = [row for row in bindings if row.get("payee_ref") == payee]
        _require(len(rows) == 1, "FUNDED_BEFORE_CLIENT_FUNDS", "each pass-through payee needs one designated settled client source")
        source_plan, source = _replay(rows[0], REVENUE_CHAIN_LIFECYCLE, "FUNDED_BEFORE_CLIENT_FUNDS")
        _require(source_plan.company_ref == plan.company_ref and _same_scope(source.scope, execution_scope) and source.scope.currency == plan.currency, "FUNDED_BEFORE_CLIENT_FUNDS", "client funds must belong to this exact company execution scope and currency")
        _require(source.status in ("cash_settled", "receivable_cleared"), "FUNDED_BEFORE_CLIENT_FUNDS", "designated client funds have not settled")
        amount = sum((Decimal(str(c["amount"])) for c in cases if c["payee_ref"] == payee), Decimal(0))
        _require(source.ledger.settled_amount >= amount and source.state_digest not in used, "FUNDED_BEFORE_CLIENT_FUNDS", "client funding cannot be short or reused across batch payees")
        _require(parsed(source.ledger.settled_at) <= parsed(at) and parsed(source.transition_history[-1].command.occurred_at) <= parsed(at), "FUNDED_BEFORE_CLIENT_FUNDS", "client source must predate release")
        used.add(source.state_digest)


def _request(plan: DisbursementPlan, data: Mapping[str, Any], state_digest: str, *, approved: bool) -> ConnectorExecutionRequest:
    scope = data["entity_scope"]
    proof = data.get("authorization_proof") or {}
    return ConnectorExecutionRequest(tool=_TOOLS[plan.rail], effect=ConnectorEffect.WRITE,
        approval_required=True, preview_only=not approved,
        approval_ref=proof.get("approval_task_id") if approved else None,
        idempotency_key=f"disbursement:{data['correlation']}",
        scope={key: scope[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id")},
        arguments={"run_ref": scope["entity_ref"], "plan_digest": plan.plan_digest,
                   "state_digest": state_digest, "amount": str(data["batch_total"]),
                   "currency": plan.currency, "pay_at": data.get("pay_at"),
                   "correlation": data["correlation"], "case_digests": list(data["case_digests"]),
                   "payments": [{"case_ref": row["case_ref"], "payee_ref": row["payee_ref"], "amount": row["amount"], "currency": row["currency"], "correlation": row["correlation"]} for row in data["cases"]],
                   "beneficiaries": [{"payee_ref": row["payee_ref"], "bank_account_digest": row["bank_account_digest"]} for row in data.get("bank_controls", ())]},
        metadata={"engine": DISBURSEMENT_KIND, "authorization_proof_digest": data.get("authorization_proof_digest")})


def release_request(state: Any, *, plan: Any) -> ConnectorExecutionRequest:
    parsed_plan, run = _replay(_artifact(state, plan), DISBURSEMENT_LIFECYCLE, "RELEASE_NOT_EXECUTED")
    _require(run.status in ("assembled", "covered", "approved", "held"), "RELEASE_NOT_EXECUTED", "only an unreleased run can propose a payment")
    if run.status == "approved":
        _funding(run.ledger.funding_bindings, run.ledger.cases, parsed_plan, at=run.ledger.pay_at, execution_scope=run.scope)
        _require(parsed(run.ledger.pay_at) <= parsed(run.ledger.approved_at) + timedelta(days=parsed_plan.max_days_approval_to_release), "RELEASE_TOO_LATE", "scheduled payment is later than the approval release window")
        if parsed_plan.require_bank_control:
            for payee in {c["payee_ref"] for c in run.ledger.cases}:
                controls = [c for c in run.ledger.bank_controls if c["payee_ref"] == payee]
                _require(len(controls) == 1, "BANK_CONTROL_UNVERIFIED", "payment request needs each beneficiary's verified bank control")
                _require((parsed(run.ledger.pay_at) - parsed(controls[0]["created_at"])).total_seconds() >= parsed_plan.new_payee_cooling_days * 86400, "NEW_PAYEE_COOLING", "scheduled payment falls inside new payee cooling")
                _require(parsed(controls[0]["verified_at"]) <= parsed(run.ledger.pay_at), "BANK_CONTROL_UNVERIFIED", "scheduled payment precedes independent bank verification")
    return _request(parsed_plan, run.ledger.to_dict(), run.state_digest, approved=run.status == "approved")


def release_receipt(result: Any, *, request: Any, bank_controls: Sequence[Any] = ()) -> dict[str, Any]:
    """Retain the completed result and exact request for replay at the release hop."""
    from lightbulb.company_execution_bridge import execution_receipt_from_connector
    try:
        req = ConnectorExecutionRequest.model_validate(detached(request))
        execution = execution_receipt_from_connector(detached(result), req)
        _require(req.schema_id == "lightbulb.connector_execution_request.v1" and req.tool in _TOOLS.values() and req.effect == ConnectorEffect.WRITE and req.approval_required and not req.preview_only, "RELEASE_NOT_EXECUTED", "a preview is not an executed payment")
        output = detached(result).get("output") or {}
        expected = hashlib.sha256(str(req.arguments.get("correlation", "")).encode()).hexdigest()
        _require(output.get("provider_correlation_sha256") == expected, "RELEASE_NOT_EXECUTED", "the provider output must retain the exact batch correlation")
        _require(decimal_value(output.get("amount"), field_name="amount") == decimal_value(req.arguments.get("amount"), field_name="amount") and output.get("currency") == req.arguments.get("currency"), "RELEASE_NOT_EXECUTED", "provider amount and currency must equal the released batch")
    except (ValueError, TypeError, KeyError) as exc:
        raise DisbursementError("RELEASE_NOT_EXECUTED", "release needs a completed, approved write bound to the exact amount, currency and correlation") from exc
    for vendor in bank_controls:
        _control(vendor)
    return {"execution_request": detached(req), "execution_result": detached(result),
            "bank_controls": list(detached(bank_controls)), "evidence_refs": [f"execution:{execution.execution_digest}"]}


def _payout_row(tool: str, item: Mapping[str, Any]) -> dict[str, Any]:
    """One rail payout row, normalized; a row that states none of its own facts is refused, never defaulted."""

    if tool.startswith("airwallex."):
        ref, when = item.get("id"), item.get("paid_at") or item.get("created_at")
        reference = item.get("reference") or item.get("payment_reference") or item.get("short_reference_id")
    else:
        ref, when = item.get("id"), item.get("processDate") or item.get("paidDate")
        reference = item.get("description") or item.get("paymentReference")
    status, amount, currency = str(item.get("status") or "").upper(), item.get("amount"), str(item.get("currency") or "").upper()
    _require(status in ("PAID", "SETTLED", "COMPLETED"), "SETTLEMENT_SHORT", f"a {tool} row settles only once it is paid; this one is {status or 'unstated'}")
    _require(all((ref, reference, when, currency)) and amount is not None, "SETTLEMENT_SHORT", f"a {tool} row names its id, reference, amount, currency and payment time")
    return {"line_ref": f"{tool.split('.')[0]}:payout:{ref}", "occurred_at": timestamp(str(when), field_name="occurred_at"),
            "amount": decimal_value(amount, field_name="amount"), "currency": currency, "reference": str(reference)}


def _payout_rows(read: Mapping[str, Any]) -> tuple[Any, list[dict[str, Any]]]:
    """Replay a retained rail payout read into rows; the page must match the digest of the read that produced it."""

    from lightbulb.company_execution_bridge import ObservationProvenance
    try:
        prov = ObservationProvenance.model_validate(dict(detached(read["provenance"])))
        raw = dict(detached(read["payload"]))
    except (ValueError, TypeError, KeyError) as exc:
        raise DisbursementError("SETTLEMENT_SHORT", "payout rows arrive with the provenance of the read that produced them") from exc
    _require(prov.source_tool in PAYOUT_ROW_TOOLS, "SETTLEMENT_SHORT", f"payout settlement reads one of {list(PAYOUT_ROW_TOOLS)}")
    _require(stable_digest(raw) == prov.output_digest, "SETTLEMENT_SHORT", "the payout page does not match the output digest of its read")
    rows = raw.get("items") or raw.get("response_data") or raw.get("payments")
    _require(isinstance(rows, Sequence) and not isinstance(rows, str) and bool(rows), "SETTLEMENT_SHORT", "a payout page carries its rows as a list")
    try:
        return prov, [_payout_row(prov.source_tool, dict(detached(item))) for item in rows]  # type: ignore[union-attr]
    except DisbursementError:
        raise
    except (ValueError, TypeError) as exc:
        raise DisbursementError("SETTLEMENT_SHORT", f"a payout row carries an amount or time this engine cannot read: {exc}"[:200]) from exc


def payout_rows_receipt(provenance: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    """The ``settle`` receipt for a rail whose payouts never reach a bank feed: the paying account's own record.

    Weaker than a reconciled bank line and never a substitute for one on a rail
    that has a bank feed, so the read is retained whole and re-normalized by the
    hop rather than trusted as numbers.
    """

    read = {"provenance": detached(provenance), "payload": dict(detached(payload))}
    prov, _ = _payout_rows(read)
    return {"payout_reads": [read], "evidence_refs": [f"payout:{prov.observation_ref}"]}


def _settled(bank_sources: Sequence[Mapping[str, Any]], payout_reads: Sequence[Mapping[str, Any]] = (), *, run_digest: str, data: Mapping[str, Any], plan: DisbursementPlan, at: str | None = None) -> tuple[Decimal, str | None, list[str]]:
    from lightbulb.bank_reconciliation import BANK_REC_LIFECYCLE
    total, settled_at, seen, digests = Decimal(0), None, set(), []
    for read in payout_reads:
        prov, rows = _payout_rows(read)
        _require(at is None or parsed(prov.completed_at) <= parsed(at), "SETTLEMENT_SHORT", "the payout read must predate its consumption")
        # A rail whose payouts reach a bank feed settles there; its own statement never stands in for one.
        _require(prov.source_tool.split(".")[0] == plan.rail, "SETTLEMENT_SHORT", f"a {plan.rail} batch does not settle on {prov.source_tool} rows")
        for row in rows:
            if row["reference"] != data["correlation"]:
                continue
            if prov.provenance_digest not in digests:
                digests.append(prov.provenance_digest)
            _require(row["currency"] == plan.currency, "SETTLEMENT_SHORT", "a payout row in another currency never settles this batch")
            _require(parsed(row["occurred_at"]) >= parsed(data["released_at"]), "SETTLEMENT_SHORT", "a payout row that predates release settles nothing")
            _require(row["line_ref"] not in seen, "DUPLICATE_IN_BATCH", "one payout row cannot settle a batch twice")
            seen.add(row["line_ref"])
            total += row["amount"]
            settled_at = max(settled_at or row["occurred_at"], row["occurred_at"])
    for artifact in bank_sources:
        bp, bank = _replay(artifact, BANK_REC_LIFECYCLE, "SETTLEMENT_SHORT")
        _require(bp.company_ref == plan.company_ref and _same_scope(bank.scope, data["entity_scope"]) and bank.scope.currency == plan.currency, "SETTLEMENT_SHORT", "bank settlement belongs to this exact execution scope and currency")
        _require(at is None or parsed(bank.transition_history[-1].command.occurred_at) <= parsed(at), "SETTLEMENT_SHORT", "the bank source must predate its consumption")
        relevant = [m for m in bank.ledger.matches if m.counterpart_kind == DISBURSEMENT_KIND and m.counterpart_state_digest == run_digest]
        for match in relevant:
            _require(match.counterpart_ref == f"disbursement_run:{data['entity_scope']['entity_ref']}" and match.amount < 0, "SETTLEMENT_SHORT", "bank match must settle this run's outflow")
            lines = [line for line in bank.ledger.lines if line.line_ref in match.line_refs]
            _require(bool(lines) and all(line.reference == data["correlation"] and parsed(line.occurred_at) >= parsed(data["released_at"]) for line in lines), "SETTLEMENT_SHORT", "bank lines must carry this release correlation and follow release")
            for line in lines:
                key = (bank.ledger.account_ref, line.line_ref)
                _require(key not in seen, "DUPLICATE_IN_BATCH", "one bank line cannot settle a batch twice")
                seen.add(key)
                total += abs(line.amount)
                settled_at = max(settled_at or line.occurred_at, line.occurred_at)
            digests.append(bank.state_digest)
    return total.quantize(MONEY_QUANTUM), settled_at, digests


def settle_receipt(bank_states: Sequence[Any] = (), *, bank_plans: Mapping[str, Any] | None = None, run_state: Any, run_plan: Any, payout_reads: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The ``settle`` receipt: bank reconciliation matches on this exact released run, rail payout rows, or both.

    ``bank_plans`` maps each bank case's plan_digest to its sealed plan, so the
    hop replays the case that carries the line rather than reading a claim.
    """

    plan, run = _replay(_artifact(run_state, run_plan), DISBURSEMENT_LIFECYCLE, "SETTLEMENT_SHORT")
    _require(run.status == "released", "SETTLEMENT_SHORT", "settlement consumes the released run")
    plans = dict(bank_plans or {})
    sources = [_artifact(state, plans.get(detached(state).get("plan_digest"))) for state in bank_states]
    reads = [{"provenance": detached(read["provenance"]), "payload": dict(detached(read["payload"]))} for read in payout_reads]
    _require(bool(sources or reads), "SETTLEMENT_SHORT", "settlement names at least one bank case or rail payout read")
    _settled(sources, reads, run_digest=run.state_digest, data=run.ledger.to_dict(), plan=plan)
    return {"bank_states": sources, "payout_reads": reads,
            "evidence_refs": [f"bank:{s['state']['state_digest']}" for s in sources] + [f"payout:{r['provenance'].get('observation_ref')}" for r in reads]}


def clear_receipt(close_state: Any, *, close_plan: Any) -> dict[str, Any]:
    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
    _, close = _replay(_artifact(close_state, close_plan), CLOSE_LIFECYCLE, "CLOSE_BEFORE_PAYMENT")
    _require(close.status == "closed", "CLOSE_BEFORE_PAYMENT", "clearance needs a closed finance period")
    return {"close_source": _artifact(close, close_plan), "evidence_refs": [f"close:{close.state_digest}"]}


def _apply(plan: DisbursementPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    from lightbulb.authority_matrix import require_authorization_proof
    from lightbulb.company_treasury import CashCover
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "assemble":
        require(bool(r.sources) and r.entity_scope is not None, "CASE_NOT_APPROVED", "assembly requires approved source states and scope")
        scope = EngineScope.model_validate(r.entity_scope)
        require(command.expected_state_digest == DISBURSEMENT_LIFECYCLE.state_digest(plan.plan_digest, scope, ()), "CASE_NOT_APPROVED", "the retained assembly scope must equal the lifecycle scope")
        cases = [_case(s) for s in r.sources]
        require(all(_same_scope(c, scope) and c["plan_company_ref"] == plan.company_ref for c in cases), "CASE_NOT_APPROVED", "batch and source execution scopes must agree")
        require(all(c["approved_at"] is not None and parsed(c["approved_at"]) <= parsed(at) for c in cases), "CASE_NOT_APPROVED", "source approval or reservation must predate assembly")
        require(scope.currency == plan.currency and all(c["currency"] == plan.currency for c in cases), "MIXED_CURRENCY_BATCH", "every liability must have the batch currency")
        require(all(len({c[key] for c in cases}) == len(cases) for key in ("case_ref", "state_digest", "invoice_number", "correlation")), "DUPLICATE_IN_BATCH", "case, invoice and correlation are unique inside the batch", "do_not_replay")
        total = sum((Decimal(c["amount"]) for c in cases), Decimal(0)).quantize(MONEY_QUANTUM)
        require(total <= plan.max_batch_total, "BATCH_TOTAL_EXCEEDED", "batch exceeds the plan's maximum", "await_approval")
        controls = [_control(v) for v in r.bank_controls]
        require(len({v['payee_ref'] for v in controls}) == len(controls), "BANK_CONTROL_UNVERIFIED", "each payee has one onboarding snapshot", "manual_reconciliation")
        require(all(_same_scope(v, scope) for v in controls), "BANK_CONTROL_UNVERIFIED", "vendor bank controls belong to the batch execution scope", "manual_reconciliation")
        correlation = f"LB-DR-{stable_digest({'scope': scope.to_dict(), 'cases': cases})[:32]}"
        data.update(entity_scope=scope.to_dict(), assembler_ref=command.actor_ref, cases=cases,
                    case_digests=[c["state_digest"] for c in cases], batch_total=str(total),
                    payee_count=len({c["payee_ref"] for c in cases}), currency=plan.currency,
                    bank_controls=controls, funding_bindings=list(detached(r.funding_bindings)),
                    correlation=correlation, correlation_sha256=hashlib.sha256(correlation.encode()).hexdigest())
    if event == "confirm_cover" or event == "release_hold" and r.cover is not None:
        require(r.cover is not None, "COVER_INSUFFICIENT", "the batch requires its treasury cover", "await_approval")
        cover = CashCover.model_validate(cover_receipt(r.cover, forecast=r.cover_forecast)["cover"])
        require(r.cover_forecast["currency"] == plan.currency and parsed(r.cover_forecast["as_of"]) <= parsed(at), "COVER_INSUFFICIENT", "the cash forecast must have this batch currency and predate its decision", "await_approval")
        require(cover.covered and cover.amount == Decimal(data["batch_total"]) and parsed(cover.at) >= parsed(at), "COVER_INSUFFICIENT", "cash cover must cover the exact batch at a future payment time", "await_approval")
        data.update(cover_digest=cover.cover_digest, pay_at=cover.at)
    if event in ("approve", "release_hold"):
        require(bool(data.get("cover_digest")), "COVER_INSUFFICIENT", "an uncovered held batch cannot become approved", "await_approval")
        require(r.authorization_proof is not None, "APPROVAL_NOT_BOUND", "a typed approval reference is not a bound proof", "await_approval")
        require(r.approved_total is None or r.approved_total == Decimal(data["batch_total"]), "APPROVED_TOTAL_MISMATCH", "approved total must equal the batch to the cent", "manual_reconciliation")
        require(r.authorization_proof.get("entity_ref") == data["entity_scope"]["entity_ref"], "APPROVAL_REUSED", "another run's approval cannot authorize this batch", "do_not_replay")
        prior = []
        for source in r.prior_runs:
            _, other = _replay(source, DISBURSEMENT_LIFECYCLE, "APPROVAL_NOT_BOUND")
            if other.ledger.authorization_proof:
                prior.append(other.ledger.authorization_proof)
        # The proof must name the batch's own preparer, so the matrix's not_preparer row is a real segregation.
        proof = require_authorization_proof(r.authorization_proof, category="disbursement", amount=Decimal(data["batch_total"]), currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref, entity_ref=data["entity_scope"]["entity_ref"], preparer_ref=data["assembler_ref"] if plan.require_dual_control else None, prior_proofs=prior)
        if plan.require_dual_control:
            require(proof.approver_ref not in {data["assembler_ref"], *(c["requester_ref"] for c in data["cases"])}, "SELF_APPROVAL", "assembler and bill requesters cannot approve their own batch", "manual_reconciliation")
        data.update(authorization_proof=proof.to_dict(), authorization_proof_digest=proof.proof_digest, approver_ref=proof.approver_ref, approved_at=proof.decided_at, holds=[])
    elif event == "hold":
        require(r.hold_payee_ref is None or r.hold_payee_ref in {c["payee_ref"] for c in data["cases"]}, "BANK_CONTROL_UNVERIFIED", "held beneficiary must belong to this batch")
        data["holds"] = [*data.get("holds", ()), {"payee_ref": r.hold_payee_ref or data["entity_scope"]["entity_ref"], "reason": command.reason}]
    elif event == "release":
        require(parsed(at) <= parsed(data["approved_at"]) + timedelta(days=plan.max_days_approval_to_release), "RELEASE_TOO_LATE", "the batch approval is stale", "manual_reconciliation")
        current = [_control(v) for v in r.bank_controls]
        if plan.require_bank_control:
            for payee in {c["payee_ref"] for c in data["cases"]}:
                baseline = [v for v in data["bank_controls"] if v["payee_ref"] == payee]
                latest = [v for v in current if v["payee_ref"] == payee]
                require(len(baseline) == len(latest) == 1 and _same_scope(latest[0], data["entity_scope"]), "BANK_CONTROL_UNVERIFIED", "each beneficiary needs approved and current independently verified bank control in this execution scope", "manual_reconciliation")
                b, v = baseline[0], latest[0]
                require(v["bank_account_digest"] == b["bank_account_digest"], "BENEFICIARY_CHANGED", "the beneficiary changed after the batch was assembled", "manual_reconciliation")
                require((parsed(at) - parsed(v["created_at"])).total_seconds() >= plan.new_payee_cooling_days * 86400, "NEW_PAYEE_COOLING", "new payee cooling period has not elapsed", "await_approval")
                require(parsed(v["verified_at"]) <= parsed(at), "BANK_CONTROL_UNVERIFIED", "bank verification must predate release", "manual_reconciliation")
        _funding(data["funding_bindings"], data["cases"], plan, at=at, execution_scope=data["entity_scope"])
        require(r.execution_result is not None and r.execution_request is not None, "RELEASE_NOT_EXECUTED", "release requires a completed execution bound to this batch")
        release_receipt(r.execution_result, request=r.execution_request)
        from lightbulb.company_execution_bridge import execution_receipt_from_connector
        execution = execution_receipt_from_connector(r.execution_result, r.execution_request)
        expected = _request(plan, data, command.expected_state_digest, approved=True)
        require(execution.request_digest == expected.custody_fingerprint() and execution.approval_ref == data["authorization_proof"]["approval_task_id"] and execution.project_id == data["entity_scope"]["project_id"], "RELEASE_NOT_EXECUTED", "execution must bind the exact approved run, beneficiary and project")
        require(parsed(data["approved_at"]) <= parsed(execution.completed_at) <= parsed(at), "RELEASE_NOT_EXECUTED", "execution must follow approval and predate its recording")
        data.update(released_total=data["batch_total"], release_journal_ref=execution.journal_ref,
                    release_request_digest=execution.request_digest, released_at=execution.completed_at,
                    unsettled=data["batch_total"])
    elif event == "settle":
        total, settled_at, digests = _settled(r.bank_states, r.payout_reads, run_digest=command.expected_state_digest, data=data, plan=plan, at=at)
        short = Decimal(data["released_total"]) - total
        require(settled_at is not None and abs(short) <= plan.settlement_tolerance, "SETTLEMENT_SHORT", "bank settlement must equal the release inside tolerance", "manual_reconciliation")
        require(parsed(settled_at) <= parsed(at), "SETTLEMENT_SHORT", "settlement cannot be recorded before its bank line")
        data.update(settled_total=str(total), unsettled=str(max(Decimal(0), short)), settled_at=settled_at,
                    settlement_digests=digests, days_approval_to_settlement=(parsed(settled_at)-parsed(data["approved_at"])).days)
    elif event == "reconcile":
        from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
        require(r.close_source is not None, "CLOSE_BEFORE_PAYMENT", "clearance needs a finance close", "manual_reconciliation")
        _, close = _replay(r.close_source, CLOSE_LIFECYCLE, "CLOSE_BEFORE_PAYMENT")
        required_accounts = {"payroll" if c["kind"] == "payroll_run_chain" else "accounts_payable" for c in data["cases"]}
        require(close.status == "closed" and _same_scope(close.scope, data["entity_scope"]) and close.scope.currency == plan.currency and required_accounts <= set(close.ledger.reconciled_accounts), "CLOSE_BEFORE_PAYMENT", "close must reconcile the batch's liabilities in this execution scope and currency", "manual_reconciliation")
        require(parsed(close.transition_history[-1].command.occurred_at) <= parsed(at), "CLOSE_BEFORE_PAYMENT", "the closed finance source must predate its consumption", "manual_reconciliation")
        require(parsed(close.ledger.period_start) <= parsed(data["pay_at"]) <= parsed(close.ledger.period_end) and parsed(close.ledger.period_end) >= parsed(data["settled_at"]), "CLOSE_BEFORE_PAYMENT", "the finance period must cover payment and settlement", "manual_reconciliation")
        data.update(close_ref=close.scope.entity_ref, outcome="reconciled")
    elif event in ("cancel", "require_reconciliation"):
        data["outcome"] = next_status
    return next_status, data


def _guarded_apply(plan: Any, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    try:
        return _apply(plan, next_status, status, data, command)
    except DisbursementError as exc:
        require(False, exc.code, str(exc), RECOVERY_BY_CODE.get(exc.code, "correct_input"))  # type: ignore[arg-type]
        raise AssertionError("unreachable")


DISBURSEMENT_LIFECYCLE = LifecycleSpec(entity="disbursement_run", schema_prefix="disbursement_run", statuses=DISBURSEMENT_STATUSES, terminal=("reconciled", "cancelled", "reconciliation_required"), events=DISBURSEMENT_EVENTS, table=_TABLE, opening_event="assemble", reason_events=("hold", "cancel", "require_reconciliation"), apply=_guarded_apply, ledger_model=DisbursementLedger, receipt_model=DisbursementReceipt, effect_boundary_model=DisbursementEffectBoundary, plan_model=DisbursementPlan, max_transitions=16)
DisbursementRunState = DISBURSEMENT_LIFECYCLE.State


def open_disbursement_run(plan: Any, scope: Any, *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return DISBURSEMENT_LIFECYCLE.open(plan, scope, receipt={**receipt, "entity_scope": detached(scope)}, opened_at=opened_at, actor_ref=actor_ref)


def advance_disbursement_run(plan: Any, state: Any, command: Any) -> Any:
    return DISBURSEMENT_LIFECYCLE.advance(plan, state, command)


def payable_payment_receipts(state: Any, *, plan: Any) -> dict[str, dict[str, Any]]:
    """Return bill-correlated apply_payment receipts derived from proven batch cash."""
    _, run = _replay(_artifact(state, plan), DISBURSEMENT_LIFECYCLE, "SETTLEMENT_SHORT")
    _require(run.status in ("settled", "reconciled") and run.ledger.settled_total == run.ledger.batch_total, "SETTLEMENT_SHORT", "only a fully bank-settled batch pays its individual bills")
    out = {}
    for case in run.ledger.cases:
        if case["kind"] != "payables_chain":
            continue
        out[case["case_ref"]] = {"correlation_sha256": case["correlation"], "payment_evidence_sha256": run.state_digest,
            "applied_amount": case["amount"], "payment_count": 1, "applied_at": run.ledger.settled_at,
            "disbursement_source": _artifact(run, plan), "evidence_refs": [f"disbursement:{run.state_digest}"]}
    return out


def beneficiary_exception(state: Any, *, plan: Any, payee_ref: str, current: Any) -> dict[str, Any]:
    """An exceptions-desk opening for one payee whose bank custody moved after the batch was approved.

    The halt is per payee: the rest of the batch keeps its approval, and the
    desk's evidence is the vendor's own re-verified onboarding snapshot.
    """

    _, run = _replay(_artifact(state, plan), DISBURSEMENT_LIFECYCLE, "BENEFICIARY_CHANGED")
    baseline = next((row for row in run.ledger.bank_controls if row["payee_ref"] == payee_ref), None)
    _require(baseline is not None, "BENEFICIARY_CHANGED", "the batch carries no approved bank control for this payee")
    latest = _control(current)
    _require(latest["payee_ref"] == payee_ref, "BENEFICIARY_CHANGED", "the current snapshot belongs to another payee")
    _require(latest["bank_account_digest"] != baseline["bank_account_digest"], "BENEFICIARY_CHANGED", "this payee's bank custody is unchanged; there is nothing to open")
    return {"kind": BENEFICIARY_EXCEPTION_KIND, "source_engine": DISBURSEMENT_KIND, "code": "BENEFICIARY_CHANGED",
            "source_ref": f"{DISBURSEMENT_KIND}:{run.scope.entity_ref}:{payee_ref}"[:200], "source_digest": run.state_digest,
            "detail": f"{payee_ref} was approved against bank custody {baseline['bank_account_digest'][:16]} and now presents {latest['bank_account_digest'][:16]}, verified by {latest['verification_method']}; the payee is held, the batch is not",
            "evidence_refs": [f"{DISBURSEMENT_KIND}:{run.scope.entity_ref}", f"vendor:{latest['source_digest'][:24]}"]}


def unsettled_exception(state: Any, *, plan: Any) -> dict[str, Any] | None:
    """An opening for released cash the bank never proved; ``None`` once the batch settles in full."""

    _, run = _replay(_artifact(state, plan), DISBURSEMENT_LIFECYCLE, "SETTLEMENT_SHORT")
    _require(run.ledger.released_total > 0, "SETTLEMENT_SHORT", "an unreleased batch has no cash to chase")
    if run.ledger.unsettled <= 0:
        return None
    return {"kind": UNSETTLED_EXCEPTION_KIND, "source_engine": DISBURSEMENT_KIND, "code": "DISBURSEMENT_UNSETTLED",
            "source_ref": f"{DISBURSEMENT_KIND}:{run.scope.entity_ref}"[:200], "source_digest": run.state_digest,
            "detail": f"{run.ledger.unsettled} of {run.ledger.released_total} {run.ledger.currency} released on {run.ledger.released_at} against {run.ledger.correlation} carries no bank line",
            "evidence_refs": [f"{DISBURSEMENT_KIND}:{run.scope.entity_ref}", f"journal:{run.ledger.release_journal_ref}"[:200]]}


def disbursement_summary(state: Any, *, plan: Any) -> dict[str, Any]:
    _, run = _replay(_artifact(state, plan), DISBURSEMENT_LIFECYCLE, "CASE_NOT_APPROVED")
    return {"run_ref": run.scope.entity_ref, "status": run.status, "payee_count": run.ledger.payee_count,
            "case_count": len(run.ledger.case_digests), "batch_total": str(run.ledger.batch_total),
            "released_total": str(run.ledger.released_total), "settled_total": str(run.ledger.settled_total),
            "unsettled": str(run.ledger.unsettled), "holds": [dict(row) for row in run.ledger.holds],
            "approver_ref": run.ledger.approver_ref, "settled_at": run.ledger.settled_at,
            "days_approval_to_settlement": run.ledger.days_approval_to_settlement,
            "correlation": run.ledger.correlation, "outcome": run.ledger.outcome}


DISBURSEMENT_MANIFEST = {
    "schema": "lightbulb.company_engine_manifest.v1", "engine": DISBURSEMENT_KIND,
    "golden_loop": DISBURSEMENT_GOLDEN_LOOP, "stages": ["assemble", "confirm_cover", "approve", "release", "settle", "reconcile"],
    "statuses": list(DISBURSEMENT_STATUSES), "events": list(DISBURSEMENT_EVENTS), "guards": list(DISBURSEMENT_CODES),
    "hops": {"assemble": "approved payable/payroll or reserved obligation state and plan", "confirm_cover": "treasury CashCover", "approve": "AuthorizationProof for the whole batch, naming the assembler as preparer", "release": "vendor bank control and bound completed ConnectorExecutionResult", "settle": f"a bank reconciliation match on this released run, or {list(PAYOUT_ROW_TOOLS)} rows with the provenance of their read", "reconcile": "closed liability reconciliation"},
    "produces": {"payables_chain": "apply_payment receipts derived from the bank-proven batch", "payroll_run_chain": "the batch's payment evidence for its pay runs", "company_cost_centres": "payable cost sources, through the payables cases this run pays", "exceptions_desk": f"a moved beneficiary and an unsettled batch (as {BENEFICIARY_EXCEPTION_KIND} until beneficiary_changed and disbursement_unsettled are registered)"},
    "required_connectors": ["xero", "quickbooks", "billcom", "airwallex", "lightbulb.sdk_engine_state"],
    "hard_rules": ["a batch is approved once, as a total, by someone who did not assemble it", "a changed beneficiary halts the payee, never the whole batch silently", "the SDK emits the payment request; the platform executes and journals it", "a bill is paid when a bank line proves it, not when a provider says so"],
}

__all__ = ["DISBURSEMENT_KIND", "DISBURSEMENT_GOLDEN_LOOP", "DISBURSEMENT_STATUSES", "DISBURSEMENT_EVENTS", "DISBURSEMENT_LIFECYCLE", "DISBURSEMENT_MANIFEST", "DISBURSEMENT_CODES", "RECOVERY_BY_CODE", "PAYOUT_ROW_TOOLS", "BENEFICIARY_EXCEPTION_KIND", "UNSETTLED_EXCEPTION_KIND", "DisbursementPlan", "DisbursementReceipt", "DisbursementLedger", "DisbursementEffectBoundary", "DisbursementRunState", "DisbursementError", "compile_disbursement_run", "open_disbursement_run", "advance_disbursement_run", "assemble_receipt", "cover_receipt", "bank_control_receipt", "release_request", "release_receipt", "settle_receipt", "payout_rows_receipt", "clear_receipt", "payable_payment_receipts", "beneficiary_exception", "unsettled_exception", "disbursement_summary"]
