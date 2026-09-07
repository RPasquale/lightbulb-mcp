"""The payroll run chain: one replay-fenced lifecycle from a drafted pay run to wages paid, statutory liabilities reserved, and the payroll account reconciled.

Payroll is the largest and least reversible outflow a company makes and the
SDK could not run one.  Treasury carried payroll as a typed ``PayrollSchedule``
inside the module whose own rule is that nothing is estimated into a chat; the
compliance calendar sized PAYG withholding, superannuation, and payroll tax
from ``estimated_payroll_per_month``; the fortnightly close required a payroll
reconciliation nothing could produce.  This chain proves the run instead::

    drafted -> timesheets_approved -> costed -> approved -> funded
            -> paid -> liabilities_reserved -> reconciled     (terminal)
    drafted | timesheets_approved | costed -> rejected        (terminal)
    costed | approved | funded | paid -> reconciliation_required

* ``draft_receipt`` opens the run from the provider's own pay-run read and
  reduces every row to run-level aggregates and hashed opaque worker refs
  before anything crosses the boundary; a payload that names a person is
  refused.  A period already paid on the same provider is refused as a
  duplicate: one pay period is paid once.
* ``timesheet_receipt`` consumes approved timesheets only, and refuses hours
  no worker could have worked in the period.
* ``cost_receipt`` consumes the provider's payroll summary, hashed against the
  read's ``output_digest``.  The SDK never computes statutory withholding: it
  checks the provider's numbers against the sealed basis (gross equals net
  plus withholding plus deductions) and against the prior run's sealed state.
* ``approve`` consumes an authority matrix proof bound to this exact command,
  plan, run and net amount. An ``ApprovalBinding`` alone is insufficient.
* ``cover_receipt`` consumes a treasury ``CashCover``: no run is funded that
  the cover cannot clear.
* ``payment_receipt`` consumes a bank reconciliation match, or a bank line
  read whose reference carries this run's ``LB-PAY-`` correlation.
* ``liability_receipt_for`` sizes the compliance calendar's PAYG,
  superannuation, and payroll-tax reservations from *this* run instead of an
  estimate, and ``payroll_source_balance`` is the ``SourceBalance(kind=
  'payroll')`` the fortnightly close demands.  ``period_evidence_receipt``
  carries labour cost to the cost centre register and ``payroll_flows``
  replaces the typed payroll schedule in the cash forecast.

Nothing here reads a provider, moves money, lodges anything, or posts a
journal. Receipts retain the original privacy-checked provider documents and
provenance, treasury forecast, and source plans; replay rederives every value.
"""

from __future__ import annotations

import re
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
    parsed,
    percent_value,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import ApprovalBinding, ObservationProvenance
from lightbulb.company_treasury import CASH_COVER_SCHEMA, CashCover, ScheduledFlow
from lightbulb.finance_close_observations import SourceBalance

PAYROLL_RUN_KIND = "payroll_run_chain"
PAYROLL_RUN_SCHEMA_PREFIX = "payroll_run"
PAYROLL_RUN_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
PAYROLL_RUN_PLAN_SCHEMA = "lightbulb.payroll_run_plan.v1"
BANK_MATCH_SCHEMA = "lightbulb.bank_reconciliation_match.v1"
PAY_CORRELATION_PREFIX = "LB-PAY-"
MAX_PAY_RUN_TRANSITIONS = 24

# Governed Xero observations and existing host reads retain their distinct provenance lanes.
RUN_TOOLS: tuple[str, ...] = ("xero.observe_payrun", "xero.list_payroll_au_payruns", "quickbooks.payroll_payslips", "host.payroll_run_summary")
TIMESHEET_TOOLS: tuple[str, ...] = ("xero.observe_timesheets", "xero.list_payroll_au_timesheets", "host.payroll_timesheets")
COST_TOOLS: tuple[str, ...] = ("xero.observe_payrun", "xero.payroll_summary_report", "host.payroll_run_summary")
PAYMENT_TOOLS: tuple[str, ...] = ("xero.list_bank_transactions", "airwallex.list_transactions", "host.bank_lines")
PROPOSED_GOVERNED_READ: dict[str, Any] = {
    "tool": "xero.observe_payrun",
    "effect": "read",
    "emits": ["run_ref", "period_start", "period_end", "pay_date", "gross", "withholding", "employer_super", "deductions", "net", "headcount", "correlation"],
    "why": "run-level aggregates only; payslip rows never need to leave the provider",
}

LIABILITY_KINDS: tuple[str, ...] = ("payg_withholding", "superannuation", "payroll_tax")
Jurisdiction = Literal["AU", "CA", "US", "UK", "NZ"]
PayrollProvider = Literal["xero", "quickbooks", "host"]

PAY_RUN_STATUSES: tuple[str, ...] = ("drafted", "timesheets_approved", "costed", "approved", "funded", "paid", "liabilities_reserved", "reconciled", "rejected", "reconciliation_required")
TERMINAL_PAY_RUN_STATUSES: frozenset[str] = frozenset({"reconciled", "rejected", "reconciliation_required"})
PAY_RUN_EVENTS: tuple[str, ...] = ("draft_run", "attach_timesheets", "cost_run", "approve", "confirm_cover", "apply_payment", "reserve_liabilities", "reconcile_payroll", "reject", "require_reconciliation")
_PAY_RUN_TABLE: dict[tuple[str, str], str] = {
    ("new", "draft_run"): "drafted",
    ("drafted", "attach_timesheets"): "timesheets_approved",
    ("timesheets_approved", "cost_run"): "costed",
    ("drafted", "cost_run"): "costed",  # a salaried run carries no timesheets
    ("costed", "approve"): "approved",
    ("approved", "confirm_cover"): "funded",
    ("funded", "apply_payment"): "paid",
    ("paid", "reserve_liabilities"): "liabilities_reserved",
    ("liabilities_reserved", "reserve_liabilities"): "liabilities_reserved",  # one reservation per obligation kind
    ("liabilities_reserved", "reconcile_payroll"): "reconciled",
    **{(status, "reject"): "rejected" for status in ("drafted", "timesheets_approved", "costed")},
    **{(status, "require_reconciliation"): "reconciliation_required" for status in ("costed", "approved", "funded", "paid")},
}
_PROVEN_RUN_STATUSES: frozenset[str] = frozenset({"paid", "liabilities_reserved", "reconciled"})
_HUNDRED = Decimal("100")


class PayrollPlan(StrictModel):
    """What the chain enforces: the cycle, the tolerances a run may drift inside, and whether cover and an independent approver are required."""

    schema_id: Literal["lightbulb.payroll_run_plan.v1"] = Field(default=PAYROLL_RUN_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: Jurisdiction = "AU"
    provider: PayrollProvider = "xero"
    pay_cycle_days: int = Field(default=14, ge=1, le=31)
    materiality: Decimal = Field(default=Decimal("1.00"), validate_default=True)
    variance_tolerance_percent: Decimal = Field(default=Decimal("15.00"), validate_default=True)
    headcount_delta_tolerance_percent: Decimal = Field(default=Decimal("20.00"), validate_default=True)
    max_hours_per_worker_per_period: Decimal = Field(default=Decimal("80"), validate_default=True)
    require_cash_cover: bool = True
    require_independent_approver: bool = True
    max_days_pay_to_reserve: int = Field(default=14, ge=1, le=120)
    centre_ref: OpaqueRef = "cost_centre:labour"
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("materiality", "max_hours_per_worker_per_period", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("variance_tolerance_percent", "headcount_delta_tolerance_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PayrollPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(PayrollPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_payroll_run(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> PayrollPlan:
    return seal(PayrollPlan, {"company_ref": company_ref, "currency": currency.upper(), **dict(overrides or {})}, "plan_digest")


class PayRunReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    entity_scope: EngineScope | None = None
    source_provenance: ObservationProvenance | None = None
    source_payload: dict[str, Any] | tuple[dict[str, Any], ...] | None = None
    paid_sources: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    prior_source: dict[str, Any] | None = None
    close_source: dict[str, Any] | None = None
    cover_source: dict[str, Any] | None = None
    forecast_source: dict[str, Any] | None = None
    bank_source: dict[str, Any] | None = None
    authorization_proof: dict[str, Any] | None = None
    run_ref: OpaqueRef | None = None
    provider: ShortText | None = None
    provider_status: ShortText | None = None
    period_start: str | None = None
    period_end: str | None = None
    pay_date: str | None = None
    headcount: int | None = Field(default=None, ge=0, le=100000)
    worker_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    period_key: OpaqueRef | None = None
    paid_period_keys: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    payment_correlation: OpaqueRef | None = None
    draft_digest: Sha256Digest | None = None
    timesheet_status: ShortText | None = None
    timesheet_count: int | None = Field(default=None, ge=0, le=100000)
    worker_count: int | None = Field(default=None, ge=0, le=100000)
    total_hours: Decimal | None = None
    max_worker_hours: Decimal | None = None
    timesheet_digest: Sha256Digest | None = None
    gross: Decimal | None = None
    withholding: Decimal | None = None
    employer_super: Decimal | None = None
    employer_tax: Decimal | None = None
    deductions: Decimal | None = None
    net: Decimal | None = None
    cost_source: ShortText | None = None
    cost_digest: Sha256Digest | None = None
    observed_at: str | None = None
    prior_run_digest: Sha256Digest | None = None
    prior_net: Decimal | None = None
    prior_headcount: int | None = Field(default=None, ge=0, le=100000)
    locked_through: str | None = None
    approval_ref: OpaqueRef | None = None
    approver_ref: OpaqueRef | None = None
    approved_at: str | None = None
    approved_amount: Decimal | None = None
    approval_binding_digest: Sha256Digest | None = None
    approval_event: ShortText | None = None
    approval_plan_digest: Sha256Digest | None = None
    approval_entity_ref: OpaqueRef | None = None
    cover_digest: Sha256Digest | None = None
    forecast_digest: Sha256Digest | None = None
    cover_amount: Decimal | None = None
    shortfall: Decimal | None = None
    covered: bool | None = None
    cover_week: int | None = Field(default=None, ge=1, le=104)
    payment_amount: Decimal | None = None
    paid_at: str | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    liability_kind: ShortText | None = None
    liability_amount: Decimal | None = None
    liability_source: ShortText | None = None
    liability_digest: Sha256Digest | None = None
    close_ref: OpaqueRef | None = None
    close_state_digest: Sha256Digest | None = None
    reconciliation_ref: OpaqueRef | None = None
    reconciled_payroll: bool | None = None
    close_period_start: str | None = None
    close_period_end: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "worker_refs", "paid_period_keys", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("gross", "withholding", "employer_super", "employer_tax", "deductions", "net", "total_hours", "max_worker_hours", "approved_amount", "cover_amount", "shortfall", "payment_amount", "liability_amount", "prior_net", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("period_start", "period_end", "pay_date", "observed_at", "locked_through", "approved_at", "paid_at", "close_period_start", "close_period_end")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class PayRunLedger(StrictModel):
    entity_scope: EngineScope | None = None
    authorization_proof_digest: Sha256Digest | None = None
    worker_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    run_ref: str | None = None
    provider: str | None = None
    provider_status: str | None = None
    period_start: str | None = None
    period_end: str | None = None
    period_key: str | None = None
    pay_date: str | None = None
    headcount: int | None = None
    preparer_ref: str | None = None
    drafted_at: str | None = None
    draft_digest: str | None = None
    timesheet_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    timesheet_workers: int | None = None
    timesheet_digest: str | None = None
    gross: Decimal = Field(default=Decimal("0"), validate_default=True)
    withholding: Decimal = Field(default=Decimal("0"), validate_default=True)
    employer_super: Decimal = Field(default=Decimal("0"), validate_default=True)
    employer_tax: Decimal = Field(default=Decimal("0"), validate_default=True)
    deductions: Decimal = Field(default=Decimal("0"), validate_default=True)
    net: Decimal = Field(default=Decimal("0"), validate_default=True)
    cost_source: str | None = None
    cost_digest: str | None = None
    cost_observed_at: str | None = None
    prior_run_digest: str | None = None
    variance_percent: Decimal | None = None
    headcount_delta_percent: Decimal | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    approved_at: str | None = None
    approval_binding_digest: str | None = None
    cover_digest: str | None = None
    funded_at: str | None = None
    payment_correlation: str | None = None
    payment_evidence_sha256: str | None = None
    paid_at: str | None = None
    days_draft_to_paid: int | None = None
    liabilities_reserved: tuple[str, ...] = Field(default_factory=tuple, max_length=8)
    reserved_at: str | None = None
    close_ref: str | None = None
    reconciled_at: str | None = None
    reject_reason: str | None = None
    reconciliation_reason: str | None = None
    outcome: Literal["open", "reconciled", "rejected", "reconciliation_required"] = "open"

    @field_validator("liabilities_reserved", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("timesheet_hours", "gross", "withholding", "employer_super", "employer_tax", "deductions", "net", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("variance_percent", "headcount_delta_percent", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class PayRunEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    payroll_filed: Literal[False] = False
    wages_paid: Literal[False] = False
    liability_lodged: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _days(start: str | None, end: str) -> int:
    if not start:
        return 0
    return (parsed(end) - parsed(start)).days


def _dec(data: Mapping[str, Any], key: str) -> Decimal:
    return Decimal(str(data.get(key) or "0"))


def _apply_pay_run(plan: PayrollPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "draft_run":
        require(r.entity_scope is not None and r.entity_scope.currency == plan.currency, "SCOPE_MISMATCH", "the opening receipt must bind the authenticated payroll scope and currency")
        data["entity_scope"] = r.entity_scope.to_dict()
        data["worker_refs"] = list(r.worker_refs)
        require(r.run_ref is not None and r.period_start is not None and r.period_end is not None and r.pay_date is not None and r.headcount is not None and r.provider is not None and r.period_key is not None and r.payment_correlation is not None, "RUN_MISSING", "a drafted run names the provider run, the period, the pay date, the head count, the read it came from, and its payment correlation")
        require(r.provider == plan.provider, "PROVIDER_NOT_PLANNED", f"the read came from {r.provider}; this plan runs payroll on {plan.provider}, and the replay fence is keyed on the provider")
        require(parsed(r.period_end) > parsed(r.period_start), "PAY_PERIOD_INVERTED", "period_end must be after period_start")
        require(_days(r.period_start, r.period_end) <= plan.pay_cycle_days, "PAY_PERIOD_TOO_LONG", f"the period spans {_days(r.period_start, r.period_end)} day(s); the cycle is {plan.pay_cycle_days}")
        require(r.period_key not in tuple(r.paid_period_keys or ()), "DUPLICATE_PAY_PERIOD", f"a run for {r.period_start[:10]}..{r.period_end[:10]} on {r.provider} is already paid; one pay period is paid once", "do_not_replay")
        data.update({"run_ref": r.run_ref, "provider": r.provider, "provider_status": r.provider_status, "period_start": r.period_start, "period_end": r.period_end, "period_key": r.period_key, "pay_date": r.pay_date, "headcount": r.headcount, "preparer_ref": command.actor_ref, "drafted_at": at, "draft_digest": r.draft_digest, "payment_correlation": r.payment_correlation})
    elif event == "attach_timesheets":
        require(r.timesheet_status is not None and r.total_hours is not None and r.worker_count is not None and r.timesheet_digest is not None, "TIMESHEET_MISSING", "attached timesheets carry their status, the total hours, the worker count, and the digest of the read")
        require(r.timesheet_status.upper() == "APPROVED", "TIMESHEET_NOT_APPROVED", f"the timesheets are {r.timesheet_status}; only approved timesheets cost a run")
        require(r.max_worker_hours is None or r.max_worker_hours <= plan.max_hours_per_worker_per_period, "TIMESHEET_HOURS_IMPLAUSIBLE", f"a worker is recorded at {r.max_worker_hours} hours against a ceiling of {plan.max_hours_per_worker_per_period} for the period")
        data.update({"timesheet_hours": str(r.total_hours), "timesheet_workers": r.worker_count, "timesheet_digest": r.timesheet_digest})
    elif event == "cost_run":
        require(r.cost_source is not None and r.cost_digest is not None and r.observed_at is not None and r.gross is not None and r.withholding is not None and r.net is not None, "CALCULATION_NOT_OBSERVED", "the SDK never computes statutory withholding; cost_run consumes the provider's own payroll report with its provenance")
        deductions = r.deductions if r.deductions is not None else Decimal("0")
        drift = (r.gross - (r.net + r.withholding + deductions)).copy_abs()
        require(drift <= plan.materiality, "GROSS_NET_MISMATCH", f"gross {r.gross} is not net {r.net} + withholding {r.withholding} + deductions {deductions}; off by {drift}", "manual_reconciliation")
        require(r.locked_through is None or parsed(str(data["pay_date"])) > parsed(r.locked_through), "PERIOD_LOCKED", f"the pay date {data['pay_date']} falls inside the finance period closed through {r.locked_through}", "manual_reconciliation")
        variance = None
        if r.prior_net is not None and r.prior_net > 0:
            variance = ((r.net - r.prior_net) * _HUNDRED / r.prior_net).quantize(MONEY_QUANTUM)
            require(variance.copy_abs() <= plan.variance_tolerance_percent, "NET_PAY_VARIANCE_ABOVE_TOLERANCE", f"net pay moved {variance}% against the prior sealed run; the plan tolerates {plan.variance_tolerance_percent}%", "await_approval")
        delta = None
        if r.prior_headcount is not None and r.prior_headcount > 0:
            delta = (Decimal(int(data.get("headcount") or 0) - r.prior_headcount) * _HUNDRED / Decimal(r.prior_headcount)).quantize(MONEY_QUANTUM)
            require(delta.copy_abs() <= plan.headcount_delta_tolerance_percent, "HEADCOUNT_DELTA_ABOVE_TOLERANCE", f"head count moved {delta}% against the prior sealed run; the plan tolerates {plan.headcount_delta_tolerance_percent}%", "await_approval")
        data.update({"gross": str(r.gross), "withholding": str(r.withholding), "employer_super": str(r.employer_super or 0), "employer_tax": str(r.employer_tax or 0), "deductions": str(deductions), "net": str(r.net), "cost_source": r.cost_source, "cost_digest": r.cost_digest, "cost_observed_at": r.observed_at, "prior_run_digest": r.prior_run_digest, "variance_percent": None if variance is None else str(variance), "headcount_delta_percent": None if delta is None else str(delta)})
    elif event == "approve":
        proof = None
        if r.authorization_proof is not None:
            from lightbulb.authority_matrix import require_authorization_proof
            proof = require_authorization_proof(r.authorization_proof, category="payroll", amount=data["net"], currency=plan.currency, company_ref=plan.company_ref, plan_digest=plan.plan_digest, command=command, entity_ref=data["entity_scope"]["entity_ref"], preparer_ref=data["preparer_ref"])
            fields = {"approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref, "approved_at": proof.decided_at, "approved_amount": proof.amount, "approval_binding_digest": proof.approval_receipt_digest, "approval_plan_digest": proof.plan_digest, "approval_event": proof.event, "approval_entity_ref": proof.entity_ref}
            require(all(getattr(r, key) is None or getattr(r, key) == value for key, value in fields.items()), "APPROVAL_BINDING_MISMATCH", "approval projections must equal the independently proven decision")
            r = PayRunReceipt.model_validate({**r.to_dict(), **fields})
        require(r.approval_ref is not None and r.approver_ref is not None and r.approved_at is not None and r.approved_amount is not None, "APPROVAL_MISSING", "an approval names the task, the approver, the decision time, and the amount approved")
        require(r.approval_binding_digest is not None, "APPROVAL_NOT_BOUND", "an approval reaches the chain as a sealed ApprovalBinding that commits the task; a typed approval reference is never authority")
        require(r.approval_plan_digest == plan.plan_digest and r.approval_event == "approve", "APPROVAL_BINDING_MISMATCH", f"the sealed binding commits {r.approval_event!r} under plan {str(r.approval_plan_digest)[:16]}; this run is approved under {plan.plan_digest[:16]}, and a binding is authority for one exact command only", "manual_reconciliation")
        if plan.require_independent_approver:
            require(r.approver_ref not in (data.get("preparer_ref"), command.actor_ref), "APPROVER_IS_PREPARER", "the operator who drafted the run cannot approve it", "manual_reconciliation")
        require((r.approved_amount - _dec(data, "net")).copy_abs() <= plan.materiality, "APPROVED_AMOUNT_MISMATCH", f"approved {r.approved_amount} differs from the run's net pay {data.get('net')}", "manual_reconciliation")
        require(proof is not None, "APPROVAL_NOT_BOUND", "payroll requires an independently bound authority proof for this exact command", "await_approval")
        assert proof is not None
        require(proof.approval_task_id == r.approval_ref and proof.approver_ref == r.approver_ref and proof.amount == r.approved_amount, "APPROVAL_BINDING_MISMATCH", "approval projections must identify the proven decision and exact net amount")
        data["authorization_proof_digest"] = proof.proof_digest
        data.update({"approval_ref": r.approval_ref, "approver_ref": r.approver_ref, "approved_at": r.approved_at, "approval_binding_digest": r.approval_binding_digest})
    elif event == "confirm_cover":
        if plan.require_cash_cover:
            require(r.cover_digest is not None and r.forecast_digest is not None and r.cover_amount is not None and r.covered is not None, "COVER_MISSING", "the plan requires a treasury cash cover before wages are funded")
            require(bool(r.covered), "CASH_COVER_INSUFFICIENT", f"the cover is short by {r.shortfall}; no pay run is funded that the treasury cover cannot clear", "await_approval")
            require((r.cover_amount - _dec(data, "net")).copy_abs() <= plan.materiality, "COVER_AMOUNT_MISMATCH", f"the cover judged {r.cover_amount}; the run pays {data.get('net')}", "manual_reconciliation")
        data.update({"cover_digest": r.cover_digest, "funded_at": at})
    elif event == "apply_payment":
        require(r.payment_correlation is not None and r.payment_amount is not None and r.paid_at is not None and r.payment_evidence_sha256 is not None, "PAYMENT_MISSING", "an applied payment carries the correlation, the amount, the time, and the evidence digest")
        require(r.payment_correlation == data.get("payment_correlation"), "PAYMENT_CORRELATION_MISMATCH", f"the bank line carries {r.payment_correlation}; this run is {data.get('payment_correlation')}", "manual_reconciliation")
        require((r.payment_amount - _dec(data, "net")).copy_abs() <= plan.materiality, "PAYMENT_AMOUNT_MISMATCH", f"the bank moved {r.payment_amount}; the run pays {data.get('net')}", "manual_reconciliation")
        data.update({"payment_evidence_sha256": r.payment_evidence_sha256, "paid_at": r.paid_at, "days_draft_to_paid": _days(data.get("drafted_at"), r.paid_at)})
    elif event == "reserve_liabilities":
        require(r.liability_kind in LIABILITY_KINDS and r.liability_amount is not None and r.liability_digest is not None and r.observed_at is not None, "LIABILITY_MISSING", f"a reservation names one of {list(LIABILITY_KINDS)} with the amount this run proved, its digest, and the observation time")
        reserved = tuple(data.get("liabilities_reserved") or ())
        require(r.liability_kind not in reserved, "LIABILITY_ALREADY_RESERVED", f"{r.liability_kind} is already reserved from this run", "do_not_replay")
        require((r.liability_amount - _dec(data, _LIABILITY_FIELDS[str(r.liability_kind)])).copy_abs() <= plan.materiality, "LIABILITY_AMOUNT_MISMATCH", f"the reservation is for {r.liability_amount}; this run reported {data.get(_LIABILITY_FIELDS[str(r.liability_kind)])} of {r.liability_kind}", "manual_reconciliation")
        require(_days(data.get("paid_at"), at) <= plan.max_days_pay_to_reserve, "RESERVE_TOO_LATE", f"the reservation came more than {plan.max_days_pay_to_reserve} day(s) after the wages were paid", "manual_reconciliation")
        data.update({"liabilities_reserved": (*reserved, str(r.liability_kind)), "reserved_at": at})
    elif event == "reconcile_payroll":
        if plan.jurisdiction in ("AU", "NZ") and _dec(data, "employer_super") > 0:
            require("superannuation" in tuple(data.get("liabilities_reserved") or ()), "SUPER_UNRESERVED", "the quarter's superannuation obligation is unreserved; reserve it before the run is reconciled")
        require(r.close_ref is not None and r.close_state_digest is not None and bool(r.reconciled_payroll), "PAYROLL_NOT_RECONCILED", "a reconciled run names a closed period that reconciled the payroll account, with its sealed state digest", "manual_reconciliation")
        require(r.close_period_start is not None and r.close_period_end is not None and parsed(r.close_period_start) <= parsed(str(data["pay_date"])) <= parsed(r.close_period_end), "CLOSE_PERIOD_MISMATCH", f"the close covers {r.close_period_start}..{r.close_period_end}; this run paid on {data['pay_date']}, so that close reconciled some other period's payroll", "manual_reconciliation")
        data.update({"close_ref": r.close_ref, "reconciled_at": at, "outcome": "reconciled"})
    elif event == "reject":
        data.update({"reject_reason": str(command.reason)[:300], "outcome": "rejected"})
    elif event == "require_reconciliation":
        data.update({"reconciliation_reason": str(command.reason)[:300], "outcome": "reconciliation_required"})
    _verify_retained_receipt(plan, data, command)
    return next_status, data


class _PayrollLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope)}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope.to_dict() != self.ledger.entity_scope.to_dict():
                    raise ValueError("SCOPE_MISMATCH: payroll state must equal its replayed opening scope")
                return self
        self.State = ScopedState


PAYROLL_LIFECYCLE = _PayrollLifecycle(entity="pay_run", schema_prefix=PAYROLL_RUN_SCHEMA_PREFIX, statuses=PAY_RUN_STATUSES, terminal=TERMINAL_PAY_RUN_STATUSES, events=PAY_RUN_EVENTS, table=_PAY_RUN_TABLE, opening_event="draft_run", reason_events=("reject", "require_reconciliation"), apply=_apply_pay_run, ledger_model=PayRunLedger, receipt_model=PayRunReceipt, effect_boundary_model=PayRunEffectBoundary, plan_model=PayrollPlan, max_transitions=MAX_PAY_RUN_TRANSITIONS)
PayRunState = PAYROLL_LIFECYCLE.State


def open_pay_run(plan: PayrollPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return PAYROLL_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_pay_run(plan: PayrollPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return PAYROLL_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from the hops' sealed artifacts
# --------------------------------------------------------------------------- #


class PayrollRunError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PayrollRunError(code, message)


_IDENTITY_SUBSTRINGS: tuple[str, ...] = ("firstname", "first_name", "lastname", "last_name", "fullname", "full_name", "middlename", "middle_name", "surname", "givenname", "given_name", "preferred_name", "legal_name", "employeename", "employee_name", "email", "phone", "address", "date_of_birth", "birth_date", "tax_file", "national_insurance", "bank_account", "account_number")
_IDENTITY_KEYS: frozenset[str] = frozenset({"name", "tfn", "ssn", "sin", "nino", "dob", "bsb", "birthdate"})
_MS_DATE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")


def _reject_identity(value: Any, *, path: str = "payload") -> None:
    """Payroll payloads reach the engine as run-level aggregates and opaque worker refs, never as people."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            _require(lowered not in _IDENTITY_KEYS and not any(marker in lowered for marker in _IDENTITY_SUBSTRINGS), "IDENTITY_IN_PAYROLL_PAYLOAD", f"{path}.{key} names a person; reduce the read to run-level aggregates and hashed worker refs first")
            _reject_identity(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_identity(item, path=f"{path}[{index}]")


def _stamp(value: Any, *, field_name: str) -> str:
    text = str(value).strip()
    match = _MS_DATE.match(text)
    if match:
        text = datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    elif "T" not in text:
        text = f"{text}T00:00:00Z"
    elif not text.endswith("Z"):
        instant = datetime.fromisoformat(text)
        text = instant.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") if instant.tzinfo is None else instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return timestamp(text, field_name=field_name)


def _worker_ref(value: Any) -> str:
    return f"worker:{stable_digest({'employee': str(value)})[:24]}"


def _period_key(provider: str, period_start: str, period_end: str) -> str:
    return f"payperiod:{stable_digest({'provider': provider, 'period_start': period_start, 'period_end': period_end})[:24]}"


def _provenance(value: ObservationProvenance | Mapping[str, Any]) -> ObservationProvenance:
    read = ObservationProvenance.model_validate(dict(detached(value)))
    _require(read.schema_id == "lightbulb.engine_observation_provenance.v1" and read.provenance_digest != GENESIS_DIGEST, "OBSERVATION_DIGEST_MISMATCH", "the source must carry real observation provenance")
    return read


def _expect_tool(provenance: ObservationProvenance, tools: Sequence[str]) -> None:
    _require(provenance.source_tool in tuple(tools), "OBSERVATION_TOOL_MISMATCH", f"this hop reads {tuple(tools)}; provenance names {provenance.source_tool}")
    if provenance.source_tool in {"xero.observe_payrun", "xero.observe_timesheets"}:
        _require(provenance.lane == "governed_read", "OBSERVATION_TOOL_MISMATCH", "governed payroll tools require governed read provenance")
    else:
        _require(tuple(tools) not in (RUN_TOOLS, TIMESHEET_TOOLS, COST_TOOLS) or provenance.lane == "host_read", "OBSERVATION_TOOL_MISMATCH", "payroll reads must arrive on their admitted host lane")


def _expect_content(provenance: ObservationProvenance, payload: Any) -> None:
    """Every payload is hashed against the read's ``output_digest``: provenance proves a read happened, only the content digest proves it read *this*."""

    _require(stable_digest(payload) == provenance.output_digest, "OBSERVATION_DIGEST_MISMATCH", f"the payload does not hash to the output digest of {provenance.observation_ref}; these are not the rows the platform read")


def _provider_of(provenance: ObservationProvenance) -> str:
    """The provider behind a read tool (``xero.list_payroll_au_payruns`` -> ``xero``), so the replay fence is keyed on the provider and not on which of its reads was used."""

    return str(provenance.source_tool).split(".", 1)[0]


def _amount(value: Any, name: str) -> Decimal:
    return decimal_value(str(value if value not in (None, "") else "0"), field_name=name)


def _governed_payrun(raw: Mapping[str, Any]) -> None:
    import re
    _require(raw.get("schema") == "lightbulb.xero_payrun_observation.v1"
        and raw.get("disposition") == "POSTED" and raw.get("pay_run_status") == "POSTED",
        "PAYRUN_NOT_POSTED", "cost intake requires a complete posted governed pay run")
    _require(re.fullmatch(r"[0-9a-f]{64}", str(raw.get("pay_run_id_sha256", ""))) is not None,
        "RUN_REF_MISSING", "governed payroll identity must be committed")
    fields = ("wages_minor", "net_pay_minor", "tax_minor", "deductions_minor", "super_minor")
    rows = raw.get("workers", ())
    _require(isinstance(rows, list) and 0 < len(rows) <= 500 and type(raw.get("headcount")) is int
        and len(rows) == raw.get("headcount") and all(isinstance(row, Mapping) for row in rows),
        "RUN_HEADCOUNT_MISSING", "all workers must be present in the governed pay run")
    refs = [row.get("employee_id_sha256") for row in rows]
    _require(all(re.fullmatch(r"[0-9a-f]{64}", str(ref)) for ref in refs) and len(set(refs)) == len(refs),
        "WORKER_DUPLICATE", "payroll worker commitments must be valid and unique")
    for field in fields:
        amounts = [raw.get(field), *[row.get(field) for row in rows]]
        _require(all(type(amount) is int and 0 <= amount <= 10**14 for amount in amounts),
            "PAYROLL_NOT_INTEGER", "provider payroll amounts must retain integer minor units")
        _require(sum(amounts[1:]) == amounts[0], "PAYROLL_TOTAL_MISMATCH", "worker rows must conserve every payroll total")
    _require(type(raw.get("reimbursement_minor", 0)) is int and 0 <= raw.get("reimbursement_minor", 0) <= 10**14,
        "PAYROLL_NOT_INTEGER", "reimbursements must retain integer minor units")


def draft_receipt(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any], *, paid_runs: Sequence[Any] = (), paid_plans: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The opening receipt from the provider's pay-run read, reduced to run-level aggregates and hashed worker refs.

    ``paid_runs`` are this company's sealed pay-run states; the periods among
    them that were actually paid become the replay fence the engine refuses a
    second run against.
    """

    read = _provenance(provenance)
    _expect_tool(read, RUN_TOOLS)
    raw = dict(detached(payload))
    _reject_identity(raw)
    _expect_content(read, raw)
    provider = _provider_of(read)
    runs = raw.get("PayRuns") if isinstance(raw.get("PayRuns"), list) else (raw.get("pay_runs") if isinstance(raw.get("pay_runs"), list) else None)
    _require(runs is None or len(runs) == 1, "RUN_AMBIGUOUS", "a payroll source must identify exactly one provider run")
    row = dict(detached(runs[0])) if runs else raw
    governed = read.source_tool == "xero.observe_payrun"
    if governed:
        _governed_payrun(raw)
    run_ref = ("payrun:" + raw["pay_run_id_sha256"][:16]) if governed else str(row.get("PayRunID") or row.get("pay_run_id") or row.get("run_ref") or row.get("id") or "")
    _require(bool(run_ref), "RUN_REF_MISSING", "the read names the provider's pay run")
    period_start, period_end = row.get("PayRunPeriodStartDate") or row.get("period_start"), row.get("PayRunPeriodEndDate") or row.get("period_end")
    pay_date = row.get("PaymentDate") or row.get("pay_date") or (row.get("payment_date") if governed else None)
    _require(bool(period_start) and bool(period_end) and bool(pay_date), "RUN_PERIOD_MISSING", "the read names the pay period start, its end, and the payment date")
    slips = [dict(detached(item)) for item in (row.get("Payslips") or row.get("payslips") or ())]
    worker_refs = [_worker_ref(slip.get("EmployeeID") or slip.get("employee_ref") or index) for index, slip in enumerate(slips)]
    if governed:
        worker_refs = ["worker:" + item["employee_id_sha256"][:24] for item in raw["workers"]]
    headcount = len(worker_refs) or int(row.get("headcount") or row.get("payslip_count") or 0)
    _require(headcount > 0, "RUN_HEADCOUNT_MISSING", "a pay run covers at least one worker")
    start, end = _stamp(period_start, field_name="period_start"), _stamp(period_end, field_name="period_end")
    already: list[str] = []
    sources = []
    for state in paid_runs:
        source_plan = (paid_plans or {}).get(detached(state).get("plan_digest"))
        _, state = _replay_run(state, source_plan)
        sources.append({"state": state.to_dict(), "source_plan": detached(source_plan)})
        ledger = getattr(state, "ledger", None)
        if ledger is None or getattr(state, "status", "") not in _PROVEN_RUN_STATUSES:
            continue
        already.append(str(ledger.period_key or _period_key(str(ledger.provider), str(ledger.period_start), str(ledger.period_end))))
    return {
        "source_provenance": read.to_dict(), "source_payload": raw, "paid_sources": sources,
        "run_ref": run_ref,
        "provider": provider,
        "provider_status": str(row.get("PayRunStatus") or row.get("status") or (raw["pay_run_status"] if governed else "DRAFT")),
        "period_start": start,
        "period_end": end,
        "pay_date": _stamp(pay_date, field_name="pay_date"),
        "headcount": headcount,
        "worker_refs": worker_refs[:500],
        "period_key": _period_key(provider, start, end),
        "paid_period_keys": sorted(set(already))[:200],
        "payment_correlation": f"{PAY_CORRELATION_PREFIX}{run_ref}",
        "draft_digest": read.output_digest,
        "evidence_refs": [f"read:{read.observation_ref}"],
    }


def timesheet_receipt(provenance: ObservationProvenance | Mapping[str, Any], payload: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The ``attach_timesheets`` receipt: approved timesheets only, reduced to hours per hashed worker ref."""

    read = _provenance(provenance)
    _expect_tool(read, TIMESHEET_TOOLS)
    raw = detached(payload)
    _reject_identity(raw)
    _expect_content(read, raw)
    rows = raw if isinstance(raw, list) else list(raw.get("Timesheets") or raw.get("timesheets") or ())
    _require(bool(rows), "TIMESHEET_PAYLOAD_EMPTY", "the read carries no timesheet")
    if read.source_tool == "xero.observe_timesheets":
        _require(isinstance(raw, Mapping) and raw.get("schema") == "lightbulb.xero_timesheet_page.v1"
            and raw.get("has_more") is False and type(raw.get("record_count")) is int
            and raw["record_count"] == len(rows) <= 500,
            "TIMESHEET_PAYLOAD_INVALID", "a governed payroll run needs the complete bounded timesheet window")
    hours: dict[str, Decimal] = {}
    for index, record in enumerate(rows):
        item = dict(detached(record))
        status = str(item.get("Status") or item.get("status") or "").upper()
        _require(status == "APPROVED", "TIMESHEET_NOT_APPROVED", f"timesheet {index} is {status or 'unstated'}; only approved timesheets cost a run")
        if read.source_tool == "xero.observe_timesheets":
            import re
            _require(raw.get("schema") == "lightbulb.xero_timesheet_page.v1" and re.fullmatch(r"[0-9a-f]{64}", str(item.get("employee_id_sha256", ""))) is not None,
                "TIMESHEET_PAYLOAD_INVALID", "governed timesheets must retain committed worker identity")
            ref = "worker:" + item["employee_id_sha256"][:24]
            amount = item.get("hours")
        else:
            ref = _worker_ref(item.get("EmployeeID") or item.get("employee_ref") or index)
            amount = item.get("TotalHours", item.get("total_hours"))
        hours[ref] = hours.get(ref, Decimal("0")) + decimal_value(amount, field_name="total_hours")
    return {
        "source_provenance": read.to_dict(), "source_payload": raw,
        "timesheet_status": "APPROVED",
        "timesheet_count": len(rows),
        "worker_count": len(hours),
        "worker_refs": sorted(hours),
        "total_hours": str(sum(hours.values(), Decimal("0")).quantize(MONEY_QUANTUM)),
        "max_worker_hours": str(max(hours.values()).quantize(MONEY_QUANTUM)),
        "timesheet_digest": read.output_digest,
        "evidence_refs": [f"read:{read.observation_ref}"],
    }


_COST_LABELS: dict[str, tuple[str, ...]] = {
    "gross": ("total gross", "gross earnings", "gross pay", "gross wages", "wages", "gross"),
    "withholding": ("payg withholding", "total withholding", "paye", "tax withheld", "withholding"),
    "employer_super": ("superannuation", "super guarantee", "kiwisaver"),
    "employer_tax": ("payroll tax", "employer contributions", "employer ni"),
    "deductions": ("total deductions", "deductions"),
    "net": ("total net pay", "net pay", "net wages"),
}
_HOST_COST_KEYS: dict[str, str] = {"gross": "gross_total", "withholding": "withholding_total", "employer_super": "super_total", "employer_tax": "payroll_tax_total", "deductions": "deductions_total", "net": "net_total"}


def _report_cells(report: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Flatten a provider Reports document into lowercased (label, value) pairs from its rows."""

    out: list[tuple[str, str]] = []

    def walk(rows: Any) -> None:
        for row in rows or []:
            item = dict(detached(row))
            cells = [dict(detached(cell)) for cell in item.get("Cells") or []]
            if len(cells) >= 2:
                out.append((str(cells[0].get("Value", "")).strip().lower(), str(cells[-1].get("Value", "")).strip()))
            walk(item.get("Rows"))

    reports = report.get("Reports") if isinstance(report.get("Reports"), list) else [report]
    for item in reports or []:
        walk(dict(detached(item)).get("Rows"))
    return out


def _match_cost_lines(cells: Sequence[tuple[str, str]]) -> dict[str, Decimal | None]:
    """Assign each report row to at most one line, by its longest matching label.

    A first-token-wins scan mis-reads a report: ``wages`` names gross pay, so a
    row labelled *Net Wages* would be taken as the gross.  The longest matching
    label wins instead, and a row is spent once.
    """

    values: dict[str, Decimal | None] = {field_name: None for field_name in _COST_LABELS}
    for label, value in cells:
        if value in ("", "-"):
            continue
        best, longest = None, 0
        for field_name, labels in _COST_LABELS.items():
            for token in labels:
                if token in label and len(token) > longest:
                    best, longest = field_name, len(token)
        if best is not None and values[best] is None:
            values[best] = _amount(str(value).replace(",", "").replace("(", "").replace(")", ""), best)
    return values


def cost_receipt(provenance: ObservationProvenance | Mapping[str, Any], report: Mapping[str, Any], *, prior_run: Any = None, prior_plan: Any = None, close_state: Any = None, close_plan: Any = None) -> dict[str, Any]:
    """The ``cost_run`` receipt from the provider's payroll summary, hashed against the read's output digest.

    ``prior_run`` is the previous sealed ``PayRunState`` (the variance basis)
    and ``close_state`` a locked or closed finance period (the lock the pay
    date must clear).  Neither number is typed by the caller.
    """

    read = _provenance(provenance)
    _expect_tool(read, COST_TOOLS)
    raw = dict(detached(report))
    _reject_identity(raw)
    _require(stable_digest(raw) == read.output_digest, "LIABILITY_DIGEST_MISMATCH", "the report does not hash to the provenance output digest; these are not the numbers the platform read")
    values: dict[str, Decimal | None] = {}
    if read.source_tool == "xero.observe_payrun":
        _governed_payrun(raw)
        values = {field: Decimal(raw[key])/100 for field, key in {"gross": "wages_minor", "withholding": "tax_minor",
            "net": "net_pay_minor", "deductions": "deductions_minor", "employer_super": "super_minor"}.items()}
        values["gross"] += Decimal(raw.get("reimbursement_minor", 0))/100
    elif read.source_tool == "host.payroll_run_summary":
        for field_name, key in _HOST_COST_KEYS.items():
            values[field_name] = None if raw.get(key) is None else _amount(raw[key], key)
    else:
        values = _match_cost_lines(_report_cells(raw))
    _require(values.get("gross") is not None and values.get("withholding") is not None and values.get("net") is not None, "COST_LINE_NOT_IN_REPORT", "the report must state gross wages, withholding, and net pay")
    out: dict[str, Any] = {
        "source_provenance": read.to_dict(), "source_payload": raw,
        "gross": str(values["gross"]),
        "withholding": str(values["withholding"]),
        "net": str(values["net"]),
        "employer_super": str(values.get("employer_super") or Decimal("0")),
        "employer_tax": str(values.get("employer_tax") or Decimal("0")),
        "deductions": str(values.get("deductions") or Decimal("0")),
        "cost_source": read.source_tool,
        "cost_digest": read.output_digest,
        "observed_at": read.observed_through,
        "evidence_refs": [f"read:{read.observation_ref}"],
    }
    if prior_run is not None:
        _require(getattr(prior_run, "status", "") in _PROVEN_RUN_STATUSES, "PRIOR_RUN_NOT_PROVEN", f"the variance basis is a paid run; the prior run is {getattr(prior_run, 'status', 'missing')}")
        _, prior_run = _replay_run(prior_run, prior_plan)
        out["prior_source"] = {"state": prior_run.to_dict(), "source_plan": detached(prior_plan)}
        out.update({"prior_run_digest": prior_run.state_digest, "prior_net": str(prior_run.ledger.net), "prior_headcount": int(prior_run.ledger.headcount or 0)})
        out["evidence_refs"].append(f"prior_run:{prior_run.state_digest[:16]}")
    if close_state is not None:
        from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
        _, close_state = CLOSE_LIFECYCLE.bind(close_plan, close_state)
        out["close_source"] = {"state": close_state.to_dict(), "source_plan": detached(close_plan)}
        _require(getattr(close_state, "status", "") in ("locked", "approved", "closed"), "CLOSE_NOT_LOCKED", f"a period lock comes from a locked or closed finance period; this one is {getattr(close_state, 'status', 'missing')}")
        out["locked_through"] = str(close_state.ledger.period_end)
        out["evidence_refs"].append(f"close:{close_state.scope.entity_ref}")
    return out


def approval_receipt(task: Mapping[str, Any] | Any, *, binding: ApprovalBinding | Mapping[str, Any] | None = None, run_state: Any = None) -> dict[str, Any]:
    """The ``approve`` receipt from the platform's approved task, bound through ``company_execution_bridge.bind_approval``.

    Without the sealed binding the receipt still carries what the task said and
    the engine refuses it with ``APPROVAL_NOT_BOUND``: a typed approval
    reference is never authority to move wages.  With one, the binding is
    checked against ``run_state`` — the run it claims to approve — because a
    sealed decision about some other entity, plan, or transition is authority
    for that decision and for nothing else.
    """

    raw = dict(detached(task))
    status = str(raw.get("status") or "").upper()
    _require(status == "APPROVED", "TASK_NOT_APPROVED", f"the task is {status or 'missing'}")
    task_ref = str(raw.get("id") or raw.get("task_id") or raw.get("approval_ref") or "")
    _require(bool(task_ref), "APPROVAL_TASK_INVALID", "the approved task carries no id")
    approver = raw.get("decided_by") or raw.get("decidedBy") or raw.get("approved_by")
    decided_at = raw.get("decided_at") or raw.get("decidedAt") or raw.get("approved_at")
    _require(bool(approver) and bool(decided_at), "APPROVAL_DECISION_UNATTRIBUTED", "an approved task names who decided and when")
    action = raw.get("proposed_action") if isinstance(raw.get("proposed_action"), Mapping) else {}
    inputs = action.get("inputs") if isinstance(action.get("inputs"), Mapping) else {}
    amount = raw.get("approved_amount")
    if amount is None:
        amount = action.get("amount", inputs.get("amount"))
    _require(amount is not None, "APPROVED_AMOUNT_MISSING", "the approved task carries the amount it approved")
    out: dict[str, Any] = {"approval_ref": task_ref, "approver_ref": str(approver), "approved_at": _stamp(decided_at, field_name="approved_at"), "approved_amount": str(_amount(amount, "approved_amount")), "evidence_refs": [f"approval:{task_ref}"]}
    if binding is not None:
        bound = binding if isinstance(binding, ApprovalBinding) else ApprovalBinding.model_validate(dict(detached(binding)))
        _require(bound.approval_ref == task_ref, "APPROVAL_BINDING_MISMATCH", f"the binding commits {bound.approval_ref}; the task is {task_ref}")
        _require(bound.decided_by_ref == str(approver), "APPROVAL_BINDING_MISMATCH", "the binding names a different decider than the task")
        _require(run_state is not None, "APPROVAL_BINDING_MISMATCH", "a sealed binding is authority for one exact command; pass run_state so the binding is checked against the run it claims to approve")
        _require(bound.engine == PAYROLL_RUN_KIND, "APPROVAL_BINDING_MISMATCH", f"the binding was decided for the {bound.engine} engine, not {PAYROLL_RUN_KIND}")
        _require(bound.entity_ref == str(run_state.scope.entity_ref), "APPROVAL_BINDING_MISMATCH", f"the binding approves {bound.entity_ref}; this run is {run_state.scope.entity_ref}")
        _require(bound.plan_digest == str(run_state.plan_digest), "APPROVAL_BINDING_MISMATCH", "the binding was decided under a different payroll plan")
        _require(bound.event == "approve", "APPROVAL_BINDING_MISMATCH", f"the binding approves the {bound.event} transition, not approve")
        out.update({"approver_ref": bound.decided_by_ref, "approval_binding_digest": bound.approval_receipt_digest, "approval_event": bound.event, "approval_plan_digest": bound.plan_digest, "approval_entity_ref": bound.entity_ref})
        out["evidence_refs"].append(f"binding:{bound.approval_receipt_digest[:16]}")
    return out


def cover_receipt(cash_cover: CashCover | Mapping[str, Any], *, forecast: Any = None) -> dict[str, Any]:
    """The ``confirm_cover`` receipt from a treasury ``CashCover``; an uncovered judgement is carried, not hidden, so the engine refuses the funding itself."""

    raw = dict(detached(cash_cover))
    _require(raw.get("schema") == CASH_COVER_SCHEMA, "COVER_SCHEMA_MISMATCH", "expected a treasury cash cover")
    cover = CashCover.model_validate(raw)
    from lightbulb.company_treasury import CashForecast, assess_cash_cover
    _require(forecast is not None, "SOURCE_NOT_SEALED", "retain the complete treasury forecast that judged this cover")
    basis = CashForecast.model_validate(detached(forecast))
    expected = assess_cash_cover(basis, amount=cover.amount, at=cover.at)
    _require(expected.to_dict() == cover.to_dict(), "SOURCE_PROJECTION_MISMATCH", "the cover must rederive from its exact forecast")
    return {"cover_source": cover.to_dict(), "forecast_source": basis.to_dict(), "cover_digest": cover.cover_digest, "forecast_digest": cover.forecast_digest, "cover_amount": str(cover.amount), "covered": cover.covered, "shortfall": str(cover.shortfall), "cover_week": cover.week, "detail": cover.detail, "evidence_refs": [f"cover:{cover.cover_digest[:16]}"]}


def payment_receipt(bank_match: Mapping[str, Any] | Any, *, provenance: ObservationProvenance | Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The ``apply_payment`` receipt: a bank reconciliation match, or a bank line whose reference carries this run's ``LB-PAY-`` correlation."""

    raw = dict(detached(bank_match))
    retained = {"bank_source": raw}
    if raw.get("schema") == BANK_MATCH_SCHEMA or raw.get("match_digest") is not None:
        from lightbulb.bank_reconciliation import verify_bank_match_evidence
        try:
            raw = verify_bank_match_evidence(raw)
        except (ValueError, TypeError, AttributeError) as exc:
            raise PayrollRunError("PAYMENT_EVIDENCE_MISSING", "the bank match must replay its exact retained statement and counterpart") from exc
        correlation = str(raw.get("correlation") or raw.get("payment_correlation") or "")
        amount, when = raw.get("amount"), raw.get("occurred_at") or raw.get("matched_at")
        digest = str(raw.get("match_digest") or "")
        _require(bool(digest), "PAYMENT_EVIDENCE_MISSING", "a bank match carries the digest of the reconciled line")
    else:
        _require(provenance is not None, "PAYMENT_PROVENANCE_MISSING", "a bank line reaches the chain with the provenance of the read it came from")
        read = _provenance(provenance)  # type: ignore[arg-type]
        _expect_tool(read, PAYMENT_TOOLS)
        _expect_content(read, raw)
        retained = {"source_provenance": read.to_dict(), "source_payload": raw}
        correlation = str(raw.get("Reference") or raw.get("reference") or raw.get("payment_correlation") or "")
        amount, when, digest = raw.get("Total", raw.get("amount")), raw.get("Date") or raw.get("created_at") or raw.get("occurred_at"), read.provenance_digest
    _require(correlation.startswith(PAY_CORRELATION_PREFIX), "PAYMENT_CORRELATION_MISSING", f"the bank line reference {correlation!r} carries no {PAY_CORRELATION_PREFIX} correlation")
    _require(amount is not None and bool(when), "PAYMENT_EVIDENCE_MISSING", "a payment carries the amount that moved and when it moved")
    kind = str(raw.get("Type") or raw.get("type") or "").upper()
    _require(Decimal(str(amount)) < 0 or kind in {"SPEND", "DEBIT"}, "PAYMENT_DIRECTION_MISMATCH", "payroll payment evidence must prove cash leaving the bank")
    return {**retained, "payment_correlation": correlation, "payment_amount": str(_amount(str(amount).lstrip("-"), "payment_amount")), "paid_at": _stamp(when, field_name="paid_at"), "payment_evidence_sha256": digest, "evidence_refs": [f"bank:{digest[:16]}"]}


def close_receipt(close_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The ``reconcile_payroll`` receipt from a closed finance period; whether it reconciled payroll is carried for the engine's guard to judge."""

    from lightbulb.finance_close_engine import CLOSE_LIFECYCLE
    _, close_state = CLOSE_LIFECYCLE.bind(source_plan, close_state)
    _require(getattr(close_state, "status", "") == "closed", "CLOSE_NOT_CLOSED", f"the close is {getattr(close_state, 'status', 'missing')}")
    ledger = close_state.ledger
    reconciled = tuple(getattr(ledger, "reconciled_accounts", ()) or ())
    ref = next((str(getattr(item, "reconciliation_ref", "")) for item in getattr(ledger, "reconciliations", ()) or () if getattr(item, "account_kind", None) == "payroll"), None) or f"close:{close_state.scope.entity_ref}:payroll"
    return {"close_source": {"state": close_state.to_dict(), "source_plan": detached(source_plan)}, "close_ref": str(close_state.scope.entity_ref), "close_state_digest": close_state.state_digest, "reconciliation_ref": ref, "reconciled_payroll": "payroll" in reconciled, "close_period_start": str(ledger.period_start), "close_period_end": str(ledger.period_end), "evidence_refs": [f"close:{close_state.scope.entity_ref}:{close_state.state_digest[:16]}"]}


# --------------------------------------------------------------------------- #
# What the proven run hands to the other engines
# --------------------------------------------------------------------------- #

_LIABILITY_FIELDS: dict[str, str] = {"payg_withholding": "withholding", "superannuation": "employer_super", "payroll_tax": "employer_tax"}


def _replay_run(run_state: Any, source_plan: Any) -> tuple[Any, Any]:
    _require(source_plan is not None, "SOURCE_PLAN_MISSING", "a payroll source retains its exact plan for replay")
    try:
        return PAYROLL_LIFECYCLE.bind(source_plan, run_state)
    except (ValueError, TypeError, AttributeError) as exc:
        raise PayrollRunError("SOURCE_NOT_SEALED", "the payroll source must replay all original evidence and derived values") from exc


def verify_paid_pay_run(run_state: Any, *, source_plan: Any, company_ref: str | None = None, currency: str | None = None, expected_scope: Any = None, at: str | None = None) -> Any:
    plan, state = _replay_run(run_state, source_plan)
    _require(state.status in _PROVEN_RUN_STATUSES, "RUN_NOT_PAID", "only a paid payroll run is settlement evidence")
    _require((company_ref is None or company_ref == plan.company_ref) and (currency is None or currency == plan.currency), "SCOPE_MISMATCH", "the payroll source belongs to another company or currency")
    if expected_scope is not None:
        _require(_same_scope(state.scope, expected_scope), "SCOPE_MISMATCH", "the payroll source belongs to another authenticated execution scope")
    _require(at is None or parsed(state.transition_history[-1].command.occurred_at) <= parsed(timestamp(at, field_name="at")), "SOURCE_FROM_FUTURE", "payroll evidence cannot come from the future")
    return state


def _same_scope(left: Any, right: Any) -> bool:
    a, b = detached(left), detached(right)
    return all(a.get(key) == b.get(key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _verify_retained_receipt(plan: PayrollPlan, data: Mapping[str, Any], command: Any) -> None:
    r, event, at = command.receipt, command.event, command.occurred_at
    expected: dict[str, Any] | None = None
    try:
        if event in {"draft_run", "attach_timesheets", "cost_run"}:
            _require(r.source_provenance is not None and r.source_payload is not None, "SOURCE_NOT_SEALED", "retain the actual provider read and output before deriving payroll values")
            _require(max(parsed(r.source_provenance.completed_at), parsed(r.source_provenance.observed_through)) <= parsed(at), "SOURCE_FROM_FUTURE", "the command cannot consume a future provider read")
            body = detached(r.source_payload)
            rows = [body, *body.get("PayRuns", body.get("pay_runs", []))] if isinstance(body, dict) else body
            for row in rows:
                label = row.get("company_ref")
                currency = row.get("CurrencyCode", row.get("currency"))
                _require((label is None or label == plan.company_ref) and (currency is None or str(currency).upper() == plan.currency) and (row.get("scope") is None or _same_scope(row["scope"], data["entity_scope"])), "SCOPE_MISMATCH", "declared provider scope must match this payroll company and currency")
            if event == "draft_run":
                expected = draft_receipt(r.source_provenance, body, paid_runs=[s["state"] for s in r.paid_sources], paid_plans={s["state"]["plan_digest"]: s["source_plan"] for s in r.paid_sources})
            elif event == "attach_timesheets":
                expected = timesheet_receipt(r.source_provenance, body)
                _require(set(r.worker_refs) <= set(data.get("worker_refs", ())) if data.get("worker_refs") else r.worker_count <= data["headcount"], "TIMESHEET_RUN_MISMATCH", "timesheets must concern workers on this run")
                rows = body if isinstance(body, list) else body.get("Timesheets", body.get("timesheets", []))
                for row in rows:
                    start, end = row.get("StartDate", row.get("period_start", row.get("start_date"))), row.get("EndDate", row.get("period_end", row.get("end_date")))
                    _require(start is not None and end is not None and parsed(data["period_start"]) <= parsed(_stamp(start, field_name="start")) <= parsed(_stamp(end, field_name="end")) <= parsed(data["period_end"]), "TIMESHEET_RUN_MISMATCH", "timesheets must cover this exact pay period")
            else:
                prior = r.prior_source or {}
                prior_state = _replay_run(prior["state"], prior["source_plan"])[1] if prior else None
                close = r.close_source or {}
                expected = cost_receipt(r.source_provenance, body, prior_run=prior_state, prior_plan=prior.get("source_plan"), close_state=close.get("state"), close_plan=close.get("source_plan"))
        elif event == "confirm_cover" and plan.require_cash_cover:
            _require(r.cover_source is not None, "SOURCE_NOT_SEALED", "funding retains the complete treasury cover")
            expected = cover_receipt(r.cover_source, forecast=r.forecast_source)
            _require(r.forecast_source["currency"] == plan.currency and r.cover_source["at"] == data["pay_date"], "SCOPE_MISMATCH", "cash cover must judge this payroll currency and exact pay date")
            _require(parsed(r.forecast_source["as_of"]) <= parsed(at), "SOURCE_FROM_FUTURE", "the payroll funding decision cannot use a future forecast")
        elif event == "apply_payment":
            expected = payment_receipt(r.bank_source if r.bank_source is not None else detached(r.source_payload), provenance=r.source_provenance)
            observed = r.source_provenance.completed_at if r.source_provenance else r.bank_source["source_state"]["transition_history"][-1]["command"]["occurred_at"]
            _require(parsed(observed) <= parsed(at) and parsed(data["funded_at"]) <= parsed(r.paid_at) <= parsed(at), "SOURCE_FROM_FUTURE", "bank evidence must follow funding and predate the payroll recording")
            if r.bank_source is not None:
                bank = r.bank_source
                _require(bank["currency"] == plan.currency and bank["source_plan"]["company_ref"] == plan.company_ref and _same_scope(bank["source_state"]["scope"], data["entity_scope"]), "SCOPE_MISMATCH", "the bank match belongs to another company or execution scope")
                _require(bank["counterpart_kind"] in {"payroll", PAYROLL_RUN_KIND} and bank["counterpart_state_digest"] == command.expected_state_digest, "PAYMENT_CORRELATION_MISMATCH", "the bank match must settle this exact funded pay run")
        elif event == "reserve_liabilities":
            _require(r.liability_digest == data["cost_digest"] and r.liability_source == data["cost_source"] and r.observed_at == data["cost_observed_at"] and r.liability_amount == _dec(data, _LIABILITY_FIELDS[r.liability_kind]), "LIABILITY_DIGEST_MISMATCH", "each reservation reuses this exact observed payroll report and amount")
        elif event == "reconcile_payroll":
            _require(r.close_source is not None, "SOURCE_NOT_SEALED", "payroll reconciliation retains its complete close state and plan")
            expected = close_receipt(r.close_source["state"], source_plan=r.close_source["source_plan"])
        for source in [*r.paid_sources, *([r.prior_source] if r.prior_source else []), *([r.close_source] if r.close_source else [])]:
            _require(_same_scope(source["state"]["scope"], data["entity_scope"]), "SCOPE_MISMATCH", "retained payroll and close sources must remain within their authenticated scope")
            label = source["source_plan"].get("company_ref")
            _require(label is None or label == plan.company_ref, "SCOPE_MISMATCH", "the retained source belongs to another company")
            _require(parsed(source["state"]["transition_history"][-1]["command"]["occurred_at"]) <= parsed(at), "SOURCE_FROM_FUTURE", "a retained source cannot come from the future")
        if expected is not None:
            expected = PayRunReceipt.model_validate(expected).to_dict()
            actual = r.to_dict()
            ignored = {"evidence_refs", "entity_scope", "source_provenance", "source_payload", "paid_sources", "prior_source", "close_source", "cover_source", "forecast_source", "bank_source"}
            _require(all(actual.get(key) == value for key, value in expected.items() if key not in ignored), "SOURCE_PROJECTION_MISMATCH", "payroll receipt projections must equal their retained source artifacts")
    except PayrollRunError as exc:
        require(False, exc.code, str(exc), "correct_input")
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        require(False, "SOURCE_NOT_SEALED", f"payroll source validation failed: {exc}", "correct_input")


def _proven(run_state: Any, source_plan: Any) -> Any:
    run_state = verify_paid_pay_run(run_state, source_plan=source_plan)
    _require(getattr(run_state, "status", "") in _PROVEN_RUN_STATUSES, "RUN_NOT_PAID", f"the run is {getattr(run_state, 'status', 'missing')}; only a paid run sizes an obligation or a cost")
    return run_state.ledger


def liability_receipt_for(run_state: Any, kind: str, *, source_plan: Any) -> dict[str, Any]:
    """The compliance calendar's ``reserve`` receipt, sized from this run rather than an estimate.

    ``liability_digest`` is the digest the payroll report hashed to at
    ``cost_run``, so the reservation is bound to the content of the report and
    not merely to the provenance of the read.
    """

    _require(kind in LIABILITY_KINDS, "LIABILITY_KIND_UNKNOWN", f"{kind} is not a payroll obligation; known: {list(LIABILITY_KINDS)}")
    run_state = verify_paid_pay_run(run_state, source_plan=source_plan)
    ledger = run_state.ledger
    _require(bool(ledger.cost_digest) and bool(ledger.cost_source), "LIABILITY_DIGEST_MISSING", "the run carries no costed report digest to bind the reservation to")
    amount = Decimal(str(getattr(ledger, _LIABILITY_FIELDS[kind])))
    _require(amount > 0, "LIABILITY_NOT_IN_RUN", f"this run reported no {kind}")
    return {"source_state": run_state.to_dict(), "source_plan": detached(source_plan), "liability_amount": str(amount), "liability_source": str(ledger.cost_source), "liability_digest": str(ledger.cost_digest), "observed_at": str(ledger.cost_observed_at), "evidence_refs": [f"pay_run:{run_state.scope.entity_ref}:{run_state.state_digest[:16]}"]}


def reserve_liabilities_receipt(run_state: Any, kind: str, *, source_plan: Any) -> dict[str, Any]:
    """The chain's own ``reserve_liabilities`` receipt: the compliance reservation plus the obligation kind it reserves."""

    receipt = liability_receipt_for(run_state, kind, source_plan=source_plan)
    # This is an internal hop: the current history already retains that source.
    return {**{key: value for key, value in receipt.items() if key not in {"source_state", "source_plan"}}, "liability_kind": kind}


def payroll_source_balance(run_state: Any, *, source_plan: Any) -> SourceBalance:
    """The ``SourceBalance(kind='payroll')`` the fortnightly close demands: the payroll liability this run leaves on the books."""

    _require(getattr(run_state, "status", "") not in ("drafted", "timesheets_approved"), "RUN_NOT_COSTED", f"the run is {getattr(run_state, 'status', 'missing')}; a source balance needs the costed run")
    _, run_state = _replay_run(run_state, source_plan)
    ledger = run_state.ledger
    outstanding = Decimal(str(ledger.withholding)) + Decimal(str(ledger.employer_super)) + Decimal(str(ledger.employer_tax))
    if not ledger.paid_at:
        outstanding += Decimal(str(ledger.net))
    return SourceBalance.model_validate({"kind": "payroll", "source_ref": f"pay-run:{run_state.scope.entity_ref}", "source_tool": str(ledger.cost_source), "provenance_digest": str(ledger.cost_digest), "balance": str(outstanding.quantize(MONEY_QUANTUM)), "items": int(ledger.headcount or 0), "window_end": str(ledger.period_end)})


#: Every key ``period_evidence_receipt`` emits is a field of
#: ``company_cost_centres.CostSourceReceipt``, which forbids extras.  The one
#: thing that engine still lacks is the ``payroll_run`` member of its
#: ``SourceKind`` literal; wiring adds it, and until it does this hop is a
#: proposal, not a working handoff.
COST_CENTRE_SOURCE_KIND = "payroll"


def period_evidence_receipt(run_state: Any, *, source_plan: Any, centre_ref: str, period_ref: str | None = None) -> dict[str, Any]:
    """Labour spend for the cost centre register: the employer cost of the run (gross plus employer super and payroll tax), keyed by the sealed state that proved it left.

    The shape is exactly ``company_cost_centres.CostSourceReceipt``; nothing
    else is added, because that model forbids extra keys and an extra field
    would make the handoff unusable rather than merely lossy.
    """

    from lightbulb.company_cost_centres import payroll_cost_receipt
    return payroll_cost_receipt(verify_paid_pay_run(run_state, source_plan=source_plan), source_plan=source_plan, centre_ref=centre_ref, period_ref=period_ref)


def payroll_flows(run_state: Any, *, plan: PayrollPlan | Mapping[str, Any] | None = None, source_plan: Any = None, horizon_days: int = 0) -> list[ScheduledFlow]:
    """Treasury ``ScheduledFlow`` rows of kind ``payroll`` at the observed net on the observed pay date, replacing the typed ``PayrollSchedule``.

    With a plan and a horizon the next runs are projected at the same observed
    net on the plan's cycle; a projected row names itself in ``source``.
    """

    parsed_plan, run_state = _replay_run(run_state, source_plan or plan)
    ledger = run_state.ledger
    _require(bool(ledger.pay_date) and Decimal(str(ledger.net)) > 0, "RUN_NOT_COSTED", "a payroll flow carries the observed net pay on the observed pay date")
    net = Decimal(str(ledger.net))
    anchor = parsed(str(ledger.pay_date))
    rows = [ScheduledFlow(kind="payroll", ref=f"payroll:{run_state.scope.entity_ref}", due_at=str(ledger.pay_date), amount=str(-net), source=str(ledger.cost_source or ledger.provider))]
    if plan is not None and horizon_days > 0:
        parsed_plan = plan if isinstance(plan, PayrollPlan) else PayrollPlan.model_validate(detached(plan))
        index = 0
        while True:
            index += 1
            when = datetime.fromtimestamp(anchor.timestamp() + index * parsed_plan.pay_cycle_days * 86400, tz=timezone.utc)
            if (when - anchor).days > horizon_days:
                break
            rows.append(ScheduledFlow(kind="payroll", ref=f"payroll:{run_state.scope.entity_ref}:+{index}", due_at=when.isoformat().replace("+00:00", "Z"), amount=str(-net), source="payroll_run_projection"))
    return rows


def run_summary(run_state: Any, *, source_plan: Any) -> dict[str, Any]:
    _, run_state = _replay_run(run_state, source_plan)
    ledger = run_state.ledger
    return {"run_ref": ledger.run_ref, "status": run_state.status, "period_start": ledger.period_start, "period_end": ledger.period_end, "pay_date": ledger.pay_date, "headcount": ledger.headcount, "gross": str(ledger.gross), "withholding": str(ledger.withholding), "employer_super": str(ledger.employer_super), "net": str(ledger.net), "variance_percent": None if ledger.variance_percent is None else str(ledger.variance_percent), "liabilities_reserved": list(ledger.liabilities_reserved), "days_draft_to_paid": ledger.days_draft_to_paid, "outcome": ledger.outcome}


PAYROLL_RUN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": PAYROLL_RUN_KIND,
    "golden_loop": PAYROLL_RUN_GOLDEN_LOOP,
    "stages": ["draft_run", "attach_timesheets", "cost_run", "approve", "confirm_cover", "apply_payment", "reserve_liabilities", "reconcile_payroll"],
    "statuses": list(PAY_RUN_STATUSES),
    "events": list(PAY_RUN_EVENTS),
    "hops": {
        "draft_run": f"a pay-run read on the host lane ({', '.join(RUN_TOOLS)})",
        "attach_timesheets": f"approved timesheets ({', '.join(TIMESHEET_TOOLS)})",
        "cost_run": f"the provider's payroll summary ({', '.join(COST_TOOLS)}), hashed against the read's output digest",
        "approve": "the platform's approved task bound as a company_execution_bridge ApprovalBinding",
        "confirm_cover": "a company_treasury CashCover",
        "apply_payment": f"a bank reconciliation match, or a bank line carrying the {PAY_CORRELATION_PREFIX} correlation",
        "reserve_liabilities": "the run's own PAYG withholding, superannuation, and payroll tax, reserved on the compliance calendar",
        "reconcile_payroll": "a closed finance period that reconciled the payroll account",
    },
    "read_lane": {
        "lane": "host_read",
        "governed_reads": [],
        "detail": "no payroll read is in GOVERNED_CONNECTOR_READ_TOOLS; every hop arrives through provenance_from_host_read",
        "proposed_contract": PROPOSED_GOVERNED_READ,
    },
    "liability_kinds": list(LIABILITY_KINDS),
    "required_connectors": ["xero", "quickbooks", "airwallex", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the SDK never computes statutory withholding; the provider calculates and the engine refuses a number that does not match the sealed basis",
        "no pay run is funded that the treasury cover cannot clear",
        "one pay period is paid once",
        "payroll payloads reach the engine as run-level aggregates and opaque worker refs, never as people",
        "an authority matrix proof binds this exact run, plan, command and net amount; a task binding alone never authorizes wages",
        "every payload is hashed against its read's output digest before it is reduced; provenance alone proves only that some read happened",
    ],
}

__all__ = [
    "BANK_MATCH_SCHEMA",
    "COST_CENTRE_SOURCE_KIND",
    "COST_TOOLS",
    "LIABILITY_KINDS",
    "MAX_PAY_RUN_TRANSITIONS",
    "PAYMENT_TOOLS",
    "PAYROLL_LIFECYCLE",
    "PAYROLL_RUN_GOLDEN_LOOP",
    "PAYROLL_RUN_KIND",
    "PAYROLL_RUN_MANIFEST",
    "PAYROLL_RUN_PLAN_SCHEMA",
    "PAY_CORRELATION_PREFIX",
    "PAY_RUN_EVENTS",
    "PAY_RUN_STATUSES",
    "PROPOSED_GOVERNED_READ",
    "RUN_TOOLS",
    "TIMESHEET_TOOLS",
    "PayRunLedger",
    "PayRunReceipt",
    "PayRunState",
    "PayrollPlan",
    "PayrollRunError",
    "advance_pay_run",
    "approval_receipt",
    "close_receipt",
    "compile_payroll_run",
    "cost_receipt",
    "cover_receipt",
    "draft_receipt",
    "liability_receipt_for",
    "open_pay_run",
    "payment_receipt",
    "payroll_flows",
    "payroll_source_balance",
    "period_evidence_receipt",
    "reserve_liabilities_receipt",
    "run_summary",
    "timesheet_receipt",
    "verify_paid_pay_run",
]
