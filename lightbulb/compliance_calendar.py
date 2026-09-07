"""The compliance calendar: statutory obligations as replay-fenced cases whose reservations flow into the cash forecast.

The treasury forecast knew about payroll, bills, and the operating budget
and nothing about tax, which is the outflow most likely to be wrong.
``compile_compliance_calendar`` derives the obligations a company carries
from its jurisdiction, archetype, and payroll (GST/BAS or sales tax, PAYG
withholding, superannuation, payroll tax, income tax instalments, the annual
return) with their periods and due dates.  Each obligation is a lifecycle:

    scheduled -> reserved -> lodged -> paid        (terminal)
    scheduled | reserved | lodged -> overdue       (non-terminal; may still lodge/pay)
    any non-terminal -> waived                     (terminal, with a reason)

* ``reserve`` consumes a liability read: the Xero BAS or GST report, the
  QuickBooks tax report, or a payroll run summary, with provenance; the
  reservation is the reported liability, never an estimate.
* ``lodge`` consumes a filing receipt (the lodgement reference, the time,
  the amount lodged) that the operator holds from the authority's portal;
  the platform has no filing write, so the receipt names what it is.
* ``pay`` consumes an applied payment observation or bank transaction on
  the same amount.

``reservations`` turns every open obligation into treasury ``ScheduledFlow``
rows of kind ``tax_reservation`` so the forecast carries them, and
``calendar_summary`` says what is due, reserved, overdue, and unfunded.
Nothing here lodges or pays anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
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
    Rejected,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    iso,
    parsed,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
)
from lightbulb.company_execution_bridge import ObservationProvenance

COMPLIANCE_KIND = "compliance_obligation"
COMPLIANCE_GOLDEN_LOOP = "finance.period_close_to_verified_books@0.1.0"
CALENDAR_SCHEMA = "lightbulb.compliance_calendar_plan.v1"
LIABILITY_TOOLS: tuple[str, ...] = ("xero.bas_report", "xero.gst_report", "quickbooks.report", "xero.payroll_summary_report", "host.payroll_run_summary")
MAX_OBLIGATION_TRANSITIONS = 12
_HUNDRED = Decimal("100")

Jurisdiction = Literal["AU", "CA", "US", "UK", "NZ"]
ObligationKind = Literal["gst_bas", "sales_tax", "payg_withholding", "superannuation", "payroll_tax", "income_tax_instalment", "annual_return"]
Frequency = Literal["monthly", "quarterly", "annual"]

OBLIGATION_STATUSES: tuple[str, ...] = ("scheduled", "reserved", "lodged", "paid", "overdue", "waived")
TERMINAL_OBLIGATION_STATUSES: frozenset[str] = frozenset({"paid", "waived"})
OBLIGATION_EVENTS: tuple[str, ...] = ("schedule", "reserve", "lodge", "pay", "mark_overdue", "waive")
_OBLIGATION_TABLE: dict[tuple[str, str], str] = {
    ("new", "schedule"): "scheduled",
    ("scheduled", "reserve"): "reserved",
    ("reserved", "lodge"): "lodged",
    ("lodged", "pay"): "paid",
    ("overdue", "reserve"): "reserved",
    ("overdue", "lodge"): "lodged",
    ("overdue", "pay"): "paid",
    **{(status, "mark_overdue"): "overdue" for status in ("scheduled", "reserved", "lodged")},
    **{(status, "waive"): "waived" for status in ("scheduled", "reserved", "lodged", "overdue")},
}

# Statutory shapes per jurisdiction: kind, frequency, days after period end the lodgement is due, the basis it is reserved on.
_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    "AU": (
        {"kind": "gst_bas", "frequency": "quarterly", "due_days_after_period": 28, "basis": "net_gst", "rate_percent": "10"},
        {"kind": "payg_withholding", "frequency": "quarterly", "due_days_after_period": 28, "basis": "payroll_withholding", "rate_percent": "0"},
        {"kind": "superannuation", "frequency": "quarterly", "due_days_after_period": 28, "basis": "payroll_gross", "rate_percent": "12"},
        {"kind": "income_tax_instalment", "frequency": "quarterly", "due_days_after_period": 28, "basis": "instalment_income", "rate_percent": "0"},
        {"kind": "annual_return", "frequency": "annual", "due_days_after_period": 210, "basis": "assessed", "rate_percent": "0"},
    ),
    "CA": (
        {"kind": "gst_bas", "frequency": "quarterly", "due_days_after_period": 30, "basis": "net_gst", "rate_percent": "5"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_days_after_period": 15, "basis": "payroll_withholding", "rate_percent": "0"},
        {"kind": "income_tax_instalment", "frequency": "quarterly", "due_days_after_period": 0, "basis": "instalment_income", "rate_percent": "0"},
        {"kind": "annual_return", "frequency": "annual", "due_days_after_period": 180, "basis": "assessed", "rate_percent": "0"},
    ),
    "US": (
        {"kind": "sales_tax", "frequency": "monthly", "due_days_after_period": 20, "basis": "net_gst", "rate_percent": "0"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_days_after_period": 15, "basis": "payroll_withholding", "rate_percent": "0"},
        {"kind": "payroll_tax", "frequency": "quarterly", "due_days_after_period": 30, "basis": "payroll_gross", "rate_percent": "7.65"},
        {"kind": "income_tax_instalment", "frequency": "quarterly", "due_days_after_period": 15, "basis": "instalment_income", "rate_percent": "0"},
        {"kind": "annual_return", "frequency": "annual", "due_days_after_period": 105, "basis": "assessed", "rate_percent": "0"},
    ),
    "UK": (
        {"kind": "gst_bas", "frequency": "quarterly", "due_days_after_period": 37, "basis": "net_gst", "rate_percent": "20"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_days_after_period": 22, "basis": "payroll_withholding", "rate_percent": "0"},
        {"kind": "payroll_tax", "frequency": "monthly", "due_days_after_period": 22, "basis": "payroll_gross", "rate_percent": "13.8"},
        {"kind": "annual_return", "frequency": "annual", "due_days_after_period": 270, "basis": "assessed", "rate_percent": "0"},
    ),
    "NZ": (
        {"kind": "gst_bas", "frequency": "monthly", "due_days_after_period": 28, "basis": "net_gst", "rate_percent": "15"},
        {"kind": "payg_withholding", "frequency": "monthly", "due_days_after_period": 20, "basis": "payroll_withholding", "rate_percent": "0"},
        {"kind": "superannuation", "frequency": "monthly", "due_days_after_period": 20, "basis": "payroll_gross", "rate_percent": "3"},
        {"kind": "income_tax_instalment", "frequency": "quarterly", "due_days_after_period": 28, "basis": "instalment_income", "rate_percent": "0"},
        {"kind": "annual_return", "frequency": "annual", "due_days_after_period": 210, "basis": "assessed", "rate_percent": "0"},
    ),
}


class ObligationRule(StrictModel):
    kind: ObligationKind
    frequency: Frequency
    due_days_after_period: int = Field(ge=0, le=365)
    basis: Literal["net_gst", "payroll_withholding", "payroll_gross", "instalment_income", "assessed"]
    rate_percent: Decimal

    @field_validator("rate_percent", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="rate_percent")


class ScheduledObligation(StrictModel):
    obligation_ref: OpaqueRef
    kind: ObligationKind
    period_start: str
    period_end: str
    due_at: str
    basis: ShortText
    estimated_amount: Decimal

    @field_validator("estimated_amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="estimated_amount")


class ComplianceCalendarPlan(StrictModel):
    """The obligations a company carries: jurisdiction, rules, and the schedule derived for the horizon."""

    schema_id: str = Field(default=CALENDAR_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    jurisdiction: Jurisdiction
    currency: ShortText
    fiscal_year_end_month: int = Field(default=6, ge=1, le=12)
    has_payroll: bool = True
    registered_for_gst: bool = True
    rules: tuple[ObligationRule, ...] = Field(min_length=1, max_length=12)
    schedule: tuple[ScheduledObligation, ...] = Field(default_factory=tuple, max_length=200)
    reserve_tolerance_percent: Decimal = Field(default=Decimal("2.00"), validate_default=True)
    overdue_grace_days: int = Field(default=0, ge=0, le=60)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("reserve_tolerance_percent", mode="before")
    @classmethod
    def _tolerance(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="reserve_tolerance_percent")

    @field_validator("rules", "schedule", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ComplianceCalendarPlan:
        if not skip_digests(info) and self.plan_digest != sealed_digest(ComplianceCalendarPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def obligation(self, obligation_ref: str) -> ScheduledObligation | None:
        return next((item for item in self.schedule if item.obligation_ref == obligation_ref), None)


def _month_start(year: int, month: int) -> datetime:
    return datetime(year, month, 1, tzinfo=timezone.utc)


def _add_months(value: datetime, months: int) -> datetime:
    month = value.month - 1 + months
    return _month_start(value.year + month // 12, month % 12 + 1)


def _periods(frequency: str, start: datetime, horizon_months: int, fiscal_year_end_month: int) -> list[tuple[datetime, datetime]]:
    step = {"monthly": 1, "quarterly": 3, "annual": 12}[frequency]
    if frequency == "annual":
        first = _month_start(start.year if start.month <= fiscal_year_end_month else start.year + 1, fiscal_year_end_month)
        first = _add_months(first, 1)  # the period ends at the fiscal year end; the obligation period starts the month after last year end
        first = _add_months(first, -12)
    else:
        offset = (start.month - 1) % step
        first = _month_start(start.year, start.month - offset)
    out: list[tuple[datetime, datetime]] = []
    cursor = first
    end_limit = _add_months(_month_start(start.year, start.month), horizon_months)
    while cursor < end_limit:
        period_end = _add_months(cursor, step)
        if period_end > start:
            out.append((cursor, period_end))
        cursor = period_end
    return out


def compile_compliance_calendar(company_ref: str, *, jurisdiction: str, currency: str, start_at: str, horizon_months: int = 12, estimated_revenue_per_month: Any = "0", estimated_payroll_per_month: Any = "0", has_payroll: bool = True, registered_for_gst: bool = True, fiscal_year_end_month: int | None = None, overrides: Mapping[str, Any] | None = None) -> ComplianceCalendarPlan:
    """Derive the obligations for the horizon; estimates only size the reservation until a liability read replaces them."""

    code = jurisdiction.upper()
    if code not in _RULES:
        raise ValueError(f"unsupported jurisdiction {jurisdiction!r}; known: {sorted(_RULES)}")
    start = parsed(timestamp(start_at, field_name="start_at"))
    fy_end = fiscal_year_end_month or {"AU": 6, "NZ": 3, "UK": 3, "CA": 12, "US": 12}[code]
    revenue = decimal_value(estimated_revenue_per_month, field_name="estimated_revenue_per_month")
    payroll = decimal_value(estimated_payroll_per_month, field_name="estimated_payroll_per_month")
    rules = [ObligationRule.model_validate(rule) for rule in _RULES[code] if (registered_for_gst or rule["basis"] != "net_gst") and (has_payroll or rule["basis"] not in ("payroll_withholding", "payroll_gross"))]
    schedule: list[dict[str, Any]] = []
    for rule in rules:
        for period_start, period_end in _periods(rule.frequency, start, horizon_months, fy_end):
            months = max(1, round((period_end - period_start).days / 30))
            if rule.basis == "net_gst":
                estimate = revenue * months * rule.rate_percent / _HUNDRED * Decimal("0.6")  # net of input credits at a conservative 40%
            elif rule.basis == "payroll_withholding":
                estimate = payroll * months * Decimal("0.22")
            elif rule.basis == "payroll_gross":
                estimate = payroll * months * rule.rate_percent / _HUNDRED
            elif rule.basis == "instalment_income":
                estimate = revenue * months * Decimal("0.02")
            else:
                estimate = Decimal("0")
            due = period_end + timedelta(days=rule.due_days_after_period)
            schedule.append({"obligation_ref": f"{rule.kind}:{period_end.date().isoformat()}", "kind": rule.kind, "period_start": iso(period_start), "period_end": iso(period_end), "due_at": iso(due), "basis": rule.basis, "estimated_amount": str(estimate.quantize(MONEY_QUANTUM))})
    schedule.sort(key=lambda item: (item["due_at"], item["obligation_ref"]))
    raw = {"company_ref": company_ref, "jurisdiction": code, "currency": currency.upper(), "fiscal_year_end_month": fy_end, "has_payroll": has_payroll, "registered_for_gst": registered_for_gst, "rules": [rule.to_dict() for rule in rules], "schedule": schedule, **dict(overrides or {})}
    return seal(ComplianceCalendarPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# The obligation lifecycle
# --------------------------------------------------------------------------- #


class ObligationReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    source_state: dict[str, Any] | None = None
    source_plan: dict[str, Any] | None = None
    source_provenance: ObservationProvenance | None = None
    source_payload: dict[str, Any] | None = None
    payment_source: dict[str, Any] | None = None
    standing_source: dict[str, Any] | None = None
    disbursement_source: dict[str, Any] | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    obligation_ref: OpaqueRef | None = None
    liability_amount: Decimal | None = None
    liability_source: ShortText | None = None
    liability_digest: Sha256Digest | None = None
    observed_at: str | None = None
    lodgement_ref: OpaqueRef | None = None
    lodged_at: str | None = None
    lodged_amount: Decimal | None = None
    lodged_by: OpaqueRef | None = None
    paid_amount: Decimal | None = None
    paid_at: str | None = None
    payment_evidence_sha256: Sha256Digest | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("liability_amount", "lodged_amount", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("observed_at", "lodged_at", "paid_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class ObligationLedger(StrictModel):
    entity_scope: EngineScope | None = None
    obligation_ref: str | None = None
    kind: str | None = None
    period_end: str | None = None
    due_at: str | None = None
    estimated_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    reserved_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    liability_source: str | None = None
    reserved_at: str | None = None
    lodgement_ref: str | None = None
    lodged_at: str | None = None
    lodged_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_at: str | None = None
    overdue_since: str | None = None
    days_late: int | None = None
    waive_reason: str | None = None
    outcome: Literal["open", "paid", "waived"] = "open"

    @field_validator("estimated_amount", "reserved_amount", "lodged_amount", "paid_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class ObligationEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    lodged_with_authority: Literal[False] = False
    payment_sent: Literal[False] = False
    provider_read: Literal[False] = False


def _within(value: Decimal, reference: Decimal, tolerance_percent: Decimal) -> bool:
    if reference <= 0:
        return value == reference
    return (value - reference).copy_abs() <= (reference * tolerance_percent / _HUNDRED).quantize(MONEY_QUANTUM)


def _apply_obligation(plan: ComplianceCalendarPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "schedule":
        require(r.entity_scope is not None and r.entity_scope.currency == plan.currency, "SCOPE_MISMATCH", "the obligation binds its authenticated scope and currency")
        data["entity_scope"] = r.entity_scope.to_dict()
        require(r.obligation_ref is not None, "OBLIGATION_MISSING", "name the scheduled obligation")
        scheduled = plan.obligation(r.obligation_ref)
        require(scheduled is not None, "OBLIGATION_NOT_IN_CALENDAR", f"{r.obligation_ref} is not on this calendar")
        assert scheduled is not None
        data.update({"obligation_ref": scheduled.obligation_ref, "kind": scheduled.kind, "period_end": scheduled.period_end, "due_at": scheduled.due_at, "estimated_amount": str(scheduled.estimated_amount)})
    elif event == "reserve":
        require(r.liability_amount is not None and r.liability_source is not None and r.liability_digest is not None and r.observed_at is not None, "LIABILITY_MISSING", "a reservation carries the reported liability, its source, its digest, and the observation time")
        require(parsed(r.observed_at) >= parsed(str(data["period_end"])) - timedelta(days=7), "LIABILITY_READ_TOO_EARLY", "the liability was read before the period was substantially complete", "correct_input")
        require(parsed(r.observed_at) <= parsed(at), "LIABILITY_READ_IN_FUTURE", "the liability read must precede the reservation")
        try:
            if r.source_state is not None and r.source_plan is not None:
                from lightbulb.payroll_run_chain import liability_receipt_for, verify_paid_pay_run
                run = verify_paid_pay_run(r.source_state, source_plan=r.source_plan, company_ref=plan.company_ref, currency=plan.currency, expected_scope=data["entity_scope"], at=at)
                scheduled = plan.obligation(str(data["obligation_ref"]))
                require(scheduled is not None and parsed(run.ledger.period_start) >= parsed(scheduled.period_start) and parsed(run.ledger.period_end) <= parsed(scheduled.period_end), "LIABILITY_PERIOD_MISMATCH", "the payroll run must fall within this statutory period")
                expected = liability_receipt_for(run, str(data["kind"]), source_plan=r.source_plan)
            else:
                require(r.source_provenance is not None and r.source_payload is not None, "LIABILITY_SOURCE_REQUIRED", "retain the provider report and its complete read provenance")
                expected = liability_receipt(r.source_provenance, r.source_payload, kind=str(data["kind"]))
                declared = r.source_payload
                require(declared.get("currency", declared.get("CurrencyCode", plan.currency)) == plan.currency and declared.get("company_ref", plan.company_ref) == plan.company_ref, "SCOPE_MISMATCH", "declared report company and currency must match the calendar")
            require(all(str(getattr(r, key)) == str(expected[key]) for key in ("liability_amount", "liability_source", "liability_digest", "observed_at")), "LIABILITY_SOURCE_MISMATCH", "the reservation must equal its replayed source")
        except Rejected:
            raise
        except ValueError as exc:
            require(False, getattr(exc, "code", "LIABILITY_SOURCE_INVALID"), str(exc))
        data.update({"reserved_amount": str(r.liability_amount), "liability_source": r.liability_source, "reserved_at": at})
    elif event == "lodge":
        require(r.lodgement_ref is not None and r.lodged_at is not None and r.lodged_amount is not None and r.lodged_by is not None, "LODGEMENT_MISSING", "a lodgement carries the authority reference, the time, the amount, and who lodged it")
        if r.standing_source is not None:
            from lightbulb.obligation_paper import STANDING_LIFECYCLE, annual_return_receipt
            try:
                source = r.standing_source
                standing_plan, standing = STANDING_LIFECYCLE.bind(source["source_plan"], source["state"])
                expected = annual_return_receipt(standing, source_plan=standing_plan)
                require(source == expected["standing_source"], "STANDING_SOURCE_MISMATCH", "retain the exact annual-return projection")
                require(standing_plan.company_ref == plan.company_ref and standing_plan.currency == plan.currency and standing_plan.jurisdiction == plan.jurisdiction and all(getattr(standing.scope, key) == data["entity_scope"][key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "STANDING_SCOPE_MISMATCH", "annual-return evidence must belong to this company, jurisdiction and authenticated scope")
                require(data["kind"] == "annual_return" and expected["standing_source"]["period_end"] == data["period_end"], "STANDING_PERIOD_MISMATCH", "the confirmed annual return must cover this statutory period")
                require(all(str(getattr(r, key)) == str(expected[key]) for key in ("lodgement_ref", "lodged_at", "lodged_amount", "lodged_by")) and parsed(standing.transition_history[-1].command.occurred_at) <= parsed(at), "STANDING_SOURCE_MISMATCH", "filing fields and time must equal the replayed standing evidence")
            except Rejected:
                raise
            except (ValueError, KeyError) as exc:
                require(False, getattr(exc, "code", "STANDING_SOURCE_INVALID"), str(exc))
        reserved = Decimal(str(data.get("reserved_amount", "0")))
        require(_within(r.lodged_amount, reserved, plan.reserve_tolerance_percent), "LODGED_AMOUNT_DRIFT", f"lodged {r.lodged_amount} differs from the reserved liability {reserved} by more than {plan.reserve_tolerance_percent}%", "manual_reconciliation")
        late = (parsed(r.lodged_at) - parsed(str(data["due_at"]))).days
        data.update({"lodgement_ref": r.lodgement_ref, "lodged_at": r.lodged_at, "lodged_amount": str(r.lodged_amount), "days_late": max(0, late)})
    elif event == "pay":
        require(r.paid_amount is not None and r.paid_at is not None and r.payment_evidence_sha256 is not None, "PAYMENT_MISSING", "a payment carries the amount, the time, and the evidence digest")
        require(r.paid_amount == Decimal(str(data.get("lodged_amount", "0"))), "PAYMENT_NOT_LODGED_AMOUNT", f"paid {r.paid_amount} differs from the lodged {data.get('lodged_amount')}", "manual_reconciliation")
        require(r.payment_source is not None or r.disbursement_source is not None, "PAYMENT_SOURCE_REQUIRED", "retain the complete bank payment read or settled disbursement")
        try:
            if r.disbursement_source is not None:
                source = r.disbursement_source
                expected = disbursement_payment_receipt(source["state"], source_plan=source["source_plan"], obligation_ref=str(data["obligation_ref"]))
                require(source == expected["disbursement_source"], "PAYMENT_SOURCE_MISMATCH", "retain the exact settled allocation projection")
                require(expected["disbursement_source"]["obligation_entity_ref"] == data["entity_scope"]["entity_ref"], "PAYMENT_CORRELATION_MISMATCH", "the batch must pay this exact statutory entity")
                run_scope = source["state"]["scope"]
                require(source["source_plan"]["company_ref"] == plan.company_ref and all(run_scope[key] == data["entity_scope"][key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")), "PAYMENT_SCOPE_MISMATCH", "the disbursement must belong to this company and execution scope")
                observed_at = source["state"]["transition_history"][-1]["command"]["occurred_at"]
            else:
                source = r.payment_source
                expected = payment_receipt(source["payload"], provenance=source["provenance"], obligation_ref=str(data["obligation_ref"]), currency=plan.currency)
                require(source == expected["payment_source"], "PAYMENT_SOURCE_MISMATCH", "retain the exact bank payment projection")
                observed_at = source["provenance"]["completed_at"]
            require(all(str(getattr(r, key)) == str(expected[key]) for key in ("paid_amount", "paid_at", "payment_evidence_sha256")), "PAYMENT_SOURCE_MISMATCH", "payment fields must equal the original read")
            require(parsed(r.paid_at) >= parsed(str(data["lodged_at"])) and parsed(observed_at) <= parsed(at), "PAYMENT_TIME_MISMATCH", "payment must follow lodgement and be observed before this transition")
        except Rejected:
            raise
        except (ValueError, KeyError) as exc:
            require(False, getattr(exc, "code", "PAYMENT_SOURCE_INVALID"), str(exc))
        data.update({"paid_amount": str(r.paid_amount), "paid_at": r.paid_at, "outcome": "paid"})
    elif event == "mark_overdue":
        require(parsed(at) > parsed(str(data["due_at"])) + timedelta(days=plan.overdue_grace_days), "NOT_YET_OVERDUE", "the obligation is not past its due date and grace")
        data.update({"overdue_since": at, "days_late": (parsed(at) - parsed(str(data["due_at"]))).days})
    elif event == "waive":
        data.update({"waive_reason": str(command.reason)[:300], "outcome": "waived"})
    return next_status, data


class _ComplianceLifecycle(LifecycleSpec):
    def open(self, plan: Any, scope: Any, **kwargs: Any) -> Any:
        kwargs["receipt"] = {**detached(kwargs.get("receipt", {})), "entity_scope": detached(scope)}
        return super().open(plan, scope, **kwargs)

    def _build_models(self) -> None:
        super()._build_models()
        class ScopedState(self.State):
            @model_validator(mode="after")
            def _scope(self) -> Any:
                if self.ledger.entity_scope is None or self.scope != self.ledger.entity_scope:
                    raise ValueError("SCOPE_MISMATCH: obligation state must equal its replayed opening scope")
                return self
        self.State = ScopedState


COMPLIANCE_LIFECYCLE = _ComplianceLifecycle(entity="obligation", schema_prefix=COMPLIANCE_KIND, statuses=OBLIGATION_STATUSES, terminal=TERMINAL_OBLIGATION_STATUSES, events=OBLIGATION_EVENTS, table=_OBLIGATION_TABLE, opening_event="schedule", reason_events=("waive",), apply=_apply_obligation, ledger_model=ObligationLedger, receipt_model=ObligationReceipt, effect_boundary_model=ObligationEffectBoundary, plan_model=ComplianceCalendarPlan, max_transitions=MAX_OBLIGATION_TRANSITIONS)
ObligationState = COMPLIANCE_LIFECYCLE.State


def open_obligation(plan: ComplianceCalendarPlan | Mapping[str, Any], scope: Mapping[str, Any], *, obligation_ref: str, opened_at: str, actor_ref: str) -> Any:
    return COMPLIANCE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={"obligation_ref": obligation_ref})


def advance_obligation(plan: ComplianceCalendarPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return COMPLIANCE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts from reads and the operator's filing evidence
# --------------------------------------------------------------------------- #


class ComplianceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ComplianceError(code, message)


def _report_cells(report: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Flatten a Xero Reports API document into (label, value) pairs from its rows."""

    out: list[tuple[str, str]] = []

    def walk(rows: Any) -> None:
        for row in rows or []:
            item = dict(detached(row))
            cells = [dict(detached(cell)) for cell in item.get("Cells") or []]
            if len(cells) >= 2:
                out.append((str(cells[0].get("Value", "")).strip(), str(cells[-1].get("Value", "")).strip()))
            walk(item.get("Rows"))

    reports = report.get("Reports") if isinstance(report.get("Reports"), list) else [report]
    for item in reports or []:
        walk(dict(detached(item)).get("Rows"))
    return out


_LIABILITY_LABELS: dict[str, tuple[str, ...]] = {
    "gst_bas": ("net gst", "gst payable", "total amount payable", "net vat", "vat due", "net tax"),
    "sales_tax": ("sales tax payable", "tax payable", "total tax"),
    "payg_withholding": ("payg withholding", "total withholding", "paye", "tax withheld", "withholding"),
    "superannuation": ("superannuation", "super guarantee", "kiwisaver"),
    "payroll_tax": ("payroll tax", "employer contributions", "employer ni"),
    "income_tax_instalment": ("payg instalment", "income tax instalment", "instalment"),
    "annual_return": ("tax payable", "income tax payable", "total tax"),
}


def liability_receipt(provenance: ObservationProvenance, report: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    """The ``reserve`` receipt from a provider tax or payroll report: the first row whose label names the liability."""

    _require(provenance.source_tool in LIABILITY_TOOLS, "OBSERVATION_TOOL_MISMATCH", f"liabilities come from {LIABILITY_TOOLS}; provenance names {provenance.source_tool}")
    raw = dict(detached(report))
    _require(stable_digest(raw) == provenance.output_digest, "LIABILITY_DIGEST_MISMATCH", "the liability report must match the content committed by its read provenance")
    if provenance.source_tool == "host.payroll_run_summary":
        key = {"payg_withholding": "withholding_total", "superannuation": "super_total", "payroll_tax": "payroll_tax_total"}.get(kind)
        _require(key is not None and raw.get(key) is not None, "LIABILITY_NOT_IN_REPORT", f"the payroll summary carries no {kind} total")
        amount = decimal_value(raw[key], field_name=key)  # type: ignore[index]
    else:
        labels = _LIABILITY_LABELS.get(kind, ())
        match = next(((label, value) for label, value in _report_cells(raw) if any(token in label.lower() for token in labels) and value not in ("", "-")), None)
        _require(match is not None, "LIABILITY_NOT_IN_REPORT", f"no row of the report names the {kind} liability")
        text = str(match[1]).replace(",", "").replace("(", "-").replace(")", "")  # type: ignore[index]
        amount = decimal_value(text, field_name="liability", allow_negative=True)
    _require(amount >= 0, "LIABILITY_IS_REFUND", f"the report shows a refund of {amount.copy_abs()}; a refund is not reserved")
    return {"source_provenance": provenance.to_dict(), "source_payload": raw, "liability_amount": str(amount.quantize(MONEY_QUANTUM)), "liability_source": provenance.source_tool, "liability_digest": provenance.output_digest, "observed_at": provenance.completed_at, "evidence_refs": [f"read:{provenance.observation_ref}"]}


def filing_receipt(*, lodgement_ref: str, lodged_at: str, amount: Any, lodged_by: str, evidence_refs: Sequence[str] = ()) -> dict[str, Any]:
    """The ``lodge`` receipt: what the operator holds from the authority's portal; it names itself as operator-supplied evidence."""

    _require(len(lodgement_ref.strip()) >= 4, "LODGEMENT_REF_INVALID", "the lodgement reference is the authority's receipt number")
    return {"lodgement_ref": lodgement_ref.strip(), "lodged_at": timestamp(lodged_at, field_name="lodged_at"), "lodged_amount": str(decimal_value(amount, field_name="amount")), "lodged_by": lodged_by, "evidence_refs": [f"lodgement:{lodgement_ref.strip()}", *evidence_refs], "detail": "operator-supplied filing evidence; the platform holds no filing write"}


def disbursement_payment_receipt(run: Any, *, source_plan: Any, obligation_ref: str) -> dict[str, Any]:
    """Allocate actual settled batch cash to its retained statutory obligation."""
    from lightbulb.disbursement_run import DISBURSEMENT_LIFECYCLE
    plan, state = DISBURSEMENT_LIFECYCLE.bind(source_plan, run)
    _require(state.status in ("settled", "reconciled") and state.ledger.settled_total == state.ledger.batch_total, "PAYMENT_NOT_APPLIED", "only a completely bank-settled batch pays statutory liabilities")
    opening = state.transition_history[0].command.receipt
    sources = [row for row in opening.sources if row["state"].get("schema") == "lightbulb.compliance_obligation_state.v1" and row["state"]["ledger"].get("obligation_ref") == obligation_ref]
    _require(len(sources) == 1, "PAYMENT_CORRELATION_MISMATCH", "the batch must retain exactly one source for this obligation")
    source = sources[0]
    _, obligation = COMPLIANCE_LIFECYCLE.bind(source["plan"], source["state"])
    matches = [row for row in state.ledger.cases if row["kind"] == "compliance_calendar" and row["state_digest"] == obligation.state_digest and row["case_ref"] == obligation.scope.entity_ref]
    _require(len(matches) == 1, "PAYMENT_CORRELATION_MISMATCH", "the settled allocation must match the replayed statutory case")
    _require(Decimal(matches[0]["amount"]) == obligation.ledger.reserved_amount, "PAYMENT_SOURCE_MISMATCH", "the allocated payment must equal the reserved statutory liability")
    proof = {"state": state.to_dict(), "source_plan": plan.to_dict(), "obligation_ref": obligation_ref, "obligation_entity_ref": obligation.scope.entity_ref}
    return {"disbursement_source": proof, "paid_amount": str(obligation.ledger.reserved_amount), "paid_at": state.ledger.settled_at, "payment_evidence_sha256": stable_digest(proof), "evidence_refs": [f"disbursement:{state.state_digest}"]}


def payment_receipt(observation: Mapping[str, Any] | Any, *, provenance: ObservationProvenance | Mapping[str, Any], obligation_ref: str, currency: str) -> dict[str, Any]:
    """An exact statutory outflow from a retained native Xero or Airwallex bank read."""
    from lightbulb.bank_reconciliation import _normalize, _page_rows
    raw = dict(detached(observation))
    read = ObservationProvenance.model_validate(detached(provenance))
    _require(read.source_tool in ("xero.list_bank_transactions", "airwallex.list_transactions"), "OBSERVATION_TOOL_MISMATCH", "statutory payments require a native bank read")
    _require(stable_digest(raw) == read.output_digest, "PAYMENT_DIGEST_MISMATCH", "the payment page must equal the observed output")
    native = _page_rows(read.source_tool, raw)
    rows = [(item, _normalize(read.source_tool, item)) for item in native]
    matches = [(item, row) for item, row in rows if row["reference"] == obligation_ref]
    _require(len(matches) == 1, "PAYMENT_CORRELATION_MISMATCH", "exactly one bank line must name this obligation")
    item, row = matches[0]
    amount = Decimal(row["amount"])
    _require(row["currency"] == currency.upper(), "PAYMENT_CURRENCY_MISMATCH", "the bank payment must use the calendar currency")
    _require(amount < 0 and str(item.get("Status", item.get("status", "AUTHORISED"))).upper() in ("AUTHORISED", "COMPLETED", "SETTLED", "SUCCESS"), "PAYMENT_NOT_APPLIED", "a statutory payment is a completed outflow")
    _require(parsed(row["occurred_at"]) <= parsed(read.completed_at), "PAYMENT_TIME_MISMATCH", "the read must observe the payment after it happened")
    source = {"payload": raw, "provenance": read.to_dict(), "obligation_ref": obligation_ref, "currency": currency.upper()}
    return {"payment_source": source, "paid_amount": str(amount.copy_abs().quantize(MONEY_QUANTUM)), "paid_at": row["occurred_at"], "payment_evidence_sha256": stable_digest(source), "evidence_refs": [f"bank:{row['line_ref']}"]}


# --------------------------------------------------------------------------- #
# Into the treasury forecast and the operator's view
# --------------------------------------------------------------------------- #


def reservations(plan: ComplianceCalendarPlan | Mapping[str, Any], states: Sequence[Any] = (), *, now: str, horizon_days: int = 120) -> list[dict[str, Any]]:
    """Treasury ``ScheduledFlow`` rows (kind ``tax_reservation``) for every unpaid obligation due inside the horizon: reserved amounts where read, estimates otherwise."""

    parsed_plan = ComplianceCalendarPlan.model_validate(detached(plan))
    stamp = parsed(timestamp(now, field_name="now"))
    by_ref = _calendar_states(parsed_plan, states)
    out: list[dict[str, Any]] = []
    for item in parsed_plan.schedule:
        due = parsed(item.due_at)
        if due < stamp - timedelta(days=parsed_plan.overdue_grace_days) and item.obligation_ref not in by_ref:
            continue
        if (due - stamp).days > horizon_days:
            continue
        state = by_ref.get(item.obligation_ref)
        if state is not None and state.status in ("paid", "waived"):
            continue
        amount = Decimal(str(state.ledger.reserved_amount)) if state is not None and state.ledger.reserved_at else item.estimated_amount
        if state is not None and state.ledger.lodged_at:
            amount = Decimal(str(state.ledger.lodged_amount))
        source = state.ledger.liability_source if state is not None and state.ledger.liability_source else "compliance_estimate"
        out.append({"kind": "tax_reservation", "ref": f"tax:{item.obligation_ref}", "due_at": item.due_at, "amount": str(-amount.quantize(MONEY_QUANTUM)), "source": source})
    return out


def calendar_summary(plan: ComplianceCalendarPlan | Mapping[str, Any], states: Sequence[Any] = (), *, now: str) -> dict[str, Any]:
    parsed_plan = ComplianceCalendarPlan.model_validate(detached(plan))
    stamp = parsed(timestamp(now, field_name="now"))
    by_ref = _calendar_states(parsed_plan, states)
    rows: list[dict[str, Any]] = []
    overdue = reserved_total = estimated_total = Decimal("0")
    for item in parsed_plan.schedule:
        state = by_ref.get(item.obligation_ref)
        status = state.status if state is not None else "unscheduled"
        if status in ("paid", "waived"):
            continue
        amount = Decimal(str(state.ledger.reserved_amount)) if state is not None and state.ledger.reserved_at else item.estimated_amount
        late = parsed(item.due_at) < stamp
        if late:
            overdue += amount
        if state is not None and state.ledger.reserved_at:
            reserved_total += amount
        else:
            estimated_total += amount
        rows.append({"obligation_ref": item.obligation_ref, "kind": item.kind, "due_at": item.due_at, "status": status, "amount": str(amount.quantize(MONEY_QUANTUM)), "basis": "read" if state is not None and state.ledger.reserved_at else "estimate", "overdue": late})
    return {"jurisdiction": parsed_plan.jurisdiction, "currency": parsed_plan.currency, "as_of": iso(stamp), "open": rows, "reserved_from_reads": str(reserved_total.quantize(MONEY_QUANTUM)), "still_estimated": str(estimated_total.quantize(MONEY_QUANTUM)), "overdue": str(overdue.quantize(MONEY_QUANTUM)), "summary_digest": stable_digest(rows)}


def _calendar_states(plan: ComplianceCalendarPlan, states: Sequence[Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    scope = None
    for source in states:
        _, state = COMPLIANCE_LIFECYCLE.bind(plan, source)
        current = {key: value for key, value in state.scope.to_dict().items() if key != "entity_ref"}
        _require(scope is None or scope == current, "SCOPE_MISMATCH", "calendar projections cannot mix authenticated execution scopes")
        scope = current
        ref = str(state.ledger.obligation_ref)
        _require(ref not in result, "OBLIGATION_DUPLICATED", "supply each obligation once")
        result[ref] = state
    return result


COMPLIANCE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": COMPLIANCE_KIND,
    "golden_loop": COMPLIANCE_GOLDEN_LOOP,
    "stages": ["schedule", "reserve", "lodge", "pay"],
    "statuses": list(OBLIGATION_STATUSES),
    "events": list(OBLIGATION_EVENTS),
    "jurisdictions": sorted(_RULES),
    "tools": {"liabilities": list(LIABILITY_TOOLS)},
    "required_connectors": ["xero", "quickbooks", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "obligations come from the jurisdiction's rules and the company's payroll and registration facts, never from a typed list",
        "a reservation is the liability a provider report or payroll run reported; estimates only size it until then",
        "a lodgement is operator-supplied evidence and says so; the platform holds no filing write",
        "a payment must equal the lodged amount; the forecast carries every unpaid obligation as a tax reservation",
    ],
}

__all__ = ["CALENDAR_SCHEMA", "COMPLIANCE_GOLDEN_LOOP", "COMPLIANCE_KIND", "COMPLIANCE_LIFECYCLE", "COMPLIANCE_MANIFEST", "LIABILITY_TOOLS", "OBLIGATION_EVENTS", "OBLIGATION_STATUSES", "ComplianceCalendarPlan", "ComplianceError", "ObligationRule", "ObligationState", "ScheduledObligation", "advance_obligation", "calendar_summary", "compile_compliance_calendar", "disbursement_payment_receipt", "filing_receipt", "liability_receipt", "open_obligation", "payment_receipt", "reservations"]
