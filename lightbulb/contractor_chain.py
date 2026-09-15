"""The contractor chain: one replay-fenced engagement per contractor, from an in-force agreement to work paid at the agreed rate.

The employment chain proves employees; a services firm or a SaaS company
also runs on contractors, and nothing held that engagement: the agreement
it sits under, the rate it was engaged at, the work actually recorded, the
bill that work became, and the payment that cleared it.
``CONTRACTOR_LIFECYCLE`` does:

    engaged -> work_recorded -> invoiced -> paid -> work_recorded ...   (one cycle per bill)
    engaged | work_recorded | paid -> ended                            (terminal)
    any non-terminal -> terminated                                     (terminal, with a reason)

* ``engagement_receipt`` opens the engagement from the contractor's
  replayed obligation-paper agreement, in force and naming the contractor
  as counterparty; the rate comes from the plan's program.
* ``work_receipt`` consumes a host-lane timesheet or deliverable read; the
  value of the work is units at the program's rate, capped per month.
* ``invoice_receipt`` consumes the contractor's payable case replayed
  against its plan: the bill must equal the uninvoiced work value.
* ``payment_receipt`` consumes the same payable case once paid or cleared.

A person never enters the engine: the contractor is an opaque commitment.
Nothing here pays anyone, posts a journal, or persists anything.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import Decimal
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

CONTRACTOR_KIND = "contractor_chain"
CONTRACTOR_GOLDEN_LOOP = "people.contractor_engaged_to_paid_work@0.1.0"
CONTRACTOR_PLAN_SCHEMA = "lightbulb.contractor_plan.v1"
MAX_CONTRACTOR_TRANSITIONS = 120
WORK_TOOLS: frozenset[str] = frozenset({"host.contractor_timesheet", "host.deliverable_acceptance", "xero.observe_timesheets", "host.project_time"})
IN_FORCE_AGREEMENT_STATUSES: frozenset[str] = frozenset({"registered", "in_force", "renewed", "amended", "notice_window"})
COSTABLE_PAYABLE_STATUSES: frozenset[str] = frozenset({"approved", "scheduled", "paid", "cleared"})
PAID_PAYABLE_STATUSES: frozenset[str] = frozenset({"paid", "cleared"})
RateUom = Literal["hour", "day", "deliverable"]
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IDENTITY_MARKERS: tuple[str, ...] = ("displayname", "fullname", "firstname", "lastname", "givenname", "familyname", "surname", "email", "phone", "mobile", "address", "dateofbirth", "bankaccount", "bsb", "accountnumber", "contractorname", "abn", "sin", "tfn")
_QTY = Decimal("0.01")

CONTRACTOR_STATUSES: tuple[str, ...] = ("engaged", "work_recorded", "invoiced", "paid", "ended", "terminated")
TERMINAL_CONTRACTOR_STATUSES: frozenset[str] = frozenset({"ended", "terminated"})
CONTRACTOR_EVENTS: tuple[str, ...] = ("engage", "record_work", "invoice", "pay", "end", "terminate")
_CONTRACTOR_TABLE: dict[tuple[str, str], str] = {
    ("new", "engage"): "engaged",
    ("engaged", "record_work"): "work_recorded",
    ("work_recorded", "record_work"): "work_recorded",
    ("paid", "record_work"): "work_recorded",
    ("work_recorded", "invoice"): "invoiced",
    ("invoiced", "pay"): "paid",
    ("engaged", "end"): "ended",
    ("work_recorded", "end"): "ended",
    ("paid", "end"): "ended",
    **{(status, "terminate"): "terminated" for status in ("engaged", "work_recorded", "invoiced", "paid")},
}


class ContractorChainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ContractorChainError(code, message)


def _normalized(key: str) -> str:
    return str(key).lower().replace("_", "").replace("-", "")


def _reject_identity(payload: Any, *, path: str = "receipt") -> Any:
    if isinstance(payload, str):
        _require(not _EMAIL.search(payload), "IDENTITY_IN_RECEIPT", f"{path} carries an email address; a person never crosses this boundary")
        return payload
    if isinstance(payload, Mapping):
        for key, item in payload.items():
            _require(not any(marker == _normalized(key) or marker in _normalized(key) for marker in _IDENTITY_MARKERS), "IDENTITY_IN_RECEIPT", f"{path}.{key} names a person; only hashed commitments cross this boundary")
            _reject_identity(item, path=f"{path}.{key}")
        return payload
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            _reject_identity(item, path=f"{path}[{index}]")
    return payload


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class ContractorProgram(StrictModel):
    contractor_ref: OpaqueRef
    supplier_ref: OpaqueRef | None = None
    rate: Decimal
    rate_uom: RateUom
    monthly_cap: Decimal | None = None
    engagement_end: str | None = None

    @field_validator("rate", mode="before")
    @classmethod
    def _rate(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="rate")
        if result <= 0:
            raise ValueError("a contractor rate is positive")
        return result

    @field_validator("monthly_cap", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="monthly_cap")

    @field_validator("engagement_end")
    @classmethod
    def _end(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="engagement_end")


class ContractorPlan(StrictModel):
    """What the chain enforces: each contractor's rate and cap (and the payables identity their bills arrive under), whether agreement paper is required, and the payment window."""

    schema_id: str = Field(default=CONTRACTOR_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    programs: tuple[ContractorProgram, ...] = Field(min_length=1, max_length=500)
    require_agreement_paper: bool = True
    max_days_invoice_to_pay: int = Field(default=30, ge=1, le=180)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("programs", mode="before")
    @classmethod
    def _programs(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ContractorPlan":
        unique([item.contractor_ref for item in self.programs], label="contractor programs")
        if not skip_digests(info) and self.plan_digest != sealed_digest(ContractorPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def program(self, contractor_ref: str) -> ContractorProgram | None:
        return next((item for item in self.programs if item.contractor_ref == contractor_ref), None)


def compile_contractor_chain(company_ref: str, *, currency: str, programs: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> ContractorPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "programs": [dict(detached(item)) for item in programs], **dict(overrides or {})}
    return seal(ContractorPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class WorkRecord(StrictModel):
    work_ref: OpaqueRef
    period_ref: OpaqueRef
    units: Decimal
    value: Decimal
    recorded_at: str
    approver_ref: OpaqueRef
    work_digest: Sha256Digest

    @field_validator("units", "value", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class BillRecord(StrictModel):
    case_ref: OpaqueRef
    case_digest: Sha256Digest
    bill_ref: OpaqueRef
    amount: Decimal
    invoiced_at: str
    paid_at: str | None = None
    paid_digest: Sha256Digest | None = None

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class ContractorReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    contractor_ref: OpaqueRef | None = None
    agreement_source: dict[str, Any] | None = None
    agreement_plan: dict[str, Any] | None = None
    agreement_ref: OpaqueRef | None = None
    work_ref: OpaqueRef | None = None
    period_ref: OpaqueRef | None = None
    units: Decimal | None = None
    approver_ref: OpaqueRef | None = None
    work_provenance: dict[str, Any] | None = None
    work_digest: Sha256Digest | None = None
    payable_source: dict[str, Any] | None = None
    payable_plan: dict[str, Any] | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("units", mode="before")
    @classmethod
    def _units(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="units")


class ContractorLedger(StrictModel):
    contractor_ref: str | None = None
    agreement_ref: str | None = None
    agreement_digest: str | None = None
    engaged_at: str | None = None
    rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    rate_uom: str | None = None
    work: tuple[WorkRecord, ...] = Field(default_factory=tuple, max_length=500)
    units_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    work_value_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    uninvoiced_value: Decimal = Field(default=Decimal("0"), validate_default=True)
    monthly_value: dict[str, Decimal] = Field(default_factory=dict)
    bills: tuple[BillRecord, ...] = Field(default_factory=tuple, max_length=120)
    invoiced_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    paid_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    open_bill_ref: str | None = None
    ended_at: str | None = None
    end_reason: str | None = None
    outcome: Literal["open", "ended", "terminated"] = "open"

    @field_validator("work", "bills", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("rate", "units_total", "work_value_total", "uninvoiced_value", "invoiced_total", "paid_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("monthly_value", mode="before")
    @classmethod
    def _monthly(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="monthly_value") for key, item in dict(value or {}).items()}


class ContractorEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    contractor_paid: Literal[False] = False
    journal_posted: Literal[False] = False
    provider_read: Literal[False] = False


def _bind_payable(r: Any, plan: ContractorPlan, data: Mapping[str, Any], at: str, *, statuses: frozenset[str], code: str) -> Any:
    require(r.payable_source is not None and r.payable_plan is not None, "BILL_NOT_PROVEN", "the contractor's bill must be the replayed payable case and its plan")
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        bill_plan, bill = PAYABLES_CHAIN_LIFECYCLE.bind(r.payable_plan, r.payable_source)
    except (ValueError, TypeError, KeyError) as exc:
        require(False, "BILL_NOT_PROVEN", f"the payable must replay against its exact plan: {exc}"[:300])
        raise AssertionError from exc
    require(bill_plan.company_ref == plan.company_ref and bill.scope.currency == plan.currency, "BILL_SCOPE_MISMATCH", "the bill belongs to another company or currency")
    require(bill.status in statuses, code, f"the payable case is {bill.status}")
    program = plan.program(str(data.get("contractor_ref")))
    expected_supplier = (program.supplier_ref if program is not None and program.supplier_ref else None) or str(data.get("contractor_ref"))
    require(str(bill.ledger.supplier_ref) == expected_supplier, "SUPPLIER_MISMATCH", f"the bill is from {bill.ledger.supplier_ref}, not this contractor ({expected_supplier})")
    require(parsed(bill.transition_history[-1].command.occurred_at) <= parsed(at), "BILL_FROM_FUTURE", "the bill cannot come from the future")
    return bill


def _apply_contractor(plan: ContractorPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "engage":
        require(r.contractor_ref is not None, "CONTRACTOR_MISSING", "an engagement names the contractor commitment")
        program = plan.program(str(r.contractor_ref))
        require(program is not None, "CONTRACTOR_UNKNOWN", f"{r.contractor_ref} has no program in this plan")
        assert program is not None
        require(program.engagement_end is None or parsed(program.engagement_end) > parsed(at), "ENGAGEMENT_EXPIRED", "the program's engagement end has passed")
        agreement_digest = None
        if plan.require_agreement_paper:
            require(r.agreement_source is not None and r.agreement_plan is not None, "AGREEMENT_NOT_PROVEN", "the engagement must be the replayed obligation-paper agreement and its plan")
            from lightbulb.obligation_paper import AGREEMENT_LIFECYCLE

            try:
                paper_plan, agreement = AGREEMENT_LIFECYCLE.bind(r.agreement_plan, r.agreement_source)
            except (ValueError, TypeError, KeyError) as exc:
                require(False, "AGREEMENT_NOT_PROVEN", f"the agreement must replay against its exact plan: {exc}"[:300])
                raise AssertionError from exc
            require(paper_plan.company_ref == plan.company_ref, "AGREEMENT_SCOPE_MISMATCH", "the agreement belongs to another company")
            require(agreement.status in IN_FORCE_AGREEMENT_STATUSES, "AGREEMENT_NOT_IN_FORCE", f"the agreement is {agreement.status}")
            require(str(agreement.ledger.counterparty_ref) == str(r.contractor_ref), "COUNTERPARTY_MISMATCH", f"the agreement's counterparty is {agreement.ledger.counterparty_ref}, not {r.contractor_ref}")
            require(parsed(agreement.transition_history[-1].command.occurred_at) <= parsed(at), "AGREEMENT_FROM_FUTURE", "the agreement cannot come from the future")
            agreement_digest = agreement.state_digest
            data["agreement_ref"] = agreement.ledger.agreement_ref
        else:
            require(r.agreement_ref is not None, "AGREEMENT_MISSING", "an engagement names its agreement")
            data["agreement_ref"] = r.agreement_ref
        data.update({"contractor_ref": r.contractor_ref, "agreement_digest": agreement_digest, "engaged_at": at, "rate": str(program.rate), "rate_uom": program.rate_uom})
    elif event == "record_work":
        require(r.work_ref is not None and r.period_ref is not None and r.units is not None and r.approver_ref is not None and r.work_provenance is not None and r.work_digest is not None, "WORK_MISSING", "recorded work names itself, its period, its units, its approver, the read provenance, and its digest")
        require(str(dict(r.work_provenance or {}).get("output_digest")) == r.work_digest, "WORK_NOT_BOUND", "the provenance does not seal this work read")
        assert r.units is not None
        require(r.units > 0, "WORK_UNITS_INVALID", "recorded work is a positive number of units")
        require(all(str(dict(item)["work_digest"]) != r.work_digest and str(dict(item)["work_ref"]) != r.work_ref for item in data.get("work", ())), "WORK_ALREADY_RECORDED", "this work was already recorded")
        require(r.approver_ref != data.get("contractor_ref"), "SEGREGATION_VIOLATED", "a contractor cannot approve their own work")
        program = plan.program(str(data["contractor_ref"]))
        assert program is not None
        require(program.engagement_end is None or parsed(program.engagement_end) >= parsed(at), "ENGAGEMENT_EXPIRED", "work recorded after the engagement end")
        value = _money(r.units * program.rate)
        monthly = dict(data.get("monthly_value", {}))
        month_total = _money(Decimal(str(monthly.get(str(r.period_ref), "0"))) + value)
        require(program.monthly_cap is None or month_total <= program.monthly_cap, "MONTHLY_CAP_EXCEEDED", f"{month_total} in {r.period_ref} exceeds the {program.monthly_cap} cap", "await_approval")
        monthly[str(r.period_ref)] = str(month_total)
        record = WorkRecord(work_ref=str(r.work_ref), period_ref=str(r.period_ref), units=r.units, value=value, recorded_at=at, approver_ref=str(r.approver_ref), work_digest=str(r.work_digest)).to_dict()
        data.update({"work": [*[dict(item) for item in data.get("work", ())], record], "units_total": str(_money(Decimal(str(data["units_total"])) + r.units)), "work_value_total": str(_money(Decimal(str(data["work_value_total"])) + value)), "uninvoiced_value": str(_money(Decimal(str(data["uninvoiced_value"])) + value)), "monthly_value": monthly})
    elif event == "invoice":
        bill = _bind_payable(r, plan, data, at, statuses=COSTABLE_PAYABLE_STATUSES, code="BILL_NOT_APPROVED")
        uninvoiced = Decimal(str(data["uninvoiced_value"]))
        amount = _money(bill.ledger.amount)
        require(amount == uninvoiced, "BILL_WORK_MISMATCH", f"the bill is {amount}; the uninvoiced work is worth {uninvoiced}", "manual_reconciliation")
        require(all(str(dict(item)["case_digest"]) != bill.state_digest and str(dict(item)["case_ref"]) != bill.scope.entity_ref for item in data.get("bills", ())), "BILL_ALREADY_RECORDED", "this bill was already recorded")
        record = BillRecord(case_ref=bill.scope.entity_ref, case_digest=bill.state_digest, bill_ref=str(bill.ledger.bill_ref), amount=amount, invoiced_at=at).to_dict()
        data.update({"bills": [*[dict(item) for item in data.get("bills", ())], record], "invoiced_total": str(_money(Decimal(str(data["invoiced_total"])) + amount)), "uninvoiced_value": "0", "open_bill_ref": bill.scope.entity_ref})
    elif event == "pay":
        bill = _bind_payable(r, plan, data, at, statuses=PAID_PAYABLE_STATUSES, code="BILL_NOT_PAID")
        require(bill.scope.entity_ref == data.get("open_bill_ref"), "BILL_MISMATCH", f"{bill.scope.entity_ref} is not the open bill {data.get('open_bill_ref')}")
        bills = [dict(item) for item in data.get("bills", ())]
        current = next(item for item in bills if item["case_ref"] == bill.scope.entity_ref)
        require(bill.ledger.paid_at is not None, "BILL_NOT_PAID", "the payable case carries no payment time")
        days = (parsed(str(bill.ledger.paid_at)) - parsed(str(current["invoiced_at"]))).days
        require(days <= plan.max_days_invoice_to_pay, "PAYMENT_LATE", f"the bill was paid {days} days after invoicing; the plan allows {plan.max_days_invoice_to_pay}", "manual_reconciliation")
        current.update({"paid_at": str(bill.ledger.paid_at), "paid_digest": bill.state_digest})
        data.update({"bills": bills, "paid_total": str(_money(Decimal(str(data["paid_total"])) + Decimal(str(current["amount"])))), "open_bill_ref": None})
    elif event == "end":
        require(Decimal(str(data.get("uninvoiced_value", "0"))) == 0, "WORK_UNINVOICED", f"{data.get('uninvoiced_value')} of recorded work is not invoiced; invoice it or terminate with a reason")
        data.update({"ended_at": at, "end_reason": None if command.reason is None else str(command.reason)[:300], "outcome": "ended"})
    elif event == "terminate":
        data.update({"ended_at": at, "end_reason": str(command.reason)[:300], "outcome": "terminated"})
    return next_status, data


CONTRACTOR_LIFECYCLE = LifecycleSpec(entity="contractor_engagement", schema_prefix=CONTRACTOR_KIND, statuses=CONTRACTOR_STATUSES, terminal=TERMINAL_CONTRACTOR_STATUSES, events=CONTRACTOR_EVENTS, table=_CONTRACTOR_TABLE, opening_event="engage", reason_events=("terminate",), apply=_apply_contractor, ledger_model=ContractorLedger, receipt_model=ContractorReceipt, effect_boundary_model=ContractorEffectBoundary, plan_model=ContractorPlan, max_transitions=MAX_CONTRACTOR_TRANSITIONS)
ContractorEngagementState = CONTRACTOR_LIFECYCLE.State


def open_contractor_engagement(plan: ContractorPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return CONTRACTOR_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_contractor_engagement(plan: ContractorPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CONTRACTOR_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def engagement_receipt(agreement_state: Any, *, source_plan: Any, contractor_ref: str) -> dict[str, Any]:
    from lightbulb.obligation_paper import AGREEMENT_LIFECYCLE

    try:
        plan, state = AGREEMENT_LIFECYCLE.bind(source_plan, agreement_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise ContractorChainError("AGREEMENT_NOT_PROVEN", "retain the original agreement state and its sealed plan") from exc
    _require(state.status in IN_FORCE_AGREEMENT_STATUSES, "AGREEMENT_NOT_IN_FORCE", f"the agreement is {state.status}")
    return {"contractor_ref": contractor_ref, "agreement_source": state.to_dict(), "agreement_plan": plan.to_dict(), "evidence_refs": [f"agreement:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def work_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, work_ref: str, period_ref: str, approver_ref: str) -> dict[str, Any]:
    """From a host-lane timesheet or deliverable read: the units of work the read carries, approved by someone other than the contractor."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in WORK_TOOLS, "WORK_NOT_BOUND", f"expected a read from {sorted(WORK_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "WORK_NOT_BOUND", f"the provenance lacks {key}")
    raw = _reject_identity(dict(detached(payload)), path="work")
    _require(str(prov["output_digest"]) == stable_digest(raw), "WORK_NOT_BOUND", "the provenance does not seal this exact work read")
    units = raw.get("units") if raw.get("units") is not None else (raw.get("hours") if raw.get("hours") is not None else raw.get("quantity"))
    _require(units is not None, "WORK_INCOMPLETE", "a work read carries its units, hours, or quantity")
    return {"work_ref": work_ref, "period_ref": period_ref, "units": str(decimal_value(units, field_name="units")), "approver_ref": approver_ref, "work_provenance": prov, "work_digest": str(prov["output_digest"]), "evidence_refs": [f"work:{prov['observation_ref']}"]}


def _payable(payable_state: Any, *, source_plan: Any, statuses: frozenset[str], code: str) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise ContractorChainError("BILL_NOT_PROVEN", "retain the original payable state and its sealed plan") from exc
    _require(state.status in statuses, code, f"the payable case is {state.status}")
    return {"payable_source": state.to_dict(), "payable_plan": plan.to_dict(), "evidence_refs": [f"payable:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def invoice_receipt(payable_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """From the contractor's payable case once the bill is approved (or further along)."""

    return _payable(payable_state, source_plan=source_plan, statuses=COSTABLE_PAYABLE_STATUSES, code="BILL_NOT_APPROVED")


def payment_receipt(payable_state: Any, *, source_plan: Any) -> dict[str, Any]:
    """From the same payable case once paid or cleared."""

    return _payable(payable_state, source_plan=source_plan, statuses=PAID_PAYABLE_STATUSES, code="BILL_NOT_PAID")


def contractor_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in CONTRACTOR_STATUSES}
    return {"engagements": len(states), "by_status": counts, "units_recorded": str(sum((state.ledger.units_total for state in states), Decimal("0")).quantize(_QTY)), "work_value": str(_money(sum((state.ledger.work_value_total for state in states), Decimal("0")))), "uninvoiced_value": str(_money(sum((state.ledger.uninvoiced_value for state in states), Decimal("0")))), "invoiced_unpaid": str(_money(sum((state.ledger.invoiced_total - state.ledger.paid_total for state in states), Decimal("0")))), "paid": str(_money(sum((state.ledger.paid_total for state in states), Decimal("0"))))}


CONTRACTOR_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": CONTRACTOR_KIND,
    "golden_loop": CONTRACTOR_GOLDEN_LOOP,
    "stages": ["engage", "record_work", "invoice", "pay", "end"],
    "statuses": list(CONTRACTOR_STATUSES),
    "events": list(CONTRACTOR_EVENTS),
    "hops": {"engage": "the contractor's replayed obligation-paper agreement, in force, naming the contractor as counterparty; the rate from the plan", "record_work": "host-lane timesheet or deliverable read approved by someone other than the contractor; valued at the rate, capped per month", "invoice": "the contractor's replayed payable case equal to the uninvoiced work value", "pay": "the same payable case paid or cleared inside the plan's window", "end": "no uninvoiced work outstanding"},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "a contractor is an opaque commitment under an in-force agreement; identity never enters the engine",
        "work is valued at the program's rate from an approved read, never typed, and capped per month",
        "a bill enters only when it equals the recorded uninvoiced work; anything else is reconciled by a human",
        "payment is the payables chain's proof, replayed here",
    ],
}

__all__ = ["CONTRACTOR_EVENTS", "CONTRACTOR_GOLDEN_LOOP", "CONTRACTOR_KIND", "CONTRACTOR_LIFECYCLE", "CONTRACTOR_MANIFEST", "CONTRACTOR_STATUSES", "TERMINAL_CONTRACTOR_STATUSES", "WORK_TOOLS", "BillRecord", "ContractorChainError", "ContractorEngagementState", "ContractorLedger", "ContractorPlan", "ContractorProgram", "ContractorReceipt", "WorkRecord", "advance_contractor_engagement", "compile_contractor_chain", "contractor_summary", "engagement_receipt", "invoice_receipt", "open_contractor_engagement", "payment_receipt", "work_receipt"]
