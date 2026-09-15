"""The work order chain: one replay-fenced lifecycle per maintenance, production, or remediation job, from the request to the costed completion.

The regulated-operations controls (``compliance.evaluate_regulated_controls``)
say whether a job may proceed; the maintenance and manufacturing modules
propose transitions.  Nothing carried the money: what the job was expected
to cost, who approved it and under what authority, the parts bought for it,
the hours spent on it, what it actually cost, and whether that cost reached
the register.  ``WORK_ORDER_LIFECYCLE`` does:

    raised -> approved -> in_progress -> (record_parts | record_labour)* -> completed -> costed   (terminal)
    raised | approved | in_progress -> cancelled                                                 (terminal, with a reason)

* ``request_receipt`` names the job, its kind, the asset, the estimate, and
  the target date; ``approve`` is by someone other than the requester and,
  at or above the plan's threshold, a ``commitment`` authority decision.
* ``start`` binds the regulated-controls result (digest verified, controls
  satisfied) when the plan requires it.
* ``parts_receipt`` is the supplier's replayed payable case (approved or
  further); ``labour_receipt`` is a timesheet read costed at the plan's
  internal rate.  Each enters once.
* ``complete`` fixes the actual cost and the variance against the estimate;
  ``register_cost`` binds the replayed cost register that carries the job's
  labour as a source, so the chain knows its cost reached the books.

``work_order_cost_receipt`` hands the cost register the job's labour (the
parts bills are already payables in the register), ``overdue_work_orders``
and ``signals.work_order_overdue`` name the jobs past their target.  Nothing
here dispatches anyone, moves stock, or persists anything.
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
)

WORK_ORDER_KIND = "work_order_chain"
WORK_ORDER_GOLDEN_LOOP = "operations.raised_work_order_to_costed_completion@0.1.0"
WORK_ORDER_PLAN_SCHEMA = "lightbulb.work_order_plan.v1"
MAX_WORK_ORDER_TRANSITIONS = 200
PARTS_PAYABLE_STATUSES: frozenset[str] = frozenset({"approved", "scheduled", "paid", "cleared"})
TIMESHEET_TOOLS: frozenset[str] = frozenset({"host.timesheets", "xero.list_time_entries", "deputy.list_timesheets", "xero.list_payroll_au_timesheets"})
WorkKind = Literal["maintenance", "production", "remediation", "inspection"]
WORK_KINDS: tuple[str, ...] = ("maintenance", "production", "remediation", "inspection")
Outcome = Literal["returned_to_service", "scrapped", "deferred", "produced"]
HOURS_QUANTUM = Decimal("0.01")

WORK_ORDER_STATUSES: tuple[str, ...] = ("raised", "approved", "in_progress", "completed", "costed", "cancelled")
TERMINAL_WORK_ORDER_STATUSES: frozenset[str] = frozenset({"costed", "cancelled"})
WORK_ORDER_EVENTS: tuple[str, ...] = ("raise", "approve", "start", "record_parts", "record_stock", "record_labour", "record_contractor_labour", "complete", "register_cost", "cancel")
_WORK_ORDER_TABLE: dict[tuple[str, str], str] = {
    ("new", "raise"): "raised",
    ("raised", "approve"): "approved",
    ("approved", "start"): "in_progress",
    ("in_progress", "record_parts"): "in_progress",
    ("in_progress", "record_labour"): "in_progress",
    ("in_progress", "record_stock"): "in_progress",
    ("in_progress", "record_contractor_labour"): "in_progress",
    ("in_progress", "complete"): "completed",
    ("completed", "register_cost"): "costed",
    ("raised", "cancel"): "cancelled",
    ("approved", "cancel"): "cancelled",
    ("in_progress", "cancel"): "cancelled",
}


class WorkOrderError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise WorkOrderError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _hours(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(HOURS_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class WorkOrderPlan(StrictModel):
    """What the chain enforces: the kinds of work, when approval needs authority, whether controls gate the start, and what an internal hour costs."""

    schema_id: str = Field(default=WORK_ORDER_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    kinds: tuple[WorkKind, ...] = Field(default=WORK_KINDS, validate_default=True)
    approval_threshold: Decimal = Field(default=Decimal("5000"), validate_default=True)
    require_controls: bool = True
    internal_labour_rate: Decimal = Field(default=Decimal("0"), validate_default=True)
    overrun_tolerance_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("kinds", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("approval_threshold", "internal_labour_rate", "overrun_tolerance_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "WorkOrderPlan":
        if not self.kinds:
            raise ValueError("a work order plan allows at least one kind of work")
        if not skip_digests(info) and self.plan_digest != sealed_digest(WorkOrderPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_work_order_chain(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> WorkOrderPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}
    return seal(WorkOrderPlan, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class PartsRecord(StrictModel):
    payable_ref: OpaqueRef
    supplier_ref: OpaqueRef | None = None
    amount: Decimal
    payable_digest: Sha256Digest

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class LabourRecord(StrictModel):
    worker_ref: OpaqueRef
    period_ref: OpaqueRef
    hours: Decimal
    cost: Decimal
    timesheet_digest: Sha256Digest

    @field_validator("hours", mode="before")
    @classmethod
    def _hours_value(cls, value: Any) -> Decimal:
        return _hours(value)

    @field_validator("cost", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="cost")


class StockRecord(StrictModel):
    position_ref: OpaqueRef
    sku_ref: OpaqueRef | None = None
    units: Decimal
    unit_cost: Decimal
    value: Decimal
    inventory_digest: Sha256Digest

    @field_validator("units", "unit_cost", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return Decimal(str(value))

    @field_validator("value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")


class ContractorRecord(StrictModel):
    contractor_ref: OpaqueRef
    work_ref: OpaqueRef
    units: Decimal
    value: Decimal
    contractor_digest: Sha256Digest

    @field_validator("units", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return Decimal(str(value))

    @field_validator("value", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="value")


class WorkOrderReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    work_order_ref: OpaqueRef | None = None
    kind: WorkKind | None = None
    asset_ref: OpaqueRef | None = None
    description: BoundedText | None = None
    estimated_cost: Decimal | None = None
    requested_by: OpaqueRef | None = None
    target_at: str | None = None
    approver_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    controls_result: dict[str, Any] | None = None
    started_at: str | None = None
    payable_source: dict[str, Any] | None = None
    payable_plan: dict[str, Any] | None = None
    inventory_source: dict[str, Any] | None = None
    inventory_plan: dict[str, Any] | None = None
    issue_ref: OpaqueRef | None = None
    contractor_source: dict[str, Any] | None = None
    contractor_plan: dict[str, Any] | None = None
    work_ref: OpaqueRef | None = None
    worker_ref: OpaqueRef | None = None
    period_ref: OpaqueRef | None = None
    hours: Decimal | None = None
    timesheet_provenance: dict[str, Any] | None = None
    timesheet_digest: Sha256Digest | None = None
    completed_at: str | None = None
    checklist_sha256: Sha256Digest | None = None
    outcome: Outcome | None = None
    register_source: dict[str, Any] | None = None
    register_plan: dict[str, Any] | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("estimated_cost", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="estimated_cost")

    @field_validator("hours", mode="before")
    @classmethod
    def _hours_value(cls, value: Any) -> Decimal | None:
        return None if value is None else _hours(value)

    @field_validator("target_at", "started_at", "completed_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class WorkOrderLedger(StrictModel):
    work_order_ref: str | None = None
    kind: str | None = None
    asset_ref: str | None = None
    description: str | None = None
    estimated_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    requested_by: str | None = None
    raised_at: str | None = None
    target_at: str | None = None
    approver_ref: str | None = None
    approved_at: str | None = None
    approval_ref: str | None = None
    controls_digest: str | None = None
    controls_ref: str | None = None
    started_at: str | None = None
    parts: tuple[PartsRecord, ...] = Field(default_factory=tuple, max_length=100)
    parts_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    stock: tuple[StockRecord, ...] = Field(default_factory=tuple, max_length=200)
    stock_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    contractor_labour: tuple[ContractorRecord, ...] = Field(default_factory=tuple, max_length=200)
    contractor_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    labour: tuple[LabourRecord, ...] = Field(default_factory=tuple, max_length=200)
    labour_hours: Decimal = Field(default=Decimal("0"), validate_default=True)
    labour_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    actual_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    variance: Decimal = Field(default=Decimal("0"), validate_default=True)
    overrun: bool = False
    completed_at: str | None = None
    checklist_sha256: str | None = None
    work_outcome: str | None = None
    register_digest: str | None = None
    costed_at: str | None = None
    cancel_reason: str | None = None
    outcome: Literal["open", "costed", "cancelled"] = "open"

    @field_validator("parts", "stock", "contractor_labour", "labour", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("estimated_cost", "parts_cost", "stock_cost", "contractor_cost", "labour_cost", "actual_cost", "variance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("labour_hours", mode="before")
    @classmethod
    def _hours_value(cls, value: Any) -> Decimal:
        return _hours(value)


class WorkOrderEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    labour_dispatched: Literal[False] = False
    stock_moved: Literal[False] = False
    money_moved: Literal[False] = False
    provider_read: Literal[False] = False


def _strip_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _strip_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, (list, tuple)):
        return [_strip_none(item) for item in value]
    return value


def _verify_controls(result: Mapping[str, Any]) -> tuple[str, str]:
    """Recompute the regulated-controls result digest from its dict; returns (evaluation_ref, digest)."""

    from lightbulb.compliance_controls import REGULATED_CONTROLS_RESULT_SCHEMA, _digest

    payload = dict(detached(result))
    _require(str(payload.get("schema")) == REGULATED_CONTROLS_RESULT_SCHEMA, "CONTROLS_NOT_PROVEN", f"expected a {REGULATED_CONTROLS_RESULT_SCHEMA} result")
    claimed = str(payload.get("result_digest", ""))
    expected = _digest(_strip_none({key: value for key, value in payload.items() if key != "result_digest"}))
    _require(claimed == expected, "CONTROLS_NOT_PROVEN", "the result digest does not match the result")
    return str(payload.get("evaluation_ref")), claimed


def _apply_work_order(plan: WorkOrderPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "raise":
        require(r.work_order_ref is not None and r.kind is not None and r.asset_ref is not None and r.estimated_cost is not None and r.requested_by is not None and r.target_at is not None, "REQUEST_MISSING", "a work order names itself, its kind, the asset, the estimate, who asked, and the target date")
        require(r.kind in plan.kinds, "KIND_NOT_ALLOWED", f"{r.kind} is not a kind of work this plan allows")
        assert r.estimated_cost is not None
        require(r.estimated_cost >= 0, "ESTIMATE_INVALID", "an estimate is never negative")
        require(parsed(str(r.target_at)) > parsed(at), "TARGET_IN_PAST", "the target date is ahead of the request")
        data.update({"work_order_ref": r.work_order_ref, "kind": r.kind, "asset_ref": r.asset_ref, "description": r.description, "estimated_cost": str(_money(r.estimated_cost)), "requested_by": r.requested_by, "raised_at": at, "target_at": r.target_at})
    elif event == "approve":
        require(r.approver_ref is not None, "APPROVER_MISSING", "an approval names the approver")
        require(str(r.approver_ref) != str(data.get("requested_by")), "SEGREGATION_VIOLATED", "the requester cannot approve their own work order")
        estimate = Decimal(str(data["estimated_cost"]))
        approval_ref = None
        if estimate >= plan.approval_threshold:
            require(r.authorization_proof is not None, "WORK_ORDER_NOT_AUTHORIZED", f"a job estimated at {estimate} {plan.currency} is a commitment decision; a human decides it", "await_approval")
            from lightbulb.authority_matrix import require_authorization_proof

            proof = require_authorization_proof(r.authorization_proof, category="commitment", amount=estimate, currency=plan.currency, command=command, plan_digest=plan.plan_digest, company_ref=plan.company_ref)
            require(proof.engine == WORK_ORDER_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
            require(proof.approver_ref != data.get("requested_by"), "SEGREGATION_VIOLATED", "the requester cannot approve their own work order")
            approval_ref = proof.approval_task_id
        data.update({"approver_ref": r.approver_ref, "approved_at": at, "approval_ref": approval_ref})
    elif event == "start":
        require(r.started_at is not None, "START_MISSING", "starting names when work began")
        require(parsed(str(data["approved_at"])) <= parsed(str(r.started_at)) <= parsed(at), "START_TIME_INVALID", "work starts after approval and before the recording")
        controls_ref = controls_digest = None
        if plan.require_controls:
            require(r.controls_result is not None, "CONTROLS_MISSING", "the plan requires the regulated-controls result before work starts", "await_approval")
            try:
                controls_ref, controls_digest = _verify_controls(r.controls_result or {})
            except WorkOrderError as exc:
                require(False, exc.code, str(exc))
                raise AssertionError from exc
            payload = dict(r.controls_result or {})
            require(str(payload.get("proposed_disposition")) == "controls_satisfied", "CONTROLS_NOT_SATISFIED", f"the controls result is {payload.get('proposed_disposition')}; work starts only when controls are satisfied", "manual_reconciliation")
            require(parsed(str(payload.get("analysis_as_of"))) <= parsed(at), "CONTROLS_FROM_FUTURE", "the controls evaluation cannot come from the future")
        data.update({"started_at": r.started_at, "controls_ref": controls_ref, "controls_digest": controls_digest})
    elif event == "record_parts":
        require(r.payable_source is not None and r.payable_plan is not None, "PARTS_NOT_PROVEN", "parts are the supplier's replayed payable case")
        from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

        try:
            bill_plan, bill = PAYABLES_CHAIN_LIFECYCLE.bind(r.payable_plan, r.payable_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "PARTS_NOT_PROVEN", f"the payable must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(bill_plan.company_ref == plan.company_ref and bill.scope.currency == plan.currency, "PARTS_SCOPE_MISMATCH", "the bill belongs to another company or currency")
        require(bill.status in PARTS_PAYABLE_STATUSES, "PARTS_NOT_APPROVED", f"the payable case is {bill.status}; parts cost from an approved bill")
        require(parsed(bill.transition_history[-1].command.occurred_at) <= parsed(at), "PARTS_FROM_FUTURE", "the bill cannot come from the future")
        require(all(bill.scope.entity_ref != item["payable_ref"] for item in data.get("parts", ())), "PARTS_ALREADY_RECORDED", f"{bill.scope.entity_ref} is already on this work order")
        record = PartsRecord(payable_ref=bill.scope.entity_ref, supplier_ref=str(bill.ledger.supplier_ref), amount=_money(bill.ledger.amount), payable_digest=bill.state_digest).to_dict()
        parts = [*[dict(item) for item in data.get("parts", ())], record]
        data.update({"parts": parts, "parts_cost": str(_money(sum(Decimal(str(item["amount"])) for item in parts)))})
    elif event == "record_stock":
        require(r.inventory_source is not None and r.inventory_plan is not None and r.issue_ref is not None, "STOCK_NOT_PROVEN", "stock is the replayed inventory position that issued it")
        from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

        try:
            stock_plan, position = INVENTORY_LIFECYCLE.bind(r.inventory_plan, r.inventory_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "STOCK_NOT_PROVEN", f"the position must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(stock_plan.company_ref == plan.company_ref and stock_plan.currency == plan.currency, "STOCK_SCOPE_MISMATCH", "the position belongs to another company or currency")
        issue = next((item for item in position.ledger.issues if item.issue_ref == str(r.issue_ref)), None)
        require(issue is not None, "ISSUE_NOT_ON_POSITION", f"{position.scope.entity_ref} issued nothing as {r.issue_ref}")
        assert issue is not None
        require(issue.purpose == "work_order" and str(r.issue_ref) == f"work_order:{data['work_order_ref']}", "ISSUE_NOT_FOR_THIS_JOB", f"the issue {r.issue_ref} was not drawn for work order {data['work_order_ref']}")
        require(parsed(issue.issued_at) <= parsed(at), "STOCK_FROM_FUTURE", "the issue cannot come from the future")
        require(all(position.scope.entity_ref != item["position_ref"] for item in data.get("stock", ())), "STOCK_ALREADY_RECORDED", f"{position.scope.entity_ref} already issued to this work order")
        record = StockRecord(position_ref=position.scope.entity_ref, sku_ref=position.ledger.sku_ref, units=issue.units, unit_cost=issue.unit_cost, value=_money(issue.value), inventory_digest=position.state_digest).to_dict()
        stock = [*[dict(item) for item in data.get("stock", ())], record]
        data.update({"stock": stock, "stock_cost": str(_money(sum(Decimal(str(item["value"])) for item in stock)))})
    elif event == "record_contractor_labour":
        require(r.contractor_source is not None and r.contractor_plan is not None and r.work_ref is not None, "CONTRACTOR_WORK_NOT_PROVEN", "contractor labour is the replayed engagement that recorded the work")
        from lightbulb.contractor_chain import CONTRACTOR_LIFECYCLE

        try:
            contractor_plan, engagement = CONTRACTOR_LIFECYCLE.bind(r.contractor_plan, r.contractor_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "CONTRACTOR_WORK_NOT_PROVEN", f"the engagement must replay against its exact plan: {exc}"[:300])
            raise AssertionError from exc
        require(contractor_plan.company_ref == plan.company_ref and contractor_plan.currency == plan.currency, "CONTRACTOR_SCOPE_MISMATCH", "the engagement belongs to another company or currency")
        work = next((item for item in engagement.ledger.work if item.work_ref == str(r.work_ref)), None)
        require(work is not None, "WORK_NOT_ON_ENGAGEMENT", f"{engagement.scope.entity_ref} recorded no work {r.work_ref}")
        assert work is not None
        require(parsed(work.recorded_at) <= parsed(at), "CONTRACTOR_WORK_FROM_FUTURE", "the work cannot come from the future")
        require(all(str(r.work_ref) != item["work_ref"] for item in data.get("contractor_labour", ())), "CONTRACTOR_WORK_ALREADY_RECORDED", f"{r.work_ref} is already on this work order")
        record = ContractorRecord(contractor_ref=str(engagement.ledger.contractor_ref), work_ref=str(r.work_ref), units=work.units, value=_money(work.value), contractor_digest=engagement.state_digest).to_dict()
        rows = [*[dict(item) for item in data.get("contractor_labour", ())], record]
        data.update({"contractor_labour": rows, "contractor_cost": str(_money(sum(Decimal(str(item["value"])) for item in rows)))})
    elif event == "record_labour":
        require(r.worker_ref is not None and r.period_ref is not None and r.hours is not None and r.timesheet_provenance is not None and r.timesheet_digest is not None, "LABOUR_NOT_PROVEN", "labour is a timesheet read for one worker and period")
        require(str(dict(r.timesheet_provenance or {}).get("output_digest")) == r.timesheet_digest, "LABOUR_NOT_PROVEN", "the provenance does not seal this timesheet read")
        assert r.hours is not None
        require(r.hours > 0, "LABOUR_HOURS_INVALID", "recorded labour is a positive number of hours")
        require(plan.internal_labour_rate > 0, "LABOUR_RATE_MISSING", "the plan names no internal labour rate; labour cannot be costed", "correct_input")
        require(all(not (item["worker_ref"] == str(r.worker_ref) and item["period_ref"] == str(r.period_ref)) for item in data.get("labour", ())), "LABOUR_ALREADY_RECORDED", f"{r.worker_ref} for {r.period_ref} is already on this work order")
        cost = _money(r.hours * plan.internal_labour_rate)
        record = LabourRecord(worker_ref=str(r.worker_ref), period_ref=str(r.period_ref), hours=r.hours, cost=cost, timesheet_digest=str(r.timesheet_digest)).to_dict()
        labour = [*[dict(item) for item in data.get("labour", ())], record]
        data.update({"labour": labour, "labour_hours": str(_hours(sum(Decimal(str(item["hours"])) for item in labour))), "labour_cost": str(_money(sum(Decimal(str(item["cost"])) for item in labour)))})
    elif event == "complete":
        require(r.completed_at is not None and r.checklist_sha256 is not None and r.outcome is not None, "COMPLETION_MISSING", "completion names when, the checklist's digest, and the outcome")
        require(parsed(str(data["started_at"])) <= parsed(str(r.completed_at)) <= parsed(at), "COMPLETION_TIME_INVALID", "work completes after it starts and before the recording")
        actual = _money(Decimal(str(data["parts_cost"])) + Decimal(str(data["stock_cost"])) + Decimal(str(data["contractor_cost"])) + Decimal(str(data["labour_cost"])))
        estimate = Decimal(str(data["estimated_cost"]))
        variance = _money(actual - estimate)
        overrun = actual > _money(estimate * (Decimal("100") + plan.overrun_tolerance_percent) / Decimal("100"))
        data.update({"completed_at": r.completed_at, "checklist_sha256": r.checklist_sha256, "work_outcome": r.outcome, "actual_cost": str(actual), "variance": str(variance), "overrun": overrun})
    elif event == "register_cost":
        require(r.register_source is not None and r.register_plan is not None, "REGISTER_NOT_PROVEN", "costing binds the replayed cost register that carries this job")
        from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

        try:
            register_map, register = COST_REGISTER_LIFECYCLE.bind(r.register_plan, r.register_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "REGISTER_NOT_PROVEN", f"the register must replay against its exact map: {exc}"[:300])
            raise AssertionError from exc
        require(register_map.company_ref == plan.company_ref and register_map.currency == plan.currency, "REGISTER_SCOPE_MISMATCH", "the register belongs to another company or currency")
        expected_ref = f"work_order:{data['work_order_ref']}"
        labour_cost = _money(Decimal(str(data["labour_cost"])) + Decimal(str(data["stock_cost"])))
        if labour_cost > 0:
            source = next((item for item in register.ledger.sources if str(item.source_ref) == expected_ref), None)
            require(source is not None, "COST_NOT_IN_REGISTER", f"the register carries no source {expected_ref}")
            assert source is not None
            require(_money(source.amount) == labour_cost, "COST_AMOUNT_MISMATCH", f"the register carries {source.amount} for {expected_ref}; the job's own cost (labour and stock) is {labour_cost}")
        for item in data.get("parts", ()):
            require(any(str(source.source_ref).endswith(str(item["payable_ref"])) or str(item["payable_ref"]) in str(source.source_ref) for source in register.ledger.sources), "PARTS_NOT_IN_REGISTER", f"the register carries no payable source for {item['payable_ref']}")
        data.update({"register_digest": register.state_digest, "costed_at": at, "outcome": "costed"})
    elif event == "cancel":
        data.update({"cancel_reason": str(command.reason)[:300], "outcome": "cancelled"})
    return next_status, data


WORK_ORDER_LIFECYCLE = LifecycleSpec(entity="work_order", schema_prefix=WORK_ORDER_KIND, statuses=WORK_ORDER_STATUSES, terminal=TERMINAL_WORK_ORDER_STATUSES, events=WORK_ORDER_EVENTS, table=_WORK_ORDER_TABLE, opening_event="raise", reason_events=("cancel",), apply=_apply_work_order, ledger_model=WorkOrderLedger, receipt_model=WorkOrderReceipt, effect_boundary_model=WorkOrderEffectBoundary, plan_model=WorkOrderPlan, max_transitions=MAX_WORK_ORDER_TRANSITIONS)
WorkOrderState = WORK_ORDER_LIFECYCLE.State


def open_work_order(plan: WorkOrderPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return WORK_ORDER_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_work_order(plan: WorkOrderPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return WORK_ORDER_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def request_receipt(*, work_order_ref: str, kind: str, asset_ref: str, estimated_cost: Any, requested_by: str, target_at: str, description: str | None = None) -> dict[str, Any]:
    _require(kind in WORK_KINDS, "KIND_UNKNOWN", f"{kind} is not one of {WORK_KINDS}")
    return {"work_order_ref": work_order_ref, "kind": kind, "asset_ref": asset_ref, "estimated_cost": str(_money(decimal_value(estimated_cost, field_name="estimated_cost"))), "requested_by": requested_by, "target_at": timestamp(target_at, field_name="target_at"), "description": description, "evidence_refs": [f"work_order:{work_order_ref}"]}


def approval_receipt(*, approver_ref: str, proof: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
    receipt: dict[str, Any] = {"approver_ref": approver_ref, "evidence_refs": [f"approver:{approver_ref}"]}
    if proof is not None:
        from lightbulb.authority_matrix import authorization_evidence

        evidence = authorization_evidence(proof)
        receipt["authorization_proof"] = evidence["authorization_proof"]
        receipt["evidence_refs"].extend(evidence["evidence_refs"])
    return receipt


def controls_receipt(result: Any, *, started_at: str) -> dict[str, Any]:
    """The regulated-controls result (``compliance.evaluate_regulated_controls``) that gates the start, verified by its digest."""

    payload = result.to_dict() if hasattr(result, "to_dict") else dict(detached(result))
    ref, digest = _verify_controls(payload)
    return {"controls_result": payload, "started_at": timestamp(started_at, field_name="started_at"), "evidence_refs": [f"controls:{ref}:{digest[:16]}"]}


def parts_receipt(payable_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.payables_chain import PAYABLES_CHAIN_LIFECYCLE

    try:
        plan, state = PAYABLES_CHAIN_LIFECYCLE.bind(source_plan, payable_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise WorkOrderError("PARTS_NOT_PROVEN", "retain the original payable state and its sealed plan") from exc
    _require(state.status in PARTS_PAYABLE_STATUSES, "PARTS_NOT_APPROVED", f"the payable case is {state.status}")
    return {"payable_source": state.to_dict(), "payable_plan": plan.to_dict(), "evidence_refs": [f"payable:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def stock_receipt(inventory_state: Any, *, source_plan: Any, issue_ref: str) -> dict[str, Any]:
    """The replayed inventory position that issued stock to this job (``inventory_chain.issue`` with purpose ``work_order``)."""

    from lightbulb.inventory_chain import INVENTORY_LIFECYCLE

    try:
        plan, state = INVENTORY_LIFECYCLE.bind(source_plan, inventory_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise WorkOrderError("STOCK_NOT_PROVEN", "retain the original position state and its sealed plan") from exc
    _require(any(item.issue_ref == issue_ref for item in state.ledger.issues), "ISSUE_NOT_ON_POSITION", f"{state.scope.entity_ref} issued nothing as {issue_ref}")
    return {"inventory_source": state.to_dict(), "inventory_plan": plan.to_dict(), "issue_ref": issue_ref, "evidence_refs": [f"inventory:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def contractor_labour_receipt(contractor_state: Any, *, source_plan: Any, work_ref: str) -> dict[str, Any]:
    """The replayed contractor engagement that recorded ``work_ref``; its value reaches the register through the contractor's own bill."""

    from lightbulb.contractor_chain import CONTRACTOR_LIFECYCLE

    try:
        plan, state = CONTRACTOR_LIFECYCLE.bind(source_plan, contractor_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise WorkOrderError("CONTRACTOR_WORK_NOT_PROVEN", "retain the original engagement state and its sealed plan") from exc
    _require(any(item.work_ref == work_ref for item in state.ledger.work), "WORK_NOT_ON_ENGAGEMENT", f"{state.scope.entity_ref} recorded no work {work_ref}")
    return {"contractor_source": state.to_dict(), "contractor_plan": plan.to_dict(), "work_ref": work_ref, "evidence_refs": [f"contractor:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def labour_receipt(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any, *, worker_ref: str, period_ref: str) -> dict[str, Any]:
    """From a timesheet read: the hours one worker booked to this job in one period."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in TIMESHEET_TOOLS, "LABOUR_NOT_PROVEN", f"expected a read from {sorted(TIMESHEET_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "LABOUR_NOT_PROVEN", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "LABOUR_NOT_PROVEN", "the provenance does not seal this exact timesheet read")
    hours = raw.get("hours") if raw.get("hours") is not None else (None if raw.get("minutes") is None else Decimal(str(raw["minutes"])) / 60)
    _require(hours is not None, "LABOUR_INCOMPLETE", "a timesheet read carries the hours")
    return {"worker_ref": worker_ref, "period_ref": period_ref, "hours": str(_hours(decimal_value(hours, field_name="hours"))), "timesheet_provenance": prov, "timesheet_digest": str(prov["output_digest"]), "evidence_refs": [f"timesheet:{prov['observation_ref']}"]}


def completion_receipt(*, completed_at: str, checklist_sha256: str, outcome: str) -> dict[str, Any]:
    return {"completed_at": timestamp(completed_at, field_name="completed_at"), "checklist_sha256": checklist_sha256, "outcome": outcome, "evidence_refs": [f"checklist:{checklist_sha256[:16]}"]}


def register_receipt(register_state: Any, *, source_plan: Any) -> dict[str, Any]:
    from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

    try:
        plan, state = COST_REGISTER_LIFECYCLE.bind(source_plan, register_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise WorkOrderError("REGISTER_NOT_PROVEN", "retain the original register state and its sealed map") from exc
    return {"register_source": state.to_dict(), "register_plan": plan.to_dict(), "evidence_refs": [f"register:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def work_order_cost_receipt(state: Any, *, source_plan: Any, centre_ref: str, engine: str | None = None, category: str | None = None) -> dict[str, Any]:
    """The cost register's source receipt for the job's own cost, its internal labour and the stock it drew (parts and contractor bills are already payables in the register), replayed and keyed by work order."""

    plan, bound = WORK_ORDER_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("completed", "costed"), "WORK_ORDER_NOT_COMPLETED", f"a work order that is {bound.status} has no final cost")
    own_cost = _money(ledger.labour_cost + ledger.stock_cost)
    _require(own_cost > 0, "NO_LABOUR_COST", "the job carries no internal labour or stock; its parts and contractor work are already payables in the register")
    return {"source_kind": "work_order", "source_ref": f"work_order:{ledger.work_order_ref}", "source_digest": bound.state_digest, "centre_ref": centre_ref, "amount": str(own_cost), "currency": plan.currency, "occurred_at": ledger.completed_at, "engine": engine, "category": category, "operator_supplied": engine is not None or category is not None, "source_state": bound.to_dict(), "source_plan": plan.to_dict(), "evidence_refs": [f"work_order:{bound.scope.entity_ref}:{bound.state_digest[:16]}"]}


def overdue_work_orders(states: Sequence[Any], *, source_plan: Any, now: str) -> list[dict[str, Any]]:
    stamp = parsed(timestamp(now, field_name="now"))
    rows = []
    for state in states:
        _plan, bound = WORK_ORDER_LIFECYCLE.bind(source_plan, state)
        if bound.status in ("raised", "approved", "in_progress") and bound.ledger.target_at is not None and parsed(str(bound.ledger.target_at)) < stamp:
            rows.append({"work_order_ref": bound.ledger.work_order_ref, "asset_ref": bound.ledger.asset_ref, "status": bound.status, "target_at": bound.ledger.target_at, "days_overdue": (stamp - parsed(str(bound.ledger.target_at))).days})
    rows.sort(key=lambda row: (str(row["target_at"]), str(row["work_order_ref"])))
    return rows


def work_order_overdue_signal(states: Sequence[Any], *, source_plan: Any, now: str) -> dict[str, Any] | None:
    """``signals.work_order_overdue`` naming the open jobs past their target date."""

    rows = overdue_work_orders(states, source_plan=source_plan, now=now)
    if not rows:
        return None
    return {"name": "signals.work_order_overdue", "producer": WORK_ORDER_KIND, "emitted_at": timestamp(now, field_name="now"), "payload": {"overdue_count": len(rows), "work_order_refs": [row["work_order_ref"] for row in rows], "asset_refs": sorted({str(row["asset_ref"]) for row in rows}), "oldest_target_at": rows[0]["target_at"], "source_digest": stable_digest(rows)}}


def work_order_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in WORK_ORDER_STATUSES}
    done = [state for state in states if state.status in ("completed", "costed")]
    return {"work_orders": len(states), "by_status": counts, "estimated_total": str(_money(sum((state.ledger.estimated_cost for state in states if state.status != "cancelled"), Decimal("0")))), "actual_total": str(_money(sum((state.ledger.actual_cost for state in done), Decimal("0")))), "overruns": [state.scope.entity_ref for state in done if state.ledger.overrun], "uncosted": [state.scope.entity_ref for state in states if state.status == "completed"]}


WORK_ORDER_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": WORK_ORDER_KIND,
    "golden_loop": WORK_ORDER_GOLDEN_LOOP,
    "stages": ["raise", "approve", "start", "record_parts", "record_stock", "record_labour", "record_contractor_labour", "complete", "register_cost"],
    "statuses": list(WORK_ORDER_STATUSES),
    "events": list(WORK_ORDER_EVENTS),
    "hops": {"raise": "the job, its kind, the asset, the estimate, the requester, the target date", "approve": "someone other than the requester; commitment authority at or above the threshold", "start": "the regulated-controls result, digest verified and satisfied, when the plan requires it", "record_parts": "the supplier's replayed payable case, once", "record_stock": "the replayed inventory position that issued stock to this job at its weighted average cost, once per position", "record_contractor_labour": "the replayed contractor engagement that recorded the work, once per work record", "record_labour": "a timesheet read costed at the plan's internal rate, once per worker and period", "complete": "the checklist's digest and the outcome; actual cost and variance computed", "register_cost": "the replayed cost register carrying the job's labour and its parts bills"},
    "tools": {"timesheets": sorted(TIMESHEET_TOOLS)},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "the requester never approves; a job at or above the threshold is a commitment decision",
        "work starts only on a verified, satisfied controls result when the plan requires one",
        "parts are replayed bills and labour is a timesheet read; the actual cost is computed",
        "a job is costed only when the replayed register carries it",
    ],
}

__all__ = ["PARTS_PAYABLE_STATUSES", "TERMINAL_WORK_ORDER_STATUSES", "TIMESHEET_TOOLS", "WORK_KINDS", "WORK_ORDER_EVENTS", "WORK_ORDER_GOLDEN_LOOP", "WORK_ORDER_KIND", "WORK_ORDER_LIFECYCLE", "WORK_ORDER_MANIFEST", "WORK_ORDER_STATUSES", "LabourRecord", "PartsRecord", "WorkOrderEffectBoundary", "WorkOrderError", "WorkOrderLedger", "WorkOrderPlan", "WorkOrderReceipt", "StockRecord", "ContractorRecord", "WorkOrderState", "advance_work_order", "approval_receipt", "compile_work_order_chain", "completion_receipt", "contractor_labour_receipt", "controls_receipt", "labour_receipt", "stock_receipt", "open_work_order", "overdue_work_orders", "parts_receipt", "register_receipt", "request_receipt", "work_order_cost_receipt", "work_order_overdue_signal", "work_order_summary"]
