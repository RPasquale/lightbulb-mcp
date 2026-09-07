"""Observed team capacity and paid labour inside a company operating envelope.

The host supplies a normalized, provenance-bound capacity read. This module
does not infer employment facts or wage rates, and paid labour is derived from
replayed payroll runs. Required licences are checked through obligation_paper.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, EngineScope, LifecycleSpec,
    OpaqueRef, Sha256Digest, ShortText, StrictModel, add_days, decimal_value,
    detached, parsed, require, seal, sealed_digest, skip_digests, stable_digest, timestamp,
)
from lightbulb.company_execution_bridge import ObservationProvenance
from lightbulb.company_operating_system import CompanyOperatingPlan

PEOPLE_KIND = "people_engine"
PEOPLE_GOLDEN_LOOP = "people.capacity_to_proven_labour@0.1.0"
PEOPLE_PROFILES = {"small_team": {"profile": "small_team", "required_hours": "0.00", "required_paper_kinds": ()}}
PEOPLE_STATUSES = ("opened", "staffed", "costed", "assessed", "closed", "halted")
PEOPLE_EVENTS = ("open", "staff", "record_labour", "assess", "close", "halt")


class PeopleError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise PeopleError(code, message)


class PeoplePlan(StrictModel):
    schema_id: Literal["lightbulb.people_engine_plan.v1"] = Field(default="lightbulb.people_engine_plan.v1", alias="schema")
    company_ref: OpaqueRef
    profile: Literal["small_team"] = "small_team"
    operating_plan: CompanyOperatingPlan
    currency: CurrencyCode
    required_hours: Decimal = Decimal("0.00")
    required_paper_kinds: tuple[ShortText, ...] = ()
    max_observation_age_days: int = Field(default=14, ge=0, le=92)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("required_hours", mode="before")
    @classmethod
    def _hours(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="required_hours")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> PeoplePlan:
        if self.currency != self.operating_plan.blueprint.currency:
            raise ValueError("PEOPLE_CURRENCY_MISMATCH: capacity and operating plans share currency")
        if len(self.required_paper_kinds) != len(set(self.required_paper_kinds)):
            raise ValueError("required paper kinds must be unique")
        if not skip_digests(info) and self.plan_digest != sealed_digest(PeoplePlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact people plan")
        return self


def compile_people_engine(company_ref: str, *, operating_plan: Any, profile: str = "small_team", overrides: Mapping[str, Any] | None = None) -> PeoplePlan:
    op = CompanyOperatingPlan.model_validate(detached(operating_plan))
    _require(profile in PEOPLE_PROFILES, "UNKNOWN_ENGINE_PROFILE", profile)
    changes = dict(overrides or {})
    _require(not set(changes) & {"schema", "plan_digest", "company_ref", "operating_plan", "currency", "profile"}, "PLAN_OVERRIDE_INVALID", "identity and seals cannot be overridden")
    return seal(PeoplePlan, {**PEOPLE_PROFILES[profile], **changes, "company_ref": company_ref,
                           "operating_plan": op, "currency": op.blueprint.currency}, "plan_digest")


class CapacityWorker(StrictModel):
    worker_ref: OpaqueRef
    available_hours: Decimal
    paper_sources: tuple[dict[str, Any], ...] = ()

    @field_validator("available_hours", mode="before")
    @classmethod
    def _hours(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="available_hours")


class CapacityRead(StrictModel):
    schema_id: Literal["lightbulb.people_capacity.v1"] = Field(default="lightbulb.people_capacity.v1", alias="schema")
    scope: EngineScope
    company_ref: OpaqueRef
    observed_at: str
    period_start: str
    period_end: str
    workers: tuple[CapacityWorker, ...] = Field(min_length=1, max_length=500)

    @field_validator("observed_at", "period_start", "period_end")
    @classmethod
    def _stamp(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self) -> CapacityRead:
        if parsed(self.period_start) >= parsed(self.period_end):
            raise ValueError("CAPACITY_WINDOW_INVALID: capacity period must be ordered")
        if len({row.worker_ref for row in self.workers}) != len(self.workers):
            raise ValueError("WORKER_DUPLICATE: one observed capacity per worker")
        return self


class CapacityObservation(StrictModel):
    provenance: ObservationProvenance
    payload: CapacityRead

    @model_validator(mode="after")
    def _guard(self) -> CapacityObservation:
        if self.provenance.source_tool != "host.people_capacity" or self.provenance.lane != "host_read":
            raise ValueError("CAPACITY_SOURCE_INVALID: expected the normalized host.people_capacity read")
        if self.provenance.output_digest != stable_digest(self.payload.to_dict()):
            raise ValueError("CAPACITY_DIGEST_MISMATCH: provenance must commit the normalized payload")
        if self.provenance.observed_through != self.payload.observed_at:
            raise ValueError("CAPACITY_TIME_MISMATCH: observation and payload timestamps differ")
        return self


def capacity_receipt(provenance: Any, payload: Any) -> dict[str, Any]:
    observation = CapacityObservation.model_validate({"provenance": detached(provenance), "payload": detached(payload)})
    return {"capacity_source": observation.to_dict(), "evidence_refs": [f"capacity:{observation.provenance.output_digest}"]}


class LabourSource(StrictModel):
    state: dict[str, Any]
    plan: dict[str, Any]


def _payroll(source: LabourSource | Mapping[str, Any]) -> tuple[Any, Any]:
    from lightbulb.payroll_run_chain import PAYROLL_LIFECYCLE

    raw = LabourSource.model_validate(detached(source))
    try:
        plan, state = PAYROLL_LIFECYCLE.bind(raw.plan, raw.state)
    except (ValueError, KeyError) as exc:
        raise PeopleError("LABOUR_SOURCE_INVALID", "labour requires an exact replayed payroll run and plan") from exc
    _require(state.status in ("paid", "liabilities_reserved", "reconciled"), "LABOUR_NOT_PAID", "unpaid payroll is not operating spend")
    return plan, state


def labour_receipt(state: Any, *, source_plan: Any) -> dict[str, Any]:
    source = LabourSource(state=detached(state), plan=detached(source_plan))
    _, run = _payroll(source)
    return {"labour_source": source.to_dict(), "evidence_refs": [f"payroll:{run.state_digest}"]}


class PeopleReceipt(StrictModel):
    entity_scope: EngineScope | None = None
    period_start: str | None = None
    period_end: str | None = None
    capacity_source: CapacityObservation | None = None
    labour_source: LabourSource | None = None
    evidence_refs: tuple[OpaqueRef, ...] = ()

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamp(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class PeopleLedger(StrictModel):
    entity_scope: EngineScope | None = None
    period_start: str | None = None
    period_end: str | None = None
    capacity_source: CapacityObservation | None = None
    worker_refs: tuple[OpaqueRef, ...] = ()
    available_hours: Decimal = Decimal("0.00")
    labour_hours: Decimal = Decimal("0.00")
    labour_spend: Decimal = Decimal("0.00")
    payroll_keys: tuple[ShortText, ...] = ()
    payroll_sources: tuple[LabourSource, ...] = ()
    source_digests: tuple[Sha256Digest, ...] = ()
    capacity_shortfall: Decimal = Decimal("0.00")
    assessed_at: str | None = None
    outcome: Literal["open", "closed", "halted"] = "open"

    @field_validator("available_hours", "labour_hours", "labour_spend", "capacity_shortfall", mode="before")
    @classmethod
    def _decimal(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class PeopleEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    payroll_paid: Literal[False] = False
    worker_hired: Literal[False] = False
    provider_read: Literal[False] = False


def _same_scope(left: EngineScope, right: EngineScope) -> bool:
    return all(getattr(left, key) == getattr(right, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency"))


def _paper(plan: PeoplePlan, observation: CapacityObservation, scope: EngineScope, at: str) -> None:
    from lightbulb.obligation_paper import verify_paper_current

    for worker in observation.payload.workers:
        for kind in plan.required_paper_kinds:
            valid = False
            for source in worker.paper_sources:
                try:
                    verify_paper_current(source["state"], source_plan=source["plan"], company_ref=plan.company_ref,
                                         currency=plan.currency, at=at, kind=kind, holder_ref=worker.worker_ref, expected_scope=scope)
                    valid = True
                    break
                except (ValueError, KeyError):
                    continue
            require(valid, "CAPABILITY_LAPSED", f"{worker.worker_ref} requires current {kind} paper", "manual_reconciliation")


def _apply(plan: PeoplePlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "open":
        require(r.entity_scope is not None and r.period_start is not None and r.period_end is not None, "PERIOD_MISSING", "people period requires scope and window")
        require(command.expected_state_digest == PEOPLE_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "PEOPLE_SCOPE_MISMATCH", "opening receipt belongs to this lifecycle scope")
        require(r.entity_scope.currency == plan.currency, "PEOPLE_CURRENCY_MISMATCH", "people period uses the company currency")
        days = (parsed(r.period_end) - parsed(r.period_start)).total_seconds() / 86400
        require(0 < days <= plan.operating_plan.blueprint.period_days, "PERIOD_WINDOW_INVALID", "people period fits its operating period")
        data.update(entity_scope=r.entity_scope.to_dict(), period_start=r.period_start, period_end=r.period_end)
    elif event == "staff":
        require(r.capacity_source is not None, "CAPACITY_MISSING", "staffing requires a provenance-bound capacity read")
        source = CapacityObservation.model_validate(r.capacity_source.to_dict())
        read, scope = source.payload, EngineScope.model_validate(data["entity_scope"])
        require(_same_scope(read.scope, scope) and read.company_ref == plan.company_ref, "PEOPLE_SCOPE_MISMATCH", "capacity read belongs to this company and project")
        require(read.period_start == data["period_start"] and read.period_end == data["period_end"], "CAPACITY_WINDOW_MISMATCH", "capacity window must equal the people period")
        age = (parsed(at) - parsed(read.observed_at)).total_seconds() / 86400
        require(0 <= age <= plan.max_observation_age_days, "CAPACITY_STALE", "capacity must be observed recently and before staffing")
        _paper(plan, source, scope, at)
        data.update(capacity_source=source.to_dict(), worker_refs=[w.worker_ref for w in read.workers],
                    available_hours=str(sum((w.available_hours for w in read.workers), Decimal(0)).quantize(MONEY_QUANTUM)))
    elif event == "record_labour":
        require(r.labour_source is not None, "LABOUR_SOURCE_INVALID", "labour requires a paid payroll run")
        source_plan, run = _payroll(r.labour_source)
        scope = EngineScope.model_validate(data["entity_scope"])
        require(_same_scope(run.scope, scope) and source_plan.company_ref == plan.company_ref, "PEOPLE_SCOPE_MISMATCH", "payroll belongs to this company and project")
        require(parsed(data["period_start"]) <= parsed(run.ledger.paid_at) < parsed(data["period_end"]) and parsed(run.ledger.paid_at) <= parsed(at), "LABOUR_OUTSIDE_PERIOD", "cash labour is attributed only to its paid period")
        key = run.ledger.period_key or run.ledger.run_ref
        require(key not in data.get("payroll_keys", ()), "LABOUR_ALREADY_RECORDED", "the same payroll cannot be counted twice", "do_not_replay")
        cost = run.ledger.gross + run.ledger.employer_super + run.ledger.employer_tax
        spend = Decimal(data.get("labour_spend", "0")) + cost
        envelope = plan.operating_plan.envelope("people_engine")
        require(envelope is None or spend <= envelope.budget, "LABOUR_ENVELOPE_EXCEEDED", "paid labour exceeds the people operating envelope", "manual_reconciliation")
        data.update(labour_spend=str(spend), labour_hours=str(Decimal(data.get("labour_hours", "0")) + run.ledger.timesheet_hours),
                    payroll_keys=[*data.get("payroll_keys", ()), key], payroll_sources=[*data.get("payroll_sources", ()), r.labour_source.to_dict()],
                    source_digests=[*data.get("source_digests", ()), run.state_digest])
    elif event == "assess":
        scope = EngineScope.model_validate(data["entity_scope"])
        capacity = CapacityObservation.model_validate(data["capacity_source"])
        age = (parsed(at) - parsed(capacity.payload.observed_at)).total_seconds() / 86400
        require(0 <= age <= plan.max_observation_age_days, "CAPACITY_STALE", "refresh capacity before assessing an old staffing observation")
        _paper(plan, capacity, scope, at)
        data.update(capacity_shortfall=str(max(Decimal(0), plan.required_hours - Decimal(data["available_hours"]))), assessed_at=at)
    elif event == "close":
        require(parsed(at) >= parsed(data["period_end"]), "PERIOD_NOT_ENDED", "close only after the observed period ends")
        data["outcome"] = "closed"
    elif event == "halt":
        data["outcome"] = "halted"
    return next_status, data


_TABLE = {("new", "open"): "opened", ("opened", "staff"): "staffed", ("staffed", "staff"): "staffed",
          ("staffed", "record_labour"): "costed", ("costed", "record_labour"): "costed",
          ("staffed", "assess"): "assessed", ("costed", "assess"): "assessed", ("assessed", "close"): "closed",
          **{(s, "halt"): "halted" for s in ("opened", "staffed", "costed", "assessed")}}
PEOPLE_LIFECYCLE = LifecycleSpec(entity="people_period", schema_prefix="people_engine", statuses=PEOPLE_STATUSES,
    terminal=("closed", "halted"), events=PEOPLE_EVENTS, table=_TABLE, opening_event="open", reason_events=("halt",),
    apply=_apply, ledger_model=PeopleLedger, receipt_model=PeopleReceipt, effect_boundary_model=PeopleEffectBoundary,
    plan_model=PeoplePlan, max_transitions=120)
PeopleState = PEOPLE_LIFECYCLE.State


def open_people_period(plan: Any, scope: Mapping[str, Any], *, period_start: str, opened_at: str, actor_ref: str, period_end: str | None = None) -> Any:
    bound = PeoplePlan.model_validate(detached(plan))
    return PEOPLE_LIFECYCLE.open(bound, scope, opened_at=opened_at, actor_ref=actor_ref,
        receipt={"entity_scope": detached(scope), "period_start": period_start,
                 "period_end": period_end or add_days(period_start, bound.operating_plan.blueprint.period_days)})


def advance_people(plan: Any, state: Any, command: Any) -> Any:
    return PEOPLE_LIFECYCLE.advance(plan, state, command)


def assess_capacity(state: Any, *, plan: Any) -> dict[str, Any]:
    bound, current = PEOPLE_LIFECYCLE.bind(plan, state)
    ledger = current.ledger
    return {"people_ref": current.scope.entity_ref, "status": current.status, "currency": bound.currency,
            "available_hours": str(ledger.available_hours), "required_hours": str(bound.required_hours),
            "capacity_shortfall": str(max(Decimal(0), bound.required_hours - ledger.available_hours)),
            "labour_spend": str(ledger.labour_spend), "source_digests": list(ledger.source_digests),
            "source_digest": current.state_digest, "effects_executed": False}


PEOPLE_MANIFEST = {"schema": "lightbulb.company_engine_manifest.v1", "engine": PEOPLE_KIND,
    "golden_loop": PEOPLE_GOLDEN_LOOP, "profiles": list(PEOPLE_PROFILES), "statuses": list(PEOPLE_STATUSES),
    "events": list(PEOPLE_EVENTS), "stages": ["open", "staff", "record_labour", "assess", "close"],
    "missing_reads": ["host.people_capacity: normalized capacity window, opaque worker refs, hours and scope"],
    "hard_rules": ["capacity is an observed staffing fact, never an inferred employment record",
                   "labour spend is gross pay plus employer costs from a paid payroll run",
                   "the payroll source remains the money source; a people summary is never counted again",
                   "required worker paper must be current before staffing and assessment"]}
__all__ = ["PEOPLE_KIND", "PEOPLE_GOLDEN_LOOP", "PEOPLE_PROFILES", "PEOPLE_STATUSES", "PEOPLE_EVENTS", "PEOPLE_MANIFEST",
           "PEOPLE_LIFECYCLE", "PeoplePlan", "PeopleState", "PeopleReceipt", "PeopleLedger", "PeopleEffectBoundary",
           "PeopleError", "CapacityWorker", "CapacityRead", "CapacityObservation", "LabourSource", "compile_people_engine",
           "open_people_period", "advance_people", "capacity_receipt", "labour_receipt", "assess_capacity"]
