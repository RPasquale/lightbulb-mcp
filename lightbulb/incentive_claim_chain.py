"""The incentive claim chain: one replay-fenced claim per program and period, from eligible activities to the incentive received.

Non-dilutive money is a real revenue line for an Australian or Canadian
technology company (the R&D Tax Incentive, SR&ED, and the matched grants
the accountant surfaces), and the SDK could match a company to a program
and nothing more.  Nothing held the claim: the activities it rests on, the
costs it may include, the benefit it computes, whether it was lodged and
assessed, and whether the money arrived.  ``INCENTIVE_CLAIM_LIFECYCLE``
does:

    registered -> activities_recorded -> costs_bound -> prepared -> lodged -> assessed -> received   (terminal)
                                                                              assessed -> rejected   (terminal, with a reason)
    any non-terminal -> withdrawn                                                                  (terminal, with a reason)

* ``registration_receipt`` opens the claim for a program the plan carries
  (and, when the plan demands it, that the grant registry knows).
* ``activity_receipt`` records an eligible activity with its evidence
  digest and the opaque worker commitments who performed it.
* ``cost_receipt`` binds costs from a closed cost register replayed against
  its map: only sources the register attributed can be claimed, at the
  percentage the operator allocates, in a kind the program allows.
* ``prepare`` computes the benefit from the program's rate; the preparer
  is recorded and cannot lodge their own preparation when segregation is
  required.
* ``lodgement_receipt`` and ``assessment_receipt`` are the operator's
  portal receipts; ``receipt_of_funds`` is a bank read for the exact
  assessed amount.

Nothing here lodges anything, claims anything to an authority, or persists
anything.  Benefit rates are the operator's, from their adviser, never the
SDK's assertion of entitlement.
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
    unique,
)

INCENTIVE_KIND = "incentive_claim_chain"
INCENTIVE_GOLDEN_LOOP = "finance.eligible_activity_to_received_incentive@0.1.0"
INCENTIVE_PLAN_SCHEMA = "lightbulb.incentive_claim_plan.v1"
EXPECTED_INFLOW_SCHEMA = "lightbulb.incentive_expected_inflow.v1"
MAX_INCENTIVE_TRANSITIONS = 80
FUNDS_TOOLS: frozenset[str] = frozenset({"xero.list_bank_transactions", "quickbooks.list_deposits", "host.bank_transfer", "host.authority_refund"})
REGISTER_BOUND_STATUSES: frozenset[str] = frozenset({"coverage_asserted", "closed"})
CostKind = Literal["labour", "contractor", "supplies", "overhead"]
_KIND_BY_SOURCE: dict[str, tuple[str, ...]] = {"payroll": ("labour",), "worker": ("labour",), "metered_dispatch": ("labour",), "payable": ("contractor", "supplies", "overhead"), "spend_case": ("supplies", "overhead")}
_HUNDRED = Decimal("100")

INCENTIVE_STATUSES: tuple[str, ...] = ("registered", "activities_recorded", "costs_bound", "prepared", "lodged", "assessed", "received", "rejected", "withdrawn")
TERMINAL_INCENTIVE_STATUSES: frozenset[str] = frozenset({"received", "rejected", "withdrawn"})
INCENTIVE_EVENTS: tuple[str, ...] = ("register", "record_activity", "bind_costs", "prepare", "lodge", "assess", "receive", "reject", "withdraw")
_INCENTIVE_TABLE: dict[tuple[str, str], str] = {
    ("new", "register"): "registered",
    ("registered", "record_activity"): "activities_recorded",
    ("activities_recorded", "record_activity"): "activities_recorded",
    ("activities_recorded", "bind_costs"): "costs_bound",
    ("costs_bound", "bind_costs"): "costs_bound",
    ("costs_bound", "record_activity"): "costs_bound",
    ("costs_bound", "prepare"): "prepared",
    ("prepared", "lodge"): "lodged",
    ("lodged", "assess"): "assessed",
    ("assessed", "receive"): "received",
    ("assessed", "reject"): "rejected",
    **{(status, "withdraw"): "withdrawn" for status in ("registered", "activities_recorded", "costs_bound", "prepared", "lodged")},
}


class IncentiveClaimError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise IncentiveClaimError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #


class IncentiveProgram(StrictModel):
    program_ref: OpaqueRef
    name: ShortText
    benefit_rate_percent: Decimal
    eligible_cost_kinds: tuple[CostKind, ...] = Field(min_length=1, max_length=4)
    overhead_uplift_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    max_benefit: Decimal | None = None
    rate_source: ShortText = "operator_supplied"

    @field_validator("benefit_rate_percent", "overhead_uplift_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result > _HUNDRED:
            raise ValueError(f"{info.field_name} is a percentage")
        return result

    @field_validator("max_benefit", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="max_benefit")

    @field_validator("eligible_cost_kinds", mode="before")
    @classmethod
    def _kinds(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class IncentiveClaimPlan(StrictModel):
    """What the chain enforces: the programs and their operator-supplied rates, whether the registry must know them, and preparer segregation."""

    schema_id: str = Field(default=INCENTIVE_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    jurisdiction: str = Field(min_length=2, max_length=2)
    programs: tuple[IncentiveProgram, ...] = Field(min_length=1, max_length=20)
    require_registered_program: bool = True
    preparer_segregation: bool = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("jurisdiction")
    @classmethod
    def _jurisdiction(cls, value: str) -> str:
        return value.upper()

    @field_validator("programs", mode="before")
    @classmethod
    def _programs(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "IncentiveClaimPlan":
        unique([item.program_ref for item in self.programs], label="programs")
        if not skip_digests(info) and self.plan_digest != sealed_digest(IncentiveClaimPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def program(self, program_ref: str) -> IncentiveProgram | None:
        return next((item for item in self.programs if item.program_ref == program_ref), None)


def compile_incentive_claim_chain(company_ref: str, *, currency: str, jurisdiction: str, programs: Sequence[Mapping[str, Any]], overrides: Mapping[str, Any] | None = None) -> IncentiveClaimPlan:
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(currency).upper(), "jurisdiction": jurisdiction, "programs": [dict(detached(item)) for item in programs], **dict(overrides or {})}
    return seal(IncentiveClaimPlan, raw, "plan_digest")


def registered_program_refs() -> frozenset[str]:
    from lightbulb.grant_discovery import grant_registry

    return frozenset(str(item["program_ref"]) for item in grant_registry())


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class ActivityRecord(StrictModel):
    activity_ref: OpaqueRef
    title: ShortText
    started_at: str
    ended_at: str
    evidence_sha256: Sha256Digest
    worker_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)


class CostAllocation(StrictModel):
    activity_ref: OpaqueRef
    source_ref: OpaqueRef
    source_digest: Sha256Digest
    kind: CostKind
    percent: Decimal
    source_amount: Decimal
    eligible_amount: Decimal
    register_ref: OpaqueRef

    @field_validator("percent", "source_amount", "eligible_amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))


class IncentiveReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    program_ref: OpaqueRef | None = None
    period_ref: OpaqueRef | None = None
    eligibility_sha256: Sha256Digest | None = None
    activity: dict[str, Any] | None = None
    register_source: dict[str, Any] | None = None
    register_plan: dict[str, Any] | None = None
    allocations: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=200)
    preparer_ref: OpaqueRef | None = None
    claim_sha256: Sha256Digest | None = None
    lodger_ref: OpaqueRef | None = None
    lodgement_ref: OpaqueRef | None = None
    lodged_at: str | None = None
    lodgement_sha256: Sha256Digest | None = None
    assessed_amount: Decimal | None = None
    assessed_at: str | None = None
    notice_sha256: Sha256Digest | None = None
    funds_provenance: dict[str, Any] | None = None
    funds_digest: Sha256Digest | None = None
    received_amount: Decimal | None = None
    received_at: str | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "allocations", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("assessed_amount", "received_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("lodged_at", "assessed_at", "received_at")
    @classmethod
    def _stamps(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class IncentiveLedger(StrictModel):
    program_ref: str | None = None
    period_ref: str | None = None
    eligibility_sha256: str | None = None
    registered_at: str | None = None
    activities: tuple[ActivityRecord, ...] = Field(default_factory=tuple, max_length=200)
    allocations: tuple[CostAllocation, ...] = Field(default_factory=tuple, max_length=400)
    register_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=40)
    eligible_by_kind: dict[str, Decimal] = Field(default_factory=dict)
    eligible_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    uplift_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    benefit_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    capped: bool = False
    preparer_ref: str | None = None
    prepared_at: str | None = None
    claim_sha256: str | None = None
    lodger_ref: str | None = None
    lodgement_ref: str | None = None
    lodged_at: str | None = None
    assessed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    assessed_at: str | None = None
    notice_sha256: str | None = None
    received_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    received_at: str | None = None
    funds_digest: str | None = None
    reject_reason: str | None = None
    withdraw_reason: str | None = None
    outcome: Literal["open", "received", "rejected", "withdrawn"] = "open"

    @field_validator("activities", "allocations", "register_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("eligible_total", "uplift_amount", "benefit_amount", "assessed_amount", "received_amount", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("eligible_by_kind", mode="before")
    @classmethod
    def _by_kind(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name="eligible_by_kind") for key, item in dict(value or {}).items()}


class IncentiveEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    claim_lodged: Literal[False] = False
    entitlement_asserted: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_incentive(plan: IncentiveClaimPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "register":
        require(r.program_ref is not None and r.period_ref is not None and r.eligibility_sha256 is not None, "REGISTRATION_MISSING", "a claim names the program, the period, and the digest of the eligibility assessment it rests on")
        program = plan.program(str(r.program_ref))
        require(program is not None, "PROGRAM_UNKNOWN", f"{r.program_ref} is not a program of this plan")
        if plan.require_registered_program:
            require(str(r.program_ref) in registered_program_refs(), "PROGRAM_NOT_REGISTERED", f"{r.program_ref} is not in the grant registry; add it there with its official source first")
        data.update({"program_ref": r.program_ref, "period_ref": r.period_ref, "eligibility_sha256": r.eligibility_sha256, "registered_at": at})
    elif event == "record_activity":
        require(r.activity is not None, "ACTIVITY_MISSING", "an activity record is required")
        record = ActivityRecord.model_validate(dict(r.activity or {}))
        require(all(str(dict(item)["activity_ref"]) != record.activity_ref for item in data.get("activities", ())), "ACTIVITY_ALREADY_RECORDED", f"{record.activity_ref} was already recorded")
        require(parsed(record.started_at) <= parsed(record.ended_at) <= parsed(at), "ACTIVITY_TIME_INVALID", "an activity ends after it starts and before it is recorded")
        data.update({"activities": [*[dict(item) for item in data.get("activities", ())], record.to_dict()]})
    elif event == "bind_costs":
        require(r.register_source is not None and r.register_plan is not None and bool(r.allocations), "COSTS_NOT_PROVEN", "costs bind from a replayed cost register and the allocations against its sources")
        from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

        try:
            register_map, register = COST_REGISTER_LIFECYCLE.bind(r.register_plan, r.register_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "COSTS_NOT_PROVEN", f"the register must replay against its exact map: {exc}"[:300])
            raise AssertionError from exc
        require(register_map.company_ref == plan.company_ref and register.scope.currency == plan.currency, "REGISTER_SCOPE_MISMATCH", "the register belongs to another company or currency")
        require(register.status in REGISTER_BOUND_STATUSES, "REGISTER_NOT_CLOSED", f"the register is {register.status}; costs bind from an asserted or closed register")
        require(parsed(register.transition_history[-1].command.occurred_at) <= parsed(at), "REGISTER_FROM_FUTURE", "the register cannot come from the future")
        program = plan.program(str(data["program_ref"]))
        assert program is not None
        activities = {str(dict(item)["activity_ref"]) for item in data.get("activities", ())}
        sources = {str(item.source_ref): item for item in register.ledger.sources}
        existing = [dict(item) for item in data.get("allocations", ())]
        taken = {(item["source_ref"], item["activity_ref"]) for item in existing}
        by_kind = {str(key): Decimal(str(value)) for key, value in dict(data.get("eligible_by_kind", {})).items()}
        total = Decimal(str(data["eligible_total"]))
        for raw_allocation in r.allocations:
            allocation = dict(raw_allocation)
            activity_ref, source_ref, kind = str(allocation.get("activity_ref")), str(allocation.get("source_ref")), str(allocation.get("kind"))
            percent = decimal_value(allocation.get("percent", "0"), field_name="percent")
            require(activity_ref in activities, "ACTIVITY_UNKNOWN", f"{activity_ref} is not a recorded activity")
            require(source_ref in sources, "SOURCE_NOT_IN_REGISTER", f"{source_ref} is not a source the register attributed")
            source = sources[source_ref]
            require(kind in program.eligible_cost_kinds, "COST_KIND_NOT_ELIGIBLE", f"{program.program_ref} does not accept {kind} costs")
            require(kind in _KIND_BY_SOURCE.get(str(source.source_kind), ()), "COST_KIND_MISMATCH", f"a {source.source_kind} source cannot be claimed as {kind}")
            require(0 < percent <= _HUNDRED, "PERCENT_INVALID", "an allocation is between 0 and 100 percent")
            require((source_ref, activity_ref) not in taken, "SOURCE_ALREADY_ALLOCATED", f"{source_ref} is already allocated to {activity_ref}")
            allocated_percent = sum((Decimal(str(item["percent"])) for item in existing if item["source_ref"] == source_ref), Decimal("0")) + percent
            require(allocated_percent <= _HUNDRED, "SOURCE_OVER_ALLOCATED", f"{source_ref} would be {allocated_percent}% allocated")
            eligible = _money(Decimal(str(source.spend_amount)) * percent / _HUNDRED)
            require(eligible > 0, "SOURCE_CARRIES_NO_SPEND", f"{source_ref} carries no spend to claim")
            record = CostAllocation(activity_ref=activity_ref, source_ref=source_ref, source_digest=str(source.source_digest), kind=kind, percent=percent, source_amount=_money(source.spend_amount), eligible_amount=eligible, register_ref=register.scope.entity_ref).to_dict()
            existing.append(record)
            taken.add((source_ref, activity_ref))
            by_kind[kind] = _money(by_kind.get(kind, Decimal("0")) + eligible)
            total = _money(total + eligible)
        digests = list(data.get("register_digests", ()))
        if register.state_digest not in digests:
            digests.append(register.state_digest)
        data.update({"allocations": existing, "register_digests": digests, "eligible_by_kind": {key: str(value) for key, value in by_kind.items()}, "eligible_total": str(total)})
    elif event == "prepare":
        require(r.preparer_ref is not None and r.claim_sha256 is not None, "PREPARATION_MISSING", "a prepared claim names its preparer and the digest of the claim document")
        program = plan.program(str(data["program_ref"]))
        assert program is not None
        eligible = Decimal(str(data["eligible_total"]))
        require(eligible > 0, "NOTHING_ELIGIBLE", "no eligible cost is bound to this claim")
        uplift = _money(eligible * program.overhead_uplift_percent / _HUNDRED)
        benefit = _money((eligible + uplift) * program.benefit_rate_percent / _HUNDRED)
        capped = program.max_benefit is not None and benefit > program.max_benefit
        if capped:
            benefit = _money(program.max_benefit)
        data.update({"preparer_ref": r.preparer_ref, "prepared_at": at, "claim_sha256": r.claim_sha256, "uplift_amount": str(uplift), "benefit_amount": str(benefit), "capped": capped})
    elif event == "lodge":
        require(r.lodger_ref is not None and r.lodgement_ref is not None and r.lodged_at is not None and r.lodgement_sha256 is not None, "LODGEMENT_MISSING", "a lodgement names who lodged, the authority's reference, the time, and the digest of the lodgement receipt")
        require(not plan.preparer_segregation or r.lodger_ref != data.get("preparer_ref"), "SEGREGATION_VIOLATED", "the preparer cannot lodge their own preparation under this plan")
        require(parsed(str(data["prepared_at"])) <= parsed(str(r.lodged_at)) <= parsed(at), "LODGEMENT_TIME_INVALID", "a lodgement follows the preparation and precedes its recording")
        data.update({"lodger_ref": r.lodger_ref, "lodgement_ref": r.lodgement_ref, "lodged_at": r.lodged_at})
    elif event == "assess":
        require(r.assessed_amount is not None and r.assessed_at is not None and r.notice_sha256 is not None, "ASSESSMENT_MISSING", "an assessment names the amount, the time, and the digest of the notice")
        require(parsed(str(data["lodged_at"])) <= parsed(str(r.assessed_at)) <= parsed(at), "ASSESSMENT_TIME_INVALID", "an assessment follows the lodgement and precedes its recording")
        data.update({"assessed_amount": str(_money(r.assessed_amount)), "assessed_at": r.assessed_at, "notice_sha256": r.notice_sha256})
    elif event == "receive":
        require(r.funds_provenance is not None and r.funds_digest is not None and r.received_amount is not None and r.received_at is not None, "FUNDS_EVIDENCE_MISSING", "receipt of funds carries the bank read provenance, its digest, the amount, and the time")
        require(str(dict(r.funds_provenance or {}).get("output_digest")) == r.funds_digest, "FUNDS_NOT_BOUND", "the provenance does not seal this bank read")
        require(_money(r.received_amount) == Decimal(str(data["assessed_amount"])), "FUNDS_AMOUNT_MISMATCH", f"the assessment was {data['assessed_amount']}; the bank shows {r.received_amount}", "manual_reconciliation")
        require(parsed(str(data["assessed_at"])) <= parsed(str(r.received_at)) <= parsed(at), "FUNDS_TIME_INVALID", "funds arrive after the assessment and before their recording")
        data.update({"received_amount": str(_money(r.received_amount)), "received_at": r.received_at, "funds_digest": r.funds_digest, "outcome": "received"})
    elif event == "reject":
        data.update({"reject_reason": str(command.reason)[:300], "outcome": "rejected"})
    elif event == "withdraw":
        data.update({"withdraw_reason": str(command.reason)[:300], "outcome": "withdrawn"})
    return next_status, data


INCENTIVE_CLAIM_LIFECYCLE = LifecycleSpec(entity="incentive_claim", schema_prefix=INCENTIVE_KIND, statuses=INCENTIVE_STATUSES, terminal=TERMINAL_INCENTIVE_STATUSES, events=INCENTIVE_EVENTS, table=_INCENTIVE_TABLE, opening_event="register", reason_events=("reject", "withdraw"), apply=_apply_incentive, ledger_model=IncentiveLedger, receipt_model=IncentiveReceipt, effect_boundary_model=IncentiveEffectBoundary, plan_model=IncentiveClaimPlan, max_transitions=MAX_INCENTIVE_TRANSITIONS)
IncentiveClaimState = INCENTIVE_CLAIM_LIFECYCLE.State


def open_incentive_claim(plan: IncentiveClaimPlan | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return INCENTIVE_CLAIM_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_incentive_claim(plan: IncentiveClaimPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return INCENTIVE_CLAIM_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def registration_receipt(plan: IncentiveClaimPlan | Mapping[str, Any], *, program_ref: str, period_ref: str, eligibility: Mapping[str, Any] | Any) -> dict[str, Any]:
    """The opening receipt: a program of the plan and the digest of the eligibility assessment (a ``GrantMatchResult`` or the adviser's memo)."""

    parsed_plan = IncentiveClaimPlan.model_validate(detached(plan))
    _require(parsed_plan.program(program_ref) is not None, "PROGRAM_UNKNOWN", f"{program_ref} is not a program of this plan")
    raw = detached(eligibility)
    digest = str(raw.get("result_digest") or raw.get("digest") or stable_digest(raw)) if isinstance(raw, Mapping) else stable_digest(raw)
    return {"program_ref": program_ref, "period_ref": period_ref, "eligibility_sha256": digest, "evidence_refs": [f"eligibility:{digest[:16]}"]}


def activity_receipt(*, activity_ref: str, title: str, started_at: str, ended_at: str, evidence_sha256: str, worker_refs: Sequence[str] = ()) -> dict[str, Any]:
    record = ActivityRecord(activity_ref=activity_ref, title=title, started_at=timestamp(started_at, field_name="started_at"), ended_at=timestamp(ended_at, field_name="ended_at"), evidence_sha256=evidence_sha256, worker_refs=tuple(worker_refs))
    return {"activity": record.to_dict(), "evidence_refs": [f"activity:{activity_ref}:{evidence_sha256[:16]}"]}


def cost_receipt(register_state: Any, *, source_plan: Any, allocations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """From a closed cost register: the operator's allocations of its sources to activities, by kind and percent."""

    from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

    try:
        plan, state = COST_REGISTER_LIFECYCLE.bind(source_plan, register_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise IncentiveClaimError("COSTS_NOT_PROVEN", "retain the original cost register state and its sealed map") from exc
    _require(state.status in REGISTER_BOUND_STATUSES, "REGISTER_NOT_CLOSED", f"the register is {state.status}")
    rows = [dict(detached(item)) for item in allocations]
    _require(bool(rows), "ALLOCATIONS_MISSING", "at least one allocation is required")
    return {"register_source": state.to_dict(), "register_plan": plan.to_dict(), "allocations": rows, "evidence_refs": [f"register:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def preparation_receipt(*, preparer_ref: str, claim_sha256: str) -> dict[str, Any]:
    return {"preparer_ref": preparer_ref, "claim_sha256": claim_sha256, "evidence_refs": [f"claim:{claim_sha256[:16]}"]}


def lodgement_receipt(*, lodger_ref: str, lodgement_ref: str, lodged_at: str, lodgement_sha256: str) -> dict[str, Any]:
    return {"lodger_ref": lodger_ref, "lodgement_ref": lodgement_ref, "lodged_at": timestamp(lodged_at, field_name="lodged_at"), "lodgement_sha256": lodgement_sha256, "evidence_refs": [f"lodgement:{lodgement_ref}"]}


def assessment_receipt(*, assessed_amount: Any, assessed_at: str, notice_sha256: str) -> dict[str, Any]:
    return {"assessed_amount": str(_money(decimal_value(assessed_amount, field_name="assessed_amount"))), "assessed_at": timestamp(assessed_at, field_name="assessed_at"), "notice_sha256": notice_sha256, "evidence_refs": [f"notice:{notice_sha256[:16]}"]}


def receipt_of_funds(provenance: Mapping[str, Any] | Any, payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """From a bank read: the authority's transfer."""

    prov = dict(detached(provenance))
    _require(str(prov.get("source_tool", "")) in FUNDS_TOOLS, "FUNDS_NOT_BOUND", f"expected a read from {sorted(FUNDS_TOOLS)}, got {prov.get('source_tool')!r}")
    for key in ("observation_ref", "provenance_digest", "output_digest", "completed_at"):
        _require(bool(prov.get(key)), "FUNDS_NOT_BOUND", f"the provenance lacks {key}")
    raw = dict(detached(payload))
    _require(str(prov["output_digest"]) == stable_digest(raw), "FUNDS_NOT_BOUND", "the provenance does not seal this exact bank read")
    amount = raw.get("amount") if raw.get("amount") is not None else (None if raw.get("amount_minor") is None else Decimal(str(raw["amount_minor"])) / 100)
    stamp = raw.get("received_at") or raw.get("date") or raw.get("completed_at")
    _require(amount is not None and stamp is not None, "FUNDS_INCOMPLETE", "a bank read carries the amount and the time")
    return {"funds_provenance": prov, "funds_digest": str(prov["output_digest"]), "received_amount": str(_money(decimal_value(amount, field_name="amount"))), "received_at": timestamp(str(stamp), field_name="received_at"), "evidence_refs": [f"funds:{prov['observation_ref']}"]}


# --------------------------------------------------------------------------- #
# What the chain hands to the other engines
# --------------------------------------------------------------------------- #


def expected_inflow(state: Any, *, source_plan: Any, expected_at: str) -> dict[str, Any]:
    """A treasury ``receivable`` flow for a lodged or assessed claim: the assessed amount when known, else the prepared benefit."""

    plan, bound = INCENTIVE_CLAIM_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    _require(bound.status in ("lodged", "assessed"), "NO_INFLOW_EXPECTED", f"a claim that is {bound.status} expects no inflow")
    amount = ledger.assessed_amount if bound.status == "assessed" else ledger.benefit_amount
    return {"schema": EXPECTED_INFLOW_SCHEMA, "kind": "receivable", "flow_ref": f"incentive:{bound.scope.entity_ref}", "amount": str(_money(amount)), "currency": plan.currency, "expected_at": timestamp(expected_at, field_name="expected_at"), "basis": "assessed by the authority" if bound.status == "assessed" else "prepared benefit; not yet assessed", "source_digest": bound.state_digest}


def incentive_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in INCENTIVE_STATUSES}
    return {"claims": len(states), "by_status": counts, "eligible_costs": str(_money(sum((state.ledger.eligible_total for state in states), Decimal("0")))), "benefit_prepared": str(_money(sum((state.ledger.benefit_amount for state in states if state.status in ("prepared", "lodged")), Decimal("0")))), "assessed_outstanding": str(_money(sum((state.ledger.assessed_amount for state in states if state.status == "assessed"), Decimal("0")))), "received": str(_money(sum((state.ledger.received_amount for state in states), Decimal("0")))), "rejected": counts["rejected"]}


INCENTIVE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": INCENTIVE_KIND,
    "golden_loop": INCENTIVE_GOLDEN_LOOP,
    "stages": ["register", "record_activity", "bind_costs", "prepare", "lodge", "assess", "receive"],
    "statuses": list(INCENTIVE_STATUSES),
    "events": list(INCENTIVE_EVENTS),
    "hops": {"register": "a program of the plan (and of the grant registry) with the eligibility assessment digest", "record_activity": "an activity with evidence digest and opaque worker commitments", "bind_costs": "allocations against a replayed closed cost register's own sources, by kind and percent", "prepare": "benefit computed from the operator-supplied rate and uplift, capped when capped", "lodge": "the authority's lodgement receipt, by someone other than the preparer", "assess": "the notice of assessment", "receive": "a bank read for the exact assessed amount"},
    "required_connectors": ["xero", "lightbulb.sdk_engine_state"],
    "hard_rules": [
        "only costs a closed cost register attributed can be claimed, and a source is never allocated beyond 100 percent",
        "the benefit rate is the operator's from their adviser; the SDK asserts no entitlement",
        "the preparer never lodges their own preparation when the plan requires segregation",
        "funds are proven by a bank read for the exact assessed amount",
    ],
}

__all__ = ["FUNDS_TOOLS", "INCENTIVE_CLAIM_LIFECYCLE", "INCENTIVE_EVENTS", "INCENTIVE_GOLDEN_LOOP", "INCENTIVE_KIND", "INCENTIVE_MANIFEST", "INCENTIVE_STATUSES", "REGISTER_BOUND_STATUSES", "TERMINAL_INCENTIVE_STATUSES", "ActivityRecord", "CostAllocation", "IncentiveClaimError", "IncentiveClaimPlan", "IncentiveClaimState", "IncentiveLedger", "IncentiveProgram", "IncentiveReceipt", "activity_receipt", "advance_incentive_claim", "assessment_receipt", "compile_incentive_claim_chain", "cost_receipt", "expected_inflow", "incentive_summary", "lodgement_receipt", "open_incentive_claim", "preparation_receipt", "receipt_of_funds", "registered_program_refs", "registration_receipt"]
