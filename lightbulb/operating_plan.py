"""The operating plan: one replay-fenced plan of record per planning horizon, from a drafted budget to reviewed variance and an adopted reforecast.

The cost register attributed every dollar actually spent, the runway engine
set the envelope, and the simulator projected periods forward, but nothing
held a plan: no revenue line per engine and no budget per cost centre that
the closed period could be compared with.  The board pack could say what
happened and never whether it was on plan.  ``OPERATING_PLAN_LIFECYCLE``
does:

    drafted -> approved -> tracking -> variance_reviewed -> tracking ...
                                     variance_reviewed -> reforecast -> tracking ...
                                     variance_reviewed -> closed                 (terminal)
    any non-terminal -> abandoned                                               (terminal, with a reason)

* ``plan_receipt`` opens the plan from typed lines: planned revenue per
  engine and planned spend per cost centre for each period of the policy's
  horizon; planned spend never exceeds the operating budget per period.
* ``approve`` consumes a ``replan`` authority proof for the total planned
  spend; the approver is never the requester.
* ``actuals_receipt`` binds one period's actuals from a closed
  ``CostRegisterState`` replayed against its map: revenue per engine and
  spend per centre come from the register's own sources, never typed.
* ``review_variance`` computes each bound period's variance against the
  current forecast and marks breaches beyond the policy's threshold.
* ``reforecast_receipt`` revises only the periods still ahead; a reforecast
  that raises total spend needs its own ``replan`` proof; the plan of record
  is retained beside every forecast version.

``budget_variance_signal`` and ``reforecast_adopted_signal`` give the
operating system the two signals it routes; ``plan_vs_actual`` gives the
board pack its "against plan" table.  Nothing here changes a budget, moves
money, or persists anything.
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
    Rejected,
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

OPERATING_PLAN_KIND = "operating_plan"
OPERATING_PLAN_GOLDEN_LOOP = "planning.operating_plan_to_reforecast@0.1.0"
OPERATING_PLAN_POLICY_SCHEMA = "lightbulb.operating_plan_policy.v1"
PLAN_VS_ACTUAL_SCHEMA = "lightbulb.operating_plan_vs_actual.v1"
MAX_PLAN_TRANSITIONS = 120
REGISTER_BOUND_STATUSES: frozenset[str] = frozenset({"coverage_asserted", "closed"})
_HUNDRED = Decimal("100")
LineKind = Literal["revenue", "spend"]

PLAN_STATUSES: tuple[str, ...] = ("drafted", "approved", "tracking", "variance_reviewed", "reforecast", "closed", "abandoned")
TERMINAL_PLAN_STATUSES: frozenset[str] = frozenset({"closed", "abandoned"})
PLAN_EVENTS: tuple[str, ...] = ("draft", "approve", "bind_actuals", "review_variance", "reforecast", "close", "abandon")
_PLAN_TABLE: dict[tuple[str, str], str] = {
    ("new", "draft"): "drafted",
    ("drafted", "approve"): "approved",
    ("approved", "bind_actuals"): "tracking",
    ("tracking", "bind_actuals"): "tracking",
    ("tracking", "review_variance"): "variance_reviewed",
    ("variance_reviewed", "bind_actuals"): "tracking",
    ("variance_reviewed", "reforecast"): "reforecast",
    ("reforecast", "bind_actuals"): "tracking",
    ("variance_reviewed", "close"): "closed",
    **{(status, "abandon"): "abandoned" for status in ("drafted", "approved", "tracking", "variance_reviewed", "reforecast")},
}


class OperatingPlanError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OperatingPlanError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM)


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


class PlanPeriod(StrictModel):
    period_ref: OpaqueRef
    period_start: str
    period_end: str

    @field_validator("period_start", "period_end")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _ordered(self) -> "PlanPeriod":
        if parsed(self.period_end) <= parsed(self.period_start):
            raise ValueError("a plan period ends after it starts")
        return self


class OperatingPlanPolicy(StrictModel):
    """What the chain enforces: the horizon, the lines that may be planned, the budget ceiling per period, and the variance threshold."""

    schema_id: str = Field(default=OPERATING_PLAN_POLICY_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    periods: tuple[PlanPeriod, ...] = Field(min_length=1, max_length=24)
    revenue_engines: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    centre_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=24)
    operating_budget_per_period: Decimal
    variance_threshold_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    operating_plan_digest: Sha256Digest | None = None
    cost_centre_map_digest: Sha256Digest | None = None
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("periods", "revenue_engines", "centre_refs", mode="before")
    @classmethod
    def _sequences(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("operating_budget_per_period", "variance_threshold_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "OperatingPlanPolicy":
        unique([item.period_ref for item in self.periods], label="plan periods")
        unique(list(self.revenue_engines), label="revenue engines")
        unique(list(self.centre_refs), label="centre refs")
        for earlier, later in zip(self.periods, self.periods[1:]):
            if parsed(later.period_start) < parsed(earlier.period_end):
                raise ValueError("plan periods are ordered and do not overlap")
        if self.operating_budget_per_period <= 0:
            raise ValueError("the operating budget per period is positive")
        if not skip_digests(info) and self.plan_digest != sealed_digest(OperatingPlanPolicy, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact policy")
        return self

    def period(self, period_ref: str) -> PlanPeriod | None:
        return next((item for item in self.periods if item.period_ref == period_ref), None)


def compile_operating_plan_policy(company_ref: str, *, operating_plan: Any, periods: Sequence[Mapping[str, Any]], centre_refs: Sequence[str], cost_centre_map: Any = None, overrides: Mapping[str, Any] | None = None) -> OperatingPlanPolicy:
    """The currency, the budget ceiling and the revenue engines come from the sealed company operating plan; the centres from its cost centre map."""

    raw_plan = dict(detached(operating_plan))
    blueprint = dict(raw_plan.get("blueprint") or {})
    engines = [str(dict(item)["engine"]) for item in blueprint.get("engines") or []]
    raw: dict[str, Any] = {"company_ref": company_ref, "currency": str(blueprint.get("currency", "")).upper(), "periods": [dict(detached(item)) for item in periods], "revenue_engines": engines, "centre_refs": list(centre_refs), "operating_budget_per_period": str(blueprint.get("operating_budget_per_period")), "operating_plan_digest": raw_plan.get("plan_digest"), **dict(overrides or {})}
    if cost_centre_map is not None:
        raw["cost_centre_map_digest"] = str(dict(detached(cost_centre_map)).get("plan_digest") or stable_digest(detached(cost_centre_map)))
    return seal(OperatingPlanPolicy, raw, "plan_digest")


# --------------------------------------------------------------------------- #
# Receipts, ledger, lifecycle
# --------------------------------------------------------------------------- #


class PlanLine(StrictModel):
    period_ref: OpaqueRef
    kind: LineKind
    ref: OpaqueRef
    amount: Decimal

    @field_validator("amount", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")

    @property
    def key(self) -> str:
        return f"{self.period_ref}|{self.kind}|{self.ref}"


class VarianceLine(StrictModel):
    period_ref: OpaqueRef
    kind: LineKind
    ref: OpaqueRef
    planned: Decimal
    actual: Decimal
    variance: Decimal
    variance_percent: Decimal | None = None
    breach: bool = False

    @field_validator("planned", "actual", "variance", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("variance_percent", mode="before")
    @classmethod
    def _percent(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="variance_percent", allow_negative=True)


class VarianceReview(StrictModel):
    period_ref: OpaqueRef
    reviewer_ref: OpaqueRef
    reviewed_at: str
    forecast_version: int = Field(ge=1)
    lines: tuple[VarianceLine, ...] = Field(default_factory=tuple, max_length=200)
    breaches: int = Field(default=0, ge=0)

    @field_validator("lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class ReforecastRecord(StrictModel):
    forecast_version: int = Field(ge=2)
    adopted_at: str
    period_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=24)
    delta_spend: Decimal
    delta_revenue: Decimal
    approval_ref: OpaqueRef | None = None
    reason: BoundedText

    @field_validator("period_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("delta_spend", "delta_revenue", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class PlanReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    lines: tuple[PlanLine, ...] = Field(default_factory=tuple, max_length=600)
    requester_ref: OpaqueRef | None = None
    authorization_proof: dict[str, Any] | None = None
    period_ref: OpaqueRef | None = None
    register_source: dict[str, Any] | None = None
    register_plan: dict[str, Any] | None = None
    reviewer_ref: OpaqueRef | None = None
    detail: BoundedText | None = None

    @field_validator("evidence_refs", "lines", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value


class PeriodActuals(StrictModel):
    period_ref: OpaqueRef
    register_digest: Sha256Digest
    register_ref: OpaqueRef
    bound_at: str
    revenue: dict[str, Decimal] = Field(default_factory=dict)
    spend: dict[str, Decimal] = Field(default_factory=dict)

    @field_validator("revenue", "spend", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=str(info.field_name), allow_negative=True) for key, item in dict(value or {}).items()}


class OperatingPlanLedger(StrictModel):
    requester_ref: str | None = None
    drafted_at: str | None = None
    plan_of_record: tuple[PlanLine, ...] = Field(default_factory=tuple, max_length=600)
    forecast: tuple[PlanLine, ...] = Field(default_factory=tuple, max_length=600)
    forecast_version: int = Field(default=1, ge=1)
    planned_spend_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    planned_revenue_total: Decimal = Field(default=Decimal("0"), validate_default=True)
    approved_at: str | None = None
    approval_ref: str | None = None
    approver_ref: str | None = None
    actuals: tuple[PeriodActuals, ...] = Field(default_factory=tuple, max_length=24)
    reviews: tuple[VarianceReview, ...] = Field(default_factory=tuple, max_length=48)
    reforecasts: tuple[ReforecastRecord, ...] = Field(default_factory=tuple, max_length=24)
    breaches_total: int = Field(default=0, ge=0)
    breaches_since_reforecast: int = Field(default=0, ge=0)
    closed_at: str | None = None
    abandon_reason: str | None = None
    outcome: Literal["open", "closed", "abandoned"] = "open"

    @field_validator("plan_of_record", "forecast", "actuals", "reviews", "reforecasts", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("planned_spend_total", "planned_revenue_total", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @property
    def bound_periods(self) -> tuple[str, ...]:
        return tuple(item.period_ref for item in self.actuals)

    @property
    def reviewed_periods(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.period_ref for item in self.reviews))


class OperatingPlanEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    budget_moved: Literal[False] = False
    money_spent: Literal[False] = False
    provider_read: Literal[False] = False


def _lines(raw: Sequence[Any]) -> list[PlanLine]:
    return [item if isinstance(item, PlanLine) else PlanLine.model_validate(dict(detached(item))) for item in raw]


def _validate_lines(policy: OperatingPlanPolicy, lines: Sequence[PlanLine], *, period_refs: Sequence[str] | None = None) -> None:
    require(bool(lines), "PLAN_EMPTY", "a plan carries at least one line")
    keys = [line.key for line in lines]
    require(len(keys) == len(set(keys)), "PLAN_LINE_DUPLICATE", "one amount per period, kind, and reference")
    allowed = set(period_refs if period_refs is not None else [item.period_ref for item in policy.periods])
    for line in lines:
        require(line.period_ref in allowed, "PLAN_PERIOD_UNKNOWN", f"{line.period_ref} is not a period this plan may set")
        if line.kind == "revenue":
            require(line.ref in policy.revenue_engines, "PLAN_REF_UNKNOWN", f"{line.ref} is not a revenue engine of this company")
        else:
            require(line.ref in policy.centre_refs, "PLAN_REF_UNKNOWN", f"{line.ref} is not a cost centre of this company")
    for period_ref in allowed:
        spend = sum((line.amount for line in lines if line.period_ref == period_ref and line.kind == "spend"), Decimal("0"))
        require(spend <= policy.operating_budget_per_period, "PLAN_EXCEEDS_BUDGET", f"planned spend {spend} in {period_ref} exceeds the operating budget {policy.operating_budget_per_period}")


def _totals(lines: Sequence[PlanLine]) -> tuple[Decimal, Decimal]:
    spend = sum((line.amount for line in lines if line.kind == "spend"), Decimal("0"))
    revenue = sum((line.amount for line in lines if line.kind == "revenue"), Decimal("0"))
    return _money(spend), _money(revenue)


def _variance_lines(policy: OperatingPlanPolicy, forecast: Sequence[PlanLine], actuals: PeriodActuals) -> tuple[list[VarianceLine], int]:
    out: list[VarianceLine] = []
    breaches = 0
    planned_by_key = {line.key: line for line in forecast if line.period_ref == actuals.period_ref}
    observed: dict[tuple[str, str], Decimal] = {**{("revenue", ref): amount for ref, amount in actuals.revenue.items()}, **{("spend", ref): amount for ref, amount in actuals.spend.items()}}
    refs = sorted({(line.kind, line.ref) for line in planned_by_key.values()} | set(observed))
    for kind, ref in refs:
        planned_line = planned_by_key.get(f"{actuals.period_ref}|{kind}|{ref}")
        planned = planned_line.amount if planned_line is not None else Decimal("0")
        actual = observed.get((kind, ref), Decimal("0"))
        variance = _money(actual - planned)
        percent = None if planned == 0 else (variance / planned * _HUNDRED).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        adverse = variance > 0 if kind == "spend" else variance < 0
        breach = adverse and (percent is None or abs(percent) > policy.variance_threshold_percent)
        breaches += int(breach)
        out.append(VarianceLine(period_ref=actuals.period_ref, kind=kind, ref=ref, planned=_money(planned), actual=_money(actual), variance=variance, variance_percent=percent, breach=breach))
    return out, breaches


def _apply_plan(policy: OperatingPlanPolicy, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    r, event, at = command.receipt, command.event, command.occurred_at
    if event == "draft":
        require(r.requester_ref is not None, "PLAN_REQUESTER_MISSING", "a plan names who drafted it")
        lines = list(r.lines)
        _validate_lines(policy, lines)
        spend, revenue = _totals(lines)
        serial = [line.to_dict() for line in lines]
        data.update({"requester_ref": r.requester_ref, "drafted_at": at, "plan_of_record": serial, "forecast": serial, "forecast_version": 1, "planned_spend_total": str(spend), "planned_revenue_total": str(revenue)})
    elif event == "approve":
        require(r.authorization_proof is not None, "PLAN_NOT_AUTHORIZED", f"adopting {data['planned_spend_total']} {policy.currency} of planned spend is a replan decision; a human decides it", "await_approval")
        from lightbulb.authority_matrix import require_authorization_proof

        proof = require_authorization_proof(r.authorization_proof, category="replan", amount=Decimal(str(data["planned_spend_total"])), currency=policy.currency, command=command, plan_digest=policy.plan_digest, company_ref=policy.company_ref)
        require(proof.engine == OPERATING_PLAN_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
        require(proof.approver_ref != data.get("requester_ref"), "SEGREGATION_VIOLATED", "the drafter cannot approve their own plan")
        data.update({"approved_at": at, "approval_ref": proof.approval_task_id, "approver_ref": proof.approver_ref})
    elif event == "bind_actuals":
        require(r.period_ref is not None and r.register_source is not None and r.register_plan is not None, "ACTUALS_NOT_PROVEN", "actuals bind from the replayed cost register of the period and its map, never from typed totals")
        period = policy.period(str(r.period_ref))
        require(period is not None, "PLAN_PERIOD_UNKNOWN", f"{r.period_ref} is not a period of this plan")
        assert period is not None
        require(all(str(dict(item).get("period_ref")) != r.period_ref for item in data.get("actuals", ())), "PERIOD_ALREADY_BOUND", f"{r.period_ref} already has actuals bound")
        from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

        try:
            register_map, register = COST_REGISTER_LIFECYCLE.bind(r.register_plan, r.register_source)
        except (ValueError, TypeError, KeyError) as exc:
            require(False, "ACTUALS_NOT_PROVEN", f"the register must replay against its exact map: {exc}"[:300])
            raise AssertionError from exc
        require(register_map.company_ref == policy.company_ref and register.scope.currency == policy.currency, "REGISTER_SCOPE_MISMATCH", "the register belongs to another company or currency")
        require(register.status in REGISTER_BOUND_STATUSES, "REGISTER_NOT_CLOSED", f"the register is {register.status}; actuals bind only from an asserted or closed register")
        ledger = register.ledger
        require(str(ledger.period_ref) == r.period_ref and str(ledger.period_start) == period.period_start and str(ledger.period_end) == period.period_end, "REGISTER_PERIOD_MISMATCH", f"the register covers {ledger.period_ref} {ledger.period_start}..{ledger.period_end}, not {period.period_ref}")
        require(parsed(register.transition_history[-1].command.occurred_at) <= parsed(at), "REGISTER_FROM_FUTURE", "the register cannot come from the future")
        spend: dict[str, Decimal] = {}
        for source in ledger.sources:
            spend[str(source.centre_ref)] = _money(spend.get(str(source.centre_ref), Decimal("0")) + Decimal(str(source.spend_amount)))
        revenue = {str(engine): _money(amount) for engine, amount in ledger.engine_revenue.items()}
        actuals = PeriodActuals(period_ref=str(r.period_ref), register_digest=register.state_digest, register_ref=register.scope.entity_ref, bound_at=at, revenue=revenue, spend=spend)
        data.update({"actuals": [*[dict(item) for item in data.get("actuals", ())], actuals.to_dict()]})
    elif event == "review_variance":
        require(r.reviewer_ref is not None, "REVIEWER_MISSING", "a variance review names the reviewer")
        reviewed = {str(dict(item)["period_ref"]) for item in data.get("reviews", ())}
        pending = [PeriodActuals.model_validate(dict(item)) for item in data.get("actuals", ()) if str(dict(item)["period_ref"]) not in reviewed]
        require(bool(pending), "NOTHING_TO_REVIEW", "every bound period is already reviewed; bind the next period's actuals first")
        forecast = _lines(data.get("forecast", ()))
        reviews = [dict(item) for item in data.get("reviews", ())]
        breaches = 0
        for actuals in pending:
            lines, count = _variance_lines(policy, forecast, actuals)
            breaches += count
            reviews.append(VarianceReview(period_ref=actuals.period_ref, reviewer_ref=str(r.reviewer_ref), reviewed_at=at, forecast_version=int(data.get("forecast_version", 1)), lines=tuple(lines), breaches=count).to_dict())
        data.update({"reviews": reviews, "breaches_total": int(data.get("breaches_total", 0)) + breaches, "breaches_since_reforecast": int(data.get("breaches_since_reforecast", 0)) + breaches})
    elif event == "reforecast":
        require(int(data.get("breaches_since_reforecast", 0)) > 0, "REFORECAST_UNWARRANTED", "a reforecast follows a reviewed breach; the plan of record stands until then")
        bound = {str(dict(item)["period_ref"]) for item in data.get("actuals", ())}
        ahead = [item.period_ref for item in policy.periods if item.period_ref not in bound]
        require(bool(ahead), "NO_PERIODS_AHEAD", "every period has actuals; close the plan instead")
        lines = list(r.lines)
        _validate_lines(policy, lines, period_refs=ahead)
        forecast = [line for line in _lines(data.get("forecast", ())) if line.period_ref in bound] + lines
        old_spend, old_revenue = _totals(_lines(data.get("forecast", ())))
        new_spend, new_revenue = _totals(forecast)
        delta_spend, delta_revenue = _money(new_spend - old_spend), _money(new_revenue - old_revenue)
        approval_ref = None
        if delta_spend > 0:
            require(r.authorization_proof is not None, "REFORECAST_NOT_AUTHORIZED", f"raising planned spend by {delta_spend} {policy.currency} is a replan decision; a human decides it", "await_approval")
            from lightbulb.authority_matrix import require_authorization_proof

            proof = require_authorization_proof(r.authorization_proof, category="replan", amount=delta_spend, currency=policy.currency, command=command, plan_digest=policy.plan_digest, company_ref=policy.company_ref)
            require(proof.engine == OPERATING_PLAN_KIND, "APPROVAL_TRANSITION_MISMATCH", "the proof authorizes another engine")
            approval_ref = proof.approval_task_id
        version = int(data.get("forecast_version", 1)) + 1
        record = ReforecastRecord(forecast_version=version, adopted_at=at, period_refs=tuple(ahead), delta_spend=delta_spend, delta_revenue=delta_revenue, approval_ref=approval_ref, reason=str(command.reason)[:600])
        data.update({"forecast": [line.to_dict() for line in forecast], "forecast_version": version, "reforecasts": [*[dict(item) for item in data.get("reforecasts", ())], record.to_dict()], "breaches_since_reforecast": 0})
    elif event == "close":
        bound = {str(dict(item)["period_ref"]) for item in data.get("actuals", ())}
        reviewed = {str(dict(item)["period_ref"]) for item in data.get("reviews", ())}
        missing = [item.period_ref for item in policy.periods if item.period_ref not in bound or item.period_ref not in reviewed]
        require(not missing, "PERIODS_OUTSTANDING", f"{missing} still need actuals bound and reviewed")
        data.update({"closed_at": at, "outcome": "closed"})
    elif event == "abandon":
        data.update({"abandon_reason": str(command.reason)[:300], "outcome": "abandoned"})
    return next_status, data


OPERATING_PLAN_LIFECYCLE = LifecycleSpec(entity="operating_plan", schema_prefix=OPERATING_PLAN_KIND, statuses=PLAN_STATUSES, terminal=TERMINAL_PLAN_STATUSES, events=PLAN_EVENTS, table=_PLAN_TABLE, opening_event="draft", reason_events=("reforecast", "abandon"), apply=_apply_plan, ledger_model=OperatingPlanLedger, receipt_model=PlanReceipt, effect_boundary_model=OperatingPlanEffectBoundary, plan_model=OperatingPlanPolicy, max_transitions=MAX_PLAN_TRANSITIONS)
OperatingPlanState = OPERATING_PLAN_LIFECYCLE.State


def open_operating_plan(policy: OperatingPlanPolicy | Mapping[str, Any], scope: Mapping[str, Any], *, receipt: Mapping[str, Any], opened_at: str, actor_ref: str) -> Any:
    return OPERATING_PLAN_LIFECYCLE.open(policy, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_operating_plan(policy: OperatingPlanPolicy | Mapping[str, Any], state: Any, command: Any) -> Any:
    return OPERATING_PLAN_LIFECYCLE.advance(policy, state, command)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #


def plan_receipt(policy: OperatingPlanPolicy | Mapping[str, Any], lines: Sequence[Mapping[str, Any]], *, requester_ref: str) -> dict[str, Any]:
    """The opening receipt: typed lines checked against the policy before the plan exists."""

    parsed_policy = OperatingPlanPolicy.model_validate(detached(policy))
    parsed_lines = _lines(lines)
    try:
        _validate_lines(parsed_policy, parsed_lines)
    except Rejected as exc:
        raise OperatingPlanError(exc.code, exc.instructions) from exc
    return {"lines": [line.to_dict() for line in parsed_lines], "requester_ref": requester_ref, "evidence_refs": [f"plan:{stable_digest([line.to_dict() for line in parsed_lines])[:16]}"]}


def approval_receipt(proof: Mapping[str, Any] | Any) -> dict[str, Any]:
    from lightbulb.authority_matrix import authorization_evidence

    evidence = authorization_evidence(proof)
    return {"authorization_proof": evidence["authorization_proof"], "evidence_refs": list(evidence["evidence_refs"])}


def actuals_receipt(register_state: Any, *, source_plan: Any, period_ref: str | None = None) -> dict[str, Any]:
    """From a closed cost register: retained whole and replayed at the consuming transition."""

    from lightbulb.company_cost_centres import COST_REGISTER_LIFECYCLE

    try:
        plan, state = COST_REGISTER_LIFECYCLE.bind(source_plan, register_state)
    except (ValueError, TypeError, KeyError) as exc:
        raise OperatingPlanError("ACTUALS_NOT_PROVEN", "retain the original cost register state and its sealed map") from exc
    _require(state.status in REGISTER_BOUND_STATUSES, "REGISTER_NOT_CLOSED", f"the register is {state.status}")
    return {"period_ref": period_ref or str(state.ledger.period_ref), "register_source": state.to_dict(), "register_plan": plan.to_dict(), "evidence_refs": [f"register:{state.scope.entity_ref}:{state.state_digest[:16]}"]}


def review_receipt(*, reviewer_ref: str) -> dict[str, Any]:
    return {"reviewer_ref": reviewer_ref, "evidence_refs": [f"reviewer:{reviewer_ref}"]}


def reforecast_receipt(lines: Sequence[Mapping[str, Any]], *, authorization: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Revised lines for the periods still ahead; a proof travels with it when spend rises."""

    parsed_lines = _lines(lines)
    receipt: dict[str, Any] = {"lines": [line.to_dict() for line in parsed_lines], "evidence_refs": [f"reforecast:{stable_digest([line.to_dict() for line in parsed_lines])[:16]}"]}
    if authorization is not None:
        evidence = approval_receipt(authorization)
        receipt["authorization_proof"] = evidence["authorization_proof"]
        receipt["evidence_refs"] = [*receipt["evidence_refs"], *evidence["evidence_refs"]]
    return receipt


# --------------------------------------------------------------------------- #
# What the plan hands to the other engines
# --------------------------------------------------------------------------- #


def budget_variance_signals(state: Any, *, source_plan: Any, emitted_at: str) -> list[dict[str, Any]]:
    """One ``signals.budget_variance`` per breached line of the latest reviews; empty when nothing breached."""

    _, bound = OPERATING_PLAN_LIFECYCLE.bind(source_plan, state)
    stamp = timestamp(emitted_at, field_name="emitted_at")
    out = []
    latest_version = max((review.forecast_version for review in bound.ledger.reviews), default=0)
    for review in bound.ledger.reviews:
        if review.forecast_version != latest_version:
            continue
        for line in review.lines:
            if line.breach:
                out.append({"name": "signals.budget_variance", "producer": OPERATING_PLAN_KIND, "emitted_at": stamp, "payload": {"period_ref": line.period_ref, "kind": line.kind, "ref": line.ref, "planned": str(line.planned), "actual": str(line.actual), "variance_percent": "" if line.variance_percent is None else str(line.variance_percent), "source_digest": bound.state_digest}})
    return out


def reforecast_adopted_signal(state: Any, *, source_plan: Any, emitted_at: str) -> dict[str, Any] | None:
    _, bound = OPERATING_PLAN_LIFECYCLE.bind(source_plan, state)
    if not bound.ledger.reforecasts:
        return None
    record = bound.ledger.reforecasts[-1]
    return {"name": "signals.reforecast_adopted", "producer": OPERATING_PLAN_KIND, "emitted_at": timestamp(emitted_at, field_name="emitted_at"), "payload": {"forecast_version": record.forecast_version, "period_refs": ",".join(record.period_refs), "delta_spend": str(record.delta_spend), "delta_revenue": str(record.delta_revenue), "source_digest": bound.state_digest}}


def plan_vs_actual(state: Any, *, source_plan: Any) -> dict[str, Any]:
    """The board pack's table: per period, planned and actual revenue and spend, the variance, and whether it was reviewed."""

    policy, bound = OPERATING_PLAN_LIFECYCLE.bind(source_plan, state)
    ledger = bound.ledger
    forecast = list(ledger.forecast)
    actual_by_period = {item.period_ref: item for item in ledger.actuals}
    reviewed = set(ledger.reviewed_periods)
    rows = []
    for period in policy.periods:
        planned_spend, planned_revenue = _totals([line for line in forecast if line.period_ref == period.period_ref])
        actuals = actual_by_period.get(period.period_ref)
        actual_spend = None if actuals is None else _money(sum(actuals.spend.values(), Decimal("0")))
        actual_revenue = None if actuals is None else _money(sum(actuals.revenue.values(), Decimal("0")))
        rows.append({"period_ref": period.period_ref, "planned_revenue": str(planned_revenue), "planned_spend": str(planned_spend), "actual_revenue": None if actual_revenue is None else str(actual_revenue), "actual_spend": None if actual_spend is None else str(actual_spend), "revenue_variance": None if actual_revenue is None else str(_money(actual_revenue - planned_revenue)), "spend_variance": None if actual_spend is None else str(_money(actual_spend - planned_spend)), "reviewed": period.period_ref in reviewed, "breaches": sum(review.breaches for review in ledger.reviews if review.period_ref == period.period_ref)})
    payload = {"schema": PLAN_VS_ACTUAL_SCHEMA, "company_ref": policy.company_ref, "currency": policy.currency, "status": bound.status, "forecast_version": ledger.forecast_version, "rows": rows, "breaches_total": ledger.breaches_total, "source_digest": bound.state_digest}
    return {**payload, "table_digest": stable_digest(payload)}


def operating_plan_summary(states: Sequence[Any]) -> dict[str, Any]:
    counts = {status: sum(1 for state in states if state.status == status) for status in PLAN_STATUSES}
    return {"plans": len(states), "by_status": counts, "periods_bound": sum(len(state.ledger.actuals) for state in states), "periods_reviewed": sum(len(state.ledger.reviewed_periods) for state in states), "breaches": sum(state.ledger.breaches_total for state in states), "reforecasts": sum(len(state.ledger.reforecasts) for state in states)}


OPERATING_PLAN_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": OPERATING_PLAN_KIND,
    "golden_loop": OPERATING_PLAN_GOLDEN_LOOP,
    "stages": ["draft", "approve", "bind_actuals", "review_variance", "reforecast", "close"],
    "statuses": list(PLAN_STATUSES),
    "events": list(PLAN_EVENTS),
    "hops": {"draft": "typed revenue and spend lines inside the operating budget per period", "approve": "replan authority proof for the total planned spend", "bind_actuals": "the period's asserted or closed cost register, replayed", "review_variance": "computed from the forecast and the bound actuals; breaches beyond the threshold", "reforecast": "revised lines for the periods ahead; a proof when spend rises", "close": "every period bound and reviewed"},
    "required_connectors": ["lightbulb.sdk_engine_state"],
    "hard_rules": [
        "planned spend in a period never exceeds the operating budget the company blueprint set",
        "actuals come from the replayed cost register; a typed total never binds",
        "variance is computed, never asserted, and a breach needs the threshold exceeded on the adverse side",
        "a reforecast follows a reviewed breach, revises only the periods ahead, and raises spend only under replan authority",
        "the plan of record is retained beside every forecast version",
    ],
}

__all__ = ["OPERATING_PLAN_GOLDEN_LOOP", "OPERATING_PLAN_KIND", "OPERATING_PLAN_LIFECYCLE", "OPERATING_PLAN_MANIFEST", "PLAN_EVENTS", "PLAN_STATUSES", "PLAN_VS_ACTUAL_SCHEMA", "REGISTER_BOUND_STATUSES", "TERMINAL_PLAN_STATUSES", "OperatingPlanError", "OperatingPlanLedger", "OperatingPlanPolicy", "OperatingPlanState", "PeriodActuals", "PlanLine", "PlanPeriod", "PlanReceipt", "ReforecastRecord", "VarianceLine", "VarianceReview", "actuals_receipt", "advance_operating_plan", "approval_receipt", "budget_variance_signals", "compile_operating_plan_policy", "open_operating_plan", "operating_plan_summary", "plan_receipt", "plan_vs_actual", "reforecast_adopted_signal", "reforecast_receipt", "review_receipt"]
