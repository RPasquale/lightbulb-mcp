"""Company simulator: deterministic multi-period runs of an operating plan.

A scenario fixes a seed and per-engine assumptions (budget utilisation,
return on spend, signal rates); the simulator drives the *real* operating
period lifecycle (open → dispatch → evidence → reconcile → replan → close)
through :mod:`lightbulb.company_operating_system`, applying every fence the
production path applies, and produces a sealed trajectory: spend, revenue,
signals, cash, runway, replans, halts, and the health assessment.

Replans change the next period's envelopes, so a run is a lineage of plans;
each period is bound to the plan generation it ran under and the health
assessment reads the whole lineage.

Everything is deterministic: the same plan and scenario always produce the
same result digest, which is what makes scenarios usable as regression
evidence for blueprint changes.  Nothing here reads a provider, dispatches an
agent, or spends money; synthetic observations are labelled as such.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    percent_value,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)
from lightbulb.company_operating_system import (
    ENGINE_KINDS,
    EngineKind,
    CompanyHealthAssessment,
    CompanyOperatingPlan,
    advance_period,
    assess_company_health,
    compile_company_operating_blueprint,
    open_period,
    seal_period_command,
)

SCENARIO_SCHEMA = "lightbulb.company_simulation_scenario.v1"
RESULT_SCHEMA = "lightbulb.company_simulation_result.v1"
EVALUATION_SCHEMA = "lightbulb.company_scenario_evaluation.v1"
MAX_PERIODS = 52
REVENUE_ENGINES: frozenset[str] = frozenset({"growth_engine", "pipeline_engine", "saas_operating_engine", "marketplace_supply_engine", "engagement_engine"})
SIGNAL_BY_ENGINE: Mapping[str, tuple[str, ...]] = {
    "growth_engine": ("signals.attributed_revenue", "signals.envelope_exhausted"),
    "pipeline_engine": ("signals.qualified_pipeline",),
    "saas_operating_engine": ("signals.churn_risk", "signals.expansion_candidate", "signals.release_rolled_back"),
    "finance_close": ("signals.books_verified",),
    "service_delivery": ("signals.case_resolved",),
}
_ONE = Decimal("1")
_HUNDRED = Decimal("100")


def _pct(value: Any, name: str) -> Decimal:
    return percent_value(value, field_name=name)


def _money(value: Any, name: str) -> Decimal:
    result = decimal_value(value, field_name=name)
    if result < 0:
        raise ValueError(f"{name} must not be negative")
    return result


class EngineAssumptions(StrictModel):
    """Ranges the deterministic draw samples from, per engine."""

    engine: EngineKind
    utilisation_min_percent: Decimal = Field(default=Decimal("70"), validate_default=True)
    utilisation_max_percent: Decimal = Field(default=Decimal("100"), validate_default=True)
    return_on_spend_min: Decimal = Field(default=Decimal("0"), validate_default=True)
    return_on_spend_max: Decimal = Field(default=Decimal("0"), validate_default=True)
    signal_rate_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    return_on_spend_drift_percent_per_period: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("utilisation_min_percent", "utilisation_max_percent", "signal_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _pct(value, str(info.field_name))

    @field_validator("return_on_spend_min", "return_on_spend_max", mode="before")
    @classmethod
    def _ros(cls, value: Any, info: ValidationInfo) -> Decimal:
        result = decimal_value(value, field_name=str(info.field_name))
        if result < 0 or result > 100:
            raise ValueError(f"{info.field_name} must be between 0 and 100")
        return result

    @field_validator("return_on_spend_drift_percent_per_period", mode="before")
    @classmethod
    def _drift(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="return_on_spend_drift_percent_per_period", allow_negative=True)
        if result < -50 or result > 50:
            raise ValueError("return_on_spend_drift_percent_per_period must be between -50 and 50")
        return result

    @model_validator(mode="after")
    def _ranges(self) -> EngineAssumptions:
        if self.utilisation_min_percent > self.utilisation_max_percent:
            raise ValueError("utilisation range is inverted")
        if self.return_on_spend_min > self.return_on_spend_max:
            raise ValueError("return on spend range is inverted")
        return self


DEFAULT_ASSUMPTIONS: Mapping[str, dict[str, str]] = {
    "growth_engine": {"utilisation_min_percent": "80", "utilisation_max_percent": "100", "return_on_spend_min": "1.5", "return_on_spend_max": "4", "signal_rate_percent": "30"},
    "pipeline_engine": {"utilisation_min_percent": "60", "utilisation_max_percent": "95", "return_on_spend_min": "1", "return_on_spend_max": "6", "signal_rate_percent": "40"},
    "saas_operating_engine": {"utilisation_min_percent": "85", "utilisation_max_percent": "100", "return_on_spend_min": "2", "return_on_spend_max": "5", "signal_rate_percent": "20"},
    "finance_close": {"utilisation_min_percent": "90", "utilisation_max_percent": "100", "return_on_spend_min": "0", "return_on_spend_max": "0", "signal_rate_percent": "100"},
    "service_delivery": {"utilisation_min_percent": "70", "utilisation_max_percent": "100", "return_on_spend_min": "0", "return_on_spend_max": "0", "signal_rate_percent": "50"},
    "people_engine": {"utilisation_min_percent": "80", "utilisation_max_percent": "100", "return_on_spend_min": "0", "return_on_spend_max": "0", "signal_rate_percent": "25"},
    "marketplace_supply_engine": {"utilisation_min_percent": "70", "utilisation_max_percent": "100", "return_on_spend_min": "1", "return_on_spend_max": "3", "signal_rate_percent": "25"},
    "engagement_engine": {"utilisation_min_percent": "70", "utilisation_max_percent": "100", "return_on_spend_min": "1.5", "return_on_spend_max": "4", "signal_rate_percent": "25"},
}


class SimulationScenario(StrictModel):
    schema_id: str = Field(default=SCENARIO_SCHEMA, alias="schema")
    name: ShortText
    seed: int = Field(ge=0, le=2**63 - 1)
    periods: int = Field(ge=1, le=MAX_PERIODS)
    start_at: str
    starting_cash: Decimal
    fixed_costs_per_period: Decimal = Field(default=Decimal("0"), validate_default=True)
    assumptions: tuple[EngineAssumptions, ...] = Field(default_factory=tuple, max_length=len(ENGINE_KINDS))
    replan_each_period: bool = True
    approvals_granted: bool = False
    books_verified_failure_periods: tuple[int, ...] = Field(default_factory=tuple, max_length=MAX_PERIODS)
    halt_when_cash_negative: bool = True
    scenario_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("start_at")
    @classmethod
    def _start(cls, value: str) -> str:
        return timestamp(value, field_name="start_at")

    @field_validator("starting_cash", "fixed_costs_per_period", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SimulationScenario:
        unique([item.engine for item in self.assumptions], label="assumption engines")
        for period in self.books_verified_failure_periods:
            if period < 1 or period > self.periods:
                raise ValueError("books_verified_failure_periods must name periods inside the run")
        if not skip_digests(info) and self.scenario_digest != sealed_digest(SimulationScenario, self, "scenario_digest"):
            raise ValueError("scenario_digest must commit the exact scenario")
        return self

    def assumptions_for(self, engine: str) -> EngineAssumptions:
        found = next((item for item in self.assumptions if item.engine == engine), None)
        if found is not None:
            return found
        return EngineAssumptions.model_validate({"engine": engine, **DEFAULT_ASSUMPTIONS[engine]})


def build_scenario(scenario: SimulationScenario | Mapping[str, Any]) -> SimulationScenario:
    if isinstance(scenario, SimulationScenario):
        return scenario
    return seal(SimulationScenario, scenario, "scenario_digest")


class PeriodSummary(StrictModel):
    period: int = Field(ge=1, le=MAX_PERIODS)
    plan_digest: Sha256Digest
    period_start: str
    period_end: str
    status: str
    budget_total: Decimal
    spend: Decimal
    revenue: Decimal
    gross_profit: Decimal
    cash_end: Decimal
    spend_by_engine: dict[str, Decimal]
    revenue_by_engine: dict[str, Decimal]
    signals: tuple[str, ...] = Field(default_factory=tuple)
    shifts: dict[str, Decimal] = Field(default_factory=dict)
    approval_used: bool = False
    halt_reason: str | None = None

    @field_validator("budget_total", "spend", "revenue", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("gross_profit", "cash_end", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("spend_by_engine", "revenue_by_engine", mode="before")
    @classmethod
    def _maps(cls, value: Any, info: ValidationInfo) -> dict[str, Decimal]:
        return {str(k): _money(v, str(info.field_name)) for k, v in dict(value or {}).items()}

    @field_validator("shifts", mode="before")
    @classmethod
    def _shifts(cls, value: Any) -> dict[str, Decimal]:
        return {str(k): decimal_value(v, field_name="shifts", allow_negative=True) for k, v in dict(value or {}).items()}


class SimulationResult(StrictModel):
    schema_id: str = Field(default=RESULT_SCHEMA, alias="schema")
    scenario_digest: Sha256Digest
    initial_plan_digest: Sha256Digest
    plan_lineage: tuple[Sha256Digest, ...] = Field(min_length=1, max_length=MAX_PERIODS + 1)
    periods_run: int = Field(ge=1, le=MAX_PERIODS)
    periods: tuple[PeriodSummary, ...] = Field(min_length=1, max_length=MAX_PERIODS)
    total_spend: Decimal
    total_revenue: Decimal
    total_gross_profit: Decimal
    revenue_target: Decimal
    revenue_attainment_percent: Decimal | None = None
    final_cash: Decimal
    min_cash: Decimal
    halted_at_period: int | None = Field(default=None, ge=1, le=MAX_PERIODS)
    halt_reason: str | None = None
    replans: int = Field(ge=0)
    approvals_used: int = Field(ge=0)
    signals_by_name: dict[str, int] = Field(default_factory=dict)
    final_budget_shares: dict[str, Decimal] = Field(default_factory=dict)
    health: CompanyHealthAssessment
    synthetic_observations: Literal[True] = True
    executes_nothing: Literal[True] = True
    result_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total_spend", "total_revenue", "revenue_target", mode="before")
    @classmethod
    def _money(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _money(value, str(info.field_name))

    @field_validator("total_gross_profit", "final_cash", "min_cash", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("revenue_attainment_percent", mode="before")
    @classmethod
    def _attainment(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value, "revenue_attainment_percent")

    @field_validator("final_budget_shares", mode="before")
    @classmethod
    def _shares(cls, value: Any) -> dict[str, Decimal]:
        return {str(k): _pct(v, "final_budget_shares") for k, v in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> SimulationResult:
        if self.periods_run != len(self.periods):
            raise ValueError("periods_run must equal the number of period summaries")
        if (self.halted_at_period is None) != (self.halt_reason is None):
            raise ValueError("halt period and reason travel together")
        if not skip_digests(info) and self.result_digest != sealed_digest(SimulationResult, self, "result_digest"):
            raise ValueError("result_digest must commit the exact result")
        return self


class SimulationError(ValueError):
    """The simulator hit an engine rejection it did not expect; the plan or scenario is inconsistent."""


# --------------------------------------------------------------------------- #
# Deterministic draws
# --------------------------------------------------------------------------- #


def _draw(seed: int, *parts: Any) -> Decimal:
    """Uniform in [0, 1) with two-decimal precision, derived from the seed and the parts."""

    digest = hashlib.sha256((f"{seed}|" + "|".join(str(item) for item in parts)).encode("utf-8")).hexdigest()
    return (Decimal(int(digest[:16], 16) % 10_000) / Decimal("10000")).quantize(Decimal("0.0001"))


def _synthetic_close_proof(seed: int, period: int) -> str:
    """A labelled synthetic stand-in for finance_close.verify_books; never a real proof."""

    return hashlib.sha256(f"synthetic_close_proof|{seed}|{period}".encode("utf-8")).hexdigest()


def _between(low: Decimal, high: Decimal, unit: Decimal) -> Decimal:
    return low + (high - low) * unit


# --------------------------------------------------------------------------- #
# Simulation
# --------------------------------------------------------------------------- #


def _recompiled(plan: CompanyOperatingPlan, shares: Mapping[str, Decimal]) -> CompanyOperatingPlan:
    raw = plan.blueprint.to_dict()
    raw.pop("blueprint_digest", None)
    raw["engines"] = [{**item.to_dict(), "budget_share_percent": str(shares[item.engine])} for item in plan.blueprint.engines]
    return compile_company_operating_blueprint(raw)


def _shift_plan(plan: CompanyOperatingPlan, returns: Mapping[str, Decimal], scenario: SimulationScenario) -> tuple[dict[str, Decimal], bool]:
    """Move budget from the weakest revenue engine to the strongest, inside the replan limits."""

    bp = plan.blueprint
    candidates = [item.engine for item in bp.engines if item.engine in REVENUE_ENGINES and item.engine in returns]
    if len(candidates) < 2:
        return {}, False
    best = max(candidates, key=lambda kind: (returns[kind], kind))
    worst = min(candidates, key=lambda kind: (returns[kind], kind))
    if best == worst or returns[best] == returns[worst]:
        return {}, False
    share_worst = bp.engine(worst).budget_share_percent  # type: ignore[union-attr]
    cap = bp.max_shift_percent_per_replan if scenario.approvals_granted else bp.approval_threshold_percent
    delta = min(cap, share_worst - Decimal("5"), (returns[best] - returns[worst]) * Decimal("10")).quantize(Decimal("1"))
    if delta <= 0:
        return {}, False
    needs_approval = delta > bp.approval_threshold_percent
    return {worst: -delta, best: delta}, needs_approval


def simulate_company(plan: CompanyOperatingPlan | Mapping[str, Any], scenario: SimulationScenario | Mapping[str, Any], *, scope: Mapping[str, Any] | None = None, actor_ref: str = "actor-simulator") -> SimulationResult:
    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    parsed_scenario = build_scenario(scenario)
    bp = parsed_plan.blueprint
    base_scope = dict(scope or {"tenant_ref": "simulated", "company_ref": "simulated", "project_ref": "simulation", "project_id": "40100000-0000-4000-8000-00000000000a"})
    base_scope["currency"] = bp.currency

    current = parsed_plan
    lineage: list[str] = [parsed_plan.plan_digest]
    plans_by_digest: dict[str, CompanyOperatingPlan] = {parsed_plan.plan_digest: parsed_plan}
    states: list[Any] = []
    summaries: list[PeriodSummary] = []
    cash = parsed_scenario.starting_cash
    min_cash = cash
    signals_count: dict[str, int] = {}
    replans = approvals = 0
    halted_at: int | None = None
    halt_reason: str | None = None
    period_start = parsed_scenario.start_at
    returns_seen: dict[str, Decimal] = {}

    for period in range(1, parsed_scenario.periods + 1):
        engine_scope = {**base_scope, "entity_ref": f"sim-period-{period}"}
        state = open_period(current, engine_scope, period_start=period_start, opened_at=period_start, actor_ref=actor_ref)
        counter = 0

        def step(event: str, receipt: Mapping[str, Any] | None = None, *, at: str, reason: str | None = None) -> Any:
            nonlocal state, counter
            counter += 1
            command = seal_period_command({"event": event, "transition_ref": f"sim:{period}:{event}:{counter}", "idempotency_key": f"sim:{period}:{counter}", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": at, "actor_ref": actor_ref, "receipt": dict(receipt or {}), "reason": reason})
            result = advance_period(current, state, command)
            if event == "replan" and parsed_scenario.approvals_granted and result.receipt.rejection_code == "APPROVAL_NOT_BOUND":
                # Simulation-only artifacts go through the same approval binding
                # and matrix guards. They never leave this synthetic trajectory.
                from lightbulb.authority_matrix import adopt_matrix, authorize, authorization_evidence, bind_authority_approval, compile_authority_matrix
                from lightbulb.company_execution_bridge import ENGINE_APPROVAL_TYPE, engine_approval_request
                matrix = compile_authority_matrix(str(state.scope.company_ref), currency=bp.currency,
                    rows=[{"role_ref": "sim:controller", "category": "replan", "max_amount": str(state.ledger.budget_total), "segregation": "not_requester"}],
                    approvers=[{"approver_ref": "sim:approver", "role_ref": "sim:controller"}], effective_from=at)
                adoption = adopt_matrix(matrix, {"id": f"sim:{period}:matrix", "status": "APPROVED", "approvalType": ENGINE_APPROVAL_TYPE,
                    "contextData": {"matrix_digest": matrix.matrix_digest}, "decidedBy": "sim:approver", "decidedAt": at})
                request = engine_approval_request(result, command, engine="company_operating_system", entity_ref=str(state.scope.entity_ref), plan_digest=current.plan_digest,
                    summary="Synthetic scenario replan", description="Simulation assumption only; no platform decision or provider effect occurred.", risk_level=6)
                binding = bind_authority_approval({"id": f"sim:{period}:replan", "status": "APPROVED", "approvalType": ENGINE_APPROVAL_TYPE,
                    "contextData": request.to_platform_body()["contextData"], "decidedBy": "sim:approver", "decidedAt": at}, request)
                moved = sum((Decimal(str(item["delta_percent"])) for item in command["receipt"]["shifts"] if Decimal(str(item["delta_percent"])) > 0), Decimal("0"))
                proof = authorize(matrix, category="replan", amount=(state.ledger.budget_total * moved / _HUNDRED).quantize(MONEY_QUANTUM), currency=bp.currency,
                    approval_binding=binding, requester_ref=actor_ref, command=command, adoption=adoption, now=at)
                command = seal_period_command({**command, "receipt": {**command["receipt"], "authorization_proof": proof.to_dict()}})
                result = advance_period(current, state, command)
            if not result.candidate_validated:
                raise SimulationError(f"period {period} {event}: {result.receipt.rejection_code}: {result.receipt.recovery.instructions}")
            state = result.state
            return result

        dispatch_at = add_days(period_start, 0)
        for envelope in current.envelopes:
            refs = [f"sim:{period}:{envelope.engine}:dispatch:{index}" for index in range(1, min(envelope.dispatches_per_period, 3) + 1)]
            step("dispatch", {"engine": envelope.engine, "dispatch_refs": refs}, at=dispatch_at)

        spend_by_engine: dict[str, Decimal] = {}
        revenue_by_engine: dict[str, Decimal] = {}
        period_signals: list[str] = []
        evidence_at = add_days(period_start, max(1, bp.period_days // 2))
        for envelope in current.envelopes:
            assumptions = parsed_scenario.assumptions_for(envelope.engine)
            utilisation = _between(assumptions.utilisation_min_percent, assumptions.utilisation_max_percent, _draw(parsed_scenario.seed, period, envelope.engine, "utilisation")) / _HUNDRED
            spend = min(envelope.budget, (envelope.budget * utilisation).quantize(MONEY_QUANTUM))
            drift = _ONE + assumptions.return_on_spend_drift_percent_per_period * Decimal(period - 1) / _HUNDRED
            ros = (_between(assumptions.return_on_spend_min, assumptions.return_on_spend_max, _draw(parsed_scenario.seed, period, envelope.engine, "return")) * max(drift, Decimal("0"))).quantize(Decimal("0.01"))
            revenue = (spend * ros).quantize(MONEY_QUANTUM) if envelope.engine in REVENUE_ENGINES else Decimal("0.00")
            signals: list[str] = []
            for name in SIGNAL_BY_ENGINE.get(envelope.engine, ()):
                if current.route(name) is None:
                    continue
                if name == "signals.books_verified":
                    if period not in parsed_scenario.books_verified_failure_periods:
                        signals.append(name)
                elif name == "signals.envelope_exhausted":
                    if spend >= envelope.budget * Decimal("0.98"):
                        signals.append(name)
                elif name == "signals.attributed_revenue":
                    if revenue > 0:
                        signals.append(name)
                elif _draw(parsed_scenario.seed, period, envelope.engine, name) * _HUNDRED < assumptions.signal_rate_percent:
                    signals.append(name)
            step("record_evidence", {"engine": envelope.engine, "evidence_ref": f"sim:{period}:{envelope.engine}:evidence", "spend": str(spend), "revenue": str(revenue), "signals": signals}, at=evidence_at)
            spend_by_engine[envelope.engine] = spend
            revenue_by_engine[envelope.engine] = revenue
            period_signals.extend(signals)
            if envelope.engine in REVENUE_ENGINES and spend > 0:
                returns_seen[envelope.engine] = (revenue / spend).quantize(Decimal("0.01"))

        total_spend = sum(spend_by_engine.values(), Decimal("0"))
        total_revenue = sum(revenue_by_engine.values(), Decimal("0"))
        gross_profit = (total_revenue * bp.targets.gross_margin_percent / _HUNDRED - total_spend - parsed_scenario.fixed_costs_per_period).quantize(MONEY_QUANTUM)
        cash = (cash + gross_profit).quantize(MONEY_QUANTUM)
        min_cash = min(min_cash, cash)
        for name in period_signals:
            signals_count[name] = signals_count.get(name, 0) + 1

        reconcile_at = add_days(period_start, bp.period_days)
        books_verified = period not in parsed_scenario.books_verified_failure_periods
        shifts: dict[str, Decimal] = {}
        approval_used = False
        period_halt: str | None = None
        if not books_verified:
            period_halt = "books not verified for the period"
            step("halt", at=reconcile_at, reason=period_halt)
        elif parsed_scenario.halt_when_cash_negative and cash < 0:
            step("reconcile", {"reconciliation_ref": f"sim:{period}:reconciliation", "books_verified": True, "close_state_digest": _synthetic_close_proof(parsed_scenario.seed, period)}, at=reconcile_at)
            period_halt = "cash exhausted"
            step("halt", at=reconcile_at, reason=period_halt)
        else:
            step("reconcile", {"reconciliation_ref": f"sim:{period}:reconciliation", "books_verified": True, "close_state_digest": _synthetic_close_proof(parsed_scenario.seed, period)}, at=reconcile_at)
            if parsed_scenario.replan_each_period and period < parsed_scenario.periods:
                shifts, needs_approval = _shift_plan(current, returns_seen, parsed_scenario)
                if shifts:
                    receipt: dict[str, Any] = {"shifts": [{"engine": kind, "delta_percent": str(delta)} for kind, delta in sorted(shifts.items())]}
                    if needs_approval:
                        approval_used = True
                        approvals += 1
                    step("replan", receipt, at=reconcile_at)
                    replans += 1
            step("close", at=reconcile_at)

        states.append(state)
        summaries.append(PeriodSummary(period=period, plan_digest=current.plan_digest, period_start=period_start, period_end=state.ledger.period_end or reconcile_at, status=state.status, budget_total=state.ledger.budget_total, spend=total_spend, revenue=total_revenue, gross_profit=gross_profit, cash_end=cash, spend_by_engine=spend_by_engine, revenue_by_engine=revenue_by_engine, signals=tuple(period_signals), shifts=shifts, approval_used=approval_used, halt_reason=period_halt))
        if period_halt is not None:
            halted_at, halt_reason = period, period_halt
            break
        if shifts:
            shares = {item.engine: item.budget_share_percent for item in current.blueprint.engines}
            for kind, delta in shifts.items():
                shares[kind] = shares[kind] + delta
            current = _recompiled(current, shares)
            if current.plan_digest not in plans_by_digest:
                plans_by_digest[current.plan_digest] = current
                lineage.append(current.plan_digest)
        period_start = reconcile_at

    total_spend_all = sum((item.spend for item in summaries), Decimal("0"))
    total_revenue_all = sum((item.revenue for item in summaries), Decimal("0"))
    revenue_target = (bp.targets.revenue_per_period * len(summaries)).quantize(MONEY_QUANTUM)
    days = bp.period_days * len(summaries)
    net_loss = -sum((item.gross_profit for item in summaries), Decimal("0"))
    # Net burn: cash consumed after gross profit; a company that grows its cash has no runway constraint.
    monthly_burn = (net_loss / Decimal(days) * Decimal(30)).quantize(MONEY_QUANTUM) if days and net_loss > 0 else Decimal("0")
    health = assess_company_health(current, states, assessed_at=period_start, cash_on_hand=max(cash, Decimal("0")), monthly_burn=monthly_burn, prior_plans=tuple(plans_by_digest.values()))
    payload = {
        "scenario_digest": parsed_scenario.scenario_digest,
        "initial_plan_digest": parsed_plan.plan_digest,
        "plan_lineage": tuple(lineage),
        "periods_run": len(summaries),
        "periods": tuple(summaries),
        "total_spend": total_spend_all,
        "total_revenue": total_revenue_all,
        "total_gross_profit": sum((item.gross_profit for item in summaries), Decimal("0")),
        "revenue_target": revenue_target,
        "revenue_attainment_percent": (total_revenue_all / revenue_target * _HUNDRED).quantize(Decimal("0.01")) if revenue_target > 0 else None,
        "final_cash": cash,
        "min_cash": min_cash,
        "halted_at_period": halted_at,
        "halt_reason": halt_reason,
        "replans": replans,
        "approvals_used": approvals,
        "signals_by_name": signals_count,
        "final_budget_shares": {item.engine: item.budget_share_percent for item in current.blueprint.engines},
        "health": health,
    }
    return seal(SimulationResult, payload, "result_digest")


# --------------------------------------------------------------------------- #
# Scenario evaluation (golden expectations)
# --------------------------------------------------------------------------- #


class ScenarioExpectation(StrictModel):
    min_revenue_attainment_percent: Decimal | None = None
    min_final_cash: Decimal | None = None
    max_replans: int | None = Field(default=None, ge=0)
    must_not_halt: bool = False
    expected_halt_reason: ShortText | None = None
    required_signals: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    forbidden_signals: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    expected_result_digest: Sha256Digest | None = None

    @field_validator("min_revenue_attainment_percent", mode="before")
    @classmethod
    def _attainment(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value, "min_revenue_attainment_percent")

    @field_validator("min_final_cash", mode="before")
    @classmethod
    def _cash(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="min_final_cash", allow_negative=True)

    @model_validator(mode="after")
    def _guard(self) -> ScenarioExpectation:
        if self.must_not_halt and self.expected_halt_reason is not None:
            raise ValueError("a scenario cannot both forbid and expect a halt")
        return self


class ScenarioFinding(StrictModel):
    check: ShortText
    passed: bool
    detail: BoundedText


class ScenarioEvaluation(StrictModel):
    schema_id: str = Field(default=EVALUATION_SCHEMA, alias="schema")
    scenario_digest: Sha256Digest
    result_digest: Sha256Digest
    passed: bool
    findings: tuple[ScenarioFinding, ...] = Field(min_length=1, max_length=20)
    evaluation_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> ScenarioEvaluation:
        if self.passed != all(item.passed for item in self.findings):
            raise ValueError("passed must equal the conjunction of the findings")
        if not skip_digests(info) and self.evaluation_digest != sealed_digest(ScenarioEvaluation, self, "evaluation_digest"):
            raise ValueError("evaluation_digest must commit the exact evaluation")
        return self


def evaluate_scenario(result: SimulationResult | Mapping[str, Any], expectation: ScenarioExpectation | Mapping[str, Any]) -> ScenarioEvaluation:
    parsed_result = SimulationResult.model_validate(detached(result))
    parsed = ScenarioExpectation.model_validate(detached(expectation))
    findings: list[ScenarioFinding] = []

    def check(name: str, passed: bool, detail: str) -> None:
        findings.append(ScenarioFinding(check=name, passed=passed, detail=detail))

    if parsed.min_revenue_attainment_percent is not None:
        actual = parsed_result.revenue_attainment_percent
        check("revenue_attainment", actual is not None and actual >= parsed.min_revenue_attainment_percent, f"attainment {actual}% against minimum {parsed.min_revenue_attainment_percent}%")
    if parsed.min_final_cash is not None:
        check("final_cash", parsed_result.final_cash >= parsed.min_final_cash, f"final cash {parsed_result.final_cash} against minimum {parsed.min_final_cash}")
    if parsed.max_replans is not None:
        check("replans", parsed_result.replans <= parsed.max_replans, f"{parsed_result.replans} replan(s) against maximum {parsed.max_replans}")
    if parsed.must_not_halt:
        check("no_halt", parsed_result.halted_at_period is None, f"halted at period {parsed_result.halted_at_period}: {parsed_result.halt_reason}" if parsed_result.halted_at_period else "ran every period")
    if parsed.expected_halt_reason is not None:
        check("halt_reason", parsed_result.halt_reason == parsed.expected_halt_reason, f"halt reason {parsed_result.halt_reason!r} against expected {parsed.expected_halt_reason!r}")
    for name in parsed.required_signals:
        check(f"signal:{name}", name in parsed_result.signals_by_name, f"{name} observed {parsed_result.signals_by_name.get(name, 0)} time(s)")
    for name in parsed.forbidden_signals:
        check(f"no_signal:{name}", name not in parsed_result.signals_by_name, f"{name} observed {parsed_result.signals_by_name.get(name, 0)} time(s)")
    if parsed.expected_result_digest is not None:
        check("result_digest", parsed_result.result_digest == parsed.expected_result_digest, "result digest matches the golden run" if parsed_result.result_digest == parsed.expected_result_digest else "result digest differs from the golden run; the plan, scenario, or engine changed")
    if not findings:
        check("no_expectations", True, "no expectations declared; the run completed")
    return seal(ScenarioEvaluation, {"scenario_digest": parsed_result.scenario_digest, "result_digest": parsed_result.result_digest, "passed": all(item.passed for item in findings), "findings": tuple(findings)}, "evaluation_digest")


STANDARD_SCENARIOS: Mapping[str, dict[str, Any]] = {
    "steady_state": {"name": "Steady state, 12 periods", "seed": 7, "periods": 12, "start_at": "2026-10-05T00:00:00Z", "starting_cash": "250000", "fixed_costs_per_period": "4000", "approvals_granted": False},
    "aggressive_reallocation": {"name": "Aggressive reallocation with approvals", "seed": 11, "periods": 12, "start_at": "2026-10-05T00:00:00Z", "starting_cash": "250000", "fixed_costs_per_period": "4000", "approvals_granted": True},
    "cash_squeeze": {"name": "Cash squeeze", "seed": 3, "periods": 12, "start_at": "2026-10-05T00:00:00Z", "starting_cash": "20000", "fixed_costs_per_period": "15000", "assumptions": [{"engine": "growth_engine", "return_on_spend_min": "0.2", "return_on_spend_max": "0.8"}, {"engine": "pipeline_engine", "return_on_spend_min": "0.1", "return_on_spend_max": "0.6"}, {"engine": "saas_operating_engine", "return_on_spend_min": "0.3", "return_on_spend_max": "0.9"}]},
    "close_failure": {"name": "Books fail to verify in period 4", "seed": 5, "periods": 8, "start_at": "2026-10-05T00:00:00Z", "starting_cash": "250000", "books_verified_failure_periods": [4]},
}


def standard_scenario(name: str) -> SimulationScenario:
    if name not in STANDARD_SCENARIOS:
        raise ValueError(f"unknown standard scenario {name!r}; known: {sorted(STANDARD_SCENARIOS)}")
    return build_scenario(STANDARD_SCENARIOS[name])


__all__ = [
    "DEFAULT_ASSUMPTIONS",
    "MAX_PERIODS",
    "REVENUE_ENGINES",
    "STANDARD_SCENARIOS",
    "EngineAssumptions",
    "PeriodSummary",
    "ScenarioEvaluation",
    "ScenarioExpectation",
    "ScenarioFinding",
    "SimulationError",
    "SimulationResult",
    "SimulationScenario",
    "build_scenario",
    "evaluate_scenario",
    "simulate_company",
    "standard_scenario",
]
