"""Decisions with counterfactuals: what approving, rejecting, or choosing the alternative would do, before anyone decides.

An approval item says which transition wants to happen.  ``brief_decision``
adds what it would do: it forecasts the company from the persisted period
states (observed returns per engine become the simulator's return band, the
current plan is the baseline) under each option, and reports the deltas in
revenue, gross profit, final cash, and halt risk, plus the sensitivity: the
return-on-spend change that would flip the recommendation.  When an
operating memory is supplied its priors widen or narrow the band with what
earlier periods taught.

Supported decisions today: a period ``replan`` (approve applies the proposed
shifts to the blueprint shares; reject keeps them; the alternative is the
neutral half-shift), and a generic "hold" for any other engine transition
(approve advances now; reject leaves the entity where it is), which reports
the state consequences rather than a forecast.  The brief is sealed and cites
the state digests it was computed from; it never decides.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_approval_inbox import InboxItem
from lightbulb.company_engine_core import GENESIS_DIGEST, BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, timestamp
from lightbulb.company_operating_system import PERIOD_LIFECYCLE, CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_simulator import SimulationResult, build_scenario, simulate_company, standard_scenario

DECISION_BRIEF_SCHEMA = "lightbulb.company_decision_brief.v1"
Option = Literal["approve", "reject", "alternative"]
Recommendation = Literal["approve", "reject", "alternative", "no_forecast"]
_HUNDRED = Decimal("100")


class OptionForecast(StrictModel):
    option: Option
    label: BoundedText
    plan_digest: Sha256Digest
    periods: int = Field(ge=1)
    total_revenue: Decimal
    total_gross_profit: Decimal
    final_cash: Decimal
    min_cash: Decimal
    halted_at_period: int | None = None
    halt_reason: ShortText | None = None
    result_digest: Sha256Digest

    @field_validator("total_revenue", "total_gross_profit", "final_cash", "min_cash", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class Sensitivity(StrictModel):
    engine: ShortText
    observed_return_on_spend: Decimal
    flip_at_return_on_spend: Decimal | None = None
    direction: Literal["lower", "higher", "none"]
    note: BoundedText

    @field_validator("observed_return_on_spend", "flip_at_return_on_spend", mode="before")
    @classmethod
    def _dec(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class DecisionBrief(StrictModel):
    schema_id: str = Field(default=DECISION_BRIEF_SCHEMA, alias="schema")
    task_id: OpaqueRef | None = None
    engine: ShortText
    event: ShortText
    entity_ref: OpaqueRef
    decided_from_state_digest: Sha256Digest
    baseline_plan_digest: Sha256Digest
    horizon_periods: int = Field(ge=1, le=52)
    observed_returns: dict[str, Decimal] = Field(default_factory=dict)
    forecasts: tuple[OptionForecast, ...] = Field(default_factory=tuple, max_length=3)
    recommendation: Recommendation
    rationale: tuple[BoundedText, ...] = Field(min_length=1, max_length=8)
    sensitivity: tuple[Sensitivity, ...] = Field(default_factory=tuple, max_length=8)
    memory_state_digest: Sha256Digest | None = None
    executes_nothing: Literal[True] = True
    brief_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("observed_returns", mode="before")
    @classmethod
    def _returns(cls, value: Any) -> dict[str, Decimal]:
        return {str(key): decimal_value(item, field_name=f"observed_returns.{key}", allow_negative=True) for key, item in dict(value or {}).items()}

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> DecisionBrief:
        if not skip_digests(info) and self.brief_digest != sealed_digest(DecisionBrief, self, "brief_digest"):
            raise ValueError("brief_digest must commit the exact brief")
        return self

    def forecast(self, option: str) -> OptionForecast | None:
        return next((item for item in self.forecasts if item.option == option), None)

    def render(self) -> str:
        lines = [f"**{self.engine}.{self.event}** on `{self.entity_ref}`: recommend **{self.recommendation}**"]
        for item in self.forecasts:
            halt = f", halts period {item.halted_at_period} ({item.halt_reason})" if item.halted_at_period else ""
            lines.append(f"- {item.option}: {item.label}; revenue {item.total_revenue}, gross profit {item.total_gross_profit}, final cash {item.final_cash}{halt}")
        for reason in self.rationale:
            lines.append(f"- {reason}")
        for item in self.sensitivity:
            lines.append(f"- sensitivity: {item.note}")
        return "\n".join(lines)


def _observed_returns(plan: CompanyOperatingPlan, periods: Sequence[Any]) -> dict[str, Decimal]:
    spend: dict[str, Decimal] = {}
    revenue: dict[str, Decimal] = {}
    for state in periods:
        for engine, value in state.ledger.spend_by_engine.items():
            spend[engine] = spend.get(engine, Decimal("0")) + Decimal(str(value))
        for engine, value in state.ledger.revenue_by_engine.items():
            revenue[engine] = revenue.get(engine, Decimal("0")) + Decimal(str(value))
    return {engine: (revenue.get(engine, Decimal("0")) / total).quantize(Decimal("0.01")) for engine, total in spend.items() if total > 0}


def _bind_periods(plan: CompanyOperatingPlan, periods: Sequence[Mapping[str, Any] | Any], prior_plans: Sequence[Any]) -> list[Any]:
    lineage = {plan.plan_digest: plan, **{CompanyOperatingPlan.model_validate(detached(item)).plan_digest: CompanyOperatingPlan.model_validate(detached(item)) for item in prior_plans}}
    out = []
    for record in periods:
        document = dict(record["state"]) if isinstance(record, Mapping) and "state" in record else (record.to_dict() if hasattr(record, "to_dict") else dict(record))
        owner = lineage.get(str(document.get("plan_digest")))
        if owner is None:
            raise ValueError("a period belongs to a plan outside the supplied lineage")
        out.append(PERIOD_LIFECYCLE.State.model_validate(document, context={PERIOD_LIFECYCLE.plan_context_key: owner}))
    return out


def _shifted_plan(plan: CompanyOperatingPlan, shifts: Sequence[Mapping[str, Any]], *, factor: Decimal = Decimal("1")) -> CompanyOperatingPlan:
    blueprint = plan.blueprint.to_dict()
    shares = {item["engine"]: Decimal(str(item["budget_share_percent"])) for item in blueprint["engines"]} if blueprint.get("engines") and isinstance(blueprint["engines"][0], Mapping) else {}
    if not shares:
        raise ValueError("the blueprint carries no engine budget shares to shift")
    for shift in shifts:
        engine = str(shift["engine"])
        delta = (Decimal(str(shift["delta_percent"])) * factor).quantize(Decimal("0.01"))
        if engine not in shares:
            raise ValueError(f"shift names an engine outside the blueprint: {engine}")
        shares[engine] += delta
    if any(value < 0 for value in shares.values()):
        raise ValueError("a shift would make an engine share negative")
    blueprint["engines"] = [{**item, "budget_share_percent": str(shares[item["engine"]])} for item in blueprint["engines"]]
    return compile_company_operating_blueprint(blueprint)


def _scenario(plan: CompanyOperatingPlan, returns: Mapping[str, Decimal], *, periods: int, start_at: str, starting_cash: Any, memory_assumptions: Sequence[Mapping[str, Any]] = ()) -> Any:
    base = standard_scenario("steady_state").to_dict()
    base.pop("scenario_digest", None)
    assumptions: dict[str, dict[str, Any]] = {}
    for engine, value in returns.items():
        assumptions[engine] = {"engine": engine, "return_on_spend_min": str(max(Decimal("0"), value * Decimal("0.9"))), "return_on_spend_max": str(max(Decimal("0"), value * Decimal("1.1"))), "utilisation_min_percent": "85", "utilisation_max_percent": "100"}
    for item in memory_assumptions:
        engine = str(item["engine"])
        merged = {**assumptions.get(engine, {"engine": engine}), **{key: value for key, value in item.items() if key != "engine"}}
        assumptions[engine] = merged
    return build_scenario({**base, "name": "decision_forecast", "periods": periods, "start_at": start_at, "starting_cash": str(starting_cash), "assumptions": list(assumptions.values()), "replan_each_period": False, "approvals_granted": True})


def _forecast(option: str, label: str, plan: CompanyOperatingPlan, scenario: Any) -> tuple[SimulationResult, dict[str, Any]]:
    result = simulate_company(plan, scenario)
    return result, {"option": option, "label": label, "plan_digest": plan.plan_digest, "periods": result.periods_run, "total_revenue": str(result.total_revenue), "total_gross_profit": str(result.total_gross_profit), "final_cash": str(result.final_cash), "min_cash": str(result.min_cash), "halted_at_period": result.halted_at_period, "halt_reason": result.halt_reason, "result_digest": result.result_digest}


def brief_replan(plan: CompanyOperatingPlan | Mapping[str, Any], periods: Sequence[Mapping[str, Any] | Any], shifts: Sequence[Mapping[str, Any]], *, entity_ref: str, now: str, cash_on_hand: Any, horizon_periods: int = 3, prior_plans: Sequence[Any] = (), memory_state: Any = None, task_id: str | None = None) -> DecisionBrief:
    """Forecast approve (shifts applied), reject (current shares), and the half-shift alternative from the persisted periods."""

    parsed_plan = CompanyOperatingPlan.model_validate(detached(plan))
    states = _bind_periods(parsed_plan, periods, prior_plans)
    if not states:
        raise ValueError("a replan brief needs at least one persisted period")
    current = max(states, key=lambda item: item.version if item.scope.entity_ref == entity_ref else -1)
    returns = _observed_returns(parsed_plan, states)
    stamp = timestamp(now, field_name="now")
    memory_assumptions: list[Mapping[str, Any]] = []
    memory_digest = None
    if memory_state is not None:
        from lightbulb.company_operating_memory import priors_to_assumptions

        memory_assumptions = priors_to_assumptions(memory_state, engines=list(parsed_plan.blueprint.engine_kinds))
        memory_digest = memory_state.state_digest
    if not returns and not memory_assumptions:
        brief = {"task_id": task_id, "engine": "company_operating_system", "event": "replan", "entity_ref": entity_ref, "decided_from_state_digest": current.state_digest, "baseline_plan_digest": parsed_plan.plan_digest, "horizon_periods": horizon_periods, "observed_returns": {}, "forecasts": [], "recommendation": "no_forecast", "rationale": ["no period has recorded spend and revenue yet, and no memory priors exist; approve or reject on the blueprint's own limits"], "sensitivity": [], "memory_state_digest": memory_digest}
        return seal(DecisionBrief, brief, "brief_digest")
    scenario_for = lambda candidate: _scenario(candidate, returns, periods=horizon_periods, start_at=stamp, starting_cash=cash_on_hand, memory_assumptions=memory_assumptions)  # noqa: E731
    approve_plan = _shifted_plan(parsed_plan, shifts)
    alternative_plan = _shifted_plan(parsed_plan, shifts, factor=Decimal("0.5"))
    forecasts: list[dict[str, Any]] = []
    results: dict[str, SimulationResult] = {}
    for option, label, candidate in (("approve", "apply the proposed shifts", approve_plan), ("reject", "keep the current shares", parsed_plan), ("alternative", "apply half the proposed shifts", alternative_plan)):
        result, row = _forecast(option, label, candidate, scenario_for(candidate))
        results[option] = result
        forecasts.append(row)
    ranked = sorted(results.items(), key=lambda item: (item[1].halted_at_period is not None, -item[1].total_gross_profit, -item[1].final_cash))
    recommendation = ranked[0][0]
    best, runner_up = ranked[0][1], ranked[1][1]
    rationale = [f"{recommendation} yields gross profit {best.total_gross_profit} over {horizon_periods} period(s) versus {runner_up.total_gross_profit} for {ranked[1][0]}"]
    if any(result.halted_at_period is not None for result in results.values()):
        halted = ", ".join(f"{option} halts at period {result.halted_at_period}" for option, result in results.items() if result.halted_at_period is not None)
        rationale.append(f"halt risk: {halted}")
    rationale.append("forecast uses the returns observed in the persisted periods (±10%) and any memory priors; it is synthetic and executes nothing")
    sensitivity: list[dict[str, Any]] = []
    for shift in shifts:
        engine = str(shift["engine"])
        observed = returns.get(engine)
        if observed is None:
            sensitivity.append({"engine": engine, "observed_return_on_spend": "0", "flip_at_return_on_spend": None, "direction": "none", "note": f"{engine} has no observed return yet; the shift rests on the blueprint, not evidence"})
            continue
        delta = Decimal(str(shift["delta_percent"]))
        flip = None
        direction: str = "none"
        for step in range(1, 21):
            factor = Decimal(1) + Decimal(step) * (Decimal("-0.1") if delta > 0 else Decimal("0.1"))
            if factor <= 0:
                break
            probe = dict(returns)
            probe[engine] = (observed * factor).quantize(Decimal("0.01"))
            probe_scenario = _scenario(approve_plan, probe, periods=horizon_periods, start_at=stamp, starting_cash=cash_on_hand, memory_assumptions=memory_assumptions)
            probe_reject = _scenario(parsed_plan, probe, periods=horizon_periods, start_at=stamp, starting_cash=cash_on_hand, memory_assumptions=memory_assumptions)
            approve_result = simulate_company(approve_plan, probe_scenario)
            reject_result = simulate_company(parsed_plan, probe_reject)
            approve_wins = (approve_result.halted_at_period is None, approve_result.total_gross_profit) >= (reject_result.halted_at_period is None, reject_result.total_gross_profit)
            if approve_wins != (recommendation == "approve") and recommendation in ("approve", "reject"):
                flip = probe[engine]
                direction = "lower" if factor < 1 else "higher"
                break
        note = f"{engine} observed return {observed}; " + (f"the recommendation flips if it moves to {flip} ({direction})" if flip is not None else "no flip found within ±100% of the observed return")
        sensitivity.append({"engine": engine, "observed_return_on_spend": str(observed), "flip_at_return_on_spend": None if flip is None else str(flip), "direction": direction, "note": note})
    brief = {"task_id": task_id, "engine": "company_operating_system", "event": "replan", "entity_ref": entity_ref, "decided_from_state_digest": current.state_digest, "baseline_plan_digest": parsed_plan.plan_digest, "horizon_periods": horizon_periods, "observed_returns": {key: str(value) for key, value in returns.items()}, "forecasts": forecasts, "recommendation": recommendation, "rationale": rationale[:8], "sensitivity": sensitivity[:8], "memory_state_digest": memory_digest}
    return seal(DecisionBrief, brief, "brief_digest")


def brief_hold(item: InboxItem, *, current_state: Any | None) -> DecisionBrief:
    """For any other engine transition: what approving advances and what rejecting leaves, from the persisted state; no forecast."""

    binding = item.engine_binding
    if binding is None:
        raise ValueError("the item is not an engine transition approval")
    digest = current_state.state_digest if current_state is not None else binding.expected_state_digest
    status = current_state.status if current_state is not None else "unknown"
    rationale = [f"approve: {item.on_approve}", f"reject: {item.on_reject}", f"the entity is currently {status} at version {current_state.version if current_state is not None else binding.expected_version}; the approval is {item.freshness}"]
    if item.freshness == "stale":
        rationale.append("the persisted state moved since the approval was requested; decide against the current state or let the engine re-request")
    recommendation: Recommendation = "no_forecast"
    return seal(DecisionBrief, {"task_id": item.task_id, "engine": binding.engine, "event": binding.event, "entity_ref": binding.entity_ref, "decided_from_state_digest": digest, "baseline_plan_digest": binding.plan_digest, "horizon_periods": 1, "observed_returns": {}, "forecasts": [], "recommendation": recommendation, "rationale": rationale[:8], "sensitivity": [], "memory_state_digest": None}, "brief_digest")


def brief_for_item(item: InboxItem, *, plan: CompanyOperatingPlan | Mapping[str, Any] | None = None, periods: Sequence[Mapping[str, Any] | Any] = (), pending_command: Mapping[str, Any] | None = None, now: str, cash_on_hand: Any = None, current_state: Any | None = None, memory_state: Any = None, prior_plans: Sequence[Any] = ()) -> DecisionBrief:
    """Route an inbox item to the right brief: a replan with its pending command's shifts gets a forecast, everything else a hold brief."""

    binding = item.engine_binding
    if binding is None:
        raise ValueError("the item is not an engine transition approval")
    if binding.engine == "company_operating_system" and binding.event == "replan" and plan is not None and pending_command is not None and cash_on_hand is not None:
        shifts = list((pending_command.get("receipt") or {}).get("shifts") or [])
        if shifts:
            return brief_replan(plan, periods, shifts, entity_ref=binding.entity_ref, now=now, cash_on_hand=cash_on_hand, prior_plans=prior_plans, memory_state=memory_state, task_id=item.task_id)
    return brief_hold(item, current_state=current_state)


DECISIONS_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "company_decisions",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "stages": ["bind_periods", "observe_returns", "forecast_options", "rank", "sensitivity", "seal"],
    "supported_decisions": ["company_operating_system.replan (forecast)", "any engine transition (hold brief)"],
    "required_connectors": [],
    "hard_rules": [
        "forecasts start from the persisted periods' observed returns and the current plan; they are synthetic and flagged as such",
        "the recommendation ranks halt risk first, then gross profit, then final cash",
        "sensitivity searches the return band for the point that flips the recommendation",
        "a brief cites the state digest it was computed from and never decides",
    ],
}

__all__ = ["DECISIONS_MANIFEST", "DECISION_BRIEF_SCHEMA", "DecisionBrief", "OptionForecast", "Sensitivity", "brief_for_item", "brief_hold", "brief_replan"]
