"""Executable primitives for the company simulator and scenario evaluation.

``company.simulate_operating_periods`` runs a deterministic multi-period
simulation of an operating plan through the real period lifecycle and
returns the sealed trajectory; ``company.evaluate_scenario`` checks a result
against golden expectations (attainment, cash, replans, halts, signals,
result digest) as regression evidence for blueprint changes.  Read-only;
synthetic observations are labelled and nothing is dispatched or spent.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field

from lightbulb.company_engine_core import OpaqueRef, StrictModel
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import COMPANY_OS_GOLDEN_LOOP, CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_simulator import (
    STANDARD_SCENARIOS,
    ScenarioEvaluation,
    ScenarioExpectation,
    SimulationError,
    SimulationResult,
    SimulationScenario,
    evaluate_scenario,
    simulate_company,
    standard_scenario,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

SIMULATION_STAGES: tuple[str, ...] = ("scenario", "simulate", "evaluate", "learn")


class SimulateInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: CompanyOperatingPlan
    scenario: SimulationScenario | None = None
    standard_scenario: str | None = Field(default=None, min_length=1, max_length=40)


class EvaluateScenarioInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    result: SimulationResult
    expectation: ScenarioExpectation


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_company_operating_blueprint("b2b_saas")
        scenario = standard_scenario("steady_state")
        result = simulate_company(plan, scenario)
        self._built = {
            "simulate": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "standard_scenario": "steady_state"},
            "evaluate": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "result": result.to_dict(), "expectation": {"min_revenue_attainment_percent": "50", "must_not_halt": True, "required_signals": ["signals.books_verified"]}},
        }
        return self._built


_EXAMPLES = _Examples()


def example_simulation_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _SimulationPrimitive(EnginePrimitive[Any, Any]):
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = "company_operating_system"
    loop_stages = SIMULATION_STAGES
    profiles = tuple(sorted(STANDARD_SCENARIOS))
    hard_rules = {"drives_the_real_period_lifecycle": True, "deterministic_for_plan_and_scenario": True, "synthetic_observations_are_labelled": True, "no_dispatch_spend_or_provider_read": True}
    authority_boundary = {"agent": "proposes scenarios and expectations", "sdk": "simulates, seals, evaluates", "spring": "nothing; simulations never reach the platform", "connectors": "none", "mcp": "projects these primitives"}


class SimulateOperatingPeriodsPrimitive(_SimulationPrimitive):
    primitive_ref = "company.simulate_operating_periods"
    version = "0.1.0"
    title = "Simulate operating periods for a company plan"
    description = "Run a deterministic multi-period simulation (standard scenario or custom) through the real period lifecycle: dispatch, evidence, reconcile, replan, close or halt; returns the sealed trajectory with cash, runway, signals, replans, and the health assessment across the plan lineage."
    input_model = SimulateInput
    output_model = SimulationResult
    risk_level = "low"
    operation_spec = read_spec("company_simulate", "sdk.company.simulate_operating_periods")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "simulate")

    def _execute(self, context: PrimitiveExecutionContext, inputs: SimulateInput) -> PrimitiveExecutionResult[SimulationResult]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        if (inputs.scenario is None) == (inputs.standard_scenario is None):
            return self.blocked(digest=digest, code="SCENARIO_AMBIGUOUS", message="Provide exactly one of scenario or standard_scenario.")
        try:
            scenario = inputs.scenario if inputs.scenario is not None else standard_scenario(str(inputs.standard_scenario))
            result = simulate_company(inputs.plan, scenario)
        except SimulationError as exc:
            return self.blocked(digest=digest, code="SIMULATION_REJECTED", message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="SCENARIO_INVALID", message=str(exc))
        return self.preview(output=result, digest=digest, external_refs={"result_digest": result.result_digest, "scenario_digest": result.scenario_digest}, event_type="company.simulated", event_payload={"periods_run": result.periods_run, "total_revenue": str(result.total_revenue), "final_cash": str(result.final_cash), "halt_reason": result.halt_reason, "replans": result.replans}, evidence_kind="company_simulation_result", evidence_summary="Synthetic trajectory; nothing executed.", summary=f"{result.periods_run} period(s): revenue {result.total_revenue}, final cash {result.final_cash}, {result.replans} replan(s)" + (f", halted: {result.halt_reason}" if result.halt_reason else "") + ".")


class EvaluateScenarioPrimitive(_SimulationPrimitive):
    primitive_ref = "company.evaluate_scenario"
    version = "0.1.0"
    title = "Evaluate a simulation against golden expectations"
    description = "Check a simulation result against expectations (minimum attainment, minimum cash, maximum replans, halt rules, required and forbidden signals, golden result digest); the sealed evaluation is regression evidence for blueprint and engine changes."
    input_model = EvaluateScenarioInput
    output_model = ScenarioEvaluation
    risk_level = "low"
    operation_spec = read_spec("company_evaluate_scenario", "sdk.company.evaluate_scenario")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "evaluate")

    def _execute(self, context: PrimitiveExecutionContext, inputs: EvaluateScenarioInput) -> PrimitiveExecutionResult[ScenarioEvaluation]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        evaluation = evaluate_scenario(inputs.result, inputs.expectation)
        return self.preview(output=evaluation, digest=digest, external_refs={"evaluation_digest": evaluation.evaluation_digest, "result_digest": evaluation.result_digest}, event_type="company.scenario_evaluated", event_payload={"passed": evaluation.passed, "findings": [f"{item.check}:{'pass' if item.passed else 'fail'}" for item in evaluation.findings]}, evidence_kind="company_scenario_evaluation", evidence_summary="Golden expectation check; no effect.", summary=("Scenario passed" if evaluation.passed else "Scenario failed") + f" {sum(1 for item in evaluation.findings if item.passed)} of {len(evaluation.findings)} check(s).")


SIMULATION_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    SimulateOperatingPeriodsPrimitive(),
    EvaluateScenarioPrimitive(),
)

SIMULATION_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_simulation",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "company_simulator", "golden_loop": COMPANY_OS_GOLDEN_LOOP, "stages": list(SIMULATION_STAGES), "scenarios": sorted(STANDARD_SCENARIOS), "required_connectors": [], "hard_rules": ["deterministic for a plan and scenario", "drives the real period lifecycle with every fence", "synthetic observations are labelled", "nothing dispatched, spent, or read"]},
    "modules": {"domain": "lightbulb.company_simulator", "primitives": "lightbulb.company_simulator_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_operating_system period lifecycle and health assessment"],
    "required_connectors": [],
    "primitive_refs": [item.primitive_ref for item in SIMULATION_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no forecast is a commitment", "no provider read", "no certification or production-readiness claim"],
}

__all__ = [
    "SIMULATION_EXECUTABLE_PRIMITIVES",
    "SIMULATION_INTEGRATION_MANIFEST",
    "EvaluateScenarioInput",
    "EvaluateScenarioPrimitive",
    "SimulateInput",
    "SimulateOperatingPeriodsPrimitive",
    "example_simulation_inputs",
]
