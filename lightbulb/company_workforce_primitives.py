"""Executable primitives for the workforce loop: Lightbulb agents as company workers.

``blueprint.compile_workforce`` fits a roster inside the operating plan's
envelopes, ``workforce.plan_dispatch`` fences one dispatch against the
worker's role and budget and returns the exact ``LightbulbClient.dispatch``
payload, ``workforce.advance_worker`` materializes one replay-fenced worker
transition (hire, activate, dispatch, record outcome, pause, resume,
release), and ``workforce.assess_workforce`` derives cost and success per
worker and engine.  Read-only; Spring dispatches the agent and bills it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import CompanyOperatingPlan, compile_company_operating_blueprint
from lightbulb.company_workforce import (
    STANDARD_ROSTERS,
    WORKFORCE_GOLDEN_LOOP,
    WORKFORCE_KIND,
    WORKFORCE_MANIFEST,
    DispatchRequest,
    WorkerCommand,
    WorkerState,
    WorkerTransitionResult,
    WorkforceAssessment,
    WorkforcePlan,
    WorkforceRoster,
    advance_worker,
    assess_workforce,
    compile_workforce,
    hire_worker,
    plan_dispatch,
    seal_worker_command,
    standard_roster,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class CompileWorkforceInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    operating_plan: CompanyOperatingPlan
    roster: WorkforceRoster | None = None
    standard_roster: str | None = Field(default=None, min_length=1, max_length=40)


class PlanDispatchInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: WorkforcePlan
    state: WorkerState  # type: ignore[valid-type]
    action: str = Field(min_length=1, max_length=120)
    message: str = Field(min_length=1, max_length=4000)
    period_ref: OpaqueRef
    estimated_cost: str = Field(min_length=1, max_length=40)
    inputs: dict[str, Any] = Field(default_factory=dict)
    approval_ref: OpaqueRef | None = None


class AdvanceWorkerInput(StrictModel):
    plan: WorkforcePlan
    state: WorkerState  # type: ignore[valid-type]
    command: WorkerCommand  # type: ignore[valid-type]


class AssessWorkforceInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: WorkforcePlan
    states: tuple[WorkerState, ...] = Field(default_factory=tuple, max_length=60)  # type: ignore[valid-type]
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        operating = compile_company_operating_blueprint("b2b_saas")
        plan = compile_workforce(operating, standard_roster("b2b_saas"))
        scope = {**EXAMPLE_SCOPE, "entity_ref": "w-product-triage", "currency": "CAD"}
        state = hire_worker(plan, scope, worker_ref="w-product-triage", hired_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        activate = seal_worker_command({"event": "activate", "transition_ref": "activate:w-product-triage", "idempotency_key": "w-product-triage:activate", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-05T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {}})
        active = advance_worker(plan, state, activate).state
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "operating_plan": operating.to_dict(), "standard_roster": "b2b_saas"},
            "dispatch": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "state": active.to_dict(), "action": "feedback_synthesis", "message": "Synthesize this week's support themes into roadmap evidence.", "period_ref": "period-example", "estimated_cost": "25"},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": activate},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "states": [active.to_dict()], "assessed_at": "2026-10-06T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_workforce_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _WorkforcePrimitive(EnginePrimitive[Any, Any]):
    golden_loop = WORKFORCE_GOLDEN_LOOP
    engine = WORKFORCE_KIND
    loop_stages = tuple(WORKFORCE_MANIFEST["stages"])
    profiles = tuple(sorted(STANDARD_ROSTERS))
    hard_rules = {"workers_fit_inside_engine_envelopes": True, "dispatch_fenced_by_actions_budget_cap_and_ceiling": True, "writes_need_an_approval_reference": True, "outcomes_reconcile_against_the_open_dispatch": True, "no_agent_dispatched_or_billed_here": True}
    authority_boundary = {"agent": "proposes rosters and dispatches", "sdk": "fits rosters, fences dispatches, records outcomes, assesses cost", "spring": "dispatches domain agents, meters and bills them, persists worker states", "connectors": "none directly; agents use their own governed tools", "mcp": "projects these primitives and the loop"}


class CompileWorkforcePrimitive(_WorkforcePrimitive):
    primitive_ref = "blueprint.compile_workforce"
    version = "0.1.0"
    title = "Fit a workforce roster inside the operating plan"
    description = "Bind Lightbulb domain agents to engine stages with per-period budgets, dispatch caps, and per-dispatch ceilings, and prove no engine's workers out-spend its envelope; a standard roster exists per archetype."
    input_model = CompileWorkforceInput
    output_model = WorkforcePlan
    risk_level = "low"
    operation_spec = read_spec("workforce_compile", "sdk.blueprint.compile_workforce")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileWorkforceInput) -> PrimitiveExecutionResult[WorkforcePlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        if (inputs.roster is None) == (inputs.standard_roster is None):
            return self.blocked(digest=digest, code="ROSTER_AMBIGUOUS", message="Provide exactly one of roster or standard_roster.")
        try:
            roster = inputs.roster if inputs.roster is not None else standard_roster(str(inputs.standard_roster))
            plan = compile_workforce(inputs.operating_plan, roster)
        except ValueError as exc:
            return self.blocked(digest=digest, code="ROSTER_INVALID", message=str(exc))
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest, "operating_plan_digest": plan.operating_plan_digest}, event_type="blueprint.workforce_compiled", event_payload={"workers": len(plan.roster.workers), "total_workforce_budget": str(plan.total_workforce_budget), "engines": [item.engine for item in plan.allocations]}, evidence_kind="workforce_plan", evidence_summary="Roster fitted to envelopes; nobody hired.", summary=f"{len(plan.roster.workers)} worker(s) across {len(plan.allocations)} engine(s), {plan.currency} {plan.total_workforce_budget} per period.")


class PlanDispatchPrimitive(_WorkforcePrimitive):
    primitive_ref = "workforce.plan_dispatch"
    version = "0.1.0"
    title = "Plan one governed agent dispatch"
    description = "Check a dispatch against the worker's allowed actions, per-dispatch ceiling, period budget, cap, and approval needs, then return the exact LightbulbClient.dispatch payload; nothing is dispatched."
    input_model = PlanDispatchInput
    output_model = DispatchRequest
    risk_level = "medium"
    operation_spec = read_spec("workforce_plan_dispatch", "sdk.workforce.plan_dispatch")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "dispatch")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanDispatchInput) -> PrimitiveExecutionResult[DispatchRequest]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            request = plan_dispatch(inputs.plan, inputs.state, action=inputs.action, message=inputs.message, period_ref=inputs.period_ref, estimated_cost=inputs.estimated_cost, inputs=inputs.inputs, approval_ref=inputs.approval_ref)
        except ValueError as exc:
            code = str(exc).split(":", 1)[0] if ":" in str(exc) else "DISPATCH_INVALID"
            return self.blocked(digest=digest, code=code, message=str(exc))
        return self.preview(output=request, digest=digest, external_refs={"dispatch_request_digest": request.request_digest, "worker_ref": request.worker_ref}, event_type="workforce.dispatch_planned", event_payload={"domain": request.domain, "action": request.action, "estimated_cost": str(request.estimated_cost), "effect_class": request.effect_class}, evidence_kind="workforce_dispatch_request", evidence_summary="Dispatch payload; no agent invoked.", summary=f"{request.worker_ref} → {request.domain}.{request.action} for {request.currency} {request.estimated_cost} (ceiling and budget respected).")


class AdvanceWorkerPrimitive(_WorkforcePrimitive):
    primitive_ref = "workforce.advance_worker"
    version = "0.1.0"
    title = "Advance a worker by one transition"
    description = "Materialize one replay-fenced worker transition: activate, dispatch (inside actions, ceiling, budget, cap, and approval), record the platform outcome against the open dispatch, pause, resume, release."
    input_model = AdvanceWorkerInput
    output_model = WorkerTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("workforce_advance_worker", "sdk.workforce.advance_worker")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceWorkerInput) -> PrimitiveExecutionResult[WorkerTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the worker scope and the command.")
        try:
            result = advance_worker(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="workforce")


class AssessWorkforcePrimitive(_WorkforcePrimitive):
    primitive_ref = "workforce.assess_workforce"
    version = "0.1.0"
    title = "Assess the workforce"
    description = "Effect-dark cost and success per worker and per engine from worker states: dispatches, spend against budget, success rate, cost per success, unreconciled dispatches."
    input_model = AssessWorkforceInput
    output_model = WorkforceAssessment
    risk_level = "low"
    operation_spec = read_spec("workforce_assess", "sdk.workforce.assess_workforce")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessWorkforceInput) -> PrimitiveExecutionResult[WorkforceAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_workforce(inputs.plan, inputs.states, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATES_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="workforce.assessed", event_payload={"active": assessment.active, "total_dispatches": assessment.total_dispatches, "total_cost": str(assessment.total_cost)}, evidence_kind="workforce_assessment", evidence_summary="Workforce metrics; no effect.", summary=f"{assessment.active} active worker(s), {assessment.total_dispatches} dispatch(es), {assessment.total_cost} spent of {assessment.workforce_budget} per period: {assessment.learnings[0]}")


WORKFORCE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileWorkforcePrimitive(),
    PlanDispatchPrimitive(),
    AdvanceWorkerPrimitive(),
    AssessWorkforcePrimitive(),
)

WORKFORCE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_workforce_golden_loop",
    "golden_loop": WORKFORCE_GOLDEN_LOOP,
    "engine": WORKFORCE_MANIFEST,
    "modules": {"domain": "lightbulb.company_workforce", "primitives": "lightbulb.company_workforce_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["company_operating_system envelopes", "LightbulbClient.dispatch / dispatch_domain_agent", "approval.request_decision", "company_execution_bridge approvals"],
    "required_connectors": WORKFORCE_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in WORKFORCE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no agent dispatched, metered, or billed here", "no worker budget minted beyond the engine envelope", "no certification or production-readiness claim"],
}

__all__ = [
    "WORKFORCE_EXECUTABLE_PRIMITIVES",
    "WORKFORCE_INTEGRATION_MANIFEST",
    "AdvanceWorkerInput",
    "AdvanceWorkerPrimitive",
    "AssessWorkforceInput",
    "AssessWorkforcePrimitive",
    "CompileWorkforceInput",
    "CompileWorkforcePrimitive",
    "PlanDispatchInput",
    "PlanDispatchPrimitive",
    "example_workforce_inputs",
]
