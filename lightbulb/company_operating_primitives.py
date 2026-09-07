"""Executable primitives for the Company Operating System Golden Operating Loop.

``blueprint.compile_company_operating_system`` compiles an archetype or custom
blueprint into an operating plan; ``company.plan_formation`` previews the
formation request the user will send through their own Lightbulb account
(Australia and Canada only); ``company.advance_period`` materializes one
replay-fenced operating-period transition (dispatch inside envelopes,
evidence, reconciliation against verified books, capped and approved
replans); ``company.route_signal`` routes one typed cross-loop signal to its
enabled consumers; ``company.assess_health`` derives the health assessment.
Read-only; Spring authorizes formation, dispatch, spend, and reallocation.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_operating_system import (
    COMPANY_OS_ARCHETYPES,
    COMPANY_OS_GOLDEN_LOOP,
    COMPANY_OS_KIND,
    COMPANY_OS_MANIFEST,
    STAGE_ORDER,
    CompanyHealthAssessment,
    CompanyOperatingBlueprint,
    CompanyOperatingPlan,
    CompanySignal,
    FormationPlan,
    PeriodCommand,
    PeriodState,
    PeriodTransitionResult,
    SignalRouting,
    advance_period,
    assess_company_health,
    compile_company_operating_blueprint,
    open_period,
    route_signal,
    seal_period_command,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class CompileCompanyOperatingInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    archetype: str = Field(min_length=1, max_length=40)
    blueprint: CompanyOperatingBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class PlanFormationInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: CompanyOperatingPlan


class AdvancePeriodInput(StrictModel):
    plan: CompanyOperatingPlan
    state: PeriodState  # type: ignore[valid-type]
    command: PeriodCommand  # type: ignore[valid-type]


class RouteSignalInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: CompanyOperatingPlan
    signal: CompanySignal


class AssessHealthInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: CompanyOperatingPlan
    periods: tuple[PeriodState, ...] = Field(default_factory=tuple, max_length=200)  # type: ignore[valid-type]
    assessed_at: str
    cash_on_hand: str | None = None
    monthly_burn: str | None = None

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
        plan = compile_company_operating_blueprint("b2b_saas")
        scope = {**EXAMPLE_SCOPE, "entity_ref": "period-example", "currency": "CAD"}
        state = open_period(plan, scope, period_start="2026-10-05T00:00:00Z", opened_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = seal_period_command({"event": "dispatch", "transition_ref": "dispatch:period-example:growth", "idempotency_key": "period-example:growth:dispatch", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-05T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"engine": "growth_engine", "dispatch_refs": ["dispatch-example-1"]}})
        signal = {"name": "signals.churn_risk", "producer": "saas_operating_engine", "emitted_at": "2026-10-06T00:00:00Z", "payload": {"account_ref": "account-example-1", "mrr_at_risk": "199.00", "inactive_days": 30}}
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "archetype": "b2b_saas", "overrides": {"name": "Example Software Inc."}},
            "formation": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict()},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "route": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "signal": signal},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "periods": [state.to_dict()], "assessed_at": "2026-10-06T00:00:00Z", "cash_on_hand": "250000", "monthly_burn": "30000"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_company_operating_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _CompanyPrimitive(EnginePrimitive[Any, Any]):
    golden_loop = COMPANY_OS_GOLDEN_LOOP
    engine = COMPANY_OS_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(COMPANY_OS_ARCHETYPES))
    hard_rules = {"formation_through_the_users_own_account_in_au_or_ca_only": True, "tenant_from_credential_never_from_caller": True, "engines_dispatch_inside_envelope_and_cadence": True, "reconciliation_needs_verified_books": True, "replans_budget_neutral_capped_and_approved_above_threshold": True, "signals_typed_and_routed_to_enabled_consumers_only": True, "no_formation_dispatch_spend_or_reallocation_executed_here": True}
    authority_boundary = {"agent": "proposes blueprints, dispatches, replans, and signal handling", "sdk": "compiles plans, fences periods, routes signals, assesses health", "spring": "authorizes formation, dispatch, spend, and reallocation; persists periods", "connectors": "execute finance, CRM, commerce, and messaging operations under the engines", "mcp": "projects these primitives and the loop"}


class CompileCompanyOperatingPrimitive(_CompanyPrimitive):
    primitive_ref = "blueprint.compile_company_operating_system"
    version = "0.1.0"
    title = "Compile a company blueprint into an operating plan"
    description = "Turn an archetype (dtc_commerce, b2b_saas, services_firm, marketplace) or a custom blueprint (country, budget, engines and shares, signals, replan limits, targets) into the form → bind → plan → dispatch → evidence → reconcile → replan → learn plan with per-engine envelopes, signal routes, and the formation plan."
    input_model = CompileCompanyOperatingInput
    output_model = CompanyOperatingPlan
    risk_level = "low"
    operation_spec = read_spec("company_os_compile_blueprint", "sdk.blueprint.compile_company_operating_system")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileCompanyOperatingInput) -> PrimitiveExecutionResult[CompanyOperatingPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_company_operating_blueprint(inputs.blueprint.to_dict() if inputs.archetype == "custom" and inputs.blueprint is not None else inputs.archetype, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.company_operating_system_compiled", event_payload={"archetype": bp.archetype, "country": bp.country, "engines": list(bp.engine_kinds), "signals": len(bp.signals), "period_days": bp.period_days}, evidence_kind="company_operating_plan", evidence_summary="Operating plan with envelopes, signal routes, and formation plan; nothing executed.", summary=f"Compiled {bp.archetype} company in {bp.country_name}: {len(bp.engines)} engine(s), {bp.currency} {bp.operating_budget_per_period} per {bp.period_days}-day period.")


class PlanFormationPrimitive(_CompanyPrimitive):
    primitive_ref = "company.plan_formation"
    version = "0.1.0"
    title = "Plan company formation through the user's account"
    description = "Preview the guided formation request (name, country, industry, purpose) the user sends through LightbulbClient.create_company under their own credential. Australia and Canada only; the tenant comes from the credential; nothing is created here."
    input_model = PlanFormationInput
    output_model = FormationPlan
    risk_level = "low"
    operation_spec = read_spec("company_os_plan_formation", "sdk.company.plan_formation")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "formation")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanFormationInput) -> PrimitiveExecutionResult[FormationPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        formation = inputs.plan.formation
        return self.preview(output=formation, digest=digest, external_refs={"plan_digest": inputs.plan.plan_digest}, event_type="company.formation_planned", event_payload={"country": formation.country, "expected_region": formation.expected_region, "client_method": formation.client_method}, evidence_kind="company_formation_plan", evidence_summary="Formation request preview; no company created.", summary=f"Form {formation.request_preview['name']} in {formation.country_name} via {formation.client_method} (region {formation.expected_region}); requires the user's tenant-admin credential.")


class AdvancePeriodPrimitive(_CompanyPrimitive):
    primitive_ref = "company.advance_period"
    version = "0.1.0"
    title = "Advance an operating period by one transition"
    description = "Materialize one replay-fenced operating-period transition: dispatch a bound engine inside its envelope cadence, record evidence and signals under the envelope budget, reconcile against verified books, replan with budget-neutral capped shifts (approval above the threshold), close, or halt."
    input_model = AdvancePeriodInput
    output_model = PeriodTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("company_os_advance_period", "sdk.company.advance_period")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvancePeriodInput) -> PrimitiveExecutionResult[PeriodTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the period scope and the command.")
        try:
            result = advance_period(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="company")


class RouteSignalPrimitive(_CompanyPrimitive):
    primitive_ref = "company.route_signal"
    version = "0.1.0"
    title = "Route a typed cross-loop signal"
    description = "Validate one engine signal (name, producer, required payload keys) against the operating plan and route it to the enabled consumers with the advisory action; executes nothing."
    input_model = RouteSignalInput
    output_model = SignalRouting
    risk_level = "low"
    operation_spec = read_spec("company_os_route_signal", "sdk.company.route_signal")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "route")

    def _execute(self, context: PrimitiveExecutionContext, inputs: RouteSignalInput) -> PrimitiveExecutionResult[SignalRouting]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            routing = route_signal(inputs.plan, inputs.signal)
        except ValueError as exc:
            return self.blocked(digest=digest, code="SIGNAL_INVALID", message=str(exc))
        return self.preview(output=routing, digest=digest, external_refs={"routing_digest": routing.routing_digest}, event_type="company.signal_routed", event_payload={"signal": routing.signal.name, "producer": routing.signal.producer, "consumers": list(routing.consumers)}, evidence_kind="company_signal_routing", evidence_summary="Signal routing; no consumer invoked.", summary=f"{routing.signal.name} from {routing.signal.producer} → {', '.join(routing.consumers)}.")


class AssessHealthPrimitive(_CompanyPrimitive):
    primitive_ref = "company.assess_health"
    version = "0.1.0"
    title = "Assess company health (learn stage)"
    description = "Effect-dark company health from operating periods: revenue attainment, budget utilisation, per-engine return on spend, signal counts, cash runway against the floor, learnings and recommendations."
    input_model = AssessHealthInput
    output_model = CompanyHealthAssessment
    risk_level = "low"
    operation_spec = read_spec("company_os_assess_health", "sdk.company.assess_health")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessHealthInput) -> PrimitiveExecutionResult[CompanyHealthAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_company_health(inputs.plan, inputs.periods, assessed_at=inputs.assessed_at, cash_on_hand=inputs.cash_on_hand, monthly_burn=inputs.monthly_burn)
        except ValueError as exc:
            return self.blocked(digest=digest, code="INPUTS_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="company.health_assessed", event_payload={"periods": assessment.periods, "total_spend": str(assessment.total_spend), "total_revenue": str(assessment.total_revenue), "learnings": list(assessment.learnings)}, evidence_kind="company_health_assessment", evidence_summary="Health metrics; no effect.", summary=f"{assessment.periods} period(s): revenue {assessment.total_revenue} against {assessment.revenue_target}; {assessment.learnings[0]}")


COMPANY_OS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileCompanyOperatingPrimitive(),
    PlanFormationPrimitive(),
    AdvancePeriodPrimitive(),
    RouteSignalPrimitive(),
    AssessHealthPrimitive(),
)

COMPANY_OS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "company_operating_system_golden_loop",
    "golden_loop": COMPANY_OS_GOLDEN_LOOP,
    "engine": COMPANY_OS_MANIFEST,
    "modules": {"domain": "lightbulb.company_operating_system", "primitives": "lightbulb.company_operating_primitives", "formation": "lightbulb.company_formation", "core": "lightbulb.company_engine_core"},
    "reuses": ["growth_engine golden loop", "pipeline_engine golden loop", "saas_operating_engine golden loop", "finance.* period close", "service.* case resolution", "approval.request_decision", "compliance.evaluate_regulated_controls", "LightbulbClient.create_company / AsyncLightbulbClient.create_company"],
    "required_connectors": COMPANY_OS_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in COMPANY_OS_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no company formed, engine dispatched, budget moved, or message sent here", "no jurisdiction outside Australia and Canada", "no certification or production-readiness claim"],
}

__all__ = [
    "COMPANY_OS_EXECUTABLE_PRIMITIVES",
    "COMPANY_OS_INTEGRATION_MANIFEST",
    "AdvancePeriodInput",
    "AdvancePeriodPrimitive",
    "AssessHealthInput",
    "AssessHealthPrimitive",
    "CompileCompanyOperatingInput",
    "CompileCompanyOperatingPrimitive",
    "PlanFormationInput",
    "PlanFormationPrimitive",
    "RouteSignalInput",
    "RouteSignalPrimitive",
    "example_company_operating_inputs",
]
