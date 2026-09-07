"""Executable primitives for the Service Delivery Engine Golden Operating Loop.

``blueprint.compile_service_delivery`` builds the plan from a profile or
custom blueprint, ``service_delivery.advance_case`` materializes one
replay-fenced case transition (intake, classification, tiered assignment
and escalation, work, evidence-backed resolution with remedy limits,
customer or independent verification, close, reopen), and
``service_delivery.assess_delivery`` derives SLA attainment, verified
resolutions, and reopen rate.  Read-only; Spring authorizes messages and
remedies.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult
from lightbulb.service_delivery_engine import (
    SERVICE_DELIVERY_GOLDEN_LOOP,
    SERVICE_DELIVERY_KIND,
    SERVICE_DELIVERY_MANIFEST,
    SERVICE_DELIVERY_PROFILES,
    STAGE_ORDER,
    CaseCommand,
    CaseState,
    CaseTransitionResult,
    ServiceDeliveryAssessment,
    ServiceDeliveryBlueprint,
    ServiceDeliveryLoopPlan,
    advance_case,
    assess_service_delivery,
    compile_service_delivery_blueprint,
    open_case,
    seal_case_command,
)


class CompileServiceDeliveryInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: ServiceDeliveryBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class AdvanceCaseInput(StrictModel):
    plan: ServiceDeliveryLoopPlan
    state: CaseState  # type: ignore[valid-type]
    command: CaseCommand  # type: ignore[valid-type]


class AssessDeliveryInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: ServiceDeliveryLoopPlan
    states: tuple[CaseState, ...] = Field(default_factory=tuple, max_length=2000)  # type: ignore[valid-type]
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
        plan = compile_service_delivery_blueprint("saas_support")
        scope = {**EXAMPLE_SCOPE, "entity_ref": "case-example", "currency": "CAD"}
        state = open_case(plan, scope, case_ref="case-example", customer_ref="customer-example", channel="email", subject="Report export fails", opened_at="2026-10-05T09:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = seal_case_command({"event": "classify", "transition_ref": "classify:case-example", "idempotency_key": "case-example:classify", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-05T09:10:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"severity": "sev3", "classification_ref": "classification-example"}})
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "profile": "saas_support", "overrides": {"channels": ["email", "chat"]}},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "states": [state.to_dict()], "assessed_at": "2026-10-06T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_service_delivery_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _ServiceDeliveryPrimitive(EnginePrimitive[Any, Any]):
    golden_loop = SERVICE_DELIVERY_GOLDEN_LOOP
    engine = SERVICE_DELIVERY_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(SERVICE_DELIVERY_PROFILES))
    hard_rules = {"severity_fixes_sla_clocks_at_classification": True, "assign_inside_tiers_escalate_one_at_a_time": True, "resolutions_carry_evidence_and_remedies_stay_inside_limits": True, "customer_or_independent_verification_before_close": True, "unreachable_closes_never_claim_verification": True, "reopen_inside_the_window": True, "no_message_sent_or_remedy_issued_here": True}
    authority_boundary = {"agent": "proposes classification, assignment, resolutions, remedies", "sdk": "fences the case, derives SLA clocks, seals the resolved signal", "spring": "authorizes messages and remedies; persists cases", "connectors": "helpdesk, email, messaging, payments", "mcp": "projects these primitives and the loop"}


class CompileServiceDeliveryPrimitive(_ServiceDeliveryPrimitive):
    primitive_ref = "blueprint.compile_service_delivery"
    version = "0.1.0"
    title = "Compile a service delivery blueprint into a loop plan"
    description = "Turn a profile (commerce_support, engagement_delivery, saas_support) or a custom blueprint (channels, severity SLA table, tiers, verification policy, remedy limits, targets) into the intake → classify → assign → work → resolve → verify → close → learn plan."
    input_model = CompileServiceDeliveryInput
    output_model = ServiceDeliveryLoopPlan
    risk_level = "low"
    operation_spec = read_spec("service_delivery_compile_blueprint", "sdk.blueprint.compile_service_delivery")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileServiceDeliveryInput) -> PrimitiveExecutionResult[ServiceDeliveryLoopPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_service_delivery_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.service_delivery_compiled", event_payload={"profile": bp.profile, "channels": list(bp.channels), "verifier": bp.verification.verifier, "max_remedy_value": str(bp.remedy.max_remedy_value)}, evidence_kind="service_delivery_loop_plan", evidence_summary="Loop plan; nothing executed.", summary=f"Compiled {bp.profile}: {len(bp.channels)} channel(s), {bp.verification.verifier.replace('_', ' ')} verification within {bp.verification.verification_window_hours}h, remedies up to {bp.currency} {bp.remedy.max_remedy_value}.")


class AdvanceCasePrimitive(_ServiceDeliveryPrimitive):
    primitive_ref = "service_delivery.advance_case"
    version = "0.1.0"
    title = "Advance a service case by one transition"
    description = "Materialize one replay-fenced case transition: classify (SLA clocks), assign inside tiers, escalate one tier at a time, start work, submit an evidence-backed resolution with remedy limits and approval above the threshold, verify by the customer or an independent verifier, close (unreachable only after the window), reopen inside the window."
    input_model = AdvanceCaseInput
    output_model = CaseTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("service_delivery_advance_case", "sdk.service_delivery.advance_case")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceCaseInput) -> PrimitiveExecutionResult[CaseTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the case scope and the command.")
        try:
            result = advance_case(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="service_delivery")


class AssessDeliveryPrimitive(_ServiceDeliveryPrimitive):
    primitive_ref = "service_delivery.assess_delivery"
    version = "0.1.0"
    title = "Assess service delivery (learn stage)"
    description = "Effect-dark delivery metrics across cases: first-response and resolution attainment, verified resolution share, unreachable closes, reopen rate, escalations, remedy total, with learnings against targets."
    input_model = AssessDeliveryInput
    output_model = ServiceDeliveryAssessment
    risk_level = "low"
    operation_spec = read_spec("service_delivery_assess", "sdk.service_delivery.assess_delivery")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessDeliveryInput) -> PrimitiveExecutionResult[ServiceDeliveryAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_service_delivery(inputs.plan, inputs.states, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATES_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="service_delivery.assessed", event_payload={"cases": assessment.cases, "closed": assessment.closed, "verified": assessment.verified, "reopened": assessment.reopened}, evidence_kind="service_delivery_assessment", evidence_summary="Delivery metrics; no effect.", summary=f"{assessment.closed} of {assessment.cases} case(s) closed, {assessment.verified} verified: {assessment.learnings[0]}")


SERVICE_DELIVERY_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileServiceDeliveryPrimitive(),
    AdvanceCasePrimitive(),
    AssessDeliveryPrimitive(),
)

SERVICE_DELIVERY_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "service_delivery_golden_loop",
    "golden_loop": SERVICE_DELIVERY_GOLDEN_LOOP,
    "engine": SERVICE_DELIVERY_MANIFEST,
    "modules": {"domain": "lightbulb.service_delivery_engine", "primitives": "lightbulb.service_delivery_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["service.intake_and_classify_case", "service.route_and_escalate_case", "service.submit_resolution_for_verification", "service.verify_case_resolution", "service.evaluate_case_resolution_controls", "service.propose_remedy_authorization", "communication.write_email", "approval.request_decision", "company_operating_system signals.case_resolved"],
    "required_connectors": SERVICE_DELIVERY_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in SERVICE_DELIVERY_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no message sent, remedy issued, or refund executed here", "no provider read here", "no certification or production-readiness claim"],
}

__all__ = [
    "SERVICE_DELIVERY_EXECUTABLE_PRIMITIVES",
    "SERVICE_DELIVERY_INTEGRATION_MANIFEST",
    "AdvanceCaseInput",
    "AdvanceCasePrimitive",
    "AssessDeliveryInput",
    "AssessDeliveryPrimitive",
    "CompileServiceDeliveryInput",
    "CompileServiceDeliveryPrimitive",
    "example_service_delivery_inputs",
]
