"""Executable primitives for the Pipeline Engine Golden Operating Loop.

``blueprint.compile_pipeline_engine`` builds the plan from a profile,
``pipeline.evaluate_icp_fit`` scores a prospect deterministically against the
ICP, ``pipeline.plan_sequence`` seals a touch schedule from a blueprint
template, ``pipeline.advance_prospect`` materializes one replay-fenced
prospect transition (template order, spacing, consent, suppression, approved
claims, rubric qualification, meeting window, CRM hand-off), and
``pipeline.forecast_pipeline`` derives funnel rates and weighted pipeline.
Read-only; Spring authorizes sends, calls, CRM writes, and bookings.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.pipeline_engine_loop import (
    PIPELINE_ENGINE_GOLDEN_LOOP,
    PIPELINE_ENGINE_KIND,
    PIPELINE_ENGINE_MANIFEST,
    PIPELINE_ENGINE_PROFILES,
    STAGE_ORDER,
    IcpFitEvaluation,
    PipelineEngineBlueprint,
    PipelineEngineLoopPlan,
    PipelineForecast,
    ProspectCommand,
    ProspectFacts,
    ProspectState,
    ProspectTransitionResult,
    SequencePlan,
    advance_prospect,
    compile_pipeline_engine_blueprint,
    evaluate_icp_fit,
    forecast_pipeline,
    open_prospect,
    plan_sequence,
    seal_prospect_command,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class CompilePipelineEngineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: PipelineEngineBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class EvaluateIcpFitInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: PipelineEngineLoopPlan
    facts: ProspectFacts


class PlanSequenceInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: PipelineEngineLoopPlan
    prospect_ref: OpaqueRef
    sequence_ref: OpaqueRef
    starts_at: str

    @field_validator("starts_at")
    @classmethod
    def _starts(cls, value: str) -> str:
        return timestamp(value, field_name="starts_at")


class AdvanceProspectInput(StrictModel):
    plan: PipelineEngineLoopPlan
    state: ProspectState  # type: ignore[valid-type]
    command: ProspectCommand  # type: ignore[valid-type]


class ForecastPipelineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: PipelineEngineLoopPlan
    prospects: tuple[ProspectState, ...] = Field(default_factory=tuple, max_length=5000)  # type: ignore[valid-type]
    forecast_at: str

    @field_validator("forecast_at")
    @classmethod
    def _at(cls, value: str) -> str:
        return timestamp(value, field_name="forecast_at")


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_pipeline_engine_blueprint("b2b_saas_outbound")
        facts = {"prospect_ref": "prospect-example", "account_ref": "account-example", "industry": "software", "employees": 150, "region": "AU", "title": "VP Finance", "signals": ["hiring ops roles"], "flags": [], "source_ref": "apollo:example"}
        fit = evaluate_icp_fit(plan, facts)
        scope = {**EXAMPLE_SCOPE, "entity_ref": "prospect-example", "currency": "USD"}
        state = open_prospect(plan, scope, facts=facts, fit=fit, opened_at="2026-10-01T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = seal_prospect_command({"event": "enrich", "transition_ref": "enrich:prospect-example", "idempotency_key": "prospect-example:enrich", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-01T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"enrichment_ref": "enrichment-example", "suppression_check_ref": "suppression-check-example"}})
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "profile": "b2b_saas_outbound", "overrides": {"meeting_window_days": 21}},
            "fit": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "facts": facts},
            "sequence": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "prospect_ref": "prospect-example", "sequence_ref": "seq-email-linkedin", "starts_at": "2026-10-02T09:00:00Z"},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "forecast": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "prospects": [state.to_dict()], "forecast_at": "2026-10-31T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_pipeline_engine_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _PipelinePrimitive(EnginePrimitive[Any, Any]):
    golden_loop = PIPELINE_ENGINE_GOLDEN_LOOP
    engine = PIPELINE_ENGINE_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(PIPELINE_ENGINE_PROFILES))
    hard_rules = {"below_threshold_prospects_never_open": True, "touches_follow_the_sequence_template_and_spacing": True, "voice_and_sms_need_consent": True, "suppression_checked_before_sequencing": True, "only_approved_claims_in_touches": True, "qualification_is_rubric_scored": True, "meetings_book_inside_the_window": True, "no_send_call_crm_write_or_booking_here": True}
    authority_boundary = {"agent": "sources, drafts touches, classifies replies, proposes rubric scores", "sdk": "scores ICP fit, fences sequences, consent, claims, qualification; forecasts", "spring": "authorizes sends, calls, CRM writes, bookings; persists prospects", "connectors": "execute CRM, email, LinkedIn, voice, SMS, calendar, and enrichment operations", "mcp": "projects these primitives and the loop"}


class CompilePipelineEnginePrimitive(_PipelinePrimitive):
    primitive_ref = "blueprint.compile_pipeline_engine"
    version = "0.1.0"
    title = "Compile a pipeline-engine blueprint into a loop plan"
    description = "Turn a ready-made profile (b2b_saas_outbound, agency_outbound, enterprise_abm, partner_channel) or a custom blueprint (ICP criteria, channel policy, sequence templates, approved claims, suppression lists, qualification rubric, meeting window, CRM, targets) into the ICP → source → sequence → compose → engage → observe → qualify/book → forecast plan."
    input_model = CompilePipelineEngineInput
    output_model = PipelineEngineLoopPlan
    risk_level = "low"
    operation_spec = read_spec("pipeline_engine_compile_blueprint", "sdk.blueprint.compile_pipeline_engine")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompilePipelineEngineInput) -> PrimitiveExecutionResult[PipelineEngineLoopPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_pipeline_engine_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.pipeline_engine_compiled", event_payload={"profile": bp.profile, "channels": len(bp.channels), "sequences": len(bp.sequences), "crm_system": bp.crm_system}, evidence_kind="pipeline_engine_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {bp.profile} pipeline engine ({len(bp.sequences)} sequence(s), {bp.crm_system}, threshold {bp.qualification_threshold}).")


class EvaluateIcpFitPrimitive(_PipelinePrimitive):
    primitive_ref = "pipeline.evaluate_icp_fit"
    version = "0.1.0"
    title = "Evaluate a prospect's ICP fit"
    description = "Deterministic fit score from industry, size band, region, buyer title, and required signals, with absolute disqualifiers; the sealed evaluation is what sourcing links."
    input_model = EvaluateIcpFitInput
    output_model = IcpFitEvaluation
    risk_level = "low"
    operation_spec = read_spec("pipeline_evaluate_icp_fit", "sdk.pipeline.evaluate_icp_fit")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "fit")

    def _execute(self, context: PrimitiveExecutionContext, inputs: EvaluateIcpFitInput) -> PrimitiveExecutionResult[IcpFitEvaluation]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            evaluation = evaluate_icp_fit(inputs.plan, inputs.facts)
        except ValueError as exc:
            return self.blocked(digest=digest, code="FACTS_INVALID", message=str(exc))
        return self.preview(output=evaluation, digest=digest, external_refs={"evaluation_digest": evaluation.evaluation_digest, "prospect_ref": evaluation.prospect_ref}, event_type="pipeline.icp_fit_evaluated", event_payload={"score": evaluation.score, "fits": evaluation.fits, "disqualified_by": evaluation.disqualified_by}, evidence_kind="icp_fit_evaluation", evidence_summary="Deterministic fit score; no effect.", summary=f"{evaluation.prospect_ref}: fit {evaluation.score} ({'fits' if evaluation.fits else 'does not fit'}).")


class PlanSequencePrimitive(_PipelinePrimitive):
    primitive_ref = "pipeline.plan_sequence"
    version = "0.1.0"
    title = "Plan an outreach sequence for a prospect"
    description = "Seal a touch schedule from a blueprint sequence template: step order, channel, intent, earliest send time, and whether each touch needs approval or consent."
    input_model = PlanSequenceInput
    output_model = SequencePlan
    risk_level = "low"
    operation_spec = read_spec("pipeline_plan_sequence", "sdk.pipeline.plan_sequence")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "sequence")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanSequenceInput) -> PrimitiveExecutionResult[SequencePlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            sequence = plan_sequence(inputs.plan, prospect_ref=inputs.prospect_ref, sequence_ref=inputs.sequence_ref, starts_at=inputs.starts_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="SEQUENCE_INVALID", message=str(exc))
        return self.preview(output=sequence, digest=digest, external_refs={"sequence_plan_digest": sequence.sequence_plan_digest}, event_type="pipeline.sequence_planned", event_payload={"sequence_ref": sequence.sequence_ref, "touches": len(sequence.touches), "starts_at": sequence.starts_at}, evidence_kind="outreach_sequence_plan", evidence_summary="Sealed touch schedule; nothing sent.", summary=f"{len(sequence.touches)} touch(es) from {sequence.starts_at} for {sequence.prospect_ref}.")


class AdvanceProspectPrimitive(_PipelinePrimitive):
    primitive_ref = "pipeline.advance_prospect"
    version = "0.1.0"
    title = "Advance a prospect by one transition"
    description = "Materialize one replay-fenced prospect transition: enrichment with a suppression check, sequencing, touches that follow the template order and spacing with approved claims, consent, and approval, engagement observation (bounce or unsubscribe suppresses), reply classification, rubric-scored qualification, meeting booking inside the window, and CRM hand-off."
    input_model = AdvanceProspectInput
    output_model = ProspectTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("pipeline_advance_prospect", "sdk.pipeline.advance_prospect")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceProspectInput) -> PrimitiveExecutionResult[ProspectTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the prospect scope and the command.")
        try:
            result = advance_prospect(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="pipeline")


class ForecastPipelinePrimitive(_PipelinePrimitive):
    primitive_ref = "pipeline.forecast_pipeline"
    version = "0.1.0"
    title = "Forecast the pipeline (learn stage)"
    description = "Effect-dark funnel metrics: prospects by status, reply and meeting rates, qualified count, average fit and rubric scores, handed-off value, stage-weighted pipeline value, learnings and recommendations against targets."
    input_model = ForecastPipelineInput
    output_model = PipelineForecast
    risk_level = "low"
    operation_spec = read_spec("pipeline_forecast", "sdk.pipeline.forecast_pipeline")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "forecast")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ForecastPipelineInput) -> PrimitiveExecutionResult[PipelineForecast]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            forecast = forecast_pipeline(inputs.plan, inputs.prospects, forecast_at=inputs.forecast_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="PROSPECTS_NOT_BOUND", message=str(exc))
        return self.preview(output=forecast, digest=digest, external_refs={"forecast_digest": forecast.forecast_digest}, event_type="pipeline.forecast", event_payload={"prospects": forecast.prospects, "qualified": forecast.qualified, "meetings": forecast.meetings, "weighted_pipeline_value": str(forecast.weighted_pipeline_value), "learnings": list(forecast.learnings)}, evidence_kind="pipeline_forecast", evidence_summary="Funnel metrics; no effect.", summary=f"{forecast.prospects} prospect(s), {forecast.qualified} qualified, weighted {forecast.weighted_pipeline_value} {forecast.currency}: {forecast.learnings[0]}")


PIPELINE_ENGINE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompilePipelineEnginePrimitive(),
    EvaluateIcpFitPrimitive(),
    PlanSequencePrimitive(),
    AdvanceProspectPrimitive(),
    ForecastPipelinePrimitive(),
)

PIPELINE_ENGINE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "pipeline_engine_golden_loop",
    "golden_loop": PIPELINE_ENGINE_GOLDEN_LOOP,
    "engine": PIPELINE_ENGINE_MANIFEST,
    "modules": {"domain": "lightbulb.pipeline_engine_loop", "primitives": "lightbulb.pipeline_engine_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["crm.qualify_lead and the governed CRM turn loop", "communication.write_email, plan_crm_conversation_turn, plan_governed_voice_call", "calendar.schedule_meeting", "commercial.* quote-to-agreement custody after hand-off", "growth.* funnel and customer value", "approval.request_decision", "compliance.evaluate_regulated_controls (consent)"],
    "required_connectors": PIPELINE_ENGINE_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in PIPELINE_ENGINE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no message sent, call placed, CRM record written, or meeting booked here", "no ICP, consent, suppression, or claim invented", "no certification or production-readiness claim"],
}

__all__ = [
    "PIPELINE_ENGINE_EXECUTABLE_PRIMITIVES",
    "PIPELINE_ENGINE_INTEGRATION_MANIFEST",
    "AdvanceProspectInput",
    "AdvanceProspectPrimitive",
    "CompilePipelineEngineInput",
    "CompilePipelineEnginePrimitive",
    "EvaluateIcpFitInput",
    "EvaluateIcpFitPrimitive",
    "ForecastPipelineInput",
    "ForecastPipelinePrimitive",
    "PlanSequenceInput",
    "PlanSequencePrimitive",
    "example_pipeline_engine_inputs",
]
