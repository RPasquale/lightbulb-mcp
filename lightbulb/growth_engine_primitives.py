"""Executable primitives for the Growth Engine Golden Operating Loop.

``blueprint.compile_growth_engine`` builds the plan from a profile,
``growth_engine.plan_campaign_portfolio`` seals budget envelopes inside
channel caps, ``growth_engine.advance_campaign`` materializes one
replay-fenced campaign transition (approved claims only, spend fenced to the
envelope, attribution under the blueprint model), ``growth_engine.propose_reallocation``
proposes bounded, approval-gated budget shifts, and ``growth_engine.assess_engine``
derives blended ROAS, CPA, and LTV to CAC.  Read-only; Spring authorizes
publication, messaging, spend, and provider reads.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.growth_engine_loop import (
    GROWTH_ENGINE_GOLDEN_LOOP,
    GROWTH_ENGINE_KIND,
    GROWTH_ENGINE_MANIFEST,
    GROWTH_ENGINE_PROFILES,
    STAGE_ORDER,
    CampaignCommand,
    CampaignPortfolio,
    CampaignState,
    CampaignTransitionResult,
    GrowthEngineAssessment,
    GrowthEngineBlueprint,
    GrowthEngineLoopPlan,
    ReallocationProposal,
    advance_campaign,
    assess_growth_engine,
    compile_growth_engine_blueprint,
    open_campaign,
    plan_campaign_portfolio,
    propose_reallocation,
    seal_campaign_command,
)
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult


class CompileGrowthEngineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: GrowthEngineBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class PortfolioAllocation(StrictModel):
    envelope_ref: OpaqueRef | None = None
    channel: str = Field(min_length=1, max_length=40)
    objective: str = Field(default="acquire", min_length=1, max_length=20)
    audience_ref: OpaqueRef
    budget: str = Field(min_length=1, max_length=40)


class PlanCampaignPortfolioInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: GrowthEngineLoopPlan
    period_start: str
    period_end: str
    total_budget: str = Field(min_length=1, max_length=40)
    allocations: tuple[PortfolioAllocation, ...] = Field(min_length=1, max_length=64)

    @field_validator("period_start", "period_end")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return timestamp(value, field_name=str(info.field_name))


class AdvanceCampaignInput(StrictModel):
    plan: GrowthEngineLoopPlan
    state: CampaignState  # type: ignore[valid-type]
    command: CampaignCommand  # type: ignore[valid-type]


class ProposeReallocationInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: GrowthEngineLoopPlan
    portfolio: CampaignPortfolio
    campaigns: tuple[CampaignState, ...] = Field(default_factory=tuple, max_length=500)  # type: ignore[valid-type]
    proposed_at: str

    @field_validator("proposed_at")
    @classmethod
    def _proposed(cls, value: str) -> str:
        return timestamp(value, field_name="proposed_at")


class AssessGrowthEngineInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: GrowthEngineLoopPlan
    campaigns: tuple[CampaignState, ...] = Field(default_factory=tuple, max_length=500)  # type: ignore[valid-type]
    customer_lifetime_value: str | None = Field(default=None, max_length=40)
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
        plan = compile_growth_engine_blueprint("dtc_shopify")
        portfolio = plan_campaign_portfolio(plan, period_start="2026-10-01T00:00:00Z", period_end="2026-10-31T00:00:00Z", total_budget="5000", allocations=[{"channel": "paid_social_meta", "objective": "acquire", "audience_ref": "aud-prospecting", "budget": "1500"}])
        scope = {**EXAMPLE_SCOPE, "entity_ref": "campaign-example", "currency": "USD"}
        state = open_campaign(plan, scope, portfolio=portfolio, envelope_ref=portfolio.envelopes[0].envelope_ref, opened_at="2026-10-01T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        command = seal_campaign_command({"event": "compose", "transition_ref": "compose:campaign-example", "idempotency_key": "campaign-example:compose", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-01T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"creative_ref": "creative-example", "headline": "Cozy knits for autumn", "body": "Explore the autumn collection", "claim_refs": []}})
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "profile": "dtc_shopify", "overrides": {"attribution_window_days": 14}},
            "portfolio": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "period_start": "2026-10-01T00:00:00Z", "period_end": "2026-10-31T00:00:00Z", "total_budget": "5000", "allocations": [{"channel": "paid_social_meta", "objective": "acquire", "audience_ref": "aud-prospecting", "budget": "1500"}, {"channel": "email_lifecycle", "objective": "retain", "audience_ref": "aud-customers", "budget": "200"}]},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "reallocate": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "portfolio": portfolio.to_dict(), "campaigns": [state.to_dict()], "proposed_at": "2026-10-22T00:00:00Z"},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "campaigns": [state.to_dict()], "customer_lifetime_value": "120", "assessed_at": "2026-10-22T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_growth_engine_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _GrowthPrimitive(EnginePrimitive[Any, Any]):
    golden_loop = GROWTH_ENGINE_GOLDEN_LOOP
    engine = GROWTH_ENGINE_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(GROWTH_ENGINE_PROFILES))
    hard_rules = {"only_approved_claims_reach_creatives": True, "brand_safety_terms_refused": True, "spend_never_exceeds_envelope": True, "above_threshold_spend_needs_approval": True, "messaging_needs_consent": True, "reallocation_is_a_proposal_for_human_approval": True, "no_publication_messaging_spend_or_provider_read_here": True}
    authority_boundary = {"agent": "proposes portfolios, creatives, and shifts", "sdk": "fences envelopes, claims, consent, attribution; measures the engine", "spring": "authorizes spend, publication, messaging; persists campaigns", "connectors": "execute ad, social, lifecycle, and analytics operations", "mcp": "projects these primitives and the loop"}


class CompileGrowthEnginePrimitive(_GrowthPrimitive):
    primitive_ref = "blueprint.compile_growth_engine"
    version = "0.1.0"
    title = "Compile a growth-engine blueprint into a loop plan"
    description = "Turn a ready-made profile (dtc_shopify, b2b_saas, local_services, marketplace_demand) or a custom blueprint (channel caps and approval thresholds, approved claims, brand-safety terms, audiences, measurement sources, attribution policy, reallocation limits, targets) into the audit → portfolio → compose → approve/launch → observe → attribute → reallocate → learn plan."
    input_model = CompileGrowthEngineInput
    output_model = GrowthEngineLoopPlan
    risk_level = "low"
    operation_spec = read_spec("growth_engine_compile_blueprint", "sdk.blueprint.compile_growth_engine")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileGrowthEngineInput) -> PrimitiveExecutionResult[GrowthEngineLoopPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_growth_engine_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.growth_engine_compiled", event_payload={"profile": bp.profile, "channels": len(bp.channels), "attribution_model": bp.attribution_model, "approved_claims": len(bp.approved_claims)}, evidence_kind="growth_engine_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {bp.profile} growth engine ({len(bp.channels)} channels, {bp.attribution_model} attribution over {bp.attribution_window_days}d).")


class PlanCampaignPortfolioPrimitive(_GrowthPrimitive):
    primitive_ref = "growth_engine.plan_campaign_portfolio"
    version = "0.1.0"
    title = "Plan a campaign portfolio inside channel caps"
    description = "Seal budget envelopes per channel, objective, and audience for a period; every envelope respects the pro-rated channel cap and carries the blueprint's approval flag and targets."
    input_model = PlanCampaignPortfolioInput
    output_model = CampaignPortfolio
    risk_level = "low"
    operation_spec = read_spec("growth_engine_plan_portfolio", "sdk.growth_engine.plan_campaign_portfolio")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "portfolio")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanCampaignPortfolioInput) -> PrimitiveExecutionResult[CampaignPortfolio]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            portfolio = plan_campaign_portfolio(inputs.plan, period_start=inputs.period_start, period_end=inputs.period_end, total_budget=inputs.total_budget, allocations=[item.to_dict() for item in inputs.allocations])
        except ValueError as exc:
            return self.blocked(digest=digest, code="PORTFOLIO_INVALID", message=str(exc))
        return self.preview(output=portfolio, digest=digest, external_refs={"portfolio_digest": portfolio.portfolio_digest}, event_type="growth_engine.portfolio_planned", event_payload={"envelopes": len(portfolio.envelopes), "total_budget": str(portfolio.total_budget), "unallocated": str(portfolio.unallocated), "approval_required": sum(1 for item in portfolio.envelopes if item.approval_required)}, evidence_kind="campaign_portfolio", evidence_summary="Sealed budget envelopes; no spend.", summary=f"{len(portfolio.envelopes)} envelope(s) over {portfolio.total_budget} {portfolio.currency} ({portfolio.unallocated} unallocated).")


class AdvanceCampaignPrimitive(_GrowthPrimitive):
    primitive_ref = "growth_engine.advance_campaign"
    version = "0.1.0"
    title = "Advance a campaign by one transition"
    description = "Materialize one replay-fenced campaign transition: creative candidates from approved claims only and free of brand-safety terms, consent for messaging, approval for above-threshold spend, launch, observations from blueprint measurement sources with spend fenced to the envelope, attribution under the blueprint model, pause, resume, completion, and halt."
    input_model = AdvanceCampaignInput
    output_model = CampaignTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("growth_engine_advance_campaign", "sdk.growth_engine.advance_campaign")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceCampaignInput) -> PrimitiveExecutionResult[CampaignTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the campaign scope and the command.")
        try:
            result = advance_campaign(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="growth_engine")


class ProposeReallocationPrimitive(_GrowthPrimitive):
    primitive_ref = "growth_engine.propose_reallocation"
    version = "0.1.0"
    title = "Propose a bounded budget reallocation"
    description = "From attributed campaign performance, propose budget shifts from channels below target to channels above target, capped by the blueprint's per-cycle shift limit, holding channels without enough conversions for evidence. Always a candidate for human approval; never executes."
    input_model = ProposeReallocationInput
    output_model = ReallocationProposal
    risk_level = "medium"
    operation_spec = read_spec("growth_engine_propose_reallocation", "sdk.growth_engine.propose_reallocation")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "reallocate")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ProposeReallocationInput) -> PrimitiveExecutionResult[ReallocationProposal]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            proposal = propose_reallocation(inputs.plan, inputs.portfolio, inputs.campaigns, proposed_at=inputs.proposed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="CAMPAIGNS_NOT_BOUND", message=str(exc))
        return self.preview(output=proposal, digest=digest, external_refs={"proposal_digest": proposal.proposal_digest}, event_type="growth_engine.reallocation_proposed", event_payload={"shifts": len(proposal.shifts), "total_shifted": str(proposal.total_shifted), "max_shift_allowed": str(proposal.max_shift_allowed), "requires_human_approval": True}, evidence_kind="budget_reallocation_proposal", evidence_summary="Bounded reallocation proposal; executes nothing.", summary=f"{len(proposal.shifts)} shift(s) totalling {proposal.total_shifted}: {proposal.rationale[0]}")


class AssessGrowthEnginePrimitive(_GrowthPrimitive):
    primitive_ref = "growth_engine.assess_engine"
    version = "0.1.0"
    title = "Assess the growth engine (learn stage)"
    description = "Effect-dark engine metrics: spend, attributed revenue, conversions, blended ROAS and CPA, LTV to CAC when a lifetime value is supplied, per-channel verdicts against targets, halted campaigns, learnings and recommendations."
    input_model = AssessGrowthEngineInput
    output_model = GrowthEngineAssessment
    risk_level = "low"
    operation_spec = read_spec("growth_engine_assess", "sdk.growth_engine.assess_engine")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessGrowthEngineInput) -> PrimitiveExecutionResult[GrowthEngineAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_growth_engine(inputs.plan, inputs.campaigns, assessed_at=inputs.assessed_at, customer_lifetime_value=inputs.customer_lifetime_value)
        except ValueError as exc:
            return self.blocked(digest=digest, code="CAMPAIGNS_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="growth_engine.assessed", event_payload={"campaigns": assessment.campaigns, "spend": str(assessment.spend), "attributed_revenue": str(assessment.attributed_revenue), "blended_roas": None if assessment.blended_roas is None else str(assessment.blended_roas), "learnings": list(assessment.learnings)}, evidence_kind="growth_engine_assessment", evidence_summary="Engine metrics; no effect.", summary=f"{assessment.campaigns} campaign(s), spend {assessment.spend}, revenue {assessment.attributed_revenue}: {assessment.learnings[0]}")


GROWTH_ENGINE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileGrowthEnginePrimitive(),
    PlanCampaignPortfolioPrimitive(),
    AdvanceCampaignPrimitive(),
    ProposeReallocationPrimitive(),
    AssessGrowthEnginePrimitive(),
)

GROWTH_ENGINE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "growth_engine_golden_loop",
    "golden_loop": GROWTH_ENGINE_GOLDEN_LOOP,
    "engine": GROWTH_ENGINE_MANIFEST,
    "modules": {"domain": "lightbulb.growth_engine_loop", "primitives": "lightbulb.growth_engine_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["commerce.* product commercial identity, personalized variants, channel publication", "demand_gen.* and content.* planning", "growth.* funnel, unit economics, customer value, diagnosis", "communication.write_email", "approval.request_decision", "compliance.evaluate_regulated_controls (messaging consent)"],
    "required_connectors": GROWTH_ENGINE_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in GROWTH_ENGINE_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no ad or post published, no message sent, no money spent, no provider read here", "no claim invented; approved claims, brand-safety terms, and consent are explicit inputs", "no certification or production-readiness claim"],
}

__all__ = [
    "GROWTH_ENGINE_EXECUTABLE_PRIMITIVES",
    "GROWTH_ENGINE_INTEGRATION_MANIFEST",
    "AdvanceCampaignInput",
    "AdvanceCampaignPrimitive",
    "AssessGrowthEngineInput",
    "AssessGrowthEnginePrimitive",
    "CompileGrowthEngineInput",
    "CompileGrowthEnginePrimitive",
    "PlanCampaignPortfolioInput",
    "PlanCampaignPortfolioPrimitive",
    "PortfolioAllocation",
    "ProposeReallocationInput",
    "ProposeReallocationPrimitive",
    "example_growth_engine_inputs",
]
