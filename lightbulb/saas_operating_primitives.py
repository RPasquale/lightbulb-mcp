"""Executable primitives for the SaaS Operating Engine Golden Operating Loop.

``blueprint.compile_saas_operating`` builds the plan from a profile,
``saas_ops.observe_usage`` seals a usage snapshot (activation, cohorts,
expansion candidates, churn risks), ``saas_ops.triage_support`` scores a
support case against the SLA table, ``saas_ops.rank_roadmap`` ranks
candidates by weighted RICE with an evidence gate, ``saas_ops.advance_release``
materializes one replay-fenced release transition (evidence, approval,
canary cap, thresholds, rollback window), and ``saas_ops.assess_operating``
derives the operating assessment.  Read-only; Spring authorizes deployments,
rollbacks, plan changes, and customer contact.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import OpaqueRef, StrictModel, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult
from lightbulb.saas_operating_loop import (
    SAAS_OPERATING_GOLDEN_LOOP,
    SAAS_OPERATING_KIND,
    SAAS_OPERATING_MANIFEST,
    SAAS_OPERATING_PROFILES,
    STAGE_ORDER,
    AccountUsage,
    ReleaseCommand,
    ReleaseState,
    ReleaseTransitionResult,
    RoadmapCandidate,
    RoadmapRanking,
    SaasOperatingAssessment,
    SaasOperatingBlueprint,
    SaasOperatingLoopPlan,
    SupportCaseFacts,
    SupportTriage,
    UsageSnapshot,
    advance_release,
    assess_saas_operating,
    compile_saas_operating_blueprint,
    observe_usage,
    open_release,
    rank_roadmap,
    seal_release_command,
    triage_support_case,
)


class CompileSaasOperatingInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: SaasOperatingBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class ObserveUsageInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: SaasOperatingLoopPlan
    accounts: tuple[AccountUsage, ...] = Field(default_factory=tuple, max_length=20000)
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")


class TriageSupportInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: SaasOperatingLoopPlan
    case: SupportCaseFacts


class RankRoadmapInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: SaasOperatingLoopPlan
    candidates: tuple[RoadmapCandidate, ...] = Field(min_length=1, max_length=500)
    ranked_at: str

    @field_validator("ranked_at")
    @classmethod
    def _ranked(cls, value: str) -> str:
        return timestamp(value, field_name="ranked_at")


class AdvanceReleaseInput(StrictModel):
    plan: SaasOperatingLoopPlan
    state: ReleaseState  # type: ignore[valid-type]
    command: ReleaseCommand  # type: ignore[valid-type]


class AssessSaasOperatingInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: SaasOperatingLoopPlan
    snapshot: UsageSnapshot
    releases: tuple[ReleaseState, ...] = Field(default_factory=tuple, max_length=500)  # type: ignore[valid-type]
    triages: tuple[SupportTriage, ...] = Field(default_factory=tuple, max_length=5000)
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
        plan = compile_saas_operating_blueprint("plg_self_serve")
        accounts = [{"account_ref": "account-example-1", "plan_ref": "team", "signed_up_at": "2026-08-01T00:00:00Z", "last_active_at": "2026-09-29T00:00:00Z", "events": ["workspace_created", "first_report_run", "teammate_invited"], "seats_used": 9, "seats_last_period": 6, "mrr": "49"}, {"account_ref": "account-example-2", "plan_ref": "free", "signed_up_at": "2026-09-20T00:00:00Z", "last_active_at": "2026-09-21T00:00:00Z", "events": ["workspace_created"], "seats_used": 1, "seats_last_period": 1, "mrr": "0"}]
        snapshot = observe_usage(plan, accounts, observed_at="2026-10-01T00:00:00Z")
        case = {"case_ref": "case-example", "account_ref": "account-example-1", "plan_ref": "team", "opened_at": "2026-10-01T09:00:00Z", "reported_impact": "blocked_workflow", "accounts_affected": 1, "first_response_at": "2026-10-01T10:00:00Z"}
        triage = triage_support_case(plan, case)
        scope = {**EXAMPLE_SCOPE, "entity_ref": "release-example", "currency": "USD"}
        state = open_release(plan, scope, change_refs=["pr-example"], summary="Faster report rendering", opened_at="2026-10-01T00:00:00Z", actor_ref=EXAMPLE_ACTOR, roadmap_candidate_ref="candidate-example")
        command = seal_release_command({"event": "attach_evidence", "transition_ref": "evidence:release-example", "idempotency_key": "release-example:evidence-tests", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-10-01T01:00:00Z", "actor_ref": EXAMPLE_ACTOR, "receipt": {"evidence_kind": "automated_tests", "evidence_ref": "ci-run-example"}})
        self._built = {
            "compile": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "profile": "plg_self_serve", "overrides": {"cohort_period_days": 14}},
            "observe": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "accounts": accounts, "observed_at": "2026-10-01T00:00:00Z"},
            "triage": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "case": case},
            "rank": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "candidates": [{"candidate_ref": "candidate-example", "title": "Faster report rendering", "reach_accounts": 400, "impact": 4, "confidence_percent": 80, "effort_weeks": "2", "evidence_refs": ["interview-1", "usage-1"]}], "ranked_at": "2026-10-01T00:00:00Z"},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": plan.to_dict(), "snapshot": snapshot.to_dict(), "releases": [state.to_dict()], "triages": [triage.to_dict()], "assessed_at": "2026-10-02T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_saas_operating_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _SaasOpsPrimitive(EnginePrimitive[Any, Any]):
    golden_loop = SAAS_OPERATING_GOLDEN_LOOP
    engine = SAAS_OPERATING_KIND
    loop_stages = STAGE_ORDER
    profiles = tuple(sorted(SAAS_OPERATING_PROFILES))
    hard_rules = {"activation_and_retention_derived_from_observed_usage": True, "roadmap_items_need_evidence_to_be_admitted": True, "releases_need_every_required_evidence_kind": True, "canary_capped_and_verified_against_thresholds": True, "rollback_only_inside_the_window": True, "expansion_outreach_needs_customer_consent": True, "no_deployment_rollback_plan_change_or_customer_contact_here": True}
    authority_boundary = {"agent": "proposes releases, rankings, triage, expansion plays", "sdk": "measures usage, scores triage, gates releases, fences rollbacks", "spring": "authorizes deployments, rollbacks, plan changes, outreach; persists releases", "connectors": "execute analytics, billing, support, source control, and deployment operations", "mcp": "projects these primitives and the loop"}


class CompileSaasOperatingPrimitive(_SaasOpsPrimitive):
    primitive_ref = "blueprint.compile_saas_operating"
    version = "0.1.0"
    title = "Compile a SaaS operating blueprint into a loop plan"
    description = "Turn a ready-made profile (plg_self_serve, sales_assisted, enterprise_platform, usage_based) or a custom blueprint (activation definition, plans, release policy, support SLAs, roadmap weights, expansion signals, cohort policy, targets) into the observe → cohorts → triage → roadmap → ship → verify → expand → learn plan."
    input_model = CompileSaasOperatingInput
    output_model = SaasOperatingLoopPlan
    risk_level = "low"
    operation_spec = read_spec("saas_ops_compile_blueprint", "sdk.blueprint.compile_saas_operating")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileSaasOperatingInput) -> PrimitiveExecutionResult[SaasOperatingLoopPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_saas_operating_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self.blocked(digest=digest, code="BLUEPRINT_INVALID", message=str(exc))
        bp = plan.blueprint
        return self.preview(output=plan, digest=digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.saas_operating_compiled", event_payload={"profile": bp.profile, "plans": len(bp.plans), "required_evidence": list(bp.release_policy.required_evidence), "cohort_period_days": bp.cohort_period_days}, evidence_kind="saas_operating_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {bp.profile} operating engine ({len(bp.plans)} plan(s), {bp.cohort_period_days}d cohorts, canary {bp.release_policy.canary_percent}%).")


class ObserveUsagePrimitive(_SaasOpsPrimitive):
    primitive_ref = "saas_ops.observe_usage"
    version = "0.1.0"
    title = "Observe usage into a sealed snapshot"
    description = "From per-account usage facts derive activation against the blueprint definition, cohort retention over the horizon, expansion candidates from seat and usage signals, churn risks from inactivity, and MRR; sealed and effect-free."
    input_model = ObserveUsageInput
    output_model = UsageSnapshot
    risk_level = "low"
    operation_spec = read_spec("saas_ops_observe_usage", "sdk.saas_ops.observe_usage")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "observe")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ObserveUsageInput) -> PrimitiveExecutionResult[UsageSnapshot]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            snapshot = observe_usage(inputs.plan, inputs.accounts, observed_at=inputs.observed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="USAGE_INVALID", message=str(exc))
        return self.preview(output=snapshot, digest=digest, external_refs={"snapshot_digest": snapshot.snapshot_digest}, event_type="saas_ops.usage_observed", event_payload={"accounts": snapshot.accounts, "activated": snapshot.activated, "expansion_candidates": len(snapshot.expansion_candidates), "churn_risks": len(snapshot.churn_risks), "mrr": str(snapshot.mrr)}, evidence_kind="saas_usage_snapshot", evidence_summary="Usage snapshot; no provider read.", summary=f"{snapshot.accounts} account(s), activation {snapshot.activation_rate_percent}%, {len(snapshot.expansion_candidates)} expansion candidate(s), {len(snapshot.churn_risks)} churn risk(s).")


class TriageSupportPrimitive(_SaasOpsPrimitive):
    primitive_ref = "saas_ops.triage_support"
    version = "0.1.0"
    title = "Triage a support case against the SLA table"
    description = "Deterministic severity from impact, blast radius, data risk, and security, with first-response and resolution deadlines and the escalation owner; hands the case to the service resolution loop."
    input_model = TriageSupportInput
    output_model = SupportTriage
    risk_level = "low"
    operation_spec = read_spec("saas_ops_triage_support", "sdk.saas_ops.triage_support")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "triage")

    def _execute(self, context: PrimitiveExecutionContext, inputs: TriageSupportInput) -> PrimitiveExecutionResult[SupportTriage]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            triage = triage_support_case(inputs.plan, inputs.case)
        except ValueError as exc:
            return self.blocked(digest=digest, code="CASE_INVALID", message=str(exc))
        return self.preview(output=triage, digest=digest, external_refs={"triage_digest": triage.triage_digest, "case_ref": triage.case_ref}, event_type="saas_ops.support_triaged", event_payload={"severity": triage.severity, "first_response_due": triage.first_response_due, "first_response_met": triage.first_response_met, "escalate_to": triage.escalate_to}, evidence_kind="support_triage", evidence_summary="Severity and SLA deadlines; nothing sent.", summary=f"{triage.case_ref}: {triage.severity}, first response due {triage.first_response_due}, escalate to {triage.escalate_to}.")


class RankRoadmapPrimitive(_SaasOpsPrimitive):
    primitive_ref = "saas_ops.rank_roadmap"
    version = "0.1.0"
    title = "Rank roadmap candidates from evidence"
    description = "Weighted RICE ranking (reach, impact, confidence over effort) with the blueprint's weights; candidates below the evidence minimum are ranked but held, never admitted."
    input_model = RankRoadmapInput
    output_model = RoadmapRanking
    risk_level = "low"
    operation_spec = read_spec("saas_ops_rank_roadmap", "sdk.saas_ops.rank_roadmap")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "rank")

    def _execute(self, context: PrimitiveExecutionContext, inputs: RankRoadmapInput) -> PrimitiveExecutionResult[RoadmapRanking]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            ranking = rank_roadmap(inputs.plan, inputs.candidates, ranked_at=inputs.ranked_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="CANDIDATES_INVALID", message=str(exc))
        return self.preview(output=ranking, digest=digest, external_refs={"ranking_digest": ranking.ranking_digest}, event_type="saas_ops.roadmap_ranked", event_payload={"ranked": len(ranking.ranked), "held_for_evidence": len(ranking.held_for_evidence), "top": ranking.ranked[0].candidate_ref}, evidence_kind="roadmap_ranking", evidence_summary="Evidence-gated ranking; no effect.", summary=f"{len(ranking.ranked)} candidate(s) ranked; top {ranking.ranked[0].candidate_ref} ({ranking.ranked[0].score}); {len(ranking.held_for_evidence)} held for evidence.")


class AdvanceReleasePrimitive(_SaasOpsPrimitive):
    primitive_ref = "saas_ops.advance_release"
    version = "0.1.0"
    title = "Advance a release by one transition"
    description = "Materialize one replay-fenced release transition: evidence of the required kinds, approval when the policy needs it, canary inside the cap, canary observations, verification against error-rate and latency thresholds, roll-out, roll-back inside the window, abandonment."
    input_model = AdvanceReleaseInput
    output_model = ReleaseTransitionResult
    risk_level = "medium"
    operation_spec = read_spec("saas_ops_advance_release", "sdk.saas_ops.advance_release")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceReleaseInput) -> PrimitiveExecutionResult[ReleaseTransitionResult]:
        digest = request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not scope_matches(RequestScope.from_engine_scope(scope), inputs.command.actor_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the release scope and the command.")
        try:
            result = advance_release(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self.blocked(digest=digest, code="STATE_NOT_BOUND", message=str(exc))
        return self.transition_preview(result=result, digest=digest, entity_ref=scope.entity_ref, event_prefix="saas_ops")


class AssessSaasOperatingPrimitive(_SaasOpsPrimitive):
    primitive_ref = "saas_ops.assess_operating"
    version = "0.1.0"
    title = "Assess the operating engine (learn stage)"
    description = "Effect-dark operating metrics from the usage snapshot, releases, and triages: activation, retention, expansion rate, churn risk MRR, rollbacks, SLA attainment, learnings and recommendations against targets."
    input_model = AssessSaasOperatingInput
    output_model = SaasOperatingAssessment
    risk_level = "low"
    operation_spec = read_spec("saas_ops_assess", "sdk.saas_ops.assess_operating")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessSaasOperatingInput) -> PrimitiveExecutionResult[SaasOperatingAssessment]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_saas_operating(inputs.plan, inputs.snapshot, inputs.releases, inputs.triages, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self.blocked(digest=digest, code="INPUTS_NOT_BOUND", message=str(exc))
        return self.preview(output=assessment, digest=digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="saas_ops.assessed", event_payload={"accounts": assessment.accounts, "mrr": str(assessment.mrr), "rollbacks": assessment.rollbacks, "learnings": list(assessment.learnings)}, evidence_kind="saas_operating_assessment", evidence_summary="Operating metrics; no effect.", summary=f"{assessment.accounts} account(s), MRR {assessment.mrr}: {assessment.learnings[0]}")


SAAS_OPERATING_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileSaasOperatingPrimitive(),
    ObserveUsagePrimitive(),
    TriageSupportPrimitive(),
    RankRoadmapPrimitive(),
    AdvanceReleasePrimitive(),
    AssessSaasOperatingPrimitive(),
)

SAAS_OPERATING_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "saas_operating_golden_loop",
    "golden_loop": SAAS_OPERATING_GOLDEN_LOOP,
    "engine": SAAS_OPERATING_MANIFEST,
    "modules": {"domain": "lightbulb.saas_operating_loop", "primitives": "lightbulb.saas_operating_primitives", "core": "lightbulb.company_engine_core"},
    "reuses": ["saas.* launch loop hand-off", "subscription.* billing, proration, portfolio", "project.* software production run and events", "product.evaluate_release_governance_controls", "service.* case intake and verified resolution", "customer_success.prevent_returns_and_expand_ltv", "growth.* unit economics and customer value"],
    "required_connectors": SAAS_OPERATING_MANIFEST["required_connectors"],
    "primitive_refs": [item.primitive_ref for item in SAAS_OPERATING_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no deployment, rollback, plan change, incident, or customer contact executed here", "no usage, evidence, or observation invented", "no certification or production-readiness claim"],
}

__all__ = [
    "SAAS_OPERATING_EXECUTABLE_PRIMITIVES",
    "SAAS_OPERATING_INTEGRATION_MANIFEST",
    "AdvanceReleaseInput",
    "AdvanceReleasePrimitive",
    "AssessSaasOperatingInput",
    "AssessSaasOperatingPrimitive",
    "CompileSaasOperatingInput",
    "CompileSaasOperatingPrimitive",
    "ObserveUsageInput",
    "ObserveUsagePrimitive",
    "RankRoadmapInput",
    "RankRoadmapPrimitive",
    "TriageSupportInput",
    "TriageSupportPrimitive",
    "example_saas_operating_inputs",
]
