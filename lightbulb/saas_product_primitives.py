"""Executable primitives for the SaaS Product Golden Operating Loop.

Eight read-only primitives cover the product side of a SaaS company: compile
the blueprint, seal evidence-backed market research, evaluate demand
validation against thresholds, build the business model with its projection
and funding ask, plan the grounded materials, verify a generated material's
grounding, advance the product state, and assess it.  None of them calls a
model, a data provider, a repository host, a deployment platform, or an
investor; Spring authorizes every effect the bound primitives propose.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field, field_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
)
from lightbulb.saas_product_loop import (
    SAAS_PRODUCT_ARCHETYPE_MANIFEST,
    SAAS_PRODUCT_GOLDEN_LOOP,
    SAAS_PRODUCT_PROFILES,
    STAGE_ORDER,
    ProductTransitionResult,
    SaasProductAssessment,
    SaasProductBlueprint,
    SaasProductCommand,
    SaasProductLoopPlan,
    SaasProductState,
    advance_saas_product,
    assess_saas_product,
    compile_saas_product_blueprint,
    open_saas_product,
    seal_product_command,
)
from lightbulb.saas_product_research import (
    ArtifactGroundingReport,
    ArtifactKind,
    BusinessModel,
    DemandValidationVerdict,
    FinancialProjection,
    FundingAsk,
    MarketResearchDossier,
    ModelAssumptions,
    OpaqueRef,
    PricingHypothesis,
    ProductArtifactPlan,
    ProductThesis,
    ValidationEvidence,
    ValidationThresholds,
    _StrictModel,
    _timestamp,
    build_business_model,
    compile_market_research_dossier,
    compose_funding_ask,
    derive_pricing_hypothesis,
    derive_product_thesis,
    evaluate_demand_validation,
    plan_product_artifacts,
    project_financials,
    verify_artifact_grounding,
)


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID}


class RequestScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str


class CompileSaasProductInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: SaasProductBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class CompileMarketResearchInput(_StrictModel):
    """Seal a dossier; optionally derive the thesis and pricing hypothesis against it in the same call."""

    scope: RequestScope
    requested_by_ref: OpaqueRef
    dossier: dict[str, Any]
    thesis: dict[str, Any] | None = None
    pricing: dict[str, Any] | None = None


class MarketResearchBundle(_StrictModel):
    dossier: MarketResearchDossier
    thesis: ProductThesis | None = None
    pricing: PricingHypothesis | None = None


class EvaluateDemandValidationInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    thesis: ProductThesis
    evidence: tuple[ValidationEvidence, ...] = Field(default_factory=tuple, max_length=500)
    thresholds: ValidationThresholds | None = None
    evaluated_at: str

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")


class ProjectBusinessModelInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    pricing: PricingHypothesis
    assumptions: ModelAssumptions
    model_ref: OpaqueRef
    projection_ref: OpaqueRef
    funding_ask: dict[str, Any] | None = None


class BusinessModelBundle(_StrictModel):
    model: BusinessModel
    projection: FinancialProjection
    funding_ask: FundingAsk | None = None


class PlanProductArtifactsInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    dossier: MarketResearchDossier
    thesis: ProductThesis
    pricing: PricingHypothesis
    verdict: DemandValidationVerdict | None = None
    model: BusinessModel
    projection: FinancialProjection
    funding_ask: FundingAsk | None = None
    plan_ref: OpaqueRef


class VerifyArtifactGroundingInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: ProductArtifactPlan
    kind: ArtifactKind
    sections: dict[str, str]


class AdvanceSaasProductInput(_StrictModel):
    plan: SaasProductLoopPlan
    state: SaasProductState
    command: SaasProductCommand


class AssessSaasProductInput(_StrictModel):
    plan: SaasProductLoopPlan
    state: SaasProductState
    requested_by_ref: OpaqueRef
    assessed_at: str

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")


def _request_digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scope_matches(scope: RequestScope, requesting_ref: str, context: PrimitiveExecutionContext) -> bool:
    runtime = context.scope
    matched = scope.tenant_ref == runtime.tenant_ref and scope.company_ref == runtime.company_ref and scope.project_ref == runtime.project_ref and runtime.project_id is not None and scope.project_id == str(runtime.project_id)
    if runtime.actor_ref is not None:
        matched = matched and requesting_ref == runtime.actor_ref
    return matched


def example_dossier() -> dict[str, Any]:
    return {
        "dossier_ref": "dossier-example", "product_ref": "fieldsync", "problem_statement": "Field-service SMBs lose billable hours to paper job sheets and double entry.",
        "claims": [
            {"claim_id": "c1", "text": "UK field-service SMBs number roughly 120,000", "confidence": "evidence_backed", "evidence_refs": ["ons-2025"]},
            {"claim_id": "c2", "text": "Average of 6 technicians per firm", "confidence": "assumption_medium"},
            {"claim_id": "c3", "text": "Firms spend 4 hours per tech per week on admin", "confidence": "evidence_backed", "evidence_refs": ["interview-set-a"]},
            {"claim_id": "c4", "text": "Incumbents price at 30-60 per user per month", "confidence": "evidence_backed", "evidence_refs": ["pricing-pages"]},
        ],
        "segments": [{"segment_ref": "hvac-smb", "name": "HVAC and plumbing firms, 3-25 techs", "description": "Owner-operated firms with dispatchers", "buyer_role": "owner", "pain_points": ["double entry", "lost job sheets", "late invoicing"], "current_alternatives": ["paper", "spreadsheets"], "estimated_accounts": 40000, "willingness_to_pay_monthly": "45", "claim_ids": ["c1", "c2"]}],
        "competitors": [{"competitor_ref": "big-fs", "name": "BigFieldSuite", "kind": "direct", "positioning": "enterprise field service", "strengths": ["breadth"], "gaps": ["too complex for small firms", "no offline mode"], "evidence_refs": ["g2-reviews"]}, {"competitor_ref": "paper", "name": "Paper job sheets", "kind": "status_quo", "positioning": "free", "gaps": ["lost sheets", "no invoicing"], "evidence_refs": ["interview-set-a"]}],
        "sizing": {"currency": "GBP", "tam_annual": "648000000", "sam_annual": "216000000", "som_annual": "10800000", "basis": "bottom_up", "assumptions": ["120k firms x 6 techs x 45 GBP x 12"], "claim_ids": ["c1", "c2", "c4"]},
        "interviews": [{"interview_ref": f"int-{i}", "segment_ref": "hvac-smb", "role": "owner", "problem_confirmed": i % 5 != 0, "would_pay": i % 3 == 0, "evidence_ref": f"rec-{i}"} for i in range(1, 16)],
        "researched_at": "2026-09-01T00:00:00Z",
    }


def example_thesis() -> dict[str, Any]:
    return {"thesis_ref": "thesis-example", "product_name": "FieldSync", "target_segment_ref": "hvac-smb", "positioning": "The job sheet that invoices itself, for firms too small for enterprise suites.", "value_proposition": "Cut admin from 4 hours to 1 per tech per week.", "differentiators": ["offline-first mobile", "one-tap invoicing"], "competitor_gaps_addressed": ["too complex for small firms", "no offline mode"], "requirements": [{"requirement_ref": "req-1", "title": "Offline job sheets", "user_story": "As a technician I capture job details without signal", "acceptance_criteria": ["works with no signal", "syncs within 60 seconds of reconnect"], "addresses_pain_points": ["lost job sheets"]}, {"requirement_ref": "req-2", "title": "One-tap invoice", "user_story": "As an owner I invoice from a completed job", "acceptance_criteria": ["invoice created from a job in one tap"], "addresses_pain_points": ["late invoicing", "double entry"]}], "success_metrics": [{"metric_ref": "m1", "name": "paying firms", "target": "200 firms", "horizon_months": 12}], "defined_at": "2026-09-02T00:00:00Z"}


def example_pricing() -> dict[str, Any]:
    return {"pricing_ref": "pricing-example", "currency": "GBP", "plans": [{"plan_ref": "starter", "name": "Starter", "monthly_price": "29", "billing_model": "seat", "included_seats": 3, "target_segment_ref": "hvac-smb", "expected_mix_percent": "60"}, {"plan_ref": "team", "name": "Team", "monthly_price": "39", "billing_model": "seat", "included_seats": 8, "target_segment_ref": "hvac-smb", "expected_mix_percent": "40"}], "trial_days": 14}


def example_assumptions() -> dict[str, Any]:
    return {"currency": "GBP", "gross_margin_rate": "0.8", "monthly_churn_rate": "0.03", "customer_acquisition_cost": "400", "new_accounts_month_one": 5, "monthly_new_account_growth_rate": "0.15", "fixed_monthly_costs": "25000", "variable_cost_per_account_monthly": "5", "starting_cash": "150000", "months": 36}


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        dossier = compile_market_research_dossier(example_dossier())
        thesis = derive_product_thesis(dossier, example_thesis())
        pricing = derive_pricing_hypothesis(dossier, thesis, example_pricing())
        evidence = [{"evidence_ref": "ev-int", "method": "customer_interview", "segment_ref": "hvac-smb", "observed_at": "2026-09-03T00:00:00Z", "participants": 15, "problem_confirmed": 12, "would_pay": 6}, {"evidence_ref": "ev-land", "method": "landing_page_smoke_test", "segment_ref": "hvac-smb", "observed_at": "2026-09-04T00:00:00Z", "visitors": 1200, "signups": 60}]
        verdict = evaluate_demand_validation(thesis, evidence, evaluated_at="2026-09-05T00:00:00Z")
        model = build_business_model(pricing, example_assumptions(), model_ref="model-example")
        projection = project_financials(model, projection_ref="projection-example")
        ask_input = {"ask_ref": "ask-example", "round_type": "seed", "amount": "1200000", "use_of_funds": [{"category": "product_engineering", "amount": "600000", "rationale": "mobile and sync"}, {"category": "sales_marketing", "amount": "450000", "rationale": "field sales"}, {"category": "operations", "amount": "150000", "rationale": "support"}], "milestones": [{"milestone_ref": "ms-1", "description": "200 paying firms", "target_month": 12, "metric_ref": "m1"}]}
        ask = compose_funding_ask(model, projection, ask_input)
        artifact_plan = plan_product_artifacts(dossier, thesis, pricing, verdict, model, projection, ask, plan_ref="artifacts-example")
        one_pager = {"problem": "Field-service firms lose 4 hours per tech per week to admin.", "solution": "FieldSync: offline job sheets that invoice themselves.", "market": "TAM 648,000,000.00 with SOM 10,800,000.00 in GBP.", "traction": f"ARR {projection.ending_arr:,.2f} projected by month 36.", "ask": "Raising 1,200,000.00 seed."}
        plan = compile_saas_product_blueprint("seed_funded_saas", {"currency": "GBP"})
        scope = {**_EXAMPLE_SCOPE, "product_ref": "fieldsync", "currency": "GBP"}
        state = open_saas_product(plan, scope, opened_at="2026-09-01T00:00:00Z", actor_ref=_EXAMPLE_ACTOR, dossier_digest=dossier.dossier_digest, research_confidence_percent=dossier.research_confidence_percent)
        command = seal_product_command({"event": "complete_stage", "stage": "define_product", "transition_ref": "define_product:fieldsync", "idempotency_key": "fieldsync:define_product", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-09-02T00:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"thesis_digest": thesis.thesis_digest, "thesis_dossier_digest": thesis.dossier_digest, "pricing_digest": pricing.pricing_digest, "must_requirements": 2}})
        self._built = {
            "compile": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "seed_funded_saas", "overrides": {"currency": "GBP"}},
            "research": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "dossier": example_dossier(), "thesis": example_thesis(), "pricing": example_pricing()},
            "validate": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "thesis": thesis.to_dict(), "evidence": evidence, "evaluated_at": "2026-09-05T00:00:00Z"},
            "model": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "pricing": pricing.to_dict(), "assumptions": example_assumptions(), "model_ref": "model-example", "projection_ref": "projection-example", "funding_ask": ask_input},
            "artifacts": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "dossier": dossier.to_dict(), "thesis": thesis.to_dict(), "pricing": pricing.to_dict(), "verdict": verdict.to_dict(), "model": model.to_dict(), "projection": projection.to_dict(), "funding_ask": ask.to_dict(), "plan_ref": "artifacts-example"},
            "grounding": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "plan": artifact_plan.to_dict(), "kind": "one_pager", "sections": one_pager},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"plan": plan.to_dict(), "state": state.to_dict(), "requested_by_ref": _EXAMPLE_ACTOR, "assessed_at": "2026-09-03T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _ExampleBundle()


class _LazyExample(Mapping[str, Any]):
    def __init__(self, key: str) -> None:
        self._key = key

    def _payload(self) -> dict[str, Any]:
        return _EXAMPLES.get()[self._key]

    def __getitem__(self, key: str) -> Any:
        return self._payload()[key]

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._payload())

    def __len__(self) -> int:
        return len(self._payload())

    def keys(self):  # type: ignore[no-untyped-def]
        return self._payload().keys()

    def items(self):  # type: ignore[no-untyped-def]
        return self._payload().items()

    def values(self):  # type: ignore[no-untyped-def]
        return self._payload().values()


def example_saas_product_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _SaasPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
    connector_tools = ()
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    operation_spec: PrimitiveOperationSpec

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = self.operation_spec.to_dict()
        contract["golden_loop"] = SAAS_PRODUCT_GOLDEN_LOOP
        contract["archetype"] = SAAS_PRODUCT_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(SAAS_PRODUCT_PROFILES)
        contract["hard_rules"] = {"claims_are_evidence_backed_or_typed_assumptions": True, "research_confidence_is_derived": True, "validation_verdict_comes_from_thresholds": True, "projections_are_deterministic_arithmetic": True, "use_of_funds_equals_the_ask": True, "materials_cite_only_grounding_facts": True, "build_and_launch_bind_to_other_loops_by_reference": True}
        contract["authority_boundary"] = {"agent": "chooses segment, thesis, pricing, and go-to-market", "model_host": "drafts material sections on request through the artifact executor interface", "sdk": "seals research, derives confidence and economics, checks grounding, fences the product state", "spring": "approves materials, funding, repositories, deployments, and launches; persists the product", "connectors": "execute GitHub, CRM, social, and analytics operations", "mcp": "projects these primitives and the loop"}
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)])

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "connector_effect_executed": False, "model_called": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )


class CompileSaasProductPrimitive(_SaasPrimitive[CompileSaasProductInput, SaasProductLoopPlan]):
    primitive_ref = "blueprint.compile_saas_product"
    version = "0.1.0"
    title = "Compile a SaaS-product Company Blueprint into a loop plan"
    description = "Turn a ready-made profile (bootstrapped_saas, seed_funded_saas, enterprise_saas) or a custom blueprint into the research → define → validate → plan → materials → funding → build → deploy → launch → learn plan bound to existing primitives, connector tools, and the software-production and subscription loops."
    input_model = CompileSaasProductInput
    output_model = SaasProductLoopPlan
    risk_level = "low"
    operation_spec = _spec("saas_compile_blueprint", "sdk.blueprint.compile_saas_product")
    example_inputs: Mapping[str, Any] = _LazyExample("compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileSaasProductInput) -> PrimitiveExecutionResult[SaasProductLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_saas_product_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.saas_product_compiled", event_payload={"profile": plan.blueprint.profile, "round_type": plan.blueprint.round_type, "stack": plan.blueprint.stack, "environments": list(plan.blueprint.environments)}, evidence_kind="saas_product_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {plan.blueprint.profile} SaaS product plan ({plan.blueprint.round_type}, {plan.blueprint.stack}).")


class CompileMarketResearchPrimitive(_SaasPrimitive[CompileMarketResearchInput, MarketResearchBundle]):
    primitive_ref = "saas.compile_market_research"
    version = "0.1.0"
    title = "Seal evidence-backed market research (and optionally the thesis and pricing)"
    description = "Seal a market research dossier: claims are evidence-backed or typed assumptions, TAM ≥ SAM ≥ SOM with basis and assumptions, competitors with evidence, interviews bound to segments; research confidence is derived. Optionally derive the product thesis (segment, differentiators tied to competitor gaps, requirements with acceptance criteria) and the pricing hypothesis (plan mix, blended ARPA, willingness-to-pay anchoring) against it."
    input_model = CompileMarketResearchInput
    output_model = MarketResearchBundle
    risk_level = "medium"
    operation_spec = _spec("saas_compile_market_research", "sdk.saas.compile_market_research")
    example_inputs: Mapping[str, Any] = _LazyExample("research")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileMarketResearchInput) -> PrimitiveExecutionResult[MarketResearchBundle]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            dossier = compile_market_research_dossier(inputs.dossier)
            thesis = derive_product_thesis(dossier, inputs.thesis) if inputs.thesis is not None else None
            pricing = derive_pricing_hypothesis(dossier, thesis, inputs.pricing) if inputs.pricing is not None and thesis is not None else None
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="RESEARCH_INVALID", message=str(exc)[:500])
        bundle = MarketResearchBundle(dossier=dossier, thesis=thesis, pricing=pricing)
        return self._preview(output=bundle, request_digest=request_digest, external_refs={"dossier_digest": dossier.dossier_digest, **({"thesis_digest": thesis.thesis_digest} if thesis else {}), **({"pricing_digest": pricing.pricing_digest} if pricing else {})}, event_type="saas.market_research_compiled", event_payload={"research_confidence_percent": str(dossier.research_confidence_percent), "evidence_backed_claims": dossier.evidence_backed_claims, "assumption_claims": dossier.assumption_claims, "segments": len(dossier.segments), "competitors": len(dossier.competitors), "interviews": len(dossier.interviews), "thesis": thesis is not None, "pricing": pricing is not None}, evidence_kind="saas_market_research", evidence_summary="Sealed research; claims are evidence-backed or typed assumptions, never invented.", summary=f"Research confidence {dossier.research_confidence_percent}% ({dossier.evidence_backed_claims} evidence-backed, {dossier.assumption_claims} assumption claims)" + (f"; thesis {thesis.product_name}" if thesis else "") + (f"; blended ARPA {pricing.blended_arpa_monthly} {pricing.currency}" if pricing else "") + ".")


class EvaluateDemandValidationPrimitive(_SaasPrimitive[EvaluateDemandValidationInput, DemandValidationVerdict]):
    primitive_ref = "saas.evaluate_demand_validation"
    version = "0.1.0"
    title = "Evaluate demand validation against thresholds"
    description = "Threshold-driven go / pivot / no-go / insufficient-evidence verdict from interviews, surveys, landing-page smoke tests, waitlists, letters of intent, pilots, and presales on the thesis's target segment."
    input_model = EvaluateDemandValidationInput
    output_model = DemandValidationVerdict
    risk_level = "medium"
    operation_spec = _spec("saas_evaluate_demand_validation", "sdk.saas.evaluate_demand_validation")
    example_inputs: Mapping[str, Any] = _LazyExample("validate")

    def _execute(self, context: PrimitiveExecutionContext, inputs: EvaluateDemandValidationInput) -> PrimitiveExecutionResult[DemandValidationVerdict]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        verdict = evaluate_demand_validation(inputs.thesis, inputs.evidence, inputs.thresholds, evaluated_at=inputs.evaluated_at)
        return self._preview(output=verdict, request_digest=request_digest, external_refs={"verdict_digest": verdict.verdict_digest, "thesis_digest": verdict.thesis_digest}, event_type="saas.demand_validation_evaluated", event_payload={"verdict": verdict.verdict, "checks": dict(verdict.checks), "reasons": list(verdict.reasons)}, evidence_kind="saas_demand_validation", evidence_summary="Verdict from declared thresholds, not opinion.", summary=f"Validation verdict: {verdict.verdict}" + (f" ({'; '.join(verdict.reasons)})" if verdict.reasons else "") + ".")


class ProjectBusinessModelPrimitive(_SaasPrimitive[ProjectBusinessModelInput, BusinessModelBundle]):
    primitive_ref = "saas.project_business_model"
    version = "0.1.0"
    title = "Build the business model, projection, and funding ask"
    description = "Derive unit economics (contribution, CAC payback, lifetime value, LTV to CAC) from the pricing hypothesis and declared assumptions, project the months deterministically (accounts, MRR, costs, cash, runway, breakeven), and optionally bind a funding ask whose use of funds equals the amount with runway derived with and without the raise."
    input_model = ProjectBusinessModelInput
    output_model = BusinessModelBundle
    risk_level = "medium"
    operation_spec = _spec("saas_project_business_model", "sdk.saas.project_business_model")
    example_inputs: Mapping[str, Any] = _LazyExample("model")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ProjectBusinessModelInput) -> PrimitiveExecutionResult[BusinessModelBundle]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            model = build_business_model(inputs.pricing, inputs.assumptions, model_ref=inputs.model_ref)
            projection = project_financials(model, projection_ref=inputs.projection_ref)
            ask = compose_funding_ask(model, projection, inputs.funding_ask) if inputs.funding_ask is not None else None
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="MODEL_INVALID", message=str(exc)[:500])
        bundle = BusinessModelBundle(model=model, projection=projection, funding_ask=ask)
        blocker = PrimitiveBlocker(code="UNIT_ECONOMICS_FINDINGS", message="; ".join(model.health_findings)[:500], retryable=False) if model.health_findings else None
        return self._preview(output=bundle, request_digest=request_digest, external_refs={"model_digest": model.model_digest, "projection_digest": projection.projection_digest, **({"ask_digest": ask.ask_digest} if ask else {})}, event_type="saas.business_model_projected", event_payload={"ltv_to_cac": None if model.unit_economics.ltv_to_cac is None else str(model.unit_economics.ltv_to_cac), "payback_months": None if model.unit_economics.payback_months is None else str(model.unit_economics.payback_months), "ending_arr": str(projection.ending_arr), "runway_months": projection.runway_months_from_start, "breakeven_month": projection.breakeven_month, "ask": None if ask is None else str(ask.amount), "findings": list(model.health_findings) + (list(ask.findings) if ask else [])}, evidence_kind="saas_business_model", evidence_summary="Deterministic economics and projection from declared assumptions.", summary=f"LTV:CAC {model.unit_economics.ltv_to_cac}, payback {model.unit_economics.payback_months} months, ending ARR {projection.ending_arr}, runway {projection.runway_months_from_start} months" + (f", ask {ask.amount} ({ask.runway_months_with_raise} months after raise)" if ask else "") + ".", blocker=blocker)


class PlanProductArtifactsPrimitive(_SaasPrimitive[PlanProductArtifactsInput, ProductArtifactPlan]):
    primitive_ref = "saas.plan_product_artifacts"
    version = "0.1.0"
    title = "Plan the grounded product materials"
    description = "Assemble grounding facts from the sealed dossier, thesis, pricing, verdict, model, projection, and ask, and the artifact set a SaaS product needs (pitch deck, one-pager, financial summary, marketing site copy, launch campaign brief, investor FAQ, PRD) with required sections, audiences, formats, and approvals; generation runs through the governed artifact primitives."
    input_model = PlanProductArtifactsInput
    output_model = ProductArtifactPlan
    risk_level = "low"
    operation_spec = _spec("saas_plan_product_artifacts", "sdk.saas.plan_product_artifacts")
    example_inputs: Mapping[str, Any] = _LazyExample("artifacts")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanProductArtifactsInput) -> PrimitiveExecutionResult[ProductArtifactPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = plan_product_artifacts(inputs.dossier, inputs.thesis, inputs.pricing, inputs.verdict, inputs.model, inputs.projection, inputs.funding_ask, plan_ref=inputs.plan_ref)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="CHAIN_BROKEN", message=str(exc)[:500])
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest}, event_type="saas.product_artifacts_planned", event_payload={"facts": len(plan.facts), "artifacts": [item.kind for item in plan.artifacts]}, evidence_kind="saas_product_artifact_plan", evidence_summary="Grounding facts and artifact requirements; nothing generated.", summary=f"Planned {len(plan.artifacts)} materials over {len(plan.facts)} grounding facts.")


class VerifyArtifactGroundingPrimitive(_SaasPrimitive[VerifyArtifactGroundingInput, ArtifactGroundingReport]):
    primitive_ref = "saas.verify_artifact_grounding"
    version = "0.1.0"
    title = "Verify a generated material against its grounding facts"
    description = "Every number in the generated sections must match a grounding fact (or a trivial ordinal), every required section must exist, and headline facts must be cited. Ungrounded numbers block the material."
    input_model = VerifyArtifactGroundingInput
    output_model = ArtifactGroundingReport
    risk_level = "medium"
    operation_spec = _spec("saas_verify_artifact_grounding", "sdk.saas.verify_artifact_grounding")
    example_inputs: Mapping[str, Any] = _LazyExample("grounding")

    def _execute(self, context: PrimitiveExecutionContext, inputs: VerifyArtifactGroundingInput) -> PrimitiveExecutionResult[ArtifactGroundingReport]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            report = verify_artifact_grounding(inputs.plan, inputs.kind, inputs.sections)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="ARTIFACT_NOT_PLANNED", message=str(exc)[:500])
        blocker = PrimitiveBlocker(code="ARTIFACT_UNGROUNDED", message="; ".join(f"{item.code}: {item.message}" for item in report.findings)[:500], retryable=False) if report.status == "blocked" else None
        return self._preview(output=report, request_digest=request_digest, external_refs={"report_digest": report.report_digest, "content_digest": report.content_digest}, event_type="saas.artifact_grounding_verified", event_payload={"kind": inputs.kind, "status": report.status, "numbers_checked": report.numbers_checked, "grounded_numbers": report.grounded_numbers, "findings": [item.code for item in report.findings]}, evidence_kind="saas_artifact_grounding", evidence_summary="Numbers traced to sealed facts; no content generated.", summary=f"{inputs.kind}: {report.status} ({report.grounded_numbers}/{report.numbers_checked} numbers grounded, {len(report.findings)} finding(s)).", blocker=blocker)


class AdvanceSaasProductPrimitive(_SaasPrimitive[AdvanceSaasProductInput, ProductTransitionResult]):
    primitive_ref = "saas.advance_product"
    version = "0.1.0"
    title = "Advance a SaaS product by one stage"
    description = "Materialize one replay-fenced product transition: each stage links its sealed objects by digest (dossier, thesis and pricing chained to it, go verdict, model and projection and ask, grounded and approved materials, closed funding within the close fraction, repository with verified software-production runs per work package, ready deployment, launch with a paying customer, learnings). Pivots return to definition within the blueprint limit."
    input_model = AdvanceSaasProductInput
    output_model = ProductTransitionResult
    risk_level = "medium"
    operation_spec = _spec("saas_advance_product", "sdk.saas.advance_product")
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceSaasProductInput) -> PrimitiveExecutionResult[ProductTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the product scope and the command.")
        try:
            result = advance_saas_product(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(output=result, request_digest=request_digest, external_refs={"product_ref": scope.product_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type="saas.product_advanced", event_payload={"event": receipt.event, "stage": receipt.stage, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind="saas_product_transition", evidence_summary="Replay-fenced product transition; candidate until Spring retains it.", summary=(f"{receipt.stage or receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.stage or receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)


class AssessSaasProductPrimitive(_SaasPrimitive[AssessSaasProductInput, SaasProductAssessment]):
    primitive_ref = "saas.assess_product"
    version = "0.1.0"
    title = "Assess a SaaS product"
    description = "Effect-dark assessment: stages completed and next, pivots, research confidence, verdict, unit economics, funding status and close fraction, materials readiness, build progress, launch readiness, traction against the first-customer target, learnings, next actions, and the subscription-loop handoff."
    input_model = AssessSaasProductInput
    output_model = SaasProductAssessment
    risk_level = "low"
    operation_spec = _spec("saas_assess_product", "sdk.saas.assess_product")
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessSaasProductInput) -> PrimitiveExecutionResult[SaasProductAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the product scope.")
        try:
            assessment = assess_saas_product(inputs.plan, inputs.state, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"product_ref": assessment.product_ref, "assessment_digest": assessment.assessment_digest}, event_type="saas.product_assessed", event_payload={"status": assessment.status, "next_stage": assessment.next_stage, "traction_percent_of_target": str(assessment.traction_percent_of_target), "next_actions": list(assessment.next_actions)}, evidence_kind="saas_product_assessment", evidence_summary="Assessment and next actions; no effect.", summary=f"Product {assessment.status}; next stage {assessment.next_stage}; " + (assessment.next_actions[0] if assessment.next_actions else "no open actions") + ".")


SAAS_PRODUCT_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileSaasProductPrimitive(),
    CompileMarketResearchPrimitive(),
    EvaluateDemandValidationPrimitive(),
    ProjectBusinessModelPrimitive(),
    PlanProductArtifactsPrimitive(),
    VerifyArtifactGroundingPrimitive(),
    AdvanceSaasProductPrimitive(),
    AssessSaasProductPrimitive(),
)

SAAS_PRODUCT_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "saas_product_golden_loop",
    "golden_loop": SAAS_PRODUCT_GOLDEN_LOOP,
    "archetype": SAAS_PRODUCT_ARCHETYPE_MANIFEST,
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "modules": {"research": "lightbulb.saas_product_research", "loop": "lightbulb.saas_product_loop", "primitives": "lightbulb.saas_product_primitives"},
    "reuses": ["documents.prepare_business_artifact_generation / validate_generated_business_artifact / generate_business_artifact (materials)", "growth.build_unit_economics, growth.review_profit, growth.plan_price_move", "cash.build_cash_flow_forecast, cash.assess_runway, accounting.search_grants", "crm.qualify_lead, communication.* (investor and customer outreach)", "project.create_work_packet, project.request_software_production (build, by reference)", "blueprint.compile_subscription_business, subscription.* (launch handoff, by reference)"],
    "primitive_refs": [item.primitive_ref for item in SAAS_PRODUCT_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.saas_product_primitives import SAAS_PRODUCT_EXECUTABLE_PRIMITIVES", "splice": "*SAAS_PRODUCT_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register saas.market_research_to_launched_product@0.1.0 with STAGE_ORDER; build binds to the software-production loop and launch hands off to the subscription loop by reference"},
    "company_blueprints": {"note": "register the saas_product archetype with SAAS_PRODUCT_PROFILES; composable with subscription_business, service_business, product_commerce"},
    "connector_tools_referenced": ["github.create_repository", "github.create_ruleset", "github.create_environment", "github.dispatch_workflow", "github.list_deployments", "github.create_release", "linkedin.publish_post", "hubspot.create_campaign", "google_analytics.fetch_metrics"],
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SAAS_PRODUCT_EXECUTABLE_PRIMITIVES", "SAAS_PRODUCT_INTEGRATION_MANIFEST", "SAAS_PRODUCT_PROFILES", "SAAS_PRODUCT_ARCHETYPE_MANIFEST", "MarketResearchDossier", "ProductThesis", "PricingHypothesis", "DemandValidationVerdict", "BusinessModel", "FinancialProjection", "FundingAsk", "ProductArtifactPlan", "ArtifactGroundingReport", "RepositoryBlueprint", "DeploymentPlan", "LaunchReadiness", "LaunchPlan", "SaasProductState", "compile_market_research_dossier", "derive_product_thesis", "derive_pricing_hypothesis", "evaluate_demand_validation", "build_business_model", "project_financials", "compose_funding_ask", "plan_product_artifacts", "verify_artifact_grounding", "derive_repository_blueprint", "derive_deployment_plan", "verify_launch_readiness", "derive_launch_plan", "open_saas_product", "advance_saas_product", "assess_saas_product"]},
    "non_goals": ["no model call, data-provider call, repository creation, deployment, publication, or investor contact executed here", "no invented market numbers, assumptions, or commitments", "no certification or production-readiness claim"],
}

__all__ = [
    "SAAS_PRODUCT_EXECUTABLE_PRIMITIVES",
    "SAAS_PRODUCT_INTEGRATION_MANIFEST",
    "AdvanceSaasProductInput",
    "AdvanceSaasProductPrimitive",
    "AssessSaasProductInput",
    "AssessSaasProductPrimitive",
    "BusinessModelBundle",
    "CompileMarketResearchInput",
    "CompileMarketResearchPrimitive",
    "CompileSaasProductInput",
    "CompileSaasProductPrimitive",
    "EvaluateDemandValidationInput",
    "EvaluateDemandValidationPrimitive",
    "MarketResearchBundle",
    "PlanProductArtifactsInput",
    "PlanProductArtifactsPrimitive",
    "ProjectBusinessModelInput",
    "ProjectBusinessModelPrimitive",
    "RequestScope",
    "VerifyArtifactGroundingInput",
    "VerifyArtifactGroundingPrimitive",
    "example_assumptions",
    "example_dossier",
    "example_pricing",
    "example_saas_product_inputs",
    "example_thesis",
]
