"""Executable primitives for the Product Commerce Golden Operating Loop.

Six read-only primitives: compile the blueprint, compile a Product Commercial
Identity (optionally binding a storefront readiness receipt), compose a
policy-checked personalized variant, plan a channel publication, advance the
cycle, and assess the cycle.  None of them calls Shopify, a social platform,
or a CRM; the Connector Runtime executes publications only through the
adapter and only under Spring approval.
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
from lightbulb.product_commerce_loop import (
    PRODUCT_COMMERCE_ARCHETYPE_MANIFEST,
    PRODUCT_COMMERCE_GOLDEN_LOOP,
    PRODUCT_COMMERCE_PROFILES,
    STAGE_ORDER,
    ChannelConstraints,
    ContentVariant,
    CycleTransitionResult,
    HttpsUrl,
    OpaqueRef,
    PersonalizationBrief,
    ProductCommerceBlueprint,
    ProductCommerceCycleAssessment,
    ProductCommerceCycleCommand,
    ProductCommerceCycleState,
    ProductCommerceLoopPlan,
    ProductCommercialIdentity,
    PublicationCandidate,
    VariantComposition,
    _StrictModel,
    _timestamp,
    advance_product_commerce_cycle,
    approve_variant,
    assess_product_commerce_cycle,
    bind_storefront_readiness,
    compile_product_commerce_blueprint,
    compile_product_commercial_identity,
    compose_personalized_variant,
    open_product_commerce_cycle,
    plan_channel_publication,
    seal_cycle_command,
)


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


COMPILE_BLUEPRINT_OPERATION = _spec("product_commerce_compile_blueprint", "sdk.blueprint.compile_product_commerce")
COMPILE_IDENTITY_OPERATION = _spec("product_commerce_compile_identity", "sdk.commerce.compile_product_commercial_identity")
COMPOSE_VARIANT_OPERATION = _spec("product_commerce_compose_variant", "sdk.commerce.compose_personalized_variant")
PLAN_PUBLICATION_OPERATION = _spec("product_commerce_plan_publication", "sdk.commerce.plan_channel_publication")
ADVANCE_OPERATION = _spec("product_commerce_advance_cycle", "sdk.commerce.advance_product_cycle")
ASSESS_OPERATION = _spec("product_commerce_assess_cycle", "sdk.commerce.assess_product_cycle")

_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID}
_EXAMPLE_LANDING = "https://shop.example.com/products/trail-bottle"


class RequestScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str


class CompileProductCommerceInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: ProductCommerceBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class CompileIdentityInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    identity: dict[str, Any]
    launch_result: dict[str, Any] | None = None


class ComposeVariantInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    identity: ProductCommercialIdentity
    brief: PersonalizationBrief
    headline: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=4000)
    image_url: HttpsUrl | None = None
    variant_ref: OpaqueRef
    composed_at: str
    constraints: ChannelConstraints | None = None

    @field_validator("composed_at")
    @classmethod
    def _composed(cls, value: str) -> str:
        return _timestamp(value, field_name="composed_at")


class PlanPublicationInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    identity: ProductCommercialIdentity
    variant: ContentVariant
    candidate_ref: OpaqueRef
    target_ref: OpaqueRef


class AdvanceProductCycleInput(_StrictModel):
    plan: ProductCommerceLoopPlan
    state: ProductCommerceCycleState
    command: ProductCommerceCycleCommand


class AssessProductCycleInput(_StrictModel):
    plan: ProductCommerceLoopPlan
    state: ProductCommerceCycleState
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
    return scope.tenant_ref == runtime.tenant_ref and scope.company_ref == runtime.company_ref and scope.project_ref == runtime.project_ref and runtime.project_id is not None and scope.project_id == str(runtime.project_id) and runtime.actor_ref is not None and requesting_ref == runtime.actor_ref


def example_product_identity() -> dict[str, Any]:
    return {
        "product_ref": "trail-bottle", "sku": "TB-750-BLK", "title": "Trail Bottle 750", "positioning": "Insulated bottle for long trail days.",
        "price": {"amount": "48.00", "currency": "USD"}, "unit_cost": {"amount": "19.50", "currency": "USD"}, "target_margin_percent": "50",
        "approved_claims": [{"claim_id": "cold-24h", "text": "Keeps drinks cold for 24 hours", "evidence_refs": ["lab-report-7"], "approved_by_ref": "user:brand-lead", "approved_at": "2026-08-01T00:00:00Z"}],
        "seo": {"primary_keyword": "insulated trail bottle", "secondary_keywords": ["hiking water bottle"], "meta_title": "Trail Bottle 750 | Insulated Hiking Bottle", "meta_description": "Keeps drinks cold for 24 hours on long trail days.", "canonical_url": _EXAMPLE_LANDING},
        "inventory": {"available_units": 400, "fulfilment_mode": "shopify_fulfilment", "fulfilment_lead_days": 2, "returns_window_days": 30},
        "shopify": {"connector_account_ref": "shopify:main", "landing_url": _EXAMPLE_LANDING},
        "audiences": [{"audience_ref": "seg-hikers", "level": "segment", "description": "Weekend hikers 25-45", "allowed_channels": ["instagram", "facebook", "email"]}],
        "personalization": {"allowed_levels": ["segment", "cohort"], "prohibited_terms": ["guaranteed", "cures"]},
        "campaigns": [{"campaign_ref": "camp-ig", "channel": "instagram", "objective": "conversion", "connector_account_ref": "instagram:brand", "status": "active"}, {"campaign_ref": "camp-email", "channel": "email", "objective": "retention", "connector_account_ref": "hubspot:main"}],
        "as_of": "2026-09-01T00:00:00Z",
    }


def example_launch_result() -> dict[str, Any]:
    return {"status": "storefront_ready", "storefront_ready": True, "downstream_release_ready": True, "omnichannel_launch_completed": False, "product_id": "gid://shopify/Product/1", "publication_ids": ["pub-1"], "run_ref": "run-1", "plan_digest": "a" * 64, "receipts": [{"receipt_kind": "landing_readiness", "receipt_digest": "b" * 64}]}


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        identity = bind_storefront_readiness(compile_product_commercial_identity(example_product_identity()), example_launch_result())
        brief = {"identity_digest": identity.identity_digest, "audience_ref": "seg-hikers", "channel": "instagram", "level": "segment", "objective": "conversion", "claim_ids": ["cold-24h"]}
        composition = compose_personalized_variant(identity, brief, headline="Cold for 24 hours on the trail", body=f"Trail Bottle keeps drinks cold for 24 hours. {_EXAMPLE_LANDING}", variant_ref="variant-example", composed_at="2026-09-02T00:00:00Z", image_url="https://cdn.example.com/trail-bottle.jpg")
        assert composition.variant is not None
        approved = approve_variant(composition.variant, approval_ref="approval-example")
        plan = compile_product_commerce_blueprint("dtc_shopify")
        scope = {**_EXAMPLE_SCOPE, "cycle_ref": "cycle-example", "product_ref": "trail-bottle", "currency": "USD"}
        state = open_product_commerce_cycle(plan, scope, identity, opened_at="2026-09-01T00:00:00Z", actor_ref=_EXAMPLE_ACTOR)
        command = seal_cycle_command({"event": "complete_stage", "stage": "build_storefront", "transition_ref": "build_storefront:cycle-example", "idempotency_key": "cycle-example:build_storefront", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-09-03T00:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"storefront_status": "storefront_ready", "storefront_run_ref": "run-1", "readiness_receipt_digest": "b" * 64, "product_id": "gid://shopify/Product/1"}})
        self._built = {
            "compile_blueprint": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "dtc_shopify", "overrides": {"minimum_roas": "3"}},
            "compile_identity": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "identity": example_product_identity(), "launch_result": example_launch_result()},
            "compose_variant": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "identity": identity.to_dict(), "brief": brief, "headline": "Cold for 24 hours on the trail", "body": f"Trail Bottle keeps drinks cold for 24 hours. {_EXAMPLE_LANDING}", "image_url": "https://cdn.example.com/trail-bottle.jpg", "variant_ref": "variant-example", "composed_at": "2026-09-02T00:00:00Z"},
            "plan_publication": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "identity": identity.to_dict(), "variant": approved.to_dict(), "candidate_ref": "publication-example", "target_ref": "17841400000000000"},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "assess": {"plan": plan.to_dict(), "state": state.to_dict(), "requested_by_ref": _EXAMPLE_ACTOR, "assessed_at": "2026-09-03T01:00:00Z"},
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


def example_product_commerce_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _ProductCommercePrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
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
        contract["golden_loop"] = PRODUCT_COMMERCE_GOLDEN_LOOP
        contract["archetype"] = PRODUCT_COMMERCE_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(PRODUCT_COMMERCE_PROFILES)
        contract["hard_rules"] = {
            "approved_claims_only": True,
            "consent_and_platform_policy_are_inputs": True,
            "publication_requires_storefront_readiness_receipt": True,
            "publication_requires_spring_approval": True,
            "one_campaign_system_per_product_channel": True,
            "no_direct_shopify_or_social_client": True,
        }
        contract["authority_boundary"] = {
            "agent": "chooses the offer, audiences, and campaign strategy",
            "sdk": "seals product truth, checks personalization policy, shapes publications, advances and assesses the cycle",
            "spring": "approves claims, variants, and publications; persists the cycle",
            "connectors": "execute Shopify, social, email, and analytics operations",
            "mcp": "projects these primitives and the loop",
        }
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)])

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "connector_effect_executed": False, "content_published": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )


class CompileProductCommercePrimitive(_ProductCommercePrimitive[CompileProductCommerceInput, ProductCommerceLoopPlan]):
    primitive_ref = "blueprint.compile_product_commerce"
    version = "0.1.0"
    title = "Compile a product-commerce Company Blueprint into a loop plan"
    description = "Turn a ready-made product profile (dtc_shopify, b2b_wholesale, digital_product) or a custom blueprint into the product truth → storefront → campaign system → variants → publish → convert → fulfil → observe → improve plan bound to existing primitives and connector tools."
    input_model = CompileProductCommerceInput
    output_model = ProductCommerceLoopPlan
    risk_level = "low"
    operation_spec = COMPILE_BLUEPRINT_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("compile_blueprint")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileProductCommerceInput) -> PrimitiveExecutionResult[ProductCommerceLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_product_commerce_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest, "blueprint_digest": plan.blueprint.blueprint_digest}, event_type="blueprint.product_commerce_compiled", event_payload={"profile": plan.blueprint.profile, "channels": list(plan.blueprint.channels), "personalization_levels": list(plan.blueprint.personalization_levels), "fulfilment_mode": plan.blueprint.fulfilment_mode}, evidence_kind="product_commerce_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {plan.blueprint.profile} product-commerce plan ({', '.join(plan.blueprint.channels)}).")


class CompileProductIdentityPrimitive(_ProductCommercePrimitive[CompileIdentityInput, ProductCommercialIdentity]):
    primitive_ref = "commerce.compile_product_commercial_identity"
    version = "0.1.0"
    title = "Compile a Product Commercial Identity"
    description = "Seal the durable identity joining SKU, evidence-backed approved claims, price and margin, inventory and fulfilment constraints, Shopify product and landing binding, SEO metadata, audiences with consent basis, personalization policy, and channel campaigns; optionally bind the storefront readiness receipt from the Shopify launch runner."
    input_model = CompileIdentityInput
    output_model = ProductCommercialIdentity
    risk_level = "medium"
    operation_spec = COMPILE_IDENTITY_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("compile_identity")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileIdentityInput) -> PrimitiveExecutionResult[ProductCommercialIdentity]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            identity = compile_product_commercial_identity(inputs.identity)
            if inputs.launch_result is not None:
                identity = bind_storefront_readiness(identity, inputs.launch_result)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="IDENTITY_INVALID", message=str(exc)[:500])
        return self._preview(output=identity, request_digest=request_digest, external_refs={"identity_digest": identity.identity_digest, "product_ref": identity.product_ref}, event_type="commerce.product_identity_compiled", event_payload={"product_ref": identity.product_ref, "approved_claims": len(identity.approved_claims), "gross_margin_percent": str(identity.gross_margin_percent()), "storefront_ready": identity.shopify.storefront_ready, "channels": [item.channel for item in identity.campaigns]}, evidence_kind="product_commercial_identity", evidence_summary="Sealed product truth; claims, consent, and policy are inputs, never inferred.", summary=f"Compiled identity for {identity.product_ref} ({len(identity.approved_claims)} approved claims, {identity.gross_margin_percent()}% margin, storefront {'ready' if identity.shopify.storefront_ready else 'not ready'}).")


class ComposePersonalizedVariantPrimitive(_ProductCommercePrimitive[ComposeVariantInput, VariantComposition]):
    primitive_ref = "commerce.compose_personalized_variant"
    version = "0.1.0"
    title = "Compose a personalized content variant"
    description = "Product truth + audience profile + channel constraints → a policy-checked content variant candidate: approved claims only, consent for one-to-one, allowed levels and channels, prohibited terms, length, image and landing-link rules. Blocked compositions return typed findings."
    input_model = ComposeVariantInput
    output_model = VariantComposition
    risk_level = "medium"
    operation_spec = COMPOSE_VARIANT_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("compose_variant")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ComposeVariantInput) -> PrimitiveExecutionResult[VariantComposition]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        composition = compose_personalized_variant(inputs.identity, inputs.brief, headline=inputs.headline, body=inputs.body, variant_ref=inputs.variant_ref, composed_at=inputs.composed_at, image_url=inputs.image_url, constraints=inputs.constraints)
        blocker = None if composition.status == "candidate" else PrimitiveBlocker(code=composition.findings[0].code, message=composition.findings[0].message, retryable=False)
        return self._preview(output=composition, request_digest=request_digest, external_refs={"identity_digest": inputs.identity.identity_digest, **({"variant_digest": composition.variant.variant_digest} if composition.variant else {})}, event_type="commerce.personalized_variant_composed", event_payload={"status": composition.status, "channel": inputs.brief.channel, "level": inputs.brief.level, "findings": [item.code for item in composition.findings]}, evidence_kind="personalized_content_variant", evidence_summary="Policy-checked variant candidate; approval and publication remain with Spring.", summary=(f"Composed {inputs.brief.level} variant for {inputs.brief.channel}." if composition.status == "candidate" else f"Variant blocked: {', '.join(item.code for item in composition.findings)}."), blocker=blocker)


class PlanChannelPublicationPrimitive(_ProductCommercePrimitive[PlanPublicationInput, PublicationCandidate]):
    primitive_ref = "commerce.plan_channel_publication"
    version = "0.1.0"
    title = "Plan a governed channel publication"
    description = "Shape an approved variant into the exact connector arguments for its channel (facebook, instagram, linkedin, shopify landing, email). Requires the storefront readiness receipt and the variant's approval; the Connector Runtime executes it later under Spring approval."
    input_model = PlanPublicationInput
    output_model = PublicationCandidate
    risk_level = "high"
    operation_spec = PLAN_PUBLICATION_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("plan_publication")

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanPublicationInput) -> PrimitiveExecutionResult[PublicationCandidate]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            candidate = plan_channel_publication(inputs.identity, inputs.variant, candidate_ref=inputs.candidate_ref, target_ref=inputs.target_ref)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="PUBLICATION_HELD", message=str(exc)[:500])
        return self._preview(output=candidate, request_digest=request_digest, external_refs={"candidate_digest": candidate.candidate_digest, "readiness_receipt_digest": candidate.readiness_receipt_digest}, event_type="commerce.channel_publication_planned", event_payload={"channel": candidate.channel, "connector_tool": candidate.connector_tool, "primitive_ref": candidate.primitive_ref, "approval_ref": candidate.approval_ref}, evidence_kind="channel_publication_candidate", evidence_summary="Exact connector arguments; not published.", summary=f"Planned {candidate.channel} publication via {candidate.connector_tool or candidate.primitive_ref}.")


class AdvanceProductCyclePrimitive(_ProductCommercePrimitive[AdvanceProductCycleInput, CycleTransitionResult]):
    primitive_ref = "commerce.advance_product_cycle"
    version = "0.1.0"
    title = "Advance a product-commerce cycle by one stage"
    description = "Materialize one replay-fenced cycle transition linking the stage's evidence: product identity, storefront readiness, campaign system, variants, publications, Shopify conversion, fulfilment and returns, outcome evidence, improvement."
    input_model = AdvanceProductCycleInput
    output_model = CycleTransitionResult
    risk_level = "medium"
    operation_spec = ADVANCE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceProductCycleInput) -> PrimitiveExecutionResult[CycleTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the cycle scope and command.")
        try:
            result = advance_product_commerce_cycle(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition == "refresh_state")
        return self._preview(output=result, request_digest=request_digest, external_refs={"cycle_ref": scope.cycle_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type="commerce.product_cycle_advanced", event_payload={"event": receipt.event, "stage": receipt.stage, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind="product_commerce_cycle_transition", evidence_summary="Replay-fenced cycle transition; candidate until Spring retains it.", summary=(f"{receipt.stage or receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.stage or receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)


class AssessProductCyclePrimitive(_ProductCommercePrimitive[AssessProductCycleInput, ProductCommerceCycleAssessment]):
    primitive_ref = "commerce.assess_product_cycle"
    version = "0.1.0"
    title = "Assess a product-commerce cycle (observe and improve)"
    description = "Effect-dark assessment: net revenue, contribution margin against the blueprint target, ROAS against the floor, return rate, learnings, next-cycle recommendations, the next experiment proposal, and a learning-entry candidate."
    input_model = AssessProductCycleInput
    output_model = ProductCommerceCycleAssessment
    risk_level = "low"
    operation_spec = ASSESS_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessProductCycleInput) -> PrimitiveExecutionResult[ProductCommerceCycleAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the cycle scope.")
        try:
            assessment = assess_product_commerce_cycle(inputs.plan, inputs.state, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        # A cycle in flight assesses as a preview of where it stands; nothing to block on.
        blocker = None
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"cycle_ref": assessment.cycle_ref, "assessment_digest": assessment.assessment_digest}, event_type="commerce.product_cycle_assessed", event_payload={"status": assessment.status, "next_stage": assessment.next_stage, "contribution_margin_percent": None if assessment.contribution_margin_percent is None else str(assessment.contribution_margin_percent), "roas": None if assessment.roas is None else str(assessment.roas), "learnings": list(assessment.learnings)}, evidence_kind="product_commerce_cycle_assessment", evidence_summary="Observe/improve assessment and next experiment; no effect.", summary=(f"Cycle {assessment.status}: {assessment.learnings[0]}" if assessment.learnings else f"Cycle at {assessment.status}; next stage {assessment.next_stage}."), blocker=blocker)


PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileProductCommercePrimitive(),
    CompileProductIdentityPrimitive(),
    ComposePersonalizedVariantPrimitive(),
    PlanChannelPublicationPrimitive(),
    AdvanceProductCyclePrimitive(),
    AssessProductCyclePrimitive(),
)

PRODUCT_COMMERCE_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "product_commerce_golden_loop",
    "golden_loop": PRODUCT_COMMERCE_GOLDEN_LOOP,
    "archetype": PRODUCT_COMMERCE_ARCHETYPE_MANIFEST,
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "modules": {"domain": "lightbulb.product_commerce_loop", "primitives": "lightbulb.product_commerce_primitives"},
    "reuses": ["commerce.plan_shopify_storefront", "gtm.plan_omnichannel_product_launch", "lightbulb.gtm_shopify_launch.run_shopify_product_launch (readiness receipt consumed, runner not extended)", "lightbulb.gtm_primitives Facebook/Instagram/LinkedIn publish argument models", "lightbulb.growth_experiments.ExperimentHypothesis", "growth.* profit, funnel, customer value, learnings"],
    "primitive_refs": [item.primitive_ref for item in PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.product_commerce_primitives import PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES", "splice": "*PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register commerce.product_truth_to_measured_improvement@0.1.0 with STAGE_ORDER; publishing is a second governed runner gated on the storefront readiness receipt"},
    "company_blueprints": {"note": "register the product_commerce archetype with PRODUCT_COMMERCE_PROFILES; composable with service_business"},
    "connector_tools_used_by_reference_adapter": ["facebook.publish_post", "instagram.publish_post", "linkedin.publish_post", "shopify.update_page"],
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES", "PRODUCT_COMMERCE_INTEGRATION_MANIFEST", "PRODUCT_COMMERCE_PROFILES", "PRODUCT_COMMERCE_ARCHETYPE_MANIFEST", "ProductCommercialIdentity", "ContentVariant", "PublicationCandidate", "OutcomeEvidence", "ProductCommerceLoopPlan", "ProductCommerceCycleState", "compile_product_commercial_identity", "compose_personalized_variant", "plan_channel_publication", "advance_product_commerce_cycle", "assess_product_commerce_cycle"]},
    "mcp": {"note": "project the six primitives through the generated primitive tools; the identity, variant, and publication schemas are the resources"},
    "non_goals": ["no extension of run_shopify_product_launch", "no direct Shopify, Meta, LinkedIn, or email client", "no model-invented claims, consent, or platform policy", "no certification or production-readiness claim"],
}

__all__ = [
    "ADVANCE_OPERATION",
    "ASSESS_OPERATION",
    "COMPILE_BLUEPRINT_OPERATION",
    "COMPILE_IDENTITY_OPERATION",
    "COMPOSE_VARIANT_OPERATION",
    "PLAN_PUBLICATION_OPERATION",
    "PRODUCT_COMMERCE_EXECUTABLE_PRIMITIVES",
    "PRODUCT_COMMERCE_INTEGRATION_MANIFEST",
    "AdvanceProductCycleInput",
    "AdvanceProductCyclePrimitive",
    "AssessProductCycleInput",
    "AssessProductCyclePrimitive",
    "CompileIdentityInput",
    "CompileProductCommerceInput",
    "CompileProductCommercePrimitive",
    "CompileProductIdentityPrimitive",
    "ComposePersonalizedVariantPrimitive",
    "ComposeVariantInput",
    "PlanChannelPublicationPrimitive",
    "PlanPublicationInput",
    "RequestScope",
    "example_launch_result",
    "example_product_commerce_inputs",
    "example_product_identity",
]
