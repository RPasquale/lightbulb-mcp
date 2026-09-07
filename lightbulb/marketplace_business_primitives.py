"""Executable primitives for the Marketplace Business Golden Operating Loop.

``blueprint.compile_marketplace_business`` builds the plan from a profile,
``marketplace.advance_seller`` / ``marketplace.advance_listing`` /
``marketplace.advance_transaction`` materialize one replay-fenced transition
of the respective entity with policy-derived fees, refunds, and payouts, and
``marketplace.assess_marketplace`` derives GMV, take revenue, liquidity,
dispute and refund rates, repeat buyers, and escrow exposure.  Read-only;
Spring authorizes identity verification, listing publication, payments,
refunds, and payouts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, Field, field_validator, model_validator

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.marketplace_business_loop import (
    MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST,
    MARKETPLACE_BUSINESS_GOLDEN_LOOP,
    MARKETPLACE_BUSINESS_PROFILES,
    STAGE_ORDER,
    MarketplaceAssessment,
    MarketplaceBusinessBlueprint,
    MarketplaceBusinessLoopPlan,
    MarketplaceCommand,
    MarketplaceState,
    MarketplaceTransitionResult,
    OpaqueRef,
    _StrictModel,
    _timestamp,
    advance_marketplace_entity,
    assess_marketplace,
    compile_marketplace_business_blueprint,
    open_listing,
    open_seller,
    open_transaction,
    seal_marketplace_command,
)
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


class CompileMarketplaceBusinessInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: MarketplaceBusinessBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class _AdvanceInput(_StrictModel):
    plan: MarketplaceBusinessLoopPlan
    state: MarketplaceState
    command: MarketplaceCommand
    _entity: ClassVar[str] = "seller"

    @model_validator(mode="after")
    def _entity_matches(self) -> "_AdvanceInput":
        expected = type(self)._entity
        if self.state.entity != expected or self.command.entity != expected:
            raise ValueError(f"state and command must both be {expected} entities")
        return self


class AdvanceSellerInput(_AdvanceInput):
    _entity: ClassVar[str] = "seller"


class AdvanceListingInput(_AdvanceInput):
    _entity: ClassVar[str] = "listing"


class AdvanceTransactionInput(_AdvanceInput):
    _entity: ClassVar[str] = "transaction"


class AssessMarketplaceInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: MarketplaceBusinessLoopPlan
    sellers: tuple[MarketplaceState, ...] = Field(default_factory=tuple, max_length=5000)
    listings: tuple[MarketplaceState, ...] = Field(default_factory=tuple, max_length=5000)
    transactions: tuple[MarketplaceState, ...] = Field(default_factory=tuple, max_length=5000)
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


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_marketplace_business_blueprint("services_marketplace")
        scope = {**_EXAMPLE_SCOPE, "currency": "USD"}
        at = "2026-09-10T09:00:00Z"

        def command(state: MarketplaceState, event: str, receipt: Mapping[str, Any], occurred_at: str, reason: str | None = None) -> dict[str, Any]:
            return seal_marketplace_command({"entity": state.entity, "event": event, "transition_ref": f"{event}:{state.scope.entity_ref}", "idempotency_key": f"{state.scope.entity_ref}:{event}", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": occurred_at, "actor_ref": _EXAMPLE_ACTOR, "receipt": dict(receipt), "reason": reason})

        seller = open_seller(plan, {**scope, "entity_ref": "seller-example"}, requested_at=at, actor_ref=_EXAMPLE_ACTOR)
        verify = command(seller, "verify", {"kyc_ref": "kyc-example", "kyc_level": "basic"}, "2026-09-10T10:00:00Z")
        verified = advance_marketplace_entity(plan, seller, verify).state
        assert verified is not None
        active = advance_marketplace_entity(plan, verified, command(verified, "activate", {"payout_account_ref": "payout-account-example"}, "2026-09-10T11:00:00Z")).state
        assert active is not None
        listing = open_listing(plan, {**scope, "entity_ref": "listing-example"}, requested_at="2026-09-11T09:00:00Z", actor_ref=_EXAMPLE_ACTOR, receipt={"category_ref": "home-services", "title": "Example service", "unit_price": "120", "seller_ref": "seller-example"}, seller=active)
        submit = command(listing, "submit", {}, "2026-09-11T09:30:00Z")
        live = advance_marketplace_entity(plan, listing, submit).state
        assert live is not None
        transaction = open_transaction(plan, {**scope, "entity_ref": "transaction-example"}, requested_at="2026-09-12T09:00:00Z", actor_ref=_EXAMPLE_ACTOR, receipt={"listing_ref": "listing-example", "buyer_ref": "buyer-example"}, listing=live)
        fund = command(transaction, "fund", {"payment_ref": "payment-example", "amount": str(transaction.ledger.gross)}, "2026-09-12T09:05:00Z")
        self._built = {
            "compile": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "services_marketplace", "overrides": {"buyer_fee_percent": "3"}},
            "seller": {"plan": plan.to_dict(), "state": seller.to_dict(), "command": verify},
            "listing": {"plan": plan.to_dict(), "state": listing.to_dict(), "command": submit},
            "transaction": {"plan": plan.to_dict(), "state": transaction.to_dict(), "command": fund},
            "assess": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "plan": plan.to_dict(), "sellers": [active.to_dict()], "listings": [live.to_dict()], "transactions": [transaction.to_dict()], "assessed_at": "2026-09-13T00:00:00Z"},
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


def example_marketplace_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _MarketplacePrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
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
        contract["golden_loop"] = MARKETPLACE_BUSINESS_GOLDEN_LOOP
        contract["archetype"] = MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(MARKETPLACE_BUSINESS_PROFILES)
        contract["hard_rules"] = {"kyc_level_meets_blueprint_before_activation": True, "prohibited_categories_never_listed": True, "fees_refunds_and_payouts_derived_from_policy": True, "disputes_only_inside_the_window": True, "payouts_only_after_the_delay": True, "no_identity_check_payment_refund_or_payout_here": True}
        contract["authority_boundary"] = {"agent": "recruits sellers, curates listings, acquires buyers, proposes resolutions", "sdk": "fences seller, listing, and transaction transitions; derives money; measures the marketplace", "spring": "authorizes verification, publication, payments, refunds, payouts; persists entities", "connectors": "execute payment, payout, and CRM operations", "mcp": "projects these primitives and the loop"}
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)])

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "connector_effect_executed": False, "funds_moved": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )

    def _advance(self, context: PrimitiveExecutionContext, inputs: _AdvanceInput) -> PrimitiveExecutionResult[MarketplaceTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the entity scope and the command.")  # type: ignore[return-value]
        try:
            result = advance_marketplace_entity(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])  # type: ignore[return-value]
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(output=result, request_digest=request_digest, external_refs={"entity_ref": scope.entity_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type=f"marketplace.{receipt.entity}_advanced", event_payload={"entity": receipt.entity, "event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind=f"marketplace_{receipt.entity}_transition", evidence_summary="Replay-fenced marketplace transition; candidate until Spring retains it.", summary=(f"{receipt.entity} {receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.entity} {receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)  # type: ignore[return-value]


class CompileMarketplaceBusinessPrimitive(_MarketplacePrimitive[CompileMarketplaceBusinessInput, MarketplaceBusinessLoopPlan]):
    primitive_ref = "blueprint.compile_marketplace_business"
    version = "0.1.0"
    title = "Compile a marketplace-business Company Blueprint into a loop plan"
    description = "Turn a ready-made profile (services_marketplace, goods_marketplace, rental_marketplace, b2b_marketplace) or a custom blueprint (categories, take rate, buyer fee, escrow, KYC level, listing review, dispute window, refund policy, prohibited categories, listing limits, targets) into the onboard → list → acquire → match → transact → fulfil → review → settle → learn plan."
    input_model = CompileMarketplaceBusinessInput
    output_model = MarketplaceBusinessLoopPlan
    risk_level = "low"
    operation_spec = _spec("marketplace_compile_blueprint", "sdk.blueprint.compile_marketplace_business")
    example_inputs: Mapping[str, Any] = _LazyExample("compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileMarketplaceBusinessInput) -> PrimitiveExecutionResult[MarketplaceBusinessLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_marketplace_business_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        bp = plan.blueprint
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest}, event_type="blueprint.marketplace_business_compiled", event_payload={"profile": bp.profile, "categories": len(bp.categories), "take_rate_percent": str(bp.take_rate_percent), "escrow_required": bp.escrow_required, "kyc_level": bp.kyc_level}, evidence_kind="marketplace_business_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {bp.profile} marketplace plan ({len(bp.categories)} categories, {bp.take_rate_percent}% take rate, KYC {bp.kyc_level}).")


class AdvanceSellerPrimitive(_MarketplacePrimitive[AdvanceSellerInput, MarketplaceTransitionResult]):
    primitive_ref = "marketplace.advance_seller"
    version = "0.1.0"
    title = "Advance a seller by one transition"
    description = "Materialize one replay-fenced seller transition: verification at or above the blueprint KYC level, activation with a payout account reference, suspension with strikes, reinstatement, rejection, and offboarding."
    input_model = AdvanceSellerInput
    output_model = MarketplaceTransitionResult
    risk_level = "medium"
    operation_spec = _spec("marketplace_advance_seller", "sdk.marketplace.advance_seller")
    example_inputs: Mapping[str, Any] = _LazyExample("seller")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceSellerInput) -> PrimitiveExecutionResult[MarketplaceTransitionResult]:
        return self._advance(context, inputs)


class AdvanceListingPrimitive(_MarketplacePrimitive[AdvanceListingInput, MarketplaceTransitionResult]):
    primitive_ref = "marketplace.advance_listing"
    version = "0.1.0"
    title = "Advance a listing by one transition"
    description = "Materialize one replay-fenced listing transition: submission into review or straight to live per policy, approval with the review reference, rejection, pause and resume, price updates, sold-out on tracked quantity, and delisting."
    input_model = AdvanceListingInput
    output_model = MarketplaceTransitionResult
    risk_level = "medium"
    operation_spec = _spec("marketplace_advance_listing", "sdk.marketplace.advance_listing")
    example_inputs: Mapping[str, Any] = _LazyExample("listing")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceListingInput) -> PrimitiveExecutionResult[MarketplaceTransitionResult]:
        return self._advance(context, inputs)


class AdvanceTransactionPrimitive(_MarketplacePrimitive[AdvanceTransactionInput, MarketplaceTransitionResult]):
    primitive_ref = "marketplace.advance_transaction"
    version = "0.1.0"
    title = "Advance a transaction by one transition"
    description = "Materialize one replay-fenced transaction transition: funding of the exact gross into escrow or on terms, fulfilment and delivery, acceptance (buyer or elapsed window), dispute inside the window, resolution inside the refund policy with derived refund, payout, and platform revenue, settlement after the payout delay, closure with ratings, and cancellation."
    input_model = AdvanceTransactionInput
    output_model = MarketplaceTransitionResult
    risk_level = "medium"
    operation_spec = _spec("marketplace_advance_transaction", "sdk.marketplace.advance_transaction")
    example_inputs: Mapping[str, Any] = _LazyExample("transaction")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceTransactionInput) -> PrimitiveExecutionResult[MarketplaceTransitionResult]:
        return self._advance(context, inputs)


class AssessMarketplacePrimitive(_MarketplacePrimitive[AssessMarketplaceInput, MarketplaceAssessment]):
    primitive_ref = "marketplace.assess_marketplace"
    version = "0.1.0"
    title = "Assess a marketplace (learn stage)"
    description = "Effect-dark marketplace metrics: sellers, listings, and transactions by status, GMV, take revenue, refunds, escrow held, pending payouts, average order value, liquidity, dispute and refund rates, repeat-buyer rate, and average seller rating, with recommendations against the blueprint targets."
    input_model = AssessMarketplaceInput
    output_model = MarketplaceAssessment
    risk_level = "low"
    operation_spec = _spec("marketplace_assess_marketplace", "sdk.marketplace.assess_marketplace")
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessMarketplaceInput) -> PrimitiveExecutionResult[MarketplaceAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_marketplace(inputs.plan, inputs.sellers, inputs.listings, inputs.transactions, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="ENTITIES_NOT_BOUND", message=str(exc)[:500])
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="marketplace.assessed", event_payload={"sellers": assessment.sellers, "listings": assessment.listings, "transactions": assessment.transactions, "gmv": str(assessment.gmv), "take_revenue": str(assessment.take_revenue), "learnings": list(assessment.learnings)}, evidence_kind="marketplace_assessment", evidence_summary="Marketplace metrics; no effect.", summary=f"{assessment.transactions} transaction(s), GMV {assessment.gmv} {assessment.currency}: {assessment.learnings[0]}")


MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileMarketplaceBusinessPrimitive(),
    AdvanceSellerPrimitive(),
    AdvanceListingPrimitive(),
    AdvanceTransactionPrimitive(),
    AssessMarketplacePrimitive(),
)

MARKETPLACE_BUSINESS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "marketplace_business_golden_loop",
    "golden_loop": MARKETPLACE_BUSINESS_GOLDEN_LOOP,
    "archetype": MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST,
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "modules": {"domain": "lightbulb.marketplace_business_loop", "primitives": "lightbulb.marketplace_business_primitives"},
    "reuses": ["crm.qualify_lead", "compliance.evaluate_regulated_controls (KYC and listing review)", "finance.create_invoice, finance.collect_payment", "communication.write_email, communication.plan_crm_conversation_turn", "service.* dispute cases", "growth.* funnel, customer value, unit economics", "stripe.*, airwallex.* payment and payout connector tools"],
    "primitive_refs": [item.primitive_ref for item in MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.marketplace_business_primitives import MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES", "splice": "*MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register marketplace.supply_demand_to_settled_transaction@0.1.0 with STAGE_ORDER and the three entity transition tables"},
    "company_blueprints": {"note": "register the marketplace_business archetype with MARKETPLACE_BUSINESS_PROFILES; composable with the other archetypes"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES", "MARKETPLACE_BUSINESS_INTEGRATION_MANIFEST", "MARKETPLACE_BUSINESS_PROFILES", "MARKETPLACE_BUSINESS_ARCHETYPE_MANIFEST", "MarketplaceBusinessBlueprint", "MarketplaceBusinessLoopPlan", "MarketplaceState", "compile_marketplace_business_blueprint", "open_seller", "open_listing", "open_transaction", "advance_marketplace_entity", "assess_marketplace"]},
    "non_goals": ["no identity verification, payment, refund, payout, or listing publication executed here", "no bank, card, or identity data on the wire (such fields are refused)", "no certification or production-readiness claim"],
}

__all__ = [
    "MARKETPLACE_BUSINESS_EXECUTABLE_PRIMITIVES",
    "MARKETPLACE_BUSINESS_INTEGRATION_MANIFEST",
    "AdvanceListingInput",
    "AdvanceListingPrimitive",
    "AdvanceSellerInput",
    "AdvanceSellerPrimitive",
    "AdvanceTransactionInput",
    "AdvanceTransactionPrimitive",
    "AssessMarketplaceInput",
    "AssessMarketplacePrimitive",
    "CompileMarketplaceBusinessInput",
    "CompileMarketplaceBusinessPrimitive",
    "RequestScope",
    "example_marketplace_inputs",
]
