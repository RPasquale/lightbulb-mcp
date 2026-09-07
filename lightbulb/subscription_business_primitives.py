"""Executable primitives for the Subscription Business Golden Operating Loop.

``blueprint.compile_subscription_business`` builds the plan from a profile,
``subscription.advance_account`` materializes one replay-fenced account
transition, ``subscription.prorate_plan_change`` computes a deterministic
mid-period proration candidate, and ``subscription.assess_portfolio`` derives
MRR, ARR, ARPA, NRR, churn, trial conversion, LTV, and exposure.  All are
read-only; Spring authorizes every charge, reminder, discount, and provider
subscription change.
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
from lightbulb.subscription_business_loop import (
    STAGE_ORDER,
    SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST,
    SUBSCRIPTION_BUSINESS_GOLDEN_LOOP,
    SUBSCRIPTION_BUSINESS_PROFILES,
    AccountTransitionResult,
    CurrencyCode,
    OpaqueRef,
    ProrationCandidate,
    SubscriptionAccountCommand,
    SubscriptionAccountState,
    SubscriptionBusinessBlueprint,
    SubscriptionBusinessLoopPlan,
    SubscriptionPortfolioAssessment,
    _StrictModel,
    _timestamp,
    advance_subscription_account,
    assess_subscription_portfolio,
    compile_subscription_business_blueprint,
    open_subscription_account,
    prorate_plan_change,
    seal_account_command,
)


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


def _spec(operation_ref: str, tool: str) -> PrimitiveOperationSpec:
    return PrimitiveOperationSpec(operation_ref=operation_ref, tool=tool, effect=ConnectorEffect.READ, approval_required=False, replay_class=PrimitiveOperationReplayClass.SAFE, freshness_class=PrimitiveOperationFreshnessClass.CURRENT, recovery_policy=PrimitiveOperationRecoveryPolicy.NONE)


COMPILE_OPERATION = _spec("subscription_compile_blueprint", "sdk.blueprint.compile_subscription_business")
ADVANCE_OPERATION = _spec("subscription_advance_account", "sdk.subscription.advance_account")
PRORATE_OPERATION = _spec("subscription_prorate_plan_change", "sdk.subscription.prorate_plan_change")
ASSESS_OPERATION = _spec("subscription_assess_portfolio", "sdk.subscription.assess_portfolio")

_EXAMPLE_PROJECT_ID = "40100000-0000-4000-8000-000000000001"
_EXAMPLE_ACTOR = "actor-requester-example"
_EXAMPLE_SCOPE = {"tenant_ref": "authenticated", "company_ref": "selected", "project_ref": "workflow-improvement", "project_id": _EXAMPLE_PROJECT_ID}


class RequestScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str


class CompileSubscriptionBusinessInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    profile: str = Field(min_length=1, max_length=40)
    blueprint: SubscriptionBusinessBlueprint | None = None
    overrides: dict[str, Any] = Field(default_factory=dict)


class AdvanceAccountInput(_StrictModel):
    plan: SubscriptionBusinessLoopPlan
    state: SubscriptionAccountState
    command: SubscriptionAccountCommand


class ProratePlanChangeInput(_StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    old_plan_ref: OpaqueRef
    new_plan_ref: OpaqueRef
    old_price: str = Field(min_length=1, max_length=40)
    new_price: str = Field(min_length=1, max_length=40)
    old_seats: int = Field(default=1, ge=1, le=100_000)
    new_seats: int = Field(default=1, ge=1, le=100_000)
    period_start: str
    period_end: str
    change_at: str
    currency: CurrencyCode = "USD"

    @field_validator("period_start", "period_end", "change_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=str(info.field_name))


class AssessPortfolioInput(_StrictModel):
    plan: SubscriptionBusinessLoopPlan
    accounts: tuple[SubscriptionAccountState, ...] = Field(default_factory=tuple, max_length=2000)
    scope: RequestScope
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


class _ExampleBundle:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        plan = compile_subscription_business_blueprint("saas_self_serve")
        scope = {**_EXAMPLE_SCOPE, "account_ref": "account-example", "customer_ref": "customer-example", "currency": "USD"}
        state = open_subscription_account(plan, scope, opened_at="2026-09-01T00:00:00Z", actor_ref=_EXAMPLE_ACTOR)
        command = seal_account_command({"event": "convert_trial", "transition_ref": "convert:account-example", "idempotency_key": "account-example:convert", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": "2026-09-15T00:00:00Z", "actor_ref": _EXAMPLE_ACTOR, "receipt": {"plan_ref": "plan-pro", "plan_price": "50", "seats": 4, "term_start": "2026-09-15T00:00:00Z", "term_end": "2026-10-15T00:00:00Z", "subscription_snapshot_digest": "c" * 64, "subscription_status": "active"}})
        self._built = {
            "compile": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "profile": "saas_self_serve", "overrides": {"max_save_offers": 2}},
            "advance": {"plan": plan.to_dict(), "state": state.to_dict(), "command": command},
            "prorate": {"scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "old_plan_ref": "plan-pro", "new_plan_ref": "plan-team", "old_price": "50", "new_price": "80", "old_seats": 4, "new_seats": 4, "period_start": "2026-09-15T00:00:00Z", "period_end": "2026-10-15T00:00:00Z", "change_at": "2026-09-30T00:00:00Z", "currency": "USD"},
            "assess": {"plan": plan.to_dict(), "accounts": [state.to_dict()], "scope": _EXAMPLE_SCOPE, "requested_by_ref": _EXAMPLE_ACTOR, "assessed_at": "2026-10-01T00:00:00Z"},
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


def example_subscription_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class _SubscriptionPrimitive(BusinessProcessPrimitive[InputT, OutputT], Generic[InputT, OutputT]):
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
        contract["golden_loop"] = SUBSCRIPTION_BUSINESS_GOLDEN_LOOP
        contract["archetype"] = SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST["archetype"]
        contract["loop_stages"] = list(STAGE_ORDER)
        contract["profiles"] = sorted(SUBSCRIPTION_BUSINESS_PROFILES)
        contract["hard_rules"] = {"bill_amount_derives_from_plan_seats_discount_and_usage": True, "one_open_invoice_at_a_time": True, "dunning_retries_follow_the_schedule_and_are_finite": True, "save_offers_bounded_by_count_and_discount": True, "cancellation_at_period_end_unless_blueprint_says_immediate": True, "renewal_terms_are_contiguous": True, "no_card_charge_or_provider_change_here": True}
        contract["authority_boundary"] = {"agent": "chooses plans, offers, and outreach", "sdk": "derives bills, fences transitions, prorates, and measures", "spring": "authorizes charges, discounts, provider subscription changes; persists accounts", "connectors": "execute Stripe, Xero, HubSpot operations", "mcp": "projects these primitives and the loop"}
        return contract

    def _blocked(self, *, request_digest: str, code: str, message: str) -> PrimitiveExecutionResult[OutputT]:
        blocker = PrimitiveBlocker(code=code, message=message, field="scope" if code == "SCOPE_MISMATCH" else None, retryable=False)
        return PrimitiveExecutionResult[OutputT](status=PrimitiveExecutionStatus.BLOCKED, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=f"{self.title} blocked: {code}.", blockers=[blocker], operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED, request_digest=request_digest, error=blocker)])

    def _preview(self, *, output: OutputT, request_digest: str, external_refs: Mapping[str, str], event_type: str, event_payload: Mapping[str, Any], evidence_kind: str, evidence_summary: str, summary: str, blocker: PrimitiveBlocker | None = None) -> PrimitiveExecutionResult[OutputT]:
        status = PrimitiveExecutionStatus.BLOCKED if blocker else PrimitiveExecutionStatus.PREVIEW
        return PrimitiveExecutionResult[OutputT](
            status=status, primitive_ref=self.primitive_ref, primitive_version=self.version, summary=summary, output=output,
            events=[PrimitiveEvent(type=event_type, payload={**dict(event_payload), "request_digest": request_digest, "connector_effect_executed": False, "card_charged": False})],
            evidence=[PrimitiveEvidence(kind=evidence_kind, summary=evidence_summary, refs={"request_digest": request_digest, **dict(external_refs)})],
            operation_receipts=[PrimitiveOperationReceipt(spec=self.operation_spec, status=PrimitiveOperationStatus.BLOCKED if blocker else PrimitiveOperationStatus.PREVIEW, request_digest=request_digest, external_refs=dict(external_refs), error=blocker)],
            blockers=[blocker] if blocker else [],
        )


class CompileSubscriptionBusinessPrimitive(_SubscriptionPrimitive[CompileSubscriptionBusinessInput, SubscriptionBusinessLoopPlan]):
    primitive_ref = "blueprint.compile_subscription_business"
    version = "0.1.0"
    title = "Compile a subscription-business Company Blueprint into a loop plan"
    description = "Turn a ready-made profile (saas_self_serve, saas_sales_led, membership, subscription_box) or a custom blueprint into the acquire → trial → activate → bill → collect → serve → retain → expand → renew → learn plan bound to existing primitives and connector tools."
    input_model = CompileSubscriptionBusinessInput
    output_model = SubscriptionBusinessLoopPlan
    risk_level = "low"
    operation_spec = COMPILE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("compile")

    def _execute(self, context: PrimitiveExecutionContext, inputs: CompileSubscriptionBusinessInput) -> PrimitiveExecutionResult[SubscriptionBusinessLoopPlan]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            plan = compile_subscription_business_blueprint(inputs.blueprint.to_dict() if inputs.profile == "custom" and inputs.blueprint is not None else inputs.profile, inputs.overrides)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="BLUEPRINT_INVALID", message=str(exc)[:500])
        return self._preview(output=plan, request_digest=request_digest, external_refs={"plan_digest": plan.plan_digest, "blueprint_digest": plan.blueprint.blueprint_digest}, event_type="blueprint.subscription_business_compiled", event_payload={"profile": plan.blueprint.profile, "billing_interval": plan.blueprint.billing_interval, "billing_model": plan.blueprint.billing_model, "trial_days": plan.blueprint.trial_days}, evidence_kind="subscription_business_loop_plan", evidence_summary="Loop plan with stage bindings; nothing executed.", summary=f"Compiled {plan.blueprint.profile} subscription plan ({plan.blueprint.billing_interval}, {plan.blueprint.billing_model}, {plan.blueprint.payment_method}).")


class AdvanceSubscriptionAccountPrimitive(_SubscriptionPrimitive[AdvanceAccountInput, AccountTransitionResult]):
    primitive_ref = "subscription.advance_account"
    version = "0.1.0"
    title = "Advance a subscription account by one transition"
    description = "Materialize one replay-fenced account transition: trial start and conversion, activation, billing at the derived amount, payments and failures with the finite dunning schedule, pause and resume, plan changes with proration, usage, cancellation at period end with bounded save offers, contiguous renewal, and expiry."
    input_model = AdvanceAccountInput
    output_model = AccountTransitionResult
    risk_level = "medium"
    operation_spec = ADVANCE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("advance")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AdvanceAccountInput) -> PrimitiveExecutionResult[AccountTransitionResult]:
        request_digest = _request_digest(inputs.to_dict())
        scope = inputs.state.scope
        if not _scope_matches(RequestScope(tenant_ref=scope.tenant_ref, company_ref=scope.company_ref, project_ref=scope.project_ref, project_id=scope.project_id), inputs.command.actor_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and acting actor must exactly match the account scope and the command.")
        try:
            result = advance_subscription_account(inputs.plan, inputs.state, inputs.command)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="STATE_NOT_BOUND", message=str(exc)[:500])
        receipt = result.receipt
        blocker = None if result.candidate_validated else PrimitiveBlocker(code=str(receipt.rejection_code), message=str(receipt.recovery.instructions)[:500], retryable=receipt.recovery.disposition in {"refresh_state", "await_approval"})
        return self._preview(output=result, request_digest=request_digest, external_refs={"account_ref": scope.account_ref, "transition_ref": receipt.transition_ref, "to_state_digest": receipt.to_state_digest}, event_type="subscription.account_advanced", event_payload={"event": receipt.event, "transition_status": receipt.status, "from_status": receipt.from_status, "to_status": receipt.to_status, "rejection_code": receipt.rejection_code, "recovery": receipt.recovery.disposition}, evidence_kind="subscription_account_transition", evidence_summary="Replay-fenced account transition; candidate until Spring retains it.", summary=(f"{receipt.event}: {receipt.from_status} -> {receipt.to_status} (v{receipt.to_version})." if result.candidate_validated else f"{receipt.event} rejected: {receipt.rejection_code} ({receipt.recovery.disposition})."), blocker=blocker)


class ProratePlanChangePrimitive(_SubscriptionPrimitive[ProratePlanChangeInput, ProrationCandidate]):
    primitive_ref = "subscription.prorate_plan_change"
    version = "0.1.0"
    title = "Prorate a mid-period plan change"
    description = "Deterministic proration: credit the unused fraction of the old plan, charge the same fraction of the new plan, and classify the change as upgrade, downgrade, or lateral. The candidate digest is what a plan-change transition links."
    input_model = ProratePlanChangeInput
    output_model = ProrationCandidate
    risk_level = "low"
    operation_spec = PRORATE_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("prorate")

    def _execute(self, context: PrimitiveExecutionContext, inputs: ProratePlanChangeInput) -> PrimitiveExecutionResult[ProrationCandidate]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            candidate = prorate_plan_change(old_plan_ref=inputs.old_plan_ref, new_plan_ref=inputs.new_plan_ref, old_price=inputs.old_price, new_price=inputs.new_price, old_seats=inputs.old_seats, new_seats=inputs.new_seats, period_start=inputs.period_start, period_end=inputs.period_end, change_at=inputs.change_at, currency=inputs.currency)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="PRORATION_INVALID", message=str(exc)[:500])
        return self._preview(output=candidate, request_digest=request_digest, external_refs={"proration_digest": candidate.proration_digest}, event_type="subscription.plan_change_prorated", event_payload={"direction": candidate.direction, "net_amount": str(candidate.net_amount), "unused_fraction": str(candidate.unused_fraction)}, evidence_kind="subscription_proration", evidence_summary="Deterministic proration candidate; no invoice or credit issued.", summary=f"{candidate.direction}: credit {candidate.credit_for_unused}, charge {candidate.charge_for_remaining}, net {candidate.net_amount} {candidate.currency}.")


class AssessSubscriptionPortfolioPrimitive(_SubscriptionPrimitive[AssessPortfolioInput, SubscriptionPortfolioAssessment]):
    primitive_ref = "subscription.assess_portfolio"
    version = "0.1.0"
    title = "Assess a subscription portfolio (learn stage)"
    description = "Effect-dark metrics from account ledgers: MRR, ARR, ARPA, starting/expansion/contraction/churned MRR, net revenue retention, gross churn, trial conversion, LTV, past-due exposure, and recommendations against the blueprint targets."
    input_model = AssessPortfolioInput
    output_model = SubscriptionPortfolioAssessment
    risk_level = "low"
    operation_spec = ASSESS_OPERATION
    example_inputs: Mapping[str, Any] = _LazyExample("assess")

    def _execute(self, context: PrimitiveExecutionContext, inputs: AssessPortfolioInput) -> PrimitiveExecutionResult[SubscriptionPortfolioAssessment]:
        request_digest = _request_digest(inputs.to_dict())
        if not _scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self._blocked(request_digest=request_digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            assessment = assess_subscription_portfolio(inputs.plan, inputs.accounts, assessed_at=inputs.assessed_at)
        except ValueError as exc:
            return self._blocked(request_digest=request_digest, code="ACCOUNTS_NOT_BOUND", message=str(exc)[:500])
        return self._preview(output=assessment, request_digest=request_digest, external_refs={"assessment_digest": assessment.assessment_digest}, event_type="subscription.portfolio_assessed", event_payload={"accounts": assessment.accounts, "mrr": str(assessment.mrr), "gross_churn_percent": None if assessment.gross_churn_percent is None else str(assessment.gross_churn_percent), "learnings": list(assessment.learnings)}, evidence_kind="subscription_portfolio_assessment", evidence_summary="Portfolio metrics; no effect.", summary=f"{assessment.accounts} account(s), MRR {assessment.mrr} {assessment.currency}: {assessment.learnings[0]}")


SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    CompileSubscriptionBusinessPrimitive(),
    AdvanceSubscriptionAccountPrimitive(),
    ProratePlanChangePrimitive(),
    AssessSubscriptionPortfolioPrimitive(),
)

SUBSCRIPTION_BUSINESS_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "subscription_business_golden_loop",
    "golden_loop": SUBSCRIPTION_BUSINESS_GOLDEN_LOOP,
    "archetype": SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST,
    "base": "origin/main d6528edc87ee79ad5fb2c2d39339901a99517b21",
    "modules": {"domain": "lightbulb.subscription_business_loop", "primitives": "lightbulb.subscription_business_primitives"},
    "reuses": ["commercial.propose_operations_transition (activate_subscription, propose_recurring_billing, propose_usage_billing, prepare_renewal)", "commercial_controls subscription, usage billing, and renewal snapshots (by digest)", "finance.create_invoice", "finance.collect_payment", "finance.reconcile_stripe_settlements", "growth.* customer value, price move, unit economics"],
    "primitive_refs": [item.primitive_ref for item in SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES],
    "executable_registry": {"file": "lightbulb/executable_primitives.py", "import": "from lightbulb.subscription_business_primitives import SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES", "splice": "*SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES in BUILTIN_EXECUTABLE_PRIMITIVES"},
    "golden_loop_registry": {"note": "register subscription.trial_to_renewal_business@0.1.0 with STAGE_ORDER and the account event table"},
    "company_blueprints": {"note": "register the subscription_business archetype with SUBSCRIPTION_BUSINESS_PROFILES; composable with service_business and product_commerce"},
    "public_exports": {"file": "lightbulb/__init__.py", "names": ["SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES", "SUBSCRIPTION_BUSINESS_INTEGRATION_MANIFEST", "SUBSCRIPTION_BUSINESS_PROFILES", "SUBSCRIPTION_BUSINESS_ARCHETYPE_MANIFEST", "SubscriptionBusinessBlueprint", "SubscriptionBusinessLoopPlan", "SubscriptionAccountState", "ProrationCandidate", "compile_subscription_business_blueprint", "open_subscription_account", "advance_subscription_account", "prorate_plan_change", "assess_subscription_portfolio"]},
    "non_goals": ["no card charge, reminder, discount, or provider subscription change executed here", "no replacement of the commercial operations lifecycle commands", "no certification or production-readiness claim"],
}

__all__ = [
    "ADVANCE_OPERATION",
    "ASSESS_OPERATION",
    "COMPILE_OPERATION",
    "PRORATE_OPERATION",
    "SUBSCRIPTION_BUSINESS_EXECUTABLE_PRIMITIVES",
    "SUBSCRIPTION_BUSINESS_INTEGRATION_MANIFEST",
    "AdvanceAccountInput",
    "AdvanceSubscriptionAccountPrimitive",
    "AssessPortfolioInput",
    "AssessSubscriptionPortfolioPrimitive",
    "CompileSubscriptionBusinessInput",
    "CompileSubscriptionBusinessPrimitive",
    "ProratePlanChangeInput",
    "ProratePlanChangePrimitive",
    "RequestScope",
    "example_subscription_inputs",
]
