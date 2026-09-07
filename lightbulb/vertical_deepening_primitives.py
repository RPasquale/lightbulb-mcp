"""Executable primitives for the vertical deepening: close reads, next touch, launch request, billing observation.

All previews.  Each takes inputs the caller already holds (a close state, a
prospect state and its sequence, a campaign state, a Stripe invoice read with
provenance) and returns a sealed plan, request, or observation; the platform
performs every read and write behind its own fences.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import Field, field_validator

from lightbulb.company_engine_core import BoundedText, OpaqueRef, Sha256Digest, ShortText, StrictModel, stable_digest, timestamp
from lightbulb.company_engine_primitives_base import EXAMPLE_ACTOR, EXAMPLE_SCOPE, EnginePrimitive, LazyExample, RequestScope, read_spec, request_digest, scope_matches
from lightbulb.company_execution_bridge import BridgeError, ObservationProvenance
from lightbulb.finance_close_engine import CLOSE_LIFECYCLE, FinanceCloseLoopPlan, compile_finance_close_blueprint, open_period_close
from lightbulb.finance_close_observations import CloseReadPlan, plan_close_reads
from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE, GrowthEngineLoopPlan, compile_growth_engine_blueprint, open_campaign, plan_campaign_portfolio
from lightbulb.growth_execution import GrowthExecutionError, LaunchRequest, creative_from_variants, plan_launch
from lightbulb.live_signal_observations import BillingObservation, billing_from_stripe_invoices
from lightbulb.pipeline_engine_loop import PROSPECT_LIFECYCLE, PipelineEngineLoopPlan, SequencePlan, compile_pipeline_engine_blueprint, evaluate_icp_fit, open_prospect, plan_sequence
from lightbulb.pipeline_execution import ConsentRegistry, PipelineExecutionError, TouchRequest, plan_next_touch
from lightbulb.primitive_runtime import BusinessProcessPrimitive, PrimitiveExecutionContext, PrimitiveExecutionResult

VERTICAL_STAGES: tuple[str, ...] = ("plan_close_reads", "plan_next_touch", "plan_launch", "observe_billing")
_PROFILES = ("b2b_saas", "dtc_commerce", "services_firm", "marketplace")


def _seal_command(spec: Any, state: Any, event: str, receipt: Mapping[str, Any], *, at: str) -> dict[str, Any]:
    return spec.seal_command({"event": event, "transition_ref": f"{event}:{state.version}", "idempotency_key": f"{event}:{state.version}", "expected_version": state.version, "expected_state_digest": state.state_digest, "occurred_at": at, "actor_ref": EXAMPLE_ACTOR, "receipt": receipt})


def _example_eligibility() -> tuple[Any, Any, str]:
    """Synthetic, fixed provider observations for executable documentation only."""
    from lightbulb import permission_register as permissions
    from lightbulb.company_operating_system import compile_company_operating_blueprint
    operating = compile_company_operating_blueprint("b2b_saas")
    plan = permissions.compile_permission_register("company-example", operating_plan=operating)
    endpoint = "a1" * 32
    def observed(event: str, at: str) -> Any:
        payload = {"company_ref": plan.company_ref, "endpoint_digest": endpoint, "digest_method": "hmac_sha256", "key_ref": "example-endpoint-key", "channel": "email", "event": event, "occurred_at": at, "basis": "express", "confirmed": event == "confirm", "explicit_choice": True, "operator_import": False}
        provenance = ObservationProvenance(lane="governed_read", source_tool="ecommerce.get_customer" if event == "capture" else "gmail.get_thread", observation_ref=f"example-consent:{event}", provenance_digest=stable_digest({"synthetic_example": event}), output_digest=stable_digest(payload), completed_at=at)
        return permissions.permission_observation(provenance, payload)
    consent = permissions.open_contact_endpoint(plan, {**EXAMPLE_SCOPE, "entity_ref": "example-endpoint", "currency": "CAD"}, receipt=permissions.capture_receipt(observed("capture", "2026-10-01T09:00:00Z")), opened_at="2026-10-01T09:00:00Z", actor_ref=EXAMPLE_ACTOR)
    consent = permissions.advance_contact_endpoint(plan, consent, _seal_command(permissions.CONSENT_LIFECYCLE, consent, "confirm", permissions.confirm_receipt(observed("confirm", "2026-10-01T10:00:00Z")), at="2026-10-01T10:00:00Z")).state
    proof, suppression = permissions.eligibility_receipt([permissions.register_snapshot(consent, plan)], channel="email", endpoints=[endpoint], now="2026-10-02T09:00:00Z")
    return proof, suppression, endpoint


class _Examples:
    def __init__(self) -> None:
        self._built: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        if self._built is not None:
            return self._built
        close_plan = compile_finance_close_blueprint("weekly_close")
        close = open_period_close(close_plan, {**EXAMPLE_SCOPE, "entity_ref": "close-example-1", "currency": "CAD"}, period_start="2026-10-05T00:00:00Z", period_end="2026-10-12T00:00:00Z", ledger_ref="xero-main", preparer_ref="user-preparer-example", opened_at="2026-10-05T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        eligibility, suppression, endpoint = _example_eligibility()
        pipeline_plan = compile_pipeline_engine_blueprint("b2b_saas_outbound", {"permission_company_ref": "company-example", "currency": "CAD"})
        facts = {"prospect_ref": "prospect-example-1", "account_ref": "account-example-1", "industry": "software", "employees": 120, "region": "CA", "title": "VP Operations", "signals": ["hiring_ops"], "flags": [], "source_ref": "list-example"}
        prospect = open_prospect(pipeline_plan, {**EXAMPLE_SCOPE, "entity_ref": "prospect-example-1", "currency": pipeline_plan.blueprint.currency}, facts=facts, fit=evaluate_icp_fit(pipeline_plan, facts), opened_at="2026-10-01T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        sequence_ref = pipeline_plan.blueprint.sequences[0].sequence_ref
        sequence = plan_sequence(pipeline_plan, prospect_ref="prospect-example-1", sequence_ref=sequence_ref, starts_at="2026-10-02T09:00:00Z")
        prospect = PROSPECT_LIFECYCLE.advance(pipeline_plan, prospect, _seal_command(PROSPECT_LIFECYCLE, prospect, "enrich", {"enrichment_ref": "enrichment:example", "suppression_check_ref": "suppression-check-example"}, at="2026-10-01T01:00:00Z")).state
        prospect = PROSPECT_LIFECYCLE.advance(pipeline_plan, prospect, _seal_command(PROSPECT_LIFECYCLE, prospect, "sequence", {"sequence_ref": sequence_ref, "sequence_plan_digest": sequence.sequence_plan_digest, "sequence_plan": sequence.to_dict()}, at="2026-10-01T02:00:00Z")).state
        growth_plan = compile_growth_engine_blueprint("b2b_saas", {"permission_company_ref": "company-example", "currency": "CAD"})
        portfolio = plan_campaign_portfolio(growth_plan, period_start="2026-10-01T00:00:00Z", period_end="2026-10-31T00:00:00Z", total_budget="400", allocations=[{"channel": "email_lifecycle", "objective": "retain", "audience_ref": "aud-trialists", "budget": "400"}])
        campaign = open_campaign(growth_plan, {**EXAMPLE_SCOPE, "entity_ref": "campaign-example-1", "currency": growth_plan.blueprint.currency}, portfolio=portfolio, envelope_ref=portfolio.envelopes[0].envelope_ref, opened_at="2026-10-01T00:00:00Z", actor_ref=EXAMPLE_ACTOR)
        variants = {"status": "completed", "experiments": [{"content_id": "c-1", "platform": "email", "original_title": "Close your books in a day", "variants": [{"variant_id": "variant-example-1", "variant_type": "hook", "text": "Your close, done by Tuesday", "hypothesis": "urgency", "target_metric": "open_rate"}], "test_duration_days": 7, "success_metric": "open_rate", "minimum_sample_size": 500}]}
        creative = {**creative_from_variants(variants, variant_id="variant-example-1"), "body": "Explore our tools for finance teams.", "eligibility_receipt": eligibility.to_dict(), "suppression_digest": suppression.suppression_digest}
        campaign = CAMPAIGN_LIFECYCLE.advance(growth_plan, campaign, _seal_command(CAMPAIGN_LIFECYCLE, campaign, "compose", creative, at="2026-10-02T09:00:00Z")).state
        if campaign.ledger.approval_required:
            from lightbulb.company_execution_bridge import bind_approval, command_with_approval, engine_approval_request
            campaign = CAMPAIGN_LIFECYCLE.advance(growth_plan, campaign, _seal_command(CAMPAIGN_LIFECYCLE, campaign, "submit_for_approval", {}, at="2026-10-02T09:00:00Z")).state
            command = _seal_command(CAMPAIGN_LIFECYCLE, campaign, "approve", {}, at="2026-10-02T09:00:00Z")
            refusal = CAMPAIGN_LIFECYCLE.advance(growth_plan, campaign, command)
            approval = engine_approval_request(refusal, command, engine="growth_engine", entity_ref=campaign.scope.entity_ref, plan_digest=growth_plan.plan_digest, summary="Review example campaign", description="Synthetic approved task for executable documentation", risk_level=5)
            binding = bind_approval({"id": "example-campaign-approval", "approvalType": "sdk_engine_transition", "status": "APPROVED", "decidedBy": "example-human-reviewer", "decidedAt": "2026-10-02T09:00:00Z", "contextData": approval.to_platform_body()["contextData"]}, approval)
            approved = command_with_approval(binding, command, state=campaign, occurred_at="2026-10-02T09:00:00Z")
            campaign = CAMPAIGN_LIFECYCLE.advance(growth_plan, campaign, CAMPAIGN_LIFECYCLE.seal_command(approved)).state
        provenance = {"lane": "host_read", "source_tool": "stripe.list_invoices", "observation_ref": "read-example-1", "provenance_digest": "d" * 64, "output_digest": "e" * 64, "completed_at": "2026-10-20T00:00:00Z", "window_start": "2026-09-20T00:00:00Z", "window_end": "2026-10-20T00:00:00Z"}
        invoices = [{"id": "in_example", "customer": "cus_example", "currency": "cad", "status": "paid", "amount_due": 19900, "amount_paid": 19900, "created": 1790000000, "status_transitions": {"paid_at": 1790500000}, "lines": {"data": [{"amount": 19900, "price": {"id": "price_example", "nickname": "team", "recurring": {"interval": "month"}}, "period": {"start": 1789000000, "end": 1791592000}}]}}]
        self._built = {
            "close_reads": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": close_plan.to_dict(), "state": close.to_dict(), "ledger": "xero"},
            "next_touch": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": pipeline_plan.to_dict(), "state": prospect.to_dict(), "sequence": sequence.to_dict(), "now": sequence.touches[0].not_before, "to_address_ref": "contact-example-1", "subject": "Quick question about your close", "body": "Hello, a short note about closing the books faster.", "claim_refs": [], "eligibility_receipt": eligibility.to_dict(), "suppression_digest": suppression.suppression_digest, "endpoint_digest": endpoint, "channel_sources": []},
            "launch": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "plan": growth_plan.to_dict(), "state": campaign.to_dict(), "recipients": 1, "subject": creative["headline"], "body": creative["body"], "tool": "notifications.send_email", "audience_list_ref": "list-trialists-example", "now": "2026-10-02T09:00:00Z", "eligibility_receipt": eligibility.to_dict(), "suppression_digest": suppression.suppression_digest, "endpoint_digests": [endpoint]},
            "billing": {"scope": EXAMPLE_SCOPE, "requested_by_ref": EXAMPLE_ACTOR, "provenance": provenance, "invoices": invoices, "currency": "CAD", "now": "2026-10-20T00:00:00Z"},
        }
        return self._built


_EXAMPLES = _Examples()


def example_vertical_inputs() -> dict[str, Any]:
    return {key: dict(value) for key, value in _EXAMPLES.get().items()}


class PlanCloseReadsInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: FinanceCloseLoopPlan
    state: dict[str, Any]
    ledger: ShortText


class PlanCloseReadsPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "finance_close.plan_close_reads"
    version = "0.1.0"
    title = "Plan the ledger and settlement reads a finance close needs now"
    description = "From a persisted close state and the ledger system, list the exact governed reads (trial balance, Stripe settlements, open invoices, period status) that would supply the close's next receipts; nothing is read here."
    input_model = PlanCloseReadsInput
    output_model = CloseReadPlan
    risk_level = "low"
    operation_spec = read_spec("finance_close_plan_close_reads", "sdk.finance_close.plan_close_reads")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "close_reads")
    golden_loop = "finance.period_close_to_verified_books@0.1.0"
    engine = "finance_close"
    loop_stages = VERTICAL_STAGES
    profiles = _PROFILES
    hard_rules = {"reads_from_status_only": True, "account_map_is_operator_input": True, "nothing_read_here": True}
    authority_boundary = {"agent": "supplies the account map and hands back reads", "sdk": "plans reads and converts receipts", "spring": "executes governed reads and journals them", "connectors": "Xero, QuickBooks, Stripe reads", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanCloseReadsInput) -> PrimitiveExecutionResult[CloseReadPlan]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            _, state = CLOSE_LIFECYCLE.bind(inputs.plan, inputs.state)
            plan = plan_close_reads(inputs.plan, state, ledger=inputs.ledger)
        except (BridgeError, ValueError) as exc:
            return self.blocked(digest=digest, code=getattr(exc, "code", "CLOSE_READ_PLAN_INVALID"), message=str(exc))
        return self.preview(output=plan, digest=digest, external_refs={"read_plan_digest": plan.plan_digest, "close_ref": plan.close_ref}, event_type="finance_close.reads_planned", event_payload={"status": plan.close_status, "reads": [item.kind for item in plan.reads]}, evidence_kind="close_read_plan", evidence_summary="Reads planned; none executed.", summary=f"{len(plan.reads)} read(s) planned for {plan.close_ref} at {plan.close_status}.")


class PlanNextTouchInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: PipelineEngineLoopPlan
    state: dict[str, Any]
    sequence: SequencePlan
    now: str
    to_address_ref: OpaqueRef
    subject: ShortText | None = None
    body: BoundedText
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    consents: ConsentRegistry | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    endpoint_digest: Sha256Digest | None = None
    channel_sources: tuple[dict[str, Any], ...] | None = None

    @field_validator("claim_refs", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")


class PlanNextTouchPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "pipeline.plan_next_touch"
    version = "0.1.0"
    title = "Plan the next outreach touch as an exact platform request"
    description = "From a sequenced prospect and its sequence plan, return the exact write the platform must execute for the next step (tool, arguments, idempotency key, consent), refusing touches that are not due, too soon, or unconsented; nothing is sent here."
    input_model = PlanNextTouchInput
    output_model = TouchRequest
    risk_level = "medium"
    operation_spec = read_spec("pipeline_plan_next_touch", "sdk.pipeline.plan_next_touch")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "next_touch")
    golden_loop = "revenue.icp_to_qualified_pipeline@0.1.0"
    engine = "pipeline_engine"
    loop_stages = VERTICAL_STAGES
    profiles = _PROFILES
    hard_rules = {"idempotency_from_prospect_sequence_step": True, "consent_from_sealed_registry": True, "nothing_sent_here": True}
    authority_boundary = {"agent": "supplies the message and recipient ref", "sdk": "plans the request and binds the receipt", "spring": "executes the write behind approval", "connectors": "Gmail, LinkedIn, Twilio writes", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanNextTouchInput) -> PrimitiveExecutionResult[TouchRequest]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            _, state = PROSPECT_LIFECYCLE.bind(inputs.plan, inputs.state)
            if any(getattr(state.scope, key) != getattr(inputs.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")):
                return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="The prospect must belong to the requesting scope.")
            request = plan_next_touch(inputs.plan, state, inputs.sequence, now=inputs.now, to_address=inputs.to_address_ref, subject=inputs.subject, body=inputs.body, claim_refs=list(inputs.claim_refs), consents=inputs.consents, eligibility_receipt=inputs.eligibility_receipt, suppression_digest=inputs.suppression_digest, endpoint_digest=inputs.endpoint_digest, channel_sources=inputs.channel_sources)
        except PipelineExecutionError as exc:
            return self.blocked(digest=digest, code=exc.code, message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="TOUCH_INPUT_INVALID", message=str(exc))
        return self.preview(output=request, digest=digest, external_refs={"touch_request_digest": request.request_digest, "idempotency_key": request.idempotency_key}, event_type="pipeline.touch_planned", event_payload={"prospect_ref": request.prospect_ref, "step": request.step, "channel": request.channel, "tool": request.tool}, evidence_kind="pipeline_touch_request", evidence_summary="Request planned; nothing sent.", summary=f"Step {request.step} ({request.channel}) for {request.prospect_ref} via {request.tool}; execute behind approval.")


class PlanLaunchInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    plan: GrowthEngineLoopPlan
    state: dict[str, Any]
    recipients: int = Field(ge=1, le=1_000_000)
    subject: ShortText
    body: BoundedText
    tool: ShortText = "notifications.send_email"
    audience_list_ref: OpaqueRef | None = None
    now: str | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    endpoint_digests: tuple[Sha256Digest, ...] | None = None
    claim_projections: tuple[dict[str, Any], ...] = ()

    @field_validator("now")
    @classmethod
    def _now(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="now")


class PlanLaunchPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "growth.plan_launch"
    version = "0.1.0"
    title = "Plan a campaign launch as an exact platform request"
    description = "From an approved campaign on an executable channel, return the exact write that launches it (tool, arguments, idempotency key); paid channels without a platform adapter are refused rather than simulated; nothing is sent or spent here."
    input_model = PlanLaunchInput
    output_model = LaunchRequest
    risk_level = "medium"
    operation_spec = read_spec("growth_plan_launch", "sdk.growth.plan_launch")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "launch")
    golden_loop = "growth.store_truth_to_attributed_revenue@0.1.0"
    engine = "growth_engine"
    loop_stages = VERTICAL_STAGES
    profiles = _PROFILES
    hard_rules = {"executable_channels_only": True, "approval_before_launch": True, "nothing_sent_or_spent_here": True}
    authority_boundary = {"agent": "supplies the message and list ref", "sdk": "plans the request and binds the receipt", "spring": "executes the write behind approval", "connectors": "email sends", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: PlanLaunchInput) -> PrimitiveExecutionResult[LaunchRequest]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            _, state = CAMPAIGN_LIFECYCLE.bind(inputs.plan, inputs.state)
            if any(getattr(state.scope, key) != getattr(inputs.scope, key) for key in ("tenant_ref", "company_ref", "project_ref", "project_id")):
                return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="The campaign must belong to the requesting scope.")
            request = plan_launch(inputs.plan, state, recipients=inputs.recipients, subject=inputs.subject, body=inputs.body, tool=inputs.tool, audience_list_ref=inputs.audience_list_ref, now=inputs.now, eligibility_receipt=inputs.eligibility_receipt, suppression_digest=inputs.suppression_digest, endpoint_digests=inputs.endpoint_digests, claim_projections=inputs.claim_projections)
        except GrowthExecutionError as exc:
            return self.blocked(digest=digest, code=exc.code, message=str(exc))
        except ValueError as exc:
            return self.blocked(digest=digest, code="LAUNCH_INPUT_INVALID", message=str(exc))
        return self.preview(output=request, digest=digest, external_refs={"launch_request_digest": request.request_digest, "idempotency_key": request.idempotency_key}, event_type="growth.launch_planned", event_payload={"campaign_ref": request.campaign_ref, "channel": request.channel, "tool": request.tool, "recipients": request.recipients}, evidence_kind="growth_launch_request", evidence_summary="Request planned; nothing sent.", summary=f"Launch {request.campaign_ref} on {request.channel} via {request.tool} to {request.recipients} recipient(s); execute behind approval.")


class ObserveBillingInput(StrictModel):
    scope: RequestScope
    requested_by_ref: OpaqueRef
    provenance: ObservationProvenance
    invoices: tuple[dict[str, Any], ...] = Field(default_factory=tuple, max_length=5000)
    currency: ShortText
    now: str

    @field_validator("invoices", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("now")
    @classmethod
    def _now(cls, value: str) -> str:
        return timestamp(value, field_name="now")


class ObserveBillingPrimitive(EnginePrimitive[Any, Any]):
    primitive_ref = "saas_ops.observe_billing"
    version = "0.1.0"
    title = "Derive per-account billing (MRR, paid, past due) from a Stripe invoice read"
    description = "Seal a Stripe invoice read (with provenance) into per-account MRR from recurring lines, amounts paid in the window, and past-due balances with days overdue, ready to merge with usage for saas_ops.observe_usage and to raise churn-risk signals; nothing is charged or changed."
    input_model = ObserveBillingInput
    output_model = BillingObservation
    risk_level = "low"
    operation_spec = read_spec("saas_ops_observe_billing", "sdk.saas_ops.observe_billing")
    example_inputs: Mapping[str, Any] = LazyExample(_EXAMPLES, "billing")
    golden_loop = "saas.launched_product_to_compounding_revenue@0.1.0"
    engine = "saas_operating_engine"
    loop_stages = VERTICAL_STAGES
    profiles = _PROFILES
    hard_rules = {"mrr_from_recurring_lines_only": True, "past_due_raises_churn_risk": True, "nothing_charged_here": True}
    authority_boundary = {"agent": "performs the host-lane read and hands back provenance", "sdk": "derives billing and signals", "spring": "owns the connector and journals reads", "connectors": "Stripe invoices", "mcp": "projects this primitive"}

    def _execute(self, context: PrimitiveExecutionContext, inputs: ObserveBillingInput) -> PrimitiveExecutionResult[BillingObservation]:
        digest = request_digest(inputs.to_dict())
        if not scope_matches(inputs.scope, inputs.requested_by_ref, context):
            return self.blocked(digest=digest, code="SCOPE_MISMATCH", message="Runtime scope and requesting actor must exactly match the request.")
        try:
            billing = billing_from_stripe_invoices(inputs.provenance, list(inputs.invoices), currency=inputs.currency, now=inputs.now)
        except (BridgeError, ValueError) as exc:
            return self.blocked(digest=digest, code=getattr(exc, "code", "BILLING_INPUT_INVALID"), message=str(exc))
        past_due = [row.account_ref for row in billing.accounts if row.past_due > 0]
        return self.preview(output=billing, digest=digest, external_refs={"provenance_digest": billing.provenance_digest}, event_type="saas_ops.billing_observed", event_payload={"accounts": len(billing.accounts), "past_due_accounts": past_due}, evidence_kind="saas_billing_observation", evidence_summary="Billing derived from the read; nothing charged.", summary=f"{len(billing.accounts)} account(s) observed; {len(past_due)} past due.")


VERTICAL_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (PlanCloseReadsPrimitive(), PlanNextTouchPrimitive(), PlanLaunchPrimitive(), ObserveBillingPrimitive())

VERTICAL_INTEGRATION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.capability_pack_integration_manifest.v1",
    "capability_pack": "vertical_deepening",
    "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0",
    "engine": {"schema": "lightbulb.company_engine_manifest.v1", "engine": "vertical_deepening", "golden_loop": "company.blueprint_to_governed_operating_cadence@0.1.0", "stages": list(VERTICAL_STAGES), "required_connectors": ["xero", "quickbooks", "stripe", "gmail", "hubspot", "notifications", "posthog", "freshservice"], "hard_rules": ["close receipts come from governed ledger and settlement reads through an operator account map", "outreach touches and campaign launches are exact requests executed behind approval and recorded from execution receipts", "billing, usage, threads, and tickets convert through adapters with provenance; nothing executes here"]},
    "modules": {"finance_close_observations": "lightbulb.finance_close_observations", "pipeline_execution": "lightbulb.pipeline_execution", "growth_execution": "lightbulb.growth_execution", "live_signal_observations": "lightbulb.live_signal_observations", "primitives": "lightbulb.vertical_deepening_primitives"},
    "reuses": ["finance_close_engine", "pipeline_engine_loop", "growth_engine_loop", "saas_operating_loop", "service_delivery_engine", "company_execution_bridge", "company_observation_jobs"],
    "required_connectors": ["xero", "quickbooks", "stripe", "gmail", "hubspot", "notifications", "posthog", "freshservice"],
    "primitive_refs": [item.primitive_ref for item in VERTICAL_EXECUTABLE_PRIMITIVES],
    "non_goals": ["no read or write executed here", "no certification or production-readiness claim"],
}

__all__ = ["VERTICAL_EXECUTABLE_PRIMITIVES", "VERTICAL_INTEGRATION_MANIFEST", "ObserveBillingInput", "ObserveBillingPrimitive", "PlanCloseReadsInput", "PlanCloseReadsPrimitive", "PlanLaunchInput", "PlanLaunchPrimitive", "PlanNextTouchInput", "PlanNextTouchPrimitive", "example_vertical_inputs"]
