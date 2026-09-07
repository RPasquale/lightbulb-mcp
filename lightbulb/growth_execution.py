"""Growth engine execution bindings: creatives from the content agents, launches as exact requests, reallocation applied.

The campaign lifecycle already fences drafting, composing, approving,
launching, observing, and attributing.  What was missing:

* ``creative_from_variants`` turns a ``content_generate_variants`` agent
  result into the ``compose`` receipt for one chosen variant (the operator
  picks the variant; the engine's brand-safety and claim guards still run).
* ``plan_launch`` turns an approved campaign into the exact platform write
  that launches it.  Today that is the email lifecycle channel through the
  governed email tools (a write behind approval, idempotency key derived
  from the campaign).  Paid channels have no platform adapter yet, so
  ``plan_launch`` refuses them with ``CHANNEL_EXECUTION_UNSUPPORTED`` rather
  than pretending; their launches stay hand-receipted from the ad platform
  with provenance.
* ``launch_receipt`` binds the platform's write execution receipt (approval
  carried) to the ``launch`` event through the execution bridge, and refuses
  a receipt for a different tool than the request named.
* ``apply_reallocation`` turns a ``ReallocationProposal`` that a person
  approved into the next portfolio: the same envelopes with the proposed
  shifts applied, sealed through the engine's own portfolio planner, so a
  shift can never exceed what the proposal stated.

Nothing sends or spends here; the platform executes the request behind the
approval the receipt carries.

New plans require the permission register by default. An explicit
``require_permission_register=False`` preserves compatibility/simulation
mechanics; such a request does not prove eligible outreach. Hosts bind
recipient addresses to keyed endpoints, supply current complete permission
state, and atomically reserve/record sends before accepting concurrent work.
"""

from __future__ import annotations

from lightbulb.company_engine_core import stable_digest

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    BoundedText,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    seal,
    sealed_digest,
    skip_digests,
)
from lightbulb.company_execution_bridge import BoundExecution, ExecutionReceipt, bind_execution
from lightbulb.growth_engine_loop import CampaignPortfolio, GrowthEngineLoopPlan, ReallocationProposal, plan_campaign_portfolio

LAUNCH_REQUEST_SCHEMA = "lightbulb.growth_launch_request.v1"
EMAIL_TOOLS: tuple[str, ...] = ("notifications.send_email", "gmail.send_email", "ses.send_email", "microsoft.send_email")
EXECUTABLE_CHANNELS: Mapping[str, tuple[str, ...]] = {"email_lifecycle": EMAIL_TOOLS}
UNSUPPORTED_CHANNELS: tuple[str, ...] = ("paid_social_meta", "paid_search_google", "paid_social_tiktok", "organic_social", "sms_lifecycle", "seo_content", "affiliate")


class GrowthExecutionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GrowthExecutionError(code, message)


# --------------------------------------------------------------------------- #
# Creatives from the content agents
# --------------------------------------------------------------------------- #


def creative_from_variants(result: Mapping[str, Any], *, variant_id: str, trace_ref: str | None = None, claim_refs: Sequence[str] = (), consent_ref: str | None = None) -> dict[str, Any]:
    """The ``compose`` receipt for one chosen variant of a ``content_generate_variants`` result."""

    raw = dict(detached(result))
    _require(str(raw.get("status", "")).lower() == "completed", "VARIANTS_NOT_COMPLETED", f"the content agent reported {raw.get('status') or 'no status'}")
    chosen: Mapping[str, Any] | None = None
    original_title = ""
    for experiment in raw.get("experiments") or []:
        for variant in (experiment or {}).get("variants") or []:
            if str((variant or {}).get("variant_id")) == variant_id:
                chosen = variant
                original_title = str((experiment or {}).get("original_title") or "")
                break
        if chosen is not None:
            break
    _require(chosen is not None, "VARIANT_UNKNOWN", f"no variant {variant_id!r} in the result")
    assert chosen is not None
    text = str(chosen.get("text") or "").strip()
    _require(bool(text), "VARIANT_TEXT_MISSING", "the chosen variant carries text")
    kind = str(chosen.get("variant_type") or "")
    headline = text if kind in ("hook", "title", "cta") else (original_title or text[:120])
    body = text if kind in ("body_opening", "cta") else None
    receipt: dict[str, Any] = {"creative_ref": f"variant:{variant_id}", "headline": headline[:200], "claim_refs": list(claim_refs), "evidence_refs": [f"content_variant:{variant_id}", *( [f"trace:{trace_ref}"] if trace_ref else [] )]}
    if body:
        receipt["body"] = body
    if consent_ref:
        receipt["consent_ref"] = consent_ref
    return receipt


# --------------------------------------------------------------------------- #
# Launch as an exact request
# --------------------------------------------------------------------------- #


class LaunchRequest(StrictModel):
    schema_id: str = Field(default=LAUNCH_REQUEST_SCHEMA, alias="schema")
    campaign_ref: OpaqueRef
    channel: ShortText
    tool: ShortText
    audience_ref: OpaqueRef
    recipients: int = Field(ge=1, le=1_000_000)
    subject: ShortText
    body: BoundedText
    budget: Decimal
    approval_ref: OpaqueRef | None = None
    idempotency_key: OpaqueRef
    arguments: dict[str, Any]
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    claim_projections: tuple[dict[str, Any], ...] = ()
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("budget", mode="before")
    @classmethod
    def _budget(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="budget")

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> LaunchRequest:
        if self.tool not in EXECUTABLE_CHANNELS.get(self.channel, ()):
            raise ValueError(f"{self.tool} does not execute the {self.channel} channel")
        if not skip_digests(info) and self.request_digest != sealed_digest(LaunchRequest, self, "request_digest"):
            raise ValueError("request_digest must commit the exact request")
        return self


def plan_launch(plan: GrowthEngineLoopPlan | Mapping[str, Any], campaign: Any, *, recipients: Sequence[str] | int, subject: str, body: str, tool: str = "notifications.send_email", audience_list_ref: str | None = None, now: str | None = None, eligibility_receipt: Any = None, suppression_digest: str | None = None, endpoint_digests: Sequence[str] | None = None, claim_projections: Sequence[Mapping[str, Any]] = ()) -> LaunchRequest:
    """The exact platform write that launches an approved (or approval-exempt) campaign on an executable channel."""

    from lightbulb.growth_engine_loop import CAMPAIGN_LIFECYCLE
    parsed_plan, campaign = CAMPAIGN_LIFECYCLE.bind(plan, campaign)
    ledger = campaign.ledger
    channel = str(getattr(ledger, "channel", "") or "")
    _require(channel in EXECUTABLE_CHANNELS, "CHANNEL_EXECUTION_UNSUPPORTED", f"{channel or 'unknown channel'} has no platform adapter; supported: {sorted(EXECUTABLE_CHANNELS)}; record its launch from the ad platform's receipt with provenance")
    _require(tool in EXECUTABLE_CHANNELS[channel], "TOOL_NOT_FOR_CHANNEL", f"{tool} does not execute {channel}; use one of {EXECUTABLE_CHANNELS[channel]}")
    _require(campaign.status in ("approved", "composed"), "CAMPAIGN_NOT_LAUNCHABLE", f"campaign is {campaign.status}; launch needs an approved (or approval-exempt composed) campaign")
    if campaign.status == "composed":
        _require(not bool(getattr(ledger, "approval_required", False)), "APPROVAL_REQUIRED", "this campaign's budget requires approval before launch")
    creative = getattr(ledger, "creative_digest", None)
    _require(bool(creative), "CREATIVE_MISSING", "compose the campaign before launching it")
    count = recipients if isinstance(recipients, int) else len(list(recipients))
    _require(count >= 1, "RECIPIENTS_MISSING", "a launch reaches at least one recipient")
    permission_fields: dict[str, Any] = {}
    if parsed_plan.blueprint.require_permission_register or eligibility_receipt is not None or ledger.eligibility_receipt is not None:
        from lightbulb.permission_register import verify_eligibility, verify_claim_projection
        _require(now is not None and endpoint_digests is not None and len(set(endpoint_digests)) == count, "SEND_WITHOUT_ELIGIBILITY", "launch commits one keyed endpoint digest per recipient and the send time")
        proof = verify_eligibility(eligibility_receipt or ledger.eligibility_receipt, suppression_digest=suppression_digest or ledger.suppression_digest, channel="email", at=now, endpoints=endpoint_digests, company_ref=parsed_plan.blueprint.permission_company_ref, expected_scope=campaign.scope)
        projections = tuple(claim_projections) or ledger.claim_projections
        _require({item.get("claim_ref") for item in projections} == set(ledger.claim_refs), "CLAIM_NOT_APPROVED", "launch must retain each composed claim's current projection")
        for projection in projections:
            verify_claim_projection(projection, channel=channel, jurisdiction=parsed_plan.blueprint.claim_jurisdiction, product=parsed_plan.blueprint.claim_product_ref, at=now, company_ref=parsed_plan.blueprint.permission_company_ref, expected_scope=campaign.scope)
        permission_fields = {"eligibility_receipt": proof.to_dict(), "suppression_digest": proof.suppression_digest, "claim_projections": list(projections)}
    campaign_ref = str(campaign.scope.entity_ref)
    arguments: dict[str, Any] = {"subject": subject, "body": body, "context": {"campaign_ref": campaign_ref, "creative_digest": creative, "audience_ref": str(ledger.audience_ref)}}
    if permission_fields:
        _require(stable_digest({"headline": subject, "body": body, "claims": list(ledger.claim_refs)}) == creative, "CREATIVE_MISMATCH", "the send must use the exact composed headline, body and approved claims")
        arguments["context"].update({"eligibility_digest": proof.eligibility_digest, "suppression_digest": proof.suppression_digest, "endpoint_digests": list(endpoint_digests)})
    if isinstance(recipients, int):
        arguments["to"] = audience_list_ref or str(ledger.audience_ref)
    else:
        arguments["to"] = list(recipients)
    return seal(LaunchRequest, {"campaign_ref": campaign_ref, "channel": channel, "tool": tool, "audience_ref": str(ledger.audience_ref), "recipients": count, "subject": subject, "body": body, "budget": str(ledger.budget), "approval_ref": getattr(ledger, "approval_ref", None), "idempotency_key": f"launch:{campaign_ref}:{creative[:16]}", "arguments": arguments, **permission_fields}, "request_digest")


def connector_request(launch: LaunchRequest, *, scope: Mapping[str, Any], connector_account_ref: str, approval_ref: str | None = None) -> dict[str, Any]:
    ref = approval_ref or launch.approval_ref
    return {"schema": "lightbulb.connector_execution_request.v1", "tool": launch.tool, "arguments": dict(launch.arguments), "scope": dict(scope), "connector_account_ref": connector_account_ref, "effect": "write", "approval_required": True, "approval_ref": ref, "preview_only": ref is None, "idempotency_key": launch.idempotency_key, "metadata": {"campaign_ref": launch.campaign_ref, "launch_request_digest": launch.request_digest}}


def launch_receipt(launch: LaunchRequest, execution: ExecutionReceipt | Mapping[str, Any], *, request: Any = None) -> BoundExecution:
    """Bind the platform's write execution receipt to the ``launch`` event; the tool must match the request."""

    receipt = execution if isinstance(execution, ExecutionReceipt) else ExecutionReceipt.model_validate(dict(detached(execution)))
    _require(receipt.tool == launch.tool, "LAUNCH_TOOL_MISMATCH", f"the request named {launch.tool}; the execution ran {receipt.tool}")
    _require(request is not None or launch.eligibility_receipt is None, "EXECUTION_REQUEST_MISSING", "a protected launch retains its exact approved connector request")
    if request is not None:
        from lightbulb._execution_gates import exact_request
        exact_request(request, receipt, tool=launch.tool, arguments=launch.arguments, idempotency_key=launch.idempotency_key)
    return bind_execution(receipt, engine="growth_engine", event="launch", fields={key: value for key, value in launch.to_dict().items() if key in {"eligibility_receipt", "suppression_digest", "claim_projections"}})


# --------------------------------------------------------------------------- #
# Reallocation applied
# --------------------------------------------------------------------------- #


def preview_reallocation(plan: GrowthEngineLoopPlan | Mapping[str, Any], portfolio: CampaignPortfolio | Mapping[str, Any], proposal: ReallocationProposal | Mapping[str, Any], *, scope=None, scope_keyring=None) -> CampaignPortfolio:
    """Project candidate budgets for review; grants no authority or live effect."""

    parsed_plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    current = portfolio if isinstance(portfolio, CampaignPortfolio) else CampaignPortfolio.model_validate(dict(detached(portfolio)))
    raw_proposal = detached(proposal)
    incremental = raw_proposal.get("schema") == "lightbulb.growth_incremental_reallocation_proposal.v1"
    if incremental:
        from lightbulb.growth_reallocation import verify_incremental_reallocation
        proposed = verify_incremental_reallocation(raw_proposal, scope=scope, scope_keyring=scope_keyring)
    else:
        proposed = ReallocationProposal.model_validate(raw_proposal)
    _require(proposed.shifts != (), "NO_SHIFTS", "the proposal moves nothing")
    _require(current.plan_digest == parsed_plan.plan_digest and proposed.plan_digest == parsed_plan.plan_digest
             and proposed.portfolio_digest == current.portfolio_digest, "PROPOSAL_NOT_BOUND", "the proposal must bind this exact plan and portfolio")
    from lightbulb.company_engine_core import pct
    maximum = pct(current.total_budget - current.unallocated, parsed_plan.blueprint.max_shift_percent_per_cycle)
    if incremental:
        _require(proposed.max_shift_percent <= parsed_plan.blueprint.max_shift_percent_per_cycle,
                 "SHIFT_LIMIT_EXCEEDED", "proposal cannot exceed current blueprint policy")
        maximum = pct(current.total_budget - current.unallocated, proposed.max_shift_percent)
    _require(proposed.total_shifted <= maximum and proposed.max_shift_allowed == maximum,
             "SHIFT_LIMIT_EXCEEDED", "the limit derives from allocated budget, excluding unallocated reserves")
    budgets: dict[str, Decimal] = {envelope.envelope_ref: envelope.budget for envelope in current.envelopes}
    def resolve(channel: str, ref: str | None) -> str:
        matches = [envelope.envelope_ref for envelope in current.envelopes
                   if envelope.channel == channel and (ref is None or ref == envelope.envelope_ref)]
        _require(bool(matches), "SHIFT_CHANNEL_UNKNOWN", "shift names a channel or envelope outside the portfolio")
        _require(len(matches) == 1, "SHIFT_ENVELOPE_AMBIGUOUS", "multiple envelopes on a channel require explicit envelope references")
        return matches[0]
    for shift in proposed.shifts:
        source = resolve(shift.from_channel, shift.from_envelope_ref)
        target = resolve(shift.to_channel, shift.to_envelope_ref)
        amount = shift.amount
        _require(budgets[source] >= amount, "SHIFT_EXCEEDS_ENVELOPE", f"{source} cannot supply {amount}")
        budgets[source] -= amount
        budgets[target] += amount
    _require(sum(budgets.values(), Decimal(0)) == current.total_budget - current.unallocated,
             "REALLOCATION_NOT_NEUTRAL", "reallocation must preserve allocated budget exactly")
    allocations = [{"envelope_ref": envelope.envelope_ref, "channel": envelope.channel,
                    "objective": envelope.objective, "audience_ref": envelope.audience_ref,
                    "budget": str(budgets[envelope.envelope_ref])} for envelope in current.envelopes]
    return plan_campaign_portfolio(parsed_plan, period_start=current.period_start, period_end=current.period_end, total_budget=str(current.total_budget), allocations=allocations)


def apply_reallocation(plan, portfolio, proposal, *, approval_ref: str, scope=None, scope_keyring=None):
    """Return the approved portfolio projection; provider effects are separate."""
    _require(bool(approval_ref and approval_ref.strip()), "APPROVAL_REQUIRED", "a reallocation is applied only with the approval that accepted the proposal")
    return preview_reallocation(plan, portfolio, proposal, scope=scope, scope_keyring=scope_keyring)


GROWTH_EXECUTION_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine_manifest.v1",
    "engine": "growth_execution",
    "golden_loop": "growth.store_truth_to_attributed_revenue@0.1.0",
    "stages": ["compose_from_variants", "plan_launch", "execute_behind_approval", "bind_launch", "apply_reallocation"],
    "executable_channels": {channel: list(tools) for channel, tools in EXECUTABLE_CHANNELS.items()},
    "unsupported_channels": list(UNSUPPORTED_CHANNELS),
    "required_connectors": ["notifications", "gmail", "lightbulb.domain_agents"],
    "hard_rules": [
        "a creative comes from a named variant of the content agent's result; the engine's brand-safety and claim guards still decide",
        "a launch is an exact request on a channel the platform can execute; other channels are refused, not simulated",
        "a launch is recorded only from the platform's write execution receipt with its approval",
        "a reallocation is applied only with the approval that accepted the proposal and never exceeds the proposed shifts",
    ],
}

__all__ = [
    "EXECUTABLE_CHANNELS",
    "GROWTH_EXECUTION_MANIFEST",
    "LAUNCH_REQUEST_SCHEMA",
    "UNSUPPORTED_CHANNELS",
    "GrowthExecutionError",
    "LaunchRequest",
    "apply_reallocation",
    "connector_request",
    "creative_from_variants",
    "launch_receipt",
    "plan_launch",
]
