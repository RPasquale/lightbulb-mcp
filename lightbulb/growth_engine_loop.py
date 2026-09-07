"""Growth Engine Golden Operating Loop: store truth to attributed revenue.

The engine that lets a store, a SaaS product, or a local service market
itself under governance::

    Audit truth -> Plan portfolio (budget envelopes per channel)
      -> Compose candidates (ads, organic social, email/SMS lifecycle, SEO)
      -> Approve and launch -> Observe (analytics, orders, settlements)
      -> Attribute revenue -> Propose reallocation -> Learn

What is typed here: the growth blueprint (channels, caps, approval
thresholds, approved claims, brand safety, attribution policy, reallocation
limits, measurement sources, targets), a sealed campaign portfolio, a
replay-fenced per-campaign lifecycle whose creative candidates may only use
approved claims and whose spend can never exceed its envelope, revenue
attribution under the blueprint's window and model, a reallocation
proposal that is always a candidate for human approval, and an engine
assessment against targets.

Nothing here publishes an ad or a post, sends an email or SMS, spends money,
or reads a provider.  Spring authorizes those effects; the Connector Runtime
executes them through the ``meta_ads.*``, ``google_ads.*``, ``tiktok_ads.*``,
``klaviyo.*``, ``ga4.*``, ``search_console.*``, ``instagram.*``,
``linkedin.*``, ``shopify.*``, and ``stripe.*`` tools.  Approved claims,
brand-safety terms, consent, and platform policy are explicit inputs that a
model never invents.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import (
    GENESIS_DIGEST,
    MONEY_QUANTUM,
    BoundedText,
    CurrencyCode,
    EngineScope,
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    decimal_value,
    detached,
    parsed,
    pct,
    percent_value,
    require,
    seal,
    sealed_digest,
    skip_digests,
    stable_digest,
    timestamp,
    unique,
)

GROWTH_ENGINE_GOLDEN_LOOP = "growth.store_truth_to_attributed_revenue@0.1.0"
GROWTH_ENGINE_KIND = "growth_engine"
BLUEPRINT_SCHEMA = "lightbulb.growth_engine_blueprint.v1"
PLAN_SCHEMA = "lightbulb.growth_engine_loop_plan.v1"
PORTFOLIO_SCHEMA = "lightbulb.campaign_portfolio.v1"
REALLOCATION_SCHEMA = "lightbulb.budget_reallocation_proposal.v1"
ASSESSMENT_SCHEMA = "lightbulb.growth_engine_assessment.v1"
MAX_CAMPAIGN_TRANSITIONS = 200

Channel = Literal["paid_social_meta", "paid_search_google", "paid_social_tiktok", "organic_social", "email_lifecycle", "sms_lifecycle", "seo_content", "affiliate"]
CHANNELS: tuple[str, ...] = ("paid_social_meta", "paid_search_google", "paid_social_tiktok", "organic_social", "email_lifecycle", "sms_lifecycle", "seo_content", "affiliate")
PAID_CHANNELS: frozenset[str] = frozenset({"paid_social_meta", "paid_search_google", "paid_social_tiktok", "affiliate"})
MessagingChannel = Literal["email_lifecycle", "sms_lifecycle"]
AttributionModel = Literal["last_touch", "first_touch", "linear", "platform_reported"]
MeasurementSource = Literal["ga4", "shopify_analytics", "stripe_settlements", "hubspot", "platform_reported", "klaviyo", "search_console"]
Objective = Literal["acquire", "convert", "retain", "reactivate", "expand"]
BlueprintProfile = Literal["dtc_shopify", "b2b_saas", "local_services", "marketplace_demand", "plg_self_serve", "custom"]
LoopStage = Literal["audit_truth", "plan_portfolio", "compose_candidates", "approve_and_launch", "observe", "attribute", "reallocate", "learn"]
STAGE_ORDER: tuple[str, ...] = ("audit_truth", "plan_portfolio", "compose_candidates", "approve_and_launch", "observe", "attribute", "reallocate", "learn")

CampaignStatus = Literal["drafted", "composed", "pending_approval", "approved", "live", "paused", "attributed", "completed", "halted"]
CAMPAIGN_STATUSES: tuple[str, ...] = ("drafted", "composed", "pending_approval", "approved", "live", "paused", "attributed", "completed", "halted")
TERMINAL_CAMPAIGN_STATUSES: frozenset[str] = frozenset({"completed", "halted"})
CampaignEvent = Literal["draft", "compose", "submit_for_approval", "approve", "reject_creative", "launch", "observe", "pause", "resume", "attribute", "complete", "halt"]
CAMPAIGN_EVENTS: tuple[str, ...] = ("draft", "compose", "submit_for_approval", "approve", "reject_creative", "launch", "observe", "pause", "resume", "attribute", "complete", "halt")
_CAMPAIGN_TABLE: dict[tuple[str, str], str] = {
    ("new", "draft"): "drafted",
    ("drafted", "compose"): "composed",
    ("composed", "compose"): "composed",
    ("composed", "submit_for_approval"): "pending_approval",
    ("composed", "launch"): "live",
    ("pending_approval", "approve"): "approved",
    ("pending_approval", "reject_creative"): "drafted",
    ("approved", "launch"): "live",
    ("live", "observe"): "live",
    ("live", "pause"): "paused",
    ("live", "attribute"): "attributed",
    ("live", "halt"): "halted",
    ("paused", "resume"): "live",
    ("paused", "attribute"): "attributed",
    ("paused", "halt"): "halted",
    ("attributed", "observe"): "live",
    ("attributed", "attribute"): "attributed",
    ("attributed", "complete"): "completed",
    ("attributed", "halt"): "halted",
}

_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_growth_engine", "growth_engine.plan_campaign_portfolio", "growth_engine.advance_campaign", "growth_engine.propose_reallocation", "growth_engine.assess_engine",
        "commerce.compile_product_commercial_identity", "commerce.compose_personalized_variant", "commerce.compose_personalized_variant", "commerce.plan_channel_publication",
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "content.run_creative_experiment_factory",
        "growth.build_funnel_snapshot", "growth.compare_funnel_snapshots", "growth.build_unit_economics", "growth.review_customer_value", "growth.allocate_incremental_acquisition", "growth.diagnose",
        "communication.write_email", "crm.qualify_lead", "learning.plan_optimization_sweep", "compliance.evaluate_regulated_controls", "approval.request_decision",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset(
    {
        "google_ads.get_account", "google_ads.create_campaign_budget",
        "meta_ads.get_account", "meta_ads.list_campaigns", "meta_ads.get_insights", "meta_ads.create_campaign", "meta_ads.create_adset", "meta_ads.update_budget", "meta_ads.pause_campaign",
        "google_ads.get_account", "google_ads.list_campaigns", "google_ads.get_metrics", "google_ads.create_campaign_budget", "google_ads.create_campaign", "google_ads.update_budget", "google_ads.pause_campaign",
        "tiktok_ads.list_campaigns", "tiktok_ads.get_report", "tiktok_ads.create_campaign", "tiktok_ads.update_budget",
        "instagram.publish_post", "instagram.get_insights", "facebook.publish_post", "linkedin.publish_post", "linkedin.get_analytics",
        "klaviyo.list_flows", "klaviyo.create_flow", "klaviyo.send_campaign", "klaviyo.get_metrics", "twilio.send_sms_turn",
        "ga4.run_report", "search_console.query_analytics", "shopify.analytics_query", "shopify.list_orders", "shopify.list_abandoned_checkouts", "stripe.list_balance_transactions", "hubspot.get_contact",
    }
)
_CHANNEL_TOOLS: dict[str, tuple[str, ...]] = {
    "paid_social_meta": ("meta_ads.get_account", "meta_ads.list_campaigns", "meta_ads.get_insights", "meta_ads.create_campaign", "meta_ads.update_budget", "meta_ads.pause_campaign"),
    "paid_search_google": ("google_ads.list_campaigns", "google_ads.get_metrics", "google_ads.create_campaign", "google_ads.update_budget", "google_ads.pause_campaign"),
    "paid_social_tiktok": ("tiktok_ads.list_campaigns", "tiktok_ads.get_report", "tiktok_ads.create_campaign", "tiktok_ads.update_budget"),
    "organic_social": ("instagram.publish_post", "instagram.get_insights", "facebook.publish_post", "linkedin.publish_post", "linkedin.get_analytics"),
    "email_lifecycle": ("klaviyo.list_flows", "klaviyo.create_flow", "klaviyo.send_campaign", "klaviyo.get_metrics"),
    "sms_lifecycle": ("twilio.send_sms_turn", "klaviyo.send_campaign", "klaviyo.get_metrics"),
    "seo_content": ("search_console.query_analytics", "ga4.run_report"),
    "affiliate": ("shopify.list_orders", "ga4.run_report"),
}
_MEASUREMENT_TOOLS: dict[str, str] = {"ga4": "ga4.run_report", "shopify_analytics": "shopify.analytics_query", "stripe_settlements": "stripe.list_balance_transactions", "hubspot": "hubspot.get_contact", "klaviyo": "klaviyo.get_metrics", "search_console": "search_console.query_analytics", "platform_reported": "meta_ads.get_insights"}


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class ChannelPolicy(StrictModel):
    channel: Channel
    monthly_budget_cap: Decimal
    approval_threshold: Decimal = Field(default=Decimal("0"), validate_default=True)
    target_roas: Decimal | None = None
    target_cpa: Decimal | None = None
    enabled: bool = True

    @field_validator("monthly_budget_cap", "approval_threshold", "target_roas", "target_cpa", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _paid_needs_target(self) -> "ChannelPolicy":
        if self.channel in PAID_CHANNELS and self.enabled and self.target_roas is None and self.target_cpa is None:
            raise ValueError(f"{self.channel} needs a target ROAS or target CPA")
        if self.approval_threshold > self.monthly_budget_cap:
            raise ValueError(f"{self.channel} approval threshold cannot exceed its budget cap")
        return self


class ApprovedClaim(StrictModel):
    claim_ref: OpaqueRef
    text: ShortText
    evidence_ref: OpaqueRef
    expires_at: str | None = None

    @field_validator("expires_at")
    @classmethod
    def _expires(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="expires_at")


class GrowthEngineBlueprint(StrictModel):
    schema_id: Literal["lightbulb.growth_engine_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    channels: tuple[ChannelPolicy, ...] = Field(min_length=1, max_length=8)
    approved_claims: tuple[ApprovedClaim, ...] = Field(default_factory=tuple, max_length=200)
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=200)
    audiences: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    measurement_sources: tuple[MeasurementSource, ...] = Field(min_length=1, max_length=7)
    attribution_model: AttributionModel = "last_touch"
    attribution_window_days: int = Field(default=7, ge=1, le=90)
    max_shift_percent_per_cycle: Decimal = Field(default=Decimal("20"), validate_default=True)
    min_conversions_for_evidence: int = Field(default=20, ge=1, le=100000)
    consent_required_for_messaging: bool = True
    # False is an explicit compatibility/simulation policy, never evidence of
    # eligible outreach. New plans require the replayed permission register.
    require_permission_register: bool = True
    require_demand_registry: bool = False
    permission_company_ref: OpaqueRef | None = None
    claim_jurisdiction: ShortText | None = None
    claim_product_ref: OpaqueRef | None = None
    target_blended_roas: Decimal = Field(default=Decimal("3"), validate_default=True)
    target_ltv_to_cac: Decimal = Field(default=Decimal("3"), validate_default=True)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("max_shift_percent_per_cycle", mode="before")
    @classmethod
    def _shift(cls, value: Any) -> Decimal:
        return percent_value(value, field_name="max_shift_percent_per_cycle")

    @field_validator("target_blended_roas", "target_ltv_to_cac", mode="before")
    @classmethod
    def _targets(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "GrowthEngineBlueprint":
        unique([item.channel for item in self.channels], label="channels")
        unique([item.claim_ref for item in self.approved_claims], label="approved claim refs")
        unique(list(self.audiences), label="audiences")
        unique(list(self.measurement_sources), label="measurement sources")
        if not any(item.enabled for item in self.channels):
            raise ValueError("at least one channel must be enabled")
        if self.attribution_model == "platform_reported" and "platform_reported" not in self.measurement_sources:
            raise ValueError("platform-reported attribution needs platform_reported as a measurement source")
        if skip_digests(info):
            return self
        if self.blueprint_digest != sealed_digest(GrowthEngineBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def channel(self, name: str) -> ChannelPolicy | None:
        return next((item for item in self.channels if item.channel == name), None)

    def claim(self, ref: str) -> ApprovedClaim | None:
        return next((item for item in self.approved_claims if item.claim_ref == ref), None)


def seal_growth_engine_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(detached(blueprint))
    raw["blueprint_digest"] = sealed_digest(GrowthEngineBlueprint, raw, "blueprint_digest")
    return GrowthEngineBlueprint.model_validate(raw).to_dict()


_CLAIMS = [{"claim_ref": "claim-free-shipping", "text": "Free shipping on orders over 50", "evidence_ref": "policy:shipping"}, {"claim_ref": "claim-30-day-returns", "text": "30-day returns", "evidence_ref": "policy:returns"}]
GROWTH_ENGINE_PROFILES: dict[str, dict[str, Any]] = {
    "dtc_shopify": {"profile": "dtc_shopify", "name": "DTC Shopify brand", "channels": [{"channel": "paid_social_meta", "monthly_budget_cap": "6000", "approval_threshold": "2000", "target_roas": "3"}, {"channel": "paid_search_google", "monthly_budget_cap": "4000", "approval_threshold": "1500", "target_roas": "4"}, {"channel": "paid_social_tiktok", "monthly_budget_cap": "2000", "approval_threshold": "1000", "target_roas": "2.5"}, {"channel": "organic_social", "monthly_budget_cap": "500"}, {"channel": "email_lifecycle", "monthly_budget_cap": "300"}, {"channel": "sms_lifecycle", "monthly_budget_cap": "200"}, {"channel": "seo_content", "monthly_budget_cap": "800"}], "approved_claims": _CLAIMS, "prohibited_terms": ["guaranteed results", "clinically proven", "best in the world"], "audiences": ["aud-prospecting", "aud-retargeting", "aud-customers"], "measurement_sources": ["shopify_analytics", "ga4", "stripe_settlements", "klaviyo"], "attribution_model": "last_touch", "attribution_window_days": 7, "max_shift_percent_per_cycle": "20", "min_conversions_for_evidence": 25, "target_blended_roas": "3", "target_ltv_to_cac": "3", "notes": "Paid above threshold needs approval; lifecycle needs consent."},
    "b2b_saas": {"profile": "b2b_saas", "name": "B2B SaaS demand", "channels": [{"channel": "paid_search_google", "monthly_budget_cap": "8000", "approval_threshold": "2500", "target_cpa": "400"}, {"channel": "paid_social_meta", "monthly_budget_cap": "3000", "approval_threshold": "1500", "target_cpa": "600"}, {"channel": "organic_social", "monthly_budget_cap": "500"}, {"channel": "email_lifecycle", "monthly_budget_cap": "400"}, {"channel": "seo_content", "monthly_budget_cap": "2500"}], "approved_claims": [{"claim_ref": "claim-soc2", "text": "SOC 2 Type II certified", "evidence_ref": "audit:soc2-2026"}], "prohibited_terms": ["unlimited", "zero risk"], "audiences": ["aud-icp-tier1", "aud-icp-tier2", "aud-trialists"], "measurement_sources": ["ga4", "hubspot", "stripe_settlements"], "attribution_model": "linear", "attribution_window_days": 30, "max_shift_percent_per_cycle": "15", "min_conversions_for_evidence": 15, "target_blended_roas": "4", "target_ltv_to_cac": "4", "notes": "Longer windows; leads attributed through the CRM."},
    "local_services": {"profile": "local_services", "name": "Local services", "channels": [{"channel": "paid_search_google", "monthly_budget_cap": "1500", "approval_threshold": "750", "target_cpa": "60"}, {"channel": "paid_social_meta", "monthly_budget_cap": "600", "approval_threshold": "300", "target_cpa": "80"}, {"channel": "organic_social", "monthly_budget_cap": "100"}, {"channel": "sms_lifecycle", "monthly_budget_cap": "100"}, {"channel": "seo_content", "monthly_budget_cap": "300"}], "approved_claims": [{"claim_ref": "claim-licensed", "text": "Licensed and insured", "evidence_ref": "license:2026"}], "prohibited_terms": ["cheapest", "guaranteed"], "audiences": ["aud-service-area", "aud-past-customers"], "measurement_sources": ["ga4", "platform_reported"], "attribution_model": "last_touch", "attribution_window_days": 14, "max_shift_percent_per_cycle": "25", "min_conversions_for_evidence": 10, "target_blended_roas": "5", "target_ltv_to_cac": "3", "notes": "Bookings are the conversion; SMS only with consent."},
    "marketplace_demand": {"profile": "marketplace_demand", "name": "Marketplace demand side", "channels": [{"channel": "paid_social_meta", "monthly_budget_cap": "5000", "approval_threshold": "2000", "target_cpa": "25"}, {"channel": "paid_search_google", "monthly_budget_cap": "5000", "approval_threshold": "2000", "target_cpa": "30"}, {"channel": "affiliate", "monthly_budget_cap": "3000", "approval_threshold": "1000", "target_cpa": "20"}, {"channel": "email_lifecycle", "monthly_budget_cap": "500"}, {"channel": "seo_content", "monthly_budget_cap": "1500"}], "approved_claims": [], "prohibited_terms": ["risk-free"], "audiences": ["aud-buyers", "aud-lapsed-buyers"], "measurement_sources": ["ga4", "stripe_settlements"], "attribution_model": "first_touch", "attribution_window_days": 14, "max_shift_percent_per_cycle": "20", "min_conversions_for_evidence": 30, "target_blended_roas": "3", "target_ltv_to_cac": "3", "notes": "First-touch because liquidity is a network effect."},
}


GROWTH_ENGINE_PROFILES["plg_self_serve"] = {
    **GROWTH_ENGINE_PROFILES["b2b_saas"], "profile": "plg_self_serve",
    "name": "Self-serve SaaS acquisition",
}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    campaign_events: tuple[CampaignEvent, ...] = Field(default_factory=tuple, max_length=12)
    gate: Literal["none", "spring_approval", "platform_policy", "customer_consent"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class GrowthEngineLoopPlan(StrictModel):
    schema_id: Literal["lightbulb.growth_engine_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["growth.store_truth_to_attributed_revenue@0.1.0"] = GROWTH_ENGINE_GOLDEN_LOOP
    engine: Literal["growth_engine"] = GROWTH_ENGINE_KIND
    blueprint: GrowthEngineBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=8, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "GrowthEngineLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if skip_digests(info):
            return self
        if self.plan_digest != sealed_digest(GrowthEngineLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(blueprint: GrowthEngineBlueprint) -> list[dict[str, Any]]:
    enabled = [item for item in blueprint.channels if item.enabled]
    channel_tools = tuple(dict.fromkeys(tool for item in enabled for tool in _CHANNEL_TOOLS[item.channel]))
    read_tools = tuple(dict.fromkeys(tool for tool in channel_tools if any(tool.endswith(suffix) for suffix in ("get_account", "list_campaigns", "get_insights", "get_metrics", "get_report", "list_flows", "get_analytics", "query_analytics", "run_report", "list_orders"))))
    write_tools = tuple(tool for tool in channel_tools if tool not in read_tools)
    measurement_tools = tuple(dict.fromkeys(_MEASUREMENT_TOOLS[source] for source in blueprint.measurement_sources))
    messaging = any(item.channel in {"email_lifecycle", "sms_lifecycle"} for item in enabled)
    return [
        {"stage": "audit_truth", "title": "Audit the commercial truth the engine may speak about", "primitive_refs": ("commerce.compile_product_commercial_identity", "growth.build_funnel_snapshot", "growth.build_unit_economics"), "connector_tools": ("shopify.analytics_query",) + measurement_tools, "gate": "none"},
        {"stage": "plan_portfolio", "title": "Plan the campaign portfolio inside channel caps", "primitive_refs": ("growth_engine.plan_campaign_portfolio", "growth.allocate_incremental_acquisition", "demand_gen.plan_audience_growth"), "gate": "none"},
        {"stage": "compose_candidates", "title": "Compose creative and flow candidates from approved claims", "primitive_refs": ("growth_engine.advance_campaign", "commerce.compose_personalized_variant", "demand_gen.plan_content_calendar", "communication.write_email") + (("compliance.evaluate_regulated_controls",) if messaging and blueprint.consent_required_for_messaging else ()), "connector_tools": read_tools, "campaign_events": ("draft", "compose"), "gate": "customer_consent" if messaging and blueprint.consent_required_for_messaging else "platform_policy"},
        {"stage": "approve_and_launch", "title": "Approve above-threshold spend and launch", "primitive_refs": ("growth_engine.advance_campaign", "approval.request_decision", "commerce.plan_channel_publication"), "connector_tools": write_tools, "campaign_events": ("submit_for_approval", "approve", "reject_creative", "launch"), "gate": "spring_approval"},
        {"stage": "observe", "title": "Observe spend, traffic, conversions, and revenue", "primitive_refs": ("growth_engine.advance_campaign", "growth.build_funnel_snapshot"), "connector_tools": measurement_tools, "campaign_events": ("observe", "pause", "resume", "halt"), "gate": "none"},
        {"stage": "attribute", "title": f"Attribute revenue ({blueprint.attribution_model}, {blueprint.attribution_window_days}d window)", "primitive_refs": ("growth_engine.advance_campaign", "growth.compare_funnel_snapshots", "growth.review_customer_value"), "campaign_events": ("attribute", "complete"), "gate": "none"},
        {"stage": "reallocate", "title": f"Propose reallocation (max {blueprint.max_shift_percent_per_cycle}% shift per cycle)", "primitive_refs": ("growth_engine.propose_reallocation", "approval.request_decision"), "connector_tools": tuple(tool for tool in write_tools if tool.endswith("update_budget") or tool.endswith("pause_campaign")), "gate": "spring_approval"},
        {"stage": "learn", "title": "Learn: blended ROAS, CPA, LTV to CAC", "primitive_refs": ("growth_engine.assess_engine", "growth.build_unit_economics", "growth.diagnose", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_growth_engine_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> GrowthEngineLoopPlan:
    if isinstance(profile, str):
        if profile not in GROWTH_ENGINE_PROFILES:
            raise ValueError(f"unknown growth engine profile {profile!r}; choose one of {sorted(GROWTH_ENGINE_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(GROWTH_ENGINE_PROFILES[profile]))
    else:
        raw = dict(detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = GrowthEngineBlueprint.model_validate(seal_growth_engine_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = sealed_digest(GrowthEngineLoopPlan, payload, "plan_digest")
    return GrowthEngineLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Campaign portfolio
# --------------------------------------------------------------------------- #


class BudgetEnvelope(StrictModel):
    envelope_ref: OpaqueRef
    channel: Channel
    objective: Objective
    audience_ref: OpaqueRef
    budget: Decimal
    approval_required: bool
    target_roas: Decimal | None = None
    target_cpa: Decimal | None = None

    @field_validator("budget", "target_roas", "target_cpa", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class CampaignPortfolio(StrictModel):
    schema_id: Literal["lightbulb.campaign_portfolio.v1"] = Field(default=PORTFOLIO_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    period_start: str
    period_end: str
    total_budget: Decimal
    envelopes: tuple[BudgetEnvelope, ...] = Field(min_length=1, max_length=64)
    unallocated: Decimal
    currency: CurrencyCode
    portfolio_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total_budget", "unallocated", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("period_start", "period_end")
    @classmethod
    def _times(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _portfolio_is_exact(self, info: ValidationInfo) -> "CampaignPortfolio":
        unique([item.envelope_ref for item in self.envelopes], label="envelope refs")
        if parsed(self.period_end) <= parsed(self.period_start):
            raise ValueError("period_end must be after period_start")
        allocated = sum((item.budget for item in self.envelopes), Decimal("0"))
        if (allocated + self.unallocated).quantize(MONEY_QUANTUM) != self.total_budget:
            raise ValueError("envelopes plus unallocated must equal the total budget")
        if skip_digests(info):
            return self
        if self.portfolio_digest != sealed_digest(CampaignPortfolio, self, "portfolio_digest"):
            raise ValueError("portfolio_digest must commit the exact portfolio")
        return self

    def envelope(self, ref: str) -> BudgetEnvelope | None:
        return next((item for item in self.envelopes if item.envelope_ref == ref), None)


def plan_campaign_portfolio(plan: GrowthEngineLoopPlan | Mapping[str, Any], *, period_start: str, period_end: str, total_budget: Any, allocations: Sequence[Mapping[str, Any]]) -> CampaignPortfolio:
    """Turn requested allocations into sealed envelopes inside the blueprint's channel caps.

    Each allocation names ``channel``, ``objective``, ``audience_ref``, and
    ``budget``; the blueprint decides the approval flag and targets.  Caps are
    monthly and pro-rated to the period.
    """

    parsed_plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    blueprint = parsed_plan.blueprint
    start, end = timestamp(period_start, field_name="period_start"), timestamp(period_end, field_name="period_end")
    days = (parsed(end) - parsed(start)).days
    if days < 1 or days > 366:
        raise ValueError("the portfolio period must span between 1 and 366 days")
    proration = (Decimal(days) / Decimal(30)).quantize(Decimal("0.0001"))
    total = decimal_value(total_budget, field_name="total_budget")
    envelopes: list[dict[str, Any]] = []
    spent_by_channel: dict[str, Decimal] = {}
    for index, item in enumerate(allocations, start=1):
        channel = str(item.get("channel", ""))
        policy = blueprint.channel(channel)
        if policy is None or not policy.enabled:
            raise ValueError(f"CHANNEL_NOT_ENABLED: {channel} is not an enabled channel in this blueprint")
        audience = str(item.get("audience_ref", ""))
        if audience not in blueprint.audiences:
            raise ValueError(f"AUDIENCE_UNKNOWN: {audience} is not a blueprint audience")
        budget = decimal_value(item.get("budget"), field_name="budget")
        cap = (policy.monthly_budget_cap * proration).quantize(MONEY_QUANTUM)
        spent_by_channel[channel] = spent_by_channel.get(channel, Decimal("0")) + budget
        if spent_by_channel[channel] > cap:
            raise ValueError(f"CHANNEL_CAP_EXCEEDED: {channel} allocations {spent_by_channel[channel]} exceed the pro-rated cap {cap}")
        envelopes.append({"envelope_ref": str(item.get("envelope_ref") or f"env-{index}-{channel}"), "channel": channel, "objective": str(item.get("objective", "acquire")), "audience_ref": audience, "budget": str(budget), "approval_required": budget > policy.approval_threshold, "target_roas": None if policy.target_roas is None else str(policy.target_roas), "target_cpa": None if policy.target_cpa is None else str(policy.target_cpa)})
    allocated = sum((Decimal(item["budget"]) for item in envelopes), Decimal("0"))
    if allocated > total:
        raise ValueError(f"BUDGET_EXCEEDED: allocations {allocated} exceed the total budget {total}")
    payload = {"plan_digest": parsed_plan.plan_digest, "period_start": start, "period_end": end, "total_budget": str(total), "envelopes": envelopes, "unallocated": str((total - allocated).quantize(MONEY_QUANTUM)), "currency": blueprint.currency}
    return seal(CampaignPortfolio, payload, "portfolio_digest")


# --------------------------------------------------------------------------- #
# Campaign lifecycle
# --------------------------------------------------------------------------- #


class CampaignReceipt(StrictModel):
    demand_source: dict[str, Any] | None = None
    entity_scope: EngineScope | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    claim_projections: tuple[dict[str, Any], ...] = ()
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    envelope_ref: OpaqueRef | None = None
    portfolio_digest: Sha256Digest | None = None
    channel: Channel | None = None
    objective: Objective | None = None
    audience_ref: OpaqueRef | None = None
    creative_ref: OpaqueRef | None = None
    headline: ShortText | None = None
    body: BoundedText | None = None
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    consent_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    launch_ref: OpaqueRef | None = None
    measurement_source: MeasurementSource | None = None
    observation_ref: OpaqueRef | None = None
    observed_through: str | None = None
    spend: Decimal | None = None
    impressions: int | None = Field(default=None, ge=0)
    clicks: int | None = Field(default=None, ge=0)
    conversions: int | None = Field(default=None, ge=0)
    revenue: Decimal | None = None
    attribution_model: AttributionModel | None = None
    attributed_revenue: Decimal | None = None
    attributed_conversions: int | None = Field(default=None, ge=0)

    @field_validator("spend", "revenue", "attributed_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("observed_through")
    @classmethod
    def _observed(cls, value: str | None) -> str | None:
        return None if value is None else timestamp(value, field_name="observed_through")


class CampaignLedger(StrictModel):
    demand_plan_digest: Sha256Digest | None = None
    entity_scope: EngineScope | None = None
    eligibility_receipt: dict[str, Any] | None = None
    suppression_digest: Sha256Digest | None = None
    claim_projections: tuple[dict[str, Any], ...] = ()
    envelope_ref: OpaqueRef | None = None
    portfolio_digest: Sha256Digest | None = None
    channel: Channel | None = None
    objective: Objective | None = None
    audience_ref: OpaqueRef | None = None
    budget: Decimal = Field(default=Decimal("0"), validate_default=True)
    approval_required: bool = False
    creative_ref: OpaqueRef | None = None
    creative_digest: Sha256Digest | None = None
    claim_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    consent_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    launch_ref: OpaqueRef | None = None
    launched_at: str | None = None
    observations: int = Field(default=0, ge=0)
    observed_through: str | None = None
    spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    impressions: int = Field(default=0, ge=0)
    clicks: int = Field(default=0, ge=0)
    conversions: int = Field(default=0, ge=0)
    revenue_observed: Decimal = Field(default=Decimal("0"), validate_default=True)
    attribution_model: AttributionModel | None = None
    attributed_revenue: Decimal = Field(default=Decimal("0"), validate_default=True)
    attributed_conversions: int = Field(default=0, ge=0)
    roas: Decimal | None = None
    cpa: Decimal | None = None
    halt_reason: ShortText | None = None
    outcome: Literal["completed", "halted"] | None = None

    @field_validator("budget", "spend", "revenue_observed", "attributed_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("roas", "cpa", mode="before")
    @classmethod
    def _ratios(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class CampaignEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    ad_published: Literal[False] = False
    post_published: Literal[False] = False
    message_sent: Literal[False] = False
    money_spent: Literal[False] = False
    provider_read: Literal[False] = False


def _contains_prohibited(text: str | None, terms: Sequence[str]) -> str | None:
    if not text:
        return None
    lowered = text.lower()
    return next((term for term in terms if term.lower() in lowered), None)


def _apply_campaign(plan: GrowthEngineLoopPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    bp, r, event = plan.blueprint, command.receipt, command.event
    if event == "draft":
        if r.entity_scope is not None:
            require(command.expected_state_digest == CAMPAIGN_LIFECYCLE.state_digest(plan.plan_digest, r.entity_scope, ()), "SCOPE_MISMATCH", "the permission scope must be this campaign's actual scope")
            data["entity_scope"] = r.entity_scope.to_dict()
        require(r.envelope_ref is not None and r.portfolio_digest is not None and r.channel is not None and r.audience_ref is not None, "ENVELOPE_MISSING", "a campaign opens against a portfolio envelope (envelope_ref, portfolio_digest, channel, audience_ref)")
        require(not bp.require_demand_registry or r.demand_source is not None, "DEMAND_CLAIM_REQUIRED", "reserve this campaign budget in the shared demand registry before drafting")
        if r.demand_source is not None:
            from lightbulb.growth_paced_envelope import DEMAND_LIFECYCLE, verify_campaign_claim
            demand_plan, registry = DEMAND_LIFECYCLE.bind(r.demand_source["plan"], r.demand_source["state"])
            require(r.entity_scope is not None, "SOURCE_SCOPE_MISMATCH", "paced campaigns must retain their scope")
            claim = verify_campaign_claim(registry, source_plan=demand_plan, campaign_scope=r.entity_scope,
                                          envelope_ref=str(r.envelope_ref), at=command.occurred_at)
            require(demand_plan.growth_plan.plan_digest == plan.plan_digest and demand_plan.portfolio.portfolio_digest == r.portfolio_digest,
                    "PORTFOLIO_NOT_BOUND", "claim must belong to this exact growth plan and portfolio")
            require(r.spend == claim.budget, "CLAIM_BUDGET_MISMATCH", "campaign budget must equal its reserved claim")
            data["demand_plan_digest"] = demand_plan.plan_digest
        policy = bp.channel(str(r.channel))
        require(policy is not None and policy.enabled, "CHANNEL_NOT_ENABLED", f"{r.channel} is not an enabled channel")
        require(str(r.audience_ref) in bp.audiences, "AUDIENCE_UNKNOWN", f"{r.audience_ref} is not a blueprint audience")
        budget = r.spend if r.spend is not None else Decimal("0")
        require(budget > 0, "BUDGET_MISSING", "the envelope budget is carried on the draft receipt as spend")
        assert policy is not None
        data.update({"envelope_ref": r.envelope_ref, "portfolio_digest": r.portfolio_digest, "channel": r.channel, "objective": r.objective or "acquire", "audience_ref": r.audience_ref, "budget": str(budget), "approval_required": budget > policy.approval_threshold})
    elif event == "compose":
        require(r.creative_ref is not None and r.headline is not None, "CREATIVE_MISSING", "a creative candidate names its creative_ref and headline")
        if bp.require_permission_register or r.claim_projections:
            from lightbulb._permission_gates import claims
            data["claim_projections"] = list(claims(r.claim_projections, r.claim_refs, channel=data["channel"], jurisdiction=bp.claim_jurisdiction, product=bp.claim_product_ref, at=command.occurred_at, company_ref=bp.permission_company_ref, scope=data.get("entity_scope")))
        for ref in (() if bp.require_permission_register or r.claim_projections else r.claim_refs):
            claim = bp.claim(ref)
            require(claim is not None, "CLAIM_NOT_APPROVED", f"{ref} is not an approved claim", "manual_reconciliation")
            assert claim is not None
            if claim.expires_at is not None:
                require(parsed(command.occurred_at) <= parsed(claim.expires_at), "CLAIM_EXPIRED", f"{ref} expired at {claim.expires_at}", "manual_reconciliation")
        hit = _contains_prohibited(r.headline, bp.prohibited_terms) or _contains_prohibited(r.body, bp.prohibited_terms)
        require(hit is None, "BRAND_SAFETY_VIOLATION", f"creative uses the prohibited term {hit!r}", "manual_reconciliation")
        if data.get("channel") in {"email_lifecycle", "sms_lifecycle"} and bp.consent_required_for_messaging:
            if bp.require_permission_register or r.eligibility_receipt is not None:
                from lightbulb._permission_gates import eligibility
                proof = eligibility(r.eligibility_receipt, r.suppression_digest, channel=data["channel"], at=command.occurred_at, company_ref=bp.permission_company_ref, scope=data.get("entity_scope"))
                data.update(eligibility_receipt=proof.to_dict(), suppression_digest=proof.suppression_digest, consent_ref=f"eligibility:{proof.eligibility_digest[:24]}")
            else:
                require(r.consent_ref is not None, "CONSENT_MISSING", "lifecycle messaging needs the audience consent reference")
                data["consent_ref"] = r.consent_ref
        data.update({"creative_ref": r.creative_ref, "creative_digest": stable_digest({"headline": r.headline, "body": r.body, "claims": list(r.claim_refs)}), "claim_refs": list(r.claim_refs), "approval_ref": None})
    elif event == "submit_for_approval":
        require(data.get("creative_digest") is not None, "CREATIVE_MISSING", "compose a creative before requesting approval")
    elif event == "approve":
        require(r.approval_ref is not None, "APPROVAL_MISSING", "approval links the server-issued approval reference", "await_approval")
        data["approval_ref"] = r.approval_ref
    elif event == "reject_creative":
        data.update({"creative_ref": None, "creative_digest": None, "claim_refs": [], "approval_ref": None})
    elif event == "launch":
        if data.get("demand_plan_digest") is not None:
            from lightbulb.growth_paced_envelope import DEMAND_LIFECYCLE, verify_campaign_claim
            require(r.demand_source is not None, "CURRENT_DEMAND_SOURCE_REQUIRED", "launch must re-read the current shared demand registry")
            demand_plan, registry = DEMAND_LIFECYCLE.bind(r.demand_source["plan"], r.demand_source["state"])
            require(demand_plan.plan_digest == data["demand_plan_digest"], "PORTFOLIO_NOT_BOUND", "launch must use the claim's demand plan")
            verify_campaign_claim(registry, source_plan=demand_plan, campaign_scope=data["entity_scope"],
                                  envelope_ref=data["envelope_ref"], at=command.occurred_at)

        require(data.get("creative_digest") is not None, "CREATIVE_MISSING", "compose a creative before launching")
        if bp.require_permission_register or data.get("claim_projections"):
            from lightbulb._permission_gates import claims
            claims(r.claim_projections or data.get("claim_projections", ()), data.get("claim_refs", ()), channel=data["channel"], jurisdiction=bp.claim_jurisdiction, product=bp.claim_product_ref, at=command.occurred_at, company_ref=bp.permission_company_ref, scope=data.get("entity_scope"))
        if data.get("channel") in {"email_lifecycle", "sms_lifecycle"} and (bp.require_permission_register or data.get("eligibility_receipt")):
            from lightbulb._permission_gates import eligibility
            proof = eligibility(r.eligibility_receipt or data.get("eligibility_receipt"), r.suppression_digest or data.get("suppression_digest"), channel=data["channel"], at=command.occurred_at, company_ref=bp.permission_company_ref, scope=data.get("entity_scope"))
            data.update(eligibility_receipt=proof.to_dict(), suppression_digest=proof.suppression_digest)
        if data.get("approval_required"):
            require(data.get("approval_ref") is not None, "APPROVAL_REQUIRED", "this envelope is above the channel approval threshold; launch needs the approval reference", "await_approval")
        require(r.launch_ref is not None, "LAUNCH_MISSING", "launch links the provider campaign or flow reference")
        data.update({"launch_ref": r.launch_ref, "launched_at": command.occurred_at})
    elif event == "observe":
        require(r.measurement_source is not None and r.measurement_source in bp.measurement_sources, "MEASUREMENT_SOURCE_UNKNOWN", f"observations come from one of {list(bp.measurement_sources)}")
        require(r.observation_ref is not None and r.observed_through is not None, "OBSERVATION_MISSING", "an observation links its reference and the time it covers through")
        last = data.get("observed_through")
        require(last is None or parsed(str(r.observed_through)) > parsed(str(last)), "OBSERVATION_NOT_NEWER", "observations must advance the observed-through time")
        spend = Decimal(str(data.get("spend", "0"))) + (r.spend or Decimal("0"))
        require(spend <= Decimal(str(data.get("budget", "0"))), "ENVELOPE_OVERSPEND", f"spend {spend} exceeds the envelope budget {data.get('budget')}; halt the campaign", "manual_reconciliation")
        data.update({"observations": int(data.get("observations", 0)) + 1, "observed_through": r.observed_through, "spend": str(spend), "impressions": int(data.get("impressions", 0)) + (r.impressions or 0), "clicks": int(data.get("clicks", 0)) + (r.clicks or 0), "conversions": int(data.get("conversions", 0)) + (r.conversions or 0), "revenue_observed": str(Decimal(str(data.get("revenue_observed", "0"))) + (r.revenue or Decimal("0")))})
    elif event == "attribute":
        require(int(data.get("observations", 0)) >= 1, "NO_OBSERVATIONS", "attribution needs at least one observation")
        model = r.attribution_model or bp.attribution_model
        require(model == bp.attribution_model, "ATTRIBUTION_MODEL_MISMATCH", f"this blueprint attributes with {bp.attribution_model}")
        attributed = r.attributed_revenue if r.attributed_revenue is not None else Decimal(str(data.get("revenue_observed", "0")))
        conversions = r.attributed_conversions if r.attributed_conversions is not None else int(data.get("conversions", 0))
        require(attributed <= Decimal(str(data.get("revenue_observed", "0"))), "ATTRIBUTION_EXCEEDS_OBSERVED", "attributed revenue cannot exceed observed revenue")
        spend = Decimal(str(data.get("spend", "0")))
        data.update({"attribution_model": model, "attributed_revenue": str(attributed), "attributed_conversions": conversions, "roas": None if spend == 0 else str((attributed / spend).quantize(MONEY_QUANTUM)), "cpa": None if conversions == 0 else str((spend / Decimal(conversions)).quantize(MONEY_QUANTUM))})
    elif event == "complete":
        data["outcome"] = "completed"
    elif event == "halt":
        data.update({"halt_reason": str(command.reason)[:300], "outcome": "halted"})
    return next_status, data


CAMPAIGN_LIFECYCLE = LifecycleSpec(entity="campaign", schema_prefix="growth_campaign", statuses=CAMPAIGN_STATUSES, terminal=TERMINAL_CAMPAIGN_STATUSES, events=CAMPAIGN_EVENTS, table=_CAMPAIGN_TABLE, opening_event="draft", reason_events=("reject_creative", "pause", "halt"), apply=_apply_campaign, ledger_model=CampaignLedger, receipt_model=CampaignReceipt, effect_boundary_model=CampaignEffectBoundary, plan_model=GrowthEngineLoopPlan, max_transitions=MAX_CAMPAIGN_TRANSITIONS)
CampaignCommand = CAMPAIGN_LIFECYCLE.Command
CampaignState = CAMPAIGN_LIFECYCLE.State
CampaignTransitionResult = CAMPAIGN_LIFECYCLE.TransitionResult
seal_campaign_command = CAMPAIGN_LIFECYCLE.seal_command
campaign_command_digest = CAMPAIGN_LIFECYCLE.command_digest


def open_campaign(plan: GrowthEngineLoopPlan | Mapping[str, Any], scope: EngineScope | Mapping[str, Any], *, portfolio: CampaignPortfolio | Mapping[str, Any], envelope_ref: str, opened_at: str, actor_ref: str, objective: str | None = None, demand_source: Mapping[str, Any] | None = None) -> Any:
    """Open a campaign against one portfolio envelope; budget and approval flag come from the envelope."""

    parsed_plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    parsed_portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    if parsed_portfolio.plan_digest != parsed_plan.plan_digest:
        raise ValueError("PORTFOLIO_NOT_BOUND: the portfolio belongs to a different loop plan")
    envelope = parsed_portfolio.envelope(envelope_ref)
    if envelope is None:
        raise ValueError(f"ENVELOPE_UNKNOWN: {envelope_ref} is not in the portfolio")
    receipt = {"envelope_ref": envelope.envelope_ref, "portfolio_digest": parsed_portfolio.portfolio_digest, "channel": envelope.channel, "objective": objective or envelope.objective, "audience_ref": envelope.audience_ref, "spend": str(envelope.budget)}
    if demand_source is not None:
        from lightbulb.growth_paced_envelope import verify_campaign_claim
        claim = verify_campaign_claim(demand_source["state"], source_plan=demand_source["plan"], campaign_scope=scope,
                                      envelope_ref=envelope_ref, at=opened_at)
        receipt.update({"spend": str(claim.budget), "demand_source": detached(demand_source)})
    return CAMPAIGN_LIFECYCLE.open(parsed_plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt={**receipt, "entity_scope": detached(scope)})


def advance_campaign(plan: GrowthEngineLoopPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return CAMPAIGN_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Reallocation proposal
# --------------------------------------------------------------------------- #


class ChannelPerformance(StrictModel):
    channel: Channel
    campaigns: int = Field(ge=0)
    budget: Decimal
    spend: Decimal
    attributed_revenue: Decimal
    conversions: int = Field(ge=0)
    roas: Decimal | None = None
    cpa: Decimal | None = None
    target_roas: Decimal | None = None
    target_cpa: Decimal | None = None
    verdict: Literal["above_target", "below_target", "insufficient_evidence", "no_target"]

    @field_validator("budget", "spend", "attributed_revenue", "roas", "cpa", "target_roas", "target_cpa", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class BudgetShift(StrictModel):
    from_envelope_ref: OpaqueRef | None = None
    to_envelope_ref: OpaqueRef | None = None
    from_channel: Channel
    to_channel: Channel
    amount: Decimal
    reason: ShortText

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="amount")


class ReallocationProposal(StrictModel):
    schema_id: Literal["lightbulb.budget_reallocation_proposal.v1"] = Field(default=REALLOCATION_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    portfolio_digest: Sha256Digest
    performance: tuple[ChannelPerformance, ...] = Field(min_length=1, max_length=8)
    shifts: tuple[BudgetShift, ...] = Field(default_factory=tuple, max_length=16)
    total_shifted: Decimal
    max_shift_allowed: Decimal
    requires_human_approval: Literal[True] = True
    executes_nothing: Literal[True] = True
    rationale: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    proposed_at: str
    proposal_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("total_shifted", "max_shift_allowed", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @field_validator("proposed_at")
    @classmethod
    def _proposed(cls, value: str) -> str:
        return timestamp(value, field_name="proposed_at")

    @model_validator(mode="after")
    def _proposal_is_exact(self, info: ValidationInfo) -> "ReallocationProposal":
        if self.total_shifted != sum((item.amount for item in self.shifts), Decimal("0")):
            raise ValueError("total shifted must equal the exact shifts")
        if any(item.from_channel == item.to_channel or item.amount <= 0 for item in self.shifts):
            raise ValueError("shifts must move positive amounts between different channels")
        if self.total_shifted > self.max_shift_allowed:
            raise ValueError("total shifted cannot exceed the allowed shift")
        if skip_digests(info):
            return self
        if self.proposal_digest != sealed_digest(ReallocationProposal, self, "proposal_digest"):
            raise ValueError("proposal_digest must commit the exact proposal")
        return self


def _bound_campaigns(plan: GrowthEngineLoopPlan, campaigns: Sequence[Any]) -> list[Any]:
    bound = [CAMPAIGN_LIFECYCLE.bind(plan, item)[1] for item in campaigns]
    return bound


def _channel_rows(bp: GrowthEngineBlueprint, campaigns: Sequence[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for policy in bp.channels:
        mine = [item for item in campaigns if item.ledger.channel == policy.channel]
        if not mine and not policy.enabled:
            continue
        budget = sum((item.ledger.budget for item in mine), Decimal("0"))
        spend = sum((item.ledger.spend for item in mine), Decimal("0"))
        revenue = sum((item.ledger.attributed_revenue for item in mine), Decimal("0"))
        conversions = sum(item.ledger.attributed_conversions for item in mine)
        roas = None if spend == 0 else (revenue / spend).quantize(MONEY_QUANTUM)
        cpa = None if conversions == 0 else (spend / Decimal(conversions)).quantize(MONEY_QUANTUM)
        if policy.target_roas is None and policy.target_cpa is None:
            verdict = "no_target"
        elif conversions < bp.min_conversions_for_evidence:
            verdict = "insufficient_evidence"
        elif policy.target_roas is not None and roas is not None:
            verdict = "above_target" if roas >= policy.target_roas else "below_target"
        elif policy.target_cpa is not None and cpa is not None:
            verdict = "above_target" if cpa <= policy.target_cpa else "below_target"
        else:
            verdict = "insufficient_evidence"
        rows.append({"channel": policy.channel, "campaigns": len(mine), "budget": str(budget), "spend": str(spend), "attributed_revenue": str(revenue), "conversions": conversions, "roas": None if roas is None else str(roas), "cpa": None if cpa is None else str(cpa), "target_roas": None if policy.target_roas is None else str(policy.target_roas), "target_cpa": None if policy.target_cpa is None else str(policy.target_cpa), "verdict": verdict})
    return rows


def propose_reallocation(plan: GrowthEngineLoopPlan | Mapping[str, Any], portfolio: CampaignPortfolio | Mapping[str, Any], campaigns: Sequence[Any], *, proposed_at: str) -> ReallocationProposal:
    """Propose budget shifts from below-target to above-target channels, bounded and never executed."""

    parsed_plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    parsed_portfolio = CampaignPortfolio.model_validate(detached(portfolio))
    if parsed_portfolio.plan_digest != parsed_plan.plan_digest:
        raise ValueError("PORTFOLIO_NOT_BOUND: the portfolio belongs to a different loop plan")
    bp = parsed_plan.blueprint
    bound = _bound_campaigns(parsed_plan, campaigns)
    if any(item.ledger.portfolio_digest != parsed_portfolio.portfolio_digest for item in bound):
        raise ValueError("CAMPAIGN_NOT_IN_PORTFOLIO: every campaign must belong to the portfolio")
    rows = _channel_rows(bp, bound)
    max_shift = pct(parsed_portfolio.total_budget - parsed_portfolio.unallocated, bp.max_shift_percent_per_cycle)
    below = [row for row in rows if row["verdict"] == "below_target"]
    above = [row for row in rows if row["verdict"] == "above_target"]
    shifts: list[dict[str, Any]] = []
    rationale: list[str] = []
    remaining = max_shift
    for loser in sorted(below, key=lambda row: Decimal(row["budget"]), reverse=True):
        for winner in sorted(above, key=lambda row: Decimal(row["roas"] or "0"), reverse=True):
            if remaining <= 0:
                break
            amount = min(remaining, pct(Decimal(loser["budget"]), bp.max_shift_percent_per_cycle))
            if amount <= 0:
                continue
            shifts.append({"from_channel": loser["channel"], "to_channel": winner["channel"], "amount": str(amount), "reason": f"{loser['channel']} is below target ({loser['roas'] or loser['cpa']}); {winner['channel']} is above target ({winner['roas'] or winner['cpa']})"})
            remaining -= amount
            break
    for row in rows:
        if row["verdict"] == "insufficient_evidence":
            rationale.append(f"{row['channel']}: {row['conversions']} conversions, below the {bp.min_conversions_for_evidence} needed for evidence; hold")
    if shifts:
        rationale.append(f"{len(shifts)} shift(s) proposed inside the {bp.max_shift_percent_per_cycle}% per-cycle limit")
    if not below:
        rationale.append("no channel is below target with sufficient evidence")
    if not rationale:
        rationale.append("portfolio is inside targets")
    payload = {"plan_digest": parsed_plan.plan_digest, "portfolio_digest": parsed_portfolio.portfolio_digest, "performance": rows, "shifts": shifts, "total_shifted": str(sum((Decimal(item["amount"]) for item in shifts), Decimal("0"))), "max_shift_allowed": str(max_shift), "rationale": rationale, "proposed_at": proposed_at}
    return seal(ReallocationProposal, payload, "proposal_digest")


# --------------------------------------------------------------------------- #
# Engine assessment
# --------------------------------------------------------------------------- #


class GrowthEngineAssessment(StrictModel):
    schema_id: Literal["lightbulb.growth_engine_assessment.v1"] = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["growth.store_truth_to_attributed_revenue@0.1.0"] = GROWTH_ENGINE_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    campaigns: int = Field(ge=0)
    campaigns_by_status: dict[str, int] = Field(default_factory=dict)
    spend: Decimal
    attributed_revenue: Decimal
    conversions: int = Field(ge=0)
    blended_roas: Decimal | None = None
    blended_cpa: Decimal | None = None
    ltv_to_cac: Decimal | None = None
    halted: int = Field(ge=0)
    by_channel: tuple[ChannelPerformance, ...] = Field(default_factory=tuple, max_length=8)
    learnings: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("spend", "attributed_revenue", "blended_roas", "blended_cpa", "ltv_to_cac", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "GrowthEngineAssessment":
        if skip_digests(info):
            return self
        if self.assessment_digest != sealed_digest(GrowthEngineAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_growth_engine(plan: GrowthEngineLoopPlan | Mapping[str, Any], campaigns: Sequence[Any], *, assessed_at: str, customer_lifetime_value: Any | None = None) -> GrowthEngineAssessment:
    parsed_plan = GrowthEngineLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    bound = _bound_campaigns(parsed_plan, campaigns)
    spend = sum((item.ledger.spend for item in bound), Decimal("0"))
    revenue = sum((item.ledger.attributed_revenue for item in bound), Decimal("0"))
    conversions = sum(item.ledger.attributed_conversions for item in bound)
    roas = None if spend == 0 else (revenue / spend).quantize(MONEY_QUANTUM)
    cpa = None if conversions == 0 else (spend / Decimal(conversions)).quantize(MONEY_QUANTUM)
    ltv = None if customer_lifetime_value is None else decimal_value(customer_lifetime_value, field_name="customer_lifetime_value")
    ltv_to_cac = None if ltv is None or cpa is None or cpa == 0 else (ltv / cpa).quantize(MONEY_QUANTUM)
    learnings: list[str] = []
    recommendations: list[str] = []
    if roas is not None and roas < bp.target_blended_roas:
        learnings.append(f"blended ROAS {roas} is below the {bp.target_blended_roas} target")
        recommendations.append("shift budget toward channels above target and pause the lowest ROAS envelope")
    if ltv_to_cac is not None and ltv_to_cac < bp.target_ltv_to_cac:
        learnings.append(f"LTV to CAC {ltv_to_cac} is below the {bp.target_ltv_to_cac} target")
        recommendations.append("raise retention and lifecycle spend before adding acquisition spend")
    halted = sum(1 for item in bound if item.status == "halted")
    if halted:
        learnings.append(f"{halted} campaign(s) halted; review the halt reasons before the next portfolio")
    rows = _channel_rows(bp, bound)
    for row in rows:
        if row["verdict"] == "below_target":
            learnings.append(f"{row['channel']} is below target ({row['roas'] or row['cpa']})")
    if not learnings:
        learnings.append("engine is inside blueprint targets")
    payload = {"profile": bp.profile, "currency": bp.currency, "campaigns": len(bound), "campaigns_by_status": {status: sum(1 for item in bound if item.status == status) for status in sorted({item.status for item in bound})}, "spend": str(spend), "attributed_revenue": str(revenue), "conversions": conversions, "blended_roas": None if roas is None else str(roas), "blended_cpa": None if cpa is None else str(cpa), "ltv_to_cac": None if ltv_to_cac is None else str(ltv_to_cac), "halted": halted, "by_channel": rows, "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at}
    return seal(GrowthEngineAssessment, payload, "assessment_digest")


GROWTH_ENGINE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine.v1",
    "engine": GROWTH_ENGINE_KIND,
    "title": "Growth engine",
    "golden_loop": GROWTH_ENGINE_GOLDEN_LOOP,
    "profiles": sorted(GROWTH_ENGINE_PROFILES),
    "channels": list(CHANNELS),
    "campaign_statuses": list(CAMPAIGN_STATUSES),
    "campaign_events": list(CAMPAIGN_EVENTS),
    "required_connectors": sorted({tool.split(".")[0] for tool in _KNOWN_CONNECTOR_TOOLS}),
    "composes_with_archetypes": ["product_commerce", "subscription_business", "saas_product", "service_business", "appointment_business", "marketplace_business"],
    "economic_spine": {"acquire_demand": "plan_portfolio / compose_candidates / approve_and_launch", "create_offer": "audit_truth (approved claims)", "deliver_value": "handed to the archetype loop", "monetize": "attribute", "learn": "reallocate / learn"},
    "explicit_inputs_never_invented": ["approved claims and their evidence", "brand-safety terms", "audience consent for messaging", "budget caps and approval thresholds", "measurement observations", "human approval of reallocations"],
}

__all__ = [
    "CAMPAIGN_EVENTS",
    "CAMPAIGN_LIFECYCLE",
    "CAMPAIGN_STATUSES",
    "CHANNELS",
    "GROWTH_ENGINE_GOLDEN_LOOP",
    "GROWTH_ENGINE_KIND",
    "GROWTH_ENGINE_MANIFEST",
    "GROWTH_ENGINE_PROFILES",
    "STAGE_ORDER",
    "TERMINAL_CAMPAIGN_STATUSES",
    "ApprovedClaim",
    "BudgetEnvelope",
    "BudgetShift",
    "CampaignCommand",
    "CampaignEffectBoundary",
    "CampaignLedger",
    "CampaignPortfolio",
    "CampaignReceipt",
    "CampaignState",
    "CampaignTransitionResult",
    "ChannelPerformance",
    "ChannelPolicy",
    "GrowthEngineAssessment",
    "GrowthEngineBlueprint",
    "GrowthEngineLoopPlan",
    "ReallocationProposal",
    "StageBinding",
    "advance_campaign",
    "assess_growth_engine",
    "campaign_command_digest",
    "compile_growth_engine_blueprint",
    "open_campaign",
    "plan_campaign_portfolio",
    "propose_reallocation",
    "seal_campaign_command",
    "seal_growth_engine_blueprint",
]
