"""SaaS Operating Engine Golden Operating Loop: launched product to compounding revenue.

The engine that keeps a launched SaaS product shipping, measuring, supporting,
and selling itself under governance::

    Observe usage -> Measure cohorts (activation, retention, expansion)
      -> Triage support -> Rank roadmap from evidence -> Ship release
      -> Verify release (canary, thresholds, rollback window) -> Drive expansion
      -> Learn

It picks up where ``saas.market_research_to_launched_product`` hands off and
composes with the subscription loop (billing and renewals), the software
production loop (building the change), and the service case loop (support
resolution).

What is typed here: the operating blueprint (activation definition, cohort
policy, release policy, support SLAs, roadmap scoring, expansion signals,
plans, targets), a sealed usage snapshot with activation and retention
cohorts, expansion candidates and churn risks, a rubric-scored support
triage, an evidence-gated roadmap ranking, a replay-fenced release
lifecycle with canary, threshold verification and a rollback window, and an
operating assessment against targets.

Nothing here deploys, rolls back, changes a plan, contacts a customer, or
reads product analytics.  Spring authorizes those effects; the Connector
Runtime executes them through ``github.*``, ``mixpanel.*`` / ``posthog.*``,
``stripe.*``, ``zendesk.*`` / ``intercom.*``, ``slack.*``, and ``statuspage.*``
tools.
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
    LifecycleSpec,
    OpaqueRef,
    Sha256Digest,
    ShortText,
    StrictModel,
    add_days,
    decimal_value,
    detached,
    parsed,
    percent_value,
    ratio_percent,
    require,
    seal,
    sealed_digest,
    skip_digests,
    timestamp,
    unique,
)

SAAS_OPERATING_GOLDEN_LOOP = "saas.launched_product_to_compounding_revenue@0.1.0"
SAAS_OPERATING_KIND = "saas_operating_engine"
BLUEPRINT_SCHEMA = "lightbulb.saas_operating_blueprint.v1"
PLAN_SCHEMA = "lightbulb.saas_operating_loop_plan.v1"
SNAPSHOT_SCHEMA = "lightbulb.saas_usage_snapshot.v1"
TRIAGE_SCHEMA = "lightbulb.support_triage.v1"
ROADMAP_SCHEMA = "lightbulb.roadmap_ranking.v1"
ASSESSMENT_SCHEMA = "lightbulb.saas_operating_assessment.v1"
MAX_RELEASE_TRANSITIONS = 120

BlueprintProfile = Literal["plg_self_serve", "sales_assisted", "enterprise_platform", "usage_based", "custom"]
Severity = Literal["sev1", "sev2", "sev3", "sev4"]
SEVERITIES: tuple[str, ...] = ("sev1", "sev2", "sev3", "sev4")
EvidenceKind = Literal["automated_tests", "staging_verification", "changelog", "security_review", "performance_check", "customer_validation"]
EVIDENCE_KINDS: tuple[str, ...] = ("automated_tests", "staging_verification", "changelog", "security_review", "performance_check", "customer_validation")
LoopStage = Literal["observe_usage", "measure_cohorts", "triage_support", "rank_roadmap", "ship_release", "verify_release", "drive_expansion", "learn"]
STAGE_ORDER: tuple[str, ...] = ("observe_usage", "measure_cohorts", "triage_support", "rank_roadmap", "ship_release", "verify_release", "drive_expansion", "learn")

ReleaseStatus = Literal["proposed", "evidenced", "approved", "canary", "verified", "rolled_out", "rolled_back", "abandoned"]
RELEASE_STATUSES: tuple[str, ...] = ("proposed", "evidenced", "approved", "canary", "verified", "rolled_out", "rolled_back", "abandoned")
TERMINAL_RELEASE_STATUSES: frozenset[str] = frozenset({"rolled_back", "abandoned"})
ReleaseEvent = Literal["propose", "attach_evidence", "approve", "start_canary", "observe_canary", "verify", "roll_out", "roll_back", "abandon"]
RELEASE_EVENTS: tuple[str, ...] = ("propose", "attach_evidence", "approve", "start_canary", "observe_canary", "verify", "roll_out", "roll_back", "abandon")
_RELEASE_TABLE: dict[tuple[str, str], str] = {
    ("new", "propose"): "proposed",
    ("proposed", "attach_evidence"): "proposed",
    ("proposed", "abandon"): "abandoned",
    ("evidenced", "attach_evidence"): "evidenced",
    ("evidenced", "approve"): "approved",
    ("evidenced", "start_canary"): "canary",
    ("evidenced", "abandon"): "abandoned",
    ("approved", "start_canary"): "canary",
    ("approved", "abandon"): "abandoned",
    ("canary", "observe_canary"): "canary",
    ("canary", "verify"): "verified",
    ("canary", "roll_back"): "rolled_back",
    ("verified", "roll_out"): "rolled_out",
    ("verified", "roll_back"): "rolled_back",
    ("rolled_out", "roll_back"): "rolled_back",
}

_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_saas_operating", "saas_ops.observe_usage", "saas_ops.triage_support", "saas_ops.rank_roadmap", "saas_ops.advance_release", "saas_ops.assess_operating",
        "saas.advance_product", "saas.assess_product", "subscription.advance_account", "subscription.prorate_plan_change", "subscription.assess_portfolio",
        "project.request_software_production", "project.admit_software_production_run", "project.apply_software_production_event", "product.evaluate_release_governance_controls",
        "service.intake_and_classify_case", "service.verify_case_resolution", "customer_success.prevent_returns_and_expand_ltv", "growth.build_unit_economics", "growth.review_customer_value",
        "communication.write_email", "approval.request_decision", "learning.plan_optimization_sweep", "compliance.evaluate_regulated_controls",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset(
    {
        "mixpanel.query_events", "posthog.query_events", "posthog.get_cohorts", "stripe.list_customers", "stripe.list_invoices", "stripe.list_balance_transactions",
        "zendesk.list_tickets", "zendesk.update_ticket", "intercom.list_conversations", "intercom.reply_conversation", "slack.post_message",
        "github.list_pull_requests", "github.get_workflow_run", "github.create_release", "github.list_deployments", "github.create_deployment_status", "statuspage.create_incident",
        "hubspot.update_contact", "hubspot.create_deal",
    }
)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class ActivationDefinition(StrictModel):
    required_events: tuple[ShortText, ...] = Field(min_length=1, max_length=10)
    within_days: int = Field(default=7, ge=1, le=90)


class PlanTier(StrictModel):
    plan_ref: OpaqueRef
    name: ShortText
    monthly_price: Decimal
    seat_limit: int | None = Field(default=None, ge=1, le=1_000_000)
    usage_limit: int | None = Field(default=None, ge=1, le=1_000_000_000)

    @field_validator("monthly_price", mode="before")
    @classmethod
    def _price(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="monthly_price")


class ReleasePolicy(StrictModel):
    required_evidence: tuple[EvidenceKind, ...] = Field(min_length=1, max_length=6)
    approval_required: bool = True
    canary_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    max_error_rate_percent: Decimal = Field(default=Decimal("1"), validate_default=True)
    max_p95_latency_ms: int = Field(default=800, ge=1, le=60000)
    min_canary_observations: int = Field(default=2, ge=1, le=100)
    rollback_window_hours: int = Field(default=72, ge=1, le=720)

    @field_validator("canary_percent", "max_error_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))


class SupportSla(StrictModel):
    severity: Severity
    first_response_hours: int = Field(ge=1, le=720)
    resolution_hours: int = Field(ge=1, le=2000)
    escalate_to: ShortText

    @model_validator(mode="after")
    def _ordered(self) -> "SupportSla":
        if self.resolution_hours < self.first_response_hours:
            raise ValueError(f"{self.severity} resolution window must be at least the first-response window")
        return self


class RoadmapWeights(StrictModel):
    reach: int = Field(ge=1, le=100)
    impact: int = Field(ge=1, le=100)
    confidence: int = Field(ge=1, le=100)
    min_evidence_refs: int = Field(default=1, ge=0, le=20)


class ExpansionSignals(StrictModel):
    usage_of_limit_percent: Decimal = Field(default=Decimal("80"), validate_default=True)
    seat_growth_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    churn_risk_inactive_days: int = Field(default=14, ge=1, le=365)

    @field_validator("usage_of_limit_percent", "seat_growth_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))


class SaasOperatingBlueprint(StrictModel):
    schema_id: Literal["lightbulb.saas_operating_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    activation: ActivationDefinition
    plans: tuple[PlanTier, ...] = Field(min_length=1, max_length=20)
    release_policy: ReleasePolicy
    support_slas: tuple[SupportSla, ...] = Field(min_length=4, max_length=4)
    roadmap: RoadmapWeights
    expansion: ExpansionSignals
    cohort_period_days: int = Field(default=7, ge=1, le=90)
    retention_horizon_periods: int = Field(default=4, ge=1, le=52)
    target_activation_rate_percent: Decimal = Field(default=Decimal("40"), validate_default=True)
    target_retention_rate_percent: Decimal = Field(default=Decimal("60"), validate_default=True)
    target_expansion_rate_percent: Decimal = Field(default=Decimal("10"), validate_default=True)
    target_sla_attainment_percent: Decimal = Field(default=Decimal("95"), validate_default=True)
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_activation_rate_percent", "target_retention_rate_percent", "target_expansion_rate_percent", "target_sla_attainment_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Decimal:
        return percent_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "SaasOperatingBlueprint":
        unique([item.plan_ref for item in self.plans], label="plan refs")
        if tuple(item.severity for item in self.support_slas) != SEVERITIES:
            raise ValueError("support SLAs must cover sev1..sev4 in order")
        unique(list(self.release_policy.required_evidence), label="required evidence kinds")
        if skip_digests(info):
            return self
        if self.blueprint_digest != sealed_digest(SaasOperatingBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self

    def plan(self, ref: str) -> PlanTier | None:
        return next((item for item in self.plans if item.plan_ref == ref), None)

    def sla(self, severity: str) -> SupportSla:
        return next(item for item in self.support_slas if item.severity == severity)


def seal_saas_operating_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(detached(blueprint))
    raw["blueprint_digest"] = sealed_digest(SaasOperatingBlueprint, raw, "blueprint_digest")
    return SaasOperatingBlueprint.model_validate(raw).to_dict()


_SLAS = [{"severity": "sev1", "first_response_hours": 1, "resolution_hours": 8, "escalate_to": "on-call engineer"}, {"severity": "sev2", "first_response_hours": 4, "resolution_hours": 48, "escalate_to": "support lead"}, {"severity": "sev3", "first_response_hours": 24, "resolution_hours": 120, "escalate_to": "support lead"}, {"severity": "sev4", "first_response_hours": 72, "resolution_hours": 336, "escalate_to": "product"}]
_ENTERPRISE_SLAS = [{"severity": "sev1", "first_response_hours": 1, "resolution_hours": 4, "escalate_to": "incident commander"}, {"severity": "sev2", "first_response_hours": 2, "resolution_hours": 24, "escalate_to": "account engineer"}, {"severity": "sev3", "first_response_hours": 8, "resolution_hours": 72, "escalate_to": "support lead"}, {"severity": "sev4", "first_response_hours": 24, "resolution_hours": 240, "escalate_to": "product"}]
SAAS_OPERATING_PROFILES: dict[str, dict[str, Any]] = {
    "plg_self_serve": {"profile": "plg_self_serve", "name": "Product-led self-serve", "activation": {"required_events": ["workspace_created", "first_report_run", "teammate_invited"], "within_days": 7}, "plans": [{"plan_ref": "free", "name": "Free", "monthly_price": "0", "seat_limit": 3}, {"plan_ref": "team", "name": "Team", "monthly_price": "49", "seat_limit": 10}, {"plan_ref": "business", "name": "Business", "monthly_price": "199", "seat_limit": 50}], "release_policy": {"required_evidence": ["automated_tests", "staging_verification", "changelog"], "approval_required": False, "canary_percent": "10", "max_error_rate_percent": "1", "max_p95_latency_ms": 800, "min_canary_observations": 2, "rollback_window_hours": 72}, "support_slas": _SLAS, "roadmap": {"reach": 40, "impact": 40, "confidence": 20, "min_evidence_refs": 2}, "expansion": {"usage_of_limit_percent": "80", "seat_growth_percent": "25", "churn_risk_inactive_days": 14}, "cohort_period_days": 7, "retention_horizon_periods": 4, "target_activation_rate_percent": "40", "target_retention_rate_percent": "55", "target_expansion_rate_percent": "10", "target_sla_attainment_percent": "95", "notes": "Weekly cohorts; ship without approval behind canary gates."},
    "sales_assisted": {"profile": "sales_assisted", "name": "Sales-assisted mid-market", "activation": {"required_events": ["integration_connected", "first_workflow_run"], "within_days": 14}, "plans": [{"plan_ref": "growth", "name": "Growth", "monthly_price": "499", "seat_limit": 25}, {"plan_ref": "scale", "name": "Scale", "monthly_price": "1499", "seat_limit": 100}], "release_policy": {"required_evidence": ["automated_tests", "staging_verification", "changelog", "customer_validation"], "approval_required": True, "canary_percent": "5", "max_error_rate_percent": "0.5", "max_p95_latency_ms": 600, "min_canary_observations": 3, "rollback_window_hours": 96}, "support_slas": _SLAS, "roadmap": {"reach": 30, "impact": 45, "confidence": 25, "min_evidence_refs": 2}, "expansion": {"usage_of_limit_percent": "75", "seat_growth_percent": "20", "churn_risk_inactive_days": 21}, "cohort_period_days": 30, "retention_horizon_periods": 3, "target_activation_rate_percent": "60", "target_retention_rate_percent": "85", "target_expansion_rate_percent": "15", "target_sla_attainment_percent": "97", "notes": "Monthly cohorts; releases approved and validated with customers."},
    "enterprise_platform": {"profile": "enterprise_platform", "name": "Enterprise platform", "activation": {"required_events": ["sso_configured", "data_source_connected", "first_production_job"], "within_days": 30}, "plans": [{"plan_ref": "enterprise", "name": "Enterprise", "monthly_price": "8000", "seat_limit": 1000}], "release_policy": {"required_evidence": ["automated_tests", "staging_verification", "changelog", "security_review", "performance_check"], "approval_required": True, "canary_percent": "2", "max_error_rate_percent": "0.2", "max_p95_latency_ms": 500, "min_canary_observations": 4, "rollback_window_hours": 168}, "support_slas": _ENTERPRISE_SLAS, "roadmap": {"reach": 25, "impact": 50, "confidence": 25, "min_evidence_refs": 3}, "expansion": {"usage_of_limit_percent": "70", "seat_growth_percent": "15", "churn_risk_inactive_days": 30}, "cohort_period_days": 30, "retention_horizon_periods": 6, "target_activation_rate_percent": "80", "target_retention_rate_percent": "95", "target_expansion_rate_percent": "20", "target_sla_attainment_percent": "99", "notes": "Security and performance evidence on every release."},
    "usage_based": {"profile": "usage_based", "name": "Usage-based API product", "activation": {"required_events": ["api_key_created", "first_successful_call", "hundredth_call"], "within_days": 7}, "plans": [{"plan_ref": "pay-as-you-go", "name": "Pay as you go", "monthly_price": "0", "usage_limit": 100000}, {"plan_ref": "pro", "name": "Pro", "monthly_price": "299", "usage_limit": 2000000}], "release_policy": {"required_evidence": ["automated_tests", "staging_verification", "changelog", "performance_check"], "approval_required": False, "canary_percent": "10", "max_error_rate_percent": "0.5", "max_p95_latency_ms": 300, "min_canary_observations": 3, "rollback_window_hours": 48}, "support_slas": _SLAS, "roadmap": {"reach": 45, "impact": 35, "confidence": 20, "min_evidence_refs": 1}, "expansion": {"usage_of_limit_percent": "85", "seat_growth_percent": "50", "churn_risk_inactive_days": 10}, "cohort_period_days": 7, "retention_horizon_periods": 4, "target_activation_rate_percent": "35", "target_retention_rate_percent": "50", "target_expansion_rate_percent": "25", "target_sla_attainment_percent": "95", "notes": "Usage limits drive expansion; latency is the release gate."},
}


class StageBinding(StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=30)
    release_events: tuple[ReleaseEvent, ...] = Field(default_factory=tuple, max_length=12)
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


class SaasOperatingLoopPlan(StrictModel):
    schema_id: Literal["lightbulb.saas_operating_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["saas.launched_product_to_compounding_revenue@0.1.0"] = SAAS_OPERATING_GOLDEN_LOOP
    engine: Literal["saas_operating_engine"] = SAAS_OPERATING_KIND
    blueprint: SaasOperatingBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=8, max_length=8)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "SaasOperatingLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if skip_digests(info):
            return self
        if self.plan_digest != sealed_digest(SaasOperatingLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(bp: SaasOperatingBlueprint) -> list[dict[str, Any]]:
    policy = bp.release_policy
    return [
        {"stage": "observe_usage", "title": "Observe product usage and billing", "primitive_refs": ("saas_ops.observe_usage",), "connector_tools": ("mixpanel.query_events", "posthog.query_events", "posthog.get_cohorts", "stripe.list_customers", "stripe.list_invoices"), "gate": "none"},
        {"stage": "measure_cohorts", "title": f"Measure activation and {bp.cohort_period_days}-day cohorts", "primitive_refs": ("saas_ops.observe_usage", "growth.build_unit_economics", "growth.review_customer_value"), "gate": "none"},
        {"stage": "triage_support", "title": "Triage support against SLAs", "primitive_refs": ("saas_ops.triage_support", "service.intake_and_classify_case", "service.verify_case_resolution"), "connector_tools": ("zendesk.list_tickets", "zendesk.update_ticket", "intercom.list_conversations", "intercom.reply_conversation", "slack.post_message"), "gate": "spring_approval"},
        {"stage": "rank_roadmap", "title": "Rank the roadmap from evidence", "primitive_refs": ("saas_ops.rank_roadmap", "saas.advance_product"), "gate": "none"},
        {"stage": "ship_release", "title": "Ship a release through the software production loop" + (" with approval" if policy.approval_required else ""), "primitive_refs": ("saas_ops.advance_release", "project.request_software_production", "project.admit_software_production_run", "product.evaluate_release_governance_controls") + (("approval.request_decision",) if policy.approval_required else ()), "connector_tools": ("github.list_pull_requests", "github.get_workflow_run", "github.create_release", "github.list_deployments"), "release_events": ("propose", "attach_evidence", "approve", "abandon"), "gate": "spring_approval"},
        {"stage": "verify_release", "title": f"Canary {policy.canary_percent}% and verify inside a {policy.rollback_window_hours}h rollback window", "primitive_refs": ("saas_ops.advance_release", "project.apply_software_production_event"), "connector_tools": ("github.create_deployment_status", "statuspage.create_incident", "posthog.query_events"), "release_events": ("start_canary", "observe_canary", "verify", "roll_out", "roll_back"), "gate": "spring_approval"},
        {"stage": "drive_expansion", "title": "Drive expansion and save churn risks", "primitive_refs": ("subscription.prorate_plan_change", "subscription.advance_account", "customer_success.prevent_returns_and_expand_ltv", "communication.write_email"), "connector_tools": ("hubspot.update_contact", "hubspot.create_deal", "stripe.list_balance_transactions"), "gate": "customer_consent"},
        {"stage": "learn", "title": "Learn: activation, retention, expansion, SLA attainment", "primitive_refs": ("saas_ops.assess_operating", "subscription.assess_portfolio", "learning.plan_optimization_sweep"), "gate": "none"},
    ]


def compile_saas_operating_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> SaasOperatingLoopPlan:
    if isinstance(profile, str):
        if profile not in SAAS_OPERATING_PROFILES:
            raise ValueError(f"unknown SaaS operating profile {profile!r}; choose one of {sorted(SAAS_OPERATING_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(SAAS_OPERATING_PROFILES[profile]))
    else:
        raw = dict(detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = SaasOperatingBlueprint.model_validate(seal_saas_operating_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = sealed_digest(SaasOperatingLoopPlan, payload, "plan_digest")
    return SaasOperatingLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Usage snapshot
# --------------------------------------------------------------------------- #


class AccountUsage(StrictModel):
    """Per-account usage facts; opaque account references only."""

    account_ref: OpaqueRef
    plan_ref: OpaqueRef
    signed_up_at: str
    last_active_at: str | None = None
    events: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    activated_at: str | None = None
    seats_used: int = Field(default=1, ge=0, le=1_000_000)
    seats_last_period: int = Field(default=1, ge=0, le=1_000_000)
    usage_units: int = Field(default=0, ge=0, le=1_000_000_000)
    mrr: Decimal = Field(default=Decimal("0"), validate_default=True)

    @field_validator("mrr", mode="before")
    @classmethod
    def _mrr(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="mrr")

    @field_validator("signed_up_at", "last_active_at", "activated_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class CohortRow(StrictModel):
    cohort_start: str
    accounts: int = Field(ge=0)
    activated: int = Field(ge=0)
    retained: int = Field(ge=0)
    activation_rate_percent: Decimal | None = None
    retention_rate_percent: Decimal | None = None

    @field_validator("activation_rate_percent", "retention_rate_percent", mode="before")
    @classmethod
    def _rates(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class ExpansionCandidate(StrictModel):
    account_ref: OpaqueRef
    plan_ref: OpaqueRef
    reason: ShortText
    suggested_plan_ref: OpaqueRef | None = None
    requires_customer_consent: Literal[True] = True


class ChurnRisk(StrictModel):
    account_ref: OpaqueRef
    plan_ref: OpaqueRef
    inactive_days: int = Field(ge=0)
    mrr_at_risk: Decimal

    @field_validator("mrr_at_risk", mode="before")
    @classmethod
    def _mrr(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="mrr_at_risk")


class UsageSnapshot(StrictModel):
    schema_id: Literal["lightbulb.saas_usage_snapshot.v1"] = Field(default=SNAPSHOT_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    observed_at: str
    accounts: int = Field(ge=0)
    activated: int = Field(ge=0)
    activation_rate_percent: Decimal | None = None
    retention_rate_percent: Decimal | None = None
    mrr: Decimal
    cohorts: tuple[CohortRow, ...] = Field(default_factory=tuple, max_length=104)
    expansion_candidates: tuple[ExpansionCandidate, ...] = Field(default_factory=tuple, max_length=5000)
    churn_risks: tuple[ChurnRisk, ...] = Field(default_factory=tuple, max_length=5000)
    snapshot_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("activation_rate_percent", "retention_rate_percent", "mrr", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return timestamp(value, field_name="observed_at")

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "UsageSnapshot":
        if skip_digests(info):
            return self
        if self.snapshot_digest != sealed_digest(UsageSnapshot, self, "snapshot_digest"):
            raise ValueError("snapshot_digest must commit the exact snapshot")
        return self


def _activated(bp: SaasOperatingBlueprint, account: AccountUsage) -> bool:
    if account.activated_at is not None:
        return (parsed(account.activated_at) - parsed(account.signed_up_at)).days <= bp.activation.within_days
    events = {event.lower() for event in account.events}
    return all(required.lower() in events for required in bp.activation.required_events)


def observe_usage(plan: SaasOperatingLoopPlan | Mapping[str, Any], accounts: Sequence[AccountUsage | Mapping[str, Any]], *, observed_at: str) -> UsageSnapshot:
    """Derive activation, cohort retention, expansion candidates, and churn risks from account usage."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    rows = [AccountUsage.model_validate(detached(item)) for item in accounts]
    unique([item.account_ref for item in rows], label="account refs")
    now = parsed(timestamp(observed_at, field_name="observed_at"))
    for item in rows:
        if bp.plan(item.plan_ref) is None:
            raise ValueError(f"PLAN_UNKNOWN: {item.plan_ref} is not a blueprint plan")
    activated = [item for item in rows if _activated(bp, item)]
    period = bp.cohort_period_days
    cohorts: dict[str, list[AccountUsage]] = {}
    for item in rows:
        signed = parsed(item.signed_up_at)
        bucket = (now - signed).days // period
        if bucket < 0:
            raise ValueError("ACCOUNT_IN_FUTURE: signed_up_at is after observed_at")
        start = add_days(item.signed_up_at, 0)
        key = str((signed - (signed - now)).date()) if False else start[:10]
        cohorts.setdefault(key[:7] if period >= 28 else key, []).append(item)
    cohort_rows = []
    retained_total, eligible_total = 0, 0
    for key in sorted(cohorts):
        members = cohorts[key]
        act = [item for item in members if _activated(bp, item)]
        eligible = [item for item in members if (now - parsed(item.signed_up_at)).days >= period * bp.retention_horizon_periods]
        retained = [item for item in eligible if item.last_active_at is not None and (now - parsed(item.last_active_at)).days < period]
        retained_total += len(retained)
        eligible_total += len(eligible)
        cohort_rows.append({"cohort_start": key, "accounts": len(members), "activated": len(act), "retained": len(retained), "activation_rate_percent": None if not members else str(ratio_percent(len(act), len(members))), "retention_rate_percent": None if not eligible else str(ratio_percent(len(retained), len(eligible)))})
    expansion: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    ordered_plans = sorted(bp.plans, key=lambda item: item.monthly_price)
    for item in rows:
        tier = bp.plan(item.plan_ref)
        assert tier is not None
        higher = next((candidate for candidate in ordered_plans if candidate.monthly_price > tier.monthly_price), None)
        if tier.seat_limit and ratio_percent(item.seats_used, tier.seat_limit) is not None and item.seats_used * 100 >= tier.seat_limit * bp.expansion.usage_of_limit_percent:
            expansion.append({"account_ref": item.account_ref, "plan_ref": item.plan_ref, "reason": f"seats {item.seats_used} of {tier.seat_limit} used", "suggested_plan_ref": None if higher is None else higher.plan_ref})
        elif tier.usage_limit and item.usage_units * 100 >= tier.usage_limit * bp.expansion.usage_of_limit_percent:
            expansion.append({"account_ref": item.account_ref, "plan_ref": item.plan_ref, "reason": f"usage {item.usage_units} of {tier.usage_limit} units", "suggested_plan_ref": None if higher is None else higher.plan_ref})
        elif item.seats_last_period > 0 and (item.seats_used - item.seats_last_period) * 100 >= item.seats_last_period * bp.expansion.seat_growth_percent and item.seats_used > item.seats_last_period:
            expansion.append({"account_ref": item.account_ref, "plan_ref": item.plan_ref, "reason": f"seats grew from {item.seats_last_period} to {item.seats_used}", "suggested_plan_ref": None if higher is None else higher.plan_ref})
        inactive = (now - parsed(item.last_active_at)).days if item.last_active_at is not None else (now - parsed(item.signed_up_at)).days
        if inactive >= bp.expansion.churn_risk_inactive_days and item.mrr > 0:
            risks.append({"account_ref": item.account_ref, "plan_ref": item.plan_ref, "inactive_days": inactive, "mrr_at_risk": str(item.mrr)})
    payload = {"plan_digest": parsed_plan.plan_digest, "observed_at": timestamp(observed_at, field_name="observed_at"), "accounts": len(rows), "activated": len(activated), "activation_rate_percent": None if not rows else str(ratio_percent(len(activated), len(rows))), "retention_rate_percent": None if eligible_total == 0 else str(ratio_percent(retained_total, eligible_total)), "mrr": str(sum((item.mrr for item in rows), Decimal("0"))), "cohorts": cohort_rows, "expansion_candidates": expansion, "churn_risks": risks}
    return seal(UsageSnapshot, payload, "snapshot_digest")


# --------------------------------------------------------------------------- #
# Support triage
# --------------------------------------------------------------------------- #


class SupportCaseFacts(StrictModel):
    case_ref: OpaqueRef
    account_ref: OpaqueRef
    plan_ref: OpaqueRef
    opened_at: str
    reported_impact: Literal["outage", "degraded", "blocked_workflow", "question", "feature_request"]
    accounts_affected: int = Field(default=1, ge=1, le=1_000_000)
    data_at_risk: bool = False
    security_related: bool = False
    first_response_at: str | None = None

    @field_validator("opened_at", "first_response_at")
    @classmethod
    def _times(cls, value: str | None, info: ValidationInfo) -> str | None:
        return None if value is None else timestamp(value, field_name=str(info.field_name))


class SupportTriage(StrictModel):
    schema_id: Literal["lightbulb.support_triage.v1"] = Field(default=TRIAGE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    case_ref: OpaqueRef
    severity: Severity
    first_response_due: str
    resolution_due: str
    escalate_to: ShortText
    first_response_met: bool | None = None
    reasons: tuple[ShortText, ...] = Field(min_length=1, max_length=8)
    hands_off_to: Literal["service.case_customer_verified_resolution"] = "service.case_customer_verified_resolution"
    triage_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "SupportTriage":
        if skip_digests(info):
            return self
        if self.triage_digest != sealed_digest(SupportTriage, self, "triage_digest"):
            raise ValueError("triage_digest must commit the exact triage")
        return self


def triage_support_case(plan: SaasOperatingLoopPlan | Mapping[str, Any], case: SupportCaseFacts | Mapping[str, Any]) -> SupportTriage:
    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    facts = SupportCaseFacts.model_validate(detached(case))
    if bp.plan(facts.plan_ref) is None:
        raise ValueError(f"PLAN_UNKNOWN: {facts.plan_ref} is not a blueprint plan")
    reasons: list[str] = []
    if facts.security_related or facts.data_at_risk:
        severity = "sev1"
        reasons.append("security or data at risk")
    elif facts.reported_impact == "outage":
        severity = "sev1" if facts.accounts_affected > 1 else "sev2"
        reasons.append(f"outage affecting {facts.accounts_affected} account(s)")
    elif facts.reported_impact in {"degraded", "blocked_workflow"}:
        severity = "sev2" if facts.accounts_affected > 10 else "sev3"
        reasons.append(f"{facts.reported_impact} for {facts.accounts_affected} account(s)")
    else:
        severity = "sev4"
        reasons.append(facts.reported_impact.replace("_", " "))
    sla = bp.sla(severity)
    opened = parsed(facts.opened_at)
    first_due = opened.replace(microsecond=0)
    from datetime import timedelta

    first_due_iso = timestamp((first_due + timedelta(hours=sla.first_response_hours)).isoformat().replace("+00:00", "Z"), field_name="first_response_due")
    resolution_iso = timestamp((first_due + timedelta(hours=sla.resolution_hours)).isoformat().replace("+00:00", "Z"), field_name="resolution_due")
    met = None if facts.first_response_at is None else parsed(facts.first_response_at) <= parsed(first_due_iso)
    if met is False:
        reasons.append("first response SLA missed")
    payload = {"plan_digest": parsed_plan.plan_digest, "case_ref": facts.case_ref, "severity": severity, "first_response_due": first_due_iso, "resolution_due": resolution_iso, "escalate_to": sla.escalate_to, "first_response_met": met, "reasons": reasons}
    return seal(SupportTriage, payload, "triage_digest")


# --------------------------------------------------------------------------- #
# Roadmap ranking
# --------------------------------------------------------------------------- #


class RoadmapCandidate(StrictModel):
    candidate_ref: OpaqueRef
    title: ShortText
    reach_accounts: int = Field(ge=0, le=1_000_000)
    impact: int = Field(ge=1, le=5)
    confidence_percent: int = Field(ge=1, le=100)
    effort_weeks: Decimal
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("effort_weeks", mode="before")
    @classmethod
    def _effort(cls, value: Any) -> Decimal:
        result = decimal_value(value, field_name="effort_weeks")
        if result <= 0:
            raise ValueError("effort_weeks must be positive")
        return result


class RankedItem(StrictModel):
    candidate_ref: OpaqueRef
    title: ShortText
    score: Decimal
    rank: int = Field(ge=1)
    admitted: bool
    reason: ShortText

    @field_validator("score", mode="before")
    @classmethod
    def _score(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="score")


class RoadmapRanking(StrictModel):
    schema_id: Literal["lightbulb.roadmap_ranking.v1"] = Field(default=ROADMAP_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    ranked: tuple[RankedItem, ...] = Field(min_length=1, max_length=500)
    held_for_evidence: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=500)
    ranked_at: str
    ranking_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("ranked_at")
    @classmethod
    def _at(cls, value: str) -> str:
        return timestamp(value, field_name="ranked_at")

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "RoadmapRanking":
        if [item.rank for item in self.ranked] != list(range(1, len(self.ranked) + 1)):
            raise ValueError("ranks must be contiguous from 1")
        if skip_digests(info):
            return self
        if self.ranking_digest != sealed_digest(RoadmapRanking, self, "ranking_digest"):
            raise ValueError("ranking_digest must commit the exact ranking")
        return self


def rank_roadmap(plan: SaasOperatingLoopPlan | Mapping[str, Any], candidates: Sequence[RoadmapCandidate | Mapping[str, Any]], *, ranked_at: str) -> RoadmapRanking:
    """Weighted RICE: (reach·wr + impact·wi + confidence·wc) / effort; candidates without enough evidence are held."""

    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(plan))
    weights = parsed_plan.blueprint.roadmap
    rows = [RoadmapCandidate.model_validate(detached(item)) for item in candidates]
    if not rows:
        raise ValueError("NO_CANDIDATES: rank at least one candidate")
    unique([item.candidate_ref for item in rows], label="candidate refs")
    max_reach = max(item.reach_accounts for item in rows) or 1
    scored: list[tuple[Decimal, RoadmapCandidate, bool]] = []
    for item in rows:
        reach = Decimal(item.reach_accounts) / Decimal(max_reach) * 100
        impact = Decimal(item.impact) / Decimal(5) * 100
        confidence = Decimal(item.confidence_percent)
        score = ((reach * weights.reach + impact * weights.impact + confidence * weights.confidence) / Decimal(100) / item.effort_weeks).quantize(MONEY_QUANTUM)
        scored.append((score, item, len(item.evidence_refs) >= weights.min_evidence_refs))
    scored.sort(key=lambda entry: (entry[0], entry[1].candidate_ref), reverse=True)
    ranked = [{"candidate_ref": item.candidate_ref, "title": item.title, "score": str(score), "rank": index, "admitted": admitted, "reason": "admitted with evidence" if admitted else f"held: {len(item.evidence_refs)} of {weights.min_evidence_refs} evidence refs"} for index, (score, item, admitted) in enumerate(scored, start=1)]
    held = [item.candidate_ref for score, item, admitted in scored if not admitted]
    return seal(RoadmapRanking, {"plan_digest": parsed_plan.plan_digest, "ranked": ranked, "held_for_evidence": held, "ranked_at": ranked_at}, "ranking_digest")


# --------------------------------------------------------------------------- #
# Release lifecycle
# --------------------------------------------------------------------------- #


class ReleaseReceipt(StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    change_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    work_packet_ref: OpaqueRef | None = None
    roadmap_candidate_ref: OpaqueRef | None = None
    summary: ShortText | None = None
    evidence_kind: EvidenceKind | None = None
    evidence_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    canary_ref: OpaqueRef | None = None
    canary_percent: Decimal | None = None
    observation_ref: OpaqueRef | None = None
    error_rate_percent: Decimal | None = None
    p95_latency_ms: int | None = Field(default=None, ge=0, le=600000)
    rollout_ref: OpaqueRef | None = None
    rollback_ref: OpaqueRef | None = None

    @field_validator("canary_percent", "error_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else percent_value(value, field_name=str(info.field_name))


class ReleaseLedger(StrictModel):
    change_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple)
    work_packet_ref: OpaqueRef | None = None
    roadmap_candidate_ref: OpaqueRef | None = None
    summary: ShortText | None = None
    evidence: dict[str, str] = Field(default_factory=dict)
    approval_ref: OpaqueRef | None = None
    canary_ref: OpaqueRef | None = None
    canary_percent: Decimal | None = None
    canary_started_at: str | None = None
    canary_observations: int = Field(default=0, ge=0)
    worst_error_rate_percent: Decimal | None = None
    worst_p95_latency_ms: int | None = Field(default=None, ge=0)
    verified_at: str | None = None
    rollout_ref: OpaqueRef | None = None
    rolled_out_at: str | None = None
    rollback_ref: OpaqueRef | None = None
    rollback_reason: ShortText | None = None
    outcome: Literal["rolled_out", "rolled_back", "abandoned"] | None = None

    @field_validator("canary_percent", "worst_error_rate_percent", mode="before")
    @classmethod
    def _percents(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))


class ReleaseEffectBoundary(StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    deployment_executed: Literal[False] = False
    rollback_executed: Literal[False] = False
    incident_opened: Literal[False] = False
    provider_read: Literal[False] = False


def _apply_release(plan: SaasOperatingLoopPlan, next_status: str, status: str, data: dict[str, Any], command: Any) -> tuple[str, dict[str, Any]]:
    policy, r, event, at = plan.blueprint.release_policy, command.receipt, command.event, parsed(command.occurred_at)
    if event == "propose":
        require(len(r.change_refs) > 0 and r.summary is not None, "CHANGES_MISSING", "a release proposes at least one change reference and a summary")
        data.update({"change_refs": list(r.change_refs), "work_packet_ref": r.work_packet_ref, "roadmap_candidate_ref": r.roadmap_candidate_ref, "summary": r.summary, "evidence": {}})
    elif event == "attach_evidence":
        require(r.evidence_kind is not None and r.evidence_ref is not None, "EVIDENCE_MISSING", "evidence names its kind and reference")
        require(r.evidence_kind in policy.required_evidence, "EVIDENCE_NOT_REQUIRED", f"{r.evidence_kind} is not part of the release policy {list(policy.required_evidence)}")
        evidence = {**data.get("evidence", {}), str(r.evidence_kind): r.evidence_ref}
        data["evidence"] = evidence
        if all(kind in evidence for kind in policy.required_evidence):
            next_status = "evidenced"
    elif event == "approve":
        require(r.approval_ref is not None, "APPROVAL_MISSING", "approval links the server-issued approval reference")
        data["approval_ref"] = r.approval_ref
    elif event == "start_canary":
        if policy.approval_required:
            require(data.get("approval_ref") is not None, "APPROVAL_REQUIRED", "this release policy needs approval before canary", "await_approval")
        require(r.canary_ref is not None and r.canary_percent is not None, "CANARY_MISSING", "canary links the deployment reference and percent")
        require(r.canary_percent <= policy.canary_percent, "CANARY_TOO_WIDE", f"canary is capped at {policy.canary_percent}%")
        data.update({"canary_ref": r.canary_ref, "canary_percent": str(r.canary_percent), "canary_started_at": command.occurred_at, "canary_observations": 0, "worst_error_rate_percent": None, "worst_p95_latency_ms": None})
    elif event == "observe_canary":
        require(r.observation_ref is not None and r.error_rate_percent is not None and r.p95_latency_ms is not None, "OBSERVATION_MISSING", "a canary observation carries error rate and p95 latency")
        worst_err = data.get("worst_error_rate_percent")
        worst_lat = data.get("worst_p95_latency_ms")
        data.update({"canary_observations": int(data.get("canary_observations", 0)) + 1, "worst_error_rate_percent": str(max(Decimal(str(worst_err)) if worst_err is not None else Decimal("0"), r.error_rate_percent)), "worst_p95_latency_ms": max(int(worst_lat) if worst_lat is not None else 0, r.p95_latency_ms)})
    elif event == "verify":
        require(int(data.get("canary_observations", 0)) >= policy.min_canary_observations, "INSUFFICIENT_CANARY_OBSERVATIONS", f"verification needs {policy.min_canary_observations} canary observation(s)")
        err = Decimal(str(data.get("worst_error_rate_percent") or "0"))
        lat = int(data.get("worst_p95_latency_ms") or 0)
        require(err <= policy.max_error_rate_percent, "ERROR_RATE_ABOVE_THRESHOLD", f"worst canary error rate {err}% exceeds {policy.max_error_rate_percent}%; roll back", "manual_reconciliation")
        require(lat <= policy.max_p95_latency_ms, "LATENCY_ABOVE_THRESHOLD", f"worst canary p95 {lat}ms exceeds {policy.max_p95_latency_ms}ms; roll back", "manual_reconciliation")
        data["verified_at"] = command.occurred_at
    elif event == "roll_out":
        require(r.rollout_ref is not None, "ROLLOUT_MISSING", "roll-out links the deployment reference")
        data.update({"rollout_ref": r.rollout_ref, "rolled_out_at": command.occurred_at, "outcome": "rolled_out"})
    elif event == "roll_back":
        require(r.rollback_ref is not None, "ROLLBACK_MISSING", "roll-back links the rollback deployment reference")
        anchor = data.get("rolled_out_at") or data.get("canary_started_at")
        if anchor is not None:
            hours = (at - parsed(str(anchor))).total_seconds() / 3600
            require(hours <= policy.rollback_window_hours, "ROLLBACK_WINDOW_CLOSED", f"the {policy.rollback_window_hours}h rollback window closed; open an incident and ship a fix forward", "manual_reconciliation")
        data.update({"rollback_ref": r.rollback_ref, "rollback_reason": str(command.reason)[:300], "outcome": "rolled_back"})
    elif event == "abandon":
        data["outcome"] = "abandoned"
    return next_status, data


RELEASE_LIFECYCLE = LifecycleSpec(entity="release", schema_prefix="saas_release", statuses=RELEASE_STATUSES, terminal=TERMINAL_RELEASE_STATUSES, events=RELEASE_EVENTS, table=_RELEASE_TABLE, opening_event="propose", reason_events=("roll_back", "abandon"), apply=_apply_release, ledger_model=ReleaseLedger, receipt_model=ReleaseReceipt, effect_boundary_model=ReleaseEffectBoundary, plan_model=SaasOperatingLoopPlan, max_transitions=MAX_RELEASE_TRANSITIONS)
ReleaseCommand = RELEASE_LIFECYCLE.Command
ReleaseState = RELEASE_LIFECYCLE.State
ReleaseTransitionResult = RELEASE_LIFECYCLE.TransitionResult
seal_release_command = RELEASE_LIFECYCLE.seal_command
release_command_digest = RELEASE_LIFECYCLE.command_digest


def open_release(plan: SaasOperatingLoopPlan | Mapping[str, Any], scope: Mapping[str, Any], *, change_refs: Sequence[str], summary: str, opened_at: str, actor_ref: str, work_packet_ref: str | None = None, roadmap_candidate_ref: str | None = None) -> Any:
    receipt = {"change_refs": list(change_refs), "summary": summary, "work_packet_ref": work_packet_ref, "roadmap_candidate_ref": roadmap_candidate_ref}
    return RELEASE_LIFECYCLE.open(plan, scope, opened_at=opened_at, actor_ref=actor_ref, receipt=receipt)


def advance_release(plan: SaasOperatingLoopPlan | Mapping[str, Any], state: Any, command: Any) -> Any:
    return RELEASE_LIFECYCLE.advance(plan, state, command)


# --------------------------------------------------------------------------- #
# Operating assessment
# --------------------------------------------------------------------------- #


class SaasOperatingAssessment(StrictModel):
    schema_id: Literal["lightbulb.saas_operating_assessment.v1"] = Field(default=ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["saas.launched_product_to_compounding_revenue@0.1.0"] = SAAS_OPERATING_GOLDEN_LOOP
    profile: BlueprintProfile
    currency: CurrencyCode
    accounts: int = Field(ge=0)
    mrr: Decimal
    activation_rate_percent: Decimal | None = None
    retention_rate_percent: Decimal | None = None
    expansion_candidates: int = Field(ge=0)
    expansion_rate_percent: Decimal | None = None
    churn_risks: int = Field(ge=0)
    mrr_at_risk: Decimal
    releases: int = Field(ge=0)
    releases_by_status: dict[str, int] = Field(default_factory=dict)
    rollbacks: int = Field(ge=0)
    support_cases: int = Field(ge=0)
    sla_attainment_percent: Decimal | None = None
    learnings: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("mrr", "activation_rate_percent", "retention_rate_percent", "expansion_rate_percent", "mrr_at_risk", "sla_attainment_percent", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else decimal_value(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _exact(self, info: ValidationInfo) -> "SaasOperatingAssessment":
        if skip_digests(info):
            return self
        if self.assessment_digest != sealed_digest(SaasOperatingAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_saas_operating(plan: SaasOperatingLoopPlan | Mapping[str, Any], snapshot: UsageSnapshot | Mapping[str, Any], releases: Sequence[Any], triages: Sequence[SupportTriage | Mapping[str, Any]], *, assessed_at: str) -> SaasOperatingAssessment:
    parsed_plan = SaasOperatingLoopPlan.model_validate(detached(plan))
    bp = parsed_plan.blueprint
    snap = UsageSnapshot.model_validate(detached(snapshot))
    if snap.plan_digest != parsed_plan.plan_digest:
        raise ValueError("SNAPSHOT_NOT_BOUND: the snapshot belongs to a different loop plan")
    bound_releases = [RELEASE_LIFECYCLE.bind(parsed_plan, item)[1] for item in releases]
    parsed_triages = [SupportTriage.model_validate(detached(item)) for item in triages]
    if any(item.plan_digest != parsed_plan.plan_digest for item in parsed_triages):
        raise ValueError("TRIAGE_NOT_BOUND: every triage must belong to this loop plan")
    expansion_rate = ratio_percent(len(snap.expansion_candidates), snap.accounts)
    responded = [item for item in parsed_triages if item.first_response_met is not None]
    sla = ratio_percent(sum(1 for item in responded if item.first_response_met), len(responded))
    rollbacks = sum(1 for item in bound_releases if item.status == "rolled_back")
    learnings: list[str] = []
    recommendations: list[str] = []
    if snap.activation_rate_percent is not None and snap.activation_rate_percent < bp.target_activation_rate_percent:
        learnings.append(f"activation {snap.activation_rate_percent}% is below the {bp.target_activation_rate_percent}% target")
        recommendations.append("shorten time to the first required activation event; rank onboarding work higher")
    if snap.retention_rate_percent is not None and snap.retention_rate_percent < bp.target_retention_rate_percent:
        learnings.append(f"retention {snap.retention_rate_percent}% is below the {bp.target_retention_rate_percent}% target")
        recommendations.append("run retention plays on churn risks before acquisition spend")
    if expansion_rate is not None and expansion_rate < bp.target_expansion_rate_percent:
        learnings.append(f"expansion candidates {expansion_rate}% of accounts, below the {bp.target_expansion_rate_percent}% target")
    if sla is not None and sla < bp.target_sla_attainment_percent:
        learnings.append(f"first-response SLA attainment {sla}% is below the {bp.target_sla_attainment_percent}% target")
        recommendations.append("staff the escalation path named by the missed severities")
    if rollbacks:
        learnings.append(f"{rollbacks} release(s) rolled back; tighten canary thresholds or evidence")
    if snap.churn_risks:
        learnings.append(f"{len(snap.churn_risks)} account(s) at churn risk with {sum((item.mrr_at_risk for item in snap.churn_risks), Decimal('0'))} MRR")
    if not learnings:
        learnings.append("product is inside blueprint targets")
    payload = {"profile": bp.profile, "currency": bp.currency, "accounts": snap.accounts, "mrr": str(snap.mrr), "activation_rate_percent": None if snap.activation_rate_percent is None else str(snap.activation_rate_percent), "retention_rate_percent": None if snap.retention_rate_percent is None else str(snap.retention_rate_percent), "expansion_candidates": len(snap.expansion_candidates), "expansion_rate_percent": None if expansion_rate is None else str(expansion_rate), "churn_risks": len(snap.churn_risks), "mrr_at_risk": str(sum((item.mrr_at_risk for item in snap.churn_risks), Decimal("0"))), "releases": len(bound_releases), "releases_by_status": {status: sum(1 for item in bound_releases if item.status == status) for status in sorted({item.status for item in bound_releases})}, "rollbacks": rollbacks, "support_cases": len(parsed_triages), "sla_attainment_percent": None if sla is None else str(sla), "learnings": learnings, "recommendations": recommendations, "assessed_at": assessed_at}
    return seal(SaasOperatingAssessment, payload, "assessment_digest")


SAAS_OPERATING_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_engine.v1",
    "engine": SAAS_OPERATING_KIND,
    "title": "SaaS operating engine",
    "golden_loop": SAAS_OPERATING_GOLDEN_LOOP,
    "profiles": sorted(SAAS_OPERATING_PROFILES),
    "release_statuses": list(RELEASE_STATUSES),
    "release_events": list(RELEASE_EVENTS),
    "evidence_kinds": list(EVIDENCE_KINDS),
    "required_connectors": sorted({tool.split(".")[0] for tool in _KNOWN_CONNECTOR_TOOLS}),
    "picks_up_from": "saas.market_research_to_launched_product@0.1.0",
    "composes_with": ["subscription.trial_to_renewal_business@0.1.0", "software.approved_change_to_verified_production@0.1.0", "service.case_customer_verified_resolution", "project.work_packet_independent_acceptance@0.1.0"],
    "economic_spine": {"deliver_value": "ship_release / verify_release", "accept_value": "measure_cohorts (activation, retention)", "monetize": "drive_expansion", "learn": "learn"},
    "explicit_inputs_never_invented": ["usage observations", "release evidence and approvals", "canary observations", "support case facts", "customer consent for expansion outreach"],
}

__all__ = [
    "EVIDENCE_KINDS",
    "RELEASE_EVENTS",
    "RELEASE_LIFECYCLE",
    "RELEASE_STATUSES",
    "SAAS_OPERATING_GOLDEN_LOOP",
    "SAAS_OPERATING_KIND",
    "SAAS_OPERATING_MANIFEST",
    "SAAS_OPERATING_PROFILES",
    "SEVERITIES",
    "STAGE_ORDER",
    "TERMINAL_RELEASE_STATUSES",
    "AccountUsage",
    "ActivationDefinition",
    "ChurnRisk",
    "CohortRow",
    "ExpansionCandidate",
    "ExpansionSignals",
    "PlanTier",
    "RankedItem",
    "ReleaseCommand",
    "ReleaseEffectBoundary",
    "ReleaseLedger",
    "ReleasePolicy",
    "ReleaseReceipt",
    "ReleaseState",
    "ReleaseTransitionResult",
    "RoadmapCandidate",
    "RoadmapRanking",
    "RoadmapWeights",
    "SaasOperatingAssessment",
    "SaasOperatingBlueprint",
    "SaasOperatingLoopPlan",
    "StageBinding",
    "SupportCaseFacts",
    "SupportSla",
    "SupportTriage",
    "UsageSnapshot",
    "advance_release",
    "assess_saas_operating",
    "compile_saas_operating_blueprint",
    "observe_usage",
    "open_release",
    "rank_roadmap",
    "release_command_digest",
    "seal_release_command",
    "seal_saas_operating_blueprint",
    "triage_support_case",
]
