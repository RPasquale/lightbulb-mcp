"""SaaS Product Golden Operating Loop and Company Blueprint profiles.

A SaaS product is everything a company needs to research, validate, fund,
build, deploy, launch, and then operate as a subscription business::

    Research market -> Define product -> Validate demand -> Plan business
        -> Produce materials (deck, one-pager, financial summary, site copy,
           launch brief, investor FAQ, PRD)
        -> Secure funding (or bootstrap) -> Build repository -> Deploy
        -> Launch -> Learn -> hand off to subscription.trial_to_renewal_business

``saas_product_research`` supplies the sealed research, thesis, pricing,
validation, model, projection, ask, and artifact grounding.  This module
supplies the blueprint profiles, the repository and deployment plans, the
launch plan, a replay-fenced product state that links each stage's sealed
objects by digest, and the assessment.  The build stage binds to the
software-production loop (``project.request_software_production``) and the
launch stage hands off to the subscription-business loop **by reference**;
neither is imported here.

Nothing here creates a repository, deploys, publishes, or contacts an
investor; those are Spring-authorized effects executed by connectors.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.saas_product_research import (
    ArtifactKind,
    BoundedText,
    CurrencyCode,
    OpaqueRef,
    ProductThesis,
    RoundType,
    Sha256Digest,
    ShortText,
    ValidationThresholds,
    _decimal,
    _detached,
    _parsed_timestamp_or_none,
    _sealed_digest,
    _skip,
    _stable_digest,
    _StrictModel,
    _timestamp,
    _unique,
)


SAAS_PRODUCT_GOLDEN_LOOP = "saas.market_research_to_launched_product@0.1.0"
SAAS_PRODUCT_ARCHETYPE = "saas_product"
SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF = "software.approved_change_to_verified_production@0.1.0"
SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF = "subscription.trial_to_renewal_business@0.1.0"
BLUEPRINT_SCHEMA = "lightbulb.saas_product_blueprint.v1"
PLAN_SCHEMA = "lightbulb.saas_product_loop_plan.v1"
REPOSITORY_SCHEMA = "lightbulb.saas_repository_blueprint.v1"
DEPLOYMENT_SCHEMA = "lightbulb.saas_deployment_plan.v1"
READINESS_SCHEMA = "lightbulb.saas_launch_readiness.v1"
LAUNCH_SCHEMA = "lightbulb.saas_launch_plan.v1"
PRODUCT_COMMAND_SCHEMA = "lightbulb.saas_product_command.v1"
PRODUCT_STATE_SCHEMA = "lightbulb.saas_product_state.v1"
PRODUCT_RESULT_SCHEMA = "lightbulb.saas_product_transition_result.v1"
PRODUCT_ASSESSMENT_SCHEMA = "lightbulb.saas_product_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_PRODUCT_TRANSITIONS = 60

BlueprintProfile = Literal["bootstrapped_saas", "seed_funded_saas", "enterprise_saas", "custom"]
Stack = Literal["python_fastapi_react", "node_next", "java_spring_react", "ruby_rails", "django_htmx"]
EnvironmentName = Literal["preview", "staging", "production"]
LoopStage = Literal["research_market", "define_product", "validate_demand", "plan_business", "produce_materials", "secure_funding", "build_repository", "deploy", "launch", "learn"]
STAGE_ORDER: tuple[str, ...] = ("research_market", "define_product", "validate_demand", "plan_business", "produce_materials", "secure_funding", "build_repository", "deploy", "launch", "learn")
ProductStatus = Literal["opened", "researched", "defined", "validated", "planned", "materials_produced", "funded", "built", "deployed", "launched", "completed", "abandoned"]
STATUS_AFTER_STAGE: dict[str, str] = {"research_market": "researched", "define_product": "defined", "validate_demand": "validated", "plan_business": "planned", "produce_materials": "materials_produced", "secure_funding": "funded", "build_repository": "built", "deploy": "deployed", "launch": "launched", "learn": "completed"}
STATUS_BEFORE_STAGE: dict[str, str] = {"research_market": "opened", **{STAGE_ORDER[index]: STATUS_AFTER_STAGE[STAGE_ORDER[index - 1]] for index in range(1, len(STAGE_ORDER))}}
TERMINAL_PRODUCT_STATUSES: frozenset[str] = frozenset({"completed", "abandoned"})
ProductEvent = Literal["complete_stage", "pivot", "abandon"]
FundingStatus = Literal["not_required", "bootstrapped", "in_progress", "funded", "passed"]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation", "await_approval"]
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "blueprint.compile_saas_product", "saas.compile_market_research", "saas.evaluate_demand_validation", "saas.project_business_model", "saas.plan_product_artifacts", "saas.verify_artifact_grounding", "saas.advance_product", "saas.assess_product",
        "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar", "crm.qualify_lead", "communication.plan_crm_conversation_turn", "communication.write_email", "calendar.schedule_meeting",
        "documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "documents.generate_business_artifact",
        "growth.build_unit_economics", "growth.review_profit", "growth.plan_price_move", "cash.build_cash_flow_forecast", "cash.assess_runway", "accounting.search_grants", "accounting.match_grants", "business.gate_objective_funding",
        "project.create_work_packet", "project.request_software_production", "project.assess_software_production_result", "project.compile_customer_acceptance_candidate",
        "product.evaluate_release_governance_controls", "operations.evaluate_production_execution_readiness", "compliance.evaluate_regulated_controls", "legal.draft_contract", "legal.review_contract",
        "blueprint.compile_subscription_business", "subscription.advance_account", "subscription.assess_portfolio", "learning.plan_optimization_sweep",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset({"github.create_repository", "github.create_branch_ref", "github.create_pull_request", "github.dispatch_workflow", "github.list_check_runs", "github.create_environment", "github.create_ruleset", "github.create_release", "github.list_deployments", "linkedin.publish_post", "facebook.publish_post", "hubspot.create_campaign", "stripe.create_invoice", "google_analytics.fetch_metrics"})


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class SaasProductBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    round_type: RoundType = "bootstrapped"
    funding_required: bool = False
    min_close_fraction: Decimal = Field(default=Decimal("0.8"), validate_default=True)
    validation_thresholds: ValidationThresholds = Field(default_factory=ValidationThresholds)
    min_research_confidence_percent: Decimal = Field(default=Decimal("60"), validate_default=True)
    max_pivots: int = Field(default=2, ge=0, le=10)
    required_artifacts: tuple[ArtifactKind, ...] = Field(default=("pitch_deck", "one_pager", "financial_summary", "marketing_site_copy", "launch_campaign_brief", "product_requirements_document"), min_length=1, max_length=7)
    stack: Stack = "python_fastapi_react"
    environments: tuple[EnvironmentName, ...] = Field(default=("staging", "production"), min_length=1, max_length=3)
    ci_required: bool = True
    security_checklist: tuple[ShortText, ...] = Field(default=("dependency scanning", "secrets in managed store", "authentication and RBAC", "backups with restore test", "TLS everywhere"), max_length=30)
    observability_required: bool = True
    launch_channels: tuple[Literal["email", "linkedin", "facebook", "content", "partnerships", "product_hunt", "paid_search", "outbound_sales"], ...] = Field(default=("email", "linkedin", "content"), min_length=1, max_length=8)
    target_first_paying_customers: int = Field(default=10, ge=1, le=1_000_000)
    subscription_profile: Literal["saas_self_serve", "saas_sales_led"] = "saas_self_serve"
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("min_close_fraction", mode="before")
    @classmethod
    def _fraction(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="min_close_fraction", quantum=Decimal("0.0001"))
        if parsed <= 0 or parsed > 1:
            raise ValueError("min_close_fraction must be between 0 and 1")
        return parsed

    @field_validator("min_research_confidence_percent", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="min_research_confidence_percent")
        if parsed > 100:
            raise ValueError("min_research_confidence_percent must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "SaasProductBlueprint":
        _unique(list(self.required_artifacts), label="required artifacts")
        _unique(list(self.environments), label="environments")
        _unique(list(self.launch_channels), label="launch channels")
        if "production" not in self.environments:
            raise ValueError("a launchable product needs a production environment")
        if self.funding_required != (self.round_type not in {"bootstrapped"}):
            raise ValueError("funding_required must agree with the round type")
        if self.subscription_profile == "saas_sales_led" and "outbound_sales" not in self.launch_channels:
            raise ValueError("a sales-led subscription profile launches with outbound sales")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(SaasProductBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self


def seal_saas_product_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(SaasProductBlueprint, raw, "blueprint_digest")
    return SaasProductBlueprint.model_validate(raw).to_dict()


SAAS_PRODUCT_PROFILES: dict[str, dict[str, Any]] = {
    "bootstrapped_saas": {"profile": "bootstrapped_saas", "name": "Bootstrapped self-serve SaaS", "round_type": "bootstrapped", "funding_required": False, "validation_thresholds": {"min_interviews": 8, "min_problem_confirmation_rate": "0.6", "min_would_pay_rate": "0.3", "min_landing_conversion_rate": "0.02", "min_waitlist_signups": 25}, "min_research_confidence_percent": "50", "max_pivots": 3, "required_artifacts": ["one_pager", "marketing_site_copy", "launch_campaign_brief", "product_requirements_document"], "stack": "python_fastapi_react", "environments": ["staging", "production"], "ci_required": True, "observability_required": True, "launch_channels": ["email", "content", "product_hunt"], "target_first_paying_customers": 10, "subscription_profile": "saas_self_serve", "notes": "No raise; materials serve customers, not investors; ship small and iterate."},
    "seed_funded_saas": {"profile": "seed_funded_saas", "name": "Seed-funded SaaS", "round_type": "seed", "funding_required": True, "min_close_fraction": "0.8", "validation_thresholds": {"min_interviews": 15, "min_problem_confirmation_rate": "0.65", "min_would_pay_rate": "0.35", "min_landing_conversion_rate": "0.03", "min_waitlist_signups": 100}, "min_research_confidence_percent": "65", "max_pivots": 2, "required_artifacts": ["pitch_deck", "one_pager", "financial_summary", "marketing_site_copy", "launch_campaign_brief", "investor_faq", "product_requirements_document"], "stack": "node_next", "environments": ["preview", "staging", "production"], "ci_required": True, "observability_required": True, "launch_channels": ["email", "linkedin", "content", "paid_search"], "target_first_paying_customers": 50, "subscription_profile": "saas_self_serve", "notes": "Investor-grade materials grounded in the sealed model; three environments."},
    "enterprise_saas": {"profile": "enterprise_saas", "name": "Enterprise (sales-led) SaaS", "round_type": "seed", "funding_required": True, "min_close_fraction": "0.75", "validation_thresholds": {"min_interviews": 12, "min_problem_confirmation_rate": "0.7", "min_would_pay_rate": "0.4", "min_landing_conversion_rate": "0", "min_waitlist_signups": 0, "min_committed_value": "50000"}, "min_research_confidence_percent": "70", "max_pivots": 1, "required_artifacts": ["pitch_deck", "one_pager", "financial_summary", "investor_faq", "product_requirements_document"], "stack": "java_spring_react", "environments": ["staging", "production"], "ci_required": True, "security_checklist": ["dependency scanning", "secrets in managed store", "SSO and RBAC", "audit logging", "backups with restore test", "TLS everywhere", "SOC 2 readiness review", "data processing agreement"], "observability_required": True, "launch_channels": ["outbound_sales", "linkedin", "partnerships"], "target_first_paying_customers": 5, "subscription_profile": "saas_sales_led", "notes": "Validation by letters of intent and pilots; security checklist covers SOC 2 readiness."},
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    golden_loops: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=4)
    gate: Literal["none", "threshold", "spring_approval", "human_approval"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class SaasProductLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["saas.market_research_to_launched_product@0.1.0"] = SAAS_PRODUCT_GOLDEN_LOOP
    archetype: Literal["saas_product"] = SAAS_PRODUCT_ARCHETYPE
    blueprint: SaasProductBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=10, max_length=10)
    composed_golden_loops: tuple[ShortText, ...] = Field(min_length=1, max_length=6)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "SaasProductLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(SaasProductLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _stage_bindings(blueprint: SaasProductBlueprint) -> list[dict[str, Any]]:
    funding_refs: tuple[str, ...] = ("cash.build_cash_flow_forecast", "cash.assess_runway", "business.gate_objective_funding", "crm.qualify_lead", "communication.plan_crm_conversation_turn", "calendar.schedule_meeting", "legal.review_contract") if blueprint.funding_required else ("cash.build_cash_flow_forecast", "cash.assess_runway", "accounting.search_grants", "accounting.match_grants")
    launch_tools = tuple(tool for tool in ("linkedin.publish_post" if "linkedin" in blueprint.launch_channels else None, "facebook.publish_post" if "facebook" in blueprint.launch_channels else None, "hubspot.create_campaign" if "email" in blueprint.launch_channels else None, "google_analytics.fetch_metrics") if tool)
    return [
        {"stage": "research_market", "title": "Research the market", "primitive_refs": ("saas.compile_market_research", "demand_gen.plan_audience_growth"), "gate": "threshold"},
        {"stage": "define_product", "title": "Define the product thesis, requirements, and pricing hypothesis", "primitive_refs": ("saas.compile_market_research", "growth.plan_price_move", "blueprint.compile_subscription_business"), "gate": "none"},
        {"stage": "validate_demand", "title": "Validate demand", "primitive_refs": ("saas.evaluate_demand_validation", "crm.qualify_lead", "communication.plan_crm_conversation_turn", "demand_gen.plan_content_calendar"), "gate": "threshold"},
        {"stage": "plan_business", "title": "Plan the business model, projection, and ask", "primitive_refs": ("saas.project_business_model", "growth.build_unit_economics", "growth.review_profit", "cash.build_cash_flow_forecast"), "gate": "none"},
        {"stage": "produce_materials", "title": "Produce grounded materials", "primitive_refs": ("saas.plan_product_artifacts", "documents.prepare_business_artifact_generation", "documents.validate_generated_business_artifact", "saas.verify_artifact_grounding", "documents.generate_business_artifact"), "gate": "human_approval"},
        {"stage": "secure_funding", "title": "Secure funding" if blueprint.funding_required else "Confirm bootstrapped runway", "primitive_refs": funding_refs, "gate": "human_approval" if blueprint.funding_required else "none"},
        {"stage": "build_repository", "title": f"Build the repository ({blueprint.stack}) through the software-production loop", "primitive_refs": ("project.create_work_packet", "project.request_software_production", "project.assess_software_production_result", "project.compile_customer_acceptance_candidate"), "connector_tools": ("github.create_repository", "github.create_ruleset", "github.create_branch_ref", "github.create_pull_request", "github.list_check_runs"), "golden_loops": (SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF,), "gate": "spring_approval"},
        {"stage": "deploy", "title": "Deploy to " + ", ".join(blueprint.environments), "primitive_refs": ("product.evaluate_release_governance_controls", "operations.evaluate_production_execution_readiness", "compliance.evaluate_regulated_controls"), "connector_tools": ("github.create_environment", "github.dispatch_workflow", "github.list_deployments", "github.create_release"), "golden_loops": (SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF,), "gate": "spring_approval"},
        {"stage": "launch", "title": "Launch through approved channels", "primitive_refs": ("demand_gen.plan_content_calendar", "communication.write_email", "blueprint.compile_subscription_business", "subscription.advance_account"), "connector_tools": launch_tools, "golden_loops": (SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF,), "gate": "human_approval"},
        {"stage": "learn", "title": "Learn: traction against targets, hand off to the subscription loop", "primitive_refs": ("subscription.assess_portfolio", "learning.plan_optimization_sweep"), "golden_loops": (SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF,), "gate": "none"},
    ]


def compile_saas_product_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> SaasProductLoopPlan:
    if isinstance(profile, str):
        if profile not in SAAS_PRODUCT_PROFILES:
            raise ValueError(f"unknown SaaS product profile {profile!r}; choose one of {sorted(SAAS_PRODUCT_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(SAAS_PRODUCT_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        if isinstance(value, Mapping) and isinstance(raw.get(key), Mapping):
            raw[key] = {**raw[key], **value}
        else:
            raw[key] = value
    blueprint = SaasProductBlueprint.model_validate(seal_saas_product_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint), "composed_golden_loops": [SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF, SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF, "documents.governed_business_artifact_production@0.1.0"]}
    payload["plan_digest"] = _sealed_digest(SaasProductLoopPlan, payload, "plan_digest")
    return SaasProductLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Repository, deployment, launch plans
# --------------------------------------------------------------------------- #


class WorkPackageSpec(_StrictModel):
    """One requirement shaped for the software-production loop (mapped to ``project.request_software_production`` at integration)."""

    requirement_ref: OpaqueRef
    title: ShortText
    description: BoundedText
    acceptance_criteria: tuple[ShortText, ...] = Field(min_length=1, max_length=20)
    change_type: Literal["feature", "infrastructure", "security_fix", "configuration"] = "feature"
    change_risk: Literal["low", "medium", "high"] = "medium"
    environments: tuple[EnvironmentName, ...] = Field(min_length=1, max_length=3)
    priority: Literal["must", "should", "could"] = "must"


class RepositoryBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.saas_repository_blueprint.v1"] = Field(default=REPOSITORY_SCHEMA, alias="schema")
    repository_ref: OpaqueRef
    thesis_digest: Sha256Digest
    stack: Stack
    default_branch: ShortText = "main"
    structure: tuple[ShortText, ...] = Field(min_length=1, max_length=40)
    ci_workflows: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)
    branch_protection: bool = True
    environments: tuple[EnvironmentName, ...] = Field(min_length=1, max_length=3)
    sensitive_config_policy: Literal["managed_store_never_in_repo"] = "managed_store_never_in_repo"
    license: ShortText = "proprietary"
    work_packages: tuple[WorkPackageSpec, ...] = Field(min_length=1, max_length=100)
    repository_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _repository_is_exact(self, info: ValidationInfo) -> "RepositoryBlueprint":
        _unique([item.requirement_ref for item in self.work_packages], label="work package refs")
        if _skip(info):
            return self
        if self.repository_digest != _sealed_digest(RepositoryBlueprint, self, "repository_digest"):
            raise ValueError("repository_digest must commit the exact blueprint")
        return self


_STACK_STRUCTURE: dict[str, tuple[str, ...]] = {
    "python_fastapi_react": ("backend/app", "backend/tests", "frontend/src", "frontend/tests", "infra", "docs", ".github/workflows"),
    "node_next": ("apps/web", "packages/api", "packages/db", "tests", "infra", "docs", ".github/workflows"),
    "java_spring_react": ("server/src/main", "server/src/test", "web/src", "web/tests", "infra", "docs", ".github/workflows"),
    "ruby_rails": ("app", "config", "db", "spec", "infra", "docs", ".github/workflows"),
    "django_htmx": ("project", "apps", "templates", "tests", "infra", "docs", ".github/workflows"),
}


def derive_repository_blueprint(plan: SaasProductLoopPlan | Mapping[str, Any], thesis: ProductThesis | Mapping[str, Any], *, repository_ref: str) -> RepositoryBlueprint:
    """Derive the repository shape and one work package per must/should requirement from the thesis."""

    parsed_plan = SaasProductLoopPlan.model_validate(_detached(plan))
    parsed_thesis = ProductThesis.model_validate(_detached(thesis))
    blueprint = parsed_plan.blueprint
    packages = [
        {"requirement_ref": item.requirement_ref, "title": item.title, "description": item.user_story, "acceptance_criteria": list(item.acceptance_criteria), "change_type": "feature", "change_risk": "medium", "environments": list(blueprint.environments), "priority": item.priority}
        for item in parsed_thesis.requirements
        if item.priority in {"must", "should"}
    ]
    workflows = ["ci.yml", "deploy.yml"] if blueprint.ci_required else []
    if "dependency scanning" in blueprint.security_checklist:
        workflows.append("security-scan.yml")
    payload = {"repository_ref": repository_ref, "thesis_digest": parsed_thesis.thesis_digest, "stack": blueprint.stack, "structure": list(_STACK_STRUCTURE[blueprint.stack]), "ci_workflows": workflows, "branch_protection": True, "environments": list(blueprint.environments), "work_packages": packages}
    payload["repository_digest"] = _sealed_digest(RepositoryBlueprint, payload, "repository_digest")
    return RepositoryBlueprint.model_validate(payload)


class EnvironmentPlan(_StrictModel):
    name: EnvironmentName
    release_policy: Literal["automated", "approval_required"]
    url_pattern: ShortText
    observability: tuple[Literal["logs", "metrics", "traces", "alerts", "uptime_checks"], ...] = Field(default_factory=tuple, max_length=5)


class DeploymentPlan(_StrictModel):
    schema_id: Literal["lightbulb.saas_deployment_plan.v1"] = Field(default=DEPLOYMENT_SCHEMA, alias="schema")
    deployment_ref: OpaqueRef
    repository_digest: Sha256Digest
    domain: ShortText
    environments: tuple[EnvironmentPlan, ...] = Field(min_length=1, max_length=3)
    security_checklist: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=30)
    backup_policy: Literal["daily_with_restore_test", "daily", "none"] = "daily_with_restore_test"
    rollback: Literal["automatic_on_health_breach", "manual"] = "automatic_on_health_breach"
    deployment_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _deployment_is_exact(self, info: ValidationInfo) -> "DeploymentPlan":
        _unique([item.name for item in self.environments], label="environments")
        production = next((item for item in self.environments if item.name == "production"), None)
        if production is None:
            raise ValueError("a deployment plan needs a production environment")
        if production.release_policy != "approval_required":
            raise ValueError("production releases require approval")
        if _skip(info):
            return self
        if self.deployment_digest != _sealed_digest(DeploymentPlan, self, "deployment_digest"):
            raise ValueError("deployment_digest must commit the exact plan")
        return self


def derive_deployment_plan(plan: SaasProductLoopPlan | Mapping[str, Any], repository: RepositoryBlueprint | Mapping[str, Any], *, deployment_ref: str, domain: str) -> DeploymentPlan:
    parsed_plan = SaasProductLoopPlan.model_validate(_detached(plan))
    parsed_repo = RepositoryBlueprint.model_validate(_detached(repository))
    blueprint = parsed_plan.blueprint
    observability = ("logs", "metrics", "alerts", "uptime_checks") if blueprint.observability_required else ()
    environments = [{"name": name, "release_policy": "approval_required" if name == "production" else "automated", "url_pattern": (domain if name == "production" else f"{name}.{domain}"), "observability": list(observability) if name == "production" else (["logs"] if observability else [])} for name in parsed_repo.environments]
    payload = {"deployment_ref": deployment_ref, "repository_digest": parsed_repo.repository_digest, "domain": domain, "environments": environments, "security_checklist": list(blueprint.security_checklist), "backup_policy": "daily_with_restore_test" if "backups with restore test" in blueprint.security_checklist else "daily", "rollback": "automatic_on_health_breach"}
    payload["deployment_digest"] = _sealed_digest(DeploymentPlan, payload, "deployment_digest")
    return DeploymentPlan.model_validate(payload)


class DeploymentReceipt(_StrictModel):
    environment: EnvironmentName
    deployment_ref: OpaqueRef
    software_production_handle_digest: Sha256Digest | None = None
    healthy: bool
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")


class LaunchReadiness(_StrictModel):
    schema_id: Literal["lightbulb.saas_launch_readiness.v1"] = Field(default=READINESS_SCHEMA, alias="schema")
    deployment_digest: Sha256Digest
    status: Literal["ready", "not_ready"]
    environments_deployed: tuple[EnvironmentName, ...] = Field(default_factory=tuple, max_length=3)
    checklist_evidenced: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=30)
    findings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)
    readiness_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _readiness_is_exact(self, info: ValidationInfo) -> "LaunchReadiness":
        if _skip(info):
            return self
        if self.readiness_digest != _sealed_digest(LaunchReadiness, self, "readiness_digest"):
            raise ValueError("readiness_digest must commit the exact readiness")
        return self


def verify_launch_readiness(deployment: DeploymentPlan | Mapping[str, Any], receipts: Sequence[DeploymentReceipt | Mapping[str, Any]], checklist_evidence: Mapping[str, str]) -> LaunchReadiness:
    """Every environment deployed and healthy, every checklist item evidenced by reference, domain matches."""

    parsed = DeploymentPlan.model_validate(_detached(deployment))
    parsed_receipts = [DeploymentReceipt.model_validate(_detached(item)) for item in receipts]
    findings: list[str] = []
    deployed: list[str] = []
    for environment in parsed.environments:
        receipt = next((item for item in parsed_receipts if item.environment == environment.name and item.deployment_ref == parsed.deployment_ref), None)
        if receipt is None:
            findings.append(f"{environment.name} has no deployment receipt for {parsed.deployment_ref}")
        elif not receipt.healthy:
            findings.append(f"{environment.name} deployment is not healthy")
        elif environment.name == "production" and receipt.software_production_handle_digest is None:
            findings.append("production deployment must link the software-production run handle")
        else:
            deployed.append(environment.name)
    evidenced = [item for item in parsed.security_checklist if str(checklist_evidence.get(item, "")).strip()]
    for item in parsed.security_checklist:
        if item not in evidenced:
            findings.append(f"security checklist item not evidenced: {item}")
    if parsed.backup_policy == "daily_with_restore_test" and not str(checklist_evidence.get("backups with restore test", "")).strip():
        findings.append("backup restore test evidence missing")
    status = "ready" if not findings else "not_ready"
    payload = {"deployment_digest": parsed.deployment_digest, "status": status, "environments_deployed": deployed, "checklist_evidenced": evidenced, "findings": findings}
    payload["readiness_digest"] = _sealed_digest(LaunchReadiness, payload, "readiness_digest")
    return LaunchReadiness.model_validate(payload)


class LaunchPlan(_StrictModel):
    schema_id: Literal["lightbulb.saas_launch_plan.v1"] = Field(default=LAUNCH_SCHEMA, alias="schema")
    launch_ref: OpaqueRef
    readiness_digest: Sha256Digest
    channels: tuple[ShortText, ...] = Field(min_length=1, max_length=8)
    pricing_page_ref: OpaqueRef
    signup_funnel: tuple[ShortText, ...] = Field(min_length=2, max_length=10)
    launch_at: str
    success_metric_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=10)
    subscription_profile: Literal["saas_self_serve", "saas_sales_led"]
    launch_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("launch_at")
    @classmethod
    def _launch(cls, value: str) -> str:
        return _timestamp(value, field_name="launch_at")

    @model_validator(mode="after")
    def _launch_is_exact(self, info: ValidationInfo) -> "LaunchPlan":
        if _skip(info):
            return self
        if self.launch_digest != _sealed_digest(LaunchPlan, self, "launch_digest"):
            raise ValueError("launch_digest must commit the exact plan")
        return self


def derive_launch_plan(plan: SaasProductLoopPlan | Mapping[str, Any], readiness: LaunchReadiness | Mapping[str, Any], *, launch_ref: str, pricing_page_ref: str, launch_at: str, success_metric_refs: Sequence[str] = ()) -> LaunchPlan:
    parsed_plan = SaasProductLoopPlan.model_validate(_detached(plan))
    parsed_readiness = LaunchReadiness.model_validate(_detached(readiness))
    if parsed_readiness.status != "ready":
        raise ValueError("a launch plan needs a ready launch readiness verdict")
    blueprint = parsed_plan.blueprint
    funnel = ["visit", "signup", "activate", "convert"] if blueprint.subscription_profile == "saas_self_serve" else ["outreach", "discovery_call", "pilot", "contract"]
    payload = {"launch_ref": launch_ref, "readiness_digest": parsed_readiness.readiness_digest, "channels": list(blueprint.launch_channels), "pricing_page_ref": pricing_page_ref, "signup_funnel": funnel, "launch_at": launch_at, "success_metric_refs": list(success_metric_refs), "subscription_profile": blueprint.subscription_profile}
    payload["launch_digest"] = _sealed_digest(LaunchPlan, payload, "launch_digest")
    return LaunchPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Product state
# --------------------------------------------------------------------------- #


class SaasProductScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    product_ref: OpaqueRef
    currency: CurrencyCode

    @field_validator("project_id")
    @classmethod
    def _project_id(cls, value: str) -> str:
        from uuid import UUID

        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return value


class ArtifactReceipt(_StrictModel):
    kind: ArtifactKind
    artifact_ref: OpaqueRef
    grounding_report_digest: Sha256Digest
    grounding_status: Literal["grounded", "review_required", "blocked"]
    approval_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=5)


class StageReceipt(_StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    dossier_digest: Sha256Digest | None = None
    research_confidence_percent: Decimal | None = None
    thesis_digest: Sha256Digest | None = None
    thesis_dossier_digest: Sha256Digest | None = None
    pricing_digest: Sha256Digest | None = None
    must_requirements: int | None = Field(default=None, ge=0, le=100)
    verdict_digest: Sha256Digest | None = None
    verdict: Literal["go", "pivot", "no_go", "insufficient_evidence"] | None = None
    model_digest: Sha256Digest | None = None
    projection_digest: Sha256Digest | None = None
    ask_digest: Sha256Digest | None = None
    ask_amount: Decimal | None = None
    ltv_to_cac: Decimal | None = None
    payback_months: Decimal | None = None
    artifacts: tuple[ArtifactReceipt, ...] = Field(default_factory=tuple, max_length=7)
    funding_status: FundingStatus | None = None
    closed_amount: Decimal | None = None
    investor_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    repository_digest: Sha256Digest | None = None
    repository_ref: OpaqueRef | None = None
    work_packages_total: int | None = Field(default=None, ge=0, le=100)
    software_production_handle_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=100)
    deployment_digest: Sha256Digest | None = None
    readiness_digest: Sha256Digest | None = None
    readiness_status: Literal["ready", "not_ready"] | None = None
    launch_digest: Sha256Digest | None = None
    signups: int | None = Field(default=None, ge=0)
    activations: int | None = Field(default=None, ge=0)
    paying_customers: int | None = Field(default=None, ge=0)
    mrr: Decimal | None = None
    learnings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("research_confidence_percent", "ask_amount", "ltv_to_cac", "payback_months", "closed_amount", "mrr", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))


class SaasProductCommand(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_command.v1"] = Field(default=PRODUCT_COMMAND_SCHEMA, alias="schema")
    event: ProductEvent
    stage: LoopStage | None = None
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_PRODUCT_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: StageReceipt = Field(default_factory=StageReceipt)
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "SaasProductCommand":
        if (self.event == "complete_stage") != (self.stage is not None):
            raise ValueError("complete_stage names a stage; pivot and abandon do not")
        if self.event != "complete_stage" and self.reason is None:
            raise ValueError("pivot and abandon require a reason")
        if _skip(info):
            return self
        if self.request_digest != product_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def product_command_digest(command: SaasProductCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(SaasProductCommand, command, "request_digest")


def seal_product_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = product_command_digest(raw)
    return SaasProductCommand.model_validate(raw).to_dict()


class ProductLedger(_StrictModel):
    dossier_digest: Sha256Digest | None = None
    research_confidence_percent: Decimal = Field(default=Decimal("0"), validate_default=True)
    thesis_digest: Sha256Digest | None = None
    pricing_digest: Sha256Digest | None = None
    must_requirements: int = Field(default=0, ge=0)
    verdict: str | None = None
    verdict_digest: Sha256Digest | None = None
    pivots: int = Field(default=0, ge=0)
    model_digest: Sha256Digest | None = None
    projection_digest: Sha256Digest | None = None
    ask_digest: Sha256Digest | None = None
    ask_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    ltv_to_cac: Decimal | None = None
    payback_months: Decimal | None = None
    artifact_kinds: tuple[ArtifactKind, ...] = Field(default_factory=tuple, max_length=7)
    artifacts_review_required: int = Field(default=0, ge=0)
    funding_status: FundingStatus = "not_required"
    closed_amount: Decimal = Field(default=Decimal("0"), validate_default=True)
    repository_ref: OpaqueRef | None = None
    repository_digest: Sha256Digest | None = None
    work_packages_total: int = Field(default=0, ge=0)
    work_packages_verified: int = Field(default=0, ge=0)
    deployment_digest: Sha256Digest | None = None
    readiness_digest: Sha256Digest | None = None
    launch_digest: Sha256Digest | None = None
    signups: int = Field(default=0, ge=0)
    activations: int = Field(default=0, ge=0)
    paying_customers: int = Field(default=0, ge=0)
    mrr: Decimal = Field(default=Decimal("0"), validate_default=True)
    learnings: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=40)

    @field_validator("research_confidence_percent", "ask_amount", "closed_amount", "mrr", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("ltv_to_cac", "payback_months", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))


class ProductTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_PRODUCT_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: ProductStatus
    transition_digest: Sha256Digest
    command: SaasProductCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "ProductTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: SaasProductCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, scope: SaasProductScope, history: Sequence[ProductTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _apply(plan: SaasProductLoopPlan, status: str, ledger: ProductLedger, command: SaasProductCommand) -> tuple[str, ProductLedger]:
    if status in TERMINAL_PRODUCT_STATUSES:
        raise _Rejected("PRODUCT_TERMINAL", f"product is {status}; no further transitions", "do_not_replay")
    blueprint = plan.blueprint
    data = ledger.to_dict()
    if command.event == "abandon":
        return "abandoned", ledger
    if command.event == "pivot":
        if status not in {"defined", "validated", "planned", "materials_produced"}:
            raise _Rejected("PIVOT_NOT_ALLOWED", "a pivot returns to product definition; it is only possible between definition and funding", "correct_input")
        if ledger.pivots + 1 > blueprint.max_pivots:
            raise _Rejected("PIVOT_LIMIT_REACHED", f"the blueprint allows {blueprint.max_pivots} pivot(s); abandon or change the blueprint", "manual_reconciliation")
        data.update({"pivots": ledger.pivots + 1, "thesis_digest": None, "pricing_digest": None, "verdict": None, "verdict_digest": None, "model_digest": None, "projection_digest": None, "ask_digest": None, "artifact_kinds": [], "artifacts_review_required": 0})
        return "researched", ProductLedger.model_validate(data)
    stage = str(command.stage)
    if STATUS_BEFORE_STAGE[stage] != status:
        raise _Rejected("ILLEGAL_TRANSITION", f"{stage} is not the next stage after {status}", "correct_input")
    r = command.receipt
    if stage == "research_market":
        if r.dossier_digest is None or r.research_confidence_percent is None:
            raise _Rejected("DOSSIER_MISSING", "research completion links the sealed dossier digest and its derived confidence", "correct_input")
        if r.research_confidence_percent < blueprint.min_research_confidence_percent:
            raise _Rejected("RESEARCH_CONFIDENCE_LOW", f"confidence {r.research_confidence_percent}% is below the {blueprint.min_research_confidence_percent}% floor; gather evidence for the assumptions", "correct_input")
        data.update({"dossier_digest": r.dossier_digest, "research_confidence_percent": str(r.research_confidence_percent)})
    elif stage == "define_product":
        if r.thesis_digest is None or r.pricing_digest is None or r.must_requirements is None:
            raise _Rejected("THESIS_MISSING", "definition links the sealed thesis, pricing hypothesis, and the must-requirement count", "correct_input")
        if r.thesis_dossier_digest != ledger.dossier_digest:
            raise _Rejected("THESIS_NOT_CHAINED", "the thesis must be derived from the retained dossier", "correct_input")
        if r.must_requirements < 1:
            raise _Rejected("NO_MUST_REQUIREMENTS", "a product needs at least one must-have requirement", "correct_input")
        data.update({"thesis_digest": r.thesis_digest, "pricing_digest": r.pricing_digest, "must_requirements": r.must_requirements})
    elif stage == "validate_demand":
        if r.verdict_digest is None or r.verdict is None:
            raise _Rejected("VERDICT_MISSING", "validation links the sealed verdict", "correct_input")
        if r.verdict != "go":
            raise _Rejected("VALIDATION_NOT_GO", f"verdict is {r.verdict}; pivot, gather evidence, or abandon", "correct_input")
        data.update({"verdict": r.verdict, "verdict_digest": r.verdict_digest})
    elif stage == "plan_business":
        if r.model_digest is None or r.projection_digest is None:
            raise _Rejected("MODEL_MISSING", "planning links the sealed business model and projection", "correct_input")
        if blueprint.funding_required and (r.ask_digest is None or r.ask_amount is None or r.ask_amount <= 0):
            raise _Rejected("ASK_MISSING", "a funded profile links the sealed funding ask", "correct_input")
        data.update({"model_digest": r.model_digest, "projection_digest": r.projection_digest, "ask_digest": r.ask_digest, "ask_amount": str(r.ask_amount or Decimal("0")), "ltv_to_cac": None if r.ltv_to_cac is None else str(r.ltv_to_cac), "payback_months": None if r.payback_months is None else str(r.payback_months)})
    elif stage == "produce_materials":
        kinds = {item.kind for item in r.artifacts}
        missing = [kind for kind in blueprint.required_artifacts if kind not in kinds]
        if missing:
            raise _Rejected("ARTIFACTS_MISSING", f"required materials missing: {', '.join(missing)}", "correct_input")
        blocked = [item.kind for item in r.artifacts if item.grounding_status == "blocked"]
        if blocked:
            raise _Rejected("ARTIFACT_UNGROUNDED", f"materials with ungrounded numbers or missing sections: {', '.join(blocked)}", "correct_input")
        unapproved = [item.kind for item in r.artifacts if item.kind in {"pitch_deck", "financial_summary"} and not item.approval_refs]
        if unapproved:
            raise _Rejected("ARTIFACT_APPROVAL_MISSING", f"investor materials need approval references: {', '.join(unapproved)}", "await_approval")
        data.update({"artifact_kinds": sorted(kinds), "artifacts_review_required": sum(1 for item in r.artifacts if item.grounding_status == "review_required")})
    elif stage == "secure_funding":
        if r.funding_status is None:
            raise _Rejected("FUNDING_STATUS_MISSING", "funding completion records the funding status", "correct_input")
        if blueprint.funding_required:
            if r.funding_status != "funded" or r.closed_amount is None:
                raise _Rejected("NOT_FUNDED", "a funded profile completes this stage only with closed funding", "correct_input")
            minimum = (ledger.ask_amount * blueprint.min_close_fraction).quantize(Decimal("0.01"))
            if r.closed_amount < minimum:
                raise _Rejected("FUNDING_SHORT", f"closed {r.closed_amount} is below {blueprint.min_close_fraction} of the {ledger.ask_amount} ask ({minimum})", "correct_input")
            if not r.investor_refs:
                raise _Rejected("INVESTORS_MISSING", "a closed round links its investors", "correct_input")
        elif r.funding_status not in {"bootstrapped", "not_required"}:
            raise _Rejected("FUNDING_STATUS_MISMATCH", "a bootstrapped profile records bootstrapped or not_required", "correct_input")
        data.update({"funding_status": r.funding_status, "closed_amount": str(r.closed_amount or Decimal("0"))})
    elif stage == "build_repository":
        if r.repository_digest is None or r.repository_ref is None or r.work_packages_total is None:
            raise _Rejected("REPOSITORY_MISSING", "build completion links the repository blueprint digest, the repository, and the work package count", "correct_input")
        if r.work_packages_total < ledger.must_requirements:
            raise _Rejected("WORK_PACKAGES_INCOMPLETE", f"{r.work_packages_total} work package(s) cannot cover {ledger.must_requirements} must-have requirement(s)", "correct_input")
        if len(r.software_production_handle_digests) < r.work_packages_total:
            raise _Rejected("PRODUCTION_RUNS_INCOMPLETE", f"{len(r.software_production_handle_digests)} verified software-production run(s) for {r.work_packages_total} work package(s)", "correct_input")
        data.update({"repository_ref": r.repository_ref, "repository_digest": r.repository_digest, "work_packages_total": r.work_packages_total, "work_packages_verified": len(r.software_production_handle_digests)})
    elif stage == "deploy":
        if r.deployment_digest is None or r.readiness_digest is None or r.readiness_status is None:
            raise _Rejected("DEPLOYMENT_MISSING", "deploy completion links the deployment plan digest and the launch readiness verdict", "correct_input")
        if r.readiness_status != "ready":
            raise _Rejected("NOT_LAUNCH_READY", "launch readiness is not_ready; deploy every environment and evidence the checklist", "correct_input")
        data.update({"deployment_digest": r.deployment_digest, "readiness_digest": r.readiness_digest})
    elif stage == "launch":
        if r.launch_digest is None or r.signups is None or r.activations is None or r.paying_customers is None or r.mrr is None:
            raise _Rejected("LAUNCH_EVIDENCE_MISSING", "launch completion links the launch plan digest and the first signups, activations, paying customers, and MRR", "correct_input")
        if r.paying_customers < 1:
            raise _Rejected("NO_PAYING_CUSTOMER", "a launch is complete when at least one customer pays", "correct_input")
        data.update({"launch_digest": r.launch_digest, "signups": r.signups, "activations": r.activations, "paying_customers": r.paying_customers, "mrr": str(r.mrr)})
    elif stage == "learn":
        if not r.learnings:
            raise _Rejected("LEARNINGS_MISSING", "the learn stage records what the launch taught", "correct_input")
        data["learnings"] = list(r.learnings)[:40]
        if r.paying_customers is not None:
            data["paying_customers"] = r.paying_customers
        if r.mrr is not None:
            data["mrr"] = str(r.mrr)
    return STATUS_AFTER_STAGE[stage], ProductLedger.model_validate(data)


class SaasProductState(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_state.v1"] = Field(default=PRODUCT_STATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    scope: SaasProductScope
    status: ProductStatus
    version: int = Field(ge=1, le=MAX_PRODUCT_TRANSITIONS)
    transition_history: tuple[ProductTransition, ...] = Field(min_length=1, max_length=MAX_PRODUCT_TRANSITIONS)
    ledger: ProductLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "SaasProductState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("product version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        prefix: tuple[ProductTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.scope, history):
            raise ValueError("state_digest must commit the exact product state")
        plan: SaasProductLoopPlan | None = (info.context or {}).get("saas_product_plan")
        if plan is not None:
            if plan.plan_digest != self.plan_digest:
                raise ValueError("product belongs to a different loop plan")
            status, ledger = "opened", ProductLedger()
            for transition in history:
                try:
                    status, ledger = _apply(plan, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the product table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("product status and ledger must be derived from history")
        return self


class ProductRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "ProductRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class ProductTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: ProductEvent
    stage: LoopStage | None = None
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: ProductStatus
    to_status: ProductStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: ProductRecovery


class ProductEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    repository_created: Literal[False] = False
    deployment_executed: Literal[False] = False
    material_published: Literal[False] = False
    investor_contacted: Literal[False] = False
    numbers_invented_by_model: Literal[False] = False


class ProductTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_transition_result.v1"] = Field(default=PRODUCT_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: SaasProductState | None = None
    receipt: ProductTransitionReceipt
    effect_boundary: ProductEffectBoundary = Field(default_factory=ProductEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "ProductTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: SaasProductLoopPlan | Mapping[str, Any], state: SaasProductState | Mapping[str, Any]) -> tuple[SaasProductLoopPlan, SaasProductState]:
    parsed_plan = SaasProductLoopPlan.model_validate(_detached(plan))
    unbound = SaasProductState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("product belongs to a different loop plan")
    return parsed_plan, SaasProductState.model_validate(unbound.to_dict(), context={"saas_product_plan": parsed_plan})


def open_saas_product(plan: SaasProductLoopPlan | Mapping[str, Any], scope: SaasProductScope | Mapping[str, Any], *, opened_at: str, actor_ref: str, dossier_digest: str, research_confidence_percent: Any) -> SaasProductState:
    """Open a product by completing market research with a sealed dossier."""

    parsed_plan = SaasProductLoopPlan.model_validate(_detached(plan))
    parsed_scope = SaasProductScope.model_validate(_detached(scope))
    if parsed_scope.currency != parsed_plan.blueprint.currency:
        raise ValueError("product currency must match the blueprint currency")
    genesis = _state_digest(parsed_plan.plan_digest, parsed_scope, ())
    command = SaasProductCommand.model_validate(seal_product_command({"event": "complete_stage", "stage": "research_market", "transition_ref": f"research_market:{parsed_scope.product_ref}", "idempotency_key": f"{parsed_scope.product_ref}:research_market", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": {"dossier_digest": dossier_digest, "research_confidence_percent": str(research_confidence_percent)}}))
    try:
        status, ledger = _apply(parsed_plan, "opened", ProductLedger(), command)
    except _Rejected as exc:
        raise ValueError(f"{exc.code}: {exc.instructions}") from exc
    transition = ProductTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return SaasProductState.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={"saas_product_plan": parsed_plan})


def advance_saas_product(plan: SaasProductLoopPlan | Mapping[str, Any], state: SaasProductState | Mapping[str, Any], command: SaasProductCommand | Mapping[str, Any]) -> ProductTransitionResult:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = SaasProductCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> ProductTransitionResult:
        receipt = ProductTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=ProductRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return ProductTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        previous = _parsed_timestamp_or_none(parsed_state.transition_history[-1].command.occurred_at)
        current = _parsed_timestamp_or_none(parsed_command.occurred_at)
        if previous is not None and current is not None and current < previous:
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_PRODUCT_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the product reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_plan, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = ProductTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = SaasProductState.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={"saas_product_plan": parsed_plan})
    receipt = ProductTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=ProductRecovery(disposition="not_required"))
    return ProductTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


class SaasProductAssessment(_StrictModel):
    schema_id: Literal["lightbulb.saas_product_assessment.v1"] = Field(default=PRODUCT_ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["saas.market_research_to_launched_product@0.1.0"] = SAAS_PRODUCT_GOLDEN_LOOP
    profile: BlueprintProfile
    product_ref: OpaqueRef
    status: ProductStatus
    version: int = Field(ge=1)
    stages_completed: tuple[LoopStage, ...] = Field(default_factory=tuple, max_length=10)
    next_stage: LoopStage | None = None
    pivots: int = Field(ge=0)
    research_confidence_percent: Decimal
    validation_verdict: str | None = None
    ltv_to_cac: Decimal | None = None
    payback_months: Decimal | None = None
    funding_status: FundingStatus
    funding_closed_fraction: Decimal | None = None
    materials_ready: bool
    build_progress_percent: Decimal
    launch_ready: bool
    paying_customers: int = Field(ge=0)
    target_first_paying_customers: int = Field(ge=1)
    traction_percent_of_target: Decimal
    mrr: Decimal
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=40)
    next_actions: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    subscription_handoff: dict[str, Any] = Field(default_factory=dict)
    effect_boundary: ProductEffectBoundary = Field(default_factory=ProductEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("research_confidence_percent", "build_progress_percent", "traction_percent_of_target", "mrr", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("ltv_to_cac", "payback_months", "funding_closed_fraction", mode="before")
    @classmethod
    def _optional(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "SaasProductAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(SaasProductAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_saas_product(plan: SaasProductLoopPlan | Mapping[str, Any], state: SaasProductState | Mapping[str, Any], *, assessed_at: str) -> SaasProductAssessment:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    blueprint, ledger = parsed_plan.blueprint, parsed_state.ledger
    quantum = Decimal("0.01")
    completed_events = [item.command for item in parsed_state.transition_history if item.command.event == "complete_stage"]
    completed: list[str] = []
    for command in completed_events:
        stage = str(command.stage)
        if stage == "research_market" and "research_market" in completed:
            continue
        completed.append(stage)
    reached = STAGE_ORDER.index(STATUS_ORDER_STAGE[parsed_state.status]) + 1 if parsed_state.status in STATUS_ORDER_STAGE else 0
    stages_done = tuple(STAGE_ORDER[:reached])
    next_stage = None if parsed_state.status in TERMINAL_PRODUCT_STATUSES or reached >= len(STAGE_ORDER) else STAGE_ORDER[reached]
    build_progress = (Decimal(ledger.work_packages_verified) / Decimal(ledger.work_packages_total) * 100).quantize(quantum) if ledger.work_packages_total else (Decimal(100) if "build_repository" in stages_done else Decimal(0))
    closed_fraction = (ledger.closed_amount / ledger.ask_amount).quantize(Decimal("0.0001")) if ledger.ask_amount > 0 else None
    traction = (Decimal(ledger.paying_customers) / Decimal(blueprint.target_first_paying_customers) * 100).quantize(quantum)
    learnings: list[str] = list(ledger.learnings)
    actions: list[str] = []
    if parsed_state.status == "abandoned":
        learnings.append("product abandoned")
    if ledger.pivots:
        learnings.append(f"{ledger.pivots} pivot(s) before the current thesis")
    if ledger.ltv_to_cac is not None and ledger.ltv_to_cac < 3:
        learnings.append(f"LTV to CAC of {ledger.ltv_to_cac} is below 3")
        actions.append("raise pricing or cut acquisition cost before scaling spend")
    if ledger.payback_months is not None and ledger.payback_months > 18:
        actions.append("shorten CAC payback below 18 months before raising")
    if ledger.artifacts_review_required:
        actions.append(f"{ledger.artifacts_review_required} material(s) need a human review of cited facts")
    if next_stage == "secure_funding" and blueprint.funding_required:
        actions.append(f"run the investor pipeline for a {blueprint.round_type} round of {ledger.ask_amount}")
    if next_stage == "build_repository":
        actions.append(f"compile {ledger.must_requirements} work package(s) into software-production requests on the {blueprint.stack} stack")
    if next_stage == "deploy":
        actions.append("deploy every environment and evidence the security checklist before launch")
    if next_stage == "launch":
        actions.append(f"launch through {', '.join(blueprint.launch_channels)} with the {blueprint.subscription_profile} subscription profile")
    if "launch" in stages_done and traction < 100:
        actions.append(f"{ledger.paying_customers} of {blueprint.target_first_paying_customers} target paying customers; iterate the launch campaign")
    if parsed_state.status == "completed" and not learnings:
        learnings.append("product launched inside blueprint policy")
    handoff = {"golden_loop": SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF, "profile": blueprint.subscription_profile, "overrides": {"currency": blueprint.currency}, "ready": "launch" in stages_done}
    payload = {"profile": blueprint.profile, "product_ref": parsed_state.scope.product_ref, "status": parsed_state.status, "version": parsed_state.version, "stages_completed": stages_done, "next_stage": next_stage, "pivots": ledger.pivots, "research_confidence_percent": str(ledger.research_confidence_percent), "validation_verdict": ledger.verdict, "ltv_to_cac": None if ledger.ltv_to_cac is None else str(ledger.ltv_to_cac), "payback_months": None if ledger.payback_months is None else str(ledger.payback_months), "funding_status": ledger.funding_status, "funding_closed_fraction": None if closed_fraction is None else str(closed_fraction), "materials_ready": "produce_materials" in stages_done, "build_progress_percent": str(build_progress), "launch_ready": ledger.readiness_digest is not None, "paying_customers": ledger.paying_customers, "target_first_paying_customers": blueprint.target_first_paying_customers, "traction_percent_of_target": str(traction), "mrr": str(ledger.mrr), "learnings": learnings[:40], "next_actions": actions[:20], "subscription_handoff": handoff, "assessed_at": assessed_at}
    payload["assessment_digest"] = _sealed_digest(SaasProductAssessment, payload, "assessment_digest")
    return SaasProductAssessment.model_validate(payload)


STATUS_ORDER_STAGE: dict[str, str] = {status: stage for stage, status in STATUS_AFTER_STAGE.items()}

SAAS_PRODUCT_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": SAAS_PRODUCT_ARCHETYPE,
    "title": "SaaS product",
    "golden_loop": SAAS_PRODUCT_GOLDEN_LOOP,
    "composed_with": [SOFTWARE_PRODUCTION_GOLDEN_LOOP_REF, SUBSCRIPTION_BUSINESS_GOLDEN_LOOP_REF, "documents.governed_business_artifact_production@0.1.0", "growth.* unit economics, price moves", "cash.* runway and cash flow"],
    "profiles": sorted(SAAS_PRODUCT_PROFILES),
    "stages": list(STAGE_ORDER),
    "materials": list(ArtifactKind.__args__),  # type: ignore[attr-defined]
    "economic_spine": {"acquire_demand": "launch", "create_offer": "define_product", "agree_purchase": "launch (subscription handoff)", "deliver_value": "build_repository+deploy", "accept_value": "validate_demand / verified production runs", "monetize": "secure_funding + subscription handoff", "learn": "learn"},
    "composable_with": ["subscription_business", "service_business", "product_commerce", "appointment_business", "marketplace_business"],
    "explicit_inputs_never_invented": ["market claims and their evidence", "interview and validation evidence", "model assumptions", "investor commitments", "deployment and checklist evidence"],
}

__all__ = [
    "BLUEPRINT_SCHEMA",
    "DEPLOYMENT_SCHEMA",
    "LAUNCH_SCHEMA",
    "MAX_PRODUCT_TRANSITIONS",
    "PLAN_SCHEMA",
    "PRODUCT_ASSESSMENT_SCHEMA",
    "PRODUCT_COMMAND_SCHEMA",
    "PRODUCT_RESULT_SCHEMA",
    "PRODUCT_STATE_SCHEMA",
    "READINESS_SCHEMA",
    "REPOSITORY_SCHEMA",
    "SAAS_PRODUCT_ARCHETYPE",
    "SAAS_PRODUCT_ARCHETYPE_MANIFEST",
    "SAAS_PRODUCT_GOLDEN_LOOP",
    "SAAS_PRODUCT_PROFILES",
    "STAGE_ORDER",
    "STATUS_AFTER_STAGE",
    "TERMINAL_PRODUCT_STATUSES",
    "ArtifactReceipt",
    "DeploymentPlan",
    "DeploymentReceipt",
    "EnvironmentPlan",
    "LaunchPlan",
    "LaunchReadiness",
    "ProductEffectBoundary",
    "ProductLedger",
    "ProductRecovery",
    "ProductTransition",
    "ProductTransitionReceipt",
    "ProductTransitionResult",
    "RepositoryBlueprint",
    "SaasProductAssessment",
    "SaasProductBlueprint",
    "SaasProductCommand",
    "SaasProductLoopPlan",
    "SaasProductScope",
    "SaasProductState",
    "StageBinding",
    "StageReceipt",
    "WorkPackageSpec",
    "advance_saas_product",
    "assess_saas_product",
    "compile_saas_product_blueprint",
    "derive_deployment_plan",
    "derive_launch_plan",
    "derive_repository_blueprint",
    "open_saas_product",
    "product_command_digest",
    "seal_product_command",
    "seal_saas_product_blueprint",
    "verify_launch_readiness",
]
