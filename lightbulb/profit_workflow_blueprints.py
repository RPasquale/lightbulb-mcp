"""Code-owned blueprints for the ten profit workflows adjacent to launch.

The registry is intentionally declarative and immutable. Runtime planning,
evidence verification, and bounded evaluation live in
``profit_workflow_runtime``; executable adapters live in ``profit_primitives``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.dynamic_workflows import DynamicWorkflowScope


PROFIT_WORKFLOW_PLAN_SCHEMA = "lightbulb.profit_workflow_plan.v1"
PROFIT_FLYWHEEL_PLAN_SCHEMA = "lightbulb.profit_flywheel_plan.v1"
PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA = "lightbulb.profit_action_execution_receipt.v1"
PROFIT_OUTCOME_EVIDENCE_SCHEMA = "lightbulb.profit_outcome_evidence.v1"
PROFIT_WORKFLOW_EVALUATION_SCHEMA = "lightbulb.profit_workflow_evaluation.v1"
_PROFIT_ACCOUNT_HMAC_DOMAIN = "lightbulb.profit_connector_account_binding.v1"
_PROFIT_ACTION_EXECUTION_HMAC_DOMAIN = PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA
_PROFIT_METRIC_HMAC_DOMAIN = "lightbulb.profit_metric_evidence.v1"
_PROFIT_PLAN_HMAC_DOMAIN = "lightbulb.profit_workflow_plan.v1"
_PROFIT_OUTCOME_HMAC_DOMAIN = "lightbulb.profit_outcome_evidence.v1"
_PROFIT_EVALUATION_HMAC_DOMAIN = "lightbulb.profit_workflow_evaluation.v1"

_MONEY_QUANTUM = Decimal("0.01")
_RATE_QUANTUM = Decimal("0.000001")
_SCORE_QUANTUM = Decimal("0.000001")
_MAX_EVIDENCE = 100
_MAX_CANDIDATES = 20
_MAX_PARAMETERS = 30
_MAX_WORKFLOW_BYTES = 512 * 1_024
_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CAPABILITY_PATTERN = r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_FORBIDDEN_PARAMETER_PARTS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "bearer_token",
        "client_secret",
        "company_id",
        "connector_secret",
        "credential",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "tenant_id",
        "token",
        "user_id",
    }
)


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("text must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("text must contain printable characters only")
    return value


def _bounded_body(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(
        ord(character) < 32 and character not in {"\t", "\n", "\r"}
        for character in value
    ):
        raise ValueError("content contains an unsupported control character")
    return value


def _immutable_sequence(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, quantum: Decimal = _RATE_QUANTUM) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite bounded decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be finite")
    if parsed != normalized:
        raise ValueError(
            f"value supports at most {-quantum.as_tuple().exponent} decimal places"
        )
    return normalized


def _stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _serialized_size(value: Any) -> int:
    return len(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    )


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_body),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
CapabilityRef = Annotated[str, StringConstraints(pattern=_CAPABILITY_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

ProfitWorkflowId = Literal[
    "finance.allocate_launch_portfolio_profit",
    "product.discover_profitable_opportunities",
    "gtm.optimize_offer_price_and_margin",
    "commerce.govern_inventory_and_fulfillment",
    "commerce.optimize_storefront_conversion",
    "content.run_creative_experiment_factory",
    "growth.allocate_incremental_acquisition",
    "crm.orchestrate_profit_aware_lifecycle",
    "commerce.recover_abandoned_revenue",
    "customer_success.prevent_returns_and_expand_ltv",
]
ProfitMetric = Literal[
    "add_to_cart_rate",
    "average_order_value",
    "cash_conversion_cycle_days",
    "checkout_completion_rate",
    "churn_rate",
    "click_through_rate",
    "competitive_saturation_rate",
    "contribution_margin_rate",
    "contribution_profit",
    "contribution_profit_per_contact",
    "contribution_profit_per_order",
    "contribution_profit_per_session",
    "creative_profit_per_thousand_impressions",
    "customer_acquisition_cost",
    "customer_lifetime_value",
    "forecast_error_rate",
    "inventory_turnover",
    "marginal_roas",
    "qualified_demand_score",
    "recovered_contribution_profit",
    "refund_rate",
    "repeat_purchase_rate",
    "return_rate",
    "segment_conversion_rate",
    "stockout_rate",
    "storefront_conversion_rate",
]
MetricUnit = Literal["money", "ratio", "count", "days", "multiple"]
TargetDirection = Literal["maximize", "minimize"]
Provider = Literal[
    "facebook",
    "gmail",
    "google_analytics",
    "host",
    "hubspot",
    "instagram",
    "linkedin",
    "salesforce",
    "shopify",
    "stripe",
    "xero",
]
ExecutionKind = Literal[
    "connector_tool",
    "domain_action",
    "host_service",
    "sdk_primitive",
]
CapabilityAvailability = Literal[
    "sdk_available",
    "trusted_host_materializer_available",
    "generated_tool_governance_required",
    "platform_adapter_only",
    "domain_agent_only",
    "host_service_missing",
]
ProfitEffect = Literal["DRAFT", "WRITE"]


_METRIC_UNITS: dict[str, MetricUnit] = {
    "add_to_cart_rate": "ratio",
    "average_order_value": "money",
    "cash_conversion_cycle_days": "days",
    "checkout_completion_rate": "ratio",
    "churn_rate": "ratio",
    "click_through_rate": "ratio",
    "competitive_saturation_rate": "ratio",
    "contribution_margin_rate": "ratio",
    "contribution_profit": "money",
    "contribution_profit_per_contact": "money",
    "contribution_profit_per_order": "money",
    "contribution_profit_per_session": "money",
    "creative_profit_per_thousand_impressions": "money",
    "customer_acquisition_cost": "money",
    "customer_lifetime_value": "money",
    "forecast_error_rate": "ratio",
    "inventory_turnover": "multiple",
    "marginal_roas": "multiple",
    "qualified_demand_score": "ratio",
    "recovered_contribution_profit": "money",
    "refund_rate": "ratio",
    "repeat_purchase_rate": "ratio",
    "return_rate": "ratio",
    "segment_conversion_rate": "ratio",
    "stockout_rate": "ratio",
    "storefront_conversion_rate": "ratio",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


class ProfitWorkflowValidationError(ValueError):
    """A profit workflow request cannot be compiled safely."""


class ProfitScopeKeyRing(Protocol):
    """Trusted host contract for exact-scope digests and HMAC signatures."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


class ProfitCapabilityContract(_StrictModel):
    capability: CapabilityRef
    purpose: ShortText
    execution_kind: ExecutionKind
    effect: ProfitEffect
    availability: CapabilityAvailability
    notes: LongText


class ProfitWorkflowDefinition(_StrictModel):
    workflow_id: ProfitWorkflowId
    ordinal: int = Field(ge=1, le=10)
    title: ShortText
    category: ShortText
    promise: LongText
    primary_metric: ProfitMetric
    target_direction: TargetDirection
    required_metrics: tuple[ProfitMetric, ...] = Field(min_length=1, max_length=8)
    supported_metrics: tuple[ProfitMetric, ...] = Field(min_length=1, max_length=16)
    evidence_capabilities: tuple[CapabilityRef, ...] = Field(
        min_length=1,
        max_length=16,
    )
    action_capabilities: tuple[ProfitCapabilityContract, ...] = Field(
        min_length=1,
        max_length=8,
    )
    consumes: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    feeds: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    trigger_event: CapabilityRef
    emits_event: CapabilityRef

    @field_validator(
        "required_metrics",
        "supported_metrics",
        "evidence_capabilities",
        "action_capabilities",
        "consumes",
        "feeds",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _closed_definition(self) -> "ProfitWorkflowDefinition":
        if self.primary_metric not in self.required_metrics:
            raise ValueError("primary_metric must be required")
        if not set(self.required_metrics).issubset(self.supported_metrics):
            raise ValueError("required metrics must be supported")
        if len(set(self.supported_metrics)) != len(self.supported_metrics):
            raise ValueError("supported metrics must be unique")
        capabilities = [item.capability for item in self.action_capabilities]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("action capabilities must be unique")
        return self


def _capability(
    capability: str,
    purpose: str,
    execution_kind: ExecutionKind,
    effect: ProfitEffect,
    availability: CapabilityAvailability,
    notes: str,
) -> ProfitCapabilityContract:
    return ProfitCapabilityContract(
        capability=capability,
        purpose=purpose,
        execution_kind=execution_kind,
        effect=effect,
        availability=availability,
        notes=notes,
    )


PROFIT_WORKFLOW_DEFINITIONS: tuple[ProfitWorkflowDefinition, ...] = (
    ProfitWorkflowDefinition(
        workflow_id="finance.allocate_launch_portfolio_profit",
        ordinal=1,
        title="Allocate launch portfolio profit",
        category="finance",
        promise=(
            "Attribute contribution profit across stores, products, campaigns, and "
            "cohorts, then issue bounded scale, hold, revise, or retire proposals."
        ),
        primary_metric="contribution_profit",
        target_direction="maximize",
        required_metrics=("contribution_profit", "contribution_margin_rate"),
        supported_metrics=(
            "contribution_profit",
            "contribution_margin_rate",
            "cash_conversion_cycle_days",
            "forecast_error_rate",
        ),
        evidence_capabilities=(
            "shopify.analytics_query",
            "stripe.list_balance_transactions",
            "xero.profit_loss_report",
            "host.normalized_profit_ledger",
        ),
        action_capabilities=(
            _capability(
                "approval.request_decision",
                "Approve a bounded capital envelope",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The decision primitive records the envelope; it does not spend funds.",
            ),
            _capability(
                "learning.plan_optimization_sweep",
                "Create a bounded follow-up optimization sweep",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The sweep remains subject to its own runtime budget and approvals.",
            ),
        ),
        consumes=(
            "growth.allocate_incremental_acquisition",
            "commerce.recover_abandoned_revenue",
            "customer_success.prevent_returns_and_expand_ltv",
        ),
        feeds=("product.discover_profitable_opportunities",),
        trigger_event="finance.profit_portfolio_observed",
        emits_event="finance.launch_capital_allocated",
    ),
    ProfitWorkflowDefinition(
        workflow_id="product.discover_profitable_opportunities",
        ordinal=2,
        title="Discover profitable product opportunities",
        category="product",
        promise=(
            "Rank product, segment, and store opportunities by expected contribution "
            "profit and choose the cheapest bounded pilot that can disprove the thesis."
        ),
        primary_metric="qualified_demand_score",
        target_direction="maximize",
        required_metrics=(
            "qualified_demand_score",
            "competitive_saturation_rate",
        ),
        supported_metrics=(
            "qualified_demand_score",
            "competitive_saturation_rate",
            "contribution_margin_rate",
            "refund_rate",
        ),
        evidence_capabilities=(
            "shopify.analytics_query",
            "crm.search_deals",
            "linkedin.fetch_metrics",
            "host.market_demand_snapshot",
        ),
        action_capabilities=(
            _capability(
                "project.create_work_packet",
                "Create a bounded opportunity-validation work packet",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The work packet must preserve pilot budget and kill criteria.",
            ),
            _capability(
                "gtm.plan_omnichannel_product_launch",
                "Prepare a one-store pilot launch proposal",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The downstream planner still requires reviewed product and channel inputs.",
            ),
        ),
        consumes=("finance.allocate_launch_portfolio_profit",),
        feeds=("gtm.optimize_offer_price_and_margin",),
        trigger_event="product.opportunity_discovery_requested",
        emits_event="product.profitable_opportunity_ranked",
    ),
    ProfitWorkflowDefinition(
        workflow_id="gtm.optimize_offer_price_and_margin",
        ordinal=3,
        title="Optimize offer, price, and margin",
        category="growth",
        promise=(
            "Choose price, bundle, shipping-threshold, and discount experiments that "
            "maximize contribution profit without violating a hard margin floor."
        ),
        primary_metric="contribution_profit_per_order",
        target_direction="maximize",
        required_metrics=(
            "contribution_profit_per_order",
            "contribution_margin_rate",
        ),
        supported_metrics=(
            "contribution_profit_per_order",
            "contribution_margin_rate",
            "average_order_value",
            "storefront_conversion_rate",
            "refund_rate",
        ),
        evidence_capabilities=(
            "shopify.analytics_query",
            "xero.profit_loss_report",
            "host.normalized_unit_economics",
            "host.experiment_snapshot",
        ),
        action_capabilities=(
            _capability(
                "shopify.create_price_rule",
                "Create a bounded and expiring price rule",
                "connector_tool",
                "WRITE",
                "generated_tool_governance_required",
                "A live discount requires a distinct approval, redemption cap, and expiry.",
            ),
            _capability(
                "ecommerce.update_product",
                "Stage a reviewed product price or bundle update",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The shared materializer enforces exact payload, account, approval, project, and server provenance.",
            ),
            _capability(
                "approval.request_decision",
                "Approve an offer experiment and margin floor",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "Approval does not itself change a public price.",
            ),
        ),
        consumes=("product.discover_profitable_opportunities",),
        feeds=(
            "commerce.govern_inventory_and_fulfillment",
            "commerce.optimize_storefront_conversion",
            "content.run_creative_experiment_factory",
        ),
        trigger_event="gtm.offer_optimization_requested",
        emits_event="gtm.offer_experiment_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="commerce.govern_inventory_and_fulfillment",
        ordinal=4,
        title="Govern inventory and fulfillment",
        category="operations",
        promise=(
            "Gate campaigns on real availability and balance stockout loss against "
            "dead-stock cash using bounded reorder, transfer, pace, and pause proposals."
        ),
        primary_metric="stockout_rate",
        target_direction="minimize",
        required_metrics=("stockout_rate", "forecast_error_rate"),
        supported_metrics=(
            "stockout_rate",
            "forecast_error_rate",
            "inventory_turnover",
            "cash_conversion_cycle_days",
            "contribution_profit",
        ),
        evidence_capabilities=(
            "ecommerce.get_inventory",
            "shopify.analytics_query",
            "xero.list_purchase_orders",
            "host.inventory_snapshot",
        ),
        action_capabilities=(
            _capability(
                "xero.create_purchase_order",
                "Create an approved replenishment purchase order",
                "connector_tool",
                "WRITE",
                "generated_tool_governance_required",
                "Supplier, lead-time, cash, and quantity checks remain mandatory.",
            ),
            _capability(
                "host.update_inventory_level",
                "Apply a provider-specific inventory transfer or adjustment",
                "host_service",
                "WRITE",
                "host_service_missing",
                "There is no universal governed inventory mutation service today.",
            ),
            _capability(
                "project.create_work_packet",
                "Create a replenishment or campaign-pause work packet",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The work packet can gate launch but cannot assert stock changed.",
            ),
        ),
        consumes=("gtm.optimize_offer_price_and_margin",),
        feeds=("gtm.plan_omnichannel_product_launch",),
        trigger_event="commerce.inventory_governance_requested",
        emits_event="commerce.inventory_gate_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="commerce.optimize_storefront_conversion",
        ordinal=5,
        title="Optimize storefront conversion",
        category="commerce",
        promise=(
            "Design previewable storefront experiments that improve contribution profit "
            "per session, with immutable variants, holdouts, and promote-or-revert gates."
        ),
        primary_metric="contribution_profit_per_session",
        target_direction="maximize",
        required_metrics=(
            "contribution_profit_per_session",
            "storefront_conversion_rate",
        ),
        supported_metrics=(
            "contribution_profit_per_session",
            "storefront_conversion_rate",
            "add_to_cart_rate",
            "checkout_completion_rate",
            "average_order_value",
        ),
        evidence_capabilities=(
            "shopify.analytics_query",
            "google_analytics.fetch_metrics",
            "host.experiment_snapshot",
        ),
        action_capabilities=(
            _capability(
                "shopify.upsert_theme_files",
                "Build an unpublished storefront experiment variant",
                "connector_tool",
                "WRITE",
                "generated_tool_governance_required",
                "Publishing or reverting a theme remains a separate approval unit.",
            ),
            _capability(
                "ecommerce.update_product",
                "Stage reviewed product-page content changes",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The shared materializer can apply a reviewed exact product payload behind governed approval.",
            ),
            _capability(
                "project.create_work_packet",
                "Create a conversion experiment work packet",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The work packet preserves hypothesis, holdout, and rollback criteria.",
            ),
        ),
        consumes=("gtm.optimize_offer_price_and_margin",),
        feeds=("gtm.plan_omnichannel_product_launch",),
        trigger_event="commerce.storefront_optimization_requested",
        emits_event="commerce.storefront_experiment_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="content.run_creative_experiment_factory",
        ordinal=6,
        title="Run creative experiment factory",
        category="content",
        promise=(
            "Generate bounded channel-native creative experiments, detect fatigue, and "
            "select on downstream contribution profit rather than engagement alone."
        ),
        primary_metric="creative_profit_per_thousand_impressions",
        target_direction="maximize",
        required_metrics=(
            "creative_profit_per_thousand_impressions",
            "click_through_rate",
        ),
        supported_metrics=(
            "creative_profit_per_thousand_impressions",
            "click_through_rate",
            "storefront_conversion_rate",
            "refund_rate",
        ),
        evidence_capabilities=(
            "facebook.fetch_metrics",
            "instagram.fetch_metrics",
            "linkedin.fetch_metrics",
            "google_analytics.fetch_metrics",
            "host.experiment_snapshot",
        ),
        action_capabilities=(
            _capability(
                "documents.generate_business_artifact",
                "Generate a reviewable creative test pack",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "Generated claims and media still require brand and compliance review.",
            ),
            _capability(
                "facebook.publish_post",
                "Publish an approved Facebook experiment cell",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The shared materializer binds the exact reviewed post to account, approval, project, and receipt provenance.",
            ),
            _capability(
                "instagram.publish_post",
                "Publish an approved Instagram experiment cell",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "Instagram requires public media; native scheduling remains unsupported and is never inferred.",
            ),
            _capability(
                "linkedin.publish_post",
                "Publish an approved LinkedIn experiment cell",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The materializer enforces the adapter's 3,000-character limit; scheduling is never represented.",
            ),
        ),
        consumes=("gtm.optimize_offer_price_and_margin",),
        feeds=("gtm.plan_omnichannel_product_launch",),
        trigger_event="content.creative_experiment_requested",
        emits_event="content.creative_experiment_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="growth.allocate_incremental_acquisition",
        ordinal=7,
        title="Allocate incremental acquisition",
        category="growth",
        promise=(
            "Allocate only the next bounded tranche of acquisition budget where causal "
            "evidence predicts positive marginal contribution profit and capacity exists."
        ),
        primary_metric="marginal_roas",
        target_direction="maximize",
        required_metrics=("marginal_roas", "customer_acquisition_cost"),
        supported_metrics=(
            "marginal_roas",
            "customer_acquisition_cost",
            "contribution_profit",
            "customer_lifetime_value",
            "stockout_rate",
        ),
        evidence_capabilities=(
            "facebook.fetch_metrics",
            "instagram.fetch_metrics",
            "linkedin.fetch_metrics",
            "shopify.analytics_query",
            "host.paid_media_spend_snapshot",
        ),
        action_capabilities=(
            _capability(
                "approval.request_decision",
                "Approve a capped acquisition tranche and stop-loss",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The approval records a budget envelope but does not mutate an ad account.",
            ),
            _capability(
                "host.update_paid_media_budget",
                "Apply a channel budget mutation",
                "host_service",
                "WRITE",
                "host_service_missing",
                "No governed Meta, Google, or LinkedIn Ads budget adapter exists today.",
            ),
        ),
        consumes=("gtm.plan_omnichannel_product_launch",),
        feeds=(
            "customer_success.prevent_returns_and_expand_ltv",
            "finance.allocate_launch_portfolio_profit",
        ),
        trigger_event="growth.incremental_budget_requested",
        emits_event="growth.acquisition_tranche_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="crm.orchestrate_profit_aware_lifecycle",
        ordinal=8,
        title="Orchestrate profit-aware lifecycle",
        category="crm",
        promise=(
            "Choose the consent-safe next best action for each lead or customer using "
            "expected contribution, suppression rules, and bounded contact frequency."
        ),
        primary_metric="contribution_profit_per_contact",
        target_direction="maximize",
        required_metrics=(
            "contribution_profit_per_contact",
            "segment_conversion_rate",
        ),
        supported_metrics=(
            "contribution_profit_per_contact",
            "segment_conversion_rate",
            "repeat_purchase_rate",
            "customer_lifetime_value",
            "churn_rate",
        ),
        evidence_capabilities=(
            "crm.search_deals",
            "salesforce.pipeline_report",
            "shopify.analytics_query",
            "host.customer_cohort_snapshot",
        ),
        action_capabilities=(
            _capability(
                "crm.qualify_lead",
                "Qualify a lead before selecting a lifecycle action",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "Qualification uses governed CRM reads and does not send outreach.",
            ),
            _capability(
                "communication.write_email",
                "Draft or send an approved lifecycle email",
                "sdk_primitive",
                "WRITE",
                "sdk_available",
                "Consent, opt-out, dedupe, and frequency caps must be checked first.",
            ),
            _capability(
                "gmail.send_email",
                "Send one exact approved lifecycle email through the bound Gmail account",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The owning workflow must attest consent, identity, suppression, dedupe, frequency, account, content, and approval before dispatch.",
            ),
            _capability(
                "calendar.schedule_meeting",
                "Propose or schedule a qualified meeting",
                "sdk_primitive",
                "WRITE",
                "sdk_available",
                "A calendar write remains separately approval-gated.",
            ),
            _capability(
                "hubspot.create_workflow",
                "Create a HubSpot lifecycle workflow",
                "domain_action",
                "WRITE",
                "domain_agent_only",
                "There is no typed SDK sales-sequence authoring surface today.",
            ),
        ),
        consumes=("gtm.plan_omnichannel_product_launch",),
        feeds=("customer_success.prevent_returns_and_expand_ltv",),
        trigger_event="crm.lifecycle_orchestration_requested",
        emits_event="crm.next_best_action_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="commerce.recover_abandoned_revenue",
        ordinal=9,
        title="Recover abandoned revenue",
        category="commerce",
        promise=(
            "Recover already-created demand with the least costly consent-safe action, "
            "using margin floors, inventory gates, holdouts, and frequency limits."
        ),
        primary_metric="recovered_contribution_profit",
        target_direction="maximize",
        required_metrics=(
            "recovered_contribution_profit",
            "contribution_margin_rate",
        ),
        supported_metrics=(
            "recovered_contribution_profit",
            "contribution_margin_rate",
            "checkout_completion_rate",
            "stockout_rate",
            "refund_rate",
        ),
        evidence_capabilities=(
            "shopify.list_abandoned_checkouts",
            "shopify.analytics_query",
            "host.checkout_recovery_snapshot",
        ),
        action_capabilities=(
            _capability(
                "communication.write_email",
                "Send an approved checkout-recovery email",
                "sdk_primitive",
                "WRITE",
                "sdk_available",
                "Identity, consent, dedupe, holdout, and frequency checks are mandatory.",
            ),
            _capability(
                "gmail.send_email",
                "Send an exact approved recovery email through the bound Gmail account",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "Recipient, content, consent, recovery-link digest, frequency cap, and approval must all be exact-bound.",
            ),
            _capability(
                "ecommerce.create_discount",
                "Create a bounded single-customer recovery discount code",
                "connector_tool",
                "WRITE",
                "trusted_host_materializer_available",
                "The shared materializer requires one bounded expiry, usage cap, margin gate, exact approval, and governed route.",
            ),
            _capability(
                "shopify.create_price_rule",
                "Create a minimum bounded recovery incentive",
                "connector_tool",
                "WRITE",
                "generated_tool_governance_required",
                "Discounts require expiry, redemption caps, margin floor, and approval.",
            ),
            _capability(
                "project.create_work_packet",
                "Escalate high-value checkout friction to support",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The work packet must not expose payment credentials or tokens.",
            ),
        ),
        consumes=("gtm.plan_omnichannel_product_launch",),
        feeds=(
            "customer_success.prevent_returns_and_expand_ltv",
            "finance.allocate_launch_portfolio_profit",
        ),
        trigger_event="commerce.abandoned_revenue_detected",
        emits_event="commerce.recovery_action_planned",
    ),
    ProfitWorkflowDefinition(
        workflow_id="customer_success.prevent_returns_and_expand_ltv",
        ordinal=10,
        title="Prevent returns and expand LTV",
        category="customer_success",
        promise=(
            "Detect post-purchase harm early, prevent avoidable returns, fix root causes, "
            "and choose profitable retention actions without obstructing valid refunds."
        ),
        primary_metric="customer_lifetime_value",
        target_direction="maximize",
        required_metrics=("customer_lifetime_value", "return_rate"),
        supported_metrics=(
            "customer_lifetime_value",
            "return_rate",
            "refund_rate",
            "repeat_purchase_rate",
            "churn_rate",
            "contribution_profit",
        ),
        evidence_capabilities=(
            "shopify.list_refunds",
            "shopify.list_fulfillment_orders",
            "shopify.analytics_query",
            "host.customer_cohort_snapshot",
            "host.support_outcome_snapshot",
        ),
        action_capabilities=(
            _capability(
                "communication.write_email",
                "Send approved proactive help or retention communication",
                "sdk_primitive",
                "WRITE",
                "sdk_available",
                "Consent and suppression rules apply; never auto-deny a valid refund.",
            ),
            _capability(
                "project.create_work_packet",
                "Create a product, fulfillment, or claims root-cause packet",
                "sdk_primitive",
                "DRAFT",
                "sdk_available",
                "The packet feeds product, storefront, creative, and inventory changes.",
            ),
            _capability(
                "stripe.create_refund",
                "Issue an approved provider refund where Stripe owns payment truth",
                "connector_tool",
                "WRITE",
                "generated_tool_governance_required",
                "A Stripe refund is not a substitute for Shopify return-state reconciliation.",
            ),
        ),
        consumes=(
            "gtm.plan_omnichannel_product_launch",
            "growth.allocate_incremental_acquisition",
            "crm.orchestrate_profit_aware_lifecycle",
            "commerce.recover_abandoned_revenue",
        ),
        feeds=("finance.allocate_launch_portfolio_profit",),
        trigger_event="customer_success.return_risk_detected",
        emits_event="customer_success.ltv_intervention_planned",
    ),
)

_DEFINITIONS_BY_ID = {
    definition.workflow_id: definition for definition in PROFIT_WORKFLOW_DEFINITIONS
}


def _validate_profit_workflow_registry() -> None:
    expected_external = {"gtm.plan_omnichannel_product_launch"}
    if len(_DEFINITIONS_BY_ID) != 10:
        raise RuntimeError(
            "profit workflow registry must contain exactly ten workflows"
        )
    for definition in PROFIT_WORKFLOW_DEFINITIONS:
        for target in definition.feeds:
            if target in expected_external:
                continue
            if target not in _DEFINITIONS_BY_ID:
                raise RuntimeError(f"unknown profit workflow follow-up: {target}")
            if definition.workflow_id not in _DEFINITIONS_BY_ID[target].consumes:
                raise RuntimeError(
                    f"profit workflow edge {definition.workflow_id}->{target} "
                    "is missing its reciprocal consumes declaration"
                )
        for source in definition.consumes:
            if source in expected_external:
                continue
            if source not in _DEFINITIONS_BY_ID:
                raise RuntimeError(f"unknown profit workflow dependency: {source}")
            if definition.workflow_id not in _DEFINITIONS_BY_ID[source].feeds:
                raise RuntimeError(
                    f"profit workflow edge {source}->{definition.workflow_id} "
                    "is missing its reciprocal feeds declaration"
                )


_validate_profit_workflow_registry()


__all__ = [
    "PROFIT_ACTION_EXECUTION_RECEIPT_SCHEMA",
    "PROFIT_FLYWHEEL_PLAN_SCHEMA",
    "PROFIT_OUTCOME_EVIDENCE_SCHEMA",
    "PROFIT_WORKFLOW_DEFINITIONS",
    "PROFIT_WORKFLOW_EVALUATION_SCHEMA",
    "PROFIT_WORKFLOW_PLAN_SCHEMA",
    "CapabilityAvailability",
    "CapabilityRef",
    "CurrencyCode",
    "ExecutionKind",
    "MetricUnit",
    "ProfitCapabilityContract",
    "ProfitEffect",
    "ProfitMetric",
    "ProfitScopeKeyRing",
    "ProfitWorkflowDefinition",
    "ProfitWorkflowId",
    "ProfitWorkflowValidationError",
    "Provider",
    "TargetDirection",
]
