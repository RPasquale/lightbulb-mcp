"""Product Commerce Golden Operating Loop and Company Blueprint profiles.

Completes the existing Shopify/omnichannel path into one out-of-the-box loop::

    Develop product truth
        -> Build/optimize Shopify storefront
        -> Create one campaign system per product
        -> Generate segment/person/channel variants
        -> Publish through approved channels
        -> Convert through Shopify
        -> Fulfil and support
        -> Observe revenue, attribution, returns and margin
        -> Improve the product, store and campaigns

The existing storefront runner (``gtm_shopify_launch``) deliberately stops at
storefront readiness.  This pack does not extend it; it consumes its
``storefront_ready`` receipt as the precondition for governed publishing.

Every product carries a durable **Product Commercial Identity** joining the
SKU, approved claims with evidence, price and margin, inventory and
fulfilment constraints, the Shopify product and landing binding, SEO
metadata, target audiences with consent basis, the personalization policy,
channel campaigns, and outcome evidence.  Personalization is a reusable
primitive family::

    Product truth + Audience profile + Channel constraints
        -> Personalized content variant -> Approval -> Publication
        -> Outcome evidence -> Next experiment

Consent, platform policy, and approved product claims are explicit inputs;
a model never invents them.  Nothing here persists, calls Shopify or a social
platform directly, or mints approval authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationInfo, field_validator, model_validator

from lightbulb.connector_execution import ConnectorEffect, ConnectorExecutionResult, ConnectorExecutionStatus
from lightbulb.gtm_primitives import FacebookPublishArguments, InstagramPublishArguments, LinkedInPublishArguments
from lightbulb.growth_experiments import ExperimentHypothesis
from lightbulb.primitive_runtime import PrimitiveExecutionContext


PRODUCT_COMMERCE_GOLDEN_LOOP = "commerce.product_truth_to_measured_improvement@0.1.0"
PRODUCT_COMMERCE_ARCHETYPE = "product_commerce"
IDENTITY_SCHEMA = "lightbulb.product_commercial_identity.v1"
VARIANT_SCHEMA = "lightbulb.personalized_content_variant.v1"
PUBLICATION_CANDIDATE_SCHEMA = "lightbulb.channel_publication_candidate.v1"
OUTCOME_EVIDENCE_SCHEMA = "lightbulb.product_outcome_evidence.v1"
BLUEPRINT_SCHEMA = "lightbulb.product_commerce_blueprint.v1"
PLAN_SCHEMA = "lightbulb.product_commerce_loop_plan.v1"
CYCLE_COMMAND_SCHEMA = "lightbulb.product_commerce_cycle_command.v1"
CYCLE_STATE_SCHEMA = "lightbulb.product_commerce_cycle_state.v1"
CYCLE_RESULT_SCHEMA = "lightbulb.product_commerce_cycle_transition_result.v1"
CYCLE_ASSESSMENT_SCHEMA = "lightbulb.product_commerce_cycle_assessment.v1"
GENESIS_DIGEST = "0" * 64
MAX_CYCLE_TRANSITIONS = 40

_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SECRET_LIKE_KEYS = ("secret", "password", "passwd", "token", "api_key", "apikey", "authorization", "credential", "private_key", "client_secret", "tenant_id", "company_id", "user_id", "access_key")
_SECRET_LIKE_VALUES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bshpat_[A-Za-z0-9]{16,}"),
    re.compile(r"\bEAA[A-Za-z0-9]{20,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
)
_MONEY_QUANTUM = Decimal("0.01")

OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=4000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[^\s]{4,1990}$")]

Channel = Literal["facebook", "instagram", "linkedin", "email", "shopify_landing"]
PersonalizationLevel = Literal["segment", "cohort", "individual"]
ConsentBasis = Literal["not_required", "marketing_consent", "contractual", "legitimate_interest"]
FulfilmentMode = Literal["shopify_fulfilment", "third_party_logistics", "dropship", "digital_delivery"]
CampaignObjective = Literal["awareness", "traffic", "conversion", "retention"]
CampaignStatus = Literal["planned", "active", "paused", "ended"]
VariantStatus = Literal["candidate", "approved", "published", "retired"]
StructuredContentType = Literal["Product", "Offer", "FAQPage", "Article"]
PublicationOutcome = Literal["preview", "pending_approval", "completed", "blocked", "failed", "in_doubt"]
BlueprintProfile = Literal["dtc_shopify", "b2b_wholesale", "digital_product", "custom"]
PublishApproval = Literal["human_required", "policy_evaluated"]
LoopStage = Literal["develop_product_truth", "build_storefront", "create_campaign_system", "generate_variants", "publish", "convert", "fulfil_support", "observe", "improve"]
STAGE_ORDER: tuple[str, ...] = ("develop_product_truth", "build_storefront", "create_campaign_system", "generate_variants", "publish", "convert", "fulfil_support", "observe", "improve")
CycleStatus = Literal["opened", "truth_developed", "storefront_ready", "campaign_system_created", "variants_generated", "published", "converting", "fulfilled", "observed", "completed", "withdrawn", "cancelled"]
STATUS_AFTER_STAGE: dict[str, str] = {
    "develop_product_truth": "truth_developed",
    "build_storefront": "storefront_ready",
    "create_campaign_system": "campaign_system_created",
    "generate_variants": "variants_generated",
    "publish": "published",
    "convert": "converting",
    "fulfil_support": "fulfilled",
    "observe": "observed",
    "improve": "completed",
}
STATUS_BEFORE_STAGE: dict[str, str] = {"develop_product_truth": "opened", **{STAGE_ORDER[index]: STATUS_AFTER_STAGE[STAGE_ORDER[index - 1]] for index in range(1, len(STAGE_ORDER))}}
TERMINAL_CYCLE_STATUSES: frozenset[str] = frozenset({"completed", "withdrawn", "cancelled"})
CycleEvent = Literal["complete_stage", "withdraw", "cancel"]
RecoveryDisposition = Literal["not_required", "do_not_replay", "refresh_state", "correct_input", "manual_reconciliation"]

CHANNEL_TOOLS: dict[str, str | None] = {"facebook": "facebook.publish_post", "instagram": "instagram.publish_post", "linkedin": "linkedin.publish_post", "shopify_landing": "shopify.update_page", "email": None}
CHANNEL_PRIMITIVES: dict[str, str] = {"email": "communication.write_email"}
_KNOWN_PRIMITIVE_REFS: frozenset[str] = frozenset(
    {
        "commerce.compile_product_commercial_identity", "commerce.compose_personalized_variant", "commerce.plan_channel_publication", "commerce.advance_product_cycle", "commerce.assess_product_cycle",
        "commerce.plan_shopify_storefront", "gtm.plan_omnichannel_product_launch", "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar",
        "growth.plan_price_move", "growth.build_unit_economics", "growth.review_profit", "growth.build_funnel_snapshot", "growth.compare_funnel_snapshots", "growth.review_customer_value", "growth.build_customer_value",
        "learning.plan_optimization_sweep", "communication.write_email", "documents.generate_business_artifact", "service.intake_and_classify_case", "service.verify_case_resolution", "finance.create_invoice",
    }
)
_KNOWN_CONNECTOR_TOOLS: frozenset[str] = frozenset(
    {
        "ecommerce.create_product", "ecommerce.update_product", "shopify.publish_product", "shopify.verify_product_readiness", "shopify.create_page", "shopify.update_page", "shopify.update_metafield",
        "shopify.analytics_query", "shopify.list_refunds", "shopify.list_fulfillment_orders", "shopify.list_abandoned_checkouts", "shopify.create_discount", "ecommerce.search_orders", "ecommerce.get_inventory",
        "facebook.publish_post", "facebook.fetch_metrics", "instagram.publish_post", "instagram.fetch_metrics", "linkedin.publish_post", "linkedin.fetch_metrics", "google_analytics.fetch_metrics", "hubspot.create_campaign",
    }
)


# --------------------------------------------------------------------------- #
# Strict model and helpers
# --------------------------------------------------------------------------- #


def _reject_secret_like_payload(value: Any, *, path: str = "input") -> None:
    if isinstance(value, str):
        if any(pattern.search(value) for pattern in _SECRET_LIKE_VALUES):
            raise ValueError(f"{path} carries a secret-like value and is never accepted")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_LIKE_KEYS):
                raise ValueError(f"{path}.{key} is a credential- or identity-like field and is never accepted")
            _reject_secret_like_payload(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_like_payload(item, path=f"{path}[{index}]")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, revalidate_instances="always", serialize_by_alias=True, strict=True)

    @model_validator(mode="before")
    @classmethod
    def _portable_payload(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if not isinstance(value, Mapping):
            return value
        _reject_secret_like_payload(value)
        return {str(key): (tuple(item) if isinstance(item, list) else item) for key, item in value.items()}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _detached(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _detached(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached(item) for item in value]
    return value


def _timestamp(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 UTC timestamp ending in Z") from exc
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _decimal(value: Any, *, field_name: str, allow_negative: bool = False) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field_name} must be a decimal string, integer, or Decimal")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a decimal") from exc
    if not parsed.is_finite() or (parsed < 0 and not allow_negative) or abs(parsed) > Decimal("1000000000000"):
        raise ValueError(f"{field_name} must be a finite {'bounded' if allow_negative else 'non-negative bounded'} decimal")
    return parsed.quantize(_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _skip(info: ValidationInfo) -> bool:
    return bool((info.context or {}).get("skip_product_commerce_digests"))


def _sealed_digest(model: type[_StrictModel], payload: Any, field: str) -> str:
    raw = dict(_detached(payload))
    raw.setdefault(field, GENESIS_DIGEST)
    parsed = model.model_validate(raw, context={"skip_product_commerce_digests": True})
    return _stable_digest({key: value for key, value in parsed.to_dict().items() if key != field})


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


# --------------------------------------------------------------------------- #
# Product Commercial Identity
# --------------------------------------------------------------------------- #


class Money(_StrictModel):
    amount: Decimal
    currency: CurrencyCode

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="amount")


class ApprovedClaim(_StrictModel):
    """A product claim that may be used in content only because evidence and an approver back it."""

    claim_id: OpaqueRef
    text: ShortText
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    approved_by_ref: OpaqueRef
    approved_at: str
    expires_at: str | None = None

    @field_validator("approved_at")
    @classmethod
    def _approved(cls, value: str) -> str:
        return _timestamp(value, field_name="approved_at")

    @field_validator("expires_at")
    @classmethod
    def _expires(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="expires_at")

    def valid_at(self, at: str) -> bool:
        moment = _parsed_timestamp(_timestamp(at, field_name="at"))
        return _parsed_timestamp(self.approved_at) <= moment and (self.expires_at is None or moment < _parsed_timestamp(self.expires_at))


class SeoProfile(_StrictModel):
    primary_keyword: ShortText
    secondary_keywords: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    meta_title: Annotated[str, StringConstraints(min_length=1, max_length=60)]
    meta_description: Annotated[str, StringConstraints(min_length=1, max_length=160)]
    structured_content_type: StructuredContentType = "Product"
    canonical_url: HttpsUrl


class InventoryConstraint(_StrictModel):
    available_units: int = Field(ge=0, le=100_000_000)
    fulfilment_mode: FulfilmentMode
    fulfilment_lead_days: int = Field(default=2, ge=0, le=90)
    backorder_allowed: bool = False
    returns_window_days: int = Field(default=30, ge=0, le=365)

    @model_validator(mode="after")
    def _digital_has_no_lead_time(self) -> "InventoryConstraint":
        if self.fulfilment_mode == "digital_delivery" and self.fulfilment_lead_days != 0:
            raise ValueError("digital delivery has no fulfilment lead time")
        return self


class AudienceProfile(_StrictModel):
    audience_ref: OpaqueRef
    level: PersonalizationLevel
    description: ShortText
    consent_basis: ConsentBasis = "not_required"
    consent_evidence_ref: OpaqueRef | None = None
    allowed_channels: tuple[Channel, ...] = Field(min_length=1, max_length=5)
    suppressed: bool = False

    @model_validator(mode="after")
    def _consent_for_individuals(self) -> "AudienceProfile":
        _unique(list(self.allowed_channels), label="allowed channels")
        if self.level == "individual" and (self.consent_basis != "marketing_consent" or self.consent_evidence_ref is None):
            raise ValueError("one-to-one personalization requires marketing consent with a consent evidence reference")
        return self


class PersonalizationPolicy(_StrictModel):
    allowed_levels: tuple[PersonalizationLevel, ...] = Field(default=("segment",), min_length=1, max_length=3)
    approved_claims_only: Literal[True] = True
    individual_requires_consent: Literal[True] = True
    platform_policy_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)

    @model_validator(mode="after")
    def _unique_levels(self) -> "PersonalizationPolicy":
        _unique(list(self.allowed_levels), label="allowed levels")
        return self


class ChannelCampaign(_StrictModel):
    campaign_ref: OpaqueRef
    channel: Channel
    objective: CampaignObjective
    connector_account_ref: OpaqueRef
    monthly_budget: Money | None = None
    status: CampaignStatus = "planned"


class ShopifyBinding(_StrictModel):
    """Link to the Shopify product and its storefront readiness receipt (from gtm_shopify_launch)."""

    connector_account_ref: OpaqueRef
    landing_url: HttpsUrl
    product_id: OpaqueRef | None = None
    publication_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    launch_plan_digest: Sha256Digest | None = None
    storefront_ready: bool = False
    readiness_receipt_digest: Sha256Digest | None = None
    readiness_run_ref: OpaqueRef | None = None

    @model_validator(mode="after")
    def _ready_requires_receipt(self) -> "ShopifyBinding":
        if self.storefront_ready and (self.product_id is None or self.readiness_receipt_digest is None or self.readiness_run_ref is None or not self.publication_ids):
            raise ValueError("storefront readiness requires the product id, publications, and the readiness receipt from the storefront runner")
        return self


class ProductCommercialIdentity(_StrictModel):
    schema_id: Literal["lightbulb.product_commercial_identity.v1"] = Field(default=IDENTITY_SCHEMA, alias="schema")
    product_ref: OpaqueRef
    sku: OpaqueRef
    title: ShortText
    positioning: BoundedText
    price: Money
    unit_cost: Money
    target_margin_percent: Decimal = Field(default=Decimal("40"), validate_default=True)
    approved_claims: tuple[ApprovedClaim, ...] = Field(default_factory=tuple, max_length=50)
    seo: SeoProfile
    inventory: InventoryConstraint
    shopify: ShopifyBinding
    audiences: tuple[AudienceProfile, ...] = Field(min_length=1, max_length=100)
    personalization: PersonalizationPolicy = Field(default_factory=PersonalizationPolicy)
    campaigns: tuple[ChannelCampaign, ...] = Field(default_factory=tuple, max_length=10)
    outcome_evidence_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=100)
    as_of: str
    identity_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_margin_percent", mode="before")
    @classmethod
    def _margin(cls, value: Any) -> Decimal:
        parsed = _decimal(value, field_name="target_margin_percent")
        if parsed > 100:
            raise ValueError("target_margin_percent must be between 0 and 100")
        return parsed

    @field_validator("as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def _identity_is_exact(self, info: ValidationInfo) -> "ProductCommercialIdentity":
        if self.price.currency != self.unit_cost.currency:
            raise ValueError("price and unit cost must share a currency")
        if self.unit_cost.amount >= self.price.amount:
            raise ValueError("unit cost must be below the price")
        _unique([item.claim_id for item in self.approved_claims], label="claim ids")
        _unique([item.audience_ref for item in self.audiences], label="audience refs")
        _unique([item.campaign_ref for item in self.campaigns], label="campaign refs")
        _unique([item.channel for item in self.campaigns], label="campaign channels (one campaign system per product)")
        if self.seo.canonical_url != self.shopify.landing_url:
            raise ValueError("the SEO canonical URL must be the Shopify landing URL")
        if self.gross_margin_percent() < self.target_margin_percent:
            raise ValueError(f"price/cost yields {self.gross_margin_percent()}% gross margin, below the {self.target_margin_percent}% target")
        if _skip(info):
            return self
        if self.identity_digest != _sealed_digest(ProductCommercialIdentity, self, "identity_digest"):
            raise ValueError("identity_digest must commit the exact identity")
        return self

    def gross_margin_percent(self) -> Decimal:
        return ((self.price.amount - self.unit_cost.amount) / self.price.amount * Decimal(100)).quantize(_MONEY_QUANTUM)

    def claim(self, claim_id: str) -> ApprovedClaim | None:
        return next((item for item in self.approved_claims if item.claim_id == claim_id), None)

    def audience(self, audience_ref: str) -> AudienceProfile | None:
        return next((item for item in self.audiences if item.audience_ref == audience_ref), None)

    def campaign_for(self, channel: str) -> ChannelCampaign | None:
        return next((item for item in self.campaigns if item.channel == channel), None)


def compile_product_commercial_identity(identity: Mapping[str, Any]) -> ProductCommercialIdentity:
    raw = dict(_detached(identity))
    raw["identity_digest"] = _sealed_digest(ProductCommercialIdentity, raw, "identity_digest")
    return ProductCommercialIdentity.model_validate(raw)


def bind_storefront_readiness(identity: ProductCommercialIdentity | Mapping[str, Any], launch_result: Mapping[str, Any]) -> ProductCommercialIdentity:
    """Adopt a ``ShopifyLaunchRunResult`` into the identity; only a ``storefront_ready`` result binds."""

    parsed = ProductCommercialIdentity.model_validate(_detached(identity))
    result = dict(_detached(launch_result))
    if result.get("status") != "storefront_ready" or not result.get("storefront_ready") or result.get("omnichannel_launch_completed") is not False:
        raise ValueError("only a storefront_ready launch result binds; the storefront runner has not proven readiness")
    if not result.get("product_id") or not result.get("publication_ids") or not result.get("run_ref") or not result.get("plan_digest"):
        raise ValueError("launch result must carry product id, publication ids, run ref, and plan digest")
    receipts = list(result.get("receipts", ()))
    readiness = next((item for item in receipts if str(item.get("receipt_kind", "")).startswith("landing") or str(item.get("evidence_kind", "")).startswith("landing")), receipts[-1] if receipts else None)
    if readiness is None:
        raise ValueError("launch result carries no readiness receipt")
    receipt_digest = readiness.get("receipt_digest") or readiness.get("evidence_digest")
    if not isinstance(receipt_digest, str) or not re.fullmatch(_SHA256_PATTERN, receipt_digest):
        raise ValueError("readiness receipt digest must be a sha256 hex digest")
    shopify = {**parsed.shopify.to_dict(), "product_id": str(result["product_id"]), "publication_ids": [str(item) for item in result["publication_ids"]], "launch_plan_digest": str(result["plan_digest"]), "storefront_ready": True, "readiness_receipt_digest": receipt_digest, "readiness_run_ref": str(result["run_ref"])}
    return compile_product_commercial_identity({**parsed.to_dict(), "shopify": shopify, "identity_digest": GENESIS_DIGEST})


# --------------------------------------------------------------------------- #
# Personalization primitive family
# --------------------------------------------------------------------------- #


class ChannelConstraints(_StrictModel):
    channel: Channel
    max_chars: int = Field(ge=20, le=20_000)
    image_required: bool = False
    link_required: bool = True
    platform_policy_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    prohibited_terms: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=100)


DEFAULT_CHANNEL_CONSTRAINTS: dict[str, dict[str, Any]] = {
    "facebook": {"channel": "facebook", "max_chars": 2000, "image_required": False, "link_required": True},
    "instagram": {"channel": "instagram", "max_chars": 2200, "image_required": True, "link_required": False},
    "linkedin": {"channel": "linkedin", "max_chars": 3000, "image_required": False, "link_required": True},
    "email": {"channel": "email", "max_chars": 8000, "image_required": False, "link_required": True},
    "shopify_landing": {"channel": "shopify_landing", "max_chars": 20000, "image_required": False, "link_required": False},
}


class PersonalizationBrief(_StrictModel):
    identity_digest: Sha256Digest
    audience_ref: OpaqueRef
    channel: Channel
    level: PersonalizationLevel
    objective: CampaignObjective
    claim_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    experiment_ref: OpaqueRef | None = None


class ContentVariant(_StrictModel):
    schema_id: Literal["lightbulb.personalized_content_variant.v1"] = Field(default=VARIANT_SCHEMA, alias="schema")
    variant_ref: OpaqueRef
    identity_digest: Sha256Digest
    audience_ref: OpaqueRef
    channel: Channel
    level: PersonalizationLevel
    objective: CampaignObjective
    headline: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    body: BoundedText
    image_url: HttpsUrl | None = None
    landing_url: HttpsUrl
    claim_ids: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)
    experiment_ref: OpaqueRef | None = None
    status: VariantStatus = "candidate"
    approval_ref: OpaqueRef | None = None
    composed_at: str
    variant_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("composed_at")
    @classmethod
    def _composed(cls, value: str) -> str:
        return _timestamp(value, field_name="composed_at")

    @model_validator(mode="after")
    def _variant_is_exact(self, info: ValidationInfo) -> "ContentVariant":
        if self.status in {"approved", "published"} and self.approval_ref is None:
            raise ValueError("approved and published variants carry their approval reference")
        if _skip(info):
            return self
        if self.variant_digest != _sealed_digest(ContentVariant, self, "variant_digest"):
            raise ValueError("variant_digest must commit the exact variant")
        return self


class PolicyFinding(_StrictModel):
    code: Annotated[str, StringConstraints(min_length=1, max_length=80)]
    message: ShortText


class VariantComposition(_StrictModel):
    status: Literal["candidate", "blocked"]
    variant: ContentVariant | None = None
    findings: tuple[PolicyFinding, ...] = Field(default_factory=tuple, max_length=20)

    @model_validator(mode="after")
    def _coherent(self) -> "VariantComposition":
        if (self.status == "candidate") != (self.variant is not None and not self.findings):
            raise ValueError("a candidate composition carries a variant and no findings")
        return self


def _seal_variant(payload: Mapping[str, Any]) -> ContentVariant:
    raw = dict(_detached(payload))
    raw["variant_digest"] = _sealed_digest(ContentVariant, raw, "variant_digest")
    return ContentVariant.model_validate(raw)


def compose_personalized_variant(identity: ProductCommercialIdentity | Mapping[str, Any], brief: PersonalizationBrief | Mapping[str, Any], *, headline: str, body: str, variant_ref: str, composed_at: str, image_url: str | None = None, constraints: ChannelConstraints | Mapping[str, Any] | None = None) -> VariantComposition:
    """Product truth + audience profile + channel constraints -> a policy-checked content variant candidate."""

    parsed = ProductCommercialIdentity.model_validate(_detached(identity))
    parsed_brief = PersonalizationBrief.model_validate(_detached(brief))
    limits = ChannelConstraints.model_validate(_detached(constraints) if constraints is not None else DEFAULT_CHANNEL_CONSTRAINTS[parsed_brief.channel])
    findings: list[dict[str, str]] = []
    if parsed_brief.identity_digest != parsed.identity_digest:
        findings.append({"code": "IDENTITY_MISMATCH", "message": "the brief references a different product identity"})
    if limits.channel != parsed_brief.channel:
        findings.append({"code": "CHANNEL_CONSTRAINTS_MISMATCH", "message": "channel constraints belong to another channel"})
    audience = parsed.audience(parsed_brief.audience_ref)
    if audience is None:
        findings.append({"code": "AUDIENCE_UNKNOWN", "message": "the audience is not part of the product identity"})
    else:
        if audience.suppressed:
            findings.append({"code": "AUDIENCE_SUPPRESSED", "message": "the audience is suppressed"})
        if audience.level != parsed_brief.level:
            findings.append({"code": "LEVEL_MISMATCH", "message": f"audience is a {audience.level} profile; brief asks for {parsed_brief.level}"})
        if parsed_brief.channel not in audience.allowed_channels:
            findings.append({"code": "CHANNEL_NOT_ALLOWED_FOR_AUDIENCE", "message": f"{parsed_brief.channel} is not an allowed channel for this audience"})
        if parsed_brief.level == "individual" and (audience.consent_basis != "marketing_consent" or audience.consent_evidence_ref is None):
            findings.append({"code": "CONSENT_MISSING", "message": "one-to-one personalization requires marketing consent evidence"})
    if parsed_brief.level not in parsed.personalization.allowed_levels:
        findings.append({"code": "LEVEL_NOT_IN_POLICY", "message": f"the personalization policy does not allow {parsed_brief.level} personalization"})
    if parsed.campaign_for(parsed_brief.channel) is None:
        findings.append({"code": "CAMPAIGN_MISSING", "message": f"no campaign system exists for {parsed_brief.channel}"})
    for claim_id in parsed_brief.claim_ids:
        claim = parsed.claim(claim_id)
        if claim is None:
            findings.append({"code": "CLAIM_NOT_APPROVED", "message": f"claim {claim_id} is not an approved product claim"})
        elif not claim.valid_at(composed_at):
            findings.append({"code": "CLAIM_EXPIRED", "message": f"claim {claim_id} is outside its approval window"})
    text = f"{headline}\n{body}".lower()
    for term in (*parsed.personalization.prohibited_terms, *limits.prohibited_terms):
        if term.lower() in text:
            findings.append({"code": "PROHIBITED_TERM", "message": f"content uses the prohibited term {term!r}"})
    if len(body) > limits.max_chars:
        findings.append({"code": "BODY_TOO_LONG", "message": f"body exceeds {limits.max_chars} characters for {parsed_brief.channel}"})
    if limits.image_required and image_url is None:
        findings.append({"code": "IMAGE_REQUIRED", "message": f"{parsed_brief.channel} requires an image"})
    if limits.link_required and parsed.shopify.landing_url not in body:
        findings.append({"code": "LANDING_LINK_REQUIRED", "message": "the body must carry the product landing URL"})
    if findings:
        return VariantComposition(status="blocked", findings=[PolicyFinding.model_validate(item) for item in findings])
    variant = _seal_variant({"variant_ref": variant_ref, "identity_digest": parsed.identity_digest, "audience_ref": parsed_brief.audience_ref, "channel": parsed_brief.channel, "level": parsed_brief.level, "objective": parsed_brief.objective, "headline": headline, "body": body, "image_url": image_url, "landing_url": parsed.shopify.landing_url, "claim_ids": list(parsed_brief.claim_ids), "experiment_ref": parsed_brief.experiment_ref, "status": "candidate", "composed_at": composed_at})
    return VariantComposition(status="candidate", variant=variant)


def approve_variant(variant: ContentVariant | Mapping[str, Any], *, approval_ref: str) -> ContentVariant:
    parsed = ContentVariant.model_validate(_detached(variant))
    if parsed.status != "candidate":
        raise ValueError(f"only candidate variants can be approved; this one is {parsed.status}")
    return _seal_variant({**parsed.to_dict(), "status": "approved", "approval_ref": approval_ref, "variant_digest": GENESIS_DIGEST})


class PublicationCandidate(_StrictModel):
    schema_id: Literal["lightbulb.channel_publication_candidate.v1"] = Field(default=PUBLICATION_CANDIDATE_SCHEMA, alias="schema")
    candidate_ref: OpaqueRef
    identity_digest: Sha256Digest
    variant_digest: Sha256Digest
    channel: Channel
    connector_tool: ShortText | None = None
    primitive_ref: ShortText | None = None
    connector_account_ref: OpaqueRef
    arguments: dict[str, Any]
    readiness_receipt_digest: Sha256Digest
    approval_ref: OpaqueRef
    effect: Literal["write"] = "write"
    candidate_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _candidate_is_exact(self, info: ValidationInfo) -> "PublicationCandidate":
        if (self.connector_tool is None) == (self.primitive_ref is None):
            raise ValueError("a publication targets exactly one connector tool or one primitive")
        if self.connector_tool is not None and self.connector_tool not in _KNOWN_CONNECTOR_TOOLS:
            raise ValueError(f"unknown connector tool {self.connector_tool}")
        if _skip(info):
            return self
        if self.candidate_digest != _sealed_digest(PublicationCandidate, self, "candidate_digest"):
            raise ValueError("candidate_digest must commit the exact candidate")
        return self


def plan_channel_publication(identity: ProductCommercialIdentity | Mapping[str, Any], variant: ContentVariant | Mapping[str, Any], *, candidate_ref: str, target_ref: str) -> PublicationCandidate:
    """Shape an approved variant into the exact connector arguments; requires the storefront readiness receipt."""

    parsed = ProductCommercialIdentity.model_validate(_detached(identity))
    parsed_variant = ContentVariant.model_validate(_detached(variant))
    if parsed_variant.identity_digest != parsed.identity_digest:
        raise ValueError("variant belongs to a different product identity")
    if parsed_variant.status != "approved" or parsed_variant.approval_ref is None:
        raise ValueError("only an approved variant can be planned for publication")
    if not parsed.shopify.storefront_ready or parsed.shopify.readiness_receipt_digest is None:
        raise ValueError("publication is held until the storefront runner proves readiness")
    campaign = parsed.campaign_for(parsed_variant.channel)
    if campaign is None or campaign.status not in {"planned", "active"}:
        raise ValueError(f"no planned or active campaign system for {parsed_variant.channel}")
    channel = parsed_variant.channel
    message = f"{parsed_variant.headline}\n\n{parsed_variant.body}"
    if channel == "facebook":
        arguments = FacebookPublishArguments(kind="facebook_publish", page_id=target_ref, message=message, image_url=parsed_variant.image_url).model_dump(mode="json", exclude_none=True)
    elif channel == "instagram":
        if parsed_variant.image_url is None:
            raise ValueError("instagram publication requires an image")
        arguments = InstagramPublishArguments(kind="instagram_publish", instagram_business_account_id=target_ref, caption=message, image_url=parsed_variant.image_url).model_dump(mode="json", exclude_none=True)
    elif channel == "linkedin":
        arguments = LinkedInPublishArguments(kind="linkedin_publish", author_urn=target_ref, text=message[:3000], url=parsed_variant.landing_url, image_url=parsed_variant.image_url).model_dump(mode="json", exclude_none=True)
    elif channel == "shopify_landing":
        arguments = {"kind": "shopify_page_update", "page_id": target_ref, "title": parsed_variant.headline, "body_html": parsed_variant.body, "seo": {"title": parsed.seo.meta_title, "description": parsed.seo.meta_description}}
    else:
        arguments = {"kind": "email_campaign", "audience_ref": parsed_variant.audience_ref, "list_ref": target_ref, "subject": parsed_variant.headline, "body": parsed_variant.body, "landing_url": parsed_variant.landing_url}
    payload = {"candidate_ref": candidate_ref, "identity_digest": parsed.identity_digest, "variant_digest": parsed_variant.variant_digest, "channel": channel, "connector_tool": CHANNEL_TOOLS[channel], "primitive_ref": CHANNEL_PRIMITIVES.get(channel), "connector_account_ref": campaign.connector_account_ref, "arguments": arguments, "readiness_receipt_digest": parsed.shopify.readiness_receipt_digest, "approval_ref": parsed_variant.approval_ref}
    payload["candidate_digest"] = _sealed_digest(PublicationCandidate, payload, "candidate_digest")
    return PublicationCandidate.model_validate(payload)


class PublicationReceipt(_StrictModel):
    candidate_digest: Sha256Digest
    channel: Channel
    tool: ShortText
    outcome: PublicationOutcome
    approval_ref: OpaqueRef | None = None
    external_ref: OpaqueRef | None = None
    recovery_locator: str | None = None
    message: BoundedText | None = None
    published_at: str

    @field_validator("published_at")
    @classmethod
    def _published(cls, value: str) -> str:
        return _timestamp(value, field_name="published_at")

    @model_validator(mode="after")
    def _completed_requires_authority(self) -> "PublicationReceipt":
        if self.outcome == "completed" and (self.approval_ref is None or self.external_ref is None):
            raise ValueError("a completed publication carries its approval reference and the platform post reference")
        return self


class ChannelPublishingPort(Protocol):
    def publish(self, candidate: PublicationCandidate, context: PrimitiveExecutionContext, *, at: str) -> PublicationReceipt: ...


class ConnectorChannelPublishingAdapter:
    """The one real adapter: every publication goes through the governed connector Tools via the Connector Runtime."""

    primitive_ref = "commerce.plan_channel_publication"

    def publish(self, candidate: PublicationCandidate, context: PrimitiveExecutionContext, *, at: str) -> PublicationReceipt:
        parsed = PublicationCandidate.model_validate(_detached(candidate))
        if parsed.connector_tool is None:
            return PublicationReceipt(candidate_digest=parsed.candidate_digest, channel=parsed.channel, tool=str(parsed.primitive_ref), outcome="preview", approval_ref=parsed.approval_ref, message="email publication is proposed through the communication primitive, not a connector", published_at=at)
        request = context.connector_request(primitive_ref=self.primitive_ref, tool=parsed.connector_tool, arguments=dict(parsed.arguments), effect=ConnectorEffect.WRITE, approval_required=True, operation_ref=parsed.candidate_ref, connector_account_ref=parsed.connector_account_ref, metadata={"golden_loop": PRODUCT_COMMERCE_GOLDEN_LOOP, "variant_digest": parsed.variant_digest, "readiness_receipt_digest": parsed.readiness_receipt_digest})
        result: ConnectorExecutionResult = context.connectors.execute(request)
        outcome: str = {ConnectorExecutionStatus.COMPLETED: "completed", ConnectorExecutionStatus.PREVIEW: "preview", ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval", ConnectorExecutionStatus.BLOCKED: "blocked", ConnectorExecutionStatus.FAILED: "failed"}[result.status]
        if getattr(result, "unverified_recovery_journal_locator", None) is not None or result.error_code == "GOVERNED_EXECUTION_AMBIGUOUS":
            outcome = "in_doubt"
        external = None
        for key in ("id", "post_id", "page_id", "url", "permalink"):
            value = result.output.get(key)
            if value not in (None, "") and re.fullmatch(_REF_PATTERN, str(value)):
                external = str(value)
                break
        return PublicationReceipt(candidate_digest=parsed.candidate_digest, channel=parsed.channel, tool=parsed.connector_tool, outcome=outcome, approval_ref=result.approval_ref or (parsed.approval_ref if outcome == "completed" else None), external_ref=external, recovery_locator=getattr(result, "unverified_recovery_journal_locator", None), message=(result.message[:4000] if result.message else None), published_at=at)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Outcome evidence
# --------------------------------------------------------------------------- #


class ChannelMetrics(_StrictModel):
    channel: Channel
    impressions: int = Field(default=0, ge=0)
    clicks: int = Field(default=0, ge=0)
    ad_spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    attributed_orders: int = Field(default=0, ge=0)
    attributed_revenue: Decimal = Field(default=Decimal("0"), validate_default=True)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("ad_spend", "attributed_revenue", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class OutcomeEvidence(_StrictModel):
    schema_id: Literal["lightbulb.product_outcome_evidence.v1"] = Field(default=OUTCOME_EVIDENCE_SCHEMA, alias="schema")
    identity_digest: Sha256Digest
    currency: CurrencyCode
    window_start: str
    window_end: str
    orders: int = Field(ge=0)
    units_sold: int = Field(ge=0)
    gross_revenue: Decimal
    refunds: Decimal = Field(default=Decimal("0"), validate_default=True)
    returned_units: int = Field(default=0, ge=0)
    cogs: Decimal = Field(default=Decimal("0"), validate_default=True)
    fulfilment_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    channels: tuple[ChannelMetrics, ...] = Field(default_factory=tuple, max_length=5)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=50)
    evidence_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("gross_revenue", "refunds", "cogs", "fulfilment_cost", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("window_start", "window_end")
    @classmethod
    def _window(cls, value: str, info: ValidationInfo) -> str:
        return _timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _evidence_is_exact(self, info: ValidationInfo) -> "OutcomeEvidence":
        if _parsed_timestamp(self.window_end) <= _parsed_timestamp(self.window_start):
            raise ValueError("the evidence window must end after it starts")
        if self.returned_units > self.units_sold or self.refunds > self.gross_revenue:
            raise ValueError("returns and refunds cannot exceed what was sold")
        _unique([item.channel for item in self.channels], label="channel metrics")
        if sum(item.attributed_orders for item in self.channels) > self.orders:
            raise ValueError("attributed orders cannot exceed total orders")
        if _skip(info):
            return self
        if self.evidence_digest != _sealed_digest(OutcomeEvidence, self, "evidence_digest"):
            raise ValueError("evidence_digest must commit the exact evidence")
        return self

    def net_revenue(self) -> Decimal:
        return (self.gross_revenue - self.refunds).quantize(_MONEY_QUANTUM)

    def ad_spend(self) -> Decimal:
        return sum((item.ad_spend for item in self.channels), Decimal("0")).quantize(_MONEY_QUANTUM)

    def contribution(self) -> Decimal:
        return (self.net_revenue() - self.cogs - self.fulfilment_cost - self.ad_spend()).quantize(_MONEY_QUANTUM)


def seal_outcome_evidence(evidence: Mapping[str, Any]) -> OutcomeEvidence:
    raw = dict(_detached(evidence))
    raw["evidence_digest"] = _sealed_digest(OutcomeEvidence, raw, "evidence_digest")
    return OutcomeEvidence.model_validate(raw)


# --------------------------------------------------------------------------- #
# Blueprint and plan
# --------------------------------------------------------------------------- #


class ProductCommerceBlueprint(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_blueprint.v1"] = Field(default=BLUEPRINT_SCHEMA, alias="schema")
    profile: BlueprintProfile
    name: ShortText
    channels: tuple[Channel, ...] = Field(min_length=1, max_length=5)
    personalization_levels: tuple[PersonalizationLevel, ...] = Field(default=("segment",), min_length=1, max_length=3)
    fulfilment_mode: FulfilmentMode
    returns_window_days: int = Field(default=30, ge=0, le=365)
    target_contribution_margin_percent: Decimal = Field(default=Decimal("25"), validate_default=True)
    minimum_roas: Decimal = Field(default=Decimal("2"), validate_default=True)
    publish_approval: PublishApproval = "human_required"
    currency: CurrencyCode = "USD"
    notes: BoundedText | None = None
    blueprint_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("target_contribution_margin_percent", "minimum_roas", mode="before")
    @classmethod
    def _ratios(cls, value: Any, info: ValidationInfo) -> Decimal:
        parsed = _decimal(value, field_name=str(info.field_name))
        if info.field_name == "target_contribution_margin_percent" and parsed > 100:
            raise ValueError("target_contribution_margin_percent must be between 0 and 100")
        return parsed

    @model_validator(mode="after")
    def _blueprint_is_exact(self, info: ValidationInfo) -> "ProductCommerceBlueprint":
        _unique(list(self.channels), label="channels")
        _unique(list(self.personalization_levels), label="personalization levels")
        if self.fulfilment_mode == "digital_delivery" and self.returns_window_days > 30:
            raise ValueError("digital products keep a returns window of 30 days or fewer")
        if _skip(info):
            return self
        if self.blueprint_digest != _sealed_digest(ProductCommerceBlueprint, self, "blueprint_digest"):
            raise ValueError("blueprint_digest must commit the exact blueprint")
        return self


def seal_product_commerce_blueprint(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(blueprint))
    raw["blueprint_digest"] = _sealed_digest(ProductCommerceBlueprint, raw, "blueprint_digest")
    return ProductCommerceBlueprint.model_validate(raw).to_dict()


PRODUCT_COMMERCE_PROFILES: dict[str, dict[str, Any]] = {
    "dtc_shopify": {"profile": "dtc_shopify", "name": "Direct-to-consumer Shopify brand", "channels": ["shopify_landing", "instagram", "facebook", "email"], "personalization_levels": ["segment", "cohort"], "fulfilment_mode": "shopify_fulfilment", "returns_window_days": 30, "target_contribution_margin_percent": "25", "minimum_roas": "2.5", "publish_approval": "human_required", "notes": "Physical goods sold through Shopify checkout; social plus email campaigns per product."},
    "b2b_wholesale": {"profile": "b2b_wholesale", "name": "B2B wholesale product line", "channels": ["shopify_landing", "linkedin", "email"], "personalization_levels": ["segment", "cohort", "individual"], "fulfilment_mode": "third_party_logistics", "returns_window_days": 14, "target_contribution_margin_percent": "30", "minimum_roas": "3", "publish_approval": "human_required", "notes": "Wholesale terms; one-to-one outreach only with consent evidence."},
    "digital_product": {"profile": "digital_product", "name": "Digital product or template", "channels": ["shopify_landing", "email", "linkedin"], "personalization_levels": ["segment"], "fulfilment_mode": "digital_delivery", "returns_window_days": 14, "target_contribution_margin_percent": "60", "minimum_roas": "4", "publish_approval": "policy_evaluated", "notes": "Instant provisioning; refunds inside a short window."},
}


class StageBinding(_StrictModel):
    stage: LoopStage
    title: ShortText
    primitive_refs: tuple[ShortText, ...] = Field(min_length=1, max_length=12)
    connector_tools: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=12)
    gate: Literal["none", "spring_approval", "human_approval", "readiness_receipt"] = "none"

    @model_validator(mode="after")
    def _bound_to_known(self) -> "StageBinding":
        unknown = [ref for ref in self.primitive_refs if ref not in _KNOWN_PRIMITIVE_REFS]
        if unknown:
            raise ValueError(f"stage {self.stage} binds unknown primitives: {unknown}")
        unknown_tools = [tool for tool in self.connector_tools if tool not in _KNOWN_CONNECTOR_TOOLS]
        if unknown_tools:
            raise ValueError(f"stage {self.stage} binds unknown connector tools: {unknown_tools}")
        return self


class ProductCommerceLoopPlan(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_loop_plan.v1"] = Field(default=PLAN_SCHEMA, alias="schema")
    golden_loop: Literal["commerce.product_truth_to_measured_improvement@0.1.0"] = PRODUCT_COMMERCE_GOLDEN_LOOP
    archetype: Literal["product_commerce"] = PRODUCT_COMMERCE_ARCHETYPE
    blueprint: ProductCommerceBlueprint
    stages: tuple[StageBinding, ...] = Field(min_length=9, max_length=9)
    storefront_runner: Literal["lightbulb.gtm_shopify_launch.run_shopify_product_launch"] = "lightbulb.gtm_shopify_launch.run_shopify_product_launch"
    publishing_requires_readiness_receipt: Literal[True] = True
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @model_validator(mode="after")
    def _plan_is_exact(self, info: ValidationInfo) -> "ProductCommerceLoopPlan":
        if tuple(item.stage for item in self.stages) != STAGE_ORDER:
            raise ValueError("plan stages must follow the loop order exactly")
        if _skip(info):
            return self
        if self.plan_digest != _sealed_digest(ProductCommerceLoopPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self

    def stage(self, name: str) -> StageBinding:
        return next(item for item in self.stages if item.stage == name)


def _publish_tools(blueprint: ProductCommerceBlueprint) -> tuple[str, ...]:
    return tuple(tool for tool in (CHANNEL_TOOLS[channel] for channel in blueprint.channels) if tool is not None)


def _metric_tools(blueprint: ProductCommerceBlueprint) -> tuple[str, ...]:
    tools = ["shopify.analytics_query", "ecommerce.search_orders", "shopify.list_refunds", "google_analytics.fetch_metrics"]
    tools.extend(f"{channel}.fetch_metrics" for channel in blueprint.channels if channel in {"facebook", "instagram", "linkedin"})
    return tuple(tools)


def _stage_bindings(blueprint: ProductCommerceBlueprint) -> list[dict[str, Any]]:
    publish_primitives: tuple[str, ...] = ("commerce.plan_channel_publication",) + (("communication.write_email",) if "email" in blueprint.channels else ())
    return [
        {"stage": "develop_product_truth", "title": "Develop product truth", "primitive_refs": ("commerce.compile_product_commercial_identity", "growth.build_unit_economics", "growth.plan_price_move"), "connector_tools": ("ecommerce.get_inventory",), "gate": "none"},
        {"stage": "build_storefront", "title": "Build or optimize the Shopify storefront", "primitive_refs": ("commerce.plan_shopify_storefront", "gtm.plan_omnichannel_product_launch"), "connector_tools": ("ecommerce.create_product", "ecommerce.update_product", "shopify.publish_product", "shopify.verify_product_readiness", "shopify.create_page", "shopify.update_page", "shopify.update_metafield"), "gate": "readiness_receipt"},
        {"stage": "create_campaign_system", "title": "Create one campaign system per product", "primitive_refs": ("gtm.plan_omnichannel_product_launch", "demand_gen.plan_audience_growth", "demand_gen.plan_content_calendar"), "connector_tools": ("hubspot.create_campaign",) if "email" in blueprint.channels else (), "gate": "spring_approval"},
        {"stage": "generate_variants", "title": "Generate segment, cohort, and person variants per channel", "primitive_refs": ("commerce.compose_personalized_variant", "documents.generate_business_artifact"), "gate": "human_approval" if blueprint.publish_approval == "human_required" else "spring_approval"},
        {"stage": "publish", "title": "Publish through approved channels", "primitive_refs": publish_primitives, "connector_tools": _publish_tools(blueprint), "gate": "readiness_receipt"},
        {"stage": "convert", "title": "Convert through Shopify checkout", "primitive_refs": ("growth.build_funnel_snapshot",), "connector_tools": ("ecommerce.search_orders", "shopify.list_abandoned_checkouts", "shopify.create_discount"), "gate": "none"},
        {"stage": "fulfil_support", "title": "Fulfil, support, and handle returns", "primitive_refs": ("service.intake_and_classify_case", "service.verify_case_resolution"), "connector_tools": ("shopify.list_fulfillment_orders", "shopify.list_refunds"), "gate": "spring_approval"},
        {"stage": "observe", "title": "Observe revenue, attribution, returns, and margin", "primitive_refs": ("growth.build_unit_economics", "growth.review_profit", "growth.compare_funnel_snapshots", "growth.review_customer_value"), "connector_tools": _metric_tools(blueprint), "gate": "none"},
        {"stage": "improve", "title": "Improve the product, store, and campaigns", "primitive_refs": ("learning.plan_optimization_sweep", "growth.plan_price_move", "commerce.compose_personalized_variant"), "gate": "none"},
    ]


def compile_product_commerce_blueprint(profile: str | Mapping[str, Any], overrides: Mapping[str, Any] | None = None) -> ProductCommerceLoopPlan:
    if isinstance(profile, str):
        if profile not in PRODUCT_COMMERCE_PROFILES:
            raise ValueError(f"unknown product commerce profile {profile!r}; choose one of {sorted(PRODUCT_COMMERCE_PROFILES)} or pass a custom blueprint")
        raw: dict[str, Any] = json.loads(json.dumps(PRODUCT_COMMERCE_PROFILES[profile]))
    else:
        raw = dict(_detached(profile))
    for key, value in dict(overrides or {}).items():
        if key in {"schema", "blueprint_digest"}:
            raise ValueError("overrides cannot set schema or digest fields")
        raw[key] = value
    blueprint = ProductCommerceBlueprint.model_validate(seal_product_commerce_blueprint(raw))
    payload = {"blueprint": blueprint.to_dict(), "stages": _stage_bindings(blueprint)}
    payload["plan_digest"] = _sealed_digest(ProductCommerceLoopPlan, payload, "plan_digest")
    return ProductCommerceLoopPlan.model_validate(payload)


# --------------------------------------------------------------------------- #
# Cycle
# --------------------------------------------------------------------------- #


class ProductCommerceScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: str
    cycle_ref: OpaqueRef
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


class StageReceipt(_StrictModel):
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)
    identity_digest: Sha256Digest | None = None
    approved_claim_count: int | None = Field(default=None, ge=0, le=50)
    storefront_status: ShortText | None = None
    storefront_run_ref: OpaqueRef | None = None
    readiness_receipt_digest: Sha256Digest | None = None
    product_id: OpaqueRef | None = None
    campaign_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=10)
    campaign_channels: tuple[Channel, ...] = Field(default_factory=tuple, max_length=5)
    variant_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=200)
    variant_levels: tuple[PersonalizationLevel, ...] = Field(default_factory=tuple, max_length=200)
    publication_candidate_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=200)
    publication_external_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    publication_approval_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    publication_outcomes: tuple[PublicationOutcome, ...] = Field(default_factory=tuple, max_length=200)
    orders: int | None = Field(default=None, ge=0)
    units_sold: int | None = Field(default=None, ge=0)
    gross_revenue: Decimal | None = None
    fulfilment_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    support_case_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    return_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)
    outcome_evidence_digest: Sha256Digest | None = None
    refunds: Decimal | None = None
    returned_units: int | None = Field(default=None, ge=0)
    ad_spend: Decimal | None = None
    cogs: Decimal | None = None
    fulfilment_cost: Decimal | None = None
    learning_entry_digest: Sha256Digest | None = None
    next_experiment_ref: OpaqueRef | None = None
    improvement_actions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("gross_revenue", "refunds", "ad_spend", "cogs", "fulfilment_cost", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name))


class ProductCommerceCycleCommand(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_cycle_command.v1"] = Field(default=CYCLE_COMMAND_SCHEMA, alias="schema")
    event: CycleEvent
    stage: LoopStage | None = None
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_CYCLE_TRANSITIONS)
    expected_state_digest: Sha256Digest
    occurred_at: str
    actor_ref: OpaqueRef
    receipt: StageReceipt | None = None
    reason: BoundedText | None = None
    request_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("occurred_at")
    @classmethod
    def _occurred(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _command_is_exact(self, info: ValidationInfo) -> "ProductCommerceCycleCommand":
        if (self.event == "complete_stage") != (self.stage is not None):
            raise ValueError("complete_stage names a stage; withdraw and cancel do not")
        if self.event != "complete_stage" and self.reason is None:
            raise ValueError("withdraw and cancel require a reason")
        if self.event == "complete_stage" and self.receipt is None:
            raise ValueError("completing a stage requires a stage receipt")
        if _skip(info):
            return self
        if self.request_digest != cycle_command_digest(self):
            raise ValueError("request_digest must commit the exact normalized command")
        return self


def cycle_command_digest(command: ProductCommerceCycleCommand | Mapping[str, Any]) -> str:
    return _sealed_digest(ProductCommerceCycleCommand, command, "request_digest")


def seal_cycle_command(command: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(_detached(command))
    raw["request_digest"] = cycle_command_digest(raw)
    return ProductCommerceCycleCommand.model_validate(raw).to_dict()


class CycleLedger(_StrictModel):
    identity_digest: Sha256Digest | None = None
    approved_claim_count: int = Field(default=0, ge=0)
    readiness_receipt_digest: Sha256Digest | None = None
    product_id: OpaqueRef | None = None
    campaign_channels: tuple[Channel, ...] = Field(default_factory=tuple, max_length=5)
    variant_count: int = Field(default=0, ge=0)
    variant_levels: tuple[PersonalizationLevel, ...] = Field(default_factory=tuple, max_length=3)
    publication_count: int = Field(default=0, ge=0)
    orders: int = Field(default=0, ge=0)
    units_sold: int = Field(default=0, ge=0)
    gross_revenue: Decimal = Field(default=Decimal("0"), validate_default=True)
    refunds: Decimal = Field(default=Decimal("0"), validate_default=True)
    returned_units: int = Field(default=0, ge=0)
    ad_spend: Decimal = Field(default=Decimal("0"), validate_default=True)
    cogs: Decimal = Field(default=Decimal("0"), validate_default=True)
    fulfilment_cost: Decimal = Field(default=Decimal("0"), validate_default=True)
    support_cases: int = Field(default=0, ge=0)
    outcome_evidence_digest: Sha256Digest | None = None
    learning_entry_digest: Sha256Digest | None = None
    next_experiment_ref: OpaqueRef | None = None
    improvement_actions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("gross_revenue", "refunds", "ad_spend", "cogs", "fulfilment_cost", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))


class CycleTransition(_StrictModel):
    to_version: int = Field(ge=1, le=MAX_CYCLE_TRANSITIONS)
    prior_state_digest: Sha256Digest
    to_status: CycleStatus
    transition_digest: Sha256Digest
    command: ProductCommerceCycleCommand

    @model_validator(mode="after")
    def _self_proving(self) -> "CycleTransition":
        if self.command.expected_version != self.to_version - 1 or self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("transition must match the command's revision and state fences")
        if self.transition_digest != _transition_digest(self.to_version, self.prior_state_digest, self.to_status, self.command):
            raise ValueError("transition digest must commit the exact transition")
        return self


def _transition_digest(to_version: int, prior: str, to_status: str, command: ProductCommerceCycleCommand) -> str:
    return _stable_digest({"to_version": to_version, "prior_state_digest": prior, "to_status": to_status, "request_digest": command.request_digest, "transition_ref": command.transition_ref, "idempotency_key": command.idempotency_key})


def _state_digest(plan_digest: str, scope: ProductCommerceScope, history: Sequence[CycleTransition]) -> str:
    return _stable_digest({"plan_digest": plan_digest, "scope": scope.to_dict(), "transitions": [item.transition_digest for item in history]})


def genesis_cycle_state_digest(plan_digest: str, scope: ProductCommerceScope | Mapping[str, Any]) -> str:
    return _state_digest(plan_digest, ProductCommerceScope.model_validate(_detached(scope)), ())


class _Rejected(ValueError):
    def __init__(self, code: str, instructions: str, recovery: RecoveryDisposition) -> None:
        super().__init__(instructions)
        self.code, self.instructions, self.recovery = code, instructions, recovery


def _apply(plan: ProductCommerceLoopPlan, status: str, ledger: CycleLedger, command: ProductCommerceCycleCommand) -> tuple[str, CycleLedger]:
    if status in TERMINAL_CYCLE_STATUSES:
        raise _Rejected("CYCLE_TERMINAL", f"cycle is {status}; no further transitions", "do_not_replay")
    if command.event == "cancel":
        return "cancelled", ledger
    if command.event == "withdraw":
        return "withdrawn", ledger
    stage = str(command.stage)
    if STATUS_BEFORE_STAGE[stage] != status:
        raise _Rejected("ILLEGAL_TRANSITION", f"{stage} is not the next stage after {status}", "correct_input")
    receipt = command.receipt
    assert receipt is not None
    blueprint = plan.blueprint
    data = ledger.to_dict()
    if stage == "develop_product_truth":
        if receipt.identity_digest is None or receipt.approved_claim_count is None:
            raise _Rejected("PRODUCT_TRUTH_MISSING", "product truth completion links the sealed Product Commercial Identity digest and the approved-claim count", "correct_input")
        if receipt.approved_claim_count < 1:
            raise _Rejected("NO_APPROVED_CLAIMS", "at least one evidence-backed approved claim is required before content can be produced", "correct_input")
        data.update({"identity_digest": receipt.identity_digest, "approved_claim_count": receipt.approved_claim_count})
    elif stage == "build_storefront":
        if receipt.storefront_status != "storefront_ready" or receipt.readiness_receipt_digest is None or receipt.storefront_run_ref is None or receipt.product_id is None:
            raise _Rejected("STOREFRONT_NOT_READY", "storefront completion links a storefront_ready run (run ref, product id, readiness receipt digest) from the Shopify launch runner", "correct_input")
        if receipt.identity_digest is not None and receipt.identity_digest != data.get("identity_digest"):
            data["identity_digest"] = receipt.identity_digest
        data.update({"readiness_receipt_digest": receipt.readiness_receipt_digest, "product_id": receipt.product_id})
    elif stage == "create_campaign_system":
        if not receipt.campaign_refs or len(receipt.campaign_refs) != len(receipt.campaign_channels):
            raise _Rejected("CAMPAIGN_SYSTEM_MISSING", "campaign completion links one campaign reference per channel", "correct_input")
        if len(set(receipt.campaign_channels)) != len(receipt.campaign_channels):
            raise _Rejected("ONE_CAMPAIGN_PER_CHANNEL", "a product has exactly one campaign system per channel", "correct_input")
        outside = [channel for channel in receipt.campaign_channels if channel not in blueprint.channels]
        if outside:
            raise _Rejected("CHANNEL_OUTSIDE_BLUEPRINT", f"channels {outside} are not in the blueprint", "correct_input")
        data["campaign_channels"] = list(receipt.campaign_channels)
    elif stage == "generate_variants":
        if not receipt.variant_digests or len(receipt.variant_digests) != len(receipt.variant_levels):
            raise _Rejected("VARIANTS_MISSING", "variant completion links sealed variant digests with their personalization levels", "correct_input")
        outside = sorted({level for level in receipt.variant_levels if level not in blueprint.personalization_levels})
        if outside:
            raise _Rejected("LEVEL_OUTSIDE_BLUEPRINT", f"personalization levels {outside} are not allowed by the blueprint", "correct_input")
        data.update({"variant_count": len(receipt.variant_digests), "variant_levels": sorted(set(receipt.variant_levels))})
    elif stage == "publish":
        count = len(receipt.publication_candidate_digests)
        if count == 0 or len(receipt.publication_outcomes) != count or len(receipt.publication_approval_refs) != count:
            raise _Rejected("PUBLICATION_RECEIPTS_MISSING", "publish completion links each publication candidate with its outcome and approval reference", "correct_input")
        if receipt.readiness_receipt_digest != data.get("readiness_receipt_digest"):
            raise _Rejected("READINESS_RECEIPT_MISMATCH", "publications must quote the storefront readiness receipt the cycle retained", "correct_input")
        if any(outcome == "in_doubt" for outcome in receipt.publication_outcomes):
            raise _Rejected("PUBLICATION_IN_DOUBT", "an ambiguous publication must be reconciled before the stage completes", "manual_reconciliation")
        completed = sum(1 for outcome in receipt.publication_outcomes if outcome == "completed")
        if completed == 0:
            raise _Rejected("NOTHING_PUBLISHED", "at least one publication must have completed", "correct_input")
        if len(receipt.publication_external_refs) != completed:
            raise _Rejected("PUBLICATION_REFS_MISMATCH", "each completed publication carries its platform post reference", "correct_input")
        data["publication_count"] = completed
    elif stage == "convert":
        if receipt.orders is None or receipt.units_sold is None or receipt.gross_revenue is None or not receipt.evidence_refs:
            raise _Rejected("CONVERSION_EVIDENCE_MISSING", "conversion completion links Shopify order evidence with order count, units, and gross revenue", "correct_input")
        if receipt.units_sold < receipt.orders:
            raise _Rejected("UNITS_BELOW_ORDERS", "units sold cannot be fewer than orders", "correct_input")
        data.update({"orders": receipt.orders, "units_sold": receipt.units_sold, "gross_revenue": str(receipt.gross_revenue)})
    elif stage == "fulfil_support":
        if data["units_sold"] > 0 and not receipt.fulfilment_refs and blueprint.fulfilment_mode != "digital_delivery":
            raise _Rejected("FULFILMENT_MISSING", "sold units need fulfilment references", "correct_input")
        data["support_cases"] = len(receipt.support_case_refs)
        if receipt.returned_units is not None:
            if receipt.returned_units > data["units_sold"]:
                raise _Rejected("RETURNS_EXCEED_SALES", "returned units cannot exceed units sold", "correct_input")
            data["returned_units"] = receipt.returned_units
    elif stage == "observe":
        if receipt.outcome_evidence_digest is None or receipt.refunds is None or receipt.ad_spend is None or receipt.cogs is None:
            raise _Rejected("OUTCOME_EVIDENCE_MISSING", "observation links the sealed outcome evidence digest with refunds, ad spend, and COGS", "correct_input")
        if receipt.refunds > Decimal(data["gross_revenue"]):
            raise _Rejected("REFUNDS_EXCEED_REVENUE", "refunds cannot exceed gross revenue", "correct_input")
        data.update({"outcome_evidence_digest": receipt.outcome_evidence_digest, "refunds": str(receipt.refunds), "ad_spend": str(receipt.ad_spend), "cogs": str(receipt.cogs), "fulfilment_cost": str(receipt.fulfilment_cost or Decimal("0"))})
        if receipt.returned_units is not None:
            data["returned_units"] = receipt.returned_units
    elif stage == "improve":
        if receipt.learning_entry_digest is None or receipt.next_experiment_ref is None or not receipt.improvement_actions:
            raise _Rejected("IMPROVEMENT_MISSING", "improvement completion links a learning entry digest, the next experiment, and at least one improvement action", "correct_input")
        data.update({"learning_entry_digest": receipt.learning_entry_digest, "next_experiment_ref": receipt.next_experiment_ref, "improvement_actions": list(receipt.improvement_actions)})
    return STATUS_AFTER_STAGE[stage], CycleLedger.model_validate(data)


class ProductCommerceCycleState(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_cycle_state.v1"] = Field(default=CYCLE_STATE_SCHEMA, alias="schema")
    plan_digest: Sha256Digest
    scope: ProductCommerceScope
    status: CycleStatus
    version: int = Field(ge=1, le=MAX_CYCLE_TRANSITIONS)
    transition_history: tuple[CycleTransition, ...] = Field(min_length=1, max_length=MAX_CYCLE_TRANSITIONS)
    ledger: CycleLedger
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def _state_is_exact(self, info: ValidationInfo) -> "ProductCommerceCycleState":
        history = self.transition_history
        if self.version != len(history) or [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("cycle version must equal a contiguous transition history")
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique([str(getattr(item.command, field_name)) for item in history], label=f"historical {field_name} values")
        prefix: tuple[CycleTransition, ...] = ()
        for transition in history:
            if transition.prior_state_digest != _state_digest(self.plan_digest, self.scope, prefix):
                raise ValueError("historical transition has a discontinuous state digest")
            prefix = (*prefix, transition)
        if self.state_digest != _state_digest(self.plan_digest, self.scope, history):
            raise ValueError("state_digest must commit the exact cycle state")
        plan: ProductCommerceLoopPlan | None = (info.context or {}).get("product_commerce_plan")
        if plan is not None:
            status, ledger = "opened", CycleLedger()
            for transition in history:
                try:
                    status, ledger = _apply(plan, status, ledger, transition.command)
                except _Rejected as exc:
                    raise ValueError(f"historical transition {transition.to_version} is invalid: {exc.code}") from exc
                if status != transition.to_status:
                    raise ValueError("historical transition status does not match the loop table")
            if self.status != status or self.ledger != ledger:
                raise ValueError("cycle status and ledger must be derived from history")
        return self


class CycleRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: BoundedText | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "CycleRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match the disposition")
        return self


class CycleTransitionReceipt(_StrictModel):
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    event: CycleEvent
    stage: LoopStage | None = None
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_status: CycleStatus
    to_status: CycleStatus
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: CycleRecovery


class CycleEffectBoundary(_StrictModel):
    sdk_candidate_only: Literal[True] = True
    persistence_written: Literal[False] = False
    connector_effect_executed: Literal[False] = False
    content_published: Literal[False] = False
    claims_invented_by_model: Literal[False] = False


class CycleTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_cycle_transition_result.v1"] = Field(default=CYCLE_RESULT_SCHEMA, alias="schema")
    candidate_validated: bool
    state: ProductCommerceCycleState | None = None
    receipt: CycleTransitionReceipt
    effect_boundary: CycleEffectBoundary = Field(default_factory=CycleEffectBoundary)

    @model_validator(mode="after")
    def _coherent(self) -> "CycleTransitionResult":
        if self.candidate_validated != (self.receipt.status == "candidate_materialized") or (self.candidate_validated and self.state is None):
            raise ValueError("result must carry a state exactly when a candidate was materialized")
        return self


def _validate_plan_state(plan: ProductCommerceLoopPlan | Mapping[str, Any], state: ProductCommerceCycleState | Mapping[str, Any]) -> tuple[ProductCommerceLoopPlan, ProductCommerceCycleState]:
    parsed_plan = ProductCommerceLoopPlan.model_validate(_detached(plan))
    unbound = ProductCommerceCycleState.model_validate(_detached(state))
    if unbound.plan_digest != parsed_plan.plan_digest:
        raise ValueError("cycle state belongs to a different loop plan")
    parsed_state = ProductCommerceCycleState.model_validate(unbound.to_dict(), context={"product_commerce_plan": parsed_plan})
    return parsed_plan, parsed_state


def open_product_commerce_cycle(plan: ProductCommerceLoopPlan | Mapping[str, Any], scope: ProductCommerceScope | Mapping[str, Any], identity: ProductCommercialIdentity | Mapping[str, Any], *, opened_at: str, actor_ref: str) -> ProductCommerceCycleState:
    """Open a cycle by completing product truth with a sealed Product Commercial Identity."""

    parsed_plan = ProductCommerceLoopPlan.model_validate(_detached(plan))
    parsed_scope = ProductCommerceScope.model_validate(_detached(scope))
    parsed_identity = ProductCommercialIdentity.model_validate(_detached(identity))
    if parsed_scope.currency != parsed_plan.blueprint.currency or parsed_identity.price.currency != parsed_scope.currency:
        raise ValueError("cycle, blueprint, and product price must share a currency")
    if parsed_identity.product_ref != parsed_scope.product_ref:
        raise ValueError("the identity must describe the cycle's product")
    if parsed_identity.inventory.fulfilment_mode != parsed_plan.blueprint.fulfilment_mode:
        raise ValueError("the identity's fulfilment mode must match the blueprint")
    genesis = _state_digest(parsed_plan.plan_digest, parsed_scope, ())
    command = ProductCommerceCycleCommand.model_validate(seal_cycle_command({"event": "complete_stage", "stage": "develop_product_truth", "transition_ref": f"develop_product_truth:{parsed_scope.cycle_ref}", "idempotency_key": f"{parsed_scope.cycle_ref}:develop_product_truth", "expected_version": 0, "expected_state_digest": genesis, "occurred_at": opened_at, "actor_ref": actor_ref, "receipt": {"identity_digest": parsed_identity.identity_digest, "approved_claim_count": len(parsed_identity.approved_claims), "evidence_refs": [item.evidence_refs[0] for item in parsed_identity.approved_claims][:50]}}))
    try:
        status, ledger = _apply(parsed_plan, "opened", CycleLedger(), command)
    except _Rejected as exc:
        raise ValueError(f"{exc.code}: {exc.instructions}") from exc
    transition = CycleTransition(to_version=1, prior_state_digest=genesis, to_status=status, transition_digest=_transition_digest(1, genesis, status, command), command=command)
    return ProductCommerceCycleState.model_validate({"plan_digest": parsed_plan.plan_digest, "scope": parsed_scope.to_dict(), "status": status, "version": 1, "transition_history": [transition.to_dict()], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_plan.plan_digest, parsed_scope, (transition,))}, context={"product_commerce_plan": parsed_plan})


def advance_product_commerce_cycle(plan: ProductCommerceLoopPlan | Mapping[str, Any], state: ProductCommerceCycleState | Mapping[str, Any], command: ProductCommerceCycleCommand | Mapping[str, Any]) -> CycleTransitionResult:
    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    parsed_command = ProductCommerceCycleCommand.model_validate(_detached(command))
    from_version, from_status, from_digest = parsed_state.version, parsed_state.status, parsed_state.state_digest

    def rejected(exc: _Rejected) -> CycleTransitionResult:
        receipt = CycleTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="rejected", from_version=from_version, to_version=from_version, from_status=from_status, to_status=from_status, from_state_digest=from_digest, to_state_digest=from_digest, rejection_code=exc.code, recovery=CycleRecovery(disposition=exc.recovery, instructions=exc.instructions))
        return CycleTransitionResult(candidate_validated=False, receipt=receipt)

    try:
        for prior in parsed_state.transition_history:
            if prior.command.request_digest == parsed_command.request_digest:
                raise _Rejected("TRANSITION_ALREADY_APPLIED", "this exact transition is already retained; duplicate delivery ignored", "do_not_replay")
            if prior.command.transition_ref == parsed_command.transition_ref or prior.command.idempotency_key == parsed_command.idempotency_key:
                raise _Rejected("IDEMPOTENCY_CONFLICT", "a different transition already used this reference or idempotency key", "manual_reconciliation")
        if parsed_command.expected_version != from_version or parsed_command.expected_state_digest != from_digest:
            raise _Rejected("STALE_STATE", "revision or state fence does not match; refresh and retry with the current state", "refresh_state")
        if _parsed_timestamp(parsed_command.occurred_at) < _parsed_timestamp(parsed_state.transition_history[-1].command.occurred_at):
            raise _Rejected("NON_CHRONOLOGICAL_TRANSITION", "transition precedes the last retained transition", "correct_input")
        if from_version >= MAX_CYCLE_TRANSITIONS:
            raise _Rejected("TRANSITION_BOUND_REACHED", "the cycle reached its bounded transition count", "manual_reconciliation")
        next_status, ledger = _apply(parsed_plan, from_status, parsed_state.ledger, parsed_command)
    except _Rejected as exc:
        return rejected(exc)
    transition = CycleTransition(to_version=from_version + 1, prior_state_digest=from_digest, to_status=next_status, transition_digest=_transition_digest(from_version + 1, from_digest, next_status, parsed_command), command=parsed_command)
    history = (*parsed_state.transition_history, transition)
    new_state = ProductCommerceCycleState.model_validate({"plan_digest": parsed_state.plan_digest, "scope": parsed_state.scope.to_dict(), "status": next_status, "version": from_version + 1, "transition_history": [item.to_dict() for item in history], "ledger": ledger.to_dict(), "state_digest": _state_digest(parsed_state.plan_digest, parsed_state.scope, history)}, context={"product_commerce_plan": parsed_plan})
    receipt = CycleTransitionReceipt(transition_ref=parsed_command.transition_ref, idempotency_key=parsed_command.idempotency_key, request_digest=parsed_command.request_digest, event=parsed_command.event, stage=parsed_command.stage, status="candidate_materialized", from_version=from_version, to_version=new_state.version, from_status=from_status, to_status=next_status, from_state_digest=from_digest, to_state_digest=new_state.state_digest, recovery=CycleRecovery(disposition="not_required"))
    return CycleTransitionResult(candidate_validated=True, state=new_state, receipt=receipt)


# --------------------------------------------------------------------------- #
# Assessment (observe + improve)
# --------------------------------------------------------------------------- #


class NextExperimentProposal(_StrictModel):
    experiment_ref: OpaqueRef
    hypothesis: ExperimentHypothesis
    lever: ShortText
    control_variant_digest: Sha256Digest | None = None
    rationale: BoundedText


class ProductCommerceCycleAssessment(_StrictModel):
    schema_id: Literal["lightbulb.product_commerce_cycle_assessment.v1"] = Field(default=CYCLE_ASSESSMENT_SCHEMA, alias="schema")
    golden_loop: Literal["commerce.product_truth_to_measured_improvement@0.1.0"] = PRODUCT_COMMERCE_GOLDEN_LOOP
    profile: BlueprintProfile
    cycle_ref: OpaqueRef
    product_ref: OpaqueRef
    status: CycleStatus
    version: int = Field(ge=1)
    stages_completed: tuple[LoopStage, ...] = Field(default_factory=tuple, max_length=9)
    next_stage: LoopStage | None = None
    orders: int = Field(ge=0)
    units_sold: int = Field(ge=0)
    gross_revenue: Decimal
    net_revenue: Decimal
    ad_spend: Decimal
    contribution: Decimal
    contribution_margin_percent: Decimal | None = None
    margin_versus_target_points: Decimal | None = None
    roas: Decimal | None = None
    return_rate_percent: Decimal | None = None
    publications: int = Field(ge=0)
    variants: int = Field(ge=0)
    learnings: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    next_cycle_recommendations: tuple[BoundedText, ...] = Field(default_factory=tuple, max_length=20)
    next_experiment: NextExperimentProposal | None = None
    learning_entry_candidate: dict[str, Any] = Field(default_factory=dict)
    effect_boundary: CycleEffectBoundary = Field(default_factory=CycleEffectBoundary)
    assessed_at: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("gross_revenue", "net_revenue", "ad_spend", mode="before")
    @classmethod
    def _amounts(cls, value: Any, info: ValidationInfo) -> Decimal:
        return _decimal(value, field_name=str(info.field_name))

    @field_validator("contribution", "contribution_margin_percent", "margin_versus_target_points", "roas", "return_rate_percent", mode="before")
    @classmethod
    def _signed(cls, value: Any, info: ValidationInfo) -> Any:
        return None if value is None else _decimal(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("assessed_at")
    @classmethod
    def _assessed(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_exact(self, info: ValidationInfo) -> "ProductCommerceCycleAssessment":
        if _skip(info):
            return self
        if self.assessment_digest != _sealed_digest(ProductCommerceCycleAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest must commit the exact assessment")
        return self


def assess_product_commerce_cycle(plan: ProductCommerceLoopPlan | Mapping[str, Any], state: ProductCommerceCycleState | Mapping[str, Any], *, assessed_at: str) -> ProductCommerceCycleAssessment:
    """Effect-dark observe/improve assessment: net revenue, contribution margin against target, ROAS, returns, and the next experiment."""

    parsed_plan, parsed_state = _validate_plan_state(plan, state)
    ledger, blueprint = parsed_state.ledger, parsed_plan.blueprint
    completed = tuple(str(item.command.stage) for item in parsed_state.transition_history if item.command.event == "complete_stage")
    next_stage = None if parsed_state.status in TERMINAL_CYCLE_STATUSES else STAGE_ORDER[len(completed)]
    observed = "observe" in completed
    net = (ledger.gross_revenue - ledger.refunds).quantize(_MONEY_QUANTUM)
    contribution = (net - ledger.cogs - ledger.fulfilment_cost - ledger.ad_spend).quantize(_MONEY_QUANTUM)
    margin = (contribution / net * Decimal(100)).quantize(_MONEY_QUANTUM) if observed and net > 0 else None
    gap = (margin - blueprint.target_contribution_margin_percent).quantize(_MONEY_QUANTUM) if margin is not None else None
    roas = (net / ledger.ad_spend).quantize(_MONEY_QUANTUM) if observed and ledger.ad_spend > 0 else None
    return_rate = (Decimal(ledger.returned_units) / Decimal(ledger.units_sold) * Decimal(100)).quantize(_MONEY_QUANTUM) if ledger.units_sold > 0 and "fulfil_support" in completed else None
    learnings: list[str] = []
    recommendations: list[str] = []
    lever = "campaign_creative"
    metric = "visit_to_purchase"
    if parsed_state.status == "withdrawn":
        learnings.append("product withdrawn before the cycle completed")
    if gap is not None:
        if gap < 0:
            learnings.append(f"contribution margin {margin}% missed the {blueprint.target_contribution_margin_percent.quantize(_MONEY_QUANTUM)}% target by {abs(gap)} points")
            recommendations.append("re-run growth.plan_price_move against the unit economics or cut the weakest channel's spend")
            lever = "price"
            metric = "revenue_per_session"
        else:
            learnings.append(f"contribution margin {margin}% met the {blueprint.target_contribution_margin_percent.quantize(_MONEY_QUANTUM)}% target")
    if roas is not None and roas < blueprint.minimum_roas:
        learnings.append(f"ROAS {roas} is below the {blueprint.minimum_roas.quantize(_MONEY_QUANTUM)} floor")
        recommendations.append("pause the channel with the lowest attributed revenue per spend and reallocate to the best one")
        lever = "channel_allocation"
        metric = "reach_to_visit"
    if return_rate is not None and return_rate > Decimal("10"):
        learnings.append(f"return rate {return_rate}% exceeds 10%; product truth or expectations are misaligned")
        recommendations.append("audit approved claims against return reasons and revise the product page before the next campaign")
        lever = "product_page"
        metric = "purchase_to_repeat"
    if ledger.publication_count and ledger.orders == 0 and "convert" in completed:
        learnings.append("publications produced no orders in the window")
        recommendations.append("test a segment-level variant with a stronger approved claim and a conversion objective")
    if ledger.support_cases > max(ledger.orders // 10, 0) and "fulfil_support" in completed and ledger.support_cases > 0:
        learnings.append(f"{ledger.support_cases} support cases against {ledger.orders} orders")
        recommendations.append("add fulfilment-lead-time and returns-window facts to the landing page")
    if parsed_state.status == "completed" and not learnings:
        learnings.append("cycle completed within blueprint policy")
    experiment = None
    if observed:
        experiment = NextExperimentProposal(experiment_ref=f"exp:{parsed_state.scope.cycle_ref}:{parsed_state.version + 1}", hypothesis=ExperimentHypothesis(metric_name=metric, direction="increase", rationale=(learnings[0] if learnings else "hold the winning configuration and measure repeat purchase")), lever=lever, rationale=(recommendations[0] if recommendations else "keep the configuration and measure repeat purchase"))
    payload = {
        "profile": blueprint.profile, "cycle_ref": parsed_state.scope.cycle_ref, "product_ref": parsed_state.scope.product_ref, "status": parsed_state.status, "version": parsed_state.version,
        "stages_completed": completed, "next_stage": next_stage, "orders": ledger.orders, "units_sold": ledger.units_sold,
        "gross_revenue": str(ledger.gross_revenue), "net_revenue": str(net), "ad_spend": str(ledger.ad_spend), "contribution": str(contribution),
        "contribution_margin_percent": None if margin is None else str(margin), "margin_versus_target_points": None if gap is None else str(gap), "roas": None if roas is None else str(roas), "return_rate_percent": None if return_rate is None else str(return_rate),
        "publications": ledger.publication_count, "variants": ledger.variant_count, "learnings": learnings, "next_cycle_recommendations": recommendations,
        "next_experiment": None if experiment is None else experiment.to_dict(),
        "learning_entry_candidate": {"stage": "conversion" if metric in {"visit_to_purchase", "revenue_per_session"} else ("retention" if metric == "purchase_to_repeat" else "traffic"), "lever": lever, "metric_name": metric, "claim": learnings[0] if learnings else "no learning yet", "grade": "observational", "causal": False} if observed else {},
        "assessed_at": assessed_at,
    }
    payload["assessment_digest"] = _sealed_digest(ProductCommerceCycleAssessment, payload, "assessment_digest")
    return ProductCommerceCycleAssessment.model_validate(payload)


PRODUCT_COMMERCE_ARCHETYPE_MANIFEST: dict[str, Any] = {
    "schema": "lightbulb.company_blueprint_archetype.v1",
    "archetype": PRODUCT_COMMERCE_ARCHETYPE,
    "title": "Product commerce",
    "golden_loop": PRODUCT_COMMERCE_GOLDEN_LOOP,
    "composed_with": ["commerce.plan_shopify_storefront", "gtm.plan_omnichannel_product_launch", "lightbulb.gtm_shopify_launch.run_shopify_product_launch (storefront readiness receipt)", "growth.* profit, funnel, customer value, experiments, learnings"],
    "profiles": sorted(PRODUCT_COMMERCE_PROFILES),
    "channels": list(Channel.__args__),  # type: ignore[attr-defined]
    "personalization_family": ["commerce.compile_product_commercial_identity", "commerce.compose_personalized_variant", "approval (Spring)", "commerce.plan_channel_publication", "outcome evidence", "next experiment"],
    "economic_spine": {"acquire_demand": "create_campaign_system+publish", "create_offer": "develop_product_truth", "agree_purchase": "convert (Shopify checkout)", "deliver_value": "fulfil_support", "accept_value": "fulfil_support (delivery confirmation, returns window)", "monetize": "convert", "learn": "observe+improve"},
    "composable_with": ["service_business", "subscription_business", "saas_product", "appointment_business", "marketplace_business"],
    "explicit_inputs_never_invented": ["consent basis and evidence", "platform policy references", "approved product claims with evidence"],
}

__all__ = [
    "BLUEPRINT_SCHEMA",
    "CHANNEL_TOOLS",
    "DEFAULT_CHANNEL_CONSTRAINTS",
    "IDENTITY_SCHEMA",
    "PRODUCT_COMMERCE_ARCHETYPE",
    "PRODUCT_COMMERCE_ARCHETYPE_MANIFEST",
    "PRODUCT_COMMERCE_GOLDEN_LOOP",
    "PRODUCT_COMMERCE_PROFILES",
    "STAGE_ORDER",
    "STATUS_AFTER_STAGE",
    "TERMINAL_CYCLE_STATUSES",
    "ApprovedClaim",
    "AudienceProfile",
    "ChannelCampaign",
    "ChannelConstraints",
    "ChannelMetrics",
    "ChannelPublishingPort",
    "ConnectorChannelPublishingAdapter",
    "ContentVariant",
    "CycleEffectBoundary",
    "CycleLedger",
    "CycleRecovery",
    "CycleTransition",
    "CycleTransitionReceipt",
    "CycleTransitionResult",
    "InventoryConstraint",
    "Money",
    "NextExperimentProposal",
    "OutcomeEvidence",
    "PersonalizationBrief",
    "PersonalizationPolicy",
    "PolicyFinding",
    "ProductCommerceBlueprint",
    "ProductCommerceCycleAssessment",
    "ProductCommerceCycleCommand",
    "ProductCommerceCycleState",
    "ProductCommerceLoopPlan",
    "ProductCommerceScope",
    "ProductCommercialIdentity",
    "PublicationCandidate",
    "PublicationReceipt",
    "SeoProfile",
    "ShopifyBinding",
    "StageBinding",
    "StageReceipt",
    "VariantComposition",
    "advance_product_commerce_cycle",
    "approve_variant",
    "assess_product_commerce_cycle",
    "bind_storefront_readiness",
    "compile_product_commerce_blueprint",
    "compile_product_commercial_identity",
    "compose_personalized_variant",
    "cycle_command_digest",
    "genesis_cycle_state_digest",
    "open_product_commerce_cycle",
    "plan_channel_publication",
    "seal_cycle_command",
    "seal_outcome_evidence",
    "seal_product_commerce_blueprint",
]
