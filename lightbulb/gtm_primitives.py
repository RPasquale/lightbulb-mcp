"""Typed, deterministic go-to-market workflow planning primitives.

This module deliberately separates planning from external execution.  It gives
coding agents a closed-world operation graph, immutable evidence obligations,
and a project-scoped sharding contract without pretending that connector
surfaces with different custody models can be invoked as one transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections import defaultdict
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Annotated, Any, Iterable, Literal, Mapping, Protocol
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from lightbulb.dynamic_workflows import (
    AcceptanceCriterion,
    DynamicWorkflowScope,
    DynamicWorkflowState,
    EvidenceRef,
    WorkflowLimits,
)
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)


OMNICHANNEL_PRODUCT_LAUNCH_PLAN_SCHEMA = "lightbulb.omnichannel_product_launch_plan.v1"
OMNICHANNEL_PRODUCT_LAUNCH_PRIMITIVE_REF = "gtm.plan_omnichannel_product_launch"
PRODUCT_LAUNCH_SHARD_SCHEMA = "lightbulb.product_launch_shard.v1"
PRODUCT_LAUNCH_PORTFOLIO_SCHEMA = "lightbulb.product_launch_portfolio.v1"
PRODUCT_LAUNCH_RECEIPT_SCHEMA = "lightbulb.product_launch_receipt.v1"
PRODUCT_LAUNCH_CONNECTOR_ACCOUNT_BINDING_SCHEMA = (
    "lightbulb.product_launch_connector_account_binding.v1"
)
PRODUCT_LAUNCH_ITERATION_EVALUATION_SCHEMA = (
    "lightbulb.product_launch_iteration_evaluation.v1"
)
_PRODUCT_LAUNCH_RECEIPT_HMAC_DOMAIN = "lightbulb.product_launch_receipt.v1"
_PRODUCT_LAUNCH_PLAN_HMAC_DOMAIN = "lightbulb.omnichannel_product_launch_plan.v1"
_PRODUCT_LAUNCH_ANALYTICS_HMAC_DOMAIN = "lightbulb.product_launch_analytics_snapshot.v1"
_PRODUCT_LAUNCH_ACCOUNT_HMAC_DOMAIN = (
    "lightbulb.product_launch_connector_account_binding.v1"
)
_PRODUCT_LAUNCH_EVALUATION_HMAC_DOMAIN = (
    "lightbulb.product_launch_iteration_evaluation.v1"
)

_MAX_ANALYTICS_SNAPSHOTS = 100
_MAX_SOCIAL_DRAFTS = 3
_MAX_SALES_TOUCHES = 10
_MAX_PORTFOLIO_LAUNCHES = 10_000
_MAX_LAUNCHES_PER_SHARD = 12
_MAX_LAUNCH_JOB_BYTES = 256 * 1_024
_MAX_LAUNCH_SHARD_BYTES = 4 * 1_024 * 1_024
_MAX_LAUNCH_PORTFOLIO_BYTES = 64 * 1_024 * 1_024
_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")
_MAX_CAMPAIGN_NOTES_LENGTH = 15_000
_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHOPIFY_PUBLICATION_ID_PATTERN = (
    r"^(?:[1-9][0-9]{0,30}|gid://shopify/Publication/[1-9][0-9]{0,30})$"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


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
    """Normalize JSON arrays to tuples so frozen models are deeply immutable."""

    if isinstance(value, list):
        return tuple(value)
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
ShopifyProductTitle = Annotated[
    str,
    StringConstraints(min_length=1, max_length=255),
    AfterValidator(_bounded_text),
]
ShopifyPublicationId = Annotated[
    str,
    StringConstraints(pattern=_SHOPIFY_PUBLICATION_ID_PATTERN),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_body),
]
CampaignNotes = Annotated[
    str,
    StringConstraints(min_length=1, max_length=15_000),
    AfterValidator(_bounded_body),
]
LinkedInText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=3_000),
    AfterValidator(_bounded_body),
]
PortableRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
]
OperationRef = Annotated[
    str,
    StringConstraints(pattern=_OPERATION_REF_PATTERN),
]
WorkflowRunRef = Annotated[
    str,
    StringConstraints(min_length=1, max_length=200),
    AfterValidator(_bounded_text),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=_SHA256_PATTERN),
]
CurrencyCode = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z]{3}$"),
]
Sku = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64),
    AfterValidator(_bounded_text),
]

SocialChannel = Literal["facebook", "instagram", "linkedin"]
CrmProvider = Literal["hubspot", "salesforce"]
LaunchConnectorProvider = Literal[
    "shopify",
    "hubspot",
    "salesforce",
    "facebook",
    "instagram",
    "linkedin",
]
AnalyticsProvider = Literal[
    "shopify",
    "hubspot",
    "salesforce",
    "facebook",
    "instagram",
    "linkedin",
    "google_analytics",
]
PrimaryMetric = Literal[
    "conversion_rate",
    "click_through_rate",
    "engagement_rate",
    "pipeline_win_rate",
]


_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "shopify": frozenset({"shopify.analytics_query"}),
    "hubspot": frozenset({"crm.search_deals"}),
    "salesforce": frozenset({"salesforce.pipeline_report"}),
    "facebook": frozenset({"facebook.fetch_metrics"}),
    "instagram": frozenset({"instagram.fetch_metrics"}),
    "linkedin": frozenset({"linkedin.fetch_metrics"}),
    "google_analytics": frozenset({"google_analytics.fetch_metrics"}),
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class OmnichannelProductLaunchValidationError(ValueError):
    """A launch brief cannot be converted into a safe closed-world plan."""


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters the brief."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


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


def _iso_date(value: str) -> str:
    clean = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", clean) is None:
        raise ValueError("date must use YYYY-MM-DD")
    try:
        date.fromisoformat(clean)
    except ValueError as exc:
        raise ValueError("date must use YYYY-MM-DD") from exc
    return clean


def _public_https_url(value: str) -> str:
    clean = value.strip()
    parsed = urlsplit(clean)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain credentials")
    host = parsed.hostname.casefold()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ValueError("URL must not target a local host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("URL must use a public network address")
    return clean


PublicHttpsUrl = Annotated[
    str,
    StringConstraints(min_length=8, max_length=2_000),
    AfterValidator(_public_https_url),
]


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


class LaunchMoney(_StrictModel):
    amount: Decimal = Field(gt=0, le=100_000_000, multiple_of=_MONEY_QUANTUM)
    currency: CurrencyCode

    @field_validator("amount", mode="before")
    @classmethod
    def _money_amount(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class LaunchVariant(_StrictModel):
    variant_ref: PortableRef
    title: ShortText
    price: LaunchMoney
    sku: Sku | None = None


class LaunchProductBrief(_StrictModel):
    product_ref: PortableRef
    connector_account_ref: OperationRef
    # Shopify's product title and the governed readiness contract are both
    # bounded to 255 characters. Reject an impossible launch before approval or
    # connector execution rather than letting the final evidence gate fail.
    title: ShopifyProductTitle
    description: LongText | None = None
    vendor: ShortText | None = None
    product_type: ShortText | None = None
    tags: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    price: LaunchMoney
    sku: Sku | None = None
    taxable: bool = True
    requires_shipping: bool = True
    landing_url: PublicHttpsUrl
    publication_ids: tuple[ShopifyPublicationId, ...] = Field(
        min_length=1,
        max_length=10,
    )
    variants: tuple[LaunchVariant, ...] = Field(default_factory=tuple, max_length=20)

    @field_validator("tags", "publication_ids", "variants", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_product_metadata(self) -> "LaunchProductBrief":
        tags = [tag.casefold() for tag in self.tags]
        if len(tags) != len(set(tags)):
            raise ValueError("product tags must be unique")
        publication_ids = [value.casefold() for value in self.publication_ids]
        if len(publication_ids) != len(set(publication_ids)):
            raise ValueError("product publication_ids must be unique")
        variant_refs = [variant.variant_ref for variant in self.variants]
        if len(variant_refs) != len(set(variant_refs)):
            raise ValueError("variant_ref values must be unique")
        variant_skus = [
            variant.sku.casefold()
            for variant in self.variants
            if variant.sku is not None
        ]
        if self.sku is not None:
            variant_skus.append(self.sku.casefold())
        if len(variant_skus) != len(set(variant_skus)):
            raise ValueError("product and variant SKU values must be unique")
        currencies = {variant.price.currency for variant in self.variants}
        if currencies and currencies != {self.price.currency}:
            raise ValueError("all variant prices must use the product currency")
        return self


class SalesTouch(_StrictModel):
    day_offset: int = Field(ge=0, le=120)
    channel: Literal["email", "call", "linkedin", "task"]
    objective: ShortText
    message: LongText


class SalesCampaignBrief(_StrictModel):
    provider: CrmProvider = "hubspot"
    connector_account_ref: OperationRef
    name: ShortText
    audience: LongText
    goal: LongText
    offer: LongText
    start_date: str
    end_date: str
    notes: LongText | None = None
    touches: tuple[SalesTouch, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_SALES_TOUCHES,
    )

    @field_validator("touches", mode="before")
    @classmethod
    def _immutable_touches(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("start_date", "end_date")
    @classmethod
    def _valid_date(cls, value: str) -> str:
        return _iso_date(value)

    @model_validator(mode="after")
    def _valid_window_and_touch_order(self) -> "SalesCampaignBrief":
        start = date.fromisoformat(self.start_date)
        end = date.fromisoformat(self.end_date)
        if end < start:
            raise ValueError("campaign end_date must not precede start_date")
        offsets = [touch.day_offset for touch in self.touches]
        if offsets != sorted(offsets):
            raise ValueError("sales touches must be ordered by day_offset")
        duration_days = (end - start).days
        if any(offset > duration_days for offset in offsets):
            raise ValueError(
                "sales touch day_offset must fall inside the campaign window"
            )
        return self


class SocialPostDraft(_StrictModel):
    channel: SocialChannel
    connector_account_ref: OperationRef
    provider_target_id: ShortText
    body: LongText
    media_url: PublicHttpsUrl | None = None
    link_url: PublicHttpsUrl | None = None

    @model_validator(mode="after")
    def _instagram_requires_media(self) -> "SocialPostDraft":
        if self.channel == "instagram" and self.media_url is None:
            raise ValueError("Instagram drafts require a public media_url")
        if self.channel != "linkedin" and self.link_url is not None:
            raise ValueError("link_url is supported only for LinkedIn drafts")
        if self.channel == "linkedin" and len(self.body) > 3_000:
            raise ValueError("LinkedIn post bodies support at most 3000 characters")
        if (
            self.channel in {"facebook", "instagram"}
            and not self.provider_target_id.isdigit()
        ):
            raise ValueError("Meta provider_target_id must be a numeric Graph API ID")
        if (
            self.channel == "linkedin"
            and re.fullmatch(
                r"urn:li:(?:organization|person):[A-Za-z0-9_-]+",
                self.provider_target_id,
            )
            is None
        ):
            raise ValueError("LinkedIn provider_target_id must be an author URN")
        return self


class NormalizedPerformanceMetrics(_StrictModel):
    impressions: int | None = Field(default=None, ge=0)
    clicks: int | None = Field(default=None, ge=0)
    engagements: int | None = Field(default=None, ge=0)
    conversions: int | None = Field(default=None, ge=0)
    sessions: int | None = Field(default=None, ge=0)
    orders: int | None = Field(default=None, ge=0)
    leads: int | None = Field(default=None, ge=0)
    opportunities: int | None = Field(default=None, ge=0)
    won_deals: int | None = Field(default=None, ge=0)
    revenue: Decimal | None = Field(default=None, ge=0, multiple_of=_MONEY_QUANTUM)
    conversion_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    click_through_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    engagement_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    pipeline_win_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )

    @field_validator("revenue", mode="before")
    @classmethod
    def _revenue_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator(
        "conversion_rate",
        "click_through_rate",
        "engagement_rate",
        "pipeline_win_rate",
        mode="before",
    )
    @classmethod
    def _decimal_metrics(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _at_least_one_metric(self) -> "NormalizedPerformanceMetrics":
        if all(value is None for value in self.model_dump(mode="python").values()):
            raise ValueError("at least one normalized metric is required")
        return self


class AnalyticsSnapshot(_StrictModel):
    observation_ref: PortableRef
    connector_account_ref: OperationRef
    provider: AnalyticsProvider
    source_capability: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$",
    )
    observed_at: str
    window_start: str
    window_end: str
    sample_size: int = Field(ge=0, le=10_000_000_000)
    metrics: NormalizedPerformanceMetrics
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    snapshot_hmac: Sha256Digest | None = None

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _valid_source_and_window(self) -> "AnalyticsSnapshot":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("analytics window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede the measured window")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.snapshot_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "analytics snapshot attestation fields must be supplied together"
            )
        return self

    def hmac_payload(self) -> dict[str, Any]:
        """Return the complete canonical observation covered by host HMAC."""

        return self.model_dump(
            mode="json",
            exclude={"snapshot_hmac"},
            exclude_none=True,
        )


class ProductLaunchEvidenceScope(_StrictModel):
    status: Literal["caller_supplied_unverified", "host_hmac_verified"]
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _complete_binding(self) -> "ProductLaunchEvidenceScope":
        bound = self.status == "host_hmac_verified"
        if bound != (
            self.receipt_key_id is not None and self.exact_scope_digest is not None
        ):
            raise ValueError(
                "verified evidence scope requires a complete keyed binding"
            )
        return self


class ProductLaunchConnectorAccountBinding(_StrictModel):
    """Opaque destination account reference attested by the authenticated host."""

    schema_id: Literal["lightbulb.product_launch_connector_account_binding.v1"] = Field(
        default=PRODUCT_LAUNCH_CONNECTOR_ACCOUNT_BINDING_SCHEMA,
        alias="schema",
    )
    provider: LaunchConnectorProvider
    connector_account_ref: OperationRef
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    account_hmac: Sha256Digest | None = None

    @model_validator(mode="after")
    def _complete_attestation(self) -> "ProductLaunchConnectorAccountBinding":
        attestation = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.account_hmac,
        )
        if any(value is not None for value in attestation) and not all(
            value is not None for value in attestation
        ):
            raise ValueError(
                "connector account attestation fields must be supplied together"
            )
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"account_hmac"},
            exclude_none=True,
        )


class LaunchOptimizationPolicy(_StrictModel):
    primary_metric: PrimaryMetric = "conversion_rate"
    target_value: Decimal = Field(
        default=Decimal("0.03"), ge=0, multiple_of=_RATE_QUANTUM
    )
    minimum_sample_size: int = Field(default=100, ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(default=720, ge=1, le=8_760)
    measurement_window_hours: int = Field(default=168, ge=1, le=2_160)
    max_iterations: int = Field(default=3, ge=1, le=4)

    @field_validator("target_value", mode="before")
    @classmethod
    def _target_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _rate_target_is_bounded(self) -> "LaunchOptimizationPolicy":
        if self.target_value > 1:
            raise ValueError("rate target_value must be between 0 and 1")
        return self


class PlanOmnichannelProductLaunchInput(_StrictModel):
    analysis_as_of: str
    launch_ref: PortableRef
    business_goal: LongText
    target_audience: LongText
    value_proposition: LongText
    product: LaunchProductBrief
    sales_campaign: SalesCampaignBrief
    social_drafts: tuple[SocialPostDraft, ...] = Field(
        min_length=1,
        max_length=_MAX_SOCIAL_DRAFTS,
    )
    analytics_snapshots: tuple[AnalyticsSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_ANALYTICS_SNAPSHOTS,
    )
    optimization_policy: LaunchOptimizationPolicy = Field(
        default_factory=LaunchOptimizationPolicy
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("social_drafts", "analytics_snapshots", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _closed_world_launch(self) -> "PlanOmnichannelProductLaunchInput":
        channels = [draft.channel for draft in self.social_drafts]
        if len(channels) != len(set(channels)):
            raise ValueError("social_drafts must contain each channel at most once")
        observation_refs = [
            snapshot.observation_ref for snapshot in self.analytics_snapshots
        ]
        if len(observation_refs) != len(set(observation_refs)):
            raise ValueError("analytics observation_ref values must be unique")
        expected_accounts: dict[str, str] = {
            "shopify": self.product.connector_account_ref,
            self.sales_campaign.provider: self.sales_campaign.connector_account_ref,
            **{
                draft.channel: draft.connector_account_ref
                for draft in self.social_drafts
            },
        }
        if any(
            snapshot.provider in expected_accounts
            and snapshot.connector_account_ref != expected_accounts[snapshot.provider]
            for snapshot in self.analytics_snapshots
        ):
            raise ValueError(
                "analytics connector_account_ref must match the launch destination"
            )
        analysis_date = _parse_timestamp(self.analysis_as_of).date()
        if date.fromisoformat(self.sales_campaign.end_date) < analysis_date:
            raise ValueError("campaign end_date must not precede analysis_as_of")
        materialization_context = (
            f"Offer: {self.sales_campaign.offer}\n"
            f"Product: {self.product.title}\n"
            f"Landing page: {self.product.landing_url}"
        )
        materialized_notes = (
            f"{self.sales_campaign.notes}\n\n{materialization_context}"
            if self.sales_campaign.notes
            else materialization_context
        )
        if len(materialized_notes) > _MAX_CAMPAIGN_NOTES_LENGTH:
            raise ValueError(
                "sales campaign notes and offer exceed the materialization limit"
            )
        return self


class ShopifyDraftProductArguments(_StrictModel):
    kind: Literal["shopify_draft_product"]
    title: ShortText
    description: LongText | None = None
    vendor: ShortText | None = None
    product_type: ShortText | None = None
    status: Literal["DRAFT"] = "DRAFT"
    tags: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    price: Annotated[
        str,
        StringConstraints(pattern=r"^(?:0|[1-9][0-9]{0,8})\.[0-9]{2}$"),
    ]
    sku: Sku | None = None
    taxable: bool
    requires_shipping: bool

    @field_validator("tags", mode="before")
    @classmethod
    def _immutable_tags(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class ShopifyPublishProductArguments(_StrictModel):
    kind: Literal["shopify_publish_product"]
    publication_ids: tuple[ShopifyPublicationId, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("publication_ids", mode="before")
    @classmethod
    def _immutable_publication_ids(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class ShopifyActivateProductArguments(_StrictModel):
    kind: Literal["shopify_activate_product"]
    status: Literal["ACTIVE"] = "ACTIVE"


class LandingReadinessArguments(_StrictModel):
    kind: Literal["landing_readiness_gate"]
    landing_url: PublicHttpsUrl
    required_checks: tuple[
        Literal[
            "page_reachable",
            "product_visible",
            "price_and_currency_match",
            "checkout_available",
        ],
        ...,
    ] = (
        "page_reachable",
        "product_visible",
        "price_and_currency_match",
        "checkout_available",
    )

    @field_validator("required_checks", mode="before")
    @classmethod
    def _immutable_checks(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class HubSpotCampaignContainerArguments(_StrictModel):
    kind: Literal["hubspot_campaign_container"]
    name: ShortText
    startDate: str
    endDate: str
    goal: LongText
    audience: LongText
    notes: CampaignNotes

    @field_validator("startDate", "endDate")
    @classmethod
    def _valid_date(cls, value: str) -> str:
        return _iso_date(value)


class FacebookPublishArguments(_StrictModel):
    kind: Literal["facebook_publish"]
    page_id: ShortText
    message: LongText
    image_url: PublicHttpsUrl | None = None


class InstagramPublishArguments(_StrictModel):
    kind: Literal["instagram_publish"]
    instagram_business_account_id: ShortText
    caption: LongText
    image_url: PublicHttpsUrl


class LinkedInPublishArguments(_StrictModel):
    kind: Literal["linkedin_publish"]
    author_urn: ShortText
    text: LinkedInText
    url: PublicHttpsUrl
    image_url: PublicHttpsUrl | None = None


LaunchOperationArguments = Annotated[
    ShopifyDraftProductArguments
    | ShopifyActivateProductArguments
    | ShopifyPublishProductArguments
    | LandingReadinessArguments
    | HubSpotCampaignContainerArguments
    | FacebookPublishArguments
    | InstagramPublishArguments
    | LinkedInPublishArguments,
    Field(discriminator="kind"),
]

LaunchCapability = Literal[
    "ecommerce.create_product",
    "ecommerce.update_product",
    "shopify.publish_product",
    "gtm.verify_landing_readiness",
    "hubspot.create_campaign",
    "facebook.publish_post",
    "instagram.publish_post",
    "linkedin.publish_post",
]
ExecutionKind = Literal["connector_tool", "domain_action", "evidence_gate"]
SurfaceAvailability = Literal[
    "runtime_registered_not_generated",
    "domain_agent_only",
    "platform_registered_not_generated",
    "sdk_host_evidence_gate",
]


class ProductLaunchInputBinding(_StrictModel):
    target_field: Literal["product_id"]
    source_operation_id: OperationRef
    source_output_field: Literal["product_id"]


class ProductLaunchOperation(_StrictModel):
    ordinal: int = Field(ge=1, le=8)
    operation_id: OperationRef
    stage: Literal[
        "catalog_materialization",
        "catalog_activation",
        "catalog_publication",
        "landing_readiness",
        "crm_campaign_container",
        "social_publish",
    ]
    execution_kind: ExecutionKind
    capability: LaunchCapability
    surface_availability: SurfaceAvailability
    connector_account_ref: OperationRef
    effect: Literal["read", "write"]
    arguments: LaunchOperationArguments
    depends_on: tuple[OperationRef, ...] = Field(default_factory=tuple, max_length=2)
    input_bindings: tuple[ProductLaunchInputBinding, ...] = Field(
        default_factory=tuple,
        max_length=2,
    )
    status: Literal[
        "proposal_only_not_executed",
        "blocked_pending_evidence",
    ]
    approval_required: bool
    approval_unit: OperationRef | None = None
    receipt_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    scheduling_semantics: Literal["not_scheduled"] = "not_scheduled"
    operation_digest: str = ""

    @field_validator("depends_on", "input_bindings", mode="before")
    @classmethod
    def _immutable_dependencies(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _capability_matches_arguments(self) -> "ProductLaunchOperation":
        expected: dict[
            str,
            tuple[type[BaseModel], str, str, str, bool],
        ] = {
            "ecommerce.create_product": (
                ShopifyDraftProductArguments,
                "connector_tool",
                "runtime_registered_not_generated",
                "write",
                True,
            ),
            "shopify.publish_product": (
                ShopifyPublishProductArguments,
                "connector_tool",
                "runtime_registered_not_generated",
                "write",
                True,
            ),
            "ecommerce.update_product": (
                ShopifyActivateProductArguments,
                "connector_tool",
                "runtime_registered_not_generated",
                "write",
                True,
            ),
            "gtm.verify_landing_readiness": (
                LandingReadinessArguments,
                "evidence_gate",
                "sdk_host_evidence_gate",
                "read",
                False,
            ),
            "hubspot.create_campaign": (
                HubSpotCampaignContainerArguments,
                "domain_action",
                "domain_agent_only",
                "write",
                True,
            ),
            "facebook.publish_post": (
                FacebookPublishArguments,
                "connector_tool",
                "platform_registered_not_generated",
                "write",
                True,
            ),
            "instagram.publish_post": (
                InstagramPublishArguments,
                "connector_tool",
                "platform_registered_not_generated",
                "write",
                True,
            ),
            "linkedin.publish_post": (
                LinkedInPublishArguments,
                "connector_tool",
                "platform_registered_not_generated",
                "write",
                True,
            ),
        }
        argument_type, execution_kind, availability, effect, approval_required = (
            expected[self.capability]
        )
        if not isinstance(self.arguments, argument_type):
            raise ValueError("operation arguments do not match capability")
        if self.execution_kind != execution_kind:
            raise ValueError("operation execution_kind does not match capability")
        if self.surface_availability != availability:
            raise ValueError("surface availability does not match capability")
        if self.effect != effect or self.approval_required != approval_required:
            raise ValueError(
                "operation effect or approval policy does not match capability"
            )
        if self.approval_required != (self.approval_unit is not None):
            raise ValueError("approval_unit presence must match approval_required")
        if self.effect == "write" and self.status != "proposal_only_not_executed":
            raise ValueError("write operations must remain proposal-only")
        if self.effect == "read" and self.status != "blocked_pending_evidence":
            raise ValueError("evidence gates must remain blocked pending evidence")
        if self.operation_id in self.depends_on:
            raise ValueError("operation cannot depend on itself")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("operation dependencies must be unique")
        targets = [binding.target_field for binding in self.input_bindings]
        if len(targets) != len(set(targets)):
            raise ValueError("operation input binding targets must be unique")
        if any(
            binding.source_operation_id not in self.depends_on
            for binding in self.input_bindings
        ):
            raise ValueError("operation input bindings must reference dependencies")
        bound_product_capabilities = {
            "ecommerce.update_product",
            "shopify.publish_product",
        }
        if self.capability in bound_product_capabilities and not self.input_bindings:
            raise ValueError(f"{self.capability} requires a product_id binding")
        if self.capability not in bound_product_capabilities and self.input_bindings:
            raise ValueError("input bindings are not supported for this capability")
        if self.approval_unit is not None:
            expected_suffix = _operation_content_digest(
                self.capability,
                self.arguments,
                self.depends_on,
                self.connector_account_ref,
            )
            if not self.approval_unit.endswith(f"_{expected_suffix}"):
                raise ValueError("approval_unit is not bound to operation content")
        payload = self.model_dump(
            mode="json",
            exclude={"operation_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.operation_digest and self.operation_digest != expected_digest:
            raise ValueError(
                "operation_digest does not match canonical operation payload"
            )
        object.__setattr__(self, "operation_digest", expected_digest)
        return self

    def connector_inputs(
        self,
        resolved_outputs: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return only provider-contract arguments, excluding SDK discriminators."""

        values = self.arguments.model_dump(
            mode="json",
            exclude={"kind"},
            exclude_none=True,
        )
        if self.execution_kind == "evidence_gate":
            raise ValueError("evidence-gate operations are not connector calls")
        for binding in self.input_bindings:
            if resolved_outputs is None:
                raise ValueError(
                    "resolved_outputs are required for bound connector inputs"
                )
            source = resolved_outputs.get(binding.source_operation_id)
            value = source.get(binding.source_output_field) if source else None
            if not isinstance(value, str) or not value.strip():
                raise ValueError("bound connector output is missing or invalid")
            values[binding.target_field] = value.strip()
        return values


AnalyticsEligibility = Literal[
    "eligible",
    "scope_unverified",
    "missing",
    "future_observation",
    "stale",
    "insufficient_sample",
    "no_usable_metric",
]


class AnalyticsFinding(_StrictModel):
    provider: AnalyticsProvider
    status: AnalyticsEligibility
    observation_ref: PortableRef | None = None
    connector_account_ref: OperationRef | None = None
    source_capability: str | None = None
    evidence_digest: Sha256Digest | None = None
    age_hours: int | None = Field(default=None, ge=0)
    sample_size: int | None = Field(default=None, ge=0)
    selected_metric: PrimaryMetric | None = None
    selected_value: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    scope_verified: bool = False
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("selected_value", mode="before")
    @classmethod
    def _selected_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)


class ChannelPriority(_StrictModel):
    rank: int = Field(ge=1, le=_MAX_SOCIAL_DRAFTS)
    channel: SocialChannel
    evidence_informed: bool
    score: Decimal | None = Field(default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM)
    observation_ref: PortableRef | None = None
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("score", mode="before")
    @classmethod
    def _score_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)


GapCode = Literal[
    "proposal_only_execution_boundary",
    "generated_connector_surface_gap",
    "hubspot_campaign_container_only",
    "hubspot_sales_sequence_authoring_unavailable",
    "salesforce_campaign_materialization_unavailable",
    "analytics_evidence_incomplete",
    "instagram_native_scheduling_unavailable",
    "linkedin_schedule_is_immediate_publish",
    "connected_shop_currency_unverified",
    "typed_product_variant_creation_unavailable",
    "shopify_go_live_requires_separate_approval",
    "landing_readiness_evidence_required",
    "analytics_scope_unverified",
]


class ProductLaunchCapabilityGap(_StrictModel):
    code: GapCode
    affected_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    blocks_autonomous_launch: bool
    message: str = Field(min_length=1, max_length=1_000)

    @field_validator("affected_capabilities", mode="before")
    @classmethod
    def _immutable_capabilities(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class CampaignMaterializationDisposition(_StrictModel):
    provider: CrmProvider
    planning_complete: Literal[True] = True
    container_operation_id: OperationRef | None = None
    campaign_container_supported: bool
    sales_sequence_authoring_supported: Literal[False] = False
    sales_sequence_launch_claimed: Literal[False] = False


class RequiredLaunchReceipt(_StrictModel):
    criterion_id: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_-]{0,119}$",
    )
    receipt_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    evidence_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    operation_id: OperationRef | None = None
    operation_digest: Sha256Digest | None = None
    approval_unit: OperationRef | None = None
    proves: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _operation_binding_is_complete(self) -> "RequiredLaunchReceipt":
        if (self.operation_id is None) != (self.operation_digest is None):
            raise ValueError("operation receipt bindings must be complete")
        if self.operation_id is None and self.approval_unit is not None:
            raise ValueError("plan-level receipts cannot carry an approval unit")
        return self


class ProductLaunchReceipt(_StrictModel):
    """Host-HMAC-sealed evidence envelope bound to one launch criterion."""

    schema_id: Literal["lightbulb.product_launch_receipt.v1"] = Field(
        default=PRODUCT_LAUNCH_RECEIPT_SCHEMA,
        alias="schema",
    )
    receipt_ref: OperationRef
    criterion_id: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_-]{0,119}$",
    )
    receipt_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    evidence_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    plan_digest: Sha256Digest
    exact_scope_digest: Sha256Digest
    run_ref: WorkflowRunRef
    iteration: int = Field(ge=1, le=4)
    operation_id: OperationRef | None = None
    operation_digest: Sha256Digest | None = None
    approval_unit: OperationRef | None = None
    approval_receipt_digest: Sha256Digest | None = None
    issuer_ref: OperationRef
    evidence_digest: Sha256Digest
    status: Literal["succeeded"] = "succeeded"
    issued_at: str
    effective_at: str
    window_start: str | None = None
    window_end: str | None = None
    sample_size: int | None = Field(default=None, ge=0, le=10_000_000_000)
    primary_metric: PrimaryMetric | None = None
    metric_value: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    receipt_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    receipt_hmac: Sha256Digest
    receipt_digest: str = ""

    @field_validator("issued_at", "effective_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamps(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("metric_value", mode="before")
    @classmethod
    def _metric_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _seal_and_validate(self) -> "ProductLaunchReceipt":
        if (self.operation_id is None) != (self.operation_digest is None):
            raise ValueError("operation receipt bindings must be complete")
        if (self.approval_unit is None) != (self.approval_receipt_digest is None):
            raise ValueError("approval receipt bindings must be complete")
        if self.operation_id is None and self.approval_unit is not None:
            raise ValueError("plan-level receipts cannot carry approval evidence")
        if _parse_timestamp(self.effective_at) > _parse_timestamp(self.issued_at):
            raise ValueError("receipt effective_at must not follow issued_at")
        performance_receipt = self.receipt_kind == "gtm_performance_snapshot"
        metric_fields = (self.sample_size, self.primary_metric, self.metric_value)
        if performance_receipt and not all(
            value is not None for value in metric_fields
        ):
            raise ValueError("performance receipts require complete metric fields")
        if not performance_receipt and any(
            value is not None for value in metric_fields
        ):
            raise ValueError("metric fields are valid only for performance receipts")
        if performance_receipt != (
            self.window_start is not None and self.window_end is not None
        ):
            raise ValueError(
                "only performance receipts require a complete observation window"
            )
        if performance_receipt:
            if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
                raise ValueError("performance window_end must not precede window_start")
            if self.window_end != self.effective_at:
                raise ValueError(
                    "performance receipt effective_at must equal its window_end"
                )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.receipt_digest and self.receipt_digest != expected_digest:
            raise ValueError("receipt_digest does not match the canonical receipt")
        object.__setattr__(self, "receipt_digest", expected_digest)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_hmac", "receipt_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _product_launch_evaluation_commitment_ref(
    plan_digest: str,
    run_ref: str,
    iteration: int,
) -> str:
    seed = f"{plan_digest}:{run_ref}:iteration:{iteration}".encode("utf-8")
    return f"gtm_eval_{hashlib.sha256(seed).hexdigest()}"


class ProductLaunchIterationEvaluation(_StrictModel):
    """One deterministic decision in the bounded post-launch feedback loop."""

    schema_id: Literal["lightbulb.product_launch_iteration_evaluation.v1"] = Field(
        default=PRODUCT_LAUNCH_ITERATION_EVALUATION_SCHEMA,
        alias="schema",
    )
    plan_digest: Sha256Digest
    exact_scope_digest: Sha256Digest
    run_ref: WorkflowRunRef
    iteration: int = Field(ge=1, le=4)
    commitment_ref: OperationRef
    evaluated_at: str
    previous_evaluation_digest: Sha256Digest | None = None
    primary_metric: PrimaryMetric
    target_value: Decimal = Field(ge=0, le=1, multiple_of=_RATE_QUANTUM)
    observed_value: Decimal = Field(ge=0, le=1, multiple_of=_RATE_QUANTUM)
    target_met: bool
    decision: Literal["target_met", "revise_plan", "iteration_limit_reached"]
    next_iteration: int | None = Field(default=None, ge=2, le=4)
    verified_evidence: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=20)
    summary: str = Field(min_length=1, max_length=500)
    evaluation_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    evaluation_hmac: Sha256Digest
    evaluation_digest: str = ""

    @field_validator("target_value", "observed_value", mode="before")
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("verified_evidence", mode="before")
    @classmethod
    def _immutable_evidence(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _decision_and_digest(self) -> "ProductLaunchIterationEvaluation":
        expected_commitment = _product_launch_evaluation_commitment_ref(
            self.plan_digest,
            self.run_ref,
            self.iteration,
        )
        if self.commitment_ref != expected_commitment:
            raise ValueError(
                "commitment_ref does not match the exact launch run and iteration"
            )
        if (self.iteration == 1) != (self.previous_evaluation_digest is None):
            raise ValueError(
                "only the first iteration may omit previous_evaluation_digest"
            )
        if self.target_met != (self.observed_value >= self.target_value):
            raise ValueError("target_met does not match the immutable KPI threshold")
        if self.decision == "target_met":
            if not self.target_met or self.next_iteration is not None:
                raise ValueError("target_met decisions must stop the loop")
        elif self.decision == "revise_plan":
            if self.target_met or self.next_iteration != self.iteration + 1:
                raise ValueError("revise_plan must advance exactly one iteration")
        elif self.target_met or self.next_iteration is not None:
            raise ValueError("iteration-limit decisions must stop below target")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_digest"},
        )
        expected_digest = _stable_digest(payload)
        if self.evaluation_digest and self.evaluation_digest != expected_digest:
            raise ValueError(
                "evaluation_digest does not match the canonical evaluation"
            )
        object.__setattr__(self, "evaluation_digest", expected_digest)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_hmac", "evaluation_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ProductLaunchEvaluationLoop(_StrictModel):
    loop_ref: OperationRef
    trigger_event: Literal["gtm.product_launch_observation_window_closed"] = (
        "gtm.product_launch_observation_window_closed"
    )
    stages: tuple[
        Literal["baseline", "approve", "materialize", "observe", "evaluate", "revise"],
        ...,
    ]
    primary_metric: PrimaryMetric
    target_value: Decimal = Field(ge=0, le=1, multiple_of=_RATE_QUANTUM)
    minimum_sample_size: int = Field(ge=1, le=1_000_000_000)
    max_observation_age_hours: int = Field(ge=1, le=8_760)
    measurement_window_hours: int = Field(ge=1, le=2_160)
    max_iterations: int = Field(ge=1, le=4)
    observation_capabilities: tuple[str, ...] = Field(min_length=1, max_length=8)
    required_receipt_kinds: tuple[str, ...] = Field(min_length=1, max_length=12)
    stop_conditions: tuple[
        Literal[
            "target_met",
            "iteration_limit_reached",
            "approval_revoked",
            "evidence_missing",
        ],
        ...,
    ]
    fresh_evidence_required: Literal[True] = True
    external_writes_require_new_approval: Literal[True] = True

    @field_validator("target_value", mode="before")
    @classmethod
    def _target_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("observation_capabilities", "required_receipt_kinds")
    @classmethod
    def _unique_lists(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("evaluation loop values must be unique")
        return values

    @field_validator(
        "stages",
        "stop_conditions",
        "observation_capabilities",
        "required_receipt_kinds",
        mode="before",
    )
    @classmethod
    def _immutable_lists(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class ProductLaunchScaleContract(_StrictModel):
    execution_scope: Literal["one_declared_scope_and_project"] = (
        "one_declared_scope_and_project"
    )
    fan_out_key: Literal["scope_fingerprint+project_ref"] = (
        "scope_fingerprint+project_ref"
    )
    scope_binding: Literal["caller_supplied_requires_host_verification"] = (
        "caller_supplied_requires_host_verification"
    )
    max_launches_per_shard: Literal[12] = _MAX_LAUNCHES_PER_SHARD
    max_estimated_operations_per_shard: Literal[100] = 100
    max_serialized_job_bytes: Literal[262144] = _MAX_LAUNCH_JOB_BYTES
    max_serialized_shard_bytes: Literal[4194304] = _MAX_LAUNCH_SHARD_BYTES
    max_serialized_portfolio_bytes: Literal[67108864] = _MAX_LAUNCH_PORTFOLIO_BYTES
    recommended_global_parallelism: Literal[8] = 8
    recommended_parallelism_per_project: Literal[2] = 2
    approval_strategy: Literal["content_bound_per_write_revision"] = (
        "content_bound_per_write_revision"
    )
    operation_estimate_semantics: Literal["initial_graph_only"] = "initial_graph_only"
    resume_strategy: Literal["durable_run_per_launch"] = "durable_run_per_launch"


class ProductLaunchEffectBoundary(_StrictModel):
    connector_calls_made: Literal[0] = 0
    domain_actions_called: Literal[0] = 0
    writes_executed: Literal[0] = 0
    products_created: Literal[0] = 0
    campaigns_created: Literal[0] = 0
    posts_published: Literal[0] = 0


class OmnichannelProductLaunchPlan(_StrictModel):
    schema_id: Literal["lightbulb.omnichannel_product_launch_plan.v1"] = Field(
        default=OMNICHANNEL_PRODUCT_LAUNCH_PLAN_SCHEMA,
        alias="schema",
    )
    primitive_ref: Literal["gtm.plan_omnichannel_product_launch"] = (
        OMNICHANNEL_PRODUCT_LAUNCH_PRIMITIVE_REF
    )
    status: Literal["planned_with_execution_gaps"] = "planned_with_execution_gaps"
    proposal_only: Literal[True] = True
    materialization_supported: Literal[False] = False
    live_systems_changed: Literal[False] = False
    launch_ref: PortableRef
    analysis_as_of: str
    analytics_scope: ProductLaunchEvidenceScope
    optimization_status: Literal[
        "evidence_optimized",
        "partially_evidence_informed",
        "brief_only",
    ]
    business_goal: LongText
    target_audience: LongText
    value_proposition: LongText
    product: LaunchProductBrief
    sales_campaign: SalesCampaignBrief
    connector_account_bindings: tuple[ProductLaunchConnectorAccountBinding, ...] = (
        Field(min_length=3, max_length=5)
    )
    optimization_policy: LaunchOptimizationPolicy
    campaign_materialization: CampaignMaterializationDisposition
    analytics_findings: tuple[AnalyticsFinding, ...] = Field(min_length=1, max_length=8)
    channel_priority: tuple[ChannelPriority, ...] = Field(
        min_length=1,
        max_length=_MAX_SOCIAL_DRAFTS,
    )
    operations: tuple[ProductLaunchOperation, ...] = Field(min_length=5, max_length=8)
    capability_gaps: tuple[ProductLaunchCapabilityGap, ...] = Field(
        min_length=3,
        max_length=12,
    )
    required_receipts: tuple[RequiredLaunchReceipt, ...] = Field(
        min_length=3,
        max_length=12,
    )
    evaluation_loop: ProductLaunchEvaluationLoop
    scale_contract: ProductLaunchScaleContract = Field(
        default_factory=ProductLaunchScaleContract
    )
    effect_boundary: ProductLaunchEffectBoundary = Field(
        default_factory=ProductLaunchEffectBoundary
    )
    summary: str = Field(min_length=1, max_length=1_000)
    plan_hmac: Sha256Digest | None = None
    plan_digest: str = ""

    @field_validator(
        "analytics_findings",
        "channel_priority",
        "connector_account_bindings",
        "operations",
        "capability_gaps",
        "required_receipts",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _valid_operation_graph(self) -> "OmnichannelProductLaunchPlan":
        if (self.analytics_scope.status == "host_hmac_verified") != (
            self.plan_hmac is not None
        ):
            raise ValueError("host-bound plans require a complete plan HMAC")
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("launch operation IDs must be unique")
        known: set[str] = set()
        for expected_ordinal, operation in enumerate(self.operations, start=1):
            if operation.ordinal != expected_ordinal:
                raise ValueError("launch operations must use contiguous ordinals")
            if any(dependency not in known for dependency in operation.depends_on):
                raise ValueError(
                    "operation dependencies must reference earlier operations"
                )
            known.add(operation.operation_id)
        approval_units = [
            operation.approval_unit
            for operation in self.operations
            if operation.approval_required
        ]
        if len(approval_units) != len(set(approval_units)):
            raise ValueError("every launch write requires a separate approval unit")
        priorities = sorted(self.channel_priority, key=lambda item: item.rank)
        if [item.rank for item in priorities] != list(range(1, len(priorities) + 1)):
            raise ValueError("channel priorities must use contiguous ranks")
        if len({item.channel for item in priorities}) != len(priorities):
            raise ValueError("channel priorities must name unique channels")
        expected_capabilities: list[str] = ["ecommerce.create_product"]
        if self.sales_campaign.provider == "hubspot":
            expected_capabilities.append("hubspot.create_campaign")
        expected_capabilities.extend(
            [
                "ecommerce.update_product",
                "shopify.publish_product",
                "gtm.verify_landing_readiness",
            ]
        )
        expected_capabilities.extend(
            f"{priority.channel}.publish_post" for priority in priorities
        )
        if [
            operation.capability for operation in self.operations
        ] != expected_capabilities:
            raise ValueError(
                "launch operations do not match the canonical capability graph"
            )
        by_capability = {
            operation.capability: operation for operation in self.operations
        }
        expected_accounts = {
            ("shopify", self.product.connector_account_ref),
            (
                self.sales_campaign.provider,
                self.sales_campaign.connector_account_ref,
            ),
            *(
                (
                    operation.capability.partition(".")[0],
                    operation.connector_account_ref,
                )
                for operation in self.operations
                if operation.stage == "social_publish"
            ),
        }
        actual_accounts = {
            (binding.provider, binding.connector_account_ref)
            for binding in self.connector_account_bindings
        }
        if len(actual_accounts) != len(self.connector_account_bindings):
            raise ValueError("connector account bindings must be unique")
        if actual_accounts != expected_accounts:
            raise ValueError(
                "connector account bindings must exactly match launch destinations"
            )
        if self.analytics_scope.status == "host_hmac_verified":
            if any(
                binding.receipt_key_id != self.analytics_scope.receipt_key_id
                or binding.exact_scope_digest != self.analytics_scope.exact_scope_digest
                or binding.account_hmac is None
                for binding in self.connector_account_bindings
            ):
                raise ValueError(
                    "host-bound plans require exact-scope connector account bindings"
                )
        elif any(
            binding.account_hmac is not None
            for binding in self.connector_account_bindings
        ):
            raise ValueError(
                "caller-unverified plans cannot carry connector account attestations"
            )
        product = by_capability["ecommerce.create_product"]
        activation = by_capability["ecommerce.update_product"]
        publication = by_capability["shopify.publish_product"]
        readiness = by_capability["gtm.verify_landing_readiness"]
        product_account = self.product.connector_account_ref
        if any(
            operation.connector_account_ref != product_account
            for operation in (product, activation, publication, readiness)
        ):
            raise ValueError("Shopify launch stages must use one connector account")
        if product.depends_on:
            raise ValueError("the product draft must be the graph root")
        if activation.depends_on != (product.operation_id,):
            raise ValueError("product activation must depend exactly on the draft")
        if publication.depends_on != (activation.operation_id,):
            raise ValueError("product publication must depend exactly on activation")
        if readiness.depends_on != (publication.operation_id,):
            raise ValueError("landing readiness must depend exactly on publication")
        campaign = by_capability.get("hubspot.create_campaign")
        if campaign is not None:
            if (
                campaign.connector_account_ref
                != self.sales_campaign.connector_account_ref
                or campaign.depends_on != (product.operation_id,)
            ):
                raise ValueError("HubSpot campaign linkage does not match the brief")
        if self.campaign_materialization.provider != self.sales_campaign.provider:
            raise ValueError("campaign disposition provider does not match the brief")
        if campaign is None:
            if (
                self.campaign_materialization.campaign_container_supported
                or self.campaign_materialization.container_operation_id is not None
            ):
                raise ValueError("campaign disposition claims an absent container")
        elif (
            not self.campaign_materialization.campaign_container_supported
            or self.campaign_materialization.container_operation_id
            != campaign.operation_id
        ):
            raise ValueError("campaign disposition does not match its operation")
        social_dependencies = (readiness.operation_id,) + (
            (campaign.operation_id,) if campaign is not None else ()
        )
        for priority in priorities:
            operation = by_capability[f"{priority.channel}.publish_post"]
            if operation.depends_on != social_dependencies:
                raise ValueError(
                    "social publication must depend on landing readiness and CRM setup"
                )
        expected_receipts = tuple(
            _required_receipts(list(self.operations), launch_ref=self.launch_ref)
        )
        if self.required_receipts != expected_receipts:
            raise ValueError(
                "required receipts do not match the immutable operation graph"
            )
        if self.evaluation_loop.loop_ref != f"loop_{self.launch_ref}" or (
            self.evaluation_loop.primary_metric
            != self.optimization_policy.primary_metric
            or self.evaluation_loop.target_value
            != self.optimization_policy.target_value
            or self.evaluation_loop.minimum_sample_size
            != self.optimization_policy.minimum_sample_size
            or self.evaluation_loop.max_observation_age_hours
            != self.optimization_policy.max_observation_age_hours
            or self.evaluation_loop.measurement_window_hours
            != self.optimization_policy.measurement_window_hours
            or self.evaluation_loop.max_iterations
            != self.optimization_policy.max_iterations
            or self.evaluation_loop.required_receipt_kinds
            != tuple(receipt.evidence_kind for receipt in expected_receipts)
        ):
            raise ValueError(
                "evaluation loop does not match the immutable launch policy"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest", "plan_hmac"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.plan_digest and self.plan_digest != expected_digest:
            raise ValueError("plan_digest does not match the canonical plan payload")
        object.__setattr__(self, "plan_digest", expected_digest)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_hmac"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _parse_plan_input(
    value: PlanOmnichannelProductLaunchInput | Mapping[str, Any],
) -> PlanOmnichannelProductLaunchInput:
    try:
        return PlanOmnichannelProductLaunchInput.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, PlanOmnichannelProductLaunchInput)
            else value
        )
    except ValidationError:
        raise OmnichannelProductLaunchValidationError(
            "Omnichannel product launch brief failed closed-world validation"
        ) from None


def _safe_ratio(numerator: int | None, denominator: int | None) -> Decimal | None:
    if (
        numerator is None
        or denominator is None
        or denominator <= 0
        or numerator > denominator
    ):
        return None
    return (Decimal(numerator) / Decimal(denominator)).quantize(
        _RATE_QUANTUM,
        rounding=ROUND_HALF_UP,
    )


def _metric_values(
    provider: AnalyticsProvider,
    metrics: NormalizedPerformanceMetrics,
) -> dict[PrimaryMetric, Decimal | None]:
    conversion = metrics.conversion_rate
    if conversion is None:
        if provider == "shopify":
            conversion = _safe_ratio(metrics.orders, metrics.sessions)
        else:
            conversion = _safe_ratio(metrics.conversions, metrics.clicks)
    click_through = metrics.click_through_rate
    if click_through is None:
        click_through = _safe_ratio(metrics.clicks, metrics.impressions)
    engagement = metrics.engagement_rate
    if engagement is None:
        engagement = _safe_ratio(metrics.engagements, metrics.impressions)
    pipeline = metrics.pipeline_win_rate
    if pipeline is None:
        pipeline = _safe_ratio(metrics.won_deals, metrics.opportunities)
    return {
        "conversion_rate": conversion,
        "click_through_rate": click_through,
        "engagement_rate": engagement,
        "pipeline_win_rate": pipeline,
    }


def _evidence_scope_binding(
    *,
    verified_scope: DynamicWorkflowScope | Mapping[str, Any] | None,
    scope_keyring: ExactScopeDigestProvider | None,
    scope_key_id: str | None,
) -> ProductLaunchEvidenceScope:
    supplied = (
        verified_scope is not None,
        scope_keyring is not None,
        scope_key_id is not None,
    )
    if not any(supplied):
        return ProductLaunchEvidenceScope(status="caller_supplied_unverified")
    if verified_scope is None or scope_keyring is None:
        raise ValueError(
            "verified_scope and scope_keyring are both required for scope binding"
        )
    scope = (
        verified_scope
        if isinstance(verified_scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(verified_scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    digest = scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    return ProductLaunchEvidenceScope(
        status="host_hmac_verified",
        receipt_key_id=key_id,
        exact_scope_digest=digest,
    )


def mint_product_launch_connector_account_binding(
    value: ProductLaunchConnectorAccountBinding | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> ProductLaunchConnectorAccountBinding:
    """Seal one opaque destination account to an authenticated workflow scope."""

    binding = ProductLaunchConnectorAccountBinding.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, ProductLaunchConnectorAccountBinding)
        else value
    )
    if any(
        field is not None
        for field in (
            binding.receipt_key_id,
            binding.exact_scope_digest,
            binding.account_hmac,
        )
    ):
        raise ValueError("connector account binding is already attested")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    draft = ProductLaunchConnectorAccountBinding(
        provider=binding.provider,
        connector_account_ref=binding.connector_account_ref,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        account_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _PRODUCT_LAUNCH_ACCOUNT_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(mode="python", by_alias=True, exclude_none=True)
    sealed["account_hmac"] = signature
    return ProductLaunchConnectorAccountBinding.model_validate(sealed)


def _account_binding_attestation_matches(
    binding: ProductLaunchConnectorAccountBinding,
    *,
    evidence_scope: ProductLaunchEvidenceScope,
    scope_keyring: ExactScopeDigestProvider | None,
) -> bool:
    if evidence_scope.status != "host_hmac_verified" or scope_keyring is None:
        return False
    if (
        binding.receipt_key_id != evidence_scope.receipt_key_id
        or binding.exact_scope_digest != evidence_scope.exact_scope_digest
        or binding.account_hmac is None
    ):
        return False
    expected_hmac = scope_keyring.sign(
        binding.receipt_key_id,
        _PRODUCT_LAUNCH_ACCOUNT_HMAC_DOMAIN,
        binding.hmac_payload(),
    ).hex()
    return hmac.compare_digest(binding.account_hmac, expected_hmac)


def _destination_account_bindings(
    inputs: PlanOmnichannelProductLaunchInput,
    *,
    evidence_scope: ProductLaunchEvidenceScope,
    scope_keyring: ExactScopeDigestProvider | None,
    connector_account_bindings: Iterable[
        ProductLaunchConnectorAccountBinding | Mapping[str, Any]
    ]
    | None,
) -> tuple[ProductLaunchConnectorAccountBinding, ...]:
    expected_pairs = {
        ("shopify", inputs.product.connector_account_ref),
        (
            inputs.sales_campaign.provider,
            inputs.sales_campaign.connector_account_ref,
        ),
        *(
            (draft.channel, draft.connector_account_ref)
            for draft in inputs.social_drafts
        ),
    }
    if evidence_scope.status != "host_hmac_verified":
        if connector_account_bindings is not None:
            raise ValueError(
                "connector account attestations require verified_scope and scope_keyring"
            )
        return tuple(
            ProductLaunchConnectorAccountBinding(
                provider=provider,
                connector_account_ref=account_ref,
            )
            for provider, account_ref in sorted(expected_pairs)
        )
    if connector_account_bindings is None:
        raise ValueError(
            "verified planning requires connector_account_bindings for every destination"
        )
    parsed: list[ProductLaunchConnectorAccountBinding] = []
    for index, value in enumerate(connector_account_bindings, start=1):
        if index > len(expected_pairs):
            raise ValueError(
                "connector account binding set exceeds launch destinations"
            )
        parsed.append(
            ProductLaunchConnectorAccountBinding.model_validate(
                value.model_dump(mode="python", by_alias=True)
                if isinstance(value, ProductLaunchConnectorAccountBinding)
                else value
            )
        )
    actual_pairs = {
        (binding.provider, binding.connector_account_ref) for binding in parsed
    }
    if len(actual_pairs) != len(parsed) or actual_pairs != expected_pairs:
        raise ValueError(
            "connector account bindings must exactly match every launch destination"
        )
    if any(
        not _account_binding_attestation_matches(
            binding,
            evidence_scope=evidence_scope,
            scope_keyring=scope_keyring,
        )
        for binding in parsed
    ):
        raise ValueError(
            "verified planning requires host-HMAC connector account bindings"
        )
    return tuple(sorted(parsed, key=lambda item: item.provider))


def mint_product_launch_analytics_snapshot(
    value: AnalyticsSnapshot | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> AnalyticsSnapshot:
    """Seal one host-verified connector observation for planning.

    The trusted host should call this only after it has verified the underlying
    connector receipt identified by ``evidence_digest``. The HMAC covers the
    provider, connector account, time window, metrics, evidence digest, and
    exact workflow scope; copying a visible scope digest onto fabricated metrics
    is therefore insufficient to make them trusted.
    """

    snapshot = (
        value
        if isinstance(value, AnalyticsSnapshot)
        else AnalyticsSnapshot.model_validate(value)
    )
    if any(
        field is not None
        for field in (
            snapshot.receipt_key_id,
            snapshot.exact_scope_digest,
            snapshot.snapshot_hmac,
        )
    ):
        raise ValueError("analytics snapshot is already attested")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    payload = snapshot.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "snapshot_hmac": "0" * 64,
        }
    )
    draft = AnalyticsSnapshot.model_validate(payload)
    signature = scope_keyring.sign(
        key_id,
        _PRODUCT_LAUNCH_ANALYTICS_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["snapshot_hmac"] = signature
    return AnalyticsSnapshot.model_validate(sealed)


def _snapshot_attestation_matches(
    snapshot: AnalyticsSnapshot,
    *,
    evidence_scope: ProductLaunchEvidenceScope,
    scope_keyring: ExactScopeDigestProvider | None,
) -> bool:
    if evidence_scope.status != "host_hmac_verified" or scope_keyring is None:
        return False
    if (
        snapshot.receipt_key_id != evidence_scope.receipt_key_id
        or snapshot.exact_scope_digest != evidence_scope.exact_scope_digest
        or snapshot.snapshot_hmac is None
    ):
        return False
    expected_hmac = scope_keyring.sign(
        snapshot.receipt_key_id,
        _PRODUCT_LAUNCH_ANALYTICS_HMAC_DOMAIN,
        snapshot.hmac_payload(),
    ).hex()
    return hmac.compare_digest(snapshot.snapshot_hmac, expected_hmac)


def _snapshot_status(
    snapshot: AnalyticsSnapshot,
    *,
    analysis_at: datetime,
    policy: LaunchOptimizationPolicy,
    evidence_scope: ProductLaunchEvidenceScope,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[AnalyticsEligibility, int, PrimaryMetric | None, Decimal | None]:
    observed_at = _parse_timestamp(snapshot.observed_at)
    window_end = _parse_timestamp(snapshot.window_end)
    if observed_at > analysis_at or window_end > analysis_at:
        return "future_observation", 0, None, None
    seconds = (analysis_at - window_end).total_seconds()
    age_hours = int(seconds // 3_600)
    if (
        evidence_scope.status == "host_hmac_verified"
        and not _snapshot_attestation_matches(
            snapshot,
            evidence_scope=evidence_scope,
            scope_keyring=scope_keyring,
        )
    ):
        return "scope_unverified", age_hours, None, None
    if seconds > policy.max_observation_age_hours * 3_600:
        return "stale", age_hours, None, None
    if snapshot.sample_size < policy.minimum_sample_size:
        return "insufficient_sample", age_hours, None, None
    metrics = _metric_values(snapshot.provider, snapshot.metrics)
    preferred = metrics[policy.primary_metric]
    if preferred is not None:
        return "eligible", age_hours, policy.primary_metric, preferred
    for metric_name in (
        "conversion_rate",
        "click_through_rate",
        "engagement_rate",
        "pipeline_win_rate",
    ):
        value = metrics[metric_name]  # type: ignore[index]
        if value is not None:
            return "eligible", age_hours, metric_name, value  # type: ignore[arg-type]
    return "no_usable_metric", age_hours, None, None


def _required_analytics_providers(
    inputs: PlanOmnichannelProductLaunchInput,
) -> list[AnalyticsProvider]:
    values: list[AnalyticsProvider] = ["shopify", inputs.sales_campaign.provider]
    values.extend(draft.channel for draft in inputs.social_drafts)
    values.extend(snapshot.provider for snapshot in inputs.analytics_snapshots)
    return list(dict.fromkeys(values))


def _analytics_findings(
    inputs: PlanOmnichannelProductLaunchInput,
    *,
    evidence_scope: ProductLaunchEvidenceScope,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[list[AnalyticsFinding], dict[str, AnalyticsSnapshot]]:
    analysis_at = _parse_timestamp(inputs.analysis_as_of)
    snapshots_by_provider: dict[str, list[AnalyticsSnapshot]] = defaultdict(list)
    for snapshot in inputs.analytics_snapshots:
        snapshots_by_provider[snapshot.provider].append(snapshot)
    for snapshots in snapshots_by_provider.values():
        snapshots.sort(
            key=lambda item: (
                _parse_timestamp(item.window_end),
                _parse_timestamp(item.observed_at),
                item.observation_ref,
            ),
            reverse=True,
        )

    findings: list[AnalyticsFinding] = []
    selected: dict[str, AnalyticsSnapshot] = {}
    for provider in _required_analytics_providers(inputs):
        candidates = snapshots_by_provider.get(provider, [])
        if not candidates:
            findings.append(
                AnalyticsFinding(
                    provider=provider,
                    status="missing",
                    rationale=(
                        f"No provenance-bearing {provider} snapshot was supplied; "
                        "the plan does not fabricate performance evidence."
                    ),
                )
            )
            continue

        evaluations = [
            (
                snapshot,
                *_snapshot_status(
                    snapshot,
                    analysis_at=analysis_at,
                    policy=inputs.optimization_policy,
                    evidence_scope=evidence_scope,
                    scope_keyring=scope_keyring,
                ),
            )
            for snapshot in candidates
        ]
        chosen = next(
            (evaluation for evaluation in evaluations if evaluation[1] == "eligible"),
            evaluations[0],
        )
        snapshot, status, age_hours, metric_name, metric_value = chosen
        if status == "eligible":
            selected[provider] = snapshot
            rationale = (
                f"Selected fresh {metric_name} evidence from "
                f"{snapshot.source_capability}."
                if evidence_scope.status == "host_hmac_verified"
                else (
                    f"Ranked caller-supplied {metric_name} evidence from "
                    f"{snapshot.source_capability}; exact scope is not host-verified."
                )
            )
        else:
            rationale = {
                "future_observation": "The newest snapshot occurs after analysis_as_of and is ineligible.",
                "scope_unverified": "The snapshot is not bound to the host-verified exact workflow scope.",
                "stale": "The newest snapshot exceeds the configured evidence age limit.",
                "insufficient_sample": "The newest snapshot does not meet the minimum sample size.",
                "no_usable_metric": "The newest snapshot has no rate usable by this optimization policy.",
                "missing": "No snapshot was supplied.",
                "eligible": "Eligible evidence selected.",
            }[status]
        findings.append(
            AnalyticsFinding(
                provider=provider,
                status=status,
                observation_ref=snapshot.observation_ref,
                connector_account_ref=snapshot.connector_account_ref,
                source_capability=snapshot.source_capability,
                evidence_digest=snapshot.evidence_digest,
                age_hours=age_hours,
                sample_size=snapshot.sample_size,
                selected_metric=metric_name,
                selected_value=metric_value,
                scope_verified=(
                    _snapshot_attestation_matches(
                        snapshot,
                        evidence_scope=evidence_scope,
                        scope_keyring=scope_keyring,
                    )
                ),
                rationale=rationale,
            )
        )
    return findings, selected


def _channel_score(snapshot: AnalyticsSnapshot) -> Decimal | None:
    metrics = _metric_values(snapshot.provider, snapshot.metrics)
    weighted = (
        ("conversion_rate", Decimal("0.50")),
        ("click_through_rate", Decimal("0.30")),
        ("engagement_rate", Decimal("0.20")),
    )
    numerator = Decimal("0")
    denominator = Decimal("0")
    for metric_name, weight in weighted:
        value = metrics[metric_name]  # type: ignore[index]
        if value is not None:
            numerator += value * weight
            denominator += weight
    if denominator == 0:
        return None
    return (numerator / denominator).quantize(
        _RATE_QUANTUM,
        rounding=ROUND_HALF_UP,
    )


def _channel_priorities(
    inputs: PlanOmnichannelProductLaunchInput,
    selected: Mapping[str, AnalyticsSnapshot],
) -> list[ChannelPriority]:
    candidates: list[
        tuple[int, SocialChannel, Decimal | None, AnalyticsSnapshot | None]
    ] = []
    for index, draft in enumerate(inputs.social_drafts):
        snapshot = selected.get(draft.channel)
        score = _channel_score(snapshot) if snapshot is not None else None
        candidates.append((index, draft.channel, score, snapshot))
    candidates.sort(
        key=lambda item: (
            item[2] is None,
            -(item[2] or Decimal("0")),
            item[0],
        )
    )
    priorities: list[ChannelPriority] = []
    for rank, (_, channel, score, snapshot) in enumerate(candidates, start=1):
        priorities.append(
            ChannelPriority(
                rank=rank,
                channel=channel,
                evidence_informed=score is not None,
                score=score,
                observation_ref=(snapshot.observation_ref if snapshot else None),
                rationale=(
                    "Priority is derived from the weighted conversion, click-through, "
                    "and engagement rates in the selected snapshot."
                    if score is not None
                    else "No eligible rate evidence exists; original brief order breaks ties."
                ),
            )
        )
    return priorities


def _operation_id(ordinal: int, kind: str, reference: str) -> str:
    return f"op_{ordinal:03d}_{kind}_{reference}"


def _operation_content_digest(
    capability: str,
    arguments: BaseModel,
    depends_on: Iterable[str],
    connector_account_ref: str,
) -> str:
    return _stable_digest(
        {
            "capability": capability,
            "arguments": arguments.model_dump(
                mode="json",
                exclude={"kind"},
                exclude_none=True,
            ),
            "depends_on": list(depends_on),
            "connector_account_ref": connector_account_ref,
        }
    )


def _approval_unit(
    kind: str,
    reference: str,
    *,
    capability: str,
    arguments: BaseModel,
    connector_account_ref: str,
    depends_on: Iterable[str] = (),
) -> str:
    content_digest = _operation_content_digest(
        capability,
        arguments,
        depends_on,
        connector_account_ref,
    )
    return f"approval_{kind}_{reference}_{content_digest}"


def _operations(
    inputs: PlanOmnichannelProductLaunchInput,
    priorities: Iterable[ChannelPriority],
) -> tuple[list[ProductLaunchOperation], CampaignMaterializationDisposition]:
    operations: list[ProductLaunchOperation] = []
    product_operation_id = _operation_id(1, "product", inputs.product.product_ref)
    product_arguments = ShopifyDraftProductArguments(
        kind="shopify_draft_product",
        title=inputs.product.title,
        description=inputs.product.description,
        vendor=inputs.product.vendor,
        product_type=inputs.product.product_type,
        tags=inputs.product.tags,
        price=f"{inputs.product.price.amount:.2f}",
        sku=inputs.product.sku,
        taxable=inputs.product.taxable,
        requires_shipping=inputs.product.requires_shipping,
    )
    operations.append(
        ProductLaunchOperation(
            ordinal=1,
            operation_id=product_operation_id,
            stage="catalog_materialization",
            execution_kind="connector_tool",
            capability="ecommerce.create_product",
            surface_availability="runtime_registered_not_generated",
            connector_account_ref=inputs.product.connector_account_ref,
            effect="write",
            arguments=product_arguments,
            status="proposal_only_not_executed",
            approval_required=True,
            approval_unit=_approval_unit(
                "product",
                inputs.product.product_ref,
                capability="ecommerce.create_product",
                arguments=product_arguments,
                connector_account_ref=inputs.product.connector_account_ref,
            ),
            receipt_kind="shopify_draft_product_receipt",
        )
    )

    campaign_operation_id: str | None = None
    if inputs.sales_campaign.provider == "hubspot":
        ordinal = len(operations) + 1
        campaign_operation_id = _operation_id(
            ordinal,
            "campaign",
            inputs.launch_ref,
        )
        materialization_context = (
            f"Offer: {inputs.sales_campaign.offer}\n"
            f"Product: {inputs.product.title}\n"
            f"Landing page: {inputs.product.landing_url}"
        )
        notes = (
            f"{inputs.sales_campaign.notes}\n\n{materialization_context}"
            if inputs.sales_campaign.notes
            else materialization_context
        )
        campaign_arguments = HubSpotCampaignContainerArguments(
            kind="hubspot_campaign_container",
            name=inputs.sales_campaign.name,
            startDate=inputs.sales_campaign.start_date,
            endDate=inputs.sales_campaign.end_date,
            goal=inputs.sales_campaign.goal,
            audience=inputs.sales_campaign.audience,
            notes=notes,
        )
        campaign_dependencies = [product_operation_id]
        operations.append(
            ProductLaunchOperation(
                ordinal=ordinal,
                operation_id=campaign_operation_id,
                stage="crm_campaign_container",
                execution_kind="domain_action",
                capability="hubspot.create_campaign",
                surface_availability="domain_agent_only",
                connector_account_ref=inputs.sales_campaign.connector_account_ref,
                effect="write",
                arguments=campaign_arguments,
                depends_on=campaign_dependencies,
                status="proposal_only_not_executed",
                approval_required=True,
                approval_unit=_approval_unit(
                    "campaign",
                    inputs.launch_ref,
                    capability="hubspot.create_campaign",
                    arguments=campaign_arguments,
                    connector_account_ref=(inputs.sales_campaign.connector_account_ref),
                    depends_on=campaign_dependencies,
                ),
                receipt_kind="hubspot_campaign_container_receipt",
            )
        )

    activation_ordinal = len(operations) + 1
    activation_operation_id = _operation_id(
        activation_ordinal,
        "activate_product",
        inputs.product.product_ref,
    )
    activation_arguments = ShopifyActivateProductArguments(
        kind="shopify_activate_product"
    )
    activation_dependencies = [product_operation_id]
    operations.append(
        ProductLaunchOperation(
            ordinal=activation_ordinal,
            operation_id=activation_operation_id,
            stage="catalog_activation",
            execution_kind="connector_tool",
            capability="ecommerce.update_product",
            surface_availability="runtime_registered_not_generated",
            connector_account_ref=inputs.product.connector_account_ref,
            effect="write",
            arguments=activation_arguments,
            depends_on=activation_dependencies,
            input_bindings=[
                ProductLaunchInputBinding(
                    target_field="product_id",
                    source_operation_id=product_operation_id,
                    source_output_field="product_id",
                )
            ],
            status="proposal_only_not_executed",
            approval_required=True,
            approval_unit=_approval_unit(
                "activate_product",
                inputs.product.product_ref,
                capability="ecommerce.update_product",
                arguments=activation_arguments,
                connector_account_ref=inputs.product.connector_account_ref,
                depends_on=activation_dependencies,
            ),
            receipt_kind="shopify_product_activation_receipt",
        )
    )

    publish_ordinal = len(operations) + 1
    publish_operation_id = _operation_id(
        publish_ordinal,
        "publish_product",
        inputs.product.product_ref,
    )
    publish_arguments = ShopifyPublishProductArguments(
        kind="shopify_publish_product",
        publication_ids=inputs.product.publication_ids,
    )
    publish_dependencies = [activation_operation_id]
    operations.append(
        ProductLaunchOperation(
            ordinal=publish_ordinal,
            operation_id=publish_operation_id,
            stage="catalog_publication",
            execution_kind="connector_tool",
            capability="shopify.publish_product",
            surface_availability="runtime_registered_not_generated",
            connector_account_ref=inputs.product.connector_account_ref,
            effect="write",
            arguments=publish_arguments,
            depends_on=publish_dependencies,
            input_bindings=[
                ProductLaunchInputBinding(
                    target_field="product_id",
                    source_operation_id=activation_operation_id,
                    source_output_field="product_id",
                )
            ],
            status="proposal_only_not_executed",
            approval_required=True,
            approval_unit=_approval_unit(
                "publish_product",
                inputs.product.product_ref,
                capability="shopify.publish_product",
                arguments=publish_arguments,
                connector_account_ref=inputs.product.connector_account_ref,
                depends_on=publish_dependencies,
            ),
            receipt_kind="shopify_product_publication_receipt",
        )
    )

    readiness_ordinal = len(operations) + 1
    readiness_operation_id = _operation_id(
        readiness_ordinal,
        "landing_ready",
        inputs.product.product_ref,
    )
    operations.append(
        ProductLaunchOperation(
            ordinal=readiness_ordinal,
            operation_id=readiness_operation_id,
            stage="landing_readiness",
            execution_kind="evidence_gate",
            capability="gtm.verify_landing_readiness",
            surface_availability="sdk_host_evidence_gate",
            connector_account_ref=inputs.product.connector_account_ref,
            effect="read",
            arguments=LandingReadinessArguments(
                kind="landing_readiness_gate",
                landing_url=inputs.product.landing_url,
            ),
            depends_on=[publish_operation_id],
            status="blocked_pending_evidence",
            approval_required=False,
            receipt_kind="live_landing_page_readiness_receipt",
        )
    )

    dependencies = [readiness_operation_id]
    if campaign_operation_id is not None:
        dependencies.append(campaign_operation_id)
    priority_by_channel = {priority.channel: priority.rank for priority in priorities}
    ordered_drafts = sorted(
        inputs.social_drafts,
        key=lambda draft: priority_by_channel[draft.channel],
    )
    for draft in ordered_drafts:
        ordinal = len(operations) + 1
        operation_id = _operation_id(ordinal, draft.channel, inputs.launch_ref)
        if draft.channel == "facebook":
            arguments: LaunchOperationArguments = FacebookPublishArguments(
                kind="facebook_publish",
                page_id=draft.provider_target_id,
                message=draft.body,
                image_url=draft.media_url,
            )
        elif draft.channel == "instagram":
            if draft.media_url is None:  # model validation already fails closed
                raise ValueError("Instagram drafts require media")
            arguments = InstagramPublishArguments(
                kind="instagram_publish",
                instagram_business_account_id=draft.provider_target_id,
                caption=draft.body,
                image_url=draft.media_url,
            )
        else:
            arguments = LinkedInPublishArguments(
                kind="linkedin_publish",
                author_urn=draft.provider_target_id,
                text=draft.body,
                url=draft.link_url or inputs.product.landing_url,
                image_url=draft.media_url,
            )
        operations.append(
            ProductLaunchOperation(
                ordinal=ordinal,
                operation_id=operation_id,
                stage="social_publish",
                execution_kind="connector_tool",
                capability=f"{draft.channel}.publish_post",
                surface_availability="platform_registered_not_generated",
                connector_account_ref=draft.connector_account_ref,
                effect="write",
                arguments=arguments,
                depends_on=dependencies,
                status="proposal_only_not_executed",
                approval_required=True,
                approval_unit=_approval_unit(
                    draft.channel,
                    inputs.launch_ref,
                    capability=f"{draft.channel}.publish_post",
                    arguments=arguments,
                    connector_account_ref=draft.connector_account_ref,
                    depends_on=dependencies,
                ),
                receipt_kind=f"{draft.channel}_publish_receipt",
            )
        )

    disposition = CampaignMaterializationDisposition(
        provider=inputs.sales_campaign.provider,
        container_operation_id=campaign_operation_id,
        campaign_container_supported=campaign_operation_id is not None,
    )
    return operations, disposition


def _capability_gaps(
    inputs: PlanOmnichannelProductLaunchInput,
    findings: list[AnalyticsFinding],
    evidence_scope: ProductLaunchEvidenceScope,
) -> list[ProductLaunchCapabilityGap]:
    social_capabilities = [
        f"{draft.channel}.publish_post" for draft in inputs.social_drafts
    ]
    gaps = [
        ProductLaunchCapabilityGap(
            code="proposal_only_execution_boundary",
            affected_capabilities=[
                "ecommerce.create_product",
                "ecommerce.update_product",
                "shopify.publish_product",
                "gtm.verify_landing_readiness",
                *(
                    ["hubspot.create_campaign"]
                    if inputs.sales_campaign.provider == "hubspot"
                    else []
                ),
                *social_capabilities,
            ],
            blocks_autonomous_launch=True,
            message=(
                "This primitive compiles a plan only. It makes no connector or "
                "domain-agent call and grants no publication authority."
            ),
        ),
        ProductLaunchCapabilityGap(
            code="generated_connector_surface_gap",
            affected_capabilities=[
                "ecommerce.create_product",
                "ecommerce.update_product",
                "shopify.publish_product",
                *social_capabilities,
            ],
            blocks_autonomous_launch=True,
            message=(
                "The operations exist in platform runtimes but are not all exposed "
                "through the SDK's generated MCP connector surface."
            ),
        ),
        ProductLaunchCapabilityGap(
            code="connected_shop_currency_unverified",
            affected_capabilities=[
                "shopify.get_shop_info",
                "ecommerce.create_product",
            ],
            blocks_autonomous_launch=True,
            message=(
                "The requested price is preserved, but the connected Shopify shop "
                "currency was not read or verified."
            ),
        ),
        ProductLaunchCapabilityGap(
            code="shopify_go_live_requires_separate_approval",
            affected_capabilities=[
                "ecommerce.update_product",
                "shopify.publish_product",
            ],
            blocks_autonomous_launch=True,
            message=(
                "Activation and publication are distinct writes with their own "
                "content-bound approvals; draft creation never grants go-live authority."
            ),
        ),
        ProductLaunchCapabilityGap(
            code="landing_readiness_evidence_required",
            affected_capabilities=["gtm.verify_landing_readiness"],
            blocks_autonomous_launch=True,
            message=(
                "Public campaign operations remain blocked until a host verifies "
                "the live page, product, price/currency, and checkout readiness."
            ),
        ),
    ]
    if evidence_scope.status != "host_hmac_verified":
        gaps.append(
            ProductLaunchCapabilityGap(
                code="analytics_scope_unverified",
                affected_capabilities=_observation_capabilities(inputs),
                blocks_autonomous_launch=True,
                message=(
                    "Analytics were supplied by the caller without a host-held "
                    "HMAC binding to exact tenant, company, actor, and project scope."
                ),
            )
        )
    if inputs.sales_campaign.provider == "hubspot":
        gaps.extend(
            [
                ProductLaunchCapabilityGap(
                    code="hubspot_campaign_container_only",
                    affected_capabilities=["hubspot.create_campaign"],
                    blocks_autonomous_launch=True,
                    message=(
                        "hubspot.create_campaign creates a campaign container only; "
                        "it does not author or send a sales sequence."
                    ),
                ),
                ProductLaunchCapabilityGap(
                    code="hubspot_sales_sequence_authoring_unavailable",
                    affected_capabilities=["hubspot.create_campaign"],
                    blocks_autonomous_launch=True,
                    message=(
                        "No typed SDK action currently materializes the planned "
                        "HubSpot sales touches as a sequence."
                    ),
                ),
            ]
        )
    else:
        gaps.append(
            ProductLaunchCapabilityGap(
                code="salesforce_campaign_materialization_unavailable",
                affected_capabilities=["salesforce.pipeline_report"],
                blocks_autonomous_launch=True,
                message=(
                    "The current connector surface can analyze Salesforce pipeline "
                    "data but cannot materialize this campaign plan."
                ),
            )
        )
    if any(
        finding.status != "eligible"
        or finding.selected_metric != inputs.optimization_policy.primary_metric
        for finding in findings
    ):
        gaps.append(
            ProductLaunchCapabilityGap(
                code="analytics_evidence_incomplete",
                affected_capabilities=[
                    sorted(_SOURCE_CAPABILITIES[finding.provider])[0]
                    for finding in findings
                    if finding.status != "eligible"
                ],
                blocks_autonomous_launch=False,
                message=(
                    "One or more required analytics sources are missing, scope-"
                    "unverified, stale, future-dated, undersampled, or lack a "
                    "usable primary metric."
                ),
            )
        )
    channels = {draft.channel for draft in inputs.social_drafts}
    if "instagram" in channels:
        gaps.append(
            ProductLaunchCapabilityGap(
                code="instagram_native_scheduling_unavailable",
                affected_capabilities=["instagram.schedule_post"],
                blocks_autonomous_launch=False,
                message=(
                    "The native Instagram adapter rejects scheduled publishing; "
                    "this plan proposes an approval-gated publish operation only."
                ),
            )
        )
    if "linkedin" in channels:
        gaps.append(
            ProductLaunchCapabilityGap(
                code="linkedin_schedule_is_immediate_publish",
                affected_capabilities=["linkedin.schedule_post"],
                blocks_autonomous_launch=False,
                message=(
                    "The current LinkedIn schedule route publishes immediately, so "
                    "this plan never represents it as scheduling."
                ),
            )
        )
    if inputs.product.variants:
        gaps.append(
            ProductLaunchCapabilityGap(
                code="typed_product_variant_creation_unavailable",
                affected_capabilities=["ecommerce.create_product"],
                blocks_autonomous_launch=True,
                message=(
                    "The default product can be proposed, but additional requested "
                    "variants are not represented by the typed create contract."
                ),
            )
        )
    return gaps


def _required_receipts(
    operations: list[ProductLaunchOperation],
    *,
    launch_ref: str,
) -> list[RequiredLaunchReceipt]:
    evidence_launch_ref = launch_ref.replace("-", "_")
    receipts = [
        RequiredLaunchReceipt(
            criterion_id=f"operation-{operation.ordinal:02d}",
            receipt_kind=operation.receipt_kind,
            evidence_kind=(
                f"{operation.receipt_kind}_{operation.operation_digest[:12]}"
            ),
            operation_id=operation.operation_id,
            operation_digest=operation.operation_digest,
            approval_unit=operation.approval_unit,
            proves=(
                (
                    f"The approved {operation.capability} operation completed inside "
                    "the authenticated project scope."
                )
                if operation.approval_required
                else (
                    f"The {operation.capability} evidence gate passed inside the "
                    "authenticated project scope."
                )
            ),
        )
        for operation in operations
    ]
    receipts.extend(
        [
            RequiredLaunchReceipt(
                criterion_id="post-launch-performance",
                receipt_kind="gtm_performance_snapshot",
                evidence_kind=f"gtm_performance_snapshot_{evidence_launch_ref}",
                proves="Fresh post-launch metrics were captured with provenance.",
            ),
            RequiredLaunchReceipt(
                criterion_id="exact-scope-attestation",
                receipt_kind="scope_attestation",
                evidence_kind=f"scope_attestation_{evidence_launch_ref}",
                proves="Tenant, company, actor, and project scope remained exact.",
            ),
        ]
    )
    return receipts


def _observation_capabilities(
    inputs: PlanOmnichannelProductLaunchInput,
) -> list[str]:
    return [
        sorted(_SOURCE_CAPABILITIES[provider])[0]
        for provider in _required_analytics_providers(inputs)
    ]


def _stable_digest(value: Mapping[str, Any] | list[Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _serialized_size_bytes(value: Any) -> int:
    return len(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    )


def plan_omnichannel_product_launch(
    value: PlanOmnichannelProductLaunchInput | Mapping[str, Any],
    *,
    verified_scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
    connector_account_bindings: Iterable[
        ProductLaunchConnectorAccountBinding | Mapping[str, Any]
    ]
    | None = None,
) -> OmnichannelProductLaunchPlan:
    """Compile one deterministic, evidence-aware product-launch operation graph."""

    inputs = _parse_plan_input(value)
    evidence_scope = _evidence_scope_binding(
        verified_scope=verified_scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )
    destination_bindings = _destination_account_bindings(
        inputs,
        evidence_scope=evidence_scope,
        scope_keyring=scope_keyring,
        connector_account_bindings=connector_account_bindings,
    )
    findings, selected = _analytics_findings(
        inputs,
        evidence_scope=evidence_scope,
        scope_keyring=scope_keyring,
    )
    priorities = _channel_priorities(inputs, selected)
    operations, campaign_disposition = _operations(inputs, priorities)
    gaps = _capability_gaps(inputs, findings, evidence_scope)
    receipts = _required_receipts(operations, launch_ref=inputs.launch_ref)
    eligible_count = sum(finding.status == "eligible" for finding in findings)
    primary_evidence_count = sum(
        finding.status == "eligible"
        and finding.selected_metric == inputs.optimization_policy.primary_metric
        for finding in findings
    )
    if evidence_scope.status == "host_hmac_verified" and primary_evidence_count == len(
        findings
    ):
        optimization_status = "evidence_optimized"
    elif eligible_count:
        optimization_status = "partially_evidence_informed"
    else:
        optimization_status = "brief_only"
    loop = ProductLaunchEvaluationLoop(
        loop_ref=f"loop_{inputs.launch_ref}",
        stages=(
            "baseline",
            "approve",
            "materialize",
            "observe",
            "evaluate",
            "revise",
        ),
        primary_metric=inputs.optimization_policy.primary_metric,
        target_value=inputs.optimization_policy.target_value,
        minimum_sample_size=inputs.optimization_policy.minimum_sample_size,
        max_observation_age_hours=(
            inputs.optimization_policy.max_observation_age_hours
        ),
        measurement_window_hours=(inputs.optimization_policy.measurement_window_hours),
        max_iterations=inputs.optimization_policy.max_iterations,
        observation_capabilities=_observation_capabilities(inputs),
        required_receipt_kinds=[receipt.evidence_kind for receipt in receipts],
        stop_conditions=(
            "target_met",
            "iteration_limit_reached",
            "approval_revoked",
            "evidence_missing",
        ),
    )
    summary = (
        f"Compiled a {len(operations)}-operation graph with "
        f"{sum(operation.approval_required for operation in operations)} "
        "content-bound write approval(s) and a "
        f"{loop.max_iterations}-iteration evidence loop. No connector or domain "
        "action was called and no live system changed."
    )
    draft = OmnichannelProductLaunchPlan(
        launch_ref=inputs.launch_ref,
        analysis_as_of=inputs.analysis_as_of,
        analytics_scope=evidence_scope,
        optimization_status=optimization_status,
        business_goal=inputs.business_goal,
        target_audience=inputs.target_audience,
        value_proposition=inputs.value_proposition,
        product=inputs.product,
        sales_campaign=inputs.sales_campaign,
        connector_account_bindings=destination_bindings,
        optimization_policy=inputs.optimization_policy,
        campaign_materialization=campaign_disposition,
        analytics_findings=findings,
        channel_priority=priorities,
        operations=operations,
        capability_gaps=gaps,
        required_receipts=receipts,
        evaluation_loop=loop,
        summary=summary,
        plan_hmac=("0" * 64 if evidence_scope.status == "host_hmac_verified" else None),
    )
    if evidence_scope.status != "host_hmac_verified":
        return draft
    if scope_keyring is None or evidence_scope.receipt_key_id is None:
        raise ValueError("host-bound planning requires a complete signing keyring")
    signature = scope_keyring.sign(
        evidence_scope.receipt_key_id,
        _PRODUCT_LAUNCH_PLAN_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"plan_hmac"},
        exclude_none=True,
    )
    sealed["plan_hmac"] = signature
    return OmnichannelProductLaunchPlan.model_validate(sealed)


def _revalidate_product_launch_plan(
    plan: OmnichannelProductLaunchPlan,
) -> OmnichannelProductLaunchPlan:
    """Re-run digest and graph validators even for model_copy-created instances."""

    if not isinstance(plan, OmnichannelProductLaunchPlan):
        raise TypeError("plan must be an OmnichannelProductLaunchPlan")
    return OmnichannelProductLaunchPlan.model_validate(
        plan.model_dump(mode="python", by_alias=True)
    )


def _default_product_launch_run_ref(plan: OmnichannelProductLaunchPlan) -> str:
    return f"gtm-{plan.launch_ref}-{plan.plan_digest[:12]}"


def _product_launch_run_ref(
    plan: OmnichannelProductLaunchPlan,
    run_ref: str | None,
) -> str:
    value = _default_product_launch_run_ref(plan) if run_ref is None else run_ref
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        raise ValueError("run_ref must be a non-empty string of at most 200 characters")
    return _bounded_text(value)


def create_product_launch_evaluation_loop(
    plan: OmnichannelProductLaunchPlan,
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    created_at: datetime,
    run_ref: str | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
) -> DynamicWorkflowState:
    """Create a real bounded planner-builder-evaluator state for a launch plan.

    Authority scope is supplied separately from the business brief, so tenant,
    company, user, and project identifiers never become persisted primitive
    inputs or connector arguments.
    """

    plan = _revalidate_product_launch_plan(plan)
    if plan.analytics_scope.status != "host_hmac_verified":
        raise ValueError(
            "evaluation loops require a host-HMAC-bound launch plan; re-plan with "
            "verified_scope and scope_keyring"
        )
    if scope_keyring is None:
        raise ValueError(
            "scope_keyring is required to verify the plan's exact-scope binding"
        )
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("created_at must include a UTC offset")
    start_time = created_at.astimezone(timezone.utc)
    if start_time < _parse_timestamp(plan.analysis_as_of):
        raise ValueError("created_at must not precede plan.analysis_as_of")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    _require_product_launch_scope_binding(
        plan,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    criteria = [
        AcceptanceCriterion(
            criterion_id=receipt.criterion_id,
            description=(
                f"{receipt.proves} Plan binding: {plan.plan_digest}; "
                f"operation binding: {receipt.operation_digest or 'plan-level'}."
            ),
            required_evidence=(receipt.evidence_kind,),
        )
        for receipt in plan.required_receipts
    ]
    iterations = plan.evaluation_loop.max_iterations
    return DynamicWorkflowState.create(
        scope=workflow_scope,
        run_ref=_product_launch_run_ref(plan, run_ref),
        objective=(
            f"Execute and evaluate product launch {plan.launch_ref} from immutable "
            f"plan {plan.plan_digest}."
        ),
        acceptance_criteria=criteria,
        created_at=start_time,
        limits=WorkflowLimits(
            max_plan_revisions=iterations,
            max_build_attempts=iterations,
            max_evaluation_attempts=iterations,
            max_iterations=iterations,
            max_elapsed_seconds=min(
                31_536_000,
                plan.evaluation_loop.measurement_window_hours
                * (iterations + 1)
                * 3_600,
            ),
        ),
    )


def _require_product_launch_scope_binding(
    plan: OmnichannelProductLaunchPlan,
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> tuple[DynamicWorkflowScope, str, str]:
    if plan.analytics_scope.status != "host_hmac_verified":
        raise ValueError("launch plan is not bound to a host-verified exact scope")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = plan.analytics_scope.receipt_key_id
    expected = plan.analytics_scope.exact_scope_digest
    if key_id is None or expected is None:
        raise ValueError("launch plan has an incomplete exact-scope binding")
    actual = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(actual, expected):
        raise ValueError("workflow scope does not match the launch plan binding")
    if plan.plan_hmac is None:
        raise ValueError("launch plan has no host HMAC")
    expected_plan_hmac = scope_keyring.sign(
        key_id,
        _PRODUCT_LAUNCH_PLAN_HMAC_DOMAIN,
        plan.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(plan.plan_hmac, expected_plan_hmac):
        raise ValueError("launch plan HMAC verification failed")
    if any(
        not _account_binding_attestation_matches(
            binding,
            evidence_scope=plan.analytics_scope,
            scope_keyring=scope_keyring,
        )
        for binding in plan.connector_account_bindings
    ):
        raise ValueError("launch connector account binding HMAC verification failed")
    return workflow_scope, key_id, expected


def verify_product_launch_plan(
    value: OmnichannelProductLaunchPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> OmnichannelProductLaunchPlan:
    """Authenticate one host-bound launch plan for trusted downstream use.

    Planning remains side-effect free.  This helper is the public host-side
    admission check for materializers and evaluators: it re-runs every model
    and graph invariant, verifies the exact tenant/company/user/project scope,
    checks the plan HMAC, and checks every destination-account attestation.
    """

    plan = (
        _revalidate_product_launch_plan(value)
        if isinstance(value, OmnichannelProductLaunchPlan)
        else OmnichannelProductLaunchPlan.model_validate(value)
    )
    _require_product_launch_scope_binding(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    return plan


def mint_product_launch_receipt(
    plan: OmnichannelProductLaunchPlan,
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    criterion_id: str,
    receipt_ref: str,
    issuer_ref: str,
    evidence_digest: str,
    issued_at: str,
    effective_at: str,
    window_start: str | None = None,
    window_end: str | None = None,
    run_ref: str | None = None,
    iteration: int = 1,
    sample_size: int | None = None,
    primary_metric: PrimaryMetric | None = None,
    metric_value: Decimal | str | None = None,
    approval_receipt_digest: str | None = None,
) -> ProductLaunchReceipt:
    """Mint evidence only after a trusted host verifies the underlying artifact."""

    plan = _revalidate_product_launch_plan(plan)
    if isinstance(iteration, bool) or not isinstance(iteration, int):
        raise ValueError("iteration must be an integer")
    if not 1 <= iteration <= plan.optimization_policy.max_iterations:
        raise ValueError("iteration is outside the plan's bounded loop")
    resolved_run_ref = _product_launch_run_ref(plan, run_ref)
    _, key_id, exact_scope_digest = _require_product_launch_scope_binding(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    try:
        requirement = next(
            receipt
            for receipt in plan.required_receipts
            if receipt.criterion_id == criterion_id
        )
    except StopIteration:
        raise ValueError("criterion_id is not required by this launch plan") from None
    metric_receipt = requirement.receipt_kind == "gtm_performance_snapshot"
    metric_fields = (sample_size, primary_metric, metric_value)
    if metric_receipt and any(value is None for value in metric_fields):
        raise ValueError(
            "performance receipts require sample_size, primary_metric, and metric_value"
        )
    if not metric_receipt and any(value is not None for value in metric_fields):
        raise ValueError("metric fields are valid only for performance receipts")
    window_fields = (window_start, window_end)
    if metric_receipt and any(value is None for value in window_fields):
        raise ValueError("performance receipts require a complete observation window")
    if not metric_receipt and any(value is not None for value in window_fields):
        raise ValueError("observation windows are valid only for performance receipts")
    approval_required = requirement.approval_unit is not None
    if approval_required != (approval_receipt_digest is not None):
        raise ValueError(
            "write operation receipts require one content-bound approval receipt digest"
        )
    draft = ProductLaunchReceipt(
        receipt_ref=receipt_ref,
        criterion_id=requirement.criterion_id,
        receipt_kind=requirement.receipt_kind,
        evidence_kind=requirement.evidence_kind,
        plan_digest=plan.plan_digest,
        exact_scope_digest=exact_scope_digest,
        run_ref=resolved_run_ref,
        iteration=iteration,
        operation_id=requirement.operation_id,
        operation_digest=requirement.operation_digest,
        approval_unit=requirement.approval_unit,
        approval_receipt_digest=approval_receipt_digest,
        issuer_ref=issuer_ref,
        evidence_digest=evidence_digest,
        issued_at=issued_at,
        effective_at=effective_at,
        window_start=window_start,
        window_end=window_end,
        sample_size=sample_size,
        primary_metric=primary_metric,
        metric_value=metric_value,
        receipt_key_id=key_id,
        receipt_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _PRODUCT_LAUNCH_RECEIPT_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"receipt_digest"},
        exclude_none=True,
    )
    sealed["receipt_hmac"] = signature
    return ProductLaunchReceipt.model_validate(sealed)


def verify_product_launch_receipts(
    plan: OmnichannelProductLaunchPlan,
    receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    evaluated_at: datetime,
    run_ref: str | None = None,
    iteration: int = 1,
    evidence_after: datetime | None = None,
) -> tuple[EvidenceRef, ...]:
    """Verify a complete receipt set before admitting it to Dynamic Workflow."""

    plan = _revalidate_product_launch_plan(plan)
    if isinstance(iteration, bool) or not isinstance(iteration, int):
        raise ValueError("iteration must be an integer")
    if not 1 <= iteration <= plan.optimization_policy.max_iterations:
        raise ValueError("iteration is outside the plan's bounded loop")
    resolved_run_ref = _product_launch_run_ref(plan, run_ref)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must include a UTC offset")
    evaluation_time = evaluated_at.astimezone(timezone.utc)
    if evidence_after is not None:
        if evidence_after.tzinfo is None or evidence_after.utcoffset() is None:
            raise ValueError("evidence_after must include a UTC offset")
        evidence_cutoff = evidence_after.astimezone(timezone.utc)
    else:
        if iteration > 1:
            raise ValueError(
                "later iterations require the previous evaluation evidence cutoff"
            )
        evidence_cutoff = _parse_timestamp(plan.analysis_as_of)
    if evidence_cutoff >= evaluation_time:
        raise ValueError("evidence cutoff must precede evaluated_at")
    _, key_id, exact_scope_digest = _require_product_launch_scope_binding(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    parsed: list[ProductLaunchReceipt] = []
    maximum_receipts = len(plan.required_receipts)
    try:
        for index, value in enumerate(receipts, start=1):
            if index > maximum_receipts:
                raise ValueError("receipt set exceeds the launch acceptance criteria")
            parsed.append(
                ProductLaunchReceipt.model_validate(
                    value.model_dump(mode="python", by_alias=True)
                    if isinstance(value, ProductLaunchReceipt)
                    else value
                )
            )
    except ValidationError:
        raise OmnichannelProductLaunchValidationError(
            "Product launch receipts failed closed-world validation"
        ) from None
    by_criterion = {receipt.criterion_id: receipt for receipt in parsed}
    if len(by_criterion) != len(parsed):
        raise ValueError("product launch receipt criteria must be unique")
    receipt_refs = [receipt.receipt_ref for receipt in parsed]
    if len(receipt_refs) != len(set(receipt_refs)):
        raise ValueError("product launch receipt_ref values must be unique")
    required = {receipt.criterion_id: receipt for receipt in plan.required_receipts}
    if set(by_criterion) != set(required):
        raise ValueError("receipt set must exactly match launch acceptance criteria")
    operation_effective_times = [
        _parse_timestamp(receipt.effective_at)
        for receipt in parsed
        if receipt.operation_id is not None
    ]
    if not operation_effective_times:
        raise ValueError("receipt set contains no completed launch operations")
    latest_operation_effective_at = max(operation_effective_times)

    evidence: list[EvidenceRef] = []
    analysis_time = _parse_timestamp(plan.analysis_as_of)
    for criterion_id in sorted(required):
        expected = required[criterion_id]
        receipt = by_criterion[criterion_id]
        if receipt.receipt_key_id != key_id:
            raise ValueError("receipt key does not match the launch scope binding")
        if not hmac.compare_digest(receipt.exact_scope_digest, exact_scope_digest):
            raise ValueError("receipt scope does not match the launch plan")
        if receipt.plan_digest != plan.plan_digest:
            raise ValueError("receipt plan digest does not match the launch plan")
        if receipt.run_ref != resolved_run_ref or receipt.iteration != iteration:
            raise ValueError("receipt does not match the exact loop run and iteration")
        if (
            receipt.receipt_kind != expected.receipt_kind
            or receipt.evidence_kind != expected.evidence_kind
            or receipt.operation_id != expected.operation_id
            or receipt.operation_digest != expected.operation_digest
            or receipt.approval_unit != expected.approval_unit
        ):
            raise ValueError("receipt does not match its immutable launch criterion")
        if (expected.approval_unit is not None) != (
            receipt.approval_receipt_digest is not None
        ):
            raise ValueError("receipt approval evidence does not match its criterion")
        expected_hmac = scope_keyring.sign(
            key_id,
            _PRODUCT_LAUNCH_RECEIPT_HMAC_DOMAIN,
            receipt.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(receipt.receipt_hmac, expected_hmac):
            raise ValueError("receipt HMAC verification failed")
        issued_at = _parse_timestamp(receipt.issued_at)
        effective_at = _parse_timestamp(receipt.effective_at)
        if issued_at > evaluation_time:
            raise ValueError("future-issued receipts are not admissible")
        if issued_at <= evidence_cutoff:
            raise ValueError("receipt attestation is not fresh for this iteration")
        if effective_at < analysis_time:
            raise ValueError("receipt predates the launch evidence cutoff")
        if receipt.receipt_kind == "gtm_performance_snapshot":
            if receipt.window_start is None or receipt.window_end is None:
                raise ValueError("performance receipt has no observation window")
            window_start = _parse_timestamp(receipt.window_start)
            window_end = _parse_timestamp(receipt.window_end)
            if window_start <= latest_operation_effective_at:
                raise ValueError(
                    "performance observation window must start after every launch "
                    "operation completed"
                )
            if window_start < evidence_cutoff:
                raise ValueError(
                    "performance observation window predates this iteration"
                )
            window_seconds = (window_end - window_start).total_seconds()
            if (
                window_seconds
                < plan.optimization_policy.measurement_window_hours * 3_600
            ):
                raise ValueError(
                    "performance observation window is shorter than the policy"
                )
            if effective_at <= evidence_cutoff:
                raise ValueError(
                    "post-launch performance is not fresh for this iteration"
                )
            age_seconds = (evaluation_time - effective_at).total_seconds()
            if age_seconds > plan.optimization_policy.max_observation_age_hours * 3_600:
                raise ValueError("post-launch performance receipt is stale")
            if (
                receipt.sample_size is None
                or receipt.sample_size < plan.optimization_policy.minimum_sample_size
                or receipt.primary_metric != plan.optimization_policy.primary_metric
                or receipt.metric_value is None
            ):
                raise ValueError(
                    "post-launch performance receipt does not satisfy optimization policy"
                )
        evidence.append(
            EvidenceRef(
                ref=(
                    "lightbulb-product-launch-receipt:"
                    f"{resolved_run_ref}:i{iteration}:{receipt.receipt_ref}"
                ),
                sha256=receipt.receipt_digest,
                kind=receipt.evidence_kind,
                media_type="application/vnd.lightbulb.product-launch-receipt+json",
            )
        )
    return tuple(evidence)


def evaluate_product_launch_iteration(
    plan: OmnichannelProductLaunchPlan,
    receipts: Iterable[ProductLaunchReceipt | Mapping[str, Any]],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    evaluated_at: datetime,
    iteration: int,
    run_ref: str | None = None,
    previous_evaluation: ProductLaunchIterationEvaluation
    | Mapping[str, Any]
    | None = None,
) -> ProductLaunchIterationEvaluation:
    """Verify evidence and choose stop-or-revise for one bounded loop iteration."""

    plan = _revalidate_product_launch_plan(plan)
    if isinstance(iteration, bool) or not isinstance(iteration, int):
        raise ValueError("iteration must be an integer")
    if not 1 <= iteration <= plan.optimization_policy.max_iterations:
        raise ValueError("iteration is outside the plan's bounded loop")
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("evaluated_at must include a UTC offset")
    evaluation_time = evaluated_at.astimezone(timezone.utc)
    resolved_run_ref = _product_launch_run_ref(plan, run_ref)
    _, key_id, exact_scope_digest = _require_product_launch_scope_binding(
        plan,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    prior: ProductLaunchIterationEvaluation | None = None
    if previous_evaluation is not None:
        try:
            prior = ProductLaunchIterationEvaluation.model_validate(
                previous_evaluation.model_dump(mode="python", by_alias=True)
                if isinstance(previous_evaluation, ProductLaunchIterationEvaluation)
                else previous_evaluation
            )
        except ValidationError:
            raise OmnichannelProductLaunchValidationError(
                "Previous product launch evaluation failed closed-world validation"
            ) from None
    if iteration == 1:
        if prior is not None:
            raise ValueError("the first iteration must not have a previous evaluation")
        evidence_after = None
    else:
        if prior is None:
            raise ValueError("later iterations require the previous evaluation")
        if (
            prior.plan_digest != plan.plan_digest
            or prior.exact_scope_digest != exact_scope_digest
            or prior.run_ref != resolved_run_ref
            or prior.iteration != iteration - 1
            or prior.decision != "revise_plan"
            or prior.next_iteration != iteration
            or prior.evaluation_key_id != key_id
        ):
            raise ValueError(
                "previous evaluation does not authorize this exact next iteration"
            )
        expected_prior_hmac = scope_keyring.sign(
            key_id,
            _PRODUCT_LAUNCH_EVALUATION_HMAC_DOMAIN,
            prior.hmac_payload(),
        ).hex()
        if not hmac.compare_digest(prior.evaluation_hmac, expected_prior_hmac):
            raise ValueError("previous evaluation HMAC verification failed")
        evidence_after = _parse_timestamp(prior.evaluated_at)
        if evidence_after >= evaluation_time:
            raise ValueError("previous evaluation must precede evaluated_at")
    receipt_values: list[ProductLaunchReceipt | Mapping[str, Any]] = []
    maximum_receipts = len(plan.required_receipts)
    for index, receipt in enumerate(receipts, start=1):
        if index > maximum_receipts:
            raise ValueError("receipt set exceeds the launch acceptance criteria")
        receipt_values.append(receipt)
    verified_evidence = verify_product_launch_receipts(
        plan,
        receipt_values,
        scope=scope,
        scope_keyring=scope_keyring,
        evaluated_at=evaluated_at,
        run_ref=resolved_run_ref,
        iteration=iteration,
        evidence_after=evidence_after,
    )
    parsed = [
        ProductLaunchReceipt.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, ProductLaunchReceipt)
            else value
        )
        for value in receipt_values
    ]
    performance_receipt = next(
        receipt
        for receipt in parsed
        if receipt.receipt_kind == "gtm_performance_snapshot"
    )
    observed_value = performance_receipt.metric_value
    if observed_value is None:  # verified above; retain fail-closed local invariant
        raise ValueError("verified performance receipt is missing a metric value")
    canonical_evaluation_time = max(
        _parse_timestamp(receipt.issued_at) for receipt in parsed
    )
    target = plan.optimization_policy.target_value
    target_met = observed_value >= target
    if target_met:
        decision = "target_met"
        next_iteration = None
    elif iteration >= plan.optimization_policy.max_iterations:
        decision = "iteration_limit_reached"
        next_iteration = None
    else:
        decision = "revise_plan"
        next_iteration = iteration + 1
    summary = (
        f"Iteration {iteration} observed {plan.optimization_policy.primary_metric} "
        f"{observed_value} against target {target}: {decision}."
    )
    draft = ProductLaunchIterationEvaluation(
        plan_digest=plan.plan_digest,
        exact_scope_digest=exact_scope_digest,
        run_ref=resolved_run_ref,
        iteration=iteration,
        commitment_ref=_product_launch_evaluation_commitment_ref(
            plan.plan_digest,
            resolved_run_ref,
            iteration,
        ),
        evaluated_at=canonical_evaluation_time.isoformat().replace("+00:00", "Z"),
        previous_evaluation_digest=(prior.evaluation_digest if prior else None),
        primary_metric=plan.optimization_policy.primary_metric,
        target_value=target,
        observed_value=observed_value,
        target_met=target_met,
        decision=decision,
        next_iteration=next_iteration,
        verified_evidence=verified_evidence,
        summary=summary,
        evaluation_key_id=key_id,
        evaluation_hmac="0" * 64,
    )
    signature = scope_keyring.sign(
        key_id,
        _PRODUCT_LAUNCH_EVALUATION_HMAC_DOMAIN,
        draft.hmac_payload(),
    ).hex()
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"evaluation_digest"},
        exclude_none=True,
    )
    sealed["evaluation_hmac"] = signature
    return ProductLaunchIterationEvaluation.model_validate(sealed)


class ScopedProductLaunchJob(_StrictModel):
    job_ref: PortableRef
    scope_fingerprint: Sha256Digest
    project_ref: PortableRef
    launch: PlanOmnichannelProductLaunchInput

    @field_validator("launch", mode="before")
    @classmethod
    def _revalidate_launch(cls, value: Any) -> PlanOmnichannelProductLaunchInput:
        return PlanOmnichannelProductLaunchInput.model_validate(
            value.model_dump(mode="python", by_alias=True)
            if isinstance(value, PlanOmnichannelProductLaunchInput)
            else value
        )

    @model_validator(mode="after")
    def _bounded_serialized_job(self) -> "ScopedProductLaunchJob":
        if _serialized_size_bytes(self.model_dump(mode="json")) > _MAX_LAUNCH_JOB_BYTES:
            raise ValueError(
                f"launch job exceeds {_MAX_LAUNCH_JOB_BYTES} serialized bytes"
            )
        return self


class ProductLaunchShard(_StrictModel):
    schema_id: Literal["lightbulb.product_launch_shard.v1"] = Field(
        default=PRODUCT_LAUNCH_SHARD_SCHEMA,
        alias="schema",
    )
    shard_ref: OperationRef
    scope_fingerprint: Sha256Digest
    project_ref: PortableRef
    project_shard_index: int = Field(ge=1)
    project_shard_count: int = Field(ge=1)
    jobs: tuple[ScopedProductLaunchJob, ...] = Field(
        min_length=1,
        max_length=_MAX_LAUNCHES_PER_SHARD,
    )
    estimated_operation_count: int = Field(ge=2, le=100)
    execution_scope: Literal["one_declared_scope_and_project"] = (
        "one_declared_scope_and_project"
    )
    recommended_parallelism: int = Field(default=2, ge=1, le=2)
    shard_digest: str = ""

    @field_validator("jobs", mode="before")
    @classmethod
    def _immutable_jobs(cls, value: Any) -> Any:
        values = _immutable_sequence(value)
        return tuple(
            ScopedProductLaunchJob.model_validate(
                item.model_dump(mode="python", by_alias=True)
                if isinstance(item, ScopedProductLaunchJob)
                else item
            )
            for item in values
        )

    @model_validator(mode="after")
    def _one_exact_scope(self) -> "ProductLaunchShard":
        if any(
            job.scope_fingerprint != self.scope_fingerprint
            or job.project_ref != self.project_ref
            for job in self.jobs
        ):
            raise ValueError(
                "a product launch shard cannot cross authenticated scope or project"
            )
        expected_operation_count = sum(_estimated_operations(job) for job in self.jobs)
        if self.estimated_operation_count != expected_operation_count:
            raise ValueError("estimated_operation_count does not match shard jobs")
        job_identities = [
            (job.scope_fingerprint, job.project_ref, job.job_ref) for job in self.jobs
        ]
        if len(job_identities) != len(set(job_identities)):
            raise ValueError("job_ref values must be unique within a shard")
        launch_identities = [
            (job.scope_fingerprint, job.project_ref, job.launch.launch_ref)
            for job in self.jobs
        ]
        if len(launch_identities) != len(set(launch_identities)):
            raise ValueError("launch_ref values must be unique within a shard")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"shard_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.shard_digest and self.shard_digest != expected_digest:
            raise ValueError("shard_digest does not match the canonical shard payload")
        sealed_payload = {**payload, "shard_digest": expected_digest}
        if _serialized_size_bytes(sealed_payload) > _MAX_LAUNCH_SHARD_BYTES:
            raise ValueError("product launch shard exceeds the serialized byte budget")
        object.__setattr__(self, "shard_digest", expected_digest)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ProductLaunchPortfolioPlan(_StrictModel):
    schema_id: Literal["lightbulb.product_launch_portfolio.v1"] = Field(
        default=PRODUCT_LAUNCH_PORTFOLIO_SCHEMA,
        alias="schema",
    )
    project_count: int = Field(ge=1, le=_MAX_PORTFOLIO_LAUNCHES)
    launch_count: int = Field(ge=1, le=_MAX_PORTFOLIO_LAUNCHES)
    shard_count: int = Field(ge=1, le=_MAX_PORTFOLIO_LAUNCHES)
    estimated_operation_count: int = Field(ge=2)
    shards: tuple[ProductLaunchShard, ...] = Field(
        min_length=1,
        max_length=_MAX_PORTFOLIO_LAUNCHES,
    )
    scale_contract: ProductLaunchScaleContract = Field(
        default_factory=ProductLaunchScaleContract
    )
    portfolio_digest: str = ""

    @field_validator("shards", mode="before")
    @classmethod
    def _immutable_shards(cls, value: Any) -> Any:
        values = _immutable_sequence(value)
        return tuple(
            ProductLaunchShard.model_validate(
                item.model_dump(mode="python", by_alias=True)
                if isinstance(item, ProductLaunchShard)
                else item
            )
            for item in values
        )

    @model_validator(mode="after")
    def _derived_counts_and_digest(self) -> "ProductLaunchPortfolioPlan":
        if self.shard_count != len(self.shards):
            raise ValueError("shard_count does not match embedded shards")
        launch_count = sum(len(shard.jobs) for shard in self.shards)
        if self.launch_count != launch_count:
            raise ValueError("launch_count does not match embedded shard jobs")
        projects = {
            (shard.scope_fingerprint, shard.project_ref) for shard in self.shards
        }
        if self.project_count != len(projects):
            raise ValueError("project_count does not match embedded shard scopes")
        operation_count = sum(shard.estimated_operation_count for shard in self.shards)
        if self.estimated_operation_count != operation_count:
            raise ValueError("estimated_operation_count does not match embedded shards")
        shard_refs = [shard.shard_ref for shard in self.shards]
        if len(shard_refs) != len(set(shard_refs)):
            raise ValueError("shard_ref values must be unique")
        jobs = [job for shard in self.shards for job in shard.jobs]
        job_identities = [
            (job.scope_fingerprint, job.project_ref, job.job_ref) for job in jobs
        ]
        if len(job_identities) != len(set(job_identities)):
            raise ValueError(
                "job_ref values must be unique within each scope and project"
            )
        launch_identities = [
            (job.scope_fingerprint, job.project_ref, job.launch.launch_ref)
            for job in jobs
        ]
        if len(launch_identities) != len(set(launch_identities)):
            raise ValueError(
                "launch_ref values must be unique within each scope and project"
            )
        by_project: dict[tuple[str, str], list[ProductLaunchShard]] = defaultdict(list)
        for shard in self.shards:
            by_project[(shard.scope_fingerprint, shard.project_ref)].append(shard)
        for project_shards in by_project.values():
            expected_count = len(project_shards)
            if any(
                shard.project_shard_count != expected_count for shard in project_shards
            ):
                raise ValueError("project_shard_count does not match shard topology")
            if {shard.project_shard_index for shard in project_shards} != set(
                range(1, expected_count + 1)
            ):
                raise ValueError("project shard indexes must be contiguous")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"portfolio_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.portfolio_digest and self.portfolio_digest != expected_digest:
            raise ValueError(
                "portfolio_digest does not match the canonical portfolio payload"
            )
        sealed_payload = {**payload, "portfolio_digest": expected_digest}
        if _serialized_size_bytes(sealed_payload) > _MAX_LAUNCH_PORTFOLIO_BYTES:
            raise ValueError(
                "product launch portfolio exceeds the serialized byte budget"
            )
        object.__setattr__(self, "portfolio_digest", expected_digest)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


def _estimated_operations(job: ScopedProductLaunchJob) -> int:
    return (
        4
        + len(job.launch.social_drafts)
        + (1 if job.launch.sales_campaign.provider == "hubspot" else 0)
    )


def compile_product_launch_portfolio(
    jobs: Iterable[ScopedProductLaunchJob | Mapping[str, Any]],
    *,
    max_launches_per_shard: int = _MAX_LAUNCHES_PER_SHARD,
) -> ProductLaunchPortfolioPlan:
    """Partition launches with exact scope boundaries and serialized-byte budgets."""

    if (
        isinstance(max_launches_per_shard, bool)
        or not isinstance(max_launches_per_shard, int)
        or not 1 <= max_launches_per_shard <= _MAX_LAUNCHES_PER_SHARD
    ):
        raise ValueError(
            f"max_launches_per_shard must be an integer from 1 to {_MAX_LAUNCHES_PER_SHARD}"
        )
    parsed: list[ScopedProductLaunchJob] = []
    cumulative_job_bytes = 0
    try:
        for index, job in enumerate(jobs, start=1):
            if index > _MAX_PORTFOLIO_LAUNCHES:
                raise ValueError(
                    f"a portfolio supports at most {_MAX_PORTFOLIO_LAUNCHES} launches"
                )
            raw_job = (
                job.model_dump(mode="python")
                if isinstance(job, ScopedProductLaunchJob)
                else job
            )
            if _serialized_size_bytes(raw_job) > _MAX_LAUNCH_JOB_BYTES:
                raise ValueError(
                    f"launch job exceeds {_MAX_LAUNCH_JOB_BYTES} serialized bytes"
                )
            parsed_job = ScopedProductLaunchJob.model_validate(raw_job)
            job_bytes = _serialized_size_bytes(parsed_job.model_dump(mode="json"))
            if job_bytes > _MAX_LAUNCH_JOB_BYTES:
                raise ValueError(
                    f"launch job exceeds {_MAX_LAUNCH_JOB_BYTES} serialized bytes"
                )
            cumulative_job_bytes += job_bytes
            if cumulative_job_bytes > _MAX_LAUNCH_PORTFOLIO_BYTES:
                raise ValueError(
                    "portfolio launch inputs exceed the serialized byte budget"
                )
            parsed.append(parsed_job)
    except ValidationError:
        raise OmnichannelProductLaunchValidationError(
            "Product launch portfolio failed closed-world validation"
        ) from None
    if not parsed:
        raise ValueError("at least one scoped product launch job is required")
    identities = [
        (job.scope_fingerprint, job.project_ref, job.job_ref) for job in parsed
    ]
    if len(identities) != len(set(identities)):
        raise ValueError(
            "job_ref values must be unique within each authenticated scope and project"
        )
    launch_identities = [
        (job.scope_fingerprint, job.project_ref, job.launch.launch_ref)
        for job in parsed
    ]
    if len(launch_identities) != len(set(launch_identities)):
        raise ValueError(
            "launch_ref values must be unique within each authenticated scope and project"
        )

    grouped: dict[tuple[str, str], list[ScopedProductLaunchJob]] = defaultdict(list)
    for job in parsed:
        grouped[(job.scope_fingerprint, job.project_ref)].append(job)
    shards: list[ProductLaunchShard] = []
    for scope_fingerprint, project_ref in sorted(grouped):
        project_jobs = sorted(
            grouped[(scope_fingerprint, project_ref)],
            key=lambda job: job.job_ref,
        )
        project_chunks = [
            project_jobs[index : index + max_launches_per_shard]
            for index in range(0, len(project_jobs), max_launches_per_shard)
        ]
        for shard_index, chunk in enumerate(project_chunks, start=1):
            estimated_operation_count = sum(_estimated_operations(job) for job in chunk)
            shard_identity_core = {
                "scope_fingerprint": scope_fingerprint,
                "project_ref": project_ref,
                "project_shard_index": shard_index,
                "project_shard_count": len(project_chunks),
                "jobs": [job.model_dump(mode="json") for job in chunk],
            }
            shard_identity_digest = _stable_digest(shard_identity_core)
            shard = ProductLaunchShard(
                shard_ref=(
                    f"shard_{project_ref}_{shard_index:04d}_{shard_identity_digest[:12]}"
                ),
                scope_fingerprint=scope_fingerprint,
                project_ref=project_ref,
                project_shard_index=shard_index,
                project_shard_count=len(project_chunks),
                jobs=chunk,
                estimated_operation_count=estimated_operation_count,
            )
            if _serialized_size_bytes(shard.to_dict()) > _MAX_LAUNCH_SHARD_BYTES:
                raise ValueError(
                    "product launch shard exceeds the serialized byte budget"
                )
            shards.append(shard)
    estimated_operation_count = sum(shard.estimated_operation_count for shard in shards)
    portfolio = ProductLaunchPortfolioPlan(
        project_count=len(grouped),
        launch_count=len(parsed),
        shard_count=len(shards),
        estimated_operation_count=estimated_operation_count,
        shards=shards,
    )
    if _serialized_size_bytes(portfolio.to_dict()) > _MAX_LAUNCH_PORTFOLIO_BYTES:
        raise ValueError("product launch portfolio exceeds the serialized byte budget")
    return portfolio


class PlanOmnichannelProductLaunchPrimitive(
    BusinessProcessPrimitive[
        PlanOmnichannelProductLaunchInput,
        OmnichannelProductLaunchPlan,
    ]
):
    """Compile an evidence-aware launch plan with zero external effects."""

    primitive_ref = OMNICHANNEL_PRODUCT_LAUNCH_PRIMITIVE_REF
    version = "1.0.0"
    title = "Plan omnichannel product launch"
    description = (
        "Compile a deterministic Shopify, CRM, and social product-launch graph "
        "with analytics provenance, separate approvals, bounded scale, and a "
        "bounded host-verifiable evaluation contract."
    )
    input_model = PlanOmnichannelProductLaunchInput
    output_model = OmnichannelProductLaunchPlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "analysis_as_of": "2026-08-18T12:00:00Z",
        "launch_ref": "focus-kit-launch",
        "business_goal": "Launch a new planning kit and create qualified demand.",
        "target_audience": "Professional-services teams with 5 to 50 people.",
        "value_proposition": "A practical kit that turns priorities into weekly action.",
        "product": {
            "product_ref": "focus-kit",
            "connector_account_ref": "shopify-primary",
            "title": "Focus Kit",
            "description": "<p>A practical planning kit for focused teams.</p>",
            "vendor": "North Star Goods",
            "product_type": "Planning kit",
            "tags": ["planning", "teams"],
            "price": {"amount": "49.00", "currency": "USD"},
            "sku": "FOCUS-KIT-001",
            "taxable": True,
            "requires_shipping": True,
            "landing_url": "https://northstargoods.example/focus-kit",
            "publication_ids": ["gid://shopify/Publication/1001"],
        },
        "sales_campaign": {
            "provider": "hubspot",
            "connector_account_ref": "hubspot-primary",
            "name": "Focus Kit Launch",
            "audience": "Operations leaders at small professional-services firms.",
            "goal": "Create qualified conversations for the Focus Kit.",
            "offer": "Launch bundle with a guided team setup session.",
            "start_date": "2026-08-20",
            "end_date": "2026-09-20",
            "touches": [
                {
                    "day_offset": 0,
                    "channel": "email",
                    "objective": "Introduce the launch",
                    "message": "Show how the kit turns priorities into weekly action.",
                }
            ],
        },
        "social_drafts": [
            {
                "channel": "linkedin",
                "connector_account_ref": "linkedin-primary",
                "provider_target_id": "urn:li:organization:123456",
                "body": "Turn team priorities into weekly action with the Focus Kit.",
                "link_url": "https://northstargoods.example/focus-kit",
            },
            {
                "channel": "instagram",
                "connector_account_ref": "instagram-primary",
                "provider_target_id": "17841400000000000",
                "body": "Meet the Focus Kit: a practical system for focused teams.",
                "media_url": "https://northstargoods.example/media/focus-kit.jpg",
            },
        ],
        "analytics_snapshots": [
            {
                "observation_ref": "linkedin-baseline",
                "connector_account_ref": "linkedin-primary",
                "provider": "linkedin",
                "source_capability": "linkedin.fetch_metrics",
                "observed_at": "2026-08-18T11:00:00Z",
                "window_start": "2026-07-18T00:00:00Z",
                "window_end": "2026-08-18T10:00:00Z",
                "sample_size": 1200,
                "metrics": {
                    "impressions": 1200,
                    "clicks": 96,
                    "engagements": 180,
                    "conversions": 12,
                },
                "evidence_digest": "a" * 64,
            }
        ],
        "optimization_policy": {
            "primary_metric": "conversion_rate",
            "target_value": "0.04",
            "minimum_sample_size": 100,
            "max_observation_age_hours": 720,
            "measurement_window_hours": 168,
            "max_iterations": 3,
        },
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PlanOmnichannelProductLaunchInput,
    ) -> PrimitiveExecutionResult[OmnichannelProductLaunchPlan]:
        output = plan_omnichannel_product_launch(inputs)
        return PrimitiveExecutionResult[OmnichannelProductLaunchPlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=output.summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type="gtm.omnichannel_product_launch_planned",
                    payload={
                        "launch_ref": output.launch_ref,
                        "plan_digest": output.plan_digest,
                        "operation_count": len(output.operations),
                        "optimization_status": output.optimization_status,
                        "live_systems_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="gtm_launch_plan",
                    summary=(
                        "The SDK compiled a closed-world launch graph and immutable "
                        "receipt obligations without invoking an external system."
                    ),
                    refs={"plan_sha256": output.plan_digest},
                )
            ],
        )


__all__ = [
    "OMNICHANNEL_PRODUCT_LAUNCH_PLAN_SCHEMA",
    "OMNICHANNEL_PRODUCT_LAUNCH_PRIMITIVE_REF",
    "PRODUCT_LAUNCH_CONNECTOR_ACCOUNT_BINDING_SCHEMA",
    "PRODUCT_LAUNCH_PORTFOLIO_SCHEMA",
    "PRODUCT_LAUNCH_ITERATION_EVALUATION_SCHEMA",
    "PRODUCT_LAUNCH_RECEIPT_SCHEMA",
    "PRODUCT_LAUNCH_SHARD_SCHEMA",
    "AnalyticsFinding",
    "AnalyticsSnapshot",
    "CampaignMaterializationDisposition",
    "ChannelPriority",
    "FacebookPublishArguments",
    "HubSpotCampaignContainerArguments",
    "InstagramPublishArguments",
    "LandingReadinessArguments",
    "LaunchMoney",
    "LaunchOptimizationPolicy",
    "LaunchProductBrief",
    "LaunchVariant",
    "LinkedInPublishArguments",
    "NormalizedPerformanceMetrics",
    "OmnichannelProductLaunchPlan",
    "OmnichannelProductLaunchValidationError",
    "PlanOmnichannelProductLaunchInput",
    "PlanOmnichannelProductLaunchPrimitive",
    "ProductLaunchCapabilityGap",
    "ProductLaunchConnectorAccountBinding",
    "ProductLaunchEffectBoundary",
    "ProductLaunchEvidenceScope",
    "ProductLaunchEvaluationLoop",
    "ProductLaunchOperation",
    "ProductLaunchInputBinding",
    "ProductLaunchIterationEvaluation",
    "ProductLaunchPortfolioPlan",
    "ProductLaunchScaleContract",
    "ProductLaunchReceipt",
    "ProductLaunchShard",
    "RequiredLaunchReceipt",
    "SalesCampaignBrief",
    "SalesTouch",
    "ScopedProductLaunchJob",
    "ShopifyDraftProductArguments",
    "ShopifyActivateProductArguments",
    "ShopifyPublishProductArguments",
    "SocialPostDraft",
    "compile_product_launch_portfolio",
    "create_product_launch_evaluation_loop",
    "evaluate_product_launch_iteration",
    "mint_product_launch_analytics_snapshot",
    "mint_product_launch_connector_account_binding",
    "mint_product_launch_receipt",
    "plan_omnichannel_product_launch",
    "verify_product_launch_receipts",
    "verify_product_launch_plan",
]
