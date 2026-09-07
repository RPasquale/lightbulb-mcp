"""Execution-rail bridge: growth plans become dispatchable, receipts come home.

The governed execution rail (a separate stream) is what actually touches
connectors: it executes approved operations and mints sealed receipts. This
module is the Growth Engine's two-way seam with that rail, built strictly at
the **dict boundary** — no imports in either direction; every shape and
recipe here mirrors the rail's own contracts field-for-field (provenance
noted inline) so artifacts round-trip the day the rail lands.

Outbound — plans become dispatchable:

- :func:`author_calendar_item` binds agent-authored copy to a plan's content
  brief: the brief digest is cited, channel rules are enforced (the same
  rules the rail enforces on drafts), and the authored post gets its own
  content digest.
- :func:`compile_content_calendar_dispatch` and
  :func:`compile_audience_growth_dispatch` turn a verified plan plus authored
  posts into a sealed dispatch package of rail-shaped ``social_publish``
  operations: the rail's capability names (``{channel}.publish_post``),
  argument models, operation content-digest recipe, and
  ``approval_<kind>_<ref>_<digest>`` approval units — byte-exact, so what a
  human approves is exactly what the rail publishes. Both plan families share
  the same brief item shape, so they share one compiler. Unauthored items are
  reported, never silently dropped.

Inbound — execution proof comes home:

- :class:`RailExecutionReceipt` mirrors the rail's always-sealed receipt and
  :func:`verify_rail_execution_receipt` verifies it under the rail's own
  HMAC domain.
- :func:`reconcile_dispatch_receipts` matches receipts to a dispatch package
  by exact operation digest (and refuses any receipt lacking approval
  evidence or carrying a foreign run_ref / receipt kind), reports
  completed/pending honestly, and derives ``measure_after`` — the LAST
  completed action's ``effective_at``. Per the rail's time law a post-action
  measurement window must open STRICTLY AFTER this instant, not at it.

Nothing here executes anything: ``status`` is structurally
``proposal_only_not_executed`` and dispatch belongs to the rail behind its
own approvals. The :class:`RailDispatcher` protocol documents the seam a
rail-side executor satisfies.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol, Union
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .demand_gen_primitives import (
    AudienceGrowthPlan,
    ContentCalendarPlan,
    verify_audience_growth_plan,
    verify_content_calendar_plan,
)
from .dynamic_workflows import DynamicWorkflowScope

GROWTH_RAIL_DISPATCH_SCHEMA = "lightbulb.growth_rail_dispatch.v1"
GROWTH_RAIL_RECONCILIATION_SCHEMA = "lightbulb.growth_rail_reconciliation.v1"
# The rail's receipt schema/domain, duplicated at the dict boundary
# (mirror: gtm_primitives.PRODUCT_LAUNCH_RECEIPT_SCHEMA and
# _PRODUCT_LAUNCH_RECEIPT_HMAC_DOMAIN).
RAIL_EXECUTION_RECEIPT_SCHEMA = "lightbulb.product_launch_receipt.v1"
_RAIL_RECEIPT_HMAC_DOMAIN = RAIL_EXECUTION_RECEIPT_SCHEMA
_DISPATCH_HMAC_DOMAIN = GROWTH_RAIL_DISPATCH_SCHEMA

_RATE_QUANTUM = Decimal("0.000001")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

# The rail's operation model caps ordinal at 8, so a dispatch package holds at
# most 8 operations; larger calendars split across multiple packages/runs.
_MAX_DISPATCH_OPERATIONS = 8

SocialChannel = Literal["facebook", "instagram", "linkedin"]
PublishCapability = Literal[
    "facebook.publish_post",
    "instagram.publish_post",
    "linkedin.publish_post",
]


class GrowthRailBridgeValidationError(ValueError):
    """Bridge content violates the rail-compatibility contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
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
LinkedInText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=3_000),
    AfterValidator(_bounded_body),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
# Mirror the rail's WorkflowRunRef exactly (min 1, max 200, bounded text) so a
# rail-minted receipt's run_ref is never rejected by this bridge.
WorkflowRunRef = Annotated[
    str,
    StringConstraints(min_length=1, max_length=200),
    AfterValidator(_bounded_text),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
PublicHttpsUrl = Annotated[
    str,
    StringConstraints(min_length=8, max_length=2_000),
    AfterValidator(_public_https_url),
]


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


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthRailBridgeValidationError:
        raise
    except Exception as exc:
        raise GrowthRailBridgeValidationError(
            "the rail-bridge signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthRailBridgeValidationError:
        raise
    except Exception as exc:
        raise GrowthRailBridgeValidationError(
            "the rail-bridge signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Rail publish arguments (mirror: gtm_primitives.*PublishArguments, verbatim)
# ---------------------------------------------------------------------------


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


PublishArguments = Union[
    FacebookPublishArguments,
    InstagramPublishArguments,
    LinkedInPublishArguments,
]

_CAPABILITY_ARGUMENT_KIND: dict[str, str] = {
    "facebook.publish_post": "facebook_publish",
    "instagram.publish_post": "instagram_publish",
    "linkedin.publish_post": "linkedin_publish",
}


def _operation_content_digest(
    capability: str,
    arguments: BaseModel,
    depends_on: Sequence[str],
    connector_account_ref: str,
) -> str:
    """The rail's exact operation content-digest recipe.

    Mirror: gtm_primitives._operation_content_digest — the arguments dump
    excludes the discriminator ``kind`` and omits None fields; approval units
    derived from this digest therefore bind the byte-exact payload.
    """

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
    depends_on: Sequence[str] = (),
) -> str:
    content_digest = _operation_content_digest(
        capability, arguments, depends_on, connector_account_ref
    )
    return f"approval_{kind}_{reference}_{content_digest}"


# ---------------------------------------------------------------------------
# Authoring: briefs become byte-exact copy
# ---------------------------------------------------------------------------


class AuthoredSocialPost(_StrictModel):
    """Agent-authored copy bound to the plan brief it fulfils."""

    item_ref: PortableRef
    channel: SocialChannel
    connector_account_ref: OperationRef
    provider_target_id: ShortText
    brief_digest: Sha256Digest
    body: LongText
    media_url: PublicHttpsUrl | None = None
    link_url: PublicHttpsUrl | None = None
    authored_digest: Sha256Digest = "0" * 64

    @model_validator(mode="after")
    def _channel_rules(self) -> "AuthoredSocialPost":
        # Mirror: the rail's SocialPostDraft channel rules.
        if self.channel == "instagram" and self.media_url is None:
            raise ValueError("Instagram posts require a public media_url")
        if self.channel != "linkedin" and self.link_url is not None:
            raise ValueError("link_url is supported only for LinkedIn posts")
        if self.channel == "linkedin":
            if len(self.body) > 3_000:
                raise ValueError("LinkedIn post bodies support at most 3000 characters")
            if self.link_url is None:
                raise ValueError("LinkedIn publishes require a link_url destination")
        if self.channel in {"facebook", "instagram"} and not (
            self.provider_target_id.isdigit()
        ):
            raise ValueError("Meta provider_target_id must be a numeric Graph API ID")
        if self.channel == "linkedin" and (
            re.fullmatch(
                r"urn:li:(?:organization|person):[A-Za-z0-9_-]+",
                self.provider_target_id,
            )
            is None
        ):
            raise ValueError("LinkedIn provider_target_id must be an author URN")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authored_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.authored_digest != "0" * 64 and self.authored_digest != expected:
            raise ValueError("authored_digest does not match the canonical payload")
        object.__setattr__(self, "authored_digest", expected)
        return self


def _parse_plan(
    plan: ContentCalendarPlan | AudienceGrowthPlan | Mapping[str, Any],
) -> ContentCalendarPlan | AudienceGrowthPlan:
    if isinstance(plan, (ContentCalendarPlan, AudienceGrowthPlan)):
        return plan
    schema = str(dict(plan).get("schema", ""))
    if schema == AudienceGrowthPlan.model_fields["schema_id"].default:
        return AudienceGrowthPlan.model_validate(plan)
    return ContentCalendarPlan.model_validate(plan)


def author_calendar_item(
    plan: ContentCalendarPlan | AudienceGrowthPlan | Mapping[str, Any],
    item_ref: str,
    *,
    body: str,
    media_url: str | None = None,
    link_url: str | None = None,
) -> AuthoredSocialPost:
    """Bind authored copy to one plan brief; content drift is impossible.

    Accepts either a content-calendar or an audience-growth plan — both carry
    the same brief item shape. The returned post cites the brief's content
    digest; compilation later re-checks that binding, so approved copy can
    only fulfil the exact brief it was written for.
    """

    parsed = _parse_plan(plan)
    item = next((entry for entry in parsed.items if entry.item_ref == item_ref), None)
    if item is None:
        raise GrowthRailBridgeValidationError("the plan has no item with that ref")
    if item.media_required and media_url is None:
        raise GrowthRailBridgeValidationError(
            "the brief requires media; supply media_url"
        )
    if item.channel == "linkedin" and link_url is None:
        # The rail's LinkedIn publish argument requires a url unconditionally,
        # so every LinkedIn post needs a destination link regardless of the
        # brief's link_required flag.
        raise GrowthRailBridgeValidationError(
            "LinkedIn posts require a destination link; supply link_url"
        )
    if item.link_required and item.channel != "linkedin" and "https://" not in body:
        raise GrowthRailBridgeValidationError(
            "the brief requires a destination link; Meta channels carry it in "
            "the body text"
        )
    return AuthoredSocialPost(
        item_ref=item.item_ref,
        channel=item.channel,
        connector_account_ref=item.connector_account_ref,
        provider_target_id=item.provider_target_id,
        brief_digest=item.item_digest,
        body=body,
        media_url=media_url,
        link_url=link_url,
    )


# ---------------------------------------------------------------------------
# Dispatch package: rail-shaped operations
# ---------------------------------------------------------------------------


class RailSocialOperation(_StrictModel):
    """One rail-shaped social_publish operation.

    Mirror of the rail's operation model for the social stage, including its
    ``le=8`` ordinal bound — an operation that exceeds it would be rejected by
    the rail's own model, so the bridge stays within it and splits larger
    calendars across packages.
    """

    ordinal: int = Field(ge=1, le=_MAX_DISPATCH_OPERATIONS)
    operation_id: OperationRef
    stage: Literal["social_publish"] = "social_publish"
    execution_kind: Literal["connector_tool"] = "connector_tool"
    capability: PublishCapability
    surface_availability: Literal["platform_registered_not_generated"] = (
        "platform_registered_not_generated"
    )
    connector_account_ref: OperationRef
    effect: Literal["write"] = "write"
    arguments: PublishArguments
    depends_on: tuple[OperationRef, ...] = Field(default_factory=tuple, max_length=2)
    # The rail's operation model carries input_bindings and includes it in the
    # canonical operation payload (empty list for social ops, kept by
    # exclude_none). Social operations must have none — mirror the field so
    # our operation_digest matches the rail's byte-for-byte.
    input_bindings: tuple[str, ...] = Field(default_factory=tuple, max_length=0)
    status: Literal["proposal_only_not_executed"] = "proposal_only_not_executed"
    approval_required: Literal[True] = True
    approval_unit: OperationRef
    receipt_kind: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]{0,119}$",
    )
    scheduling_semantics: Literal["not_scheduled"] = "not_scheduled"
    operation_digest: str = ""

    @field_validator("depends_on", "input_bindings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _rail_shape(self) -> "RailSocialOperation":
        expected_kind = _CAPABILITY_ARGUMENT_KIND[self.capability]
        if self.arguments.kind != expected_kind:
            raise ValueError("operation arguments do not match the capability")
        expected_unit_suffix = _operation_content_digest(
            self.capability,
            self.arguments,
            self.depends_on,
            self.connector_account_ref,
        )
        if not self.approval_unit.endswith("_" + expected_unit_suffix):
            raise ValueError(
                "approval_unit must bind the operation's exact content digest"
            )
        # Match the rail's operation_digest recipe exactly: mode="json",
        # exclude_none=True, NO by_alias (the rail uses none; these fields
        # carry no aliases, so the two are equivalent, but stay exact).
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


class OperationSchedule(_StrictModel):
    operation_id: OperationRef
    item_ref: PortableRef
    brief_digest: Sha256Digest
    authored_digest: Sha256Digest
    scheduled_for: str

    @field_validator("scheduled_for")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class RailDispatchPackage(_StrictModel):
    """Sealed, approval-ready set of rail operations compiled from one plan."""

    schema_id: Literal["lightbulb.growth_rail_dispatch.v1"] = Field(
        default=GROWTH_RAIL_DISPATCH_SCHEMA,
        alias="schema",
    )
    dispatch_ref: PortableRef
    run_ref: WorkflowRunRef
    calendar_plan_digest: Sha256Digest
    evidence_scope_status: Literal["caller_supplied_unverified", "host_hmac_verified"]
    compiled_at: str
    operations: tuple[RailSocialOperation, ...] = Field(
        min_length=1, max_length=_MAX_DISPATCH_OPERATIONS
    )
    schedule: tuple[OperationSchedule, ...] = Field(
        min_length=1, max_length=_MAX_DISPATCH_OPERATIONS
    )
    unauthored_item_refs: tuple[PortableRef, ...] = Field(default_factory=tuple)
    package_digest: Sha256Digest = "0" * 64
    receipt_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest
    package_hmac: Sha256Digest

    @field_validator("compiled_at")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("operations", "schedule", "unauthored_item_refs", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "RailDispatchPackage":
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("dispatch operation ids must be unique")
        if [entry.operation_id for entry in self.schedule] != operation_ids:
            raise ValueError(
                "the schedule must cover exactly the dispatch operations, in order"
            )
        ordinals = [operation.ordinal for operation in self.operations]
        if ordinals != list(range(1, len(ordinals) + 1)):
            raise ValueError("operation ordinals must be contiguous from 1")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"package_digest", "package_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.package_digest != "0" * 64 and self.package_digest != expected:
            raise ValueError("package_digest does not match the canonical payload")
        object.__setattr__(self, "package_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"package_hmac", "package_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def compile_content_calendar_dispatch(
    plan: ContentCalendarPlan | Mapping[str, Any],
    authored_posts: Sequence[AuthoredSocialPost | Mapping[str, Any]],
    *,
    dispatch_ref: str,
    run_ref: str,
    compiled_at: str,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> RailDispatchPackage:
    """Compile authored content-calendar items into a sealed dispatch package.

    Compilation is execution-adjacent, so it is always sealed and always
    starts from a VERIFIED plan. Every authored post must bind byte-exactly
    to its brief; items nobody authored are reported in
    ``unauthored_item_refs`` rather than silently dropped.
    """

    workflow_scope = _workflow_scope(scope)
    verified_plan = verify_content_calendar_plan(
        plan, scope=workflow_scope, scope_keyring=scope_keyring
    )
    return _compile_dispatch(
        verified_plan,
        authored_posts,
        dispatch_ref=dispatch_ref,
        run_ref=run_ref,
        compiled_at=compiled_at,
        workflow_scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )


def compile_audience_growth_dispatch(
    plan: AudienceGrowthPlan | Mapping[str, Any],
    authored_posts: Sequence[AuthoredSocialPost | Mapping[str, Any]],
    *,
    dispatch_ref: str,
    run_ref: str,
    compiled_at: str,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> RailDispatchPackage:
    """Compile authored audience-growth items into a sealed dispatch package.

    Identical machinery to the content-calendar path — audience-growth items
    are the same brief shape (lead magnets, follower-growth posts) and dispatch
    through the same rail social_publish operations. The plan is verified with
    its own verifier before compilation.
    """

    workflow_scope = _workflow_scope(scope)
    verified_plan = verify_audience_growth_plan(
        plan, scope=workflow_scope, scope_keyring=scope_keyring
    )
    return _compile_dispatch(
        verified_plan,
        authored_posts,
        dispatch_ref=dispatch_ref,
        run_ref=run_ref,
        compiled_at=compiled_at,
        workflow_scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )


def _compile_dispatch(
    verified_plan: ContentCalendarPlan | AudienceGrowthPlan,
    authored_posts: Sequence[AuthoredSocialPost | Mapping[str, Any]],
    *,
    dispatch_ref: str,
    run_ref: str,
    compiled_at: str,
    workflow_scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None,
) -> RailDispatchPackage:
    posts = [
        post
        if isinstance(post, AuthoredSocialPost)
        else AuthoredSocialPost.model_validate(post)
        for post in authored_posts
    ]
    if not posts:
        raise GrowthRailBridgeValidationError(
            "dispatch compilation requires at least one authored post"
        )
    if len(posts) > _MAX_DISPATCH_OPERATIONS:
        raise GrowthRailBridgeValidationError(
            f"a dispatch package holds at most {_MAX_DISPATCH_OPERATIONS} "
            "operations (the rail's operation-model bound); split a larger "
            "calendar across multiple dispatch packages"
        )
    items_by_ref = {item.item_ref: item for item in verified_plan.items}
    seen: set[str] = set()
    for post in posts:
        if post.item_ref in seen:
            raise GrowthRailBridgeValidationError(
                "duplicate authored posts for one calendar item"
            )
        seen.add(post.item_ref)
        item = items_by_ref.get(post.item_ref)
        if item is None:
            raise GrowthRailBridgeValidationError(
                "an authored post references an item absent from the plan"
            )
        if post.brief_digest != item.item_digest:
            raise GrowthRailBridgeValidationError(
                "an authored post is bound to a different brief revision; "
                "re-author against the current plan"
            )
        if (
            post.channel != item.channel
            or post.connector_account_ref != item.connector_account_ref
            or post.provider_target_id != item.provider_target_id
        ):
            raise GrowthRailBridgeValidationError(
                "an authored post does not match its brief's destination"
            )

    operations: list[RailSocialOperation] = []
    schedule: list[OperationSchedule] = []
    for ordinal, post in enumerate(
        sorted(posts, key=lambda entry: entry.item_ref), start=1
    ):
        item = items_by_ref[post.item_ref]
        arguments: PublishArguments
        if post.channel == "facebook":
            arguments = FacebookPublishArguments(
                kind="facebook_publish",
                page_id=post.provider_target_id,
                message=post.body,
                image_url=post.media_url,
            )
        elif post.channel == "instagram":
            arguments = InstagramPublishArguments(
                kind="instagram_publish",
                instagram_business_account_id=post.provider_target_id,
                caption=post.body,
                image_url=post.media_url,
            )
        else:
            arguments = LinkedInPublishArguments(
                kind="linkedin_publish",
                author_urn=post.provider_target_id,
                text=post.body,
                url=post.link_url,
                image_url=post.media_url,
            )
        capability = f"{post.channel}.publish_post"
        operation_id = f"op-{ordinal:03d}.social_publish.{post.item_ref}"
        operations.append(
            RailSocialOperation(
                ordinal=ordinal,
                operation_id=operation_id,
                capability=capability,
                connector_account_ref=post.connector_account_ref,
                arguments=arguments,
                depends_on=(),
                approval_unit=_approval_unit(
                    post.channel,
                    post.item_ref,
                    capability=capability,
                    arguments=arguments,
                    connector_account_ref=post.connector_account_ref,
                    depends_on=(),
                ),
                receipt_kind=f"{post.channel}_publish_receipt",
            )
        )
        schedule.append(
            OperationSchedule(
                operation_id=operation_id,
                item_ref=post.item_ref,
                brief_digest=post.brief_digest,
                authored_digest=post.authored_digest,
                scheduled_for=item.scheduled_for,
            )
        )

    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = RailDispatchPackage(
        dispatch_ref=dispatch_ref,
        run_ref=run_ref,
        calendar_plan_digest=verified_plan.plan_digest,
        evidence_scope_status=verified_plan.evidence_scope_status,
        compiled_at=compiled_at,
        operations=tuple(operations),
        schedule=tuple(schedule),
        unauthored_item_refs=tuple(sorted(set(items_by_ref) - seen)),
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        package_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_DISPATCH_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"package_digest"},
        exclude_none=True,
    )
    sealed["package_hmac"] = signature
    return RailDispatchPackage.model_validate(sealed)


def verify_rail_dispatch_package(
    value: RailDispatchPackage | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> RailDispatchPackage:
    package = RailDispatchPackage.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, RailDispatchPackage)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=package.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(package.exact_scope_digest, expected_scope_digest):
        raise GrowthRailBridgeValidationError(
            "dispatch package attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=package.receipt_key_id,
        domain=_DISPATCH_HMAC_DOMAIN,
        payload=package.hmac_payload(),
    )
    if not hmac.compare_digest(package.package_hmac, expected_hmac):
        raise GrowthRailBridgeValidationError(
            "dispatch package attestation failed verification"
        )
    return package


# ---------------------------------------------------------------------------
# Rail receipts (mirror: gtm_primitives.ProductLaunchReceipt, verbatim)
# ---------------------------------------------------------------------------

PrimaryMetric = Literal[
    "conversion_rate",
    "click_through_rate",
    "engagement_rate",
    "pipeline_win_rate",
]


class RailExecutionReceipt(_StrictModel):
    """The rail's always-sealed execution receipt, at the dict boundary."""

    schema_id: Literal["lightbulb.product_launch_receipt.v1"] = Field(
        default=RAIL_EXECUTION_RECEIPT_SCHEMA,
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
    def _seal_and_validate(self) -> "RailExecutionReceipt":
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


def verify_rail_execution_receipt(
    value: RailExecutionReceipt | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> RailExecutionReceipt:
    """Verify a rail receipt under the rail's own HMAC domain."""

    receipt = RailExecutionReceipt.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, RailExecutionReceipt)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=receipt.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(receipt.exact_scope_digest, expected_scope_digest):
        raise GrowthRailBridgeValidationError(
            "rail receipt attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=receipt.receipt_key_id,
        domain=_RAIL_RECEIPT_HMAC_DOMAIN,
        payload=receipt.hmac_payload(),
    )
    if not hmac.compare_digest(receipt.receipt_hmac, expected_hmac):
        raise GrowthRailBridgeValidationError(
            "rail receipt attestation failed verification"
        )
    return receipt


# ---------------------------------------------------------------------------
# Reconciliation: receipts -> measurement-window facts
# ---------------------------------------------------------------------------


class CompletedOperation(_StrictModel):
    operation_id: OperationRef
    receipt_digest: Sha256Digest
    effective_at: str

    @field_validator("effective_at")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class DispatchReconciliation(_StrictModel):
    """Digest-pinned answer to "did my plan actually happen, and when"."""

    schema_id: Literal["lightbulb.growth_rail_reconciliation.v1"] = Field(
        default=GROWTH_RAIL_RECONCILIATION_SCHEMA,
        alias="schema",
    )
    package_digest: Sha256Digest
    completed: tuple[CompletedOperation, ...] = Field(default_factory=tuple)
    pending_operation_ids: tuple[OperationRef, ...] = Field(default_factory=tuple)
    all_completed: bool
    # The last completed action's effective_at. A measurement window must open
    # STRICTLY AFTER this instant (the rail rejects a window opening at it).
    measure_after: str | None = None
    reconciliation_digest: Sha256Digest = "0" * 64

    @field_validator("measure_after")
    @classmethod
    def _valid_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value)

    @field_validator("completed", "pending_operation_ids", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "DispatchReconciliation":
        if self.all_completed != (len(self.pending_operation_ids) == 0):
            raise ValueError("all_completed must match the pending set")
        if self.all_completed != (self.measure_after is not None):
            raise ValueError("measure_after exists exactly when every action completed")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reconciliation_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.reconciliation_digest != "0" * 64 and (
            self.reconciliation_digest != expected
        ):
            raise ValueError(
                "reconciliation_digest does not match the canonical payload"
            )
        object.__setattr__(self, "reconciliation_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def reconcile_dispatch_receipts(
    package: RailDispatchPackage | Mapping[str, Any],
    receipts: Sequence[RailExecutionReceipt | Mapping[str, Any]],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> DispatchReconciliation:
    """Match verified receipts to a verified dispatch, honestly.

    A receipt must bind the package digest as its plan digest AND match a
    dispatched operation's id and exact operation digest — a receipt for
    content that differs by one byte is a hard error, not a partial match.
    ``measure_after`` (the rail's time law: measurement windows open after
    the LAST completed action) exists only when every operation completed.
    """

    verified_package = verify_rail_dispatch_package(
        package, scope=scope, scope_keyring=scope_keyring
    )
    operations_by_id = {
        operation.operation_id: operation for operation in verified_package.operations
    }
    completed: dict[str, CompletedOperation] = {}
    for value in receipts:
        receipt = verify_rail_execution_receipt(
            value, scope=scope, scope_keyring=scope_keyring
        )
        if receipt.plan_digest != verified_package.package_digest:
            raise GrowthRailBridgeValidationError(
                "a receipt is bound to a different dispatch package"
            )
        if receipt.operation_id is None:
            raise GrowthRailBridgeValidationError(
                "dispatch reconciliation requires operation-level receipts"
            )
        operation = operations_by_id.get(receipt.operation_id)
        if operation is None:
            raise GrowthRailBridgeValidationError(
                "a receipt references an operation absent from the dispatch"
            )
        if receipt.operation_digest != operation.operation_digest:
            raise GrowthRailBridgeValidationError(
                "a receipt does not match the dispatched operation's exact content"
            )
        if receipt.run_ref != verified_package.run_ref:
            raise GrowthRailBridgeValidationError(
                "a receipt carries a run_ref foreign to this dispatch package"
            )
        if receipt.receipt_kind != operation.receipt_kind:
            raise GrowthRailBridgeValidationError(
                "a receipt's kind does not match the dispatched operation"
            )
        # Every dispatched operation is an approval-required write. A receipt
        # that proves execution WITHOUT approval evidence does not prove the
        # approved plan is what ran, so it cannot mark the operation complete.
        if receipt.approval_unit != operation.approval_unit or (
            receipt.approval_receipt_digest is None
        ):
            raise GrowthRailBridgeValidationError(
                "a receipt for an approval-required operation carries no "
                "matching approval evidence"
            )
        if receipt.operation_id in completed:
            raise GrowthRailBridgeValidationError(
                "duplicate receipts for one dispatched operation"
            )
        completed[receipt.operation_id] = CompletedOperation(
            operation_id=receipt.operation_id,
            receipt_digest=receipt.receipt_digest,
            effective_at=receipt.effective_at,
        )
    pending = tuple(
        operation.operation_id
        for operation in verified_package.operations
        if operation.operation_id not in completed
    )
    all_completed = not pending
    measure_after: str | None = None
    if all_completed:
        measure_after = max(
            (entry.effective_at for entry in completed.values()),
            key=_parse_timestamp,
        )
    return DispatchReconciliation(
        package_digest=verified_package.package_digest,
        completed=tuple(
            completed[operation.operation_id]
            for operation in verified_package.operations
            if operation.operation_id in completed
        ),
        pending_operation_ids=pending,
        all_completed=all_completed,
        measure_after=measure_after,
    )


class RailDispatcher(Protocol):
    """The structural seam a rail-side executor satisfies when it lands.

    Given one rail-shaped operation dict and the approval reference minted by
    the platform for that operation's approval unit, the dispatcher executes
    behind its own governance and returns the sealed receipt dict.
    """

    def dispatch(
        self,
        operation: Mapping[str, Any],
        *,
        approval_ref: str,
        run_ref: str,
    ) -> Mapping[str, Any]: ...


__all__ = [
    "GROWTH_RAIL_DISPATCH_SCHEMA",
    "GROWTH_RAIL_RECONCILIATION_SCHEMA",
    "RAIL_EXECUTION_RECEIPT_SCHEMA",
    "AuthoredSocialPost",
    "CompletedOperation",
    "DispatchReconciliation",
    "FacebookPublishArguments",
    "GrowthRailBridgeValidationError",
    "InstagramPublishArguments",
    "LinkedInPublishArguments",
    "OperationSchedule",
    "RailDispatchPackage",
    "RailDispatcher",
    "RailExecutionReceipt",
    "RailSocialOperation",
    "author_calendar_item",
    "compile_audience_growth_dispatch",
    "compile_content_calendar_dispatch",
    "reconcile_dispatch_receipts",
    "verify_rail_dispatch_package",
    "verify_rail_execution_receipt",
]
