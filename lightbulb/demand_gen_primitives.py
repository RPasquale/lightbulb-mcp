"""Demand-generation planners driven by funnel evidence and learnings.

Slice 4 of the Lightbulb Growth Engine. Two deterministic planners:

- :func:`plan_content_calendar` — a bounded posting calendar across LinkedIn,
  Facebook, and Instagram accounts whose intent mix is chosen by the verified
  funnel bottleneck and whose items cite the learnings that informed them.
- :func:`plan_audience_growth` — follower-growth and lead-magnet loops chosen
  from the funnel's audience/lead state, with structural frequency caps.

Honesty rules:

- **Plans, not posts.** Planners emit content *briefs* with rail-style
  approval units bound to each item's content digest
  (``approval_<kind>_<ref>_<digest>``): what gets approved is byte-exactly
  what was planned. ``dispatchable_by_planner`` is structurally ``False`` —
  execution belongs to the governed rail.
- **Analytics-informed or honestly unverified.** With a scope keyring the
  funnel snapshot and learning entries are HMAC-verified and the plan seals;
  without one the plan is labeled ``caller_supplied_unverified``.
- **No invented copy.** Briefs carry intent, theme, and message directives;
  the agent authors the copy later and binds it through the rail's own
  content-digest approvals.
- **No wall clocks; no randomness.** Scheduling slots, intent mixes, and
  theme cycling are deterministic functions of the brief.

Sealing follows ``docs/growth-engine-build-contract-map.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
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

from .dynamic_workflows import DynamicWorkflowScope
from .growth_funnel import GrowthFunnelSnapshot, verify_growth_funnel_snapshot
from .growth_learnings import GrowthLearningEntry, verify_growth_learning_entry

CONTENT_CALENDAR_PLAN_SCHEMA = "lightbulb.growth_content_calendar_plan.v1"
AUDIENCE_GROWTH_PLAN_SCHEMA = "lightbulb.growth_audience_growth_plan.v1"

_CALENDAR_HMAC_DOMAIN = CONTENT_CALENDAR_PLAN_SCHEMA
_AUDIENCE_HMAC_DOMAIN = AUDIENCE_GROWTH_PLAN_SCHEMA

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MAX_CHANNEL_ACCOUNTS = 10
_MAX_THEMES = 12
_MAX_LEARNINGS = 20
_MAX_CALENDAR_ITEMS = 200
_MAX_WEEKS = 12
_MAX_POSTS_PER_WEEK = 7

SocialChannel = Literal["facebook", "instagram", "linkedin"]
ContentIntent = Literal[
    "awareness",
    "traffic_driving",
    "engagement",
    "conversion",
    "lead_magnet",
    "retention",
]
AudienceStrategy = Literal["follower_growth", "lead_magnet_funnel"]
EvidenceScopeStatus = Literal["caller_supplied_unverified", "host_hmac_verified"]

# Bottleneck rate -> the intent that attacks it.
_BOTTLENECK_INTENT: dict[str, ContentIntent] = {
    "reach_to_visit": "traffic_driving",
    "visit_to_engage": "engagement",
    "visit_to_purchase": "conversion",
    "lead_capture": "lead_magnet",
    "purchase_to_repeat": "retention",
}

# Deterministic weekly posting slots (day offset within the week, hour UTC).
_WEEKLY_SLOTS: tuple[tuple[int, int], ...] = (
    (1, 17),
    (3, 16),
    (5, 15),
    (0, 18),
    (2, 12),
    (4, 11),
    (6, 14),
)


class DemandGenValidationError(ValueError):
    """A demand-gen brief cannot become a safe, bounded plan."""


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


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


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


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
    except DemandGenValidationError:
        raise
    except Exception as exc:
        raise DemandGenValidationError(
            "the demand-gen signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except DemandGenValidationError:
        raise
    except Exception as exc:
        raise DemandGenValidationError(
            "the demand-gen signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


class DemandGenChannelAccount(_StrictModel):
    """One social destination; target identity is validated per channel."""

    channel: SocialChannel
    connector_account_ref: OperationRef
    provider_target_id: ShortText

    @model_validator(mode="after")
    def _channel_target_shape(self) -> "DemandGenChannelAccount":
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
        return self


class ContentCalendarBrief(_StrictModel):
    calendar_ref: PortableRef
    planning_as_of: str
    campaign_goal: LongText
    window_start: str
    window_weeks: int = Field(ge=1, le=_MAX_WEEKS)
    posts_per_week_per_channel: int = Field(ge=1, le=_MAX_POSTS_PER_WEEK)
    channel_accounts: tuple[DemandGenChannelAccount, ...] = Field(
        min_length=1, max_length=_MAX_CHANNEL_ACCOUNTS
    )
    content_themes: tuple[ShortText, ...] = Field(min_length=1, max_length=_MAX_THEMES)
    funnel_snapshot: GrowthFunnelSnapshot
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_LEARNINGS
    )
    max_snapshot_age_hours: int = Field(default=720, ge=1, le=8_760)

    @field_validator("planning_as_of", "window_start")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("channel_accounts", "content_themes", "learnings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _bounded_brief(self) -> "ContentCalendarBrief":
        if len(self.calendar_ref) > 40:
            raise ValueError(
                "calendar_ref must stay within 40 characters so generated "
                "item refs fit the portable ref format"
            )
        if _parse_timestamp(self.window_start) < _parse_timestamp(self.planning_as_of):
            raise ValueError("the calendar window cannot begin in the past")
        accounts = [
            (item.channel, item.connector_account_ref) for item in self.channel_accounts
        ]
        if len(accounts) != len(set(accounts)):
            raise ValueError("channel accounts must be unique")
        themes = [theme.casefold() for theme in self.content_themes]
        if len(themes) != len(set(themes)):
            raise ValueError("content themes must be unique")
        total_items = (
            len(self.channel_accounts)
            * self.window_weeks
            * self.posts_per_week_per_channel
        )
        if total_items > _MAX_CALENDAR_ITEMS:
            raise ValueError(
                "the brief would exceed the maximum of "
                f"{_MAX_CALENDAR_ITEMS} calendar items"
            )
        return self


class ContentBriefItem(_StrictModel):
    """One planned post: a directive for authorship, not authored copy."""

    item_ref: PortableRef
    channel: SocialChannel
    connector_account_ref: OperationRef
    provider_target_id: ShortText
    scheduled_for: str
    intent: ContentIntent
    theme: ShortText
    message_directive: LongText
    media_required: bool
    link_required: bool
    dispatchable_by_planner: Literal[False] = False
    item_digest: Sha256Digest = "0" * 64
    approval_unit: str = Field(min_length=1, max_length=200)

    @field_validator("scheduled_for")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _content_bound_approval(self) -> "ContentBriefItem":
        if self.channel == "instagram" and not self.media_required:
            raise ValueError("Instagram briefs must require media")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"item_digest", "approval_unit"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.item_digest != "0" * 64 and self.item_digest != expected:
            raise ValueError("item_digest does not match the canonical payload")
        object.__setattr__(self, "item_digest", expected)
        expected_unit = f"approval_social_brief_{self.item_ref}_{expected}"
        sentinel_unit = f"approval_social_brief_{self.item_ref}_{'0' * 64}"
        if self.approval_unit == sentinel_unit:
            object.__setattr__(self, "approval_unit", expected_unit)
        elif self.approval_unit != expected_unit:
            raise ValueError(
                "approval_unit must bind the item ref to its content digest"
            )
        return self


def _build_brief_item(body: dict[str, Any]) -> ContentBriefItem:
    return ContentBriefItem.model_validate(
        {
            **body,
            "approval_unit": (f"approval_social_brief_{body['item_ref']}_{'0' * 64}"),
        }
    )


class InformedBy(_StrictModel):
    funnel_digest: Sha256Digest
    learning_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple)

    @field_validator("learning_digests", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class IntentAllocation(_StrictModel):
    intent: ContentIntent
    item_count: int = Field(ge=0)


class ContentCalendarPlan(_StrictModel):
    schema_id: Literal["lightbulb.growth_content_calendar_plan.v1"] = Field(
        default=CONTENT_CALENDAR_PLAN_SCHEMA,
        alias="schema",
    )
    calendar_ref: PortableRef
    planning_as_of: str
    window_start: str
    window_weeks: int = Field(ge=1, le=_MAX_WEEKS)
    campaign_goal: LongText
    evidence_scope_status: EvidenceScopeStatus
    target_bottleneck: str | None = None
    primary_intent: ContentIntent
    intent_allocations: tuple[IntentAllocation, ...]
    informed_by: InformedBy
    items: tuple[ContentBriefItem, ...] = Field(
        min_length=1, max_length=_MAX_CALENDAR_ITEMS
    )
    dispatchable_by_planner: Literal[False] = False
    plan_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    plan_hmac: Sha256Digest | None = None

    @field_validator("planning_as_of", "window_start")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("intent_allocations", "items", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "ContentCalendarPlan":
        refs = [item.item_ref for item in self.items]
        if len(refs) != len(set(refs)):
            raise ValueError("calendar item refs must be unique")
        allocation_total = sum(
            allocation.item_count for allocation in self.intent_allocations
        )
        if allocation_total != len(self.items):
            raise ValueError("intent allocations must account for every item")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.plan_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "calendar plan attestation fields must be supplied together"
            )
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.plan_hmac is None
        ):
            raise ValueError(
                "verified calendar plans require a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest", "plan_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.plan_digest != "0" * 64 and self.plan_digest != expected:
            raise ValueError("plan_digest does not match the canonical payload")
        object.__setattr__(self, "plan_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_hmac", "plan_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _verify_brief_evidence(
    brief: ContentCalendarBrief | AudienceGrowthBrief,
    *,
    scope: DynamicWorkflowScope | None,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[EvidenceScopeStatus, GrowthFunnelSnapshot]:
    """Verify snapshot + learnings when a keyring is present; else label."""

    snapshot = brief.funnel_snapshot
    planning_at = _parse_timestamp(brief.planning_as_of)
    snapshot_at = _parse_timestamp(snapshot.analysis_as_of)
    if snapshot_at > planning_at:
        raise DemandGenValidationError(
            "the funnel snapshot is from the future of planning_as_of"
        )
    age_hours = (planning_at - snapshot_at).total_seconds() / 3_600
    if age_hours > brief.max_snapshot_age_hours:
        raise DemandGenValidationError(
            "the funnel snapshot is older than the brief's staleness budget"
        )
    if scope_keyring is None or scope is None:
        return "caller_supplied_unverified", snapshot
    verified_snapshot = verify_growth_funnel_snapshot(
        snapshot, scope=scope, scope_keyring=scope_keyring
    )
    for entry in brief.learnings:
        verify_growth_learning_entry(entry, scope=scope, scope_keyring=scope_keyring)
        if entry.valid_until is not None and (
            _parse_timestamp(entry.valid_until) <= planning_at
        ):
            raise DemandGenValidationError(
                "an informing learning expired before planning_as_of"
            )
    # Trust never upgrades across hops: even with a valid snapshot seal, the
    # plan inherits the snapshot's own evidence label. A sealed snapshot built
    # from unattested envelopes stays caller_supplied_unverified here.
    return verified_snapshot.evidence_scope_status, verified_snapshot


def _intent_mix(primary: ContentIntent, total: int) -> list[ContentIntent]:
    """Deterministic largest-remainder mix: 60% primary, 20/20 support."""

    support_a: ContentIntent = "awareness"
    support_b: ContentIntent = (
        "engagement" if primary != "engagement" else "traffic_driving"
    )
    if primary == "awareness":
        support_a = "traffic_driving"
    shares = ((primary, 60), (support_a, 20), (support_b, 20))
    counts = {intent: (total * share) // 100 for intent, share in shares}
    remainders = sorted(
        shares,
        key=lambda pair: ((total * pair[1]) % 100, -pair[1]),
        reverse=True,
    )
    shortfall = total - sum(counts.values())
    for intent, _ in remainders:
        if shortfall <= 0:
            break
        counts[intent] += 1
        shortfall -= 1
    mix: list[ContentIntent] = []
    for intent, _ in shares:
        mix.extend([intent] * counts[intent])
    return mix


def _intent_directive(intent: ContentIntent, goal: str) -> str:
    directives: dict[str, str] = {
        "awareness": "Introduce the brand story behind this goal: ",
        "traffic_driving": "Drive qualified clicks to the storefront for: ",
        "engagement": "Start a conversation your audience answers about: ",
        "conversion": "Show the product solving a concrete problem for: ",
        "lead_magnet": "Offer the gated asset and capture the lead for: ",
        "retention": "Reward existing customers and invite a repeat for: ",
    }
    return directives[intent] + goal


def plan_content_calendar(
    brief: ContentCalendarBrief | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> ContentCalendarPlan:
    """Deterministically compile a bounded, approval-ready posting calendar."""

    parsed = (
        brief
        if isinstance(brief, ContentCalendarBrief)
        else ContentCalendarBrief.model_validate(brief)
    )
    if (scope is None) != (scope_keyring is None):
        raise DemandGenValidationError(
            "verified planning requires both scope and scope_keyring"
        )
    workflow_scope = _workflow_scope(scope) if scope is not None else None
    status, snapshot = _verify_brief_evidence(
        parsed, scope=workflow_scope, scope_keyring=scope_keyring
    )

    bottleneck = snapshot.bottleneck
    primary: ContentIntent = (
        _BOTTLENECK_INTENT[bottleneck.rate_name]
        if bottleneck is not None
        else "awareness"
    )
    window_start = _parse_timestamp(parsed.window_start)
    per_channel = parsed.window_weeks * parsed.posts_per_week_per_channel
    accounts = sorted(
        parsed.channel_accounts,
        key=lambda account: (account.channel, account.connector_account_ref),
    )
    items: list[ContentBriefItem] = []
    intent_counts: dict[str, int] = {}
    for account_index, account in enumerate(accounts):
        mix = _intent_mix(primary, per_channel)
        for position in range(per_channel):
            week = position // parsed.posts_per_week_per_channel
            slot = position % parsed.posts_per_week_per_channel
            day_offset, hour = _WEEKLY_SLOTS[slot]
            scheduled = window_start + timedelta(days=week * 7 + day_offset)
            scheduled = scheduled.replace(hour=hour, minute=0, second=0, microsecond=0)
            if scheduled < window_start:
                # A week-zero day-zero slot whose hour precedes the window's
                # opening time would land in the past; pin it just inside.
                scheduled = window_start + timedelta(hours=1)
            intent = mix[position]
            theme = parsed.content_themes[
                (account_index + position) % len(parsed.content_themes)
            ]
            item_ref = (
                f"{parsed.calendar_ref}-{account.channel}-a{account_index + 1}"
                f"-w{week + 1}-p{slot + 1}"
            )
            body = {
                "item_ref": item_ref,
                "channel": account.channel,
                "connector_account_ref": account.connector_account_ref,
                "provider_target_id": account.provider_target_id,
                "scheduled_for": _format_timestamp(scheduled),
                "intent": intent,
                "theme": theme,
                "message_directive": _intent_directive(intent, parsed.campaign_goal),
                "media_required": account.channel == "instagram",
                "link_required": intent
                in {"traffic_driving", "conversion", "lead_magnet"},
            }
            items.append(_build_brief_item(body))
            intent_counts[intent] = intent_counts.get(intent, 0) + 1

    allocations = tuple(
        IntentAllocation(intent=intent, item_count=count)
        for intent, count in sorted(intent_counts.items())
    )
    plan_kwargs: dict[str, Any] = {
        "calendar_ref": parsed.calendar_ref,
        "planning_as_of": parsed.planning_as_of,
        "window_start": parsed.window_start,
        "window_weeks": parsed.window_weeks,
        "campaign_goal": parsed.campaign_goal,
        "evidence_scope_status": status,
        "target_bottleneck": (bottleneck.rate_name if bottleneck is not None else None),
        "primary_intent": primary,
        "intent_allocations": allocations,
        "informed_by": InformedBy(
            funnel_digest=snapshot.funnel_digest,
            learning_digests=tuple(entry.entry_digest for entry in parsed.learnings),
        ),
        "items": tuple(items),
    }
    if scope_keyring is None or workflow_scope is None:
        return ContentCalendarPlan(**plan_kwargs)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = ContentCalendarPlan(
        **plan_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        plan_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_CALENDAR_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"plan_digest"},
        exclude_none=True,
    )
    sealed["plan_hmac"] = signature
    return ContentCalendarPlan.model_validate(sealed)


def verify_content_calendar_plan(
    value: ContentCalendarPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ContentCalendarPlan:
    plan = ContentCalendarPlan.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, ContentCalendarPlan)
        else value
    )
    if (
        plan.receipt_key_id is None
        or plan.exact_scope_digest is None
        or plan.plan_hmac is None
    ):
        raise DemandGenValidationError("the calendar plan carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=plan.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(plan.exact_scope_digest, expected_scope_digest):
        raise DemandGenValidationError("calendar plan attestation failed verification")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=plan.receipt_key_id,
        domain=_CALENDAR_HMAC_DOMAIN,
        payload=plan.hmac_payload(),
    )
    if not hmac.compare_digest(plan.plan_hmac, expected_hmac):
        raise DemandGenValidationError("calendar plan attestation failed verification")
    return plan


# ---------------------------------------------------------------------------
# Audience growth
# ---------------------------------------------------------------------------


class AudienceGrowthBrief(_StrictModel):
    plan_ref: PortableRef
    planning_as_of: str
    growth_goal: LongText
    window_start: str
    window_weeks: int = Field(ge=1, le=_MAX_WEEKS)
    actions_per_week_per_channel: int = Field(ge=1, le=_MAX_POSTS_PER_WEEK)
    channel_accounts: tuple[DemandGenChannelAccount, ...] = Field(
        min_length=1, max_length=_MAX_CHANNEL_ACCOUNTS
    )
    lead_magnet_title: ShortText | None = None
    funnel_snapshot: GrowthFunnelSnapshot
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_LEARNINGS
    )
    max_snapshot_age_hours: int = Field(default=720, ge=1, le=8_760)

    @field_validator("planning_as_of", "window_start")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("channel_accounts", "learnings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _bounded_brief(self) -> "AudienceGrowthBrief":
        if len(self.plan_ref) > 40:
            raise ValueError(
                "plan_ref must stay within 40 characters so generated "
                "item refs fit the portable ref format"
            )
        if _parse_timestamp(self.window_start) < _parse_timestamp(self.planning_as_of):
            raise ValueError("the growth window cannot begin in the past")
        accounts = [
            (item.channel, item.connector_account_ref) for item in self.channel_accounts
        ]
        if len(accounts) != len(set(accounts)):
            raise ValueError("channel accounts must be unique")
        total = (
            len(self.channel_accounts)
            * self.window_weeks
            * self.actions_per_week_per_channel
        )
        if total > _MAX_CALENDAR_ITEMS:
            raise ValueError(
                "the brief would exceed the maximum of "
                f"{_MAX_CALENDAR_ITEMS} growth actions"
            )
        return self


class AudienceGrowthPlan(_StrictModel):
    schema_id: Literal["lightbulb.growth_audience_growth_plan.v1"] = Field(
        default=AUDIENCE_GROWTH_PLAN_SCHEMA,
        alias="schema",
    )
    plan_ref: PortableRef
    planning_as_of: str
    window_start: str
    window_weeks: int = Field(ge=1, le=_MAX_WEEKS)
    growth_goal: LongText
    evidence_scope_status: EvidenceScopeStatus
    strategy: AudienceStrategy
    strategy_rationale: ShortText
    max_actions_per_week_per_channel: int = Field(ge=1, le=_MAX_POSTS_PER_WEEK)
    informed_by: InformedBy
    items: tuple[ContentBriefItem, ...] = Field(
        min_length=1, max_length=_MAX_CALENDAR_ITEMS
    )
    dispatchable_by_planner: Literal[False] = False
    plan_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    plan_hmac: Sha256Digest | None = None

    @field_validator("planning_as_of", "window_start")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("items", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "AudienceGrowthPlan":
        refs = [item.item_ref for item in self.items]
        if len(refs) != len(set(refs)):
            raise ValueError("growth action refs must be unique")
        if self.strategy == "lead_magnet_funnel" and not any(
            item.intent == "lead_magnet" for item in self.items
        ):
            raise ValueError("a lead magnet plan must contain lead magnet items")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.plan_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError("growth plan attestation fields must be supplied together")
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.plan_hmac is None
        ):
            raise ValueError(
                "verified growth plans require a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest", "plan_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.plan_digest != "0" * 64 and self.plan_digest != expected:
            raise ValueError("plan_digest does not match the canonical payload")
        object.__setattr__(self, "plan_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_hmac", "plan_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _audience_strategy(
    snapshot: GrowthFunnelSnapshot,
    *,
    has_lead_magnet: bool,
) -> tuple[AudienceStrategy, str]:
    audience_stage = snapshot.stage("audience")
    bottleneck = snapshot.bottleneck
    if (
        has_lead_magnet
        and bottleneck is not None
        and bottleneck.rate_name == "lead_capture"
    ):
        return (
            "lead_magnet_funnel",
            "lead_capture is the verified bottleneck and a magnet exists",
        )
    if audience_stage.completeness == "unknown":
        return (
            "follower_growth",
            "no admissible audience evidence; build the audience first",
        )
    if has_lead_magnet and snapshot.stage("conversion").completeness == "unknown":
        return (
            "lead_magnet_funnel",
            "audience exists but conversion evidence is absent; capture leads",
        )
    return (
        "follower_growth",
        "grow reach on the measured audience baseline",
    )


def plan_audience_growth(
    brief: AudienceGrowthBrief | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> AudienceGrowthPlan:
    """Deterministically compile a bounded audience-growth action plan."""

    parsed = (
        brief
        if isinstance(brief, AudienceGrowthBrief)
        else AudienceGrowthBrief.model_validate(brief)
    )
    if (scope is None) != (scope_keyring is None):
        raise DemandGenValidationError(
            "verified planning requires both scope and scope_keyring"
        )
    workflow_scope = _workflow_scope(scope) if scope is not None else None
    status, snapshot = _verify_brief_evidence(
        parsed, scope=workflow_scope, scope_keyring=scope_keyring
    )
    strategy, rationale = _audience_strategy(
        snapshot, has_lead_magnet=parsed.lead_magnet_title is not None
    )

    window_start = _parse_timestamp(parsed.window_start)
    per_channel = parsed.window_weeks * parsed.actions_per_week_per_channel
    accounts = sorted(
        parsed.channel_accounts,
        key=lambda account: (account.channel, account.connector_account_ref),
    )
    items: list[ContentBriefItem] = []
    for account_index, account in enumerate(accounts):
        for position in range(per_channel):
            week = position // parsed.actions_per_week_per_channel
            slot = position % parsed.actions_per_week_per_channel
            day_offset, hour = _WEEKLY_SLOTS[slot]
            scheduled = window_start + timedelta(days=week * 7 + day_offset)
            scheduled = scheduled.replace(hour=hour, minute=0, second=0, microsecond=0)
            if scheduled < window_start:
                # A week-zero day-zero slot whose hour precedes the window's
                # opening time would land in the past; pin it just inside.
                scheduled = window_start + timedelta(hours=1)
            if strategy == "lead_magnet_funnel" and position % 2 == 0:
                intent: ContentIntent = "lead_magnet"
                theme = parsed.lead_magnet_title or "lead magnet"
                directive = (
                    "Offer the gated asset and capture the lead for: "
                    + parsed.growth_goal
                )
            else:
                intent = "engagement" if position % 3 == 2 else "awareness"
                theme = "audience growth"
                directive = _intent_directive(intent, parsed.growth_goal)
            item_ref = (
                f"{parsed.plan_ref}-{account.channel}-a{account_index + 1}"
                f"-w{week + 1}-p{slot + 1}"
            )
            items.append(
                _build_brief_item(
                    {
                        "item_ref": item_ref,
                        "channel": account.channel,
                        "connector_account_ref": account.connector_account_ref,
                        "provider_target_id": account.provider_target_id,
                        "scheduled_for": _format_timestamp(scheduled),
                        "intent": intent,
                        "theme": theme,
                        "message_directive": directive,
                        "media_required": account.channel == "instagram",
                        "link_required": intent == "lead_magnet",
                    }
                )
            )

    plan_kwargs: dict[str, Any] = {
        "plan_ref": parsed.plan_ref,
        "planning_as_of": parsed.planning_as_of,
        "window_start": parsed.window_start,
        "window_weeks": parsed.window_weeks,
        "growth_goal": parsed.growth_goal,
        "evidence_scope_status": status,
        "strategy": strategy,
        "strategy_rationale": rationale,
        "max_actions_per_week_per_channel": parsed.actions_per_week_per_channel,
        "informed_by": InformedBy(
            funnel_digest=snapshot.funnel_digest,
            learning_digests=tuple(entry.entry_digest for entry in parsed.learnings),
        ),
        "items": tuple(items),
    }
    if scope_keyring is None or workflow_scope is None:
        return AudienceGrowthPlan(**plan_kwargs)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = AudienceGrowthPlan(
        **plan_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        plan_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_AUDIENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"plan_digest"},
        exclude_none=True,
    )
    sealed["plan_hmac"] = signature
    return AudienceGrowthPlan.model_validate(sealed)


def verify_audience_growth_plan(
    value: AudienceGrowthPlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> AudienceGrowthPlan:
    plan = AudienceGrowthPlan.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, AudienceGrowthPlan)
        else value
    )
    if (
        plan.receipt_key_id is None
        or plan.exact_scope_digest is None
        or plan.plan_hmac is None
    ):
        raise DemandGenValidationError("the growth plan carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=plan.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(plan.exact_scope_digest, expected_scope_digest):
        raise DemandGenValidationError("growth plan attestation failed verification")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=plan.receipt_key_id,
        domain=_AUDIENCE_HMAC_DOMAIN,
        payload=plan.hmac_payload(),
    )
    if not hmac.compare_digest(plan.plan_hmac, expected_hmac):
        raise DemandGenValidationError("growth plan attestation failed verification")
    return plan


__all__ = [
    "AUDIENCE_GROWTH_PLAN_SCHEMA",
    "CONTENT_CALENDAR_PLAN_SCHEMA",
    "AudienceGrowthBrief",
    "AudienceGrowthPlan",
    "ContentBriefItem",
    "ContentCalendarBrief",
    "ContentCalendarPlan",
    "DemandGenChannelAccount",
    "DemandGenValidationError",
    "InformedBy",
    "IntentAllocation",
    "plan_audience_growth",
    "plan_content_calendar",
    "verify_audience_growth_plan",
    "verify_content_calendar_plan",
]
