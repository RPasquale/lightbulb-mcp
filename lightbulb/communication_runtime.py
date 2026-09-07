"""Restart-safe reply tracing on the governed communication rail.

This module starts only after :mod:`lightbulb.communication_materializer` has
proved an approved email write.  Raw provider payloads, addresses, subjects,
and bodies remain transient inputs.  Durable runtime records contain only
sealed communication artifacts, opaque references, and commitments.

The runtime deliberately has no connector executor.  Reply classifications
may propose capabilities, but every proposal requires human review and no
effect is executed here.
"""

from __future__ import annotations

import hmac
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping, Protocol
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from lightbulb.communication_contracts import (
    CommunicationArtifact,
    CommunicationAuthenticityGrade,
    CommunicationChannel,
    CommunicationDispatchReceipt,
    CommunicationEndpointBinding,
    CommunicationInboundMessage,
    CommunicationIntentScore,
    CommunicationOutcomeDimension,
    CommunicationOutcomeFact,
    CommunicationOutcomeObservation,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationProviderEvent,
    CommunicationProviderEventType,
    CommunicationReplyInterpretation,
    CommunicationScopeKeyRing,
    CommunicationThreadBinding,
    CommunicationTouchpointType,
    CrmTouchpointReceipt,
    GrowthSourceBinding,
    communication_canonical_digest,
    communication_private_value_digest,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.communication_materializer import (
    CommunicationExternalEffectState,
    CommunicationGmailRoute,
    CommunicationMaterializationResult,
    CommunicationMaterializationStatus,
    communication_endpoint_address_commitment,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_PRIVATE_GMAIL_INBOUND_SCHEMA = (
    "lightbulb.communication_private_gmail_inbound.v1"
)
COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA = (
    "lightbulb.communication_crm_trace_binding.v1"
)
COMMUNICATION_CRM_TRACE_BINDING_SCHEMA = "lightbulb.communication_crm_trace_binding.v2"
COMMUNICATION_GMAIL_TRACE_RESULT_SCHEMA = (
    "lightbulb.communication_gmail_trace_result.v1"
)
COMMUNICATION_TRACE_RESULT_SCHEMA = "lightbulb.communication_trace_result.v2"

_EMAIL_RE = re.compile(r"^[^\s@\r\n]+@[^\s@\r\n]+\.[^\s@\r\n]+$")
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TAXONOMY_REF = "communication-reply-taxonomy-v1"
_TAXONOMY_VERSION = 1
_RULE_ENGINE_SCHEMA = "lightbulb.communication_reply_rules.v1"
_EXPLICIT_OPT_OUT_RE = re.compile(
    r"(?i)^\s*(?:please\s+)?(?:"
    r"unsubscribe(?:\s+me)?(?:\s+from\s+(?:(?:this|your)\s+)?(?:list|emails?|mailing\s+list))?(?:\s+and\s+remove\s+me)?"
    r"|remove\s+me(?:\s+from\s+(?:(?:this|your)\s+)?(?:list|emails?|mailing\s+list))?"
    r"|opt\s+me\s+out"
    r"|do\s+not\s+(?:contact|email)\s+me(?:\s+again)?"
    r"|stop\s+(?:contacting|emailing|sending\s+emails?\s+to)\s+me"
    r")(?:\s*[,;.-]?\s*(?:please|thanks|thank\s+you))?[.!]*\s*$"
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
        allow_inf_nan=False,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _timestamp(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label)


def _utc_text(value: datetime) -> str:
    return _utc(value, label="timestamp").isoformat().replace("+00:00", "Z")


def _visible_ref(value: str, *, label: str, maximum: int = 240) -> str:
    clean = value.strip()
    if (
        not clean
        or len(clean) > maximum
        or not _VISIBLE_REF_RE.fullmatch(clean)
        or any(ord(character) < 33 for character in clean)
    ):
        raise ValueError(f"{label} contains unsupported characters")
    return clean


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(value, DynamicWorkflowScope):
        return DynamicWorkflowScope.model_validate(value.model_dump(mode="python"))
    return DynamicWorkflowScope.model_validate(value)


class CommunicationEmailRuntimeRoute(Protocol):
    """Closed structural view used by the provider-neutral CRM runtime."""

    project_ref: str
    connector_account_ref: str
    route_digest: str
    tool: str

    def model_dump(self, **kwargs: Any) -> dict[str, Any]: ...


def _communication_runtime_route(
    value: CommunicationEmailRuntimeRoute | Mapping[str, Any],
) -> CommunicationEmailRuntimeRoute:
    if isinstance(value, CommunicationGmailRoute):
        return value
    # Outlook is imported lazily to keep the shared runtime below the channel
    # module in the dependency graph.  Exact class identity keeps this closed;
    # a caller-supplied duck type cannot become runtime authority.
    try:
        from lightbulb.communication_outlook import CommunicationOutlookRoute
    except ImportError:  # pragma: no cover - only possible during a broken install
        CommunicationOutlookRoute = None  # type: ignore[assignment,misc]
    if CommunicationOutlookRoute is not None and isinstance(
        value,
        CommunicationOutlookRoute,
    ):
        return value
    try:
        from lightbulb.communication_channels import CommunicationChannelWriteRoute
    except ImportError:  # pragma: no cover - only possible during a broken install
        CommunicationChannelWriteRoute = None  # type: ignore[assignment,misc]
    if CommunicationChannelWriteRoute is not None and isinstance(
        value,
        CommunicationChannelWriteRoute,
    ):
        return value
    if isinstance(value, Mapping):
        # Backwards-compatible mapping input remains the Gmail public surface.
        return CommunicationGmailRoute.model_validate(value)
    raise ValueError("communication runtime route is not SDK-owned")


def _runtime_channel(route: CommunicationEmailRuntimeRoute) -> CommunicationChannel:
    platform = getattr(route, "platform", None)
    if platform in {CommunicationChannel.SLACK, CommunicationChannel.TEAMS}:
        return platform
    return CommunicationChannel.EMAIL


class CommunicationPrivateInbound(_StrictModel):
    """Transient email reply content resolved by the trusted host.

    None of these private values are copied into the runtime result,
    replay repository, CRM sink, or outcome observation.
    """

    schema_id: Literal["lightbulb.communication_private_gmail_inbound.v1"] = Field(
        default=COMMUNICATION_PRIVATE_GMAIL_INBOUND_SCHEMA, alias="schema"
    )
    private_payload_ref: str = Field(min_length=1, max_length=200)
    private_content_ref: str = Field(min_length=1, max_length=200)
    provider_event_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_thread_id: str = Field(min_length=1, max_length=512, repr=False)
    in_reply_to_message_id: str = Field(min_length=1, max_length=512, repr=False)
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    sender_address: str = Field(min_length=3, max_length=998, repr=False)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=3, max_length=998, repr=False)
    subject: str = Field(default="", max_length=998, repr=False)
    body: str = Field(min_length=1, max_length=200_000, repr=False)
    raw_payload: str = Field(min_length=1, max_length=1_048_576, repr=False)
    provider_occurred_at: str

    @field_validator(
        "private_payload_ref",
        "private_content_ref",
        "sender_endpoint_ref",
        "recipient_endpoint_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible_ref(value, label=info.field_name, maximum=200)

    @field_validator(
        "provider_event_id",
        "provider_message_id",
        "provider_thread_id",
        "in_reply_to_message_id",
    )
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        return _visible_ref(value, label=info.field_name, maximum=512)

    @field_validator("sender_address", "recipient_address")
    @classmethod
    def _addresses(cls, value: str, info: Any) -> str:
        clean = value.strip()
        if not _EMAIL_RE.fullmatch(clean):
            raise ValueError(f"{info.field_name} must be one valid email address")
        return clean

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("subject must not contain header control characters")
        return value

    @field_validator("body", "raw_payload")
    @classmethod
    def _private_text(cls, value: str, info: Any) -> str:
        if "\x00" in value:
            raise ValueError(f"{info.field_name} must not contain NUL")
        return value

    @field_validator("provider_occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _utc_text(_timestamp(value, label="provider_occurred_at"))

    def payload_digest(self) -> str:
        return communication_private_value_digest(self.raw_payload)

    def content_digest(self) -> str:
        return communication_canonical_digest(
            {
                "schema": "lightbulb.communication_private_content.v1",
                "subject": self.subject,
                "body": self.body,
            }
        )

    def provider_event_commitment(self) -> str:
        return communication_private_value_digest(self.provider_event_id)

    def provider_message_commitment(self) -> str:
        return communication_private_value_digest(self.provider_message_id)

    def provider_thread_commitment(self) -> str:
        return communication_private_value_digest(self.provider_thread_id)

    def parent_message_commitment(self) -> str:
        return communication_private_value_digest(self.in_reply_to_message_id)


class CommunicationCrmTraceBinding(CommunicationArtifact):
    """Sealed CRM coordinates bound to one exact contact party and endpoint."""

    model_config = ConfigDict(revalidate_instances="never")

    schema_id: Literal[
        "lightbulb.communication_crm_trace_binding.v1",
        "lightbulb.communication_crm_trace_binding.v2",
    ] = Field(
        default=COMMUNICATION_CRM_TRACE_BINDING_SCHEMA, alias="schema"
    )
    contact_party_ref: str = Field(min_length=1, max_length=200)
    contact_party_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    contact_endpoint_ref: str = Field(min_length=1, max_length=200)
    contact_endpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    crm_contact_ref: str = Field(min_length=1, max_length=200)
    crm_account_ref: str | None = Field(default=None, max_length=200)
    crm_deal_ref: str | None = Field(default=None, max_length=200)
    crm_conversation_ref: str | None = Field(default=None, max_length=36)
    associated_source_ref: str = Field(min_length=1, max_length=200)
    associated_source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    growth_source: GrowthSourceBinding | None = None

    @model_validator(mode="before")
    @classmethod
    def _closed_schema_shape(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        schema = value.get(
            "schema",
            value.get("schema_id", COMMUNICATION_CRM_TRACE_BINDING_SCHEMA),
        )
        if (
            schema == COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA
            and "crm_conversation_ref" in value
        ):
            raise ValueError("legacy CRM trace binding cannot carry conversation ref")
        if (
            schema == COMMUNICATION_CRM_TRACE_BINDING_SCHEMA
            and "crm_conversation_ref" not in value
        ):
            raise ValueError("CRM trace binding v2 requires crm_conversation_ref")
        return value

    @field_validator(
        "crm_contact_ref",
        "crm_account_ref",
        "crm_deal_ref",
        "associated_source_ref",
        "contact_party_ref",
        "contact_endpoint_ref",
    )
    @classmethod
    def _crm_refs(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _visible_ref(value, label=info.field_name, maximum=200)

    @field_validator("crm_conversation_ref")
    @classmethod
    def _conversation_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = UUID(value)
        except (TypeError, ValueError):
            raise ValueError("crm_conversation_ref must use canonical UUID text") from None
        if str(parsed) != value:
            raise ValueError("crm_conversation_ref must use canonical UUID text")
        return value

    @model_validator(mode="after")
    def _versioned_conversation_ref(self) -> "CommunicationCrmTraceBinding":
        if (
            self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_SCHEMA
            and self.crm_conversation_ref is None
        ):
            raise ValueError("CRM trace binding v2 requires crm_conversation_ref")
        if (
            self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA
            and self.crm_conversation_ref is not None
        ):
            raise ValueError("legacy CRM trace binding cannot carry conversation ref")
        if self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_SCHEMA:
            for field_name in (
                "crm_contact_ref",
                "crm_account_ref",
                "crm_deal_ref",
            ):
                value = getattr(self, field_name)
                if value is None:
                    continue
                try:
                    parsed = UUID(value)
                except (TypeError, ValueError):
                    raise ValueError(
                        f"{field_name} must use canonical UUID text in CRM trace binding v2"
                    ) from None
                if str(parsed) != value:
                    raise ValueError(
                        f"{field_name} must use canonical UUID text in CRM trace binding v2"
                    )
        return self

    @model_serializer(mode="wrap")
    def _serialize_closed_schema(self, handler: Any) -> dict[str, Any]:
        payload = handler(self)
        if self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA:
            payload.pop("crm_conversation_ref", None)
        return payload

    def digest_payload(self) -> dict[str, Any]:
        payload = super().digest_payload()
        if self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA:
            payload.pop("crm_conversation_ref", None)
        return payload

    def hmac_payload(self) -> dict[str, Any]:
        payload = super().hmac_payload()
        if self.schema_id == COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA:
            payload.pop("crm_conversation_ref", None)
        return payload


class CommunicationTraceResult(_StrictModel):
    """Privacy-minimised result of one exactly-once communication trace.

    New results use a provider-neutral v2 schema. The original Gmail identifier
    remains accepted only as the exact legacy email replay shape.
    """

    schema_id: Literal[
        "lightbulb.communication_gmail_trace_result.v1",
        "lightbulb.communication_trace_result.v2",
    ] = Field(
        default=COMMUNICATION_TRACE_RESULT_SCHEMA, alias="schema"
    )
    inbound_message: CommunicationInboundMessage
    interpretation: CommunicationReplyInterpretation
    touchpoint_receipts: tuple[CrmTouchpointReceipt, ...] = Field(
        min_length=3,
        max_length=3,
    )
    outcome_observation: CommunicationOutcomeObservation
    replayed: bool = False

    @field_validator("touchpoint_receipts", mode="before")
    @classmethod
    def _touchpoints_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _exact_trace(self) -> "CommunicationTraceResult":
        expected_types = (
            CommunicationTouchpointType.OUTBOUND,
            CommunicationTouchpointType.INBOUND,
            CommunicationTouchpointType.REPLY,
        )
        if tuple(item.touchpoint_type for item in self.touchpoint_receipts) != (
            expected_types
        ):
            raise ValueError("trace requires outbound, inbound, and reply touchpoints")
        channels = {item.channel for item in self.touchpoint_receipts}
        if len(channels) != 1:
            raise ValueError("trace touchpoints must retain one exact channel")
        schemas = {item.schema_id for item in self.touchpoint_receipts}
        if self.schema_id == COMMUNICATION_GMAIL_TRACE_RESULT_SCHEMA:
            if schemas != {"lightbulb.crm_touchpoint_receipt.v1"} or channels != {
                CommunicationChannel.EMAIL
            }:
                raise ValueError("legacy trace requires exact email touchpoint v1 receipts")
        elif schemas != {"lightbulb.crm_touchpoint_receipt.v2"}:
            raise ValueError("trace v2 requires exact touchpoint v2 receipts")
        outbound, inbound, reply = self.touchpoint_receipts
        crm_identities = {
            (
                item.crm_contact_ref,
                item.crm_account_ref,
                item.crm_deal_ref,
                item.thread_ref,
            )
            for item in self.touchpoint_receipts
        }
        if len(crm_identities) != 1 or outbound.thread_ref != self.inbound_message.thread_ref:
            raise ValueError("trace touchpoints must retain one exact CRM thread")
        if self.outcome_observation.thread_ref != outbound.thread_ref:
            raise ValueError("outcome observation must retain the exact CRM thread")
        if (
            outbound.message_artifact_digest
            != self.outcome_observation.dispatch_receipt_digest
            or inbound.message_artifact_digest != self.inbound_message.artifact_digest
            or reply.message_artifact_digest != self.interpretation.artifact_digest
        ):
            raise ValueError("trace touchpoints do not bind their exact message artifacts")
        if (
            self.interpretation.inbound_message_digest
            != self.inbound_message.artifact_digest
        ):
            raise ValueError("reply interpretation does not bind the inbound message")
        if (
            self.outcome_observation.inbound_message_digest
            != self.inbound_message.artifact_digest
            or self.outcome_observation.touchpoint_receipt_digest
            != self.touchpoint_receipts[-1].artifact_digest
            or self.outcome_observation.causal_claim_ready
        ):
            raise ValueError(
                "outcome observation does not bind the exact non-causal trace"
            )
        return self


class CommunicationReplayError(RuntimeError):
    """Base error for replay-custody failures."""


class CommunicationReplayConflict(CommunicationReplayError):
    """A dedupe identity was previously claimed for different evidence."""


class CommunicationReplayInProgress(CommunicationReplayError):
    """The exact message is already being processed under a live lease."""


class CommunicationReplayCapacityExceeded(CommunicationReplayError):
    """The safe in-memory repository is full and refuses unsafe eviction."""


class CommunicationReplayClaim(_StrictModel):
    claim_ref: str = Field(min_length=1, max_length=200)
    dedupe_keys: tuple[str, ...] = Field(min_length=1, max_length=8)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lease_expires_at: str
    replayed_result: CommunicationTraceResult | None = None

    @field_validator("dedupe_keys", mode="before")
    @classmethod
    def _keys_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("dedupe_keys")
    @classmethod
    def _valid_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            _SHA256_RE.fullmatch(item) is None for item in value
        ):
            raise ValueError("dedupe keys must be unique SHA-256 digests")
        return value

    @field_validator("lease_expires_at")
    @classmethod
    def _lease_timestamp(cls, value: str) -> str:
        return _utc_text(_timestamp(value, label="lease_expires_at"))


class CommunicationReplayRepository(Protocol):
    """Durable claim/complete boundary for restart-safe message dedupe."""

    def claim(
        self,
        *,
        dedupe_keys: tuple[str, ...],
        request_digest: str,
        claimed_at: datetime,
        lease_for: timedelta,
    ) -> CommunicationReplayClaim: ...

    def complete(
        self,
        claim: CommunicationReplayClaim,
        *,
        result: CommunicationTraceResult,
    ) -> None: ...

    def release(self, claim: CommunicationReplayClaim) -> None: ...


@dataclass
class _ReplayEntry:
    request_digest: str
    claim_ref: str | None
    lease_expires_at: datetime | None
    result: CommunicationTraceResult | None


class InMemoryCommunicationReplayRepository:
    """Thread-safe adapter that never evicts completed dedupe evidence."""

    def __init__(self, *, max_keys: int = 100_000) -> None:
        if max_keys < 2:
            raise ValueError("max_keys must be at least two")
        self._max_keys = max_keys
        self._entries: dict[str, _ReplayEntry] = {}
        self._lock = threading.RLock()

    def claim(
        self,
        *,
        dedupe_keys: tuple[str, ...],
        request_digest: str,
        claimed_at: datetime,
        lease_for: timedelta,
    ) -> CommunicationReplayClaim:
        current = _utc(claimed_at, label="claimed_at")
        if not dedupe_keys or len(dedupe_keys) != len(set(dedupe_keys)):
            raise ValueError("dedupe_keys must be non-empty and unique")
        if any(_SHA256_RE.fullmatch(item) is None for item in dedupe_keys):
            raise ValueError("dedupe_keys must be SHA-256 digests")
        if _SHA256_RE.fullmatch(request_digest) is None:
            raise ValueError("request_digest must be a SHA-256 digest")
        if lease_for <= timedelta(0) or lease_for > timedelta(minutes=15):
            raise ValueError(
                "lease_for must be greater than zero and at most 15 minutes"
            )

        with self._lock:
            entries = [self._entries.get(key) for key in dedupe_keys]
            present = [entry for entry in entries if entry is not None]
            for entry in present:
                if not hmac.compare_digest(entry.request_digest, request_digest):
                    raise CommunicationReplayConflict(
                        "communication dedupe identity is bound to different evidence"
                    )

            completed = [entry for entry in present if entry.result is not None]
            if completed:
                canonical = communication_canonical_digest(
                    completed[0].result.model_dump(mode="json", by_alias=True)
                )
                if any(
                    entry.result is None
                    or communication_canonical_digest(
                        entry.result.model_dump(mode="json", by_alias=True)
                    )
                    != canonical
                    for entry in present
                ):
                    raise CommunicationReplayConflict(
                        "communication dedupe keys do not resolve to one completed result"
                    )
                replayed = completed[0].result.model_copy(update={"replayed": True})
                return CommunicationReplayClaim(
                    claim_ref=f"replay:{request_digest[:48]}",
                    dedupe_keys=dedupe_keys,
                    request_digest=request_digest,
                    lease_expires_at=_utc_text(current),
                    replayed_result=replayed,
                )

            for entry in present:
                if (
                    entry.claim_ref is not None
                    and entry.lease_expires_at is not None
                    and entry.lease_expires_at > current
                ):
                    raise CommunicationReplayInProgress(
                        "communication message already has a live processing lease"
                    )

            missing_count = sum(key not in self._entries for key in dedupe_keys)
            if len(self._entries) + missing_count > self._max_keys:
                raise CommunicationReplayCapacityExceeded(
                    "communication replay repository is full; no evidence was evicted"
                )

            claim_ref = f"claim:{uuid4()}"
            lease_expires_at = current + lease_for
            for key in dedupe_keys:
                self._entries[key] = _ReplayEntry(
                    request_digest=request_digest,
                    claim_ref=claim_ref,
                    lease_expires_at=lease_expires_at,
                    result=None,
                )
            return CommunicationReplayClaim(
                claim_ref=claim_ref,
                dedupe_keys=dedupe_keys,
                request_digest=request_digest,
                lease_expires_at=_utc_text(lease_expires_at),
            )

    def complete(
        self,
        claim: CommunicationReplayClaim,
        *,
        result: CommunicationTraceResult,
    ) -> None:
        if claim.replayed_result is not None:
            raise CommunicationReplayConflict(
                "a replay claim cannot be completed again"
            )
        stored_result = CommunicationTraceResult.model_validate(
            result.model_dump(mode="python", by_alias=True)
        ).model_copy(update={"replayed": False})
        with self._lock:
            entries = [self._entries.get(key) for key in claim.dedupe_keys]
            if any(
                entry is None
                or entry.claim_ref != claim.claim_ref
                or not hmac.compare_digest(
                    entry.request_digest,
                    claim.request_digest,
                )
                or entry.result is not None
                for entry in entries
            ):
                raise CommunicationReplayConflict(
                    "communication replay claim lost custody before completion"
                )
            for key in claim.dedupe_keys:
                self._entries[key] = _ReplayEntry(
                    request_digest=claim.request_digest,
                    claim_ref=None,
                    lease_expires_at=None,
                    result=stored_result,
                )

    def release(self, claim: CommunicationReplayClaim) -> None:
        if claim.replayed_result is not None:
            return
        with self._lock:
            for key in claim.dedupe_keys:
                entry = self._entries.get(key)
                if entry is not None and entry.claim_ref == claim.claim_ref:
                    self._entries.pop(key, None)


class CrmTouchpointSink(Protocol):
    """Append-only CRM boundary; implementations must be idempotent."""

    def append(
        self,
        receipt: CrmTouchpointReceipt,
        *,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> CrmTouchpointReceipt: ...


class InMemoryCrmTouchpointSink:
    """Thread-safe, privacy-minimised sink suitable for tests and local runs."""

    def __init__(self) -> None:
        self._by_ref: dict[str, CrmTouchpointReceipt] = {}
        self._by_identity: dict[str, CrmTouchpointReceipt] = {}
        self._lock = threading.RLock()

    def append(
        self,
        receipt: CrmTouchpointReceipt,
        *,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> CrmTouchpointReceipt:
        trusted = verify_communication_artifact(
            receipt,
            artifact_type=CrmTouchpointReceipt,
            scope=scope,
            scope_keyring=scope_keyring,
        )
        identity = communication_canonical_digest(
            {
                "schema": "lightbulb.crm_touchpoint_identity.v1",
                "exact_scope_digest": trusted.exact_scope_digest,
                "crm_contact_ref": trusted.crm_contact_ref,
                "thread_ref": trusted.thread_ref,
                "touchpoint_type": trusted.touchpoint_type,
                "channel": trusted.channel,
                "message_artifact_digest": trusted.message_artifact_digest,
            }
        )
        with self._lock:
            existing = self._by_ref.get(trusted.touchpoint_ref)
            semantic = self._by_identity.get(identity)
            for prior in (existing, semantic):
                if prior is not None and not hmac.compare_digest(
                    prior.artifact_digest,
                    trusted.artifact_digest,
                ):
                    raise CommunicationReplayConflict(
                        "CRM touchpoint identity is bound to different evidence"
                    )
            if existing is not None:
                return existing
            if semantic is not None:
                return semantic
            self._by_ref[trusted.touchpoint_ref] = trusted
            self._by_identity[identity] = trusted
            return trusted

    @property
    def receipts(self) -> tuple[CrmTouchpointReceipt, ...]:
        with self._lock:
            return tuple(self._by_ref.values())


@dataclass(frozen=True)
class _ReplyRule:
    intent_code: str
    confidence: float
    proposed_capability: str
    phrases: tuple[str, ...]
    risk_codes: tuple[str, ...] = ()


_REPLY_RULES = (
    _ReplyRule(
        intent_code="unsubscribe",
        confidence=0.99,
        proposed_capability="crm.suppress_contact",
        phrases=(
            "unsubscribe",
            "remove me",
            "opt out",
            "do not contact",
            "stop emailing",
            "stop sending",
        ),
        risk_codes=("explicit_opt_out",),
    ),
    _ReplyRule(
        intent_code="legal_security",
        confidence=0.98,
        proposed_capability="communication.route_human_review",
        phrases=(
            "attorney",
            "lawyer",
            "legal action",
            "lawsuit",
            "regulator",
            "security breach",
            "data breach",
            "phishing",
            "account compromised",
            "stolen credentials",
            "report fraud",
        ),
        risk_codes=("legal_or_security",),
    ),
    _ReplyRule(
        intent_code="payment_dispute",
        confidence=0.97,
        proposed_capability="billing.review_dispute",
        phrases=(
            "chargeback",
            "unauthorized charge",
            "unauthorised charge",
            "dispute this charge",
            "charged twice",
            "billing error",
            "payment dispute",
        ),
        risk_codes=("payment_dispute",),
    ),
    _ReplyRule(
        intent_code="meeting",
        confidence=0.94,
        proposed_capability="calendar.propose_meeting",
        phrases=(
            "schedule a call",
            "book a call",
            "book a meeting",
            "set up a meeting",
            "schedule a demo",
            "available to meet",
            "calendar link",
        ),
    ),
    _ReplyRule(
        intent_code="positive",
        confidence=0.88,
        proposed_capability="crm.propose_follow_up",
        phrases=(
            "i'm interested",
            "i am interested",
            "sounds good",
            "yes please",
            "let's proceed",
            "lets proceed",
            "happy to continue",
        ),
    ),
    _ReplyRule(
        intent_code="negative",
        confidence=0.91,
        proposed_capability="crm.propose_sequence_pause",
        phrases=(
            "not interested",
            "no thanks",
            "no thank you",
            "not a fit",
            "please decline",
            "we will pass",
        ),
    ),
)


def _classify_reply(
    body: str,
    *,
    event_type: CommunicationProviderEventType,
) -> _ReplyRule:
    normalized = " ".join(body.casefold().split())
    if event_type == CommunicationProviderEventType.UNSUBSCRIBED:
        return _REPLY_RULES[0]
    if _EXPLICIT_OPT_OUT_RE.fullmatch(normalized):
        return _REPLY_RULES[0]
    for rule in _REPLY_RULES[1:]:
        if any(phrase in normalized for phrase in rule.phrases):
            return rule
    return _ReplyRule(
        intent_code="general",
        confidence=0.55,
        proposed_capability="communication.propose_reply",
        phrases=(),
    )


def _verified_artifact(
    value: Any,
    artifact_type: type[Any],
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> Any:
    return verify_communication_artifact(
        value,
        artifact_type=artifact_type,
        scope=scope,
        scope_keyring=scope_keyring,
    )


def _deterministic_ref(prefix: str, payload: Any) -> str:
    return f"{prefix}:{communication_canonical_digest(payload)[:48]}"


class CommunicationRuntime:
    """Verify, interpret, and record one exact reply without effects."""

    def __init__(
        self,
        *,
        scope_keyring: CommunicationScopeKeyRing,
        replay_repository: CommunicationReplayRepository,
        touchpoint_sink: CrmTouchpointSink,
        max_event_age: timedelta = timedelta(days=30),
        max_receive_delay: timedelta = timedelta(days=7),
        clock_skew: timedelta = timedelta(minutes=5),
        claim_lease: timedelta = timedelta(minutes=2),
    ) -> None:
        if max_event_age <= timedelta(0) or max_event_age > timedelta(days=90):
            raise ValueError(
                "max_event_age must be greater than zero and at most 90 days"
            )
        if max_receive_delay <= timedelta(0) or max_receive_delay > timedelta(days=30):
            raise ValueError(
                "max_receive_delay must be greater than zero and at most 30 days"
            )
        if clock_skew < timedelta(0) or clock_skew > timedelta(minutes=15):
            raise ValueError("clock_skew must be between zero and 15 minutes")
        if claim_lease <= timedelta(0) or claim_lease > timedelta(minutes=15):
            raise ValueError(
                "claim_lease must be greater than zero and at most 15 minutes"
            )
        self._scope_keyring = scope_keyring
        self._replay_repository = replay_repository
        self._touchpoint_sink = touchpoint_sink
        self._max_event_age = max_event_age
        self._max_receive_delay = max_receive_delay
        self._clock_skew = clock_skew
        self._claim_lease = claim_lease

    def process_reply(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        route: CommunicationEmailRuntimeRoute | Mapping[str, Any],
        materialization: CommunicationMaterializationResult | Mapping[str, Any],
        thread: CommunicationThreadBinding | Mapping[str, Any],
        outbound_sender_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
        contact_party: CommunicationPartyRef | Mapping[str, Any],
        contact_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
        provider_event: CommunicationProviderEvent | Mapping[str, Any],
        private_inbound: CommunicationPrivateInbound | Mapping[str, Any],
        crm: CommunicationCrmTraceBinding | Mapping[str, Any],
        now: datetime,
    ) -> CommunicationTraceResult:
        """Process one sealed reply or return its completed replay.

        All validation and artifact minting happen before the replay claim.  CRM
        receipts are deterministic and the sink is append-idempotent, so a
        process crash after a partial append can safely retry after lease expiry.
        """

        current = _utc(now, label="now")
        workflow_scope = _workflow_scope(scope)
        parsed_route = _communication_runtime_route(route)
        expected_channel = _runtime_channel(parsed_route)
        parsed_materialization = CommunicationMaterializationResult.model_validate(
            materialization
        )
        if expected_channel == CommunicationChannel.EMAIL:
            parsed_private = (
                private_inbound
                if isinstance(private_inbound, CommunicationPrivateInbound)
                else CommunicationPrivateInbound.model_validate(private_inbound)
            )
        else:
            from lightbulb.communication_channels import (
                CommunicationPrivateChannelInbound,
            )

            parsed_private = (
                private_inbound
                if isinstance(private_inbound, CommunicationPrivateChannelInbound)
                else CommunicationPrivateChannelInbound.model_validate(private_inbound)
            )
            if parsed_private.platform != expected_channel:
                raise ValueError("private inbound crosses channel provider authority")

        accepted_state = (
            parsed_materialization.status
            == CommunicationMaterializationStatus.ACCEPTED
            and parsed_materialization.effect_state
            == CommunicationExternalEffectState.ACCEPTED
        )
        completed_state = (
            parsed_materialization.status
            == CommunicationMaterializationStatus.COMPLETED
            and parsed_materialization.effect_state
            == CommunicationExternalEffectState.COMPLETED
        )
        if (
            (not accepted_state and not completed_state)
            or parsed_materialization.receipt is None
        ):
            raise ValueError(
                "reply tracing requires a completed verified dispatch"
            )

        dispatch = _verified_artifact(
            parsed_materialization.receipt,
            CommunicationDispatchReceipt,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_thread = _verified_artifact(
            thread,
            CommunicationThreadBinding,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_sender = _verified_artifact(
            outbound_sender_endpoint,
            CommunicationEndpointBinding,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_contact = _verified_artifact(
            contact_endpoint,
            CommunicationEndpointBinding,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_contact_party = _verified_artifact(
            contact_party,
            CommunicationPartyRef,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        parsed_crm = _verified_artifact(
            crm,
            CommunicationCrmTraceBinding,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        event = _verified_artifact(
            provider_event,
            CommunicationProviderEvent,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )

        self._verify_exact_boundary(
            scope=workflow_scope,
            route=parsed_route,
            materialization=parsed_materialization,
            dispatch=dispatch,
            thread=trusted_thread,
            outbound_sender=trusted_sender,
            contact_party=trusted_contact_party,
            contact=trusted_contact,
            crm=parsed_crm,
            event=event,
            private=parsed_private,
            now=current,
        )

        deterministic_at = event.received_at
        inbound = self._mint_inbound(
            scope=workflow_scope,
            event=event,
            dispatch=dispatch,
            thread=trusted_thread,
            outbound_sender=trusted_sender,
            contact=trusted_contact,
            private=parsed_private,
        )
        interpretation = self._mint_interpretation(
            scope=workflow_scope,
            event=event,
            inbound=inbound,
            body=parsed_private.body,
            interpreted_at=deterministic_at,
        )
        touchpoints = self._mint_touchpoints(
            scope=workflow_scope,
            dispatch=dispatch,
            event=event,
            inbound=inbound,
            interpretation=interpretation,
            crm=parsed_crm,
        )
        observation = self._mint_observation(
            scope=workflow_scope,
            dispatch=dispatch,
            event=event,
            inbound=inbound,
            interpretation=interpretation,
            reply_touchpoint=touchpoints[-1],
            crm=parsed_crm,
        )
        result = CommunicationTraceResult(
            inbound_message=inbound,
            interpretation=interpretation,
            touchpoint_receipts=touchpoints,
            outcome_observation=observation,
        )

        dedupe_keys = self._dedupe_keys(
            event=event,
            dispatch=dispatch,
            inbound=inbound,
        )
        request_digest = communication_canonical_digest(
            {
                "schema": "lightbulb.communication_runtime_request.v2",
                "route": parsed_route.model_dump(mode="json", by_alias=True),
                "dispatch_digest": dispatch.artifact_digest,
                "thread_digest": trusted_thread.artifact_digest,
                "outbound_sender_digest": trusted_sender.artifact_digest,
                "contact_digest": trusted_contact.artifact_digest,
                "contact_party_digest": trusted_contact_party.artifact_digest,
                "provider_event_digest": event.artifact_digest,
                "payload_sha256": event.payload_sha256,
                "content_sha256": inbound.content_sha256,
                "crm": parsed_crm.model_dump(mode="json", by_alias=True),
            }
        )
        claim = self._replay_repository.claim(
            dedupe_keys=dedupe_keys,
            request_digest=request_digest,
            claimed_at=current,
            lease_for=self._claim_lease,
        )
        if claim.replayed_result is not None:
            return claim.replayed_result

        try:
            appended = tuple(
                self._touchpoint_sink.append(
                    receipt,
                    scope=workflow_scope,
                    scope_keyring=self._scope_keyring,
                )
                for receipt in touchpoints
            )
            if tuple(item.artifact_digest for item in appended) != tuple(
                item.artifact_digest for item in touchpoints
            ):
                raise CommunicationReplayConflict(
                    "CRM sink returned touchpoints for different evidence"
                )
            self._replay_repository.complete(claim, result=result)
        except Exception:
            self._replay_repository.release(claim)
            raise
        return result

    def _verify_exact_boundary(
        self,
        *,
        scope: DynamicWorkflowScope,
        route: CommunicationEmailRuntimeRoute,
        materialization: CommunicationMaterializationResult,
        dispatch: CommunicationDispatchReceipt,
        thread: CommunicationThreadBinding,
        outbound_sender: CommunicationEndpointBinding,
        contact_party: CommunicationPartyRef,
        contact: CommunicationEndpointBinding,
        crm: CommunicationCrmTraceBinding,
        event: CommunicationProviderEvent,
        private: CommunicationPrivateInbound,
        now: datetime,
    ) -> None:
        expected_channel = _runtime_channel(route)
        if route.project_ref != scope.project_ref:
            raise ValueError("communication route does not match authenticated project scope")
        if materialization.thread_ref != thread.thread_ref:
            raise ValueError(
                "materialization does not match the sealed communication thread"
            )
        if dispatch.thread_ref != thread.thread_ref:
            raise ValueError("dispatch receipt does not match the sealed thread")
        if (
            dispatch.thread_digest != thread.artifact_digest
            or dispatch.thread_version != thread.version
            or dispatch.thread_state != thread.state
            or dispatch.thread_participant_party_refs
            != thread.participant_party_refs
            or dispatch.parent_message_sha256 != thread.parent_message_sha256
        ):
            raise ValueError("dispatch receipt does not bind the exact thread artifact")
        if dispatch.parent_message_sha256 is None:
            raise ValueError("communication dispatch lacks a sealed parent target")
        if dispatch.channel != expected_channel:
            raise ValueError("tracer dispatch receipt crosses channel authority")

        exact_route = (route.connector_account_ref, route.route_digest)
        routed_artifacts = (
            (dispatch.connector_account_ref, dispatch.route_digest),
            (thread.connector_account_ref, thread.route_digest),
            (outbound_sender.connector_account_ref, outbound_sender.route_digest),
            (contact.connector_account_ref, contact.route_digest),
            (event.connector_account_ref, event.route_digest),
        )
        if any(candidate != exact_route for candidate in routed_artifacts):
            raise ValueError(
                "provider event, dispatch, thread, and endpoints must use one exact route/account"
            )
        if (
            thread.primary_channel != expected_channel
            or outbound_sender.channel != expected_channel
            or contact.channel != expected_channel
        ):
            raise ValueError("tracer requires one exact channel across thread/endpoints")
        if outbound_sender.party_ref not in thread.participant_party_refs or (
            contact.party_ref not in thread.participant_party_refs
        ):
            raise ValueError(
                "communication endpoints are not participants in the sealed thread"
            )
        if (
            contact_party.party_kind != CommunicationPartyKind.CRM_CONTACT
            or contact.party_ref != contact_party.party_ref
            or contact.party_digest != contact_party.artifact_digest
            or crm.contact_party_ref != contact_party.party_ref
            or crm.contact_party_digest != contact_party.artifact_digest
            or crm.contact_endpoint_ref != contact.endpoint_ref
            or crm.contact_endpoint_digest != contact.artifact_digest
            or thread.crm_trace_binding_digest != crm.artifact_digest
            or crm.crm_contact_ref != contact_party.crm_contact_ref
            or crm.crm_account_ref != contact_party.crm_account_ref
        ):
            raise ValueError(
                "CRM trace is not bound to the exact sealed contact party and endpoint"
            )
        if private.sender_endpoint_ref != contact.endpoint_ref or (
            private.recipient_endpoint_ref != outbound_sender.endpoint_ref
        ):
            raise ValueError(
                "private inbound endpoint references are reversed or mismatched"
            )

        if expected_channel == CommunicationChannel.EMAIL:
            expected_sender_address = communication_endpoint_address_commitment(
                endpoint_ref=contact.endpoint_ref,
                address=private.sender_address,
                key_id=contact.receipt_key_id,
                scope_keyring=self._scope_keyring,
            )
            expected_recipient_address = communication_endpoint_address_commitment(
                endpoint_ref=outbound_sender.endpoint_ref,
                address=private.recipient_address,
                key_id=outbound_sender.receipt_key_id,
                scope_keyring=self._scope_keyring,
            )
        else:
            from lightbulb.communication_channels import (
                communication_channel_endpoint_address_commitment,
            )

            expected_sender_address = communication_channel_endpoint_address_commitment(
                scope=scope,
                endpoint_ref=contact.endpoint_ref,
                address=private.sender_address,
                channel=expected_channel,
                key_id=contact.receipt_key_id,
                scope_keyring=self._scope_keyring,
            )
            expected_recipient_address = communication_channel_endpoint_address_commitment(
                scope=scope,
                endpoint_ref=outbound_sender.endpoint_ref,
                address=private.recipient_address,
                channel=expected_channel,
                key_id=outbound_sender.receipt_key_id,
                scope_keyring=self._scope_keyring,
            )
        if not hmac.compare_digest(
            contact.address_sha256,
            expected_sender_address,
        ) or not hmac.compare_digest(
            outbound_sender.address_sha256,
            expected_recipient_address,
        ):
            raise ValueError("private inbound addresses do not match sealed endpoints")

        if event.authenticity != CommunicationAuthenticityGrade.VERIFIED:
            raise ValueError("provider event authenticity must be VERIFIED")
        allowed_event_types = {CommunicationProviderEventType.REPLIED}
        if expected_channel == CommunicationChannel.EMAIL:
            allowed_event_types.add(CommunicationProviderEventType.UNSUBSCRIBED)
        if event.event_type not in allowed_event_types:
            raise ValueError("tracer accepts only channel-appropriate reply events")
        if event.dispatch_receipt_digest != dispatch.artifact_digest:
            raise ValueError("provider event does not bind the exact dispatch receipt")
        if event.private_payload_ref != private.private_payload_ref or (
            not hmac.compare_digest(event.payload_sha256, private.payload_digest())
        ):
            raise ValueError("private provider payload does not match the sealed event")

        incoming_message = private.provider_message_commitment()
        provider_thread = private.provider_thread_commitment()
        provider_event_id = private.provider_event_commitment()
        in_reply_to = private.parent_message_commitment()
        if event.provider_message_sha256 is None or not hmac.compare_digest(
            event.provider_message_sha256,
            incoming_message,
        ):
            raise ValueError("provider event does not prove the inbound message")
        if event.provider_thread_sha256 is None or any(
            candidate is None or not hmac.compare_digest(candidate, provider_thread)
            for candidate in (
                event.provider_thread_sha256,
                dispatch.provider_thread_sha256,
                thread.provider_thread_sha256,
            )
        ):
            if expected_channel == CommunicationChannel.EMAIL:
                raise ValueError("provider event does not prove the exact Gmail thread")
            raise ValueError("provider event does not prove the exact channel thread")
        if not hmac.compare_digest(event.provider_event_sha256, provider_event_id):
            raise ValueError(
                "provider event identity does not match its sealed commitment"
            )
        expected_parent = (
            dispatch.provider_message_sha256
            if expected_channel == CommunicationChannel.EMAIL
            else thread.parent_message_sha256
        )
        if expected_parent is None or not hmac.compare_digest(expected_parent, in_reply_to):
            if expected_channel == CommunicationChannel.EMAIL:
                raise ValueError(
                    "reply does not target the dispatched provider message"
                )
            raise ValueError("reply does not target the sealed channel root")
        if hmac.compare_digest(incoming_message, in_reply_to):
            raise ValueError(
                "inbound and outbound provider message identities must differ"
            )

        attempted_at = _timestamp(dispatch.attempted_at, label="attempted_at")
        if dispatch.accepted_at is None:
            raise ValueError("reply tracing requires an accepted dispatch")
        accepted_at = _timestamp(dispatch.accepted_at, label="accepted_at")
        thread_created_at = _timestamp(thread.created_at, label="thread.created_at")
        last_activity_at = _timestamp(
            thread.last_activity_at,
            label="thread.last_activity_at",
        )
        occurred_at = _timestamp(event.occurred_at, label="occurred_at")
        received_at = _timestamp(event.received_at, label="received_at")
        private_occurred_at = _timestamp(
            private.provider_occurred_at,
            label="provider_occurred_at",
        )
        if private_occurred_at != occurred_at:
            raise ValueError(
                "private provider occurrence time does not match sealed event"
            )
        if not (
            thread_created_at
            <= attempted_at
            <= accepted_at
            <= occurred_at
            <= received_at
        ):
            raise ValueError(
                "communication dispatch, reply, and receipt timing is inconsistent"
            )
        if last_activity_at > received_at:
            raise ValueError("sealed thread activity is later than the provider event")
        if occurred_at > now + self._clock_skew or received_at > now + self._clock_skew:
            raise ValueError("provider event is unacceptably future-dated")
        if now - received_at > self._max_event_age:
            raise ValueError("provider event is stale for replay admission")
        if received_at - occurred_at > self._max_receive_delay:
            raise ValueError("provider event receipt delay exceeds the trusted window")

    def _mint_inbound(
        self,
        *,
        scope: DynamicWorkflowScope,
        event: CommunicationProviderEvent,
        dispatch: CommunicationDispatchReceipt,
        thread: CommunicationThreadBinding,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private: CommunicationPrivateInbound,
    ) -> CommunicationInboundMessage:
        assert event.provider_message_sha256 is not None
        inbound_ref = _deterministic_ref(
            "inbound",
            {
                "event": event.provider_event_sha256,
                "message": event.provider_message_sha256,
                "thread": thread.thread_ref,
            },
        )
        return mint_communication_artifact(
            CommunicationInboundMessage,
            {
                "inbound_ref": inbound_ref,
                "thread_ref": thread.thread_ref,
                "provider_event_digest": event.artifact_digest,
                "sender_endpoint_ref": contact.endpoint_ref,
                "sender_endpoint_digest": contact.artifact_digest,
                "recipient_endpoint_digests": (outbound_sender.artifact_digest,),
                "private_content_ref": private.private_content_ref,
                "content_sha256": private.content_digest(),
                "provider_message_sha256": event.provider_message_sha256,
                "provider_thread_sha256": event.provider_thread_sha256,
                "in_reply_to_message_sha256": (
                    dispatch.provider_message_sha256
                    if dispatch.channel == CommunicationChannel.EMAIL
                    else thread.parent_message_sha256
                ),
                "authenticity": CommunicationAuthenticityGrade.VERIFIED,
                "identity_trust": contact.ownership_trust,
                "received_at": event.received_at,
            },
            scope=scope,
            scope_keyring=self._scope_keyring,
            scope_key_id=event.receipt_key_id,
        )

    def _mint_interpretation(
        self,
        *,
        scope: DynamicWorkflowScope,
        event: CommunicationProviderEvent,
        inbound: CommunicationInboundMessage,
        body: str,
        interpreted_at: str,
    ) -> CommunicationReplyInterpretation:
        rule = _classify_reply(body, event_type=event.event_type)
        provenance_digest = communication_canonical_digest(
            {
                "schema": _RULE_ENGINE_SCHEMA,
                "taxonomy_ref": _TAXONOMY_REF,
                "taxonomy_version": _TAXONOMY_VERSION,
                "intent_code": rule.intent_code,
                "deterministic": True,
            }
        )
        return mint_communication_artifact(
            CommunicationReplyInterpretation,
            {
                "interpretation_ref": _deterministic_ref(
                    "interpretation",
                    {
                        "inbound": inbound.artifact_digest,
                        "taxonomy": _TAXONOMY_REF,
                        "version": _TAXONOMY_VERSION,
                    },
                ),
                "inbound_message_digest": inbound.artifact_digest,
                "taxonomy_ref": _TAXONOMY_REF,
                "taxonomy_version": _TAXONOMY_VERSION,
                "intent_scores": (
                    CommunicationIntentScore(
                        intent_code=rule.intent_code,
                        confidence=rule.confidence,
                    ),
                ),
                "risk_codes": rule.risk_codes,
                "requires_human_review": True,
                "proposed_action_capabilities": (rule.proposed_capability,),
                "model_provenance_digest": provenance_digest,
                "interpreted_at": interpreted_at,
            },
            scope=scope,
            scope_keyring=self._scope_keyring,
            scope_key_id=inbound.receipt_key_id,
        )

    def _mint_touchpoints(
        self,
        *,
        scope: DynamicWorkflowScope,
        dispatch: CommunicationDispatchReceipt,
        event: CommunicationProviderEvent,
        inbound: CommunicationInboundMessage,
        interpretation: CommunicationReplyInterpretation,
        crm: CommunicationCrmTraceBinding,
    ) -> tuple[CrmTouchpointReceipt, CrmTouchpointReceipt, CrmTouchpointReceipt]:
        assert dispatch.accepted_at is not None
        definitions = (
            (
                CommunicationTouchpointType.OUTBOUND,
                dispatch.artifact_digest,
                (
                    dispatch.artifact_digest,
                    dispatch.connector_effect_receipt_digest,
                ),
                dispatch.accepted_at,
            ),
            (
                CommunicationTouchpointType.INBOUND,
                inbound.artifact_digest,
                (event.artifact_digest,),
                event.received_at,
            ),
            (
                CommunicationTouchpointType.REPLY,
                interpretation.artifact_digest,
                (inbound.artifact_digest, event.artifact_digest),
                interpretation.interpreted_at,
            ),
        )
        receipts: list[CrmTouchpointReceipt] = []
        for touchpoint_type, message_digest, evidence, recorded_at in definitions:
            identity = {
                "schema": "lightbulb.crm_touchpoint_runtime_identity.v1",
                "crm_contact_ref": crm.crm_contact_ref,
                "thread_ref": dispatch.thread_ref,
                "touchpoint_type": touchpoint_type,
                "message_artifact_digest": message_digest,
            }
            receipts.append(
                mint_communication_artifact(
                    CrmTouchpointReceipt,
                    {
                        "touchpoint_ref": _deterministic_ref(
                            "touchpoint",
                            identity,
                        ),
                        "touchpoint_type": touchpoint_type,
                        "channel": dispatch.channel,
                        "crm_contact_ref": crm.crm_contact_ref,
                        "crm_account_ref": crm.crm_account_ref,
                        "crm_deal_ref": crm.crm_deal_ref,
                        "crm_activity_ref": _deterministic_ref(
                            "crm-activity",
                            identity,
                        ),
                        "thread_ref": dispatch.thread_ref,
                        "message_artifact_digest": message_digest,
                        "source_evidence_digests": evidence,
                        "recorded_at": recorded_at,
                    },
                    scope=scope,
                    scope_keyring=self._scope_keyring,
                    scope_key_id=inbound.receipt_key_id,
                )
            )
        return (receipts[0], receipts[1], receipts[2])

    def _mint_observation(
        self,
        *,
        scope: DynamicWorkflowScope,
        dispatch: CommunicationDispatchReceipt,
        event: CommunicationProviderEvent,
        inbound: CommunicationInboundMessage,
        interpretation: CommunicationReplyInterpretation,
        reply_touchpoint: CrmTouchpointReceipt,
        crm: CommunicationCrmTraceBinding,
    ) -> CommunicationOutcomeObservation:
        intent_code = interpretation.intent_scores[0].intent_code
        facts = (
            CommunicationOutcomeFact(
                dimension=CommunicationOutcomeDimension.TRANSPORT,
                fact_code="provider_authenticity",
                value_code="verified",
                source_evidence_digest=event.artifact_digest,
            ),
            CommunicationOutcomeFact(
                dimension=CommunicationOutcomeDimension.CONVERSATION,
                fact_code="reply_received",
                boolean_value=True,
                source_evidence_digest=inbound.artifact_digest,
            ),
            CommunicationOutcomeFact(
                dimension=CommunicationOutcomeDimension.CONVERSATION,
                fact_code="reply_intent",
                value_code=intent_code,
                source_evidence_digest=interpretation.artifact_digest,
            ),
            CommunicationOutcomeFact(
                dimension=CommunicationOutcomeDimension.COMPLIANCE,
                fact_code="human_review_required",
                boolean_value=True,
                source_evidence_digest=interpretation.artifact_digest,
            ),
            CommunicationOutcomeFact(
                dimension=CommunicationOutcomeDimension.CRM,
                fact_code="touchpoints_recorded",
                numeric_value=3.0,
                source_evidence_digest=reply_touchpoint.artifact_digest,
            ),
        )
        return mint_communication_artifact(
            CommunicationOutcomeObservation,
            {
                "observation_ref": _deterministic_ref(
                    "observation",
                    {
                        "dispatch": dispatch.artifact_digest,
                        "inbound": inbound.artifact_digest,
                        "reply_touchpoint": reply_touchpoint.artifact_digest,
                    },
                ),
                "thread_ref": dispatch.thread_ref,
                "dispatch_receipt_digest": dispatch.artifact_digest,
                "inbound_message_digest": inbound.artifact_digest,
                "touchpoint_receipt_digest": reply_touchpoint.artifact_digest,
                "facts": facts,
                "associated_source_ref": crm.associated_source_ref,
                "associated_source_digest": crm.associated_source_digest,
                "growth_source": crm.growth_source,
                "observed_at": event.received_at,
                "causal_claim_ready": False,
            },
            scope=scope,
            scope_keyring=self._scope_keyring,
            scope_key_id=inbound.receipt_key_id,
        )

    @staticmethod
    def _dedupe_keys(
        *,
        event: CommunicationProviderEvent,
        dispatch: CommunicationDispatchReceipt,
        inbound: CommunicationInboundMessage,
    ) -> tuple[str, str]:
        event_key = communication_canonical_digest(
            {
                "schema": "lightbulb.communication_provider_event_dedupe.v1",
                "scope": event.exact_scope_digest,
                "connector_account_ref": event.connector_account_ref,
                "route_digest": event.route_digest,
                "provider_event_sha256": event.provider_event_sha256,
            }
        )
        message_key = communication_canonical_digest(
            {
                "schema": "lightbulb.communication_provider_message_dedupe.v1",
                "scope": event.exact_scope_digest,
                "connector_account_ref": event.connector_account_ref,
                "route_digest": event.route_digest,
                "thread_ref": dispatch.thread_ref,
                "provider_message_sha256": inbound.provider_message_sha256,
            }
        )
        return (event_key, message_key)


# Provider-specific names remain exact aliases so existing imports, replay
# repositories, and isinstance checks continue to work without conversions.
CommunicationPrivateGmailInbound = CommunicationPrivateInbound
CommunicationGmailTraceResult = CommunicationTraceResult
GmailCommunicationRuntime = CommunicationRuntime


__all__ = [
    "COMMUNICATION_CRM_TRACE_BINDING_SCHEMA",
    "COMMUNICATION_CRM_TRACE_BINDING_V1_SCHEMA",
    "COMMUNICATION_GMAIL_TRACE_RESULT_SCHEMA",
    "COMMUNICATION_PRIVATE_GMAIL_INBOUND_SCHEMA",
    "COMMUNICATION_TRACE_RESULT_SCHEMA",
    "CommunicationCrmTraceBinding",
    "CommunicationGmailTraceResult",
    "CommunicationPrivateGmailInbound",
    "CommunicationReplayCapacityExceeded",
    "CommunicationReplayClaim",
    "CommunicationReplayConflict",
    "CommunicationReplayError",
    "CommunicationReplayInProgress",
    "CommunicationReplayRepository",
    "CommunicationRuntime",
    "CommunicationTraceResult",
    "CrmTouchpointSink",
    "GmailCommunicationRuntime",
    "InMemoryCommunicationReplayRepository",
    "InMemoryCrmTouchpointSink",
]
