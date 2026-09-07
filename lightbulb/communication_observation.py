"""Bounded Gmail reply observation for the governed communication rail.

One call performs one fresh ``gmail.get_thread`` read.  The read route is
independent from the sealed communication/write route, but both must resolve
to the same project, connector account, and TenantConnector.  Provider
content and addresses stay transient; only sealed artifacts, opaque
references, counts, and commitments leave this module.

This is deliberately not a scheduler.  Hosts decide when to invoke
:meth:`GmailCommunicationObserver.poll_once` and how often to poll.
"""

from __future__ import annotations

import hmac
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parsedate_to_datetime
from enum import Enum
from typing import Any, Literal, Mapping, Protocol
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from lightbulb.communication_contracts import (
    CommunicationAuthenticityGrade,
    CommunicationChannel,
    CommunicationDispatchReceipt,
    CommunicationEndpointBinding,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationProviderEvent,
    CommunicationProviderEventType,
    CommunicationScopeKeyRing,
    CommunicationThreadBinding,
    communication_canonical_digest,
    communication_canonical_json,
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
from lightbulb.communication_runtime import (
    CommunicationCrmTraceBinding,
    CommunicationPrivateInbound,
    CommunicationRuntime,
    CommunicationTraceResult,
)
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionProvenance,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_GMAIL_READ_ROUTE_SCHEMA = (
    "lightbulb.communication_gmail_read_route.v1"
)
COMMUNICATION_PRIVATE_GMAIL_DISPATCH_SCHEMA = (
    "lightbulb.communication_private_gmail_dispatch.v1"
)
COMMUNICATION_GMAIL_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.communication_gmail_observation_result.v1"
)
_GMAIL_THREAD_SCHEMA = "lightbulb.gmail_thread.v1"
_GMAIL_GET_THREAD_TOOL = "gmail.get_thread"
_READ_EVIDENCE_DOMAIN = "lightbulb.communication_gmail_read_evidence.v1"
_PROVIDER_EVENT_DOMAIN = "lightbulb.communication_gmail_observed_event.v1"
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")
_PROVIDER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
_RFC_MESSAGE_ID_RE = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")


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


def _visible_ref(value: str, *, label: str, maximum: int = 512) -> str:
    clean = value.strip()
    if (
        clean != value
        or not clean
        or len(clean) > maximum
        or _VISIBLE_REF_RE.fullmatch(clean) is None
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


class CommunicationGmailReadRoute(_StrictModel):
    """Exact Spring-owned route for the ephemeral Gmail thread read."""

    schema_id: Literal[
        "lightbulb.communication_gmail_read_route.v1"
    ] = Field(default=COMMUNICATION_GMAIL_READ_ROUTE_SCHEMA, alias="schema")
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: Literal["gmail.get_thread"] = _GMAIL_GET_THREAD_TOOL
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible_ref(value, label=info.field_name, maximum=200)


class CommunicationPrivateGmailDispatch(_StrictModel):
    """Transient raw identifiers retained by the host after Gmail dispatch."""

    schema_id: Literal[
        "lightbulb.communication_private_gmail_dispatch.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_GMAIL_DISPATCH_SCHEMA, alias="schema")
    provider_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_thread_id: str = Field(min_length=1, max_length=512, repr=False)

    @field_validator("provider_message_id", "provider_thread_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be one exact Gmail identifier")
        return value

class GmailThreadHeaders(_StrictModel):
    subject: str | None = Field(default=None, max_length=998)
    from_address: str | None = Field(default=None, alias="from", max_length=998)
    to_address: str | None = Field(default=None, alias="to", max_length=998)
    date: str | None = Field(default=None, max_length=128)
    message_id: str | None = Field(default=None, alias="messageId", max_length=998)
    in_reply_to: str | None = Field(default=None, alias="inReplyTo", max_length=998)
    references: str | None = Field(default=None, max_length=4_096)

    @field_validator(
        "subject",
        "from_address",
        "to_address",
        "date",
        "message_id",
        "in_reply_to",
        "references",
    )
    @classmethod
    def _header_controls(cls, value: str | None, info: Any) -> str | None:
        if value is not None and ("\r" in value or "\n" in value):
            raise ValueError(f"{info.field_name} contains header controls")
        return value


class GmailThreadMessage(_StrictModel):
    message_id: str = Field(alias="id", min_length=1, max_length=512)
    internal_date: str | None = Field(
        default=None,
        alias="internalDate",
        pattern=r"^[0-9]{1,20}$",
    )
    snippet: str | None = Field(default=None, max_length=500)
    body: str | None = Field(default=None, max_length=2_000)
    body_truncated: bool = Field(alias="bodyTruncated")
    headers: GmailThreadHeaders

    @field_validator("message_id")
    @classmethod
    def _message_id(cls, value: str) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError("Gmail message id is invalid")
        return value


class GmailThreadOutput(_StrictModel):
    schema_id: Literal["lightbulb.gmail_thread.v1"] = Field(
        default=_GMAIL_THREAD_SCHEMA,
        alias="schema",
    )
    thread_id: str = Field(alias="threadId", min_length=1, max_length=512)
    message_count: int = Field(alias="messageCount", ge=0)
    returned_message_count: int = Field(
        alias="returnedMessageCount",
        ge=0,
        le=10,
    )
    truncated: bool
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]
    messages: tuple[GmailThreadMessage, ...] = Field(max_length=10)

    @field_validator("thread_id")
    @classmethod
    def _thread_id(cls, value: str) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError("Gmail thread id is invalid")
        return value

    @field_validator("messages", mode="before")
    @classmethod
    def _messages_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _count_integrity(self) -> "GmailThreadOutput":
        if self.returned_message_count != len(self.messages):
            raise ValueError("returned Gmail message count does not match messages")
        if self.message_count < self.returned_message_count:
            raise ValueError("Gmail total message count is smaller than returned count")
        if self.truncated != (self.message_count > self.returned_message_count):
            raise ValueError("Gmail truncation flag does not match message counts")
        ids = [message.message_id for message in self.messages]
        if len(ids) != len(set(ids)):
            raise ValueError("Gmail thread contains duplicate message identifiers")
        return self


class CommunicationGmailObservationStatus(str, Enum):
    NO_REPLY = "no_reply"
    PROCESSED = "processed"


class CommunicationGmailObservationResult(_StrictModel):
    """Privacy-minimised result of one host-invoked bounded poll."""

    schema_id: Literal[
        "lightbulb.communication_gmail_observation_result.v1"
    ] = Field(default=COMMUNICATION_GMAIL_OBSERVATION_RESULT_SCHEMA, alias="schema")
    status: CommunicationGmailObservationStatus
    read_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_provenance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_completed_at: str
    provider_message_count: int = Field(ge=0)
    returned_message_count: int = Field(ge=0, le=10)
    provider_event: CommunicationProviderEvent | None = None
    trace: CommunicationTraceResult | None = None

    @field_validator("read_completed_at")
    @classmethod
    def _completed_at(cls, value: str) -> str:
        return _utc_text(_timestamp(value, label="read_completed_at"))

    @model_validator(mode="after")
    def _status_shape(self) -> "CommunicationGmailObservationResult":
        if self.status == CommunicationGmailObservationStatus.NO_REPLY:
            if self.provider_event is not None or self.trace is not None:
                raise ValueError("no-reply observation cannot carry reply artifacts")
        elif self.provider_event is None or self.trace is None:
            raise ValueError("processed observation requires event and trace artifacts")
        elif (
            self.trace.inbound_message.provider_event_digest
            != self.provider_event.artifact_digest
        ):
            raise ValueError("trace does not bind the observed provider event")
        return self


class CommunicationObservedEventRepository(Protocol):
    """Safe first-evidence custody for restart-stable observed messages.

    A fresh Gmail read has fresh journal provenance.  The first verified read
    therefore wins custody of the stable provider-message identity; later
    polls reuse that sealed event while the communication runtime performs its
    normal exactly-once replay.  Implementations persist no provider content.
    """

    def get(self, identity_digest: str) -> CommunicationProviderEvent | None: ...

    def put(
        self,
        identity_digest: str,
        event: CommunicationProviderEvent,
    ) -> CommunicationProviderEvent: ...


class InMemoryCommunicationObservedEventRepository:
    """Thread-safe adapter retaining only sealed provider-event artifacts."""

    def __init__(self) -> None:
        self._events: dict[str, CommunicationProviderEvent] = {}
        self._lock = threading.RLock()

    def get(self, identity_digest: str) -> CommunicationProviderEvent | None:
        if re.fullmatch(r"[0-9a-f]{64}", identity_digest) is None:
            raise ValueError("observed event identity must be a SHA-256 digest")
        with self._lock:
            return self._events.get(identity_digest)

    def put(
        self,
        identity_digest: str,
        event: CommunicationProviderEvent,
    ) -> CommunicationProviderEvent:
        if re.fullmatch(r"[0-9a-f]{64}", identity_digest) is None:
            raise ValueError("observed event identity must be a SHA-256 digest")
        trusted = CommunicationProviderEvent.model_validate(
            event.model_dump(mode="python", by_alias=True)
        )
        with self._lock:
            existing = self._events.get(identity_digest)
            if existing is not None:
                stable_existing = (
                    existing.dispatch_receipt_digest,
                    existing.provider_message_sha256,
                    existing.provider_thread_sha256,
                    existing.connector_account_ref,
                    existing.route_digest,
                )
                stable_candidate = (
                    trusted.dispatch_receipt_digest,
                    trusted.provider_message_sha256,
                    trusted.provider_thread_sha256,
                    trusted.connector_account_ref,
                    trusted.route_digest,
                )
                if stable_existing != stable_candidate:
                    raise ValueError(
                        "observed communication identity is bound to different evidence"
                    )
                return existing
            self._events[identity_digest] = trusted
            return trusted


def _message_time(message: GmailThreadMessage) -> datetime:
    if message.internal_date is not None:
        try:
            milliseconds = int(message.internal_date)
            return datetime.fromtimestamp(milliseconds / 1_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Gmail internalDate is outside the supported range") from exc
    if message.headers.date is None:
        raise ValueError("Gmail message lacks an authenticated occurrence timestamp")
    try:
        parsed = parsedate_to_datetime(message.headers.date)
    except (TypeError, ValueError) as exc:
        raise ValueError("Gmail Date header is invalid") from exc
    return _utc(parsed, label="Gmail Date header")


def _addresses(value: str | None, *, label: str) -> tuple[str, ...]:
    if value is None:
        raise ValueError(f"Gmail {label} header is required")
    parsed = tuple(address.strip() for _, address in getaddresses([value]) if address)
    if not parsed:
        raise ValueError(f"Gmail {label} header contains no email address")
    return parsed


def _matching_address(
    addresses: tuple[str, ...],
    *,
    endpoint: CommunicationEndpointBinding,
    scope_keyring: CommunicationScopeKeyRing,
) -> str | None:
    matches = tuple(
        address
        for address in addresses
        if hmac.compare_digest(
            endpoint.address_sha256,
            communication_endpoint_address_commitment(
                endpoint_ref=endpoint.endpoint_ref,
                address=address,
                key_id=endpoint.receipt_key_id,
                scope_keyring=scope_keyring,
            ),
        )
    )
    if len(matches) > 1:
        raise ValueError("Gmail header repeats the exact sealed endpoint")
    return matches[0] if matches else None


def _header_message_ids(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    bracketed = tuple(item.strip() for item in re.findall(r"<[^<>\r\n]+>", value))
    if bracketed:
        return bracketed
    clean = value.strip()
    return (clean,) if clean else ()


@dataclass(frozen=True, slots=True)
class CommunicationObservedReply:
    """Transient provider-normalized reply selected by an SDK adapter."""

    provider_message_id: str
    occurred_at: datetime
    sender_address: str
    recipient_address: str
    subject: str
    body: str
    raw_payload: str


@dataclass(frozen=True, slots=True)
class CommunicationEmailObservationInspection:
    """Provider proof reduced to the facts consumed by shared custody logic."""

    output: BaseModel
    provider_conversation_id: str
    provider_message_count: int
    returned_message_count: int
    reply: CommunicationObservedReply | None
    outbound_observed: bool = True


class CommunicationEmailObservationAdapter(Protocol):
    """Closed provider proof seam used by the shared observation rail.

    Callers select a provider name; they cannot inject an implementation.
    Implementations parse the exact read/write/private provider models and own
    only provider-output/threading proof. Scope, provenance, replay, artifacts,
    and CRM effects remain in :class:`CommunicationEmailObserver`.
    """

    provider_name: str
    channel: CommunicationChannel
    read_tool: str
    read_evidence_domain: str
    provider_event_domain: str
    payload_ref_prefix: str
    content_ref_prefix: str
    event_ref_prefix: str

    def parse_read_route(self, value: Any) -> Any: ...

    def parse_communication_route(self, value: Any) -> Any: ...

    def parse_private_dispatch(self, value: Any) -> Any: ...

    def parse_authority_binding(
        self,
        value: Any,
        *,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> Any: ...

    def read_arguments(self, private_dispatch: Any, max_messages: int) -> dict[str, Any]: ...

    def provider_message_id(self, private_dispatch: Any) -> str: ...

    def provider_conversation_id(self, private_dispatch: Any) -> str: ...

    def runtime_parent_message_id(self, private_dispatch: Any) -> str: ...

    def provider_message_commitment(
        self,
        value: str,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def provider_conversation_commitment(
        self,
        private_dispatch: Any,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def provider_event_commitment(
        self,
        value: str,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def payload_commitment(
        self,
        value: str,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def content_commitment(
        self,
        *,
        subject: str,
        body: str,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def validate_authority_binding(self, **values: Any) -> None: ...

    def inspect_output(
        self,
        output: Mapping[str, Any],
        *,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: Any,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
    ) -> CommunicationEmailObservationInspection: ...

    def private_inbound(self, **values: Any) -> CommunicationPrivateInbound: ...

    def observation_result(
        self,
        *,
        processed: bool,
        outbound_observed: bool,
        **values: Any,
    ) -> BaseModel: ...


class _GmailObservationAdapter:
    __slots__ = ()

    provider_name = "gmail"
    channel = CommunicationChannel.EMAIL
    read_tool = _GMAIL_GET_THREAD_TOOL
    read_evidence_domain = _READ_EVIDENCE_DOMAIN
    provider_event_domain = _PROVIDER_EVENT_DOMAIN
    payload_ref_prefix = "gmail-payload:"
    content_ref_prefix = "gmail-content:"
    event_ref_prefix = "gmail-observation:"

    def parse_read_route(self, value: Any) -> CommunicationGmailReadRoute:
        return CommunicationGmailReadRoute.model_validate(value)

    def parse_communication_route(self, value: Any) -> CommunicationGmailRoute:
        return CommunicationGmailRoute.model_validate(value)

    def parse_private_dispatch(self, value: Any) -> CommunicationPrivateGmailDispatch:
        return CommunicationPrivateGmailDispatch.model_validate(value)

    def parse_authority_binding(self, value: Any, **_: Any) -> None:
        if value is not None:
            raise ValueError("email observation does not accept a channel binding")
        return None

    def read_arguments(
        self,
        private_dispatch: CommunicationPrivateGmailDispatch,
        max_messages: int,
    ) -> dict[str, Any]:
        return {
            "thread_id": private_dispatch.provider_thread_id,
            "max_messages": max_messages,
        }

    def provider_message_id(
        self,
        private_dispatch: CommunicationPrivateGmailDispatch,
    ) -> str:
        return private_dispatch.provider_message_id

    def provider_conversation_id(
        self,
        private_dispatch: CommunicationPrivateGmailDispatch,
    ) -> str:
        return private_dispatch.provider_thread_id

    def runtime_parent_message_id(
        self,
        private_dispatch: CommunicationPrivateGmailDispatch,
    ) -> str:
        return private_dispatch.provider_message_id

    def provider_message_commitment(self, value: str, **_: Any) -> str:
        return communication_private_value_digest(value)

    def provider_conversation_commitment(
        self,
        private_dispatch: CommunicationPrivateGmailDispatch,
        **_: Any,
    ) -> str:
        return communication_private_value_digest(private_dispatch.provider_thread_id)

    def provider_event_commitment(self, value: str, **_: Any) -> str:
        return communication_private_value_digest(value)

    def payload_commitment(self, value: str, **_: Any) -> str:
        return communication_private_value_digest(value)

    def content_commitment(self, *, subject: str, body: str, **_: Any) -> str:
        return communication_canonical_digest(
            {
                "schema": "lightbulb.communication_private_content.v1",
                "subject": subject,
                "body": body,
            }
        )

    def validate_authority_binding(self, **values: Any) -> None:
        if values.get("authority_binding") is not None:
            raise ValueError("email observation does not accept a channel binding")

    def inspect_output(
        self,
        output: Mapping[str, Any],
        *,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateGmailDispatch,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: Any = None,
        scope: DynamicWorkflowScope | None = None,
    ) -> CommunicationEmailObservationInspection:
        parsed = GmailThreadOutput.model_validate(output)
        if not hmac.compare_digest(
            parsed.thread_id,
            private_dispatch.provider_thread_id,
        ):
            raise ValueError("Gmail response does not match the exact requested thread")
        if parsed.truncated:
            raise ValueError(
                "truncated Gmail thread cannot prove an unambiguous reply set"
            )
        outbound_rfc_message_id = self._derive_outbound_rfc_message_id(
            output=parsed,
            outbound_sender=outbound_sender,
            contact=contact,
            private_dispatch=private_dispatch,
            scope_keyring=scope_keyring,
        )
        candidate = self._select_reply(
            output=parsed,
            dispatch=dispatch,
            outbound_sender=outbound_sender,
            contact=contact,
            private_dispatch=private_dispatch,
            outbound_rfc_message_id=outbound_rfc_message_id,
            scope_keyring=scope_keyring,
        )
        reply = None
        if candidate is not None:
            message, occurred_at, sender_address, recipient_address = candidate
            if message.body_truncated:
                raise ValueError(
                    "Gmail reply body is truncated and cannot be classified safely"
                )
            body = message.body or ""
            if not body.strip():
                raise ValueError("Gmail reply lacks a complete plain-text body")
            reply = CommunicationObservedReply(
                provider_message_id=message.message_id,
                occurred_at=occurred_at,
                sender_address=sender_address,
                recipient_address=recipient_address,
                subject=message.headers.subject or "",
                body=body,
                raw_payload=communication_canonical_json(
                    message.model_dump(mode="json", by_alias=True)
                ).decode("utf-8"),
            )
        return CommunicationEmailObservationInspection(
            output=parsed,
            provider_conversation_id=parsed.thread_id,
            provider_message_count=parsed.message_count,
            returned_message_count=parsed.returned_message_count,
            reply=reply,
        )

    def private_inbound(self, **values: Any) -> CommunicationPrivateInbound:
        for name in (
            "platform",
            "provider_event_hmac",
            "provider_message_hmac_digest",
            "parent_message_hmac_digest",
            "payload_hmac",
            "content_hmac",
        ):
            values.pop(name, None)
        return CommunicationPrivateInbound(**values)

    def observation_result(
        self,
        *,
        processed: bool,
        outbound_observed: bool,
        **values: Any,
    ) -> BaseModel:
        if not outbound_observed:
            raise ValueError("Gmail observation lacks its exact outbound message")
        return CommunicationGmailObservationResult(
            status=(
                CommunicationGmailObservationStatus.PROCESSED
                if processed
                else CommunicationGmailObservationStatus.NO_REPLY
            ),
            **values,
        )

    @staticmethod
    def _select_reply(
        *,
        output: GmailThreadOutput,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateGmailDispatch,
        outbound_rfc_message_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> tuple[GmailThreadMessage, datetime, str, str] | None:
        if dispatch.accepted_at is None:
            raise ValueError("Gmail observation requires an accepted dispatch")
        accepted_at = _timestamp(dispatch.accepted_at, label="dispatch.accepted_at")
        exact_replies: list[tuple[GmailThreadMessage, datetime, str, str]] = []
        for message in output.messages:
            occurred_at = _message_time(message)
            if occurred_at <= accepted_at or message.message_id == (
                private_dispatch.provider_message_id
            ):
                continue
            senders = _addresses(message.headers.from_address, label="From")
            recipients = _addresses(message.headers.to_address, label="To")
            if len(senders) != 1:
                raise ValueError("Gmail reply must have one exact sender address")
            if len(recipients) != 1:
                raise ValueError("Gmail reply must have one exact recipient address")
            contact_address = _matching_address(
                senders,
                endpoint=contact,
                scope_keyring=scope_keyring,
            )
            outbound_address = _matching_address(
                senders,
                endpoint=outbound_sender,
                scope_keyring=scope_keyring,
            )
            if outbound_address is not None:
                continue
            if contact_address is None:
                raise ValueError("post-dispatch Gmail sender is not the sealed contact")
            recipient_address = _matching_address(
                recipients,
                endpoint=outbound_sender,
                scope_keyring=scope_keyring,
            )
            if recipient_address is None:
                raise ValueError(
                    "Gmail reply recipient is not the sealed sender endpoint"
                )
            candidate = (message, occurred_at, contact_address, recipient_address)
            reply_ids = set(_header_message_ids(message.headers.in_reply_to))
            reply_ids.update(_header_message_ids(message.headers.references))
            if outbound_rfc_message_id in reply_ids:
                exact_replies.append(candidate)
        if len(exact_replies) == 1:
            return exact_replies[0]
        if len(exact_replies) > 1:
            raise ValueError("multiple Gmail replies target the dispatched message")
        return None

    @staticmethod
    def _derive_outbound_rfc_message_id(
        *,
        output: GmailThreadOutput,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateGmailDispatch,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        outbound = tuple(
            message
            for message in output.messages
            if message.message_id == private_dispatch.provider_message_id
        )
        if len(outbound) != 1:
            raise ValueError("Gmail thread lacks the exact dispatched provider message")
        message = outbound[0]
        message_ids = _header_message_ids(message.headers.message_id)
        if len(message_ids) != 1 or _RFC_MESSAGE_ID_RE.fullmatch(message_ids[0]) is None:
            raise ValueError(
                "dispatched Gmail message lacks one exact RFC Message-ID header"
            )
        senders = _addresses(message.headers.from_address, label="From")
        recipients = _addresses(message.headers.to_address, label="To")
        if len(senders) != 1 or len(recipients) != 1:
            raise ValueError("dispatched Gmail message lacks one exact address pair")
        if (
            _matching_address(
                senders,
                endpoint=outbound_sender,
                scope_keyring=scope_keyring,
            )
            is None
            or _matching_address(
                recipients,
                endpoint=contact,
                scope_keyring=scope_keyring,
            )
            is None
        ):
            raise ValueError(
                "dispatched Gmail message does not match the sealed endpoint pair"
            )
        return message_ids[0]


_GMAIL_OBSERVATION_ADAPTER = _GmailObservationAdapter()


def _closed_observation_adapter(provider: str) -> CommunicationEmailObservationAdapter:
    if provider == "gmail":
        return _GMAIL_OBSERVATION_ADAPTER
    if provider == "outlook":
        from lightbulb.communication_outlook_observation import (
            _OUTLOOK_OBSERVATION_ADAPTER,
        )

        return _OUTLOOK_OBSERVATION_ADAPTER
    if provider in {"slack", "teams"}:
        from lightbulb.communication_channel_observation import (
            _SLACK_CHANNEL_OBSERVATION_ADAPTER,
            _TEAMS_CHANNEL_OBSERVATION_ADAPTER,
        )

        return (
            _SLACK_CHANNEL_OBSERVATION_ADAPTER
            if provider == "slack"
            else _TEAMS_CHANNEL_OBSERVATION_ADAPTER
        )
    raise ValueError("communication observation provider is not SDK-owned")


class CommunicationEmailObserver:
    """Perform one fresh governed email read and process one exact reply."""

    def __init__(
        self,
        *,
        scope_keyring: CommunicationScopeKeyRing,
        connector_executor: ConnectorExecutor,
        runtime: CommunicationRuntime,
        event_repository: CommunicationObservedEventRepository | None = None,
        clock_skew_seconds: int = 300,
        max_read_age_seconds: int = 300,
        _provider: Literal["gmail", "outlook", "slack", "teams"] = "gmail",
    ) -> None:
        if isinstance(clock_skew_seconds, bool) or not 0 <= clock_skew_seconds <= 900:
            raise ValueError("clock_skew_seconds must be between zero and 900")
        if (
            isinstance(max_read_age_seconds, bool)
            or not 1 <= max_read_age_seconds <= 3_600
        ):
            raise ValueError("max_read_age_seconds must be between one and 3600")
        self._scope_keyring = scope_keyring
        self._connector_executor = connector_executor
        self._runtime = runtime
        self._adapter = _closed_observation_adapter(_provider)
        self._event_repository = (
            event_repository
            if event_repository is not None
            else InMemoryCommunicationObservedEventRepository()
        )
        self._clock_skew_seconds = clock_skew_seconds
        self._max_read_age_seconds = max_read_age_seconds

    def poll_once(
        self,
        *,
        scope: DynamicWorkflowScope | Mapping[str, Any],
        read_route: Any,
        communication_route: Any,
        materialization: CommunicationMaterializationResult | Mapping[str, Any],
        thread: CommunicationThreadBinding | Mapping[str, Any],
        outbound_sender_endpoint: CommunicationEndpointBinding
        | Mapping[str, Any],
        contact_party: CommunicationPartyRef | Mapping[str, Any],
        contact_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
        private_dispatch: Any,
        crm: CommunicationCrmTraceBinding | Mapping[str, Any],
        channel_binding: Any = None,
        now: datetime,
        max_messages: int = 10,
    ) -> BaseModel:
        """Poll one exact provider conversation once; never schedule itself."""

        current = _utc(now, label="now")
        if isinstance(max_messages, bool) or not 1 <= max_messages <= 10:
            raise ValueError("max_messages must be an integer from one through ten")
        workflow_scope = _workflow_scope(scope)
        read = self._adapter.parse_read_route(read_route)
        write = self._adapter.parse_communication_route(communication_route)
        materialized = CommunicationMaterializationResult.model_validate(materialization)
        private = self._adapter.parse_private_dispatch(private_dispatch)
        authority_binding = self._adapter.parse_authority_binding(
            channel_binding,
            scope=workflow_scope,
            scope_keyring=self._scope_keyring,
        )
        (
            trusted_thread,
            trusted_sender,
            trusted_contact_party,
            trusted_contact,
            trusted_crm,
            dispatch,
        ) = (
            self._verify_pre_read_authority(
                scope=workflow_scope,
                read_route=read,
                communication_route=write,
                materialization=materialized,
                thread=thread,
                outbound_sender_endpoint=outbound_sender_endpoint,
                contact_party=contact_party,
                contact_endpoint=contact_endpoint,
                private_dispatch=private,
                crm=crm,
                authority_binding=authority_binding,
            )
        )

        request = ConnectorExecutionRequest(
            tool=read.tool,
            arguments=self._adapter.read_arguments(private, max_messages),
            scope=ExecutionScope(
                tenant_ref=workflow_scope.tenant_id,
                company_ref=workflow_scope.company_id,
                project_ref=workflow_scope.project_ref,
                project_id=read.project_id,
                actor_ref=workflow_scope.user_id,
            ),
            connector_account_ref=read.connector_account_ref,
            effect=ConnectorEffect.READ,
            approval_required=False,
            preview_only=False,
            idempotency_key=None,
            metadata={},
        )
        if not self._connector_executor.supports(read.tool):
            raise ValueError(
                f"connector executor does not support {self._adapter.read_tool}"
            )
        try:
            raw_result = self._connector_executor.execute(request)
        except Exception:
            raise ValueError("communication provider read failed") from None
        try:
            connector_result = ConnectorExecutionResult.model_validate(raw_result)
        except ValidationError:
            raise ValueError("communication provider read result is invalid") from None
        provenance = self._verify_read_provenance(
            request=request,
            read_route=read,
            result=connector_result,
            dispatch=dispatch,
            now=current,
        )
        inspection = self._adapter.inspect_output(
            connector_result.output,
            dispatch=dispatch,
            outbound_sender=trusted_sender,
            contact=trusted_contact,
            private_dispatch=private,
            scope_keyring=self._scope_keyring,
            authority_binding=authority_binding,
            scope=workflow_scope,
        )
        if (
            not inspection.outbound_observed
            and materialized.status == CommunicationMaterializationStatus.COMPLETED
        ):
            raise ValueError(
                "completed communication lost its freshly observed outbound message"
            )

        provenance_digest = communication_canonical_digest(
            provenance.model_dump(mode="json", by_alias=True)
        )
        common = {
            "read_request_digest": request.custody_fingerprint(),
            "read_provenance_digest": provenance_digest,
            "read_receipt_digest": provenance.receipt_digest,
            "read_completed_at": provenance.completed_at,
            "provider_message_count": inspection.provider_message_count,
            "returned_message_count": inspection.returned_message_count,
        }
        if inspection.reply is None:
            return self._adapter.observation_result(
                processed=False,
                outbound_observed=inspection.outbound_observed,
                **common,
            )

        reply = inspection.reply
        provider_message_commitment = self._adapter.provider_message_commitment(
            reply.provider_message_id,
            authority_binding=authority_binding,
            scope=workflow_scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        provider_thread_commitment = self._adapter.provider_conversation_commitment(
            private,
            authority_binding=authority_binding,
            scope=workflow_scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        event_identity = communication_canonical_digest(
            {
                "schema": self._adapter.provider_event_domain,
                "exact_scope_digest": dispatch.exact_scope_digest,
                "dispatch_receipt_digest": dispatch.artifact_digest,
                "provider_message_sha256": provider_message_commitment,
                "provider_thread_sha256": provider_thread_commitment,
            }
        )
        event_private_id = (
            "observed-"
            + event_identity[:48]
        )
        private_payload_ref = (
            self._adapter.payload_ref_prefix
            + communication_private_value_digest(event_private_id)[:48]
        )
        private_content_ref = (
            self._adapter.content_ref_prefix
            + provider_message_commitment[:48]
        )
        read_evidence = self._scope_keyring.sign(
            dispatch.receipt_key_id,
            self._adapter.read_evidence_domain,
            {
                "request": request.model_dump(mode="json", by_alias=True),
                "provenance": provenance.model_dump(mode="json", by_alias=True),
                "output": inspection.output.model_dump(mode="json", by_alias=True),
                "selected_message_id": reply.provider_message_id,
            },
        ).hex()
        provider_event = self._event_repository.get(event_identity)
        provider_event_commitment = self._adapter.provider_event_commitment(
            event_private_id,
            authority_binding=authority_binding,
            scope=workflow_scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        payload_commitment = self._adapter.payload_commitment(
            reply.raw_payload,
            authority_binding=authority_binding,
            scope=workflow_scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        content_commitment = self._adapter.content_commitment(
            subject=reply.subject,
            body=reply.body,
            authority_binding=authority_binding,
            scope=workflow_scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        if provider_event is None:
            provider_event = mint_communication_artifact(
                CommunicationProviderEvent,
                {
                    "event_ref": (
                        self._adapter.event_ref_prefix
                        + communication_private_value_digest(event_private_id)[:48]
                    ),
                    "event_type": CommunicationProviderEventType.REPLIED,
                    "dispatch_receipt_digest": dispatch.artifact_digest,
                    # The runtime intentionally requires the sealed communication/write
                    # route. Read-route custody is bound by authenticity evidence.
                    "connector_account_ref": write.connector_account_ref,
                    "route_digest": write.route_digest,
                    "provider_event_sha256": provider_event_commitment,
                    "provider_message_sha256": provider_message_commitment,
                    "provider_thread_sha256": provider_thread_commitment,
                    "authenticity": CommunicationAuthenticityGrade.VERIFIED,
                    "authenticity_evidence_digest": read_evidence,
                    "private_payload_ref": private_payload_ref,
                    "payload_sha256": payload_commitment,
                    "occurred_at": _utc_text(reply.occurred_at),
                    "received_at": provenance.completed_at,
                },
                scope=workflow_scope,
                scope_keyring=self._scope_keyring,
                scope_key_id=dispatch.receipt_key_id,
            )
            provider_event = self._event_repository.put(
                event_identity,
                provider_event,
            )
        private_inbound = self._adapter.private_inbound(
            private_payload_ref=private_payload_ref,
            private_content_ref=private_content_ref,
            provider_event_id=event_private_id,
            provider_message_id=reply.provider_message_id,
            provider_thread_id=inspection.provider_conversation_id,
            in_reply_to_message_id=self._adapter.runtime_parent_message_id(private),
            sender_endpoint_ref=trusted_contact.endpoint_ref,
            sender_address=reply.sender_address,
            recipient_endpoint_ref=trusted_sender.endpoint_ref,
            recipient_address=reply.recipient_address,
            subject=reply.subject,
            body=reply.body,
            raw_payload=reply.raw_payload,
            provider_occurred_at=_utc_text(reply.occurred_at),
            platform=self._adapter.channel,
            provider_event_hmac=provider_event_commitment,
            provider_message_hmac_digest=provider_message_commitment,
            parent_message_hmac_digest=(
                trusted_thread.parent_message_sha256
                if self._adapter.channel != CommunicationChannel.EMAIL
                else dispatch.provider_message_sha256
            ),
            payload_hmac=payload_commitment,
            content_hmac=content_commitment,
        )
        trace = self._runtime.process_reply(
            scope=workflow_scope,
            route=write,
            materialization=materialized,
            thread=trusted_thread,
            outbound_sender_endpoint=trusted_sender,
            contact_party=trusted_contact_party,
            contact_endpoint=trusted_contact,
            provider_event=provider_event,
            private_inbound=private_inbound,
            crm=trusted_crm,
            now=current,
        )
        return self._adapter.observation_result(
            processed=True,
            outbound_observed=inspection.outbound_observed,
            provider_event=provider_event,
            trace=trace,
            **common,
        )

    def _verify_pre_read_authority(
        self,
        *,
        scope: DynamicWorkflowScope,
        read_route: Any,
        communication_route: Any,
        materialization: CommunicationMaterializationResult,
        thread: CommunicationThreadBinding | Mapping[str, Any],
        outbound_sender_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
        contact_party: CommunicationPartyRef | Mapping[str, Any],
        contact_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
        private_dispatch: Any,
        crm: CommunicationCrmTraceBinding | Mapping[str, Any],
        authority_binding: Any,
    ) -> tuple[
        CommunicationThreadBinding,
        CommunicationEndpointBinding,
        CommunicationPartyRef,
        CommunicationEndpointBinding,
        CommunicationCrmTraceBinding,
        CommunicationDispatchReceipt,
    ]:
        if scope.project_ref != read_route.project_ref or (
            scope.project_ref != communication_route.project_ref
        ):
            raise ValueError("communication routes do not match authenticated project scope")
        if (
            read_route.project_id != communication_route.project_id
            or read_route.connector_account_ref
            != communication_route.connector_account_ref
            or read_route.tenant_connector_id
            != communication_route.tenant_connector_id
        ):
            raise ValueError(
                "communication read/write routes must share project, account, and TenantConnector"
            )
        accepted_state = (
            materialization.status == CommunicationMaterializationStatus.ACCEPTED
            and materialization.effect_state
            == CommunicationExternalEffectState.ACCEPTED
        )
        completed_state = (
            materialization.status == CommunicationMaterializationStatus.COMPLETED
            and materialization.effect_state
            == CommunicationExternalEffectState.COMPLETED
        )
        if (not accepted_state and not completed_state) or materialization.receipt is None:
            raise ValueError("communication observation requires an accepted dispatch")
        dispatch = verify_communication_artifact(
            materialization.receipt,
            artifact_type=CommunicationDispatchReceipt,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_thread = verify_communication_artifact(
            thread,
            artifact_type=CommunicationThreadBinding,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_sender = verify_communication_artifact(
            outbound_sender_endpoint,
            artifact_type=CommunicationEndpointBinding,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_contact = verify_communication_artifact(
            contact_endpoint,
            artifact_type=CommunicationEndpointBinding,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_contact_party = verify_communication_artifact(
            contact_party,
            artifact_type=CommunicationPartyRef,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        trusted_crm = verify_communication_artifact(
            crm,
            artifact_type=CommunicationCrmTraceBinding,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        write_route = (
            communication_route.connector_account_ref,
            communication_route.route_digest,
        )
        if any(
            candidate != write_route
            for candidate in (
                (dispatch.connector_account_ref, dispatch.route_digest),
                (trusted_thread.connector_account_ref, trusted_thread.route_digest),
                (trusted_sender.connector_account_ref, trusted_sender.route_digest),
                (trusted_contact.connector_account_ref, trusted_contact.route_digest),
            )
        ):
            raise ValueError("sealed communication artifacts do not match write route")
        if (
            dispatch.thread_ref != trusted_thread.thread_ref
            or materialization.thread_ref != trusted_thread.thread_ref
            or dispatch.channel != self._adapter.channel
            or trusted_thread.primary_channel != self._adapter.channel
            or trusted_sender.channel != self._adapter.channel
            or trusted_contact.channel != self._adapter.channel
        ):
            raise ValueError("dispatch, thread, and endpoints are not one channel turn")
        if (
            dispatch.thread_digest != trusted_thread.artifact_digest
            or dispatch.thread_version != trusted_thread.version
            or dispatch.thread_state != trusted_thread.state
            or dispatch.thread_participant_party_refs
            != trusted_thread.participant_party_refs
            or dispatch.parent_message_sha256
            != trusted_thread.parent_message_sha256
        ):
            raise ValueError("dispatch does not bind the exact sealed thread artifact")
        if dispatch.parent_message_sha256 is None:
            raise ValueError("communication dispatch lacks a sealed parent target")
        if trusted_sender.party_ref not in trusted_thread.participant_party_refs or (
            trusted_contact.party_ref not in trusted_thread.participant_party_refs
        ):
            raise ValueError("sealed endpoints are not thread participants")
        if (
            trusted_contact_party.party_kind
            != CommunicationPartyKind.CRM_CONTACT
            or trusted_contact.party_ref != trusted_contact_party.party_ref
            or trusted_contact.party_digest
            != trusted_contact_party.artifact_digest
            or trusted_crm.contact_party_ref != trusted_contact_party.party_ref
            or trusted_crm.contact_party_digest
            != trusted_contact_party.artifact_digest
            or trusted_crm.contact_endpoint_ref != trusted_contact.endpoint_ref
            or trusted_crm.contact_endpoint_digest
            != trusted_contact.artifact_digest
            or trusted_thread.crm_trace_binding_digest
            != trusted_crm.artifact_digest
            or trusted_crm.crm_contact_ref
            != trusted_contact_party.crm_contact_ref
            or trusted_crm.crm_account_ref
            != trusted_contact_party.crm_account_ref
        ):
            raise ValueError("CRM trace does not bind the exact sealed contact")
        self._adapter.validate_authority_binding(
            authority_binding=authority_binding,
            read_route=read_route,
            communication_route=communication_route,
            dispatch=dispatch,
            thread=trusted_thread,
            outbound_sender=trusted_sender,
            contact_party=trusted_contact_party,
            contact=trusted_contact,
            private_dispatch=private_dispatch,
            crm=trusted_crm,
            scope=scope,
            scope_keyring=self._scope_keyring,
        )
        provider_message_digest = self._adapter.provider_message_commitment(
            self._adapter.provider_message_id(private_dispatch),
            authority_binding=authority_binding,
            scope=scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        if dispatch.provider_message_sha256 is None or not hmac.compare_digest(
            dispatch.provider_message_sha256,
            provider_message_digest,
        ):
            raise ValueError("private dispatch message does not match receipt")
        provider_thread_digest = self._adapter.provider_conversation_commitment(
            private_dispatch,
            authority_binding=authority_binding,
            scope=scope,
            key_id=dispatch.receipt_key_id,
            scope_keyring=self._scope_keyring,
        )
        if any(
            digest is None or not hmac.compare_digest(digest, provider_thread_digest)
            for digest in (
                dispatch.provider_thread_sha256,
                trusted_thread.provider_thread_sha256,
            )
        ):
            raise ValueError("private conversation does not match sealed dispatch")
        return (
            trusted_thread,
            trusted_sender,
            trusted_contact_party,
            trusted_contact,
            trusted_crm,
            dispatch,
        )

    def _verify_read_provenance(
        self,
        *,
        request: ConnectorExecutionRequest,
        read_route: Any,
        result: ConnectorExecutionResult,
        dispatch: CommunicationDispatchReceipt,
        now: datetime,
    ) -> ConnectorExecutionProvenance:
        if (
            result.status != ConnectorExecutionStatus.COMPLETED
            or result.tool != read_route.tool
            or result.provenance is None
            or result.cached
        ):
            raise ValueError("email conversation read lacks fresh completed provenance")
        provenance = ConnectorExecutionProvenance.model_validate(result.provenance)
        if (
            provenance.tool != read_route.tool
            or provenance.tool_version != read_route.tool_version
            or provenance.server_effect != ConnectorEffect.READ
            or provenance.connector_account_ref != read_route.connector_account_ref
            or provenance.tenant_connector_id != read_route.tenant_connector_id
            or provenance.project_id != read_route.project_id
            or provenance.route_digest != read_route.route_digest
            or provenance.request_digest != request.custody_fingerprint()
            or provenance.approval_ref is not None
            or provenance.approval_receipt_digest is not None
        ):
            raise ValueError("email read provenance does not match exact route/request")
        completed_at = _timestamp(provenance.completed_at, label="completed_at")
        if completed_at > now + timedelta(seconds=self._clock_skew_seconds):
            raise ValueError("email read provenance is future-dated")
        if now - completed_at > timedelta(seconds=self._max_read_age_seconds):
            raise ValueError("email read provenance is not fresh")
        if dispatch.accepted_at is None or completed_at <= _timestamp(
            dispatch.accepted_at,
            label="dispatch.accepted_at",
        ):
            raise ValueError("email read did not occur after dispatch acceptance")
        return provenance

class GmailCommunicationObserver(CommunicationEmailObserver):
    """Backward-compatible Gmail facade over the shared observation rail."""


__all__ = [
    "COMMUNICATION_GMAIL_OBSERVATION_RESULT_SCHEMA",
    "COMMUNICATION_GMAIL_READ_ROUTE_SCHEMA",
    "COMMUNICATION_PRIVATE_GMAIL_DISPATCH_SCHEMA",
    "CommunicationGmailObservationResult",
    "CommunicationGmailObservationStatus",
    "CommunicationGmailReadRoute",
    "CommunicationObservedEventRepository",
    "CommunicationPrivateGmailDispatch",
    "GmailCommunicationObserver",
    "GmailThreadHeaders",
    "GmailThreadMessage",
    "GmailThreadOutput",
    "InMemoryCommunicationObservedEventRepository",
]
