"""Microsoft Graph models and proof adapter for shared email observation."""

from __future__ import annotations

import hmac
import re
from datetime import datetime
from email.utils import getaddresses
from enum import Enum
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationChannel,
    CommunicationDispatchReceipt,
    CommunicationEndpointBinding,
    CommunicationProviderEvent,
    CommunicationScopeKeyRing,
    communication_canonical_digest,
    communication_canonical_json,
    communication_private_value_digest,
)
from lightbulb.communication_observation import (
    CommunicationEmailObservationInspection,
    CommunicationEmailObserver,
    CommunicationObservedEventRepository,
    CommunicationObservedReply,
    InMemoryCommunicationObservedEventRepository,
    _RFC_MESSAGE_ID_RE,
    _StrictModel,
    _header_message_ids,
    _matching_address,
    _timestamp,
    _utc_text,
    _visible_ref,
)
from lightbulb.communication_outlook import CommunicationOutlookRoute
from lightbulb.communication_outlook_runtime import (
    CommunicationOutlookTraceResult,
    CommunicationPrivateOutlookInbound,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_OUTLOOK_READ_ROUTE_SCHEMA = (
    "lightbulb.communication_outlook_read_route.v1"
)
COMMUNICATION_PRIVATE_OUTLOOK_DISPATCH_SCHEMA = (
    "lightbulb.communication_private_outlook_dispatch.v1"
)
COMMUNICATION_OUTLOOK_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.communication_outlook_observation_result.v1"
)
_OUTLOOK_CONVERSATION_SCHEMA = "lightbulb.outlook_conversation.v1"
_OUTLOOK_GET_CONVERSATION_TOOL = "microsoft.get_conversation"
_READ_EVIDENCE_DOMAIN = "lightbulb.communication_outlook_read_evidence.v1"
_PROVIDER_EVENT_DOMAIN = "lightbulb.communication_outlook_observed_event.v1"
_PROVIDER_ID_RE = re.compile(r"[^\s\x00-\x1f\x7f]{1,512}")


def _outlook_addresses(value: str | None, *, label: str) -> tuple[str, ...]:
    if value is None:
        raise ValueError(f"Outlook {label} header is required")
    parsed = tuple(address.strip() for _, address in getaddresses([value]) if address)
    if not parsed:
        raise ValueError(f"Outlook {label} header contains no email address")
    return parsed


class CommunicationOutlookReadRoute(_StrictModel):
    """Exact Spring-owned route for the ephemeral Outlook conversation read."""

    schema_id: Literal[
        "lightbulb.communication_outlook_read_route.v1"
    ] = Field(default=COMMUNICATION_OUTLOOK_READ_ROUTE_SCHEMA, alias="schema")
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: Literal["microsoft.get_conversation"] = _OUTLOOK_GET_CONVERSATION_TOOL
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible_ref(value, label=info.field_name, maximum=200)


class CommunicationPrivateOutlookDispatch(_StrictModel):
    """Transient immutable identifiers retained after Outlook acceptance."""

    schema_id: Literal[
        "lightbulb.communication_private_outlook_dispatch.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_OUTLOOK_DISPATCH_SCHEMA, alias="schema")
    provider_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_conversation_id: str = Field(
        min_length=1,
        max_length=512,
        repr=False,
    )

    @field_validator("provider_message_id", "provider_conversation_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be one exact Outlook identifier")
        return value


class OutlookMessageHeaders(_StrictModel):
    message_id: str | None = Field(default=None, alias="messageId", max_length=998)
    in_reply_to: str | None = Field(default=None, alias="inReplyTo", max_length=998)
    references: str | None = Field(default=None, max_length=4_096)

    @field_validator("message_id", "in_reply_to", "references")
    @classmethod
    def _header_controls(cls, value: str | None, info: Any) -> str | None:
        if value is not None and ("\r" in value or "\n" in value):
            raise ValueError(f"{info.field_name} contains header controls")
        return value


class OutlookConversationMessage(_StrictModel):
    message_id: str = Field(alias="id", min_length=1, max_length=512)
    conversation_id: str = Field(alias="conversationId", min_length=1, max_length=512)
    internet_message_id: str = Field(
        alias="internetMessageId",
        min_length=5,
        max_length=998,
    )
    headers: OutlookMessageHeaders
    from_address: str = Field(alias="from", min_length=3, max_length=254)
    sender_address: str = Field(alias="sender", min_length=3, max_length=254)
    to_recipients: tuple[str, ...] = Field(alias="toRecipients", max_length=50)
    cc_recipients: tuple[str, ...] = Field(alias="ccRecipients", max_length=50)
    bcc_recipients: tuple[str, ...] = Field(alias="bccRecipients", max_length=50)
    reply_to: tuple[str, ...] = Field(alias="replyTo", max_length=50)
    received_at: str | None = Field(
        default=None,
        alias="receivedDateTime",
        max_length=128,
    )
    sent_at: str | None = Field(
        default=None,
        alias="sentDateTime",
        max_length=128,
    )
    subject: str | None = Field(default=None, max_length=998)
    body: str = Field(max_length=2_000)
    body_truncated: bool = Field(alias="bodyTruncated")
    is_draft: bool = Field(alias="isDraft")

    @field_validator("message_id", "conversation_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} is invalid")
        return value

    @field_validator("internet_message_id")
    @classmethod
    def _internet_message_id(cls, value: str) -> str:
        if _RFC_MESSAGE_ID_RE.fullmatch(value) is None:
            raise ValueError("internetMessageId must be one RFC Message-ID")
        return value

    @field_validator(
        "from_address",
        "sender_address",
        "to_recipients",
        "cc_recipients",
        "bcc_recipients",
        "reply_to",
    )
    @classmethod
    def _exact_addresses(cls, value: Any, info: Any) -> Any:
        values = value if isinstance(value, tuple) else (value,)
        if any(
            _outlook_addresses(item, label=info.field_name) != (item,)
            for item in values
        ):
            raise ValueError(f"{info.field_name} contains an invalid mailbox")
        return value

    @field_validator(
        "to_recipients",
        "cc_recipients",
        "bcc_recipients",
        "reply_to",
        mode="before",
    )
    @classmethod
    def _address_tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("received_at", "sent_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _utc_text(_timestamp(value, label=info.field_name))

    @model_validator(mode="after")
    def _provider_fields_agree(self) -> "OutlookConversationMessage":
        if (
            self.headers.message_id is not None
            and self.headers.message_id != self.internet_message_id
        ):
            raise ValueError("Graph Message-ID fields disagree")
        if self.received_at is None and self.sent_at is None:
            raise ValueError("Outlook message lacks provider occurrence time")
        return self


class OutlookConversationOutput(_StrictModel):
    schema_id: Literal["lightbulb.outlook_conversation.v1"] = Field(
        default=_OUTLOOK_CONVERSATION_SCHEMA,
        alias="schema",
    )
    conversation_id: str = Field(alias="conversationId", min_length=1, max_length=512)
    returned_message_count: int = Field(
        alias="returnedMessageCount",
        ge=0,
        le=10,
    )
    truncated: bool
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]
    messages: tuple[OutlookConversationMessage, ...] = Field(max_length=10)

    @field_validator("conversation_id")
    @classmethod
    def _conversation_id(cls, value: str) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError("Outlook conversation id is invalid")
        return value

    @field_validator("messages", mode="before")
    @classmethod
    def _messages_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _count_integrity(self) -> "OutlookConversationOutput":
        if self.returned_message_count != len(self.messages):
            raise ValueError("returned Outlook message count does not match messages")
        ids = [message.message_id for message in self.messages]
        if len(ids) != len(set(ids)):
            raise ValueError("Outlook conversation contains duplicate message identifiers")
        if any(
            message.conversation_id != self.conversation_id
            for message in self.messages
        ):
            raise ValueError("Outlook message belongs to another conversation")
        return self


class CommunicationOutlookObservationStatus(str, Enum):
    OUTBOUND_PENDING = "outbound_pending"
    NO_REPLY = "no_reply"
    PROCESSED = "processed"


class CommunicationOutlookObservationResult(_StrictModel):
    """Privacy-minimised result of one host-invoked bounded poll."""

    schema_id: Literal[
        "lightbulb.communication_outlook_observation_result.v1"
    ] = Field(default=COMMUNICATION_OUTLOOK_OBSERVATION_RESULT_SCHEMA, alias="schema")
    status: CommunicationOutlookObservationStatus
    read_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_provenance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_completed_at: str
    provider_message_count: int = Field(ge=0)
    returned_message_count: int = Field(ge=0, le=10)
    outbound_observed: bool
    provider_event: CommunicationProviderEvent | None = None
    trace: CommunicationOutlookTraceResult | None = None

    @field_validator("read_completed_at")
    @classmethod
    def _completed_at(cls, value: str) -> str:
        return _utc_text(_timestamp(value, label="read_completed_at"))

    @model_validator(mode="after")
    def _status_shape(self) -> "CommunicationOutlookObservationResult":
        if self.status == CommunicationOutlookObservationStatus.OUTBOUND_PENDING:
            if self.outbound_observed:
                raise ValueError("pending outbound observation cannot claim sent proof")
            if self.provider_event is not None or self.trace is not None:
                raise ValueError("pending outbound observation cannot carry reply artifacts")
        elif self.status == CommunicationOutlookObservationStatus.NO_REPLY:
            if not self.outbound_observed:
                raise ValueError("no-reply observation requires exact outbound proof")
            if self.provider_event is not None or self.trace is not None:
                raise ValueError("no-reply observation cannot carry reply artifacts")
        elif not self.outbound_observed or self.provider_event is None or self.trace is None:
            raise ValueError("processed observation requires event and trace artifacts")
        elif (
            self.trace.inbound_message.provider_event_digest
            != self.provider_event.artifact_digest
        ):
            raise ValueError("trace does not bind the observed provider event")
        return self


def _message_time(message: OutlookConversationMessage) -> datetime:
    value = message.received_at or message.sent_at
    if value is None:  # model validation protects this; defensive for typed callers
        raise ValueError("Outlook message lacks a provider occurrence timestamp")
    return _timestamp(value, label="Outlook occurrence time")


class _OutlookObservationAdapter:
    __slots__ = ()

    provider_name = "outlook"
    channel = CommunicationChannel.EMAIL
    read_tool = _OUTLOOK_GET_CONVERSATION_TOOL
    read_evidence_domain = _READ_EVIDENCE_DOMAIN
    provider_event_domain = _PROVIDER_EVENT_DOMAIN
    payload_ref_prefix = "outlook-payload:"
    content_ref_prefix = "outlook-content:"
    event_ref_prefix = "outlook-observation:"

    def parse_read_route(self, value: Any) -> CommunicationOutlookReadRoute:
        return CommunicationOutlookReadRoute.model_validate(value)

    def parse_communication_route(self, value: Any) -> CommunicationOutlookRoute:
        return CommunicationOutlookRoute.model_validate(value)

    def parse_private_dispatch(
        self,
        value: Any,
    ) -> CommunicationPrivateOutlookDispatch:
        return CommunicationPrivateOutlookDispatch.model_validate(value)

    def parse_authority_binding(self, value: Any, **_: Any) -> None:
        if value is not None:
            raise ValueError("email observation does not accept a channel binding")
        return None

    def read_arguments(
        self,
        private_dispatch: CommunicationPrivateOutlookDispatch,
        max_messages: int,
    ) -> dict[str, Any]:
        return {
            "conversation_id": private_dispatch.provider_conversation_id,
            "max_messages": max_messages,
        }

    def provider_message_id(
        self,
        private_dispatch: CommunicationPrivateOutlookDispatch,
    ) -> str:
        return private_dispatch.provider_message_id

    def provider_conversation_id(
        self,
        private_dispatch: CommunicationPrivateOutlookDispatch,
    ) -> str:
        return private_dispatch.provider_conversation_id

    def runtime_parent_message_id(
        self,
        private_dispatch: CommunicationPrivateOutlookDispatch,
    ) -> str:
        return private_dispatch.provider_message_id

    def provider_message_commitment(self, value: str, **_: Any) -> str:
        return communication_private_value_digest(value)

    def provider_conversation_commitment(
        self,
        private_dispatch: CommunicationPrivateOutlookDispatch,
        **_: Any,
    ) -> str:
        return communication_private_value_digest(
            private_dispatch.provider_conversation_id
        )

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
        private_dispatch: CommunicationPrivateOutlookDispatch,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: Any = None,
        scope: DynamicWorkflowScope | None = None,
    ) -> CommunicationEmailObservationInspection:
        parsed = OutlookConversationOutput.model_validate(output)
        if not hmac.compare_digest(
            parsed.conversation_id,
            private_dispatch.provider_conversation_id,
        ):
            raise ValueError(
                "Outlook response does not match the exact requested conversation"
            )
        if parsed.truncated:
            raise ValueError(
                "truncated Outlook conversation cannot prove an unambiguous reply set"
            )
        outbound_rfc_message_id = self._derive_outbound_rfc_message_id(
            output=parsed,
            outbound_sender=outbound_sender,
            contact=contact,
            private_dispatch=private_dispatch,
            dispatch=dispatch,
            scope_keyring=scope_keyring,
        )
        if outbound_rfc_message_id is None:
            return CommunicationEmailObservationInspection(
                output=parsed,
                provider_conversation_id=parsed.conversation_id,
                provider_message_count=parsed.returned_message_count,
                returned_message_count=parsed.returned_message_count,
                reply=None,
                outbound_observed=False,
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
                    "Outlook reply body is truncated and cannot be classified safely"
                )
            if not message.body.strip():
                raise ValueError("Outlook reply lacks a complete plain-text body")
            reply = CommunicationObservedReply(
                provider_message_id=message.message_id,
                occurred_at=occurred_at,
                sender_address=sender_address,
                recipient_address=recipient_address,
                subject=message.subject or "",
                body=message.body,
                raw_payload=communication_canonical_json(
                    message.model_dump(mode="json", by_alias=True)
                ).decode("utf-8"),
            )
        return CommunicationEmailObservationInspection(
            output=parsed,
            provider_conversation_id=parsed.conversation_id,
            provider_message_count=parsed.returned_message_count,
            returned_message_count=parsed.returned_message_count,
            reply=reply,
            outbound_observed=True,
        )

    def private_inbound(self, **values: Any) -> CommunicationPrivateOutlookInbound:
        for name in (
            "platform",
            "provider_event_hmac",
            "provider_message_hmac_digest",
            "parent_message_hmac_digest",
            "payload_hmac",
            "content_hmac",
        ):
            values.pop(name, None)
        return CommunicationPrivateOutlookInbound(**values)

    def observation_result(
        self,
        *,
        processed: bool,
        outbound_observed: bool,
        **values: Any,
    ) -> CommunicationOutlookObservationResult:
        return CommunicationOutlookObservationResult(
            status=(
                CommunicationOutlookObservationStatus.PROCESSED
                if processed
                else (
                    CommunicationOutlookObservationStatus.NO_REPLY
                    if outbound_observed
                    else CommunicationOutlookObservationStatus.OUTBOUND_PENDING
                )
            ),
            outbound_observed=outbound_observed,
            **values,
        )

    @staticmethod
    def _select_reply(
        *,
        output: OutlookConversationOutput,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateOutlookDispatch,
        outbound_rfc_message_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> tuple[OutlookConversationMessage, datetime, str, str] | None:
        if dispatch.accepted_at is None:
            raise ValueError("Outlook observation requires an accepted dispatch")
        accepted_at = _timestamp(dispatch.accepted_at, label="dispatch.accepted_at")
        exact_replies: list[
            tuple[OutlookConversationMessage, datetime, str, str]
        ] = []
        for message in output.messages:
            occurred_at = _message_time(message)
            if occurred_at <= accepted_at or message.message_id == (
                private_dispatch.provider_message_id
            ):
                continue
            if message.is_draft:
                continue
            if message.sender_address != message.from_address:
                raise ValueError("Outlook reply sender and From identities differ")
            if message.cc_recipients or message.bcc_recipients:
                raise ValueError(
                    "Outlook reply contains an unapproved copied recipient"
                )
            senders = (message.from_address,)
            recipients = message.to_recipients
            if len(recipients) != 1:
                raise ValueError("Outlook reply must have one exact recipient address")
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
                raise ValueError("post-dispatch Outlook sender is not the sealed contact")
            recipient_address = _matching_address(
                recipients,
                endpoint=outbound_sender,
                scope_keyring=scope_keyring,
            )
            if recipient_address is None:
                raise ValueError(
                    "Outlook reply recipient is not the sealed sender endpoint"
                )
            reply_ids = set(_header_message_ids(message.headers.in_reply_to))
            reply_ids.update(_header_message_ids(message.headers.references))
            if outbound_rfc_message_id in reply_ids:
                exact_replies.append(
                    (message, occurred_at, contact_address, recipient_address)
                )
        if len(exact_replies) == 1:
            return exact_replies[0]
        if len(exact_replies) > 1:
            raise ValueError("multiple Outlook replies target the dispatched message")
        return None

    @staticmethod
    def _derive_outbound_rfc_message_id(
        *,
        output: OutlookConversationOutput,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateOutlookDispatch,
        dispatch: CommunicationDispatchReceipt,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str | None:
        outbound = tuple(
            message
            for message in output.messages
            if message.message_id == private_dispatch.provider_message_id
        )
        if not outbound:
            return None
        if len(outbound) != 1:
            raise ValueError(
                "Outlook conversation contains duplicate dispatched provider messages"
            )
        message = outbound[0]
        if message.is_draft:
            raise ValueError("dispatched Outlook message remains a draft")
        if message.sender_address != message.from_address:
            raise ValueError("dispatched Outlook sender and From identities differ")
        message_ids = _header_message_ids(message.headers.message_id)
        if len(message_ids) != 1 or _RFC_MESSAGE_ID_RE.fullmatch(message_ids[0]) is None:
            raise ValueError(
                "dispatched Outlook message lacks one exact RFC Message-ID header"
            )
        parent_ids = set(_header_message_ids(message.headers.in_reply_to))
        parent_ids.update(_header_message_ids(message.headers.references))
        if dispatch.parent_message_sha256 is None or not any(
            hmac.compare_digest(
                dispatch.parent_message_sha256,
                communication_private_value_digest(parent_id),
            )
            for parent_id in parent_ids
        ):
            raise ValueError("dispatched Outlook message lacks the sealed RFC parent")
        if message.cc_recipients or message.bcc_recipients:
            raise ValueError(
                "dispatched Outlook message contains an unapproved copied recipient"
            )
        recipients = message.to_recipients
        if len(recipients) != 1:
            raise ValueError("dispatched Outlook message lacks one exact address pair")
        if (
            _matching_address(
                (message.from_address,),
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
                "dispatched Outlook message does not match the sealed endpoint pair"
            )
        return message_ids[0]


_OUTLOOK_OBSERVATION_ADAPTER = _OutlookObservationAdapter()


class OutlookCommunicationObserver(CommunicationEmailObserver):
    """Outlook facade selecting the closed Graph proof adapter."""

    def __init__(self, **arguments: Any) -> None:
        super().__init__(**arguments, _provider="outlook")


__all__ = [
    "COMMUNICATION_OUTLOOK_OBSERVATION_RESULT_SCHEMA",
    "COMMUNICATION_OUTLOOK_READ_ROUTE_SCHEMA",
    "COMMUNICATION_PRIVATE_OUTLOOK_DISPATCH_SCHEMA",
    "CommunicationOutlookObservationResult",
    "CommunicationOutlookObservationStatus",
    "CommunicationOutlookReadRoute",
    "CommunicationObservedEventRepository",
    "CommunicationPrivateOutlookDispatch",
    "InMemoryCommunicationObservedEventRepository",
    "OutlookCommunicationObserver",
    "OutlookConversationMessage",
    "OutlookConversationOutput",
    "OutlookMessageHeaders",
]
