"""Exact Outlook adapter for the shared governed email materializer."""

from __future__ import annotations

import re
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationChannel,
    CommunicationScopeKeyRing,
    communication_private_value_digest,
)

from lightbulb.communication_materializer import (
    CommunicationContactReservationAuthority,
    CommunicationEmailEffectProof,
    CommunicationExternalEffectState,
    CommunicationMaterializationResult,
    CommunicationMaterializationStatus,
    communication_endpoint_address_commitment,
    _materialize_email_communication_turn,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_OUTLOOK_ROUTE_SCHEMA = "lightbulb.communication_outlook_route.v1"
COMMUNICATION_PRIVATE_OUTLOOK_MESSAGE_SCHEMA = (
    "lightbulb.communication_private_outlook_message.v1"
)
_OUTLOOK_REPLY_TOOL = "microsoft.reply_email"
_EMAIL_RE = re.compile(r"^[^\s,@;<>]+@[^\s,@;<>]+\.[^\s,@;<>]+$")
_RFC_MESSAGE_ID_RE = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")
_PROVIDER_ID_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,512}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _visible(value: str, *, label: str, maximum: int = 240) -> str:
    if (
        value != value.strip()
        or len(value) > maximum
        or _VISIBLE_REF_RE.fullmatch(value) is None
    ):
        raise ValueError(f"{label} contains unsupported characters")
    return value


class CommunicationOutlookRoute(_StrictModel):
    """Server-attested coordinates for one exact Microsoft account route."""

    schema_id: Literal["lightbulb.communication_outlook_route.v1"] = Field(
        default=COMMUNICATION_OUTLOOK_ROUTE_SCHEMA,
        alias="schema",
    )
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: Literal["microsoft.reply_email"] = _OUTLOOK_REPLY_TOOL
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _route_refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)


class CommunicationPrivateOutlookMessage(_StrictModel):
    """Transient content and Graph selectors resolved by the trusted host."""

    schema_id: Literal[
        "lightbulb.communication_private_outlook_message.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_OUTLOOK_MESSAGE_SCHEMA, alias="schema")
    private_content_ref: str = Field(min_length=1, max_length=200)
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=3, max_length=254, repr=False)
    subject: str = Field(min_length=1, max_length=998, repr=False)
    body: str = Field(min_length=1, max_length=50_000, repr=False)
    provider_conversation_id: str = Field(min_length=1, max_length=512, repr=False)
    parent_provider_message_id: str = Field(
        min_length=1,
        max_length=512,
        repr=False,
    )
    parent_rfc_message_id: str = Field(min_length=5, max_length=998, repr=False)

    @field_validator(
        "private_content_ref",
        "sender_endpoint_ref",
        "recipient_endpoint_ref",
    )
    @classmethod
    def _private_refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)

    @field_validator("recipient_address")
    @classmethod
    def _mailbox(cls, value: str) -> str:
        if value != value.strip() or _EMAIL_RE.fullmatch(value) is None:
            raise ValueError("recipient_address must be one exact mailbox")
        return value

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("subject must not contain header controls")
        return value

    @field_validator("body")
    @classmethod
    def _body(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("body must not contain NUL")
        return value

    @field_validator("provider_conversation_id", "parent_provider_message_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} is not one exact Graph identifier")
        return value

    @field_validator("parent_rfc_message_id")
    @classmethod
    def _parent_rfc_id(cls, value: str) -> str:
        if _RFC_MESSAGE_ID_RE.fullmatch(value) is None:
            raise ValueError("parent_rfc_message_id must be one RFC Message-ID")
        return value

    def connector_arguments(self) -> dict[str, str]:
        return {
            "to": self.recipient_address,
            "subject": self.subject,
            "body": self.body,
            "conversation_id": self.provider_conversation_id,
            "parent_provider_message_id": self.parent_provider_message_id,
            "parent_rfc_message_id": self.parent_rfc_message_id,
        }


class _OutlookReplyOutput(_StrictModel):
    schema_id: Literal["lightbulb.outlook_reply.v1"] = Field(alias="schema")
    provider_message_id: str = Field(alias="id", min_length=1, max_length=512)
    provider_conversation_id: str = Field(
        alias="conversationId",
        min_length=1,
        max_length=512,
    )
    internet_message_id: str = Field(alias="internetMessageId", max_length=998)
    parent_internet_message_id: str = Field(
        alias="parentInternetMessageId",
        max_length=998,
    )
    accepted: Literal[True]
    sent_items_observed: bool = Field(alias="sentItemsObserved")

    @field_validator("provider_message_id", "provider_conversation_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if _PROVIDER_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} is not one exact Graph identifier")
        return value

    @field_validator("internet_message_id", "parent_internet_message_id")
    @classmethod
    def _rfc_ids(cls, value: str, info: Any) -> str:
        if _RFC_MESSAGE_ID_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be one RFC Message-ID")
        return value

    @model_validator(mode="after")
    def _distinct_reply(self) -> "_OutlookReplyOutput":
        if self.internet_message_id == self.parent_internet_message_id:
            raise ValueError("reply and parent RFC Message-IDs must differ")
        return self


class _OutlookEmailMaterializerAdapter:
    """Small provider adapter; all governance stays in the shared materializer."""

    __slots__ = ()

    provider_name = "outlook"
    tool = _OUTLOOK_REPLY_TOOL
    channel = CommunicationChannel.EMAIL

    def parse_route(self, value: Any) -> CommunicationOutlookRoute:
        return CommunicationOutlookRoute.model_validate(value)

    def parse_private_message(self, value: Any) -> CommunicationPrivateOutlookMessage:
        return CommunicationPrivateOutlookMessage.model_validate(value)

    def connector_arguments(
        self,
        value: CommunicationPrivateOutlookMessage,
    ) -> dict[str, Any]:
        return value.connector_arguments()

    def provider_conversation_id(
        self,
        value: CommunicationPrivateOutlookMessage,
    ) -> str:
        return value.provider_conversation_id

    def provider_conversation_sha256(
        self,
        value: CommunicationPrivateOutlookMessage,
    ) -> str:
        return communication_private_value_digest(value.provider_conversation_id)

    def parent_message_sha256(
        self,
        value: CommunicationPrivateOutlookMessage,
    ) -> str:
        return communication_private_value_digest(value.parent_rfc_message_id)

    def recipient_address(self, value: CommunicationPrivateOutlookMessage) -> str:
        return value.recipient_address

    def subject(self, value: CommunicationPrivateOutlookMessage) -> str:
        return value.subject

    def body(self, value: CommunicationPrivateOutlookMessage) -> str:
        return value.body

    def endpoint_address_commitment(
        self,
        *,
        scope: DynamicWorkflowScope,
        endpoint_ref: str,
        address: str,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        return communication_endpoint_address_commitment(
            endpoint_ref=endpoint_ref,
            address=address,
            key_id=key_id,
            scope_keyring=scope_keyring,
        )

    def validate_authority_binding(self, **values: Any) -> None:
        if values.get("authority_binding") is not None:
            raise ValueError("email dispatch does not accept a channel binding")

    def validate_effect_output(
        self,
        output: Mapping[str, Any],
        private_message: CommunicationPrivateOutlookMessage,
        **_: Any,
    ) -> CommunicationEmailEffectProof:
        parsed = _OutlookReplyOutput.model_validate(output)
        if (
            parsed.provider_conversation_id
            != private_message.provider_conversation_id
            or parsed.parent_internet_message_id
            != private_message.parent_rfc_message_id
        ):
            raise ValueError("Outlook effect output does not bind the exact parent")
        return CommunicationEmailEffectProof(
            provider_message_id=parsed.provider_message_id,
            provider_conversation_id=parsed.provider_conversation_id,
            completed=parsed.sent_items_observed,
        )

    def provider_effect_message_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        **_: Any,
    ) -> str:
        return communication_private_value_digest(proof.provider_message_id)

    def provider_effect_conversation_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        **_: Any,
    ) -> str:
        return communication_private_value_digest(proof.provider_conversation_id)


_OUTLOOK_MATERIALIZER_ADAPTER = _OutlookEmailMaterializerAdapter()


def materialize_outlook_communication_turn(
    **arguments: Any,
) -> CommunicationMaterializationResult:
    """Run the shared authority with exact Microsoft-specific proof hooks."""

    return _materialize_email_communication_turn(
        provider_adapter=_OUTLOOK_MATERIALIZER_ADAPTER,
        **arguments,
    )


__all__ = [
    "COMMUNICATION_OUTLOOK_ROUTE_SCHEMA",
    "COMMUNICATION_PRIVATE_OUTLOOK_MESSAGE_SCHEMA",
    "CommunicationContactReservationAuthority",
    "CommunicationExternalEffectState",
    "CommunicationMaterializationResult",
    "CommunicationMaterializationStatus",
    "CommunicationOutlookRoute",
    "CommunicationPrivateOutlookMessage",
    "communication_endpoint_address_commitment",
    "materialize_outlook_communication_turn",
]
