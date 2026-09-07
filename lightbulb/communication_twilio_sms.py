"""Closed contracts for the dark governed Twilio SMS tracer.

This module owns provider-specific route, transient payload, acceptance, and
status shapes.  It deliberately does not register Tools, create connector
routes, or expose a transport.  Raw phone numbers and message SIDs are valid
only in the transient models below; durable callers use the domain-separated
commitment helper.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationProviderEventType,
    CommunicationScopeKeyRing,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


TWILIO_SEND_SMS_TOOL = "twilio.send_sms_turn"
TWILIO_LOOKUP_MESSAGE_STATUS_TOOL = "twilio.lookup_message_status"

COMMUNICATION_TWILIO_SMS_WRITE_ROUTE_SCHEMA = (
    "lightbulb.communication_twilio_sms_write_route.v1"
)
COMMUNICATION_TWILIO_SMS_STATUS_ROUTE_SCHEMA = (
    "lightbulb.communication_twilio_sms_status_route.v1"
)
COMMUNICATION_PRIVATE_TWILIO_SMS_TURN_SCHEMA = (
    "lightbulb.communication_private_twilio_sms_turn.v1"
)
COMMUNICATION_PRIVATE_TWILIO_SMS_DISPATCH_SCHEMA = (
    "lightbulb.communication_private_twilio_sms_dispatch.v1"
)
COMMUNICATION_TWILIO_SMS_PRIVATE_RESULT_COMMITMENTS_SCHEMA = (
    "lightbulb.communication_twilio_sms_private_result_commitments.v1"
)
TWILIO_SMS_ACCEPTANCE_SCHEMA = "lightbulb.twilio_sms_acceptance.v1"
TWILIO_SMS_STATUS_SCHEMA = "lightbulb.twilio_sms_status.v1"

TWILIO_SMS_PRIVATE_IDENTIFIER_DOMAIN = (
    "lightbulb.communication_twilio_sms_private_identifier.v1"
)

_E164_RE = re.compile(r"^\+[1-9][0-9]{7,14}$")
_MESSAGE_SID_RE = re.compile(r"^SM[0-9A-Fa-f]{32}$")
_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def canonical_twilio_e164(value: str) -> str:
    """Require one already-canonical E.164 destination; never guess a country."""

    if (
        not isinstance(value, str)
        or value != value.strip()
        or _E164_RE.fullmatch(value) is None
    ):
        raise ValueError("phone number must be one canonical E.164 address")
    return value


def canonical_twilio_message_sid(value: str) -> str:
    """Require the first-tracer Twilio Message SID shape."""

    if (
        not isinstance(value, str)
        or value != value.strip()
        or _MESSAGE_SID_RE.fullmatch(value) is None
    ):
        raise ValueError("message SID must be one exact Twilio Message SID")
    return value


def _safe_ref(value: str, *, label: str) -> str:
    if value != value.strip() or _SAFE_REF_RE.fullmatch(value) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _utc_text(value: str, *, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def communication_twilio_sms_private_identifier_commitment(
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    connector_account_ref: str,
    route_digest: str,
    identifier_kind: Literal["message_sid"],
    value: str,
) -> str:
    """Key a provider identifier by tenant, company, project route, and kind."""

    if identifier_kind != "message_sid":
        raise ValueError("Twilio SMS identifier kind is not reviewed")
    canonical = canonical_twilio_message_sid(value)
    account_ref = _safe_ref(connector_account_ref, label="connector_account_ref")
    if _SHA256_RE.fullmatch(route_digest) is None:
        raise ValueError("route_digest must be lowercase SHA-256")
    return scope_keyring.sign(
        key_id,
        TWILIO_SMS_PRIVATE_IDENTIFIER_DOMAIN,
        {
            "schema": TWILIO_SMS_PRIVATE_IDENTIFIER_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "project_ref": scope.project_ref,
            "connector_account_ref": account_ref,
            "route_digest": route_digest,
            "identifier_kind": identifier_kind,
            "value": canonical,
        },
    ).hex()


class TwilioSmsProviderStatus(str, Enum):
    ACCEPTED = "accepted"
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    UNDELIVERED = "undelivered"
    FAILED = "failed"
    CANCELED = "canceled"

    @property
    def terminal(self) -> bool:
        return self in {
            TwilioSmsProviderStatus.DELIVERED,
            TwilioSmsProviderStatus.UNDELIVERED,
            TwilioSmsProviderStatus.FAILED,
            TwilioSmsProviderStatus.CANCELED,
        }

    @property
    def event_type(self) -> CommunicationProviderEventType:
        if self == TwilioSmsProviderStatus.ACCEPTED:
            return CommunicationProviderEventType.ACCEPTED
        if self == TwilioSmsProviderStatus.DELIVERED:
            return CommunicationProviderEventType.DELIVERED
        if self in {
            TwilioSmsProviderStatus.UNDELIVERED,
            TwilioSmsProviderStatus.FAILED,
            TwilioSmsProviderStatus.CANCELED,
        }:
            return CommunicationProviderEventType.FAILED
        return CommunicationProviderEventType.QUEUED


class _TwilioSmsRoute(_StrictModel):
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _route_refs(cls, value: str, info: Any) -> str:
        return _safe_ref(value, label=info.field_name)


class CommunicationTwilioSmsWriteRoute(_TwilioSmsRoute):
    schema_id: Literal["lightbulb.communication_twilio_sms_write_route.v1"] = Field(
        default=COMMUNICATION_TWILIO_SMS_WRITE_ROUTE_SCHEMA, alias="schema"
    )
    tool: Literal["twilio.send_sms_turn"] = TWILIO_SEND_SMS_TOOL


class CommunicationTwilioSmsStatusRoute(_TwilioSmsRoute):
    schema_id: Literal["lightbulb.communication_twilio_sms_status_route.v1"] = Field(
        default=COMMUNICATION_TWILIO_SMS_STATUS_ROUTE_SCHEMA, alias="schema"
    )
    tool: Literal["twilio.lookup_message_status"] = TWILIO_LOOKUP_MESSAGE_STATUS_TOOL


class CommunicationPrivateTwilioSmsTurn(_StrictModel):
    """Transient approved destination and content loaded by the trusted host."""

    schema_id: Literal["lightbulb.communication_private_twilio_sms_turn.v1"] = Field(
        default=COMMUNICATION_PRIVATE_TWILIO_SMS_TURN_SCHEMA, alias="schema"
    )
    private_content_ref: str = Field(min_length=1, max_length=200)
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=9, max_length=16, repr=False)
    body: str = Field(min_length=1, max_length=1_600, repr=False)

    @field_validator(
        "private_content_ref",
        "sender_endpoint_ref",
        "recipient_endpoint_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _safe_ref(value, label=info.field_name)

    @field_validator("recipient_address")
    @classmethod
    def _recipient(cls, value: str) -> str:
        return canonical_twilio_e164(value)

    @field_validator("body")
    @classmethod
    def _body(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("SMS body must not contain NUL")
        return value

    def connector_arguments(self) -> dict[str, str]:
        return {"to": self.recipient_address, "body": self.body}


class TwilioSmsAcceptance(_StrictModel):
    """Live provider acceptance proof; Message SID enters encrypted custody."""

    schema_id: Literal["lightbulb.twilio_sms_acceptance.v1"] = Field(
        default=TWILIO_SMS_ACCEPTANCE_SCHEMA,
        alias="schema",
    )
    message_sid: str = Field(alias="messageSid", repr=False)
    status: Literal["accepted", "queued", "sending", "sent"]
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    provider_observed: Literal[True] = Field(alias="providerObserved")

    @field_validator("message_sid")
    @classmethod
    def _sid(cls, value: str) -> str:
        return canonical_twilio_message_sid(value)


class TwilioSmsStatus(_StrictModel):
    """Fresh ephemeral status response; it never claims a conversational reply."""

    schema_id: Literal["lightbulb.twilio_sms_status.v1"] = Field(
        default=TWILIO_SMS_STATUS_SCHEMA,
        alias="schema",
    )
    message_sid: str = Field(alias="messageSid", repr=False)
    recipient_address: str = Field(alias="to", repr=False)
    status: TwilioSmsProviderStatus
    event_type: CommunicationProviderEventType = Field(alias="eventType")
    terminal: bool
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[0-9a-f]{64}$")
    error_code: int | None = Field(default=None, alias="errorCode", ge=0, le=99_999)
    provider_updated_at: str | None = Field(default=None, alias="providerUpdatedAt")
    provider_observed: Literal[True] = Field(alias="providerObserved")
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]

    @field_validator("message_sid")
    @classmethod
    def _sid(cls, value: str) -> str:
        return canonical_twilio_message_sid(value)

    @field_validator("recipient_address")
    @classmethod
    def _recipient(cls, value: str) -> str:
        return canonical_twilio_e164(value)

    @field_validator("provider_updated_at")
    @classmethod
    def _updated_at(cls, value: str | None) -> str | None:
        return None if value is None else _utc_text(value, label="providerUpdatedAt")

    @model_validator(mode="after")
    def _normalized_status(self) -> "TwilioSmsStatus":
        if self.terminal != self.status.terminal:
            raise ValueError("terminal flag does not match provider status")
        if self.event_type != self.status.event_type:
            raise ValueError("eventType does not match provider status")
        if not self.terminal and self.error_code is not None:
            raise ValueError("nonterminal status cannot carry an error code")
        if (
            self.status == TwilioSmsProviderStatus.DELIVERED
            and self.error_code is not None
        ):
            raise ValueError("delivered status cannot carry an error code")
        return self


class CommunicationTwilioSmsPrivateResultCommitments(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_twilio_sms_private_result_commitments.v1"
    ] = Field(
        default=COMMUNICATION_TWILIO_SMS_PRIVATE_RESULT_COMMITMENTS_SCHEMA,
        alias="schema",
    )
    key_id: str = Field(min_length=8, max_length=80)
    provider_message_sid_hmac_v1: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CommunicationPrivateTwilioSmsDispatch(_StrictModel):
    """Encrypted-outbox identity derived from one verified send acceptance."""

    schema_id: Literal["lightbulb.communication_private_twilio_sms_dispatch.v1"] = (
        Field(default=COMMUNICATION_PRIVATE_TWILIO_SMS_DISPATCH_SCHEMA, alias="schema")
    )
    provider_message_sid: str = Field(repr=False)
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    provider_message_sid_hmac_v1: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    provider_observed: Literal[True]

    @field_validator("provider_message_sid")
    @classmethod
    def _sid(cls, value: str) -> str:
        return canonical_twilio_message_sid(value)


__all__ = [
    "COMMUNICATION_PRIVATE_TWILIO_SMS_DISPATCH_SCHEMA",
    "COMMUNICATION_PRIVATE_TWILIO_SMS_TURN_SCHEMA",
    "COMMUNICATION_TWILIO_SMS_PRIVATE_RESULT_COMMITMENTS_SCHEMA",
    "COMMUNICATION_TWILIO_SMS_STATUS_ROUTE_SCHEMA",
    "COMMUNICATION_TWILIO_SMS_WRITE_ROUTE_SCHEMA",
    "CommunicationPrivateTwilioSmsDispatch",
    "CommunicationPrivateTwilioSmsTurn",
    "CommunicationTwilioSmsPrivateResultCommitments",
    "CommunicationTwilioSmsStatusRoute",
    "CommunicationTwilioSmsWriteRoute",
    "TWILIO_LOOKUP_MESSAGE_STATUS_TOOL",
    "TWILIO_SEND_SMS_TOOL",
    "TWILIO_SMS_ACCEPTANCE_SCHEMA",
    "TWILIO_SMS_PRIVATE_IDENTIFIER_DOMAIN",
    "TWILIO_SMS_STATUS_SCHEMA",
    "TwilioSmsAcceptance",
    "TwilioSmsProviderStatus",
    "TwilioSmsStatus",
    "canonical_twilio_e164",
    "canonical_twilio_message_sid",
    "communication_twilio_sms_private_identifier_commitment",
]
