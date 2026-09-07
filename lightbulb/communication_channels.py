"""Sealed Slack and Teams turns on the shared communication authority rail.

Provider targets and message identifiers are transient. Durable artifacts retain
only domain-separated host-HMAC commitments, exact route/tool custody, and the
existing communication receipts. Channel acceptance never claims delivery or
human readership.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationArtifact,
    CommunicationChannel,
    CommunicationScopeKeyRing,
    CommunicationThreadState,
    communication_canonical_digest,
    communication_private_value_digest,
    verify_communication_artifact,
)
from lightbulb.communication_materializer import (
    CommunicationEmailEffectProof,
    CommunicationMaterializationResult,
    CommunicationPrivateDispatchSink,
    _materialize_communication_turn,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_CHANNEL_TURN_BINDING_SCHEMA = (
    "lightbulb.communication_channel_turn_binding.v1"
)
COMMUNICATION_CHANNEL_WRITE_ROUTE_SCHEMA = (
    "lightbulb.communication_channel_write_route.v1"
)
COMMUNICATION_CHANNEL_READ_ROUTE_SCHEMA = (
    "lightbulb.communication_channel_read_route.v1"
)
COMMUNICATION_PRIVATE_CHANNEL_TURN_SCHEMA = (
    "lightbulb.communication_private_channel_turn.v1"
)
COMMUNICATION_PRIVATE_CHANNEL_DISPATCH_SCHEMA = (
    "lightbulb.communication_private_channel_dispatch.v1"
)
COMMUNICATION_PRIVATE_CHANNEL_INBOUND_SCHEMA = (
    "lightbulb.communication_private_channel_inbound.v1"
)
COMMUNICATION_CHANNEL_PRIVATE_RESULT_COMMITMENTS_SCHEMA = (
    "lightbulb.communication_channel_private_result_commitments.v1"
)

SLACK_POST_TURN_TOOL = "slack.post_conversation_turn"
SLACK_READ_THREAD_TOOL = "slack.get_conversation_thread"
TEAMS_POST_TURN_TOOL = "microsoft.post_channel_turn"
TEAMS_READ_THREAD_TOOL = "microsoft.get_channel_thread"

_PRIVATE_IDENTIFIER_DOMAIN = "lightbulb.communication_channel_private_identifier.v1"
_PRIVATE_VALUE_DOMAIN = "lightbulb.communication_channel_private_value.v1"
_ENDPOINT_ADDRESS_DOMAIN = "lightbulb.communication_channel_endpoint_address.v1"
_TARGET_DIGEST_SCHEMA = "lightbulb.communication_channel_target_commitment.v1"
_MESSAGE_DIGEST_SCHEMA = "lightbulb.communication_channel_message_commitment.v1"
_SLACK_CHANNEL_RE = re.compile(r"^C[A-Z0-9]{1,31}$")
_SLACK_TS_RE = re.compile(r"^[0-9]{1,20}\.[0-9]{6}$")
_VISIBLE_ID_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,512}$")
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SLACK_AUDIENCE_EXPANSION_RE = re.compile(
    r"(?i)(<[@#!]|@(?:channel|here|everyone)\b)"
)
_TEAMS_AUDIENCE_EXPANSION_RE = re.compile(
    r"(?i)(<at(?:\s|>)|@(?:channel|team|everyone)\b)"
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


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _visible(value: str, *, label: str, maximum: int = 512) -> str:
    if value != value.strip() or len(value) > maximum or not _VISIBLE_ID_RE.fullmatch(value):
        raise ValueError(f"{label} is not one exact provider identifier")
    return value


def _uuid_text(value: str, *, label: str) -> str:
    clean = _visible(value, label=label, maximum=64)
    try:
        parsed = UUID(clean)
    except ValueError as exc:
        raise ValueError(f"{label} must be one UUID") from exc
    canonical = str(parsed)
    if clean.casefold() != canonical:
        raise ValueError(f"{label} must use canonical UUID text")
    return canonical


def communication_channel_private_identifier_commitment(
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    platform: CommunicationChannel,
    identifier_kind: str,
    value: str,
) -> str:
    """Return an unlinkable tenant/company-scoped provider-ID commitment."""

    if platform not in {CommunicationChannel.SLACK, CommunicationChannel.TEAMS}:
        raise ValueError("private channel commitment requires Slack or Teams")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,47}", identifier_kind) is None:
        raise ValueError("identifier_kind is invalid")
    _visible(value, label=identifier_kind)
    return scope_keyring.sign(
        key_id,
        _PRIVATE_IDENTIFIER_DOMAIN,
        {
            "schema": _PRIVATE_IDENTIFIER_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "platform": platform,
            "identifier_kind": identifier_kind,
            "value": value,
        },
    ).hex()


def communication_channel_endpoint_address_commitment(
    *,
    scope: DynamicWorkflowScope,
    endpoint_ref: str,
    address: str,
    channel: CommunicationChannel,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Bind one private provider actor ID to a sealed channel endpoint."""

    if _VISIBLE_REF_RE.fullmatch(endpoint_ref) is None:
        raise ValueError("endpoint_ref is invalid")
    _visible(address, label="channel endpoint address")
    return scope_keyring.sign(
        key_id,
        _ENDPOINT_ADDRESS_DOMAIN,
        {
            "schema": _ENDPOINT_ADDRESS_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "endpoint_ref": endpoint_ref,
            "channel": channel,
            "address": address,
        },
    ).hex()


def communication_channel_private_value_commitment(
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    platform: CommunicationChannel,
    value_kind: str,
    value: str,
) -> str:
    """Key a bounded private payload/content commitment by tenant and company."""

    if platform not in {CommunicationChannel.SLACK, CommunicationChannel.TEAMS}:
        raise ValueError("private channel commitment requires Slack or Teams")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,47}", value_kind) is None:
        raise ValueError("value_kind is invalid")
    if not value or len(value) > 1_048_576 or "\x00" in value:
        raise ValueError("private channel value is invalid")
    return scope_keyring.sign(
        key_id,
        _PRIVATE_VALUE_DOMAIN,
        {
            "schema": _PRIVATE_VALUE_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "platform": platform,
            "value_kind": value_kind,
            "value": value,
        },
    ).hex()


def _identifier_commitments(
    private: "CommunicationPrivateChannelTurn | CommunicationPrivateChannelDispatch",
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> dict[str, str | None]:
    values: dict[str, str | None] = {
        "team": None,
        "channel": communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=private.platform,
            identifier_kind="channel_id",
            value=private.channel_id,
        ),
        "root": communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=private.platform,
            identifier_kind="root_message_id",
            value=private.root_message_id,
        ),
    }
    if private.team_id is not None:
        values["team"] = communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=private.platform,
            identifier_kind="team_id",
            value=private.team_id,
        )
    return values


def communication_channel_target_digest(
    *,
    platform: CommunicationChannel,
    team_commitment: str | None,
    channel_commitment: str,
    root_message_commitment: str,
) -> str:
    return communication_canonical_digest(
        {
            "schema": _TARGET_DIGEST_SCHEMA,
            "platform": platform,
            "team_commitment": team_commitment,
            "channel_commitment": channel_commitment,
            "root_message_commitment": root_message_commitment,
        }
    )


def communication_channel_message_digest(message_commitment: str) -> str:
    return communication_canonical_digest(
        {
            "schema": _MESSAGE_DIGEST_SCHEMA,
            "message_commitment": message_commitment,
        }
    )


class CommunicationChannelWriteRoute(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_channel_write_route.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_WRITE_ROUTE_SCHEMA, alias="schema")
    platform: CommunicationChannel
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: str
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)

    @model_validator(mode="after")
    def _exact_tool(self) -> "CommunicationChannelWriteRoute":
        expected = {
            CommunicationChannel.SLACK: SLACK_POST_TURN_TOOL,
            CommunicationChannel.TEAMS: TEAMS_POST_TURN_TOOL,
        }.get(self.platform)
        if self.tool != expected:
            raise ValueError("channel write route has a cross-provider tool")
        return self


class CommunicationChannelReadRoute(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_channel_read_route.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_READ_ROUTE_SCHEMA, alias="schema")
    platform: CommunicationChannel
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: str
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)

    @model_validator(mode="after")
    def _exact_tool(self) -> "CommunicationChannelReadRoute":
        expected = {
            CommunicationChannel.SLACK: SLACK_READ_THREAD_TOOL,
            CommunicationChannel.TEAMS: TEAMS_READ_THREAD_TOOL,
        }.get(self.platform)
        if self.tool != expected:
            raise ValueError("channel read route has a cross-provider tool")
        return self


class CommunicationChannelTurnBinding(CommunicationArtifact):
    """Sealed exact target, audience, content, and read/write route authority."""

    schema_id: Literal[
        "lightbulb.communication_channel_turn_binding.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_TURN_BINDING_SCHEMA, alias="schema")
    binding_ref: str = Field(min_length=1, max_length=200)
    platform: CommunicationChannel
    thread_ref: str = Field(min_length=1, max_length=200)
    thread_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    thread_version: int = Field(ge=1)
    thread_state: CommunicationThreadState
    thread_participant_party_refs: tuple[str, ...] = Field(min_length=2, max_length=100)
    draft_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sender_endpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience_party_ref: str = Field(min_length=1, max_length=200)
    audience_party_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    audience_endpoint_ref: str = Field(min_length=1, max_length=200)
    audience_endpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    write_route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    write_tool: str
    write_tool_version: int = Field(ge=1)
    read_tool: str
    read_tool_version: int = Field(ge=1)
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    team_id_hmac: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    channel_id_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_message_id_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_message_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bound_at: str
    human_read_claimed: Literal[False] = False
    delivery_claimed: Literal[False] = False

    @field_validator("thread_participant_party_refs", mode="before")
    @classmethod
    def _tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("bound_at")
    @classmethod
    def _bound_at(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("bound_at must be ISO-8601") from exc
        return _utc_text(parsed)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _route_refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)

    @model_validator(mode="after")
    def _closed_shape(self) -> "CommunicationChannelTurnBinding":
        expected_tools = {
            CommunicationChannel.SLACK: (
                SLACK_POST_TURN_TOOL,
                SLACK_READ_THREAD_TOOL,
            ),
            CommunicationChannel.TEAMS: (
                TEAMS_POST_TURN_TOOL,
                TEAMS_READ_THREAD_TOOL,
            ),
        }.get(self.platform)
        if expected_tools is None or (self.write_tool, self.read_tool) != expected_tools:
            raise ValueError("channel binding mixes provider tool families")
        if self.thread_state == CommunicationThreadState.CLOSED:
            raise ValueError("closed channel threads are nondispatchable")
        if len(set(self.thread_participant_party_refs)) != len(
            self.thread_participant_party_refs
        ):
            raise ValueError("channel binding participants must be unique")
        if self.platform == CommunicationChannel.SLACK and self.team_id_hmac is not None:
            raise ValueError("Slack binding must not carry a Teams identity")
        if self.platform == CommunicationChannel.TEAMS and self.team_id_hmac is None:
            raise ValueError("Teams binding requires a team identity")
        expected_target = communication_channel_target_digest(
            platform=self.platform,
            team_commitment=self.team_id_hmac,
            channel_commitment=self.channel_id_hmac,
            root_message_commitment=self.root_message_id_hmac,
        )
        if not hmac.compare_digest(self.provider_target_digest, expected_target):
            raise ValueError("channel target commitment is not canonical")
        expected_parent = communication_channel_message_digest(
            self.root_message_id_hmac
        )
        if not hmac.compare_digest(self.parent_message_digest, expected_parent):
            raise ValueError("channel root commitment is not canonical")
        return self


class CommunicationPrivateChannelTurn(_StrictModel):
    """Transient approved content and provider target loaded by the host."""

    schema_id: Literal[
        "lightbulb.communication_private_channel_turn.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_CHANNEL_TURN_SCHEMA, alias="schema")
    platform: CommunicationChannel
    authority_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_message_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    private_content_ref: str = Field(min_length=1, max_length=200)
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=1, max_length=512, repr=False)
    team_id: str | None = Field(default=None, max_length=64, repr=False)
    channel_id: str = Field(min_length=1, max_length=512, repr=False)
    root_message_id: str = Field(min_length=1, max_length=512, repr=False)
    body: str = Field(min_length=1, max_length=40_000, repr=False)

    @model_validator(mode="after")
    def _provider_shape(self) -> "CommunicationPrivateChannelTurn":
        _visible(self.recipient_address, label="recipient_address")
        if self.platform == CommunicationChannel.SLACK:
            if self.team_id is not None or _SLACK_CHANNEL_RE.fullmatch(self.channel_id) is None:
                raise ValueError("Slack private target is invalid")
            if _SLACK_TS_RE.fullmatch(self.root_message_id) is None:
                raise ValueError("Slack root timestamp is invalid")
            if len(self.body) > 40_000 or _SLACK_AUDIENCE_EXPANSION_RE.search(self.body):
                raise ValueError("Slack content exceeds or expands its approved audience")
        elif self.platform == CommunicationChannel.TEAMS:
            if self.team_id is None:
                raise ValueError("Teams private target requires team_id")
            _uuid_text(self.team_id, label="team_id")
            _visible(self.channel_id, label="channel_id")
            _visible(self.root_message_id, label="root_message_id")
            if len(self.body) > 28_000 or _TEAMS_AUDIENCE_EXPANSION_RE.search(self.body):
                raise ValueError("Teams content exceeds or expands its approved audience")
        else:
            raise ValueError("private channel turn requires Slack or Teams")
        if "\x00" in self.body:
            raise ValueError("channel body must not contain NUL")
        return self


class CommunicationPrivateChannelDispatch(_StrictModel):
    """Encrypted-outbox-only provider write result; never a durable journal value."""

    schema_id: Literal[
        "lightbulb.communication_private_channel_dispatch.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_CHANNEL_DISPATCH_SCHEMA, alias="schema")
    platform: CommunicationChannel
    authority_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    provider_target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    team_id: str | None = Field(default=None, max_length=64, repr=False)
    channel_id: str = Field(min_length=1, max_length=512, repr=False)
    root_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_message_id: str = Field(min_length=1, max_length=512, repr=False)
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    provider_observed: Literal[True]

    @model_validator(mode="after")
    def _provider_shape(self) -> "CommunicationPrivateChannelDispatch":
        if self.platform == CommunicationChannel.SLACK:
            if self.team_id is not None or _SLACK_CHANNEL_RE.fullmatch(self.channel_id) is None:
                raise ValueError("Slack private dispatch target is invalid")
            if _SLACK_TS_RE.fullmatch(self.root_message_id) is None or (
                _SLACK_TS_RE.fullmatch(self.provider_message_id) is None
            ):
                raise ValueError("Slack private dispatch timestamp is invalid")
        elif self.platform == CommunicationChannel.TEAMS:
            if self.team_id is None:
                raise ValueError("Teams private dispatch requires team_id")
            _uuid_text(self.team_id, label="team_id")
            _visible(self.channel_id, label="channel_id")
            _visible(self.root_message_id, label="root_message_id")
            _visible(self.provider_message_id, label="provider_message_id")
        else:
            raise ValueError("private channel dispatch requires Slack or Teams")
        if self.provider_message_id == self.root_message_id:
            raise ValueError("channel reply identity must differ from its root")
        return self


class CommunicationChannelPrivateResultCommitments(_StrictModel):
    """Plaintext-safe validator companion for one encrypted private outbox row."""

    schema_id: Literal[
        "lightbulb.communication_channel_private_result_commitments.v1"
    ] = Field(
        default=COMMUNICATION_CHANNEL_PRIVATE_RESULT_COMMITMENTS_SCHEMA,
        alias="schema",
    )
    key_id: str = Field(min_length=8, max_length=80)
    platform: CommunicationChannel
    authority_binding_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    team_id_hmac: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    channel_id_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_message_id_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_message_id_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_message_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _canonical_bundle(self) -> "CommunicationChannelPrivateResultCommitments":
        if self.platform == CommunicationChannel.SLACK:
            if self.team_id_hmac is not None:
                raise ValueError("Slack private result cannot carry a team commitment")
        elif self.platform == CommunicationChannel.TEAMS:
            if self.team_id_hmac is None:
                raise ValueError("Teams private result requires a team commitment")
        else:
            raise ValueError("private result commitments require Slack or Teams")
        target = communication_channel_target_digest(
            platform=self.platform,
            team_commitment=self.team_id_hmac,
            channel_commitment=self.channel_id_hmac,
            root_message_commitment=self.root_message_id_hmac,
        )
        message = communication_channel_message_digest(self.provider_message_id_hmac)
        if not hmac.compare_digest(self.provider_target_digest, target) or (
            not hmac.compare_digest(self.provider_message_digest, message)
        ):
            raise ValueError("private result commitment bundle is not canonical")
        return self


def communication_channel_private_result_commitments(
    private_dispatch: CommunicationPrivateChannelDispatch,
    *,
    authority_binding: CommunicationChannelTurnBinding,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationChannelPrivateResultCommitments:
    """Validate raw outbox plaintext and return only safe durable commitments."""

    private = CommunicationPrivateChannelDispatch.model_validate(private_dispatch)
    binding = verify_communication_artifact(
        authority_binding,
        artifact_type=CommunicationChannelTurnBinding,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    if (
        private.platform != binding.platform
        or private.authority_binding_digest != binding.artifact_digest
        or private.provider_commitment_key_id != binding.provider_commitment_key_id
        or private.provider_target_digest != binding.provider_target_digest
    ):
        raise ValueError("private result does not match its sealed channel binding")
    target = _identifier_commitments(
        private,
        scope=scope,
        key_id=binding.provider_commitment_key_id,
        scope_keyring=scope_keyring,
    )
    provider_message_id_hmac = communication_channel_private_identifier_commitment(
        scope=scope,
        key_id=binding.provider_commitment_key_id,
        scope_keyring=scope_keyring,
        platform=binding.platform,
        identifier_kind="provider_message_id",
        value=private.provider_message_id,
    )
    bundle = CommunicationChannelPrivateResultCommitments(
        key_id=binding.provider_commitment_key_id,
        platform=binding.platform,
        authority_binding_digest=binding.artifact_digest,
        team_id_hmac=target["team"],
        channel_id_hmac=str(target["channel"]),
        root_message_id_hmac=str(target["root"]),
        provider_message_id_hmac=provider_message_id_hmac,
        provider_target_digest=communication_channel_target_digest(
            platform=binding.platform,
            team_commitment=target["team"],
            channel_commitment=str(target["channel"]),
            root_message_commitment=str(target["root"]),
        ),
        provider_message_digest=communication_channel_message_digest(
            provider_message_id_hmac
        ),
        body_sha256=private.body_sha256,
    )
    expected = (
        binding.team_id_hmac,
        binding.channel_id_hmac,
        binding.root_message_id_hmac,
        binding.provider_target_digest,
        binding.body_sha256,
    )
    actual = (
        bundle.team_id_hmac,
        bundle.channel_id_hmac,
        bundle.root_message_id_hmac,
        bundle.provider_target_digest,
        bundle.body_sha256,
    )
    if actual != expected:
        raise ValueError("private result target/content differs from sealed authority")
    return bundle


def communication_channel_private_dispatch_from_effect_output(
    output: Mapping[str, Any],
    *,
    authority_binding: CommunicationChannelTurnBinding | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> tuple[
    CommunicationPrivateChannelDispatch,
    CommunicationChannelPrivateResultCommitments,
]:
    """Purely recover one exact encrypted channel dispatch from connector output.

    The sealed binding carries only keyed target/content commitments.  This
    helper accepts one fresh or recovered provider result, reconstructs the
    existing SDK private-dispatch contract, and verifies every raw identifier
    against those commitments before returning it.  It performs no connector
    I/O and emits no raw value in the durable commitment companion.
    """

    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    binding = verify_communication_artifact(
        authority_binding,
        artifact_type=CommunicationChannelTurnBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if binding.platform == CommunicationChannel.SLACK:
        parsed = _SlackTurnOutput.model_validate(output)
        private = CommunicationPrivateChannelDispatch(
            platform=binding.platform,
            authority_binding_digest=binding.artifact_digest,
            provider_commitment_key_id=binding.provider_commitment_key_id,
            provider_target_digest=binding.provider_target_digest,
            channel_id=parsed.channel_id,
            root_message_id=parsed.thread_ts,
            provider_message_id=parsed.message_ts,
            body_sha256=parsed.text_sha256,
            accepted=True,
            provider_observed=True,
        )
    elif binding.platform == CommunicationChannel.TEAMS:
        parsed = _TeamsTurnOutput.model_validate(output)
        private = CommunicationPrivateChannelDispatch(
            platform=binding.platform,
            authority_binding_digest=binding.artifact_digest,
            provider_commitment_key_id=binding.provider_commitment_key_id,
            provider_target_digest=binding.provider_target_digest,
            team_id=parsed.team_id,
            channel_id=parsed.channel_id,
            root_message_id=parsed.thread_message_id,
            provider_message_id=parsed.message_id,
            body_sha256=parsed.content_sha256,
            accepted=True,
            provider_observed=True,
        )
    else:  # pragma: no cover - the binding model rejects this before the branch
        raise ValueError("channel recovery requires Slack or Teams")
    commitments = communication_channel_private_result_commitments(
        private,
        authority_binding=binding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    return private, commitments


class CommunicationPrivateChannelInbound(_StrictModel):
    """Transient fresh-read turn plus keyed commitments consumed by runtime."""

    schema_id: Literal[
        "lightbulb.communication_private_channel_inbound.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_CHANNEL_INBOUND_SCHEMA, alias="schema")
    platform: CommunicationChannel
    private_payload_ref: str = Field(min_length=1, max_length=200)
    private_content_ref: str = Field(min_length=1, max_length=200)
    provider_event_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_thread_id: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    in_reply_to_message_id: str = Field(min_length=1, max_length=512, repr=False)
    provider_event_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_message_hmac_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_message_hmac_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_hmac: str = Field(pattern=r"^[0-9a-f]{64}$")
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    sender_address: str = Field(min_length=1, max_length=512, repr=False)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=1, max_length=512, repr=False)
    subject: Literal[""] = ""
    body: str = Field(min_length=1, max_length=50_000, repr=False)
    raw_payload: str = Field(min_length=1, max_length=1_048_576, repr=False)
    provider_occurred_at: str

    @field_validator(
        "provider_event_id",
        "provider_message_id",
        "in_reply_to_message_id",
        "sender_address",
        "recipient_address",
    )
    @classmethod
    def _private_ids(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name)

    @field_validator("provider_occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("provider_occurred_at must be ISO-8601") from exc
        return _utc_text(parsed)

    @model_validator(mode="after")
    def _private_shape(self) -> "CommunicationPrivateChannelInbound":
        if self.platform not in {CommunicationChannel.SLACK, CommunicationChannel.TEAMS}:
            raise ValueError("private channel inbound requires Slack or Teams")
        if "\x00" in self.body or "\x00" in self.raw_payload:
            raise ValueError("private channel content must not contain NUL")
        return self

    def payload_digest(self) -> str:
        return self.payload_hmac

    def content_digest(self) -> str:
        return self.content_hmac

    def provider_event_commitment(self) -> str:
        return self.provider_event_hmac

    def provider_message_commitment(self) -> str:
        return self.provider_message_hmac_digest

    def provider_thread_commitment(self) -> str:
        return self.provider_thread_id

    def parent_message_commitment(self) -> str:
        return self.parent_message_hmac_digest


class _SlackTurnOutput(_StrictModel):
    schema_id: Literal["lightbulb.slack_conversation_turn.v1"] = Field(alias="schema")
    channel_id: str = Field(alias="channelId")
    thread_ts: str = Field(alias="threadTs")
    message_ts: str = Field(alias="messageTs")
    text_sha256: str = Field(alias="textSha256", pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    provider_observed: Literal[True] = Field(alias="providerObserved")

    @field_validator("channel_id")
    @classmethod
    def _channel(cls, value: str) -> str:
        if _SLACK_CHANNEL_RE.fullmatch(value) is None:
            raise ValueError("Slack output channel is invalid")
        return value

    @field_validator("thread_ts", "message_ts")
    @classmethod
    def _ts(cls, value: str) -> str:
        if _SLACK_TS_RE.fullmatch(value) is None:
            raise ValueError("Slack output timestamp is invalid")
        return value


class _TeamsTurnOutput(_StrictModel):
    schema_id: Literal["lightbulb.teams_channel_turn.v1"] = Field(alias="schema")
    team_id: str = Field(alias="teamId")
    channel_id: str = Field(alias="channelId")
    thread_message_id: str = Field(alias="threadMessageId")
    message_id: str = Field(alias="messageId")
    content_sha256: str = Field(alias="contentSha256", pattern=r"^[0-9a-f]{64}$")
    accepted: Literal[True]
    provider_observed: Literal[True] = Field(alias="providerObserved")

    @field_validator("team_id")
    @classmethod
    def _team(cls, value: str) -> str:
        return _uuid_text(value, label="teamId")

    @field_validator("channel_id", "thread_message_id", "message_id")
    @classmethod
    def _ids(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name)


@dataclass(frozen=True, slots=True)
class _ChannelMaterializerAdapter:
    platform: CommunicationChannel
    provider_name: str
    tool: str

    @property
    def channel(self) -> CommunicationChannel:
        return self.platform

    def parse_route(self, value: Any) -> CommunicationChannelWriteRoute:
        route = CommunicationChannelWriteRoute.model_validate(value)
        if route.platform != self.platform or route.tool != self.tool:
            raise ValueError("channel write route crosses provider authority")
        return route

    def parse_private_message(self, value: Any) -> CommunicationPrivateChannelTurn:
        private = CommunicationPrivateChannelTurn.model_validate(value)
        if private.platform != self.platform:
            raise ValueError("private channel turn crosses provider authority")
        return private

    def connector_arguments(self, value: CommunicationPrivateChannelTurn) -> dict[str, Any]:
        if self.platform == CommunicationChannel.SLACK:
            return {
                "channel_id": value.channel_id,
                "thread_ts": value.root_message_id,
                "text": value.body,
            }
        return {
            "team_id": value.team_id,
            "channel_id": value.channel_id,
            "thread_message_id": value.root_message_id,
            "content": value.body,
        }

    def provider_conversation_id(self, value: CommunicationPrivateChannelTurn) -> str:
        return value.provider_target_digest

    def provider_conversation_sha256(self, value: CommunicationPrivateChannelTurn) -> str:
        return value.provider_target_digest

    def parent_message_sha256(self, value: CommunicationPrivateChannelTurn) -> str:
        return value.parent_message_digest

    def recipient_address(self, value: CommunicationPrivateChannelTurn) -> str:
        return value.recipient_address

    def subject(self, value: CommunicationPrivateChannelTurn) -> None:
        return None

    def body(self, value: CommunicationPrivateChannelTurn) -> str:
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
        return communication_channel_endpoint_address_commitment(
            scope=scope,
            endpoint_ref=endpoint_ref,
            address=address,
            channel=self.platform,
            key_id=key_id,
            scope_keyring=scope_keyring,
        )

    def validate_authority_binding(self, **values: Any) -> None:
        binding = values.get("authority_binding")
        if not isinstance(binding, CommunicationChannelTurnBinding):
            raise ValueError("channel dispatch requires one sealed authority binding")
        route = values["route"]
        thread = values["thread"]
        sender_party = values["sender_party"]
        recipient_party = values["recipient_party"]
        sender = values["sender_endpoint"]
        recipient = values["recipient_endpoint"]
        draft = values["draft"]
        private = values["private_message"]
        scope = values["scope"]
        scope_keyring = values["scope_keyring"]
        commitments = _identifier_commitments(
            private,
            scope=scope,
            key_id=binding.provider_commitment_key_id,
            scope_keyring=scope_keyring,
        )
        expected_target = communication_channel_target_digest(
            platform=self.platform,
            team_commitment=commitments["team"],
            channel_commitment=str(commitments["channel"]),
            root_message_commitment=str(commitments["root"]),
        )
        expected_parent = communication_channel_message_digest(str(commitments["root"]))
        expected = (
            self.platform,
            thread.thread_ref,
            thread.artifact_digest,
            thread.version,
            thread.state,
            thread.participant_party_refs,
            draft.artifact_digest,
            sender.artifact_digest,
            recipient_party.party_ref,
            recipient_party.artifact_digest,
            recipient.endpoint_ref,
            recipient.artifact_digest,
            draft.body_sha256,
            route.project_id,
            route.project_ref,
            route.connector_account_ref,
            route.tenant_connector_id,
            route.route_digest,
            route.tool,
            route.tool_version,
            binding.provider_commitment_key_id,
            commitments["team"],
            commitments["channel"],
            commitments["root"],
            expected_target,
            expected_parent,
        )
        actual = (
            binding.platform,
            binding.thread_ref,
            binding.thread_digest,
            binding.thread_version,
            binding.thread_state,
            binding.thread_participant_party_refs,
            binding.draft_digest,
            binding.sender_endpoint_digest,
            binding.audience_party_ref,
            binding.audience_party_digest,
            binding.audience_endpoint_ref,
            binding.audience_endpoint_digest,
            binding.body_sha256,
            binding.project_id,
            binding.project_ref,
            binding.connector_account_ref,
            binding.tenant_connector_id,
            binding.write_route_digest,
            binding.write_tool,
            binding.write_tool_version,
            private.provider_commitment_key_id,
            binding.team_id_hmac,
            binding.channel_id_hmac,
            binding.root_message_id_hmac,
            private.provider_target_digest,
            private.parent_message_digest,
        )
        if actual != expected or private.authority_binding_digest != binding.artifact_digest:
            raise ValueError("channel binding does not match exact scope/route/target/audience/content")
        if binding.provider_commitment_key_id != binding.receipt_key_id:
            raise ValueError("channel provider commitments must use the binding seal key epoch")
        if binding.provider_commitment_key_id != draft.receipt_key_id:
            raise ValueError("channel binding and dispatch must use one receipt key epoch")
        if sender_party.party_ref not in binding.thread_participant_party_refs:
            raise ValueError("channel sender is not a bound thread participant")

    def validate_effect_output(
        self,
        output: Mapping[str, Any],
        private_message: CommunicationPrivateChannelTurn,
        **_: Any,
    ) -> CommunicationEmailEffectProof:
        if self.platform == CommunicationChannel.SLACK:
            parsed = _SlackTurnOutput.model_validate(output)
            if (
                parsed.channel_id != private_message.channel_id
                or parsed.thread_ts != private_message.root_message_id
                or parsed.text_sha256 != communication_private_value_digest(private_message.body)
            ):
                raise ValueError("Slack output does not prove the approved target/content")
            private_dispatch = CommunicationPrivateChannelDispatch(
                platform=self.platform,
                authority_binding_digest=private_message.authority_binding_digest,
                provider_commitment_key_id=private_message.provider_commitment_key_id,
                provider_target_digest=private_message.provider_target_digest,
                channel_id=parsed.channel_id,
                root_message_id=parsed.thread_ts,
                provider_message_id=parsed.message_ts,
                body_sha256=parsed.text_sha256,
                accepted=True,
                provider_observed=True,
            )
            provider_message_id = parsed.message_ts
        else:
            parsed = _TeamsTurnOutput.model_validate(output)
            if (
                parsed.team_id != private_message.team_id
                or parsed.channel_id != private_message.channel_id
                or parsed.thread_message_id != private_message.root_message_id
                or parsed.content_sha256 != communication_private_value_digest(private_message.body)
            ):
                raise ValueError("Teams output does not prove the approved target/content")
            private_dispatch = CommunicationPrivateChannelDispatch(
                platform=self.platform,
                authority_binding_digest=private_message.authority_binding_digest,
                provider_commitment_key_id=private_message.provider_commitment_key_id,
                provider_target_digest=private_message.provider_target_digest,
                team_id=parsed.team_id,
                channel_id=parsed.channel_id,
                root_message_id=parsed.thread_message_id,
                provider_message_id=parsed.message_id,
                body_sha256=parsed.content_sha256,
                accepted=True,
                provider_observed=True,
            )
            provider_message_id = parsed.message_id
        return CommunicationEmailEffectProof(
            provider_message_id=provider_message_id,
            provider_conversation_id=private_message.provider_target_digest,
            completed=False,
            provider_conversation_sha256=private_message.provider_target_digest,
            private_dispatch=private_dispatch,
        )

    def provider_effect_message_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        if not isinstance(authority_binding, CommunicationChannelTurnBinding):
            raise ValueError("channel effect lacks sealed binding")
        commitment = communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=authority_binding.provider_commitment_key_id,
            scope_keyring=scope_keyring,
            platform=self.platform,
            identifier_kind="provider_message_id",
            value=proof.provider_message_id,
        )
        return communication_channel_message_digest(commitment)

    def provider_effect_conversation_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        *,
        authority_binding: Any,
        **_: Any,
    ) -> str:
        if not isinstance(authority_binding, CommunicationChannelTurnBinding):
            raise ValueError("channel effect lacks sealed binding")
        return authority_binding.provider_target_digest


_SLACK_CHANNEL_MATERIALIZER_ADAPTER = _ChannelMaterializerAdapter(
    platform=CommunicationChannel.SLACK,
    provider_name="slack",
    tool=SLACK_POST_TURN_TOOL,
)
_TEAMS_CHANNEL_MATERIALIZER_ADAPTER = _ChannelMaterializerAdapter(
    platform=CommunicationChannel.TEAMS,
    provider_name="teams",
    tool=TEAMS_POST_TURN_TOOL,
)


def _materialize_channel_turn(
    *,
    provider_adapter: _ChannelMaterializerAdapter,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    channel_binding: CommunicationChannelTurnBinding | Mapping[str, Any],
    private_dispatch_sink: CommunicationPrivateDispatchSink,
    **arguments: Any,
) -> CommunicationMaterializationResult:
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    if channel_binding is None:
        raise ValueError("channel dispatch requires one sealed authority binding")
    trusted_binding = verify_communication_artifact(
        channel_binding,
        artifact_type=CommunicationChannelTurnBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    return _materialize_communication_turn(
        provider_adapter=provider_adapter,
        authority_binding=trusted_binding,
        private_dispatch_sink=private_dispatch_sink,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        **arguments,
    )


def materialize_slack_communication_turn(**arguments: Any) -> CommunicationMaterializationResult:
    return _materialize_channel_turn(
        provider_adapter=_SLACK_CHANNEL_MATERIALIZER_ADAPTER,
        **arguments,
    )


def materialize_teams_communication_turn(**arguments: Any) -> CommunicationMaterializationResult:
    return _materialize_channel_turn(
        provider_adapter=_TEAMS_CHANNEL_MATERIALIZER_ADAPTER,
        **arguments,
    )


__all__ = [
    "COMMUNICATION_CHANNEL_READ_ROUTE_SCHEMA",
    "COMMUNICATION_CHANNEL_PRIVATE_RESULT_COMMITMENTS_SCHEMA",
    "COMMUNICATION_CHANNEL_TURN_BINDING_SCHEMA",
    "COMMUNICATION_CHANNEL_WRITE_ROUTE_SCHEMA",
    "COMMUNICATION_PRIVATE_CHANNEL_DISPATCH_SCHEMA",
    "COMMUNICATION_PRIVATE_CHANNEL_INBOUND_SCHEMA",
    "COMMUNICATION_PRIVATE_CHANNEL_TURN_SCHEMA",
    "CommunicationChannelReadRoute",
    "CommunicationChannelPrivateResultCommitments",
    "CommunicationChannelTurnBinding",
    "CommunicationChannelWriteRoute",
    "CommunicationPrivateChannelDispatch",
    "CommunicationPrivateChannelInbound",
    "CommunicationPrivateChannelTurn",
    "CommunicationPrivateDispatchSink",
    "SLACK_POST_TURN_TOOL",
    "SLACK_READ_THREAD_TOOL",
    "TEAMS_POST_TURN_TOOL",
    "TEAMS_READ_THREAD_TOOL",
    "communication_channel_endpoint_address_commitment",
    "communication_channel_message_digest",
    "communication_channel_private_dispatch_from_effect_output",
    "communication_channel_private_identifier_commitment",
    "communication_channel_private_result_commitments",
    "communication_channel_private_value_commitment",
    "communication_channel_target_digest",
    "materialize_slack_communication_turn",
    "materialize_teams_communication_turn",
]
