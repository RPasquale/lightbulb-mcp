"""Fresh bounded Slack/Teams observation on the shared communication rail."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Mapping
from uuid import UUID

from pydantic import Field, ValidationError, field_validator, model_validator

from lightbulb.communication_channels import (
    CommunicationChannelReadRoute,
    CommunicationChannelTurnBinding,
    CommunicationChannelWriteRoute,
    CommunicationPrivateChannelDispatch,
    CommunicationPrivateChannelInbound,
    SLACK_READ_THREAD_TOOL,
    TEAMS_READ_THREAD_TOOL,
    communication_channel_endpoint_address_commitment,
    communication_channel_message_digest,
    communication_channel_private_identifier_commitment,
    communication_channel_private_result_commitments,
    communication_channel_private_value_commitment,
)
from lightbulb.communication_contracts import (
    CommunicationChannel,
    CommunicationDispatchReceipt,
    CommunicationEndpointBinding,
    CommunicationProviderEvent,
    CommunicationScopeKeyRing,
    communication_canonical_json,
    verify_communication_artifact,
)
from lightbulb.communication_observation import (
    CommunicationEmailObservationInspection,
    CommunicationEmailObserver,
    CommunicationObservedReply,
    _StrictModel,
    _timestamp,
)
from lightbulb.communication_runtime import CommunicationTraceResult
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_CHANNEL_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.communication_channel_observation_result.v1"
)
_SLACK_READ_EVIDENCE_DOMAIN = "lightbulb.communication_slack_read_evidence.v1"
_TEAMS_READ_EVIDENCE_DOMAIN = "lightbulb.communication_teams_read_evidence.v1"
_SLACK_EVENT_DOMAIN = "lightbulb.communication_slack_observed_event.v1"
_TEAMS_EVENT_DOMAIN = "lightbulb.communication_teams_observed_event.v1"


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _slack_time(value: str) -> datetime:
    seconds, micros = value.split(".", 1)
    try:
        return datetime.fromtimestamp(
            int(seconds) + int(micros) / 1_000_000,
            tz=timezone.utc,
        )
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError("Slack timestamp is outside the supported range") from exc


def _matches_endpoint(
    value: str,
    *,
    scope: DynamicWorkflowScope,
    endpoint: CommunicationEndpointBinding,
    channel: CommunicationChannel,
    scope_keyring: CommunicationScopeKeyRing,
) -> bool:
    expected = communication_channel_endpoint_address_commitment(
        scope=scope,
        endpoint_ref=endpoint.endpoint_ref,
        address=value,
        channel=channel,
        key_id=endpoint.receipt_key_id,
        scope_keyring=scope_keyring,
    )
    return hmac.compare_digest(expected, endpoint.address_sha256)


class SlackConversationMessage(_StrictModel):
    message_ts: str = Field(alias="messageTs", pattern=r"^[0-9]{1,20}\.[0-9]{6}$")
    thread_ts: str = Field(alias="threadTs", pattern=r"^[0-9]{1,20}\.[0-9]{6}$")
    sender_kind: Literal["user", "bot"] = Field(alias="senderKind")
    sender_ref: str = Field(alias="senderRef", min_length=1, max_length=64)
    text: str = Field(max_length=2_000)
    text_sha256: str = Field(alias="textSha256", pattern=r"^[0-9a-f]{64}$")
    text_truncated: bool = Field(alias="textTruncated")


class SlackConversationThreadOutput(_StrictModel):
    schema_id: Literal["lightbulb.slack_conversation_thread.v1"] = Field(alias="schema")
    channel_id: str = Field(alias="channelId", pattern=r"^C[A-Z0-9]{1,31}$")
    thread_ts: str = Field(alias="threadTs", pattern=r"^[0-9]{1,20}\.[0-9]{6}$")
    returned_message_count: int = Field(alias="returnedMessageCount", ge=1, le=10)
    truncated: bool
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]
    messages: tuple[SlackConversationMessage, ...] = Field(min_length=1, max_length=10)

    @field_validator("messages", mode="before")
    @classmethod
    def _tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _integrity(self) -> "SlackConversationThreadOutput":
        if self.returned_message_count != len(self.messages):
            raise ValueError("Slack returned count does not match messages")
        identities = [item.message_ts for item in self.messages]
        if len(identities) != len(set(identities)):
            raise ValueError("Slack thread contains duplicate message identities")
        if self.messages[0].message_ts != self.thread_ts:
            raise ValueError("Slack first message is not the exact thread root")
        if any(item.thread_ts != self.thread_ts for item in self.messages):
            raise ValueError("Slack output mixes thread roots")
        return self


class TeamsChannelMessage(_StrictModel):
    message_id: str = Field(alias="messageId", min_length=1, max_length=512)
    thread_message_id: str = Field(alias="threadMessageId", min_length=1, max_length=512)
    turn_kind: Literal["root", "reply"] = Field(alias="turnKind")
    sender_kind: Literal["user", "application", "device"] = Field(alias="senderKind")
    sender_ref: str = Field(alias="senderRef", min_length=1, max_length=512)
    content_type: Literal["text", "html"] = Field(alias="contentType")
    content: str = Field(max_length=2_000)
    content_sha256: str = Field(alias="contentSha256", pattern=r"^[0-9a-f]{64}$")
    content_truncated: bool = Field(alias="contentTruncated")
    created_date_time: str | None = Field(
        default=None,
        alias="createdDateTime",
        min_length=1,
        max_length=128,
    )

    @field_validator("message_id", "thread_message_id", "sender_ref")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError(f"{info.field_name} is not one provider identifier")
        return value

    @field_validator("created_date_time")
    @classmethod
    def _created_at(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _timestamp(value, label="createdDateTime").isoformat().replace(
            "+00:00",
            "Z",
        )


class TeamsChannelThreadOutput(_StrictModel):
    schema_id: Literal["lightbulb.teams_channel_thread.v1"] = Field(alias="schema")
    team_id: str = Field(alias="teamId")
    channel_id: str = Field(alias="channelId", min_length=1, max_length=512)
    thread_message_id: str = Field(alias="threadMessageId", min_length=1, max_length=512)
    returned_message_count: int = Field(alias="returnedMessageCount", ge=1, le=10)
    truncated: bool
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]
    messages: tuple[TeamsChannelMessage, ...] = Field(min_length=1, max_length=10)

    @field_validator("team_id")
    @classmethod
    def _team_uuid(cls, value: str) -> str:
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("teamId must be one UUID") from exc
        canonical = str(parsed)
        if value.casefold() != canonical:
            raise ValueError("teamId must use canonical UUID text")
        return canonical

    @field_validator("channel_id", "thread_message_id")
    @classmethod
    def _provider_ids(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError(f"{info.field_name} is not one provider identifier")
        return value

    @field_validator("messages", mode="before")
    @classmethod
    def _tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _integrity(self) -> "TeamsChannelThreadOutput":
        if self.returned_message_count != len(self.messages):
            raise ValueError("Teams returned count does not match messages")
        identities = [item.message_id for item in self.messages]
        if len(identities) != len(set(identities)):
            raise ValueError("Teams thread contains duplicate message identities")
        root = self.messages[0]
        if root.turn_kind != "root" or root.message_id != self.thread_message_id:
            raise ValueError("Teams first message is not the exact thread root")
        if any(item.thread_message_id != self.thread_message_id for item in self.messages):
            raise ValueError("Teams output mixes thread roots")
        if any(item.turn_kind != "reply" for item in self.messages[1:]):
            raise ValueError("Teams output contains a second root")
        return self


class CommunicationChannelObservationStatus(str, Enum):
    NO_TURN = "no_turn"
    PROCESSED = "processed"


class CommunicationChannelObservationResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_channel_observation_result.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_OBSERVATION_RESULT_SCHEMA, alias="schema")
    platform: CommunicationChannel
    status: CommunicationChannelObservationStatus
    read_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_provenance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    read_completed_at: str
    provider_message_count: int = Field(ge=1, le=10)
    returned_message_count: int = Field(ge=1, le=10)
    outbound_observed: Literal[True] = True
    human_read_claimed: Literal[False] = False
    delivery_claimed: Literal[False] = False
    provider_event: CommunicationProviderEvent | None = None
    trace: CommunicationTraceResult | None = None

    @field_validator("read_completed_at")
    @classmethod
    def _read_time(cls, value: str) -> str:
        return _timestamp(value, label="read_completed_at").isoformat().replace(
            "+00:00",
            "Z",
        )

    @model_validator(mode="after")
    def _status_shape(self) -> "CommunicationChannelObservationResult":
        if self.platform not in {CommunicationChannel.SLACK, CommunicationChannel.TEAMS}:
            raise ValueError("channel observation requires Slack or Teams")
        if self.status == CommunicationChannelObservationStatus.NO_TURN:
            if self.provider_event is not None or self.trace is not None:
                raise ValueError("no-turn result cannot carry observed artifacts")
        elif self.provider_event is None or self.trace is None:
            raise ValueError("processed channel result requires event and trace")
        elif (
            self.trace.inbound_message.provider_event_digest
            != self.provider_event.artifact_digest
        ):
            raise ValueError("channel trace does not bind the observed event")
        return self


@dataclass(frozen=True, slots=True)
class _ChannelObservationAdapter:
    channel: CommunicationChannel
    provider_name: str
    read_tool: str
    read_evidence_domain: str
    provider_event_domain: str
    payload_ref_prefix: str
    content_ref_prefix: str
    event_ref_prefix: str

    def parse_read_route(self, value: Any) -> CommunicationChannelReadRoute:
        route = CommunicationChannelReadRoute.model_validate(value)
        if route.platform != self.channel or route.tool != self.read_tool:
            raise ValueError("channel read route crosses provider authority")
        return route

    def parse_communication_route(self, value: Any) -> CommunicationChannelWriteRoute:
        route = CommunicationChannelWriteRoute.model_validate(value)
        if route.platform != self.channel:
            raise ValueError("channel write route crosses provider authority")
        return route

    def parse_private_dispatch(self, value: Any) -> CommunicationPrivateChannelDispatch:
        private = CommunicationPrivateChannelDispatch.model_validate(value)
        if private.platform != self.channel:
            raise ValueError("private dispatch crosses provider authority")
        return private

    def parse_authority_binding(
        self,
        value: Any,
        *,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> CommunicationChannelTurnBinding:
        binding = verify_communication_artifact(
            value,
            artifact_type=CommunicationChannelTurnBinding,
            scope=scope,
            scope_keyring=scope_keyring,
        )
        if binding.platform != self.channel:
            raise ValueError("sealed binding crosses provider authority")
        return binding

    def read_arguments(
        self,
        private_dispatch: CommunicationPrivateChannelDispatch,
        max_messages: int,
    ) -> dict[str, Any]:
        if self.channel == CommunicationChannel.SLACK:
            return {
                "channel_id": private_dispatch.channel_id,
                "thread_ts": private_dispatch.root_message_id,
                "max_messages": max_messages,
            }
        return {
            "team_id": private_dispatch.team_id,
            "channel_id": private_dispatch.channel_id,
            "thread_message_id": private_dispatch.root_message_id,
            "max_messages": max_messages,
        }

    def provider_message_id(
        self,
        private_dispatch: CommunicationPrivateChannelDispatch,
    ) -> str:
        return private_dispatch.provider_message_id

    def provider_conversation_id(
        self,
        private_dispatch: CommunicationPrivateChannelDispatch,
    ) -> str:
        return private_dispatch.provider_target_digest

    def runtime_parent_message_id(
        self,
        private_dispatch: CommunicationPrivateChannelDispatch,
    ) -> str:
        return private_dispatch.root_message_id

    def provider_message_commitment(
        self,
        value: str,
        *,
        authority_binding: CommunicationChannelTurnBinding,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        if key_id != authority_binding.provider_commitment_key_id:
            raise ValueError("provider commitment key epoch differs from dispatch")
        provider_hmac = communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=self.channel,
            identifier_kind="provider_message_id",
            value=value,
        )
        return communication_channel_message_digest(provider_hmac)

    def provider_conversation_commitment(
        self,
        private_dispatch: CommunicationPrivateChannelDispatch,
        *,
        authority_binding: CommunicationChannelTurnBinding,
        **_: Any,
    ) -> str:
        if private_dispatch.authority_binding_digest != authority_binding.artifact_digest:
            raise ValueError("private dispatch does not bind the sealed channel target")
        return authority_binding.provider_target_digest

    def provider_event_commitment(
        self,
        value: str,
        *,
        authority_binding: CommunicationChannelTurnBinding,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        if key_id != authority_binding.provider_commitment_key_id:
            raise ValueError("provider event key epoch differs from dispatch")
        return communication_channel_private_identifier_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=self.channel,
            identifier_kind="provider_event_id",
            value=value,
        )

    def payload_commitment(
        self,
        value: str,
        *,
        authority_binding: CommunicationChannelTurnBinding,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        if key_id != authority_binding.provider_commitment_key_id:
            raise ValueError("payload key epoch differs from dispatch")
        return communication_channel_private_value_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=self.channel,
            value_kind="provider_payload",
            value=value,
        )

    def content_commitment(
        self,
        *,
        subject: str,
        body: str,
        authority_binding: CommunicationChannelTurnBinding,
        scope: DynamicWorkflowScope,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str:
        if subject:
            raise ValueError("channel turn content cannot acquire an email subject")
        if key_id != authority_binding.provider_commitment_key_id:
            raise ValueError("content key epoch differs from dispatch")
        return communication_channel_private_value_commitment(
            scope=scope,
            key_id=key_id,
            scope_keyring=scope_keyring,
            platform=self.channel,
            value_kind="message_content",
            value=body,
        )

    def validate_authority_binding(self, **values: Any) -> None:
        binding = values["authority_binding"]
        read = values["read_route"]
        write = values["communication_route"]
        dispatch = values["dispatch"]
        thread = values["thread"]
        sender = values["outbound_sender"]
        contact_party = values["contact_party"]
        contact = values["contact"]
        private = values["private_dispatch"]
        scope = values["scope"]
        scope_keyring = values["scope_keyring"]
        if not isinstance(binding, CommunicationChannelTurnBinding):
            raise ValueError("channel observation requires a sealed binding")
        bundle = communication_channel_private_result_commitments(
            private,
            authority_binding=binding,
            scope=scope,
            scope_keyring=scope_keyring,
        )
        expected = (
            self.channel,
            read.project_id,
            read.project_ref,
            read.connector_account_ref,
            read.tenant_connector_id,
            read.route_digest,
            read.tool,
            read.tool_version,
            write.project_id,
            write.project_ref,
            write.connector_account_ref,
            write.tenant_connector_id,
            write.route_digest,
            write.tool,
            write.tool_version,
            thread.thread_ref,
            thread.artifact_digest,
            thread.version,
            thread.state,
            thread.participant_party_refs,
            sender.artifact_digest,
            contact_party.party_ref,
            contact_party.artifact_digest,
            contact.endpoint_ref,
            contact.artifact_digest,
            dispatch.provider_message_sha256,
            dispatch.provider_thread_sha256,
            thread.provider_thread_sha256,
            dispatch.parent_message_sha256,
            thread.parent_message_sha256,
            private.body_sha256,
        )
        actual = (
            binding.platform,
            binding.project_id,
            binding.project_ref,
            binding.connector_account_ref,
            binding.tenant_connector_id,
            binding.read_route_digest,
            binding.read_tool,
            binding.read_tool_version,
            binding.project_id,
            binding.project_ref,
            binding.connector_account_ref,
            binding.tenant_connector_id,
            binding.write_route_digest,
            binding.write_tool,
            binding.write_tool_version,
            binding.thread_ref,
            binding.thread_digest,
            binding.thread_version,
            binding.thread_state,
            binding.thread_participant_party_refs,
            binding.sender_endpoint_digest,
            binding.audience_party_ref,
            binding.audience_party_digest,
            binding.audience_endpoint_ref,
            binding.audience_endpoint_digest,
            bundle.provider_message_digest,
            binding.provider_target_digest,
            binding.provider_target_digest,
            binding.parent_message_digest,
            binding.parent_message_digest,
            binding.body_sha256,
        )
        if expected != actual:
            raise ValueError("channel observation binding/route/target/audience is not exact")

    def inspect_output(
        self,
        output: Mapping[str, Any],
        *,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateChannelDispatch,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: CommunicationChannelTurnBinding,
        scope: DynamicWorkflowScope,
    ) -> CommunicationEmailObservationInspection:
        if self.channel == CommunicationChannel.SLACK:
            return self._inspect_slack(
                output,
                dispatch=dispatch,
                outbound_sender=outbound_sender,
                contact=contact,
                private_dispatch=private_dispatch,
                scope=scope,
                scope_keyring=scope_keyring,
                authority_binding=authority_binding,
            )
        return self._inspect_teams(
            output,
            dispatch=dispatch,
            outbound_sender=outbound_sender,
            contact=contact,
            private_dispatch=private_dispatch,
            scope=scope,
            scope_keyring=scope_keyring,
            authority_binding=authority_binding,
        )

    def _inspect_slack(
        self,
        output: Mapping[str, Any],
        *,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateChannelDispatch,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: CommunicationChannelTurnBinding,
    ) -> CommunicationEmailObservationInspection:
        try:
            parsed = SlackConversationThreadOutput.model_validate(output)
        except ValidationError:
            raise ValueError(
                "Slack thread failed closed schema, limit, or identity validation"
            ) from None
        if parsed.truncated:
            raise ValueError("truncated Slack thread cannot prove one exact observed turn")
        if (
            parsed.channel_id != private_dispatch.channel_id
            or parsed.thread_ts != private_dispatch.root_message_id
        ):
            raise ValueError("Slack read returned another channel/root")
        outbound = [
            item for item in parsed.messages
            if item.message_ts == private_dispatch.provider_message_id
        ]
        if len(outbound) != 1:
            raise ValueError("Slack read lacks one exact accepted outbound turn")
        sent = outbound[0]
        if (
            sent.text_truncated
            or sent.text_sha256 != authority_binding.body_sha256
            or not _matches_endpoint(
                sent.sender_ref,
                scope=scope,
                endpoint=outbound_sender,
                channel=self.channel,
                scope_keyring=scope_keyring,
            )
        ):
            raise ValueError("Slack outbound proof differs from approved sender/content")
        accepted_at = _timestamp(dispatch.accepted_at or "", label="accepted_at")
        sent_at = _slack_time(sent.message_ts)
        candidates: list[SlackConversationMessage] = []
        for item in parsed.messages:
            occurred = _slack_time(item.message_ts)
            if occurred <= sent_at or occurred <= accepted_at:
                continue
            if _matches_endpoint(
                item.sender_ref,
                scope=scope,
                endpoint=outbound_sender,
                channel=self.channel,
                scope_keyring=scope_keyring,
            ):
                continue
            if not _matches_endpoint(
                item.sender_ref,
                scope=scope,
                endpoint=contact,
                channel=self.channel,
                scope_keyring=scope_keyring,
            ):
                raise ValueError("Slack post-dispatch sender is not the sealed contact")
            if item.text_truncated or not item.text.strip():
                raise ValueError("Slack contact turn content is incomplete")
            candidates.append(item)
        if len(candidates) > 1:
            raise ValueError("multiple Slack contact turns make observation ambiguous")
        reply = None
        if candidates:
            candidate = candidates[0]
            reply = CommunicationObservedReply(
                provider_message_id=candidate.message_ts,
                occurred_at=_slack_time(candidate.message_ts),
                sender_address=candidate.sender_ref,
                recipient_address=sent.sender_ref,
                subject="",
                body=candidate.text,
                raw_payload=communication_canonical_json(
                    candidate.model_dump(mode="json", by_alias=True)
                ).decode("utf-8"),
            )
        return CommunicationEmailObservationInspection(
            output=parsed,
            provider_conversation_id=authority_binding.provider_target_digest,
            provider_message_count=len(parsed.messages),
            returned_message_count=len(parsed.messages),
            reply=reply,
            outbound_observed=True,
        )

    def _inspect_teams(
        self,
        output: Mapping[str, Any],
        *,
        dispatch: CommunicationDispatchReceipt,
        outbound_sender: CommunicationEndpointBinding,
        contact: CommunicationEndpointBinding,
        private_dispatch: CommunicationPrivateChannelDispatch,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
        authority_binding: CommunicationChannelTurnBinding,
    ) -> CommunicationEmailObservationInspection:
        try:
            parsed = TeamsChannelThreadOutput.model_validate(output)
        except ValidationError:
            raise ValueError(
                "Teams thread failed closed schema, limit, or identity validation"
            ) from None
        if parsed.truncated:
            raise ValueError("truncated Teams thread cannot prove one exact observed turn")
        if (
            parsed.team_id != private_dispatch.team_id
            or parsed.channel_id != private_dispatch.channel_id
            or parsed.thread_message_id != private_dispatch.root_message_id
        ):
            raise ValueError("Teams read returned another team/channel/root")
        outbound = [
            item for item in parsed.messages
            if item.message_id == private_dispatch.provider_message_id
        ]
        if len(outbound) != 1:
            raise ValueError("Teams read lacks one exact accepted outbound turn")
        sent = outbound[0]
        if sent.created_date_time is None:
            raise ValueError("Teams outbound proof lacks occurrence time")
        if (
            sent.turn_kind != "reply"
            or sent.content_type != "text"
            or sent.content_truncated
            or sent.content_sha256 != authority_binding.body_sha256
            or not _matches_endpoint(
                sent.sender_ref,
                scope=scope,
                endpoint=outbound_sender,
                channel=self.channel,
                scope_keyring=scope_keyring,
            )
        ):
            raise ValueError("Teams outbound proof differs from approved sender/content")
        sent_at = _timestamp(sent.created_date_time, label="createdDateTime")
        accepted_at = _timestamp(dispatch.accepted_at or "", label="accepted_at")
        candidates: list[tuple[TeamsChannelMessage, datetime]] = []
        for item in parsed.messages:
            if item.created_date_time is None:
                if item.turn_kind == "reply" and item.message_id != sent.message_id:
                    raise ValueError("Teams reply lacks occurrence time")
                continue
            occurred = _timestamp(item.created_date_time, label="createdDateTime")
            if occurred <= sent_at or occurred <= accepted_at:
                continue
            if _matches_endpoint(
                item.sender_ref,
                scope=scope,
                endpoint=outbound_sender,
                channel=self.channel,
                scope_keyring=scope_keyring,
            ):
                continue
            if not _matches_endpoint(
                item.sender_ref,
                scope=scope,
                endpoint=contact,
                channel=self.channel,
                scope_keyring=scope_keyring,
            ):
                raise ValueError("Teams post-dispatch sender is not the sealed contact")
            if item.content_type != "text" or item.content_truncated or not item.content.strip():
                raise ValueError("Teams contact turn content is incomplete or unsafe")
            candidates.append((item, occurred))
        if len(candidates) > 1:
            raise ValueError("multiple Teams contact turns make observation ambiguous")
        reply = None
        if candidates:
            candidate, occurred = candidates[0]
            reply = CommunicationObservedReply(
                provider_message_id=candidate.message_id,
                occurred_at=occurred,
                sender_address=candidate.sender_ref,
                recipient_address=sent.sender_ref,
                subject="",
                body=candidate.content,
                raw_payload=communication_canonical_json(
                    candidate.model_dump(mode="json", by_alias=True)
                ).decode("utf-8"),
            )
        return CommunicationEmailObservationInspection(
            output=parsed,
            provider_conversation_id=authority_binding.provider_target_digest,
            provider_message_count=len(parsed.messages),
            returned_message_count=len(parsed.messages),
            reply=reply,
            outbound_observed=True,
        )

    def private_inbound(self, **values: Any) -> CommunicationPrivateChannelInbound:
        return CommunicationPrivateChannelInbound(**values)

    def observation_result(
        self,
        *,
        processed: bool,
        outbound_observed: bool,
        **values: Any,
    ) -> CommunicationChannelObservationResult:
        if not outbound_observed:
            raise ValueError("channel observation lacks exact outbound proof")
        return CommunicationChannelObservationResult(
            platform=self.channel,
            status=(
                CommunicationChannelObservationStatus.PROCESSED
                if processed
                else CommunicationChannelObservationStatus.NO_TURN
            ),
            outbound_observed=True,
            **values,
        )


_SLACK_CHANNEL_OBSERVATION_ADAPTER = _ChannelObservationAdapter(
    channel=CommunicationChannel.SLACK,
    provider_name="slack",
    read_tool=SLACK_READ_THREAD_TOOL,
    read_evidence_domain=_SLACK_READ_EVIDENCE_DOMAIN,
    provider_event_domain=_SLACK_EVENT_DOMAIN,
    payload_ref_prefix="slack-payload:",
    content_ref_prefix="slack-content:",
    event_ref_prefix="slack-observation:",
)
_TEAMS_CHANNEL_OBSERVATION_ADAPTER = _ChannelObservationAdapter(
    channel=CommunicationChannel.TEAMS,
    provider_name="teams",
    read_tool=TEAMS_READ_THREAD_TOOL,
    read_evidence_domain=_TEAMS_READ_EVIDENCE_DOMAIN,
    provider_event_domain=_TEAMS_EVENT_DOMAIN,
    payload_ref_prefix="teams-payload:",
    content_ref_prefix="teams-content:",
    event_ref_prefix="teams-observation:",
)


class SlackCommunicationObserver(CommunicationEmailObserver):
    def __init__(self, **arguments: Any) -> None:
        super().__init__(**arguments, _provider="slack")


class TeamsCommunicationObserver(CommunicationEmailObserver):
    def __init__(self, **arguments: Any) -> None:
        super().__init__(**arguments, _provider="teams")


__all__ = [
    "COMMUNICATION_CHANNEL_OBSERVATION_RESULT_SCHEMA",
    "CommunicationChannelObservationResult",
    "CommunicationChannelObservationStatus",
    "SlackCommunicationObserver",
    "SlackConversationMessage",
    "SlackConversationThreadOutput",
    "TeamsChannelMessage",
    "TeamsChannelThreadOutput",
    "TeamsCommunicationObserver",
]
