"""Crash-safe, privacy-minimised finalization for governed dispatches.

The recovery stage is minted after contact authority is consumed and before
connector I/O.  It contains only sealed artifacts, commitments, and exact
route/schedule coordinates.  Raw addresses, content, and provider identifiers
remain outside the stage and enter this module only through one fresh or
recovered connector result.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationApprovalGrant,
    CommunicationArtifact,
    CommunicationChannel,
    CommunicationContactPolicyDecision,
    CommunicationContactReservation,
    CommunicationContactReservationConsumption,
    CommunicationContactReservationRequest,
    CommunicationDispatchReceipt,
    CommunicationDispatchState,
    CommunicationEndpointBinding,
    CommunicationMessageDraft,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationScopeKeyRing,
    CommunicationThreadBinding,
    CommunicationThreadState,
    communication_canonical_digest,
    communication_private_value_digest,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.communication_governance import (
    verify_communication_approval_grant,
    verify_communication_contact_policy_decision,
    verify_communication_contact_reservation,
    verify_communication_dispatch_authority,
)
from lightbulb.communication_channels import (
    SLACK_POST_TURN_TOOL,
    SLACK_READ_THREAD_TOOL,
    TEAMS_POST_TURN_TOOL,
    TEAMS_READ_THREAD_TOOL,
    CommunicationChannelReadRoute,
    CommunicationChannelTurnBinding,
    CommunicationChannelWriteRoute,
    CommunicationPrivateChannelDispatch,
    communication_channel_private_dispatch_from_effect_output,
)
from lightbulb.communication_host import CommunicationGmailPollArtifacts
from lightbulb.communication_materializer import (
    CommunicationEmailEffectProof,
    CommunicationExternalEffectState,
    CommunicationGmailRoute,
    CommunicationMaterializationResult,
    CommunicationMaterializationStatus,
    _GMAIL_MATERIALIZER_ADAPTER,
    _idempotency_key,
    _result,
)
from lightbulb.communication_observation import (
    CommunicationGmailReadRoute,
    CommunicationPrivateGmailDispatch,
)
from lightbulb.communication_outlook import (
    CommunicationOutlookRoute,
    _OUTLOOK_MATERIALIZER_ADAPTER,
)
from lightbulb.communication_outlook_host import CommunicationOutlookPollArtifacts
from lightbulb.communication_outlook_observation import (
    CommunicationOutlookReadRoute,
    CommunicationPrivateOutlookDispatch,
)
from lightbulb.communication_runtime import (
    COMMUNICATION_CRM_TRACE_BINDING_SCHEMA,
    CommunicationCrmTraceBinding,
)
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA = (
    "lightbulb.communication_dispatch_recovery_stage_request.v1"
)
COMMUNICATION_DISPATCH_RECOVERY_STAGE_SCHEMA = (
    "lightbulb.communication_dispatch_recovery_stage.v1"
)
COMMUNICATION_DISPATCH_RECOVERY_FINALIZATION_SCHEMA = (
    "lightbulb.communication_dispatch_recovery_finalization.v1"
)
COMMUNICATION_GMAIL_POLL_TEMPLATE_SCHEMA = (
    "lightbulb.communication_gmail_poll_template.v1"
)
COMMUNICATION_OUTLOOK_POLL_TEMPLATE_SCHEMA = (
    "lightbulb.communication_outlook_poll_template.v1"
)
COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA = (
    "lightbulb.communication_channel_dispatch_recovery_stage_request.v1"
)
COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_SCHEMA = (
    "lightbulb.communication_channel_dispatch_recovery_stage.v1"
)
COMMUNICATION_CHANNEL_POLL_TEMPLATE_SCHEMA = (
    "lightbulb.communication_channel_poll_template.v1"
)
COMMUNICATION_CHANNEL_POLL_ARTIFACTS_SCHEMA = (
    "lightbulb.communication_channel_poll_artifacts.v1"
)
COMMUNICATION_POLL_PLAN_SCHEMA = "lightbulb.communication_poll_plan.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


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


def _utc_text(value: str, *, label: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label).isoformat().replace("+00:00", "Z")


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(value, DynamicWorkflowScope):
        value = value.model_dump(mode="python")
    return DynamicWorkflowScope.model_validate(value)


class CommunicationPollPlan(_StrictModel):
    """Concrete bounded schedule approved before the provider effect."""

    schema_id: Literal["lightbulb.communication_poll_plan.v1"] = Field(
        default=COMMUNICATION_POLL_PLAN_SCHEMA,
        alias="schema",
    )
    job_ref: str = Field(min_length=1, max_length=200)
    artifacts_ref: str = Field(min_length=1, max_length=200)
    not_before_at: str
    deadline_at: str
    poll_interval_seconds: int = Field(ge=1, le=86_400)
    max_attempts: int = Field(ge=1, le=100)
    max_messages: int = Field(ge=1, le=10)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("job_ref", "artifacts_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        if value != value.strip() or _SAFE_REF.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @field_validator("not_before_at", "deadline_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _utc_text(value, label=info.field_name)

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"schedule_digest"},
        )

    @model_validator(mode="after")
    def _exact_schedule(self) -> "CommunicationPollPlan":
        if datetime.fromisoformat(self.deadline_at.replace("Z", "+00:00")) <= (
            datetime.fromisoformat(self.not_before_at.replace("Z", "+00:00"))
        ):
            raise ValueError("poll deadline must follow not_before_at")
        expected = communication_canonical_digest(self.digest_payload())
        if not hmac.compare_digest(self.schedule_digest, expected):
            raise ValueError("poll schedule digest does not match exact inputs")
        return self


def mint_communication_poll_plan(
    *,
    job_ref: str,
    artifacts_ref: str,
    not_before_at: datetime,
    deadline_at: datetime,
    poll_interval_seconds: int,
    max_attempts: int,
    max_messages: int,
) -> CommunicationPollPlan:
    fields: dict[str, Any] = {
        "schema": COMMUNICATION_POLL_PLAN_SCHEMA,
        "job_ref": job_ref,
        "artifacts_ref": artifacts_ref,
        "not_before_at": _utc(not_before_at, label="not_before_at")
        .isoformat()
        .replace("+00:00", "Z"),
        "deadline_at": _utc(deadline_at, label="deadline_at")
        .isoformat()
        .replace("+00:00", "Z"),
        "poll_interval_seconds": poll_interval_seconds,
        "max_attempts": max_attempts,
        "max_messages": max_messages,
    }
    fields["schedule_digest"] = communication_canonical_digest(fields)
    return CommunicationPollPlan.model_validate(fields)


class CommunicationGmailPollTemplate(_StrictModel):
    schema_id: Literal["lightbulb.communication_gmail_poll_template.v1"] = Field(
        default=COMMUNICATION_GMAIL_POLL_TEMPLATE_SCHEMA,
        alias="schema",
    )
    read_route: CommunicationGmailReadRoute
    communication_route: CommunicationGmailRoute
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding

    @model_validator(mode="after")
    def _bindings(self) -> "CommunicationGmailPollTemplate":
        _validate_poll_template(self)
        return self


class CommunicationOutlookPollTemplate(_StrictModel):
    schema_id: Literal["lightbulb.communication_outlook_poll_template.v1"] = Field(
        default=COMMUNICATION_OUTLOOK_POLL_TEMPLATE_SCHEMA,
        alias="schema",
    )
    read_route: CommunicationOutlookReadRoute
    communication_route: CommunicationOutlookRoute
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding

    @model_validator(mode="after")
    def _bindings(self) -> "CommunicationOutlookPollTemplate":
        _validate_poll_template(self)
        return self


class CommunicationChannelPollTemplate(_StrictModel):
    """Provider-neutral Slack/Teams observation seed."""

    schema_id: Literal[
        "lightbulb.communication_channel_poll_template.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_POLL_TEMPLATE_SCHEMA, alias="schema")
    read_route: CommunicationChannelReadRoute
    communication_route: CommunicationChannelWriteRoute
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding
    channel_binding: CommunicationChannelTurnBinding

    @model_validator(mode="after")
    def _bindings(self) -> "CommunicationChannelPollTemplate":
        _validate_poll_template(self)
        _validate_channel_poll_template(self)
        return self


CommunicationPollTemplate = (
    CommunicationGmailPollTemplate
    | CommunicationOutlookPollTemplate
    | CommunicationChannelPollTemplate
)


def _validate_poll_template(template: Any) -> None:
    read = template.read_route
    write = template.communication_route
    thread = template.thread
    sender = template.outbound_sender_endpoint
    party = template.contact_party
    contact = template.contact_endpoint
    crm = template.crm
    if (
        read.project_id != write.project_id
        or read.project_ref != write.project_ref
        or read.connector_account_ref != write.connector_account_ref
        or read.tenant_connector_id != write.tenant_connector_id
    ):
        raise ValueError("poll routes do not share one exact account")
    route = (write.connector_account_ref, write.route_digest)
    if any(
        item != route
        for item in (
            (thread.connector_account_ref, thread.route_digest),
            (sender.connector_account_ref, sender.route_digest),
            (contact.connector_account_ref, contact.route_digest),
        )
    ):
        raise ValueError("poll template does not bind the write route")
    if thread.state != CommunicationThreadState.AWAITING_REPLY:
        raise ValueError("poll template requires an awaiting-reply thread")
    if (
        sender.party_ref not in thread.participant_party_refs
        or party.party_ref not in thread.participant_party_refs
        or sender.party_ref == party.party_ref
        or party.party_kind != CommunicationPartyKind.CRM_CONTACT
        or contact.party_ref != party.party_ref
        or contact.party_digest != party.artifact_digest
        or crm.contact_party_ref != party.party_ref
        or crm.contact_party_digest != party.artifact_digest
        or crm.contact_endpoint_ref != contact.endpoint_ref
        or crm.contact_endpoint_digest != contact.artifact_digest
        or crm.crm_contact_ref != party.crm_contact_ref
        or crm.crm_account_ref != party.crm_account_ref
        or thread.crm_trace_binding_digest != crm.artifact_digest
    ):
        raise ValueError("poll template CRM/thread binding is inconsistent")


def _validate_channel_poll_template(template: CommunicationChannelPollTemplate) -> None:
    read = template.read_route
    write = template.communication_route
    binding = template.channel_binding
    if template.crm.schema_id != COMMUNICATION_CRM_TRACE_BINDING_SCHEMA:
        raise ValueError("channel poll template requires CRM trace binding v2")
    expected_tools = {
        CommunicationChannel.SLACK: (SLACK_POST_TURN_TOOL, SLACK_READ_THREAD_TOOL),
        CommunicationChannel.TEAMS: (TEAMS_POST_TURN_TOOL, TEAMS_READ_THREAD_TOOL),
    }.get(write.platform)
    if (
        expected_tools is None
        or read.platform != write.platform
        or binding.platform != write.platform
        or (write.tool, read.tool) != expected_tools
        or template.thread.primary_channel != write.platform
        or template.outbound_sender_endpoint.channel != write.platform
        or template.contact_endpoint.channel != write.platform
    ):
        raise ValueError("channel poll template crosses provider authority")
    if (
        binding.thread_ref != template.thread.thread_ref
        or binding.thread_digest != template.thread.artifact_digest
        or binding.thread_version != template.thread.version
        or binding.thread_state != template.thread.state
        or binding.thread_participant_party_refs
        != template.thread.participant_party_refs
        or binding.sender_endpoint_digest
        != template.outbound_sender_endpoint.artifact_digest
        or binding.audience_party_ref != template.contact_party.party_ref
        or binding.audience_party_digest != template.contact_party.artifact_digest
        or binding.audience_endpoint_ref != template.contact_endpoint.endpoint_ref
        or binding.audience_endpoint_digest
        != template.contact_endpoint.artifact_digest
        or binding.project_id != write.project_id
        or binding.project_ref != write.project_ref
        or binding.connector_account_ref != write.connector_account_ref
        or binding.tenant_connector_id != write.tenant_connector_id
        or binding.write_route_digest != write.route_digest
        or binding.read_route_digest != read.route_digest
        or binding.write_tool != write.tool
        or binding.write_tool_version != write.tool_version
        or binding.read_tool != read.tool
        or binding.read_tool_version != read.tool_version
    ):
        raise ValueError("channel poll template differs from its sealed binding")


class CommunicationDispatchRecoveryStageRequest(_StrictModel):
    """Pre-consume seed sent to one atomic durable recovery authority."""

    schema_id: Literal[
        "lightbulb.communication_dispatch_recovery_stage_request.v1"
    ] = Field(
        default=COMMUNICATION_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA,
        alias="schema",
    )
    provider: Literal["gmail", "outlook"]
    run_ref: str = Field(min_length=1, max_length=160)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=240)
    invocation_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    draft: CommunicationMessageDraft
    policy_decision: CommunicationContactPolicyDecision
    approval_grant: CommunicationApprovalGrant
    reservation_request: CommunicationContactReservationRequest
    reservation: CommunicationContactReservation
    poll_plan: CommunicationPollPlan
    poll_template: CommunicationPollTemplate

    @field_validator("run_ref", "idempotency_key")
    @classmethod
    def _visible(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @model_validator(mode="after")
    def _closed_provider_shape(self) -> "CommunicationDispatchRecoveryStageRequest":
        _validate_stage_shape(self)
        return self


class CommunicationDispatchRecoveryStage(CommunicationArtifact):
    """HMAC-sealed authority and poll plan sufficient for pure finalization."""

    schema_id: Literal["lightbulb.communication_dispatch_recovery_stage.v1"] = Field(
        default=COMMUNICATION_DISPATCH_RECOVERY_STAGE_SCHEMA,
        alias="schema",
    )
    provider: Literal["gmail", "outlook"]
    run_ref: str = Field(min_length=1, max_length=160)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=240)
    invocation_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    draft: CommunicationMessageDraft
    policy_decision: CommunicationContactPolicyDecision
    approval_grant: CommunicationApprovalGrant
    reservation_request: CommunicationContactReservationRequest
    reservation: CommunicationContactReservation
    reservation_consumption: CommunicationContactReservationConsumption
    poll_plan: CommunicationPollPlan
    poll_template: CommunicationPollTemplate

    @field_validator("run_ref", "idempotency_key")
    @classmethod
    def _visible(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @model_validator(mode="after")
    def _closed_provider_shape(self) -> "CommunicationDispatchRecoveryStage":
        _validate_stage_shape(self)
        return self

    def as_request(self) -> CommunicationDispatchRecoveryStageRequest:
        return CommunicationDispatchRecoveryStageRequest.model_validate(
            self.model_dump(
                mode="python",
                by_alias=True,
                exclude={
                    "reservation_consumption",
                    "receipt_key_id",
                    "exact_scope_digest",
                    "artifact_digest",
                    "artifact_hmac",
                },
            )
            | {"schema": COMMUNICATION_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA}
        )


class CommunicationChannelDispatchRecoveryStageRequest(_StrictModel):
    """Closed pre-consume seed for one Slack or Teams channel turn."""

    schema_id: Literal[
        "lightbulb.communication_channel_dispatch_recovery_stage_request.v1"
    ] = Field(
        default=COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA,
        alias="schema",
    )
    provider: Literal["slack", "teams"]
    run_ref: str = Field(min_length=1, max_length=160)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=240)
    invocation_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    draft: CommunicationMessageDraft
    policy_decision: CommunicationContactPolicyDecision
    approval_grant: CommunicationApprovalGrant
    reservation_request: CommunicationContactReservationRequest
    reservation: CommunicationContactReservation
    poll_plan: CommunicationPollPlan
    poll_template: CommunicationChannelPollTemplate

    @field_validator("run_ref", "idempotency_key")
    @classmethod
    def _visible(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @model_validator(mode="after")
    def _closed_provider_shape(
        self,
    ) -> "CommunicationChannelDispatchRecoveryStageRequest":
        _validate_stage_shape(self)
        return self


class CommunicationChannelDispatchRecoveryStage(CommunicationArtifact):
    """HMAC-sealed channel authority sufficient for pure finalization."""

    schema_id: Literal[
        "lightbulb.communication_channel_dispatch_recovery_stage.v1"
    ] = Field(
        default=COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_SCHEMA,
        alias="schema",
    )
    provider: Literal["slack", "teams"]
    run_ref: str = Field(min_length=1, max_length=160)
    schedule_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=240)
    invocation_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    draft: CommunicationMessageDraft
    policy_decision: CommunicationContactPolicyDecision
    approval_grant: CommunicationApprovalGrant
    reservation_request: CommunicationContactReservationRequest
    reservation: CommunicationContactReservation
    reservation_consumption: CommunicationContactReservationConsumption
    poll_plan: CommunicationPollPlan
    poll_template: CommunicationChannelPollTemplate

    @field_validator("run_ref", "idempotency_key")
    @classmethod
    def _visible(cls, value: str, info: Any) -> str:
        if value != value.strip() or any(ord(character) < 33 for character in value):
            raise ValueError(f"{info.field_name} contains unsupported characters")
        return value

    @model_validator(mode="after")
    def _closed_provider_shape(
        self,
    ) -> "CommunicationChannelDispatchRecoveryStage":
        _validate_stage_shape(self)
        return self

    def as_request(self) -> CommunicationChannelDispatchRecoveryStageRequest:
        return CommunicationChannelDispatchRecoveryStageRequest.model_validate(
            self.model_dump(
                mode="python",
                by_alias=True,
                exclude={
                    "reservation_consumption",
                    "receipt_key_id",
                    "exact_scope_digest",
                    "artifact_digest",
                    "artifact_hmac",
                },
            )
            | {"schema": COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA}
        )


CommunicationRecoveryStageRequest = (
    CommunicationDispatchRecoveryStageRequest
    | CommunicationChannelDispatchRecoveryStageRequest
)
CommunicationRecoveryStage = (
    CommunicationDispatchRecoveryStage | CommunicationChannelDispatchRecoveryStage
)


def _validate_stage_shape(stage: Any) -> None:
    template = stage.poll_template
    write = template.communication_route
    if isinstance(template, CommunicationGmailPollTemplate):
        expected_provider, expected_tool = "gmail", "gmail.send_email"
    elif isinstance(template, CommunicationOutlookPollTemplate):
        expected_provider, expected_tool = "outlook", "microsoft.reply_email"
    else:
        expected_provider = template.communication_route.platform.value
        expected_tool = template.communication_route.tool
    if stage.provider != expected_provider or write.tool != expected_tool:
        raise ValueError("recovery stage crosses provider authority")
    if (
        stage.schedule_digest != stage.poll_plan.schedule_digest
        or stage.schedule_digest != stage.approval_grant.schedule_digest
    ):
        raise ValueError("recovery stage schedule is not exact")
    if stage.run_ref != stage.reservation_request.run_ref:
        raise ValueError("recovery stage run does not match reservation authority")
    expected_key = _idempotency_key(
        provider_name=stage.provider,
        draft_digest=stage.draft.artifact_digest,
        thread_ref=template.thread.thread_ref,
        route_digest=write.route_digest,
        schedule_digest=stage.schedule_digest,
        run_ref=stage.run_ref,
    )
    if not hmac.compare_digest(stage.idempotency_key, expected_key):
        raise ValueError("recovery stage idempotency identity is invalid")
    if (
        stage.draft.thread_ref != template.thread.thread_ref
        or stage.draft.thread_digest != template.thread.artifact_digest
        or stage.draft.thread_version != template.thread.version
        or stage.draft.thread_state != template.thread.state
        or stage.draft.thread_participant_party_refs
        != template.thread.participant_party_refs
        or stage.draft.parent_message_sha256
        != template.thread.parent_message_sha256
        or stage.draft.sender_endpoint_ref
        != template.outbound_sender_endpoint.endpoint_ref
        or stage.draft.sender_endpoint_digest
        != template.outbound_sender_endpoint.artifact_digest
        or stage.draft.recipient_endpoint_refs
        != (template.contact_endpoint.endpoint_ref,)
        or stage.draft.recipient_endpoint_digests
        != (template.contact_endpoint.artifact_digest,)
    ):
        raise ValueError("recovery stage draft does not bind the poll template")
    if isinstance(template, CommunicationChannelPollTemplate):
        binding = template.channel_binding
        if (
            binding.draft_digest != stage.draft.artifact_digest
            or binding.body_sha256 != stage.draft.body_sha256
            or binding.parent_message_digest != stage.draft.parent_message_sha256
        ):
            raise ValueError("channel recovery stage differs from its sealed binding")


class CommunicationDispatchRecoveryAuthority(Protocol):
    """Atomic production seam for reservation consumption plus stage custody."""

    contact_token_key_id: str

    def consume_and_stage(
        self,
        *,
        request: CommunicationRecoveryStageRequest,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
        consumed_at: datetime,
    ) -> CommunicationRecoveryStage: ...


def _parse_stage_request(
    value: CommunicationRecoveryStageRequest | Mapping[str, Any],
) -> CommunicationRecoveryStageRequest:
    if isinstance(
        value,
        (
            CommunicationDispatchRecoveryStageRequest,
            CommunicationChannelDispatchRecoveryStageRequest,
        ),
    ):
        return value
    schema = value.get("schema") if isinstance(value, Mapping) else None
    request_type = (
        CommunicationChannelDispatchRecoveryStageRequest
        if schema == COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA
        else CommunicationDispatchRecoveryStageRequest
    )
    return request_type.model_validate(value)


def _parse_stage(
    value: CommunicationRecoveryStage | Mapping[str, Any],
) -> CommunicationRecoveryStage:
    if isinstance(
        value,
        (CommunicationDispatchRecoveryStage, CommunicationChannelDispatchRecoveryStage),
    ):
        return value
    schema = value.get("schema") if isinstance(value, Mapping) else None
    stage_type = (
        CommunicationChannelDispatchRecoveryStage
        if schema == COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_SCHEMA
        else CommunicationDispatchRecoveryStage
    )
    return stage_type.model_validate(value)


def validate_communication_dispatch_recovery_stage_request(
    value: CommunicationRecoveryStageRequest | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    at: datetime,
) -> CommunicationRecoveryStageRequest:
    """Verify every sealed seed component before reservation consumption."""

    request = _parse_stage_request(value)
    workflow_scope = _workflow_scope(scope)
    timestamp = _utc(at, label="at")
    template = request.poll_template
    write = template.communication_route
    draft = verify_communication_artifact(
        request.draft,
        artifact_type=CommunicationMessageDraft,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    policy = verify_communication_contact_policy_decision(
        request.policy_decision,
        draft=draft,
        at=timestamp,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    approval = verify_communication_approval_grant(
        request.approval_grant,
        draft=draft,
        policy_decision=policy,
        connector_account_ref=write.connector_account_ref,
        route_digest=write.route_digest,
        schedule_digest=request.schedule_digest,
        at=timestamp,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    trusted_request = verify_communication_artifact(
        request.reservation_request,
        artifact_type=CommunicationContactReservationRequest,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    reservation = verify_communication_contact_reservation(
        request.reservation,
        request=trusted_request,
        at=timestamp,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    _verify_poll_template_artifacts(template, workflow_scope, scope_keyring)
    return request.model_copy(
        update={
            "draft": draft,
            "policy_decision": policy,
            "approval_grant": approval,
            "reservation_request": trusted_request,
            "reservation": reservation,
        }
    )


def mint_communication_dispatch_recovery_stage(
    request: CommunicationRecoveryStageRequest | Mapping[str, Any],
    *,
    reservation_consumption: CommunicationContactReservationConsumption
    | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationRecoveryStage:
    """Mint the final stage after an authority atomically consumes its slot."""

    seed = _parse_stage_request(request)
    consumption = CommunicationContactReservationConsumption.model_validate(
        reservation_consumption
    )
    payload = seed.model_dump(mode="python", by_alias=True)
    payload.pop("schema", None)
    payload["reservation_consumption"] = consumption
    stage_type: type[CommunicationArtifact] = (
        CommunicationChannelDispatchRecoveryStage
        if isinstance(seed, CommunicationChannelDispatchRecoveryStageRequest)
        else CommunicationDispatchRecoveryStage
    )
    return mint_communication_artifact(
        stage_type,
        payload,
        scope=scope,
        scope_keyring=scope_keyring,
        scope_key_id=seed.draft.receipt_key_id,
    )


def verify_communication_dispatch_recovery_stage(
    value: CommunicationRecoveryStage | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    expected_request: CommunicationRecoveryStageRequest
    | Mapping[str, Any]
    | None = None,
) -> CommunicationRecoveryStage:
    """Verify a stage at its consumed time, not at recovery wall-clock time."""

    workflow_scope = _workflow_scope(scope)
    candidate = _parse_stage(value)
    stage = verify_communication_artifact(
        candidate,
        artifact_type=type(candidate),
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if expected_request is not None:
        expected = _parse_stage_request(expected_request)
        if stage.as_request() != expected:
            raise ValueError("recovery stage differs from the exact staged request")
    consumed_at = datetime.fromisoformat(
        stage.reservation_consumption.consumed_at.replace("Z", "+00:00")
    )
    verify_communication_dispatch_authority(
        draft=stage.draft,
        policy_decision=stage.policy_decision,
        approval_grant=stage.approval_grant,
        reservation_request=stage.reservation_request,
        reservation=stage.reservation,
        reservation_consumption=stage.reservation_consumption,
        connector_account_ref=stage.poll_template.communication_route.connector_account_ref,
        route_digest=stage.poll_template.communication_route.route_digest,
        schedule_digest=stage.schedule_digest,
        at=consumed_at,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    _verify_poll_template_artifacts(stage.poll_template, workflow_scope, scope_keyring)
    return stage


def _verify_poll_template_artifacts(
    template: CommunicationPollTemplate,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> None:
    if template.communication_route.project_ref != scope.project_ref:
        raise ValueError("poll template crosses project scope")
    artifacts: list[tuple[CommunicationArtifact, type[CommunicationArtifact]]] = [
        (template.thread, CommunicationThreadBinding),
        (template.outbound_sender_endpoint, CommunicationEndpointBinding),
        (template.contact_party, CommunicationPartyRef),
        (template.contact_endpoint, CommunicationEndpointBinding),
        (template.crm, CommunicationCrmTraceBinding),
    ]
    if isinstance(template, CommunicationChannelPollTemplate):
        artifacts.append((template.channel_binding, CommunicationChannelTurnBinding))
    for value, artifact_type in artifacts:
        verify_communication_artifact(
            value,
            artifact_type=artifact_type,
            scope=scope,
            scope_keyring=scope_keyring,
        )


class CommunicationChannelPollArtifacts(_StrictModel):
    """Complete encrypted-at-rest Slack/Teams observation input."""

    schema_id: Literal[
        "lightbulb.communication_channel_poll_artifacts.v1"
    ] = Field(default=COMMUNICATION_CHANNEL_POLL_ARTIFACTS_SCHEMA, alias="schema")
    read_route: CommunicationChannelReadRoute
    communication_route: CommunicationChannelWriteRoute
    materialization: CommunicationMaterializationResult
    thread: CommunicationThreadBinding
    outbound_sender_endpoint: CommunicationEndpointBinding
    contact_party: CommunicationPartyRef
    contact_endpoint: CommunicationEndpointBinding
    crm: CommunicationCrmTraceBinding
    private_dispatch: CommunicationPrivateChannelDispatch
    channel_binding: CommunicationChannelTurnBinding

    @model_validator(mode="after")
    def _bindings(self) -> "CommunicationChannelPollArtifacts":
        _validate_channel_poll_template(
            CommunicationChannelPollTemplate(
                read_route=self.read_route,
                communication_route=self.communication_route,
                thread=self.thread,
                outbound_sender_endpoint=self.outbound_sender_endpoint,
                contact_party=self.contact_party,
                contact_endpoint=self.contact_endpoint,
                crm=self.crm,
                channel_binding=self.channel_binding,
            )
        )
        return self


class CommunicationDispatchRecoveryFinalization(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_dispatch_recovery_finalization.v1"
    ] = Field(
        default=COMMUNICATION_DISPATCH_RECOVERY_FINALIZATION_SCHEMA,
        alias="schema",
    )
    stage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    materialization: CommunicationMaterializationResult
    poll_artifacts: (
        CommunicationGmailPollArtifacts
        | CommunicationOutlookPollArtifacts
        | CommunicationChannelPollArtifacts
        | None
    ) = None

    @model_validator(mode="after")
    def _terminal_shape(self) -> "CommunicationDispatchRecoveryFinalization":
        successful = self.materialization.status in {
            CommunicationMaterializationStatus.ACCEPTED,
            CommunicationMaterializationStatus.COMPLETED,
        }
        if successful != (self.poll_artifacts is not None):
            raise ValueError("only a finalized dispatch may carry poll artifacts")
        return self


def build_communication_dispatch_recovery_stage_request(
    *,
    provider: Literal["gmail", "outlook", "slack", "teams"],
    run_ref: str,
    schedule_digest: str,
    idempotency_key: str,
    invocation_request_digest: str,
    draft: CommunicationMessageDraft,
    policy_decision: CommunicationContactPolicyDecision,
    approval_grant: CommunicationApprovalGrant,
    reservation_request: CommunicationContactReservationRequest,
    reservation: CommunicationContactReservation,
    poll_plan: CommunicationPollPlan | Mapping[str, Any],
    poll_template: CommunicationPollTemplate | Mapping[str, Any],
) -> CommunicationRecoveryStageRequest:
    request_type: type[_StrictModel] = (
        CommunicationChannelDispatchRecoveryStageRequest
        if provider in {"slack", "teams"}
        else CommunicationDispatchRecoveryStageRequest
    )
    return request_type(
        provider=provider,
        run_ref=run_ref,
        schedule_digest=schedule_digest,
        idempotency_key=idempotency_key,
        invocation_request_digest=invocation_request_digest,
        draft=draft,
        policy_decision=policy_decision,
        approval_grant=approval_grant,
        reservation_request=reservation_request,
        reservation=reservation,
        poll_plan=CommunicationPollPlan.model_validate(poll_plan),
        poll_template=_parse_poll_template(provider, poll_template),
    )


def _parse_poll_template(
    provider: str,
    value: CommunicationPollTemplate | Mapping[str, Any],
) -> CommunicationPollTemplate:
    template_type = {
        "gmail": CommunicationGmailPollTemplate,
        "outlook": CommunicationOutlookPollTemplate,
        "slack": CommunicationChannelPollTemplate,
        "teams": CommunicationChannelPollTemplate,
    }.get(provider)
    if template_type is None:
        raise ValueError("recovery provider is not SDK-reviewed")
    return template_type.model_validate(value)


def finalize_recovered_communication_dispatch(
    *,
    stage: CommunicationRecoveryStage | Mapping[str, Any],
    connector_result: ConnectorExecutionResult | Mapping[str, Any],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationDispatchRecoveryFinalization:
    """Purely finalize one recovered governed effect without new I/O."""

    trusted = verify_communication_dispatch_recovery_stage(
        stage,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    result = ConnectorExecutionResult.model_validate(connector_result)
    workflow_scope = _workflow_scope(scope)
    if isinstance(trusted, CommunicationChannelDispatchRecoveryStage):
        materialized, private = _finalize_channel_result(
            stage=trusted,
            connector_result=result,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        poll_artifacts: (
            CommunicationGmailPollArtifacts
            | CommunicationOutlookPollArtifacts
            | CommunicationChannelPollArtifacts
            | None
        ) = None
        if private is not None:
            template = trusted.poll_template
            poll_artifacts = CommunicationChannelPollArtifacts(
                read_route=template.read_route,
                communication_route=template.communication_route,
                materialization=materialized,
                thread=template.thread,
                outbound_sender_endpoint=template.outbound_sender_endpoint,
                contact_party=template.contact_party,
                contact_endpoint=template.contact_endpoint,
                crm=template.crm,
                private_dispatch=private,
                channel_binding=template.channel_binding,
            )
    else:
        materialized, proof = _finalize_email_result(
            provider=trusted.provider,
            route=trusted.poll_template.communication_route,
            thread=trusted.poll_template.thread,
            draft=trusted.draft,
            policy=trusted.policy_decision,
            approval=trusted.approval_grant,
            consumption=trusted.reservation_consumption,
            request_digest=trusted.invocation_request_digest,
            run_ref=trusted.run_ref,
            idempotency_key=trusted.idempotency_key,
            connector_result=result,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        poll_artifacts = None
    if not isinstance(trusted, CommunicationChannelDispatchRecoveryStage) and proof is not None:
        template = trusted.poll_template
        common = {
            "read_route": template.read_route,
            "communication_route": template.communication_route,
            "materialization": materialized,
            "thread": template.thread,
            "outbound_sender_endpoint": template.outbound_sender_endpoint,
            "contact_party": template.contact_party,
            "contact_endpoint": template.contact_endpoint,
            "crm": template.crm,
        }
        if trusted.provider == "gmail":
            private = CommunicationPrivateGmailDispatch(
                provider_message_id=proof.provider_message_id,
                provider_thread_id=proof.provider_conversation_id,
            )
            poll_artifacts = CommunicationGmailPollArtifacts(
                **common,
                private_dispatch=private,
            )
            _validate_final_gmail_poll(poll_artifacts, workflow_scope, scope_keyring)
        else:
            private = CommunicationPrivateOutlookDispatch(
                provider_message_id=proof.provider_message_id,
                provider_conversation_id=proof.provider_conversation_id,
            )
            poll_artifacts = CommunicationOutlookPollArtifacts(
                **common,
                private_dispatch=private,
            )
    return CommunicationDispatchRecoveryFinalization(
        stage_digest=trusted.artifact_digest,
        materialization=materialized,
        poll_artifacts=poll_artifacts,
    )


def finalize_live_communication_dispatch(
    *,
    provider: Literal["gmail", "outlook"],
    route: CommunicationGmailRoute | CommunicationOutlookRoute,
    thread: CommunicationThreadBinding,
    draft: CommunicationMessageDraft,
    policy_decision: CommunicationContactPolicyDecision,
    approval_grant: CommunicationApprovalGrant,
    reservation_consumption: CommunicationContactReservationConsumption,
    invocation_request_digest: str,
    run_ref: str,
    idempotency_key: str,
    connector_result: ConnectorExecutionResult,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> CommunicationMaterializationResult:
    """Internal live-path entry to the exact same pure finalization core."""

    materialized, _ = _finalize_email_result(
        provider=provider,
        route=route,
        thread=thread,
        draft=draft,
        policy=policy_decision,
        approval=approval_grant,
        consumption=reservation_consumption,
        request_digest=invocation_request_digest,
        run_ref=run_ref,
        idempotency_key=idempotency_key,
        connector_result=connector_result,
        scope=scope,
        scope_keyring=scope_keyring,
    )
    return materialized


def _finalize_channel_result(
    *,
    stage: CommunicationChannelDispatchRecoveryStage,
    connector_result: ConnectorExecutionResult,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> tuple[CommunicationMaterializationResult, CommunicationPrivateChannelDispatch | None]:
    template = stage.poll_template
    route = template.communication_route
    binding = template.channel_binding
    failure = {
        "draft": stage.draft,
        "run_ref": stage.run_ref,
        "idempotency_key": stage.idempotency_key,
        "effect_state": CommunicationExternalEffectState.UNKNOWN,
        "connector_status": connector_result.status,
        "approval_ref": stage.approval_grant.approval_ref,
        "approval_receipt_digest": stage.approval_grant.authority_evidence_digest,
    }
    if connector_result.tool != route.tool:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="connector_tool_mismatch",
                summary="Connector result named a different Tool.",
                **failure,
            ),
            None,
        )
    if connector_result.status != ConnectorExecutionStatus.COMPLETED:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=(
                    connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
                ),
                connector_error_code=(
                    connector_result.error_code or "connector_not_completed"
                ),
                summary="Connector did not return a trustworthy completed effect.",
                **failure,
            ),
            None,
        )
    if (
        connector_result.error_kind is not None
        or connector_result.error_code is not None
        or connector_result.retryable
    ):
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=(
                    connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
                ),
                connector_error_code=(
                    connector_result.error_code or "contradictory_completion"
                ),
                summary="Connector completion carried contradictory failure metadata.",
                **failure,
            ),
            None,
        )
    provenance = connector_result.provenance
    if provenance is None:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="execution_provenance_missing",
                summary="Connector completion lacked immutable execution provenance.",
                **failure,
            ),
            None,
        )
    if (
        provenance.tool != route.tool
        or provenance.tool_version != route.tool_version
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != route.connector_account_ref
        or provenance.tenant_connector_id != route.tenant_connector_id
        or provenance.project_id != route.project_id
        or provenance.route_digest != route.route_digest
        or provenance.approval_ref != stage.approval_grant.approval_ref
        or provenance.approval_receipt_digest
        != stage.approval_grant.authority_evidence_digest
        or provenance.request_digest != stage.invocation_request_digest
    ):
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                connector_error_code="execution_provenance_mismatch",
                summary="Connector provenance did not match Tool, route, account, project, request, and approval.",
                **failure,
            ),
            None,
        )
    completed_at = datetime.fromisoformat(
        provenance.completed_at.replace("Z", "+00:00")
    )
    consumed_at = datetime.fromisoformat(
        stage.reservation_consumption.consumed_at.replace("Z", "+00:00")
    )
    if completed_at < consumed_at:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="completion_time_invalid",
                summary="Connector completion predates contact-reservation consumption.",
                **failure,
            ),
            None,
        )
    try:
        private, commitments = communication_channel_private_dispatch_from_effect_output(
            connector_result.output,
            authority_binding=binding,
            scope=scope,
            scope_keyring=scope_keyring,
        )
    except ValueError:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="provider_effect_proof_invalid",
                summary="Connector output did not prove the exact provider channel turn.",
                **failure,
            ),
            None,
        )
    provenance_digest = communication_canonical_digest(
        provenance.model_dump(mode="json", by_alias=True)
    )
    receipt = mint_communication_artifact(
        CommunicationDispatchReceipt,
        {
            "dispatch_ref": f"dispatch:{stage.idempotency_key[-48:]}",
            "draft_digest": stage.draft.artifact_digest,
            "policy_decision_digest": stage.policy_decision.artifact_digest,
            "approval_digest": stage.approval_grant.artifact_digest,
            "reservation_consumption_digest": (
                stage.reservation_consumption.artifact_digest
            ),
            "thread_ref": template.thread.thread_ref,
            "thread_digest": template.thread.artifact_digest,
            "thread_version": template.thread.version,
            "thread_state": template.thread.state,
            "thread_participant_party_refs": (
                template.thread.participant_party_refs
            ),
            "parent_message_sha256": template.thread.parent_message_sha256,
            "purpose": stage.draft.purpose,
            "channel": binding.platform,
            "connector_account_ref": route.connector_account_ref,
            "route_digest": route.route_digest,
            "connector_execution_provenance_digest": provenance_digest,
            "connector_effect_receipt_digest": provenance.receipt_digest,
            "provider_message_sha256": commitments.provider_message_digest,
            "provider_thread_sha256": binding.provider_target_digest,
            "state": CommunicationDispatchState.ACCEPTED,
            "attempted_at": stage.reservation_consumption.consumed_at,
            "accepted_at": provenance.completed_at,
        },
        scope=scope,
        scope_keyring=scope_keyring,
        scope_key_id=stage.draft.receipt_key_id,
    )
    return (
        _result(
            status=CommunicationMaterializationStatus.ACCEPTED,
            draft=stage.draft,
            run_ref=stage.run_ref,
            idempotency_key=stage.idempotency_key,
            effect_state=CommunicationExternalEffectState.ACCEPTED,
            connector_status=connector_result.status,
            approval_ref=stage.approval_grant.approval_ref,
            approval_receipt_digest=stage.approval_grant.authority_evidence_digest,
            receipt=receipt,
            summary=(
                "Provider accepted; awaiting fresh observation for one approved, "
                f"exact-route {stage.provider} CRM turn and minted its receipt."
            ),
        ),
        private,
    )


def _finalize_email_result(
    *,
    provider: str,
    route: Any,
    thread: CommunicationThreadBinding,
    draft: CommunicationMessageDraft,
    policy: CommunicationContactPolicyDecision,
    approval: CommunicationApprovalGrant,
    consumption: CommunicationContactReservationConsumption,
    request_digest: str,
    run_ref: str,
    idempotency_key: str,
    connector_result: ConnectorExecutionResult,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> tuple[CommunicationMaterializationResult, CommunicationEmailEffectProof | None]:
    adapter = (
        _GMAIL_MATERIALIZER_ADAPTER
        if provider == "gmail"
        else _OUTLOOK_MATERIALIZER_ADAPTER
    )
    failure = {
        "draft": draft,
        "run_ref": run_ref,
        "idempotency_key": idempotency_key,
        "effect_state": CommunicationExternalEffectState.UNKNOWN,
        "connector_status": connector_result.status,
        "approval_ref": approval.approval_ref,
        "approval_receipt_digest": approval.authority_evidence_digest,
    }
    if connector_result.tool != adapter.tool:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="connector_tool_mismatch",
                summary="Connector result named a different Tool.",
                **failure,
            ),
            None,
        )
    if connector_result.status != ConnectorExecutionStatus.COMPLETED:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=(
                    connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
                ),
                connector_error_code=(
                    connector_result.error_code or "connector_not_completed"
                ),
                summary="Connector did not return a trustworthy completed effect.",
                **failure,
            ),
            None,
        )
    if (
        connector_result.error_kind is not None
        or connector_result.error_code is not None
        or connector_result.retryable
    ):
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=(
                    connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
                ),
                connector_error_code=(
                    connector_result.error_code or "contradictory_completion"
                ),
                summary="Connector completion carried contradictory failure metadata.",
                **failure,
            ),
            None,
        )
    provenance = connector_result.provenance
    if provenance is None:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="execution_provenance_missing",
                summary="Connector completion lacked immutable execution provenance.",
                **failure,
            ),
            None,
        )
    if (
        provenance.tool != adapter.tool
        or provenance.tool_version != route.tool_version
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != route.connector_account_ref
        or provenance.tenant_connector_id != route.tenant_connector_id
        or provenance.project_id != route.project_id
        or provenance.route_digest != route.route_digest
        or provenance.approval_ref != approval.approval_ref
        or provenance.approval_receipt_digest != approval.authority_evidence_digest
        or provenance.request_digest != request_digest
    ):
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                connector_error_code="execution_provenance_mismatch",
                summary="Connector provenance did not match Tool, route, account, project, request, and approval.",
                **failure,
            ),
            None,
        )
    completed_at = datetime.fromisoformat(
        provenance.completed_at.replace("Z", "+00:00")
    )
    consumed_at = datetime.fromisoformat(
        consumption.consumed_at.replace("Z", "+00:00")
    )
    if completed_at < consumed_at:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="completion_time_invalid",
                summary="Connector completion predates contact-reservation consumption.",
                **failure,
            ),
            None,
        )
    try:
        proof = _validate_recovered_effect_output(
            provider,
            connector_result.output,
            thread,
        )
    except ValueError:
        return (
            _result(
                status=CommunicationMaterializationStatus.FAILED,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="provider_effect_proof_invalid",
                summary="Connector output did not prove the exact provider message and conversation.",
                **failure,
            ),
            None,
        )
    provenance_digest = communication_canonical_digest(
        provenance.model_dump(mode="json", by_alias=True)
    )
    receipt = mint_communication_artifact(
        CommunicationDispatchReceipt,
        {
            "dispatch_ref": f"dispatch:{idempotency_key[-48:]}",
            "draft_digest": draft.artifact_digest,
            "policy_decision_digest": policy.artifact_digest,
            "approval_digest": approval.artifact_digest,
            "reservation_consumption_digest": consumption.artifact_digest,
            "thread_ref": thread.thread_ref,
            "thread_digest": thread.artifact_digest,
            "thread_version": thread.version,
            "thread_state": thread.state,
            "thread_participant_party_refs": thread.participant_party_refs,
            "parent_message_sha256": thread.parent_message_sha256,
            "purpose": draft.purpose,
            "channel": CommunicationChannel.EMAIL,
            "connector_account_ref": route.connector_account_ref,
            "route_digest": route.route_digest,
            "connector_execution_provenance_digest": provenance_digest,
            "connector_effect_receipt_digest": provenance.receipt_digest,
            "provider_message_sha256": communication_private_value_digest(
                proof.provider_message_id
            ),
            "provider_thread_sha256": communication_private_value_digest(
                proof.provider_conversation_id
            ),
            "state": CommunicationDispatchState.ACCEPTED,
            "attempted_at": consumption.consumed_at,
            "accepted_at": provenance.completed_at,
        },
        scope=scope,
        scope_keyring=scope_keyring,
        scope_key_id=draft.receipt_key_id,
    )
    status = (
        CommunicationMaterializationStatus.COMPLETED
        if proof.completed
        else CommunicationMaterializationStatus.ACCEPTED
    )
    effect = (
        CommunicationExternalEffectState.COMPLETED
        if proof.completed
        else CommunicationExternalEffectState.ACCEPTED
    )
    return (
        _result(
            status=status,
            draft=draft,
            run_ref=run_ref,
            idempotency_key=idempotency_key,
            effect_state=effect,
            connector_status=connector_result.status,
            approval_ref=approval.approval_ref,
            approval_receipt_digest=approval.authority_evidence_digest,
            receipt=receipt,
            summary=(
                ("Completed" if proof.completed else "Provider accepted; awaiting fresh observation for")
                + " one approved, exact-route "
                + f"{provider} CRM turn and minted its receipt."
            ),
        ),
        proof,
    )


def _validate_recovered_effect_output(
    provider: str,
    output: Mapping[str, Any],
    thread: CommunicationThreadBinding,
) -> CommunicationEmailEffectProof:
    if not isinstance(output, Mapping):
        raise ValueError("provider output must be an object")
    if provider == "gmail":
        if not set(output).issubset({"id", "threadId", "labelIds"}):
            raise ValueError("Gmail effect output contains an unreviewed field")
        message = output.get("id")
        conversation = output.get("threadId")
        completed = True
    else:
        required = {
            "schema",
            "id",
            "conversationId",
            "internetMessageId",
            "parentInternetMessageId",
            "accepted",
            "sentItemsObserved",
        }
        if set(output) != required or output.get("schema") != "lightbulb.outlook_reply.v1":
            raise ValueError("Outlook effect output is not exact")
        message = output.get("id")
        conversation = output.get("conversationId")
        parent = output.get("parentInternetMessageId")
        if (
            output.get("accepted") is not True
            or not isinstance(output.get("sentItemsObserved"), bool)
            or not isinstance(parent, str)
            or thread.parent_message_sha256 is None
            or not hmac.compare_digest(
                communication_private_value_digest(parent),
                thread.parent_message_sha256,
            )
        ):
            raise ValueError("Outlook effect output does not bind the exact parent")
        completed = bool(output["sentItemsObserved"])
    if (
        not isinstance(message, str)
        or not message
        or len(message) > 512
        or message != message.strip()
        or not isinstance(conversation, str)
        or not conversation
        or len(conversation) > 512
        or conversation != conversation.strip()
        or thread.provider_thread_sha256 is None
        or not hmac.compare_digest(
            communication_private_value_digest(conversation),
            thread.provider_thread_sha256,
        )
    ):
        raise ValueError("provider effect output does not bind the exact conversation")
    return CommunicationEmailEffectProof(
        provider_message_id=message,
        provider_conversation_id=conversation,
        completed=completed,
    )


def _validate_final_gmail_poll(
    artifacts: CommunicationGmailPollArtifacts,
    scope: DynamicWorkflowScope,
    keyring: CommunicationScopeKeyRing,
) -> None:
    materialized = artifacts.materialization
    if (
        materialized.status != CommunicationMaterializationStatus.COMPLETED
        or materialized.receipt is None
    ):
        raise ValueError("Gmail polling requires a completed dispatch")
    dispatch = verify_communication_artifact(
        materialized.receipt,
        artifact_type=CommunicationDispatchReceipt,
        scope=scope,
        scope_keyring=keyring,
    )
    if (
        dispatch.provider_message_sha256
        != communication_private_value_digest(
            artifacts.private_dispatch.provider_message_id
        )
        or dispatch.provider_thread_sha256
        != communication_private_value_digest(
            artifacts.private_dispatch.provider_thread_id
        )
    ):
        raise ValueError("Gmail poll private dispatch does not match receipt")


__all__ = [
    "COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA",
    "COMMUNICATION_CHANNEL_DISPATCH_RECOVERY_STAGE_SCHEMA",
    "COMMUNICATION_CHANNEL_POLL_ARTIFACTS_SCHEMA",
    "COMMUNICATION_CHANNEL_POLL_TEMPLATE_SCHEMA",
    "COMMUNICATION_DISPATCH_RECOVERY_FINALIZATION_SCHEMA",
    "COMMUNICATION_DISPATCH_RECOVERY_STAGE_REQUEST_SCHEMA",
    "COMMUNICATION_DISPATCH_RECOVERY_STAGE_SCHEMA",
    "COMMUNICATION_GMAIL_POLL_TEMPLATE_SCHEMA",
    "COMMUNICATION_OUTLOOK_POLL_TEMPLATE_SCHEMA",
    "COMMUNICATION_POLL_PLAN_SCHEMA",
    "CommunicationChannelDispatchRecoveryStage",
    "CommunicationChannelDispatchRecoveryStageRequest",
    "CommunicationChannelPollArtifacts",
    "CommunicationChannelPollTemplate",
    "CommunicationDispatchRecoveryAuthority",
    "CommunicationDispatchRecoveryFinalization",
    "CommunicationDispatchRecoveryStage",
    "CommunicationDispatchRecoveryStageRequest",
    "CommunicationGmailPollTemplate",
    "CommunicationOutlookPollTemplate",
    "CommunicationPollPlan",
    "build_communication_dispatch_recovery_stage_request",
    "finalize_recovered_communication_dispatch",
    "mint_communication_dispatch_recovery_stage",
    "mint_communication_poll_plan",
    "validate_communication_dispatch_recovery_stage_request",
    "verify_communication_dispatch_recovery_stage",
]
