"""Governed one-recipient materialization for CRM conversation turns.

Raw addresses and message content cross this module only as transient values.
Every durable result contains commitments and opaque references, never message
content.  A nominal connector success is insufficient: completion requires an
exact Spring-owned route, approval, request, account, project and receipt
provenance envelope plus a provider message/thread proof.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Mapping, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lightbulb.communication_contracts import (
    CommunicationApprovalDisposition,
    CommunicationApprovalGrant,
    CommunicationChannel,
    CommunicationContactPolicyDecision,
    CommunicationContactReservation,
    CommunicationContactReservationConsumption,
    CommunicationContactReservationRequest,
    CommunicationContextSnapshot,
    CommunicationDispatchReceipt,
    CommunicationDispatchState,
    CommunicationEndpointBinding,
    CommunicationMessageDraft,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationPolicyDisposition,
    CommunicationScopeKeyRing,
    CommunicationThreadBinding,
    CommunicationThreadState,
    communication_canonical_digest,
    communication_company_contact_scope_digest,
    communication_private_value_digest,
    communication_recipient_address_commitment,
    communication_recipient_contact_commitment,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ConnectorExecutor,
    ExecutionScope,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.communication_governance import (
    CommunicationContactReservationAuthority,
    verify_communication_dispatch_authority,
)


COMMUNICATION_GMAIL_ROUTE_SCHEMA = "lightbulb.communication_gmail_route.v1"
COMMUNICATION_PRIVATE_GMAIL_MESSAGE_SCHEMA = (
    "lightbulb.communication_private_gmail_message.v1"
)
COMMUNICATION_MATERIALIZATION_RESULT_SCHEMA = (
    "lightbulb.communication_materialization_result.v1"
)
_GMAIL_SEND_TOOL = "gmail.send_email"
_ADDRESS_HMAC_DOMAIN = "lightbulb.communication_endpoint_address.v1"
_EMAIL_RE = re.compile(r"^[^\s@\r\n]+@[^\s@\r\n]+\.[^\s@\r\n]+$")
_RFC_MESSAGE_ID_RE = re.compile(r"^<[^<>\s@]+@[^<>\s@]+>$")
_VISIBLE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _utc(value, label="timestamp").isoformat().replace("+00:00", "Z")


def _timestamp(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label)


def _visible(value: str, *, label: str, maximum: int = 240) -> str:
    clean = value.strip()
    if (
        not clean
        or len(clean) > maximum
        or not _VISIBLE_REF_RE.fullmatch(clean)
        or any(ord(character) < 33 for character in clean)
    ):
        raise ValueError(f"{label} contains unsupported characters")
    return clean


class CommunicationGmailRoute(_StrictModel):
    """Server-attested coordinates resolved before a communication turn."""

    schema_id: Literal["lightbulb.communication_gmail_route.v1"] = Field(
        default=COMMUNICATION_GMAIL_ROUTE_SCHEMA,
        alias="schema",
    )
    project_id: UUID
    project_ref: str = Field(min_length=1, max_length=160)
    connector_account_ref: str = Field(min_length=1, max_length=200)
    tenant_connector_id: UUID
    route_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool: Literal["gmail.send_email"] = _GMAIL_SEND_TOOL
    tool_version: int = Field(ge=1)

    @field_validator("project_ref", "connector_account_ref")
    @classmethod
    def _route_refs(cls, value: str, info: Any) -> str:
        return _visible(value, label=info.field_name, maximum=200)


class CommunicationPrivateGmailMessage(_StrictModel):
    """Transient private content resolved by the trusted host at dispatch."""

    schema_id: Literal[
        "lightbulb.communication_private_gmail_message.v1"
    ] = Field(default=COMMUNICATION_PRIVATE_GMAIL_MESSAGE_SCHEMA, alias="schema")
    private_content_ref: str = Field(min_length=1, max_length=200)
    sender_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_endpoint_ref: str = Field(min_length=1, max_length=200)
    recipient_address: str = Field(min_length=3, max_length=998, repr=False)
    subject: str = Field(min_length=1, max_length=998, repr=False)
    body: str = Field(min_length=1, max_length=50_000, repr=False)
    provider_thread_id: str = Field(min_length=1, max_length=512, repr=False)
    parent_message_id: str = Field(min_length=5, max_length=998, repr=False)

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
    def _email(cls, value: str) -> str:
        clean = value.strip()
        if not _EMAIL_RE.fullmatch(clean):
            raise ValueError("recipient_address must be one valid email address")
        return clean

    @field_validator("subject")
    @classmethod
    def _subject(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("subject must not contain header control characters")
        return value

    @field_validator("body")
    @classmethod
    def _body(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("body must not contain NUL")
        return value

    @field_validator("provider_thread_id")
    @classmethod
    def _thread_id(cls, value: str) -> str:
        return _visible(value, label="provider_thread_id", maximum=512)

    @field_validator("parent_message_id")
    @classmethod
    def _parent_message_id(cls, value: str) -> str:
        clean = value.strip()
        if _RFC_MESSAGE_ID_RE.fullmatch(clean) is None:
            raise ValueError("parent_message_id must be one exact RFC Message-ID")
        return clean

    def connector_arguments(self) -> dict[str, str]:
        return {
            "to": self.recipient_address,
            "subject": self.subject,
            "body": self.body,
            "thread_id": self.provider_thread_id,
            "parent_message_id": self.parent_message_id,
        }


@dataclass(frozen=True, slots=True)
class CommunicationEmailEffectProof:
    provider_message_id: str
    provider_conversation_id: str
    completed: bool
    provider_message_sha256: str | None = None
    provider_conversation_sha256: str | None = None
    private_dispatch: Any | None = None


class CommunicationPrivateDispatchSink(Protocol):
    """Trusted host boundary for encrypted provider-write result custody."""

    def store(
        self,
        *,
        dispatch: CommunicationDispatchReceipt,
        authority_binding: Any,
        private_dispatch: Any,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> None: ...


class CommunicationEmailMaterializerAdapter(Protocol):
    """Closed provider seam around shared dispatch authority and receipts."""

    provider_name: str
    tool: str
    channel: CommunicationChannel

    def parse_route(self, value: Any) -> Any: ...

    def parse_private_message(self, value: Any) -> Any: ...

    def connector_arguments(self, value: Any) -> dict[str, Any]: ...

    def provider_conversation_id(self, value: Any) -> str: ...

    def provider_conversation_sha256(self, value: Any) -> str: ...

    def parent_message_sha256(self, value: Any) -> str | None: ...

    def recipient_address(self, value: Any) -> str: ...

    def subject(self, value: Any) -> str | None: ...

    def body(self, value: Any) -> str: ...

    def endpoint_address_commitment(
        self,
        *,
        scope: DynamicWorkflowScope,
        endpoint_ref: str,
        address: str,
        key_id: str,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def validate_authority_binding(self, **values: Any) -> None: ...

    def validate_effect_output(
        self,
        output: Mapping[str, Any],
        private_message: Any,
        **context: Any,
    ) -> CommunicationEmailEffectProof: ...

    def provider_effect_message_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...

    def provider_effect_conversation_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> str: ...


class _GmailMaterializerAdapter:
    __slots__ = ()

    provider_name = "gmail"
    tool = _GMAIL_SEND_TOOL
    channel = CommunicationChannel.EMAIL

    def parse_route(self, value: Any) -> CommunicationGmailRoute:
        return CommunicationGmailRoute.model_validate(value)

    def parse_private_message(self, value: Any) -> CommunicationPrivateGmailMessage:
        return CommunicationPrivateGmailMessage.model_validate(value)

    def connector_arguments(
        self,
        value: CommunicationPrivateGmailMessage,
    ) -> dict[str, Any]:
        return value.connector_arguments()

    def provider_conversation_id(
        self,
        value: CommunicationPrivateGmailMessage,
    ) -> str:
        return value.provider_thread_id

    def provider_conversation_sha256(
        self,
        value: CommunicationPrivateGmailMessage,
    ) -> str:
        return communication_private_value_digest(value.provider_thread_id)

    def parent_message_sha256(
        self,
        value: CommunicationPrivateGmailMessage,
    ) -> str:
        return communication_private_value_digest(value.parent_message_id)

    def recipient_address(self, value: CommunicationPrivateGmailMessage) -> str:
        return value.recipient_address

    def subject(self, value: CommunicationPrivateGmailMessage) -> str:
        return value.subject

    def body(self, value: CommunicationPrivateGmailMessage) -> str:
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
        private_message: CommunicationPrivateGmailMessage,
        **_: Any,
    ) -> CommunicationEmailEffectProof:
        if not isinstance(output, Mapping):
            raise ValueError("Gmail effect output must be an object")
        if not set(output).issubset({"id", "threadId", "labelIds"}):
            raise ValueError("Gmail effect output contains an unreviewed field")
        provider_message_id = output.get("id")
        provider_thread_id = output.get("threadId")
        if (
            not isinstance(provider_message_id, str)
            or not provider_message_id
            or len(provider_message_id) > 512
            or provider_message_id != provider_message_id.strip()
            or not isinstance(provider_thread_id, str)
            or provider_thread_id != private_message.provider_thread_id
        ):
            raise ValueError("Gmail effect output is not exact")
        return CommunicationEmailEffectProof(
            provider_message_id=provider_message_id,
            provider_conversation_id=provider_thread_id,
            completed=True,
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


_GMAIL_MATERIALIZER_ADAPTER = _GmailMaterializerAdapter()


def _require_reviewed_materializer_adapter(
    adapter: CommunicationEmailMaterializerAdapter,
) -> CommunicationEmailMaterializerAdapter:
    if adapter is _GMAIL_MATERIALIZER_ADAPTER:
        return adapter
    # Lazy import keeps the shared authority independent of the Outlook model
    # module while exact singleton identity prevents caller-defined validators
    # from becoming receipt-minting authority.
    try:
        from lightbulb.communication_outlook import _OUTLOOK_MATERIALIZER_ADAPTER
    except ImportError:  # pragma: no cover - only possible during a broken install
        _OUTLOOK_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
    if adapter is _OUTLOOK_MATERIALIZER_ADAPTER:
        return adapter
    try:
        from lightbulb.communication_channels import (
            _SLACK_CHANNEL_MATERIALIZER_ADAPTER,
            _TEAMS_CHANNEL_MATERIALIZER_ADAPTER,
        )
    except ImportError:  # pragma: no cover - only possible during a broken install
        _SLACK_CHANNEL_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
        _TEAMS_CHANNEL_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
    if (
        adapter is _SLACK_CHANNEL_MATERIALIZER_ADAPTER
        or adapter is _TEAMS_CHANNEL_MATERIALIZER_ADAPTER
    ):
        return adapter
    try:
        from lightbulb.communication_omnichannel import (
            _TWILIO_SMS_MATERIALIZER_ADAPTER,
            _WHATSAPP_SERVICE_WINDOW_MATERIALIZER_ADAPTER,
            _WHATSAPP_TEMPLATE_MATERIALIZER_ADAPTER,
        )
    except ImportError:  # pragma: no cover - only possible during a broken install
        _TWILIO_SMS_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
        _WHATSAPP_SERVICE_WINDOW_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
        _WHATSAPP_TEMPLATE_MATERIALIZER_ADAPTER = None  # type: ignore[assignment]
    if adapter in {
        _TWILIO_SMS_MATERIALIZER_ADAPTER,
        _WHATSAPP_SERVICE_WINDOW_MATERIALIZER_ADAPTER,
        _WHATSAPP_TEMPLATE_MATERIALIZER_ADAPTER,
    }:
        return adapter
    raise ValueError("communication provider adapter is not SDK-owned")


class CommunicationMaterializationStatus(str, Enum):
    PREVIEW = "preview"
    PENDING_APPROVAL = "pending_approval"
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class CommunicationExternalEffectState(str, Enum):
    NONE = "none"
    ACCEPTED = "accepted"
    COMPLETED = "completed"
    UNKNOWN = "unknown"


class CommunicationMaterializationResult(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_materialization_result.v1"
    ] = Field(default=COMMUNICATION_MATERIALIZATION_RESULT_SCHEMA, alias="schema")
    status: CommunicationMaterializationStatus
    draft_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    thread_ref: str
    run_ref: str
    idempotency_key: str = Field(min_length=1, max_length=240)
    connector_status: ConnectorExecutionStatus | None = None
    approval_ref: str | None = Field(default=None, max_length=200)
    approval_receipt_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    connector_error_kind: ConnectorErrorKind | None = None
    connector_error_code: str | None = Field(default=None, max_length=160)
    effect_state: CommunicationExternalEffectState
    receipt: CommunicationDispatchReceipt | None = None
    summary: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def _status_shape(self) -> "CommunicationMaterializationResult":
        if self.status in {
            CommunicationMaterializationStatus.ACCEPTED,
            CommunicationMaterializationStatus.COMPLETED,
        }:
            expected_effect = (
                CommunicationExternalEffectState.ACCEPTED
                if self.status == CommunicationMaterializationStatus.ACCEPTED
                else CommunicationExternalEffectState.COMPLETED
            )
            if (
                self.connector_status != ConnectorExecutionStatus.COMPLETED
                or self.approval_ref is None
                or self.approval_receipt_digest is None
                or self.receipt is None
                or self.effect_state != expected_effect
            ):
                raise ValueError(
                    "accepted/completed communication requires exact effect evidence"
                )
        elif self.receipt is not None:
            raise ValueError(
                "only accepted/completed communication may carry a dispatch receipt"
            )
        if self.status == CommunicationMaterializationStatus.PENDING_APPROVAL and (
            self.connector_status != ConnectorExecutionStatus.PENDING_APPROVAL
            or self.approval_ref is None
            or self.approval_receipt_digest is None
            or self.effect_state != CommunicationExternalEffectState.NONE
        ):
            raise ValueError("pending approval requires durable platform approval proof")
        if self.status in {
            CommunicationMaterializationStatus.PREVIEW,
            CommunicationMaterializationStatus.BLOCKED,
        } and self.effect_state != CommunicationExternalEffectState.NONE:
            raise ValueError("preview and blocked communication cannot claim an effect")
        return self


def communication_endpoint_address_commitment(
    *,
    endpoint_ref: str,
    address: str,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Return a host-keyed address commitment resistant to dictionary lookup."""

    normalized = address.strip()
    if not _EMAIL_RE.fullmatch(normalized):
        raise ValueError("address must be one valid email address")
    return scope_keyring.sign(
        key_id,
        _ADDRESS_HMAC_DOMAIN,
        {
            "schema": _ADDRESS_HMAC_DOMAIN,
            "endpoint_ref": endpoint_ref,
            "address": normalized,
        },
    ).hex()


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    raw = (
        value.model_dump(mode="python")
        if isinstance(value, DynamicWorkflowScope)
        else value
    )
    return DynamicWorkflowScope.model_validate(raw)


def _execution_scope(value: ExecutionScope | Mapping[str, Any]) -> ExecutionScope:
    raw = value.model_dump(mode="python") if isinstance(value, ExecutionScope) else value
    return ExecutionScope.model_validate(raw)


def _validate_live_scope(
    execution_scope: ExecutionScope,
    workflow_scope: DynamicWorkflowScope,
    route: Any,
) -> None:
    if execution_scope.project_id is None:
        raise ValueError("communication dispatch requires an authenticated project UUID")
    expected = (
        workflow_scope.tenant_id,
        workflow_scope.company_id,
        workflow_scope.project_ref,
        workflow_scope.user_id,
        route.project_id,
    )
    actual = (
        execution_scope.tenant_ref,
        execution_scope.company_ref,
        execution_scope.project_ref,
        execution_scope.actor_ref,
        execution_scope.project_id,
    )
    if actual != expected or route.project_ref != workflow_scope.project_ref:
        raise ValueError("execution scope does not match authenticated communication scope")


def _verified(
    artifact: Any,
    artifact_type: type[Any],
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
    at: datetime | None = None,
) -> Any:
    return verify_communication_artifact(
        artifact,
        artifact_type=artifact_type,
        scope=scope,
        scope_keyring=scope_keyring,
        at=at,
    )


def _idempotency_key(
    *,
    provider_name: str,
    draft_digest: str,
    thread_ref: str,
    route_digest: str,
    schedule_digest: str,
    run_ref: str,
) -> str:
    digest = communication_canonical_digest(
        {
            "schema": "lightbulb.communication_dispatch_identity.v1",
            "draft_digest": draft_digest,
            "thread_ref": thread_ref,
            "route_digest": route_digest,
            "schedule_digest": schedule_digest,
            "run_ref": run_ref,
        }
    )
    return f"communication:{provider_name}:{digest}"


def _result(
    *,
    status: CommunicationMaterializationStatus,
    draft: CommunicationMessageDraft,
    run_ref: str,
    idempotency_key: str,
    effect_state: CommunicationExternalEffectState,
    summary: str,
    connector_status: ConnectorExecutionStatus | None = None,
    approval_ref: str | None = None,
    approval_receipt_digest: str | None = None,
    connector_error_kind: ConnectorErrorKind | None = None,
    connector_error_code: str | None = None,
    receipt: CommunicationDispatchReceipt | None = None,
) -> CommunicationMaterializationResult:
    return CommunicationMaterializationResult(
        status=status,
        draft_digest=draft.artifact_digest,
        thread_ref=draft.thread_ref,
        run_ref=run_ref,
        idempotency_key=idempotency_key,
        connector_status=connector_status,
        approval_ref=approval_ref,
        approval_receipt_digest=approval_receipt_digest,
        connector_error_kind=connector_error_kind,
        connector_error_code=connector_error_code,
        effect_state=effect_state,
        receipt=receipt,
        summary=summary,
    )


def materialize_gmail_communication_turn(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    route: CommunicationGmailRoute | Mapping[str, Any],
    context: CommunicationContextSnapshot | Mapping[str, Any],
    thread: CommunicationThreadBinding | Mapping[str, Any],
    sender_party: CommunicationPartyRef | Mapping[str, Any],
    recipient_party: CommunicationPartyRef | Mapping[str, Any],
    sender_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
    recipient_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
    draft: CommunicationMessageDraft | Mapping[str, Any],
    policy_decision: CommunicationContactPolicyDecision | Mapping[str, Any],
    private_message: CommunicationPrivateGmailMessage | Mapping[str, Any],
    executor: ConnectorExecutor,
    run_ref: str,
    schedule_digest: str,
    now: datetime,
    preview_only: bool = True,
    approval_grant: CommunicationApprovalGrant | Mapping[str, Any] | None = None,
    reservation_request: CommunicationContactReservationRequest
    | Mapping[str, Any]
    | None = None,
    reservation: CommunicationContactReservation | Mapping[str, Any] | None = None,
    reservation_authority: CommunicationContactReservationAuthority | None = None,
    _provider_adapter: CommunicationEmailMaterializerAdapter | None = None,
    _authority_binding: Any = None,
    _private_dispatch_sink: CommunicationPrivateDispatchSink | None = None,
    _recovery_authority: Any = None,
    _recovery_poll_plan: Any = None,
    _recovery_poll_template: Any = None,
) -> CommunicationMaterializationResult:
    """Preview, propose, resume, or complete one governed CRM turn."""

    provider_adapter = _require_reviewed_materializer_adapter(
        _provider_adapter or _GMAIL_MATERIALIZER_ADAPTER
    )
    provider_label = provider_adapter.provider_name.capitalize()
    expected_channel = provider_adapter.channel
    current = _utc(now, label="now")
    workflow_scope = _workflow_scope(scope)
    runtime_scope = _execution_scope(execution_scope)
    parsed_route = provider_adapter.parse_route(route)
    _validate_live_scope(runtime_scope, workflow_scope, parsed_route)
    parsed_context = _verified(
        context,
        CommunicationContextSnapshot,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        at=current,
    )
    parsed_thread = _verified(
        thread,
        CommunicationThreadBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_sender_party = _verified(
        sender_party,
        CommunicationPartyRef,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_recipient_party = _verified(
        recipient_party,
        CommunicationPartyRef,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_sender = _verified(
        sender_endpoint,
        CommunicationEndpointBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_recipient = _verified(
        recipient_endpoint,
        CommunicationEndpointBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_draft = _verified(
        draft,
        CommunicationMessageDraft,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    parsed_policy = _verified(
        policy_decision,
        CommunicationContactPolicyDecision,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        at=current,
    )
    private = provider_adapter.parse_private_message(private_message)
    clean_run_ref = _visible(run_ref, label="run_ref", maximum=160)
    if not re.fullmatch(r"[0-9a-f]{64}", schedule_digest):
        raise ValueError("schedule_digest must be lowercase SHA-256")

    endpoint_route = (
        parsed_route.connector_account_ref,
        parsed_route.route_digest,
    )
    if parsed_thread.state == CommunicationThreadState.CLOSED:
        raise ValueError("closed communication threads cannot be dispatched")
    if parsed_thread.crm_trace_binding_digest is None:
        raise ValueError("CRM communication thread requires a sealed CRM trace binding")
    if parsed_context.thread_ref != parsed_thread.thread_ref or (
        parsed_context.party_refs != parsed_thread.participant_party_refs
    ):
        raise ValueError("context does not bind the exact thread and participants")
    if (
        parsed_sender.endpoint_ref == parsed_recipient.endpoint_ref
        or parsed_sender_party.party_ref == parsed_recipient_party.party_ref
    ):
        raise ValueError("sender and recipient must be distinct communication parties")
    if (
        parsed_sender.party_ref != parsed_sender_party.party_ref
        or parsed_sender.party_digest != parsed_sender_party.artifact_digest
        or parsed_recipient.party_ref != parsed_recipient_party.party_ref
        or parsed_recipient.party_digest != parsed_recipient_party.artifact_digest
    ):
        raise ValueError("endpoints do not bind the exact sealed sender/recipient parties")
    if parsed_recipient_party.party_kind != CommunicationPartyKind.CRM_CONTACT:
        raise ValueError("CRM communication recipient must be a sealed CRM contact")
    endpoint_parties = (
        parsed_sender_party.party_ref,
        parsed_recipient_party.party_ref,
    )
    if any(
        party_ref not in parsed_thread.participant_party_refs
        for party_ref in endpoint_parties
    ):
        raise ValueError("sender and recipient parties are not thread participants")
    if parsed_sender.channel != expected_channel:
        raise ValueError("sender endpoint does not match the governed channel")
    if parsed_recipient.channel != expected_channel:
        raise ValueError("recipient endpoint does not match the governed channel")
    if (
        parsed_sender.connector_account_ref,
        parsed_sender.route_digest,
    ) != endpoint_route:
        raise ValueError("sender endpoint does not match the exact communication route")
    if (
        parsed_recipient.connector_account_ref,
        parsed_recipient.route_digest,
    ) != endpoint_route:
        raise ValueError("recipient endpoint does not match the exact communication route")
    if (
        parsed_thread.connector_account_ref,
        parsed_thread.route_digest,
    ) != endpoint_route:
        raise ValueError("thread does not match the exact communication route")
    if parsed_thread.primary_channel != expected_channel:
        raise ValueError("thread does not match the governed channel")
    if parsed_draft.channel != expected_channel:
        raise ValueError("materializer draft does not match the governed channel")
    if len(parsed_draft.recipient_endpoint_refs) != 1:
        raise ValueError("governed communication turns require exactly one recipient")
    private_recipient_address = provider_adapter.recipient_address(private)
    company_contact_scope = communication_company_contact_scope_digest(
        scope=workflow_scope,
        key_id=parsed_draft.contact_token_key_id,
        scope_keyring=scope_keyring,
    )
    recipient_contact_digest = communication_recipient_contact_commitment(
        company_contact_scope_digest=company_contact_scope,
        party_ref=parsed_recipient_party.party_ref,
        key_id=parsed_draft.contact_token_key_id,
        scope_keyring=scope_keyring,
    )
    recipient_address_digest = communication_recipient_address_commitment(
        company_contact_scope_digest=company_contact_scope,
        channel=expected_channel,
        address=private_recipient_address,
        key_id=parsed_draft.contact_token_key_id,
        scope_keyring=scope_keyring,
    )
    expected_draft = (
        parsed_context.artifact_digest,
        parsed_thread.thread_ref,
        parsed_thread.artifact_digest,
        parsed_thread.version,
        parsed_thread.state,
        parsed_thread.participant_party_refs,
        parsed_thread.parent_message_sha256,
        parsed_sender.endpoint_ref,
        parsed_sender.artifact_digest,
        (parsed_recipient.endpoint_ref,),
        (parsed_recipient.artifact_digest,),
        company_contact_scope,
        (recipient_contact_digest,),
        (recipient_address_digest,),
        parsed_draft.purpose,
    )
    actual_draft = (
        parsed_draft.context_digest,
        parsed_draft.thread_ref,
        parsed_draft.thread_digest,
        parsed_draft.thread_version,
        parsed_draft.thread_state,
        parsed_draft.thread_participant_party_refs,
        parsed_draft.parent_message_sha256,
        parsed_draft.sender_endpoint_ref,
        parsed_draft.sender_endpoint_digest,
        parsed_draft.recipient_endpoint_refs,
        parsed_draft.recipient_endpoint_digests,
        parsed_draft.company_contact_scope_digest,
        parsed_draft.recipient_contact_digests,
        parsed_draft.recipient_address_digests,
        parsed_thread.purpose,
    )
    if actual_draft != expected_draft:
        raise ValueError("draft does not match context, thread, or endpoint bindings")
    if (
        private.private_content_ref != parsed_draft.private_content_ref
        or private.sender_endpoint_ref != parsed_sender.endpoint_ref
        or private.recipient_endpoint_ref != parsed_recipient.endpoint_ref
        or (
            communication_private_value_digest(provider_adapter.subject(private))
            if provider_adapter.subject(private) is not None
            else None
        )
        != parsed_draft.subject_sha256
        or communication_private_value_digest(provider_adapter.body(private))
        != parsed_draft.body_sha256
    ):
        raise ValueError(
            f"private {provider_label} content does not match sealed draft"
        )
    expected_address_commitment = provider_adapter.endpoint_address_commitment(
        scope=workflow_scope,
        endpoint_ref=parsed_recipient.endpoint_ref,
        address=private_recipient_address,
        key_id=parsed_recipient.receipt_key_id,
        scope_keyring=scope_keyring,
    )
    if not hmac.compare_digest(
        expected_address_commitment,
        parsed_recipient.address_sha256,
    ):
        raise ValueError("private recipient does not match sealed endpoint")
    provider_thread_digest = provider_adapter.provider_conversation_sha256(private)
    if (
        parsed_thread.provider_thread_sha256 is None
        or not hmac.compare_digest(
            provider_thread_digest,
            parsed_thread.provider_thread_sha256,
        )
    ):
        raise ValueError("private provider thread does not match sealed thread")
    parent_message_digest = provider_adapter.parent_message_sha256(private)
    if parent_message_digest is None:
        if (
            parsed_thread.parent_message_sha256 is not None
            or parsed_draft.parent_message_sha256 is not None
        ):
            raise ValueError(
                "parentless provider turn does not match sealed thread/draft"
            )
    elif parsed_thread.parent_message_sha256 is None or any(
        not hmac.compare_digest(candidate, parent_message_digest)
        for candidate in (
            parsed_thread.parent_message_sha256,
            parsed_draft.parent_message_sha256,
        )
    ):
        raise ValueError(
            "private parent Message-ID/target does not match sealed thread/draft"
        )
    if parsed_policy.disposition != CommunicationPolicyDisposition.ALLOW:
        raise ValueError("contact policy does not allow dispatch")
    expected_policy = (
        parsed_draft.artifact_digest,
        parsed_draft.purpose,
        expected_channel,
        parsed_draft.recipient_endpoint_digests,
    )
    actual_policy = (
        parsed_policy.draft_digest,
        parsed_policy.purpose,
        parsed_policy.channel,
        parsed_policy.recipient_endpoint_digests,
    )
    if actual_policy != expected_policy:
        raise ValueError("contact policy does not match sealed draft")
    provider_adapter.validate_authority_binding(
        authority_binding=_authority_binding,
        route=parsed_route,
        context=parsed_context,
        thread=parsed_thread,
        sender_party=parsed_sender_party,
        recipient_party=parsed_recipient_party,
        sender_endpoint=parsed_sender,
        recipient_endpoint=parsed_recipient,
        draft=parsed_draft,
        policy_decision=parsed_policy,
        private_message=private,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )

    parsed_approval: CommunicationApprovalGrant | None = None
    if approval_grant is not None:
        parsed_approval = _verified(
            approval_grant,
            CommunicationApprovalGrant,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            at=current,
        )
        expected_approval = (
            CommunicationApprovalDisposition.APPROVED,
            parsed_draft.artifact_digest,
            parsed_policy.artifact_digest,
            parsed_draft.thread_digest,
            parsed_draft.thread_version,
            parsed_draft.thread_state,
            parsed_draft.thread_participant_party_refs,
            parsed_draft.parent_message_sha256,
            parsed_draft.purpose,
            expected_channel,
            parsed_sender.artifact_digest,
            parsed_draft.recipient_endpoint_digests,
            parsed_draft.subject_sha256,
            parsed_draft.body_sha256,
            parsed_draft.attachment_sha256s,
            parsed_route.connector_account_ref,
            parsed_route.route_digest,
            schedule_digest,
        )
        actual_approval = (
            parsed_approval.disposition,
            parsed_approval.draft_digest,
            parsed_approval.policy_decision_digest,
            parsed_approval.thread_digest,
            parsed_approval.thread_version,
            parsed_approval.thread_state,
            parsed_approval.thread_participant_party_refs,
            parsed_approval.parent_message_sha256,
            parsed_approval.purpose,
            parsed_approval.channel,
            parsed_approval.sender_endpoint_digest,
            parsed_approval.recipient_endpoint_digests,
            parsed_approval.subject_sha256,
            parsed_approval.body_sha256,
            parsed_approval.attachment_sha256s,
            parsed_approval.connector_account_ref,
            parsed_approval.route_digest,
            parsed_approval.schedule_digest,
        )
        if actual_approval != expected_approval:
            raise ValueError("approval does not match content, policy, endpoints, or route")

    key = _idempotency_key(
        provider_name=provider_adapter.provider_name,
        draft_digest=parsed_draft.artifact_digest,
        thread_ref=parsed_thread.thread_ref,
        route_digest=parsed_route.route_digest,
        schedule_digest=schedule_digest,
        run_ref=clean_run_ref,
    )
    if preview_only:
        return _result(
            status=CommunicationMaterializationStatus.PREVIEW,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.NONE,
            connector_status=ConnectorExecutionStatus.PREVIEW,
            summary=(
                f"Validated one exact {provider_label} CRM turn; "
                "preview performed no connector call."
            ),
        )

    parsed_request: CommunicationContactReservationRequest | None = None
    parsed_reservation: CommunicationContactReservation | None = None
    if parsed_approval is not None:
        if (
            reservation_request is None
            or reservation is None
            or (reservation_authority is None and _recovery_authority is None)
        ):
            raise ValueError("approved dispatch requires a live contact reservation")
        authority = _recovery_authority or reservation_authority
        if authority is None:  # narrowed above; keep the trust boundary explicit
            raise ValueError("approved dispatch requires contact authority")
        if (
            authority.contact_token_key_id
            != parsed_draft.contact_token_key_id
        ):
            raise ValueError(
                "contact reservation authority uses a different tokenization key"
            )
        parsed_request = _verified(
            reservation_request,
            CommunicationContactReservationRequest,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        parsed_reservation = _verified(
            reservation,
            CommunicationContactReservation,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
            at=current,
        )
        if (
            parsed_request.draft_digest != parsed_draft.artifact_digest
            or parsed_request.policy_decision_digest
            != parsed_policy.artifact_digest
            or parsed_request.purpose != parsed_draft.purpose
            or parsed_request.channel != expected_channel
            or parsed_request.recipient_endpoint_digests
            != parsed_draft.recipient_endpoint_digests
            or parsed_request.company_contact_scope_digest
            != parsed_draft.company_contact_scope_digest
            or parsed_request.contact_token_key_id
            != parsed_draft.contact_token_key_id
            or parsed_request.recipient_contact_digests
            != parsed_draft.recipient_contact_digests
            or parsed_request.recipient_address_digests
            != parsed_draft.recipient_address_digests
            or parsed_request.run_ref != clean_run_ref
            or parsed_reservation.request_digest != parsed_request.artifact_digest
            or parsed_reservation.slot_digest != parsed_request.slot_digest
        ):
            raise ValueError("contact reservation does not match exact dispatch")

    request = ConnectorExecutionRequest(
        tool=provider_adapter.tool,
        arguments=provider_adapter.connector_arguments(private),
        scope=runtime_scope,
        connector_account_ref=parsed_route.connector_account_ref,
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        approval_ref=(
            parsed_approval.approval_ref if parsed_approval is not None else None
        ),
        preview_only=False,
        idempotency_key=key,
        metadata={
            "communication_schema": "lightbulb.governed_communication_turn.v1",
            "draft_digest": parsed_draft.artifact_digest,
            "policy_decision_digest": parsed_policy.artifact_digest,
            "approval_digest": (
                parsed_approval.artifact_digest
                if parsed_approval is not None
                else None
            ),
            "thread_ref": parsed_thread.thread_ref,
            "thread_digest": parsed_thread.artifact_digest,
            "thread_version": parsed_thread.version,
            "thread_state": parsed_thread.state.value,
            "thread_participant_party_refs": parsed_thread.participant_party_refs,
            "parent_message_sha256": parsed_thread.parent_message_sha256,
            "run_ref": clean_run_ref,
            "schedule_digest": schedule_digest,
            "authority_binding_digest": (
                _authority_binding.artifact_digest
                if _authority_binding is not None
                else None
            ),
        },
    )

    consumption: CommunicationContactReservationConsumption | None = None
    recovery_stage: Any = None
    if parsed_approval is not None:
        assert parsed_request is not None
        assert parsed_reservation is not None
        if _recovery_authority is not None:
            if (
                provider_adapter.provider_name
                not in {"gmail", "outlook", "slack", "teams"}
                or _recovery_poll_plan is None
                or _recovery_poll_template is None
            ):
                raise ValueError(
                    "durable dispatch recovery requires one exact poll plan and template"
                )
            from lightbulb.communication_dispatch_recovery import (
                build_communication_dispatch_recovery_stage_request,
                validate_communication_dispatch_recovery_stage_request,
                verify_communication_dispatch_recovery_stage,
            )

            stage_request = build_communication_dispatch_recovery_stage_request(
                provider=provider_adapter.provider_name,
                run_ref=clean_run_ref,
                schedule_digest=schedule_digest,
                idempotency_key=key,
                invocation_request_digest=request.custody_fingerprint(),
                draft=parsed_draft,
                policy_decision=parsed_policy,
                approval_grant=parsed_approval,
                reservation_request=parsed_request,
                reservation=parsed_reservation,
                poll_plan=_recovery_poll_plan,
                poll_template=_recovery_poll_template,
            )
            stage_request = validate_communication_dispatch_recovery_stage_request(
                stage_request,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
                at=current,
            )
            recovery_stage = _recovery_authority.consume_and_stage(
                request=stage_request,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
                consumed_at=current,
            )
            recovery_stage = verify_communication_dispatch_recovery_stage(
                recovery_stage,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
                expected_request=stage_request,
            )
            consumption = recovery_stage.reservation_consumption
        else:
            assert reservation_authority is not None
            consumption = reservation_authority.consume(
                parsed_reservation,
                request=parsed_request,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
                consumed_at=current,
            )
        consumption = _verified(
            consumption,
            CommunicationContactReservationConsumption,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if (
            consumption.reservation_ref != parsed_reservation.reservation_ref
            or consumption.request_digest != parsed_request.artifact_digest
            or consumption.slot_digest != parsed_request.slot_digest
            or _timestamp(consumption.consumed_at, label="consumed_at") != current
        ):
            raise ValueError("contact reservation consumption is not exact")
        verify_communication_dispatch_authority(
            draft=parsed_draft,
            policy_decision=parsed_policy,
            approval_grant=parsed_approval,
            reservation_request=parsed_request,
            reservation=parsed_reservation,
            reservation_consumption=consumption,
            connector_account_ref=parsed_route.connector_account_ref,
            route_digest=parsed_route.route_digest,
            schedule_digest=schedule_digest,
            at=current,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )

    try:
        connector_result = executor.execute(request)
    except Exception:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=(
                CommunicationExternalEffectState.UNKNOWN
                if parsed_approval is not None
                else CommunicationExternalEffectState.NONE
            ),
            approval_ref=(
                parsed_approval.approval_ref if parsed_approval is not None else None
            ),
            approval_receipt_digest=(
                parsed_approval.authority_evidence_digest
                if parsed_approval is not None
                else None
            ),
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_execute_failed",
            summary="Connector execution raised; external effect state is unknown.",
        )
    if not isinstance(connector_result, ConnectorExecutionResult):
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="invalid_connector_result",
            summary="Connector returned an invalid result contract.",
        )
    if connector_result.tool != provider_adapter.tool:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="connector_tool_mismatch",
            summary="Connector result named a different Tool.",
        )
    if connector_result.status == ConnectorExecutionStatus.PENDING_APPROVAL:
        if (
            parsed_approval is not None
            or not connector_result.approval_ref
            or connector_result.approval_receipt_digest is None
        ):
            return _result(
                status=CommunicationMaterializationStatus.FAILED,
                draft=parsed_draft,
                run_ref=clean_run_ref,
                idempotency_key=key,
                effect_state=CommunicationExternalEffectState.NONE,
                connector_status=connector_result.status,
                connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
                connector_error_code="approval_state_invalid",
                summary="Connector did not persist the expected approval proposal.",
            )
        return _result(
            status=CommunicationMaterializationStatus.PENDING_APPROVAL,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.NONE,
            connector_status=connector_result.status,
            approval_ref=connector_result.approval_ref,
            approval_receipt_digest=connector_result.approval_receipt_digest,
            summary=(
                f"Exact {provider_label} reply is pending platform approval; "
                "no write completed."
            ),
        )
    if connector_result.status == ConnectorExecutionStatus.BLOCKED:
        return _result(
            status=CommunicationMaterializationStatus.BLOCKED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.NONE,
            connector_status=connector_result.status,
            connector_error_kind=connector_result.error_kind,
            connector_error_code=connector_result.error_code,
            approval_ref=(
                parsed_approval.approval_ref if parsed_approval is not None else None
            ),
            approval_receipt_digest=(
                parsed_approval.authority_evidence_digest
                if parsed_approval is not None
                else None
            ),
            summary=(
                f"Governed connector blocked the {provider_label} action before an effect."
            ),
        )
    if connector_result.status != ConnectorExecutionStatus.COMPLETED:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=(
                CommunicationExternalEffectState.UNKNOWN
                if parsed_approval is not None
                else CommunicationExternalEffectState.NONE
            ),
            connector_status=connector_result.status,
            connector_error_kind=(
                connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
            ),
            connector_error_code=(
                connector_result.error_code or "connector_not_completed"
            ),
            approval_ref=(
                parsed_approval.approval_ref if parsed_approval is not None else None
            ),
            approval_receipt_digest=(
                parsed_approval.authority_evidence_digest
                if parsed_approval is not None
                else None
            ),
            summary="Connector did not return a trustworthy completed effect.",
        )
    if parsed_approval is None or consumption is None:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="completed_without_authority",
            summary="Connector claimed completion without approval and contact custody.",
        )
    if recovery_stage is not None:
        from lightbulb.communication_dispatch_recovery import (
            finalize_recovered_communication_dispatch,
        )

        return finalize_recovered_communication_dispatch(
            stage=recovery_stage,
            connector_result=connector_result,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        ).materialization
    if provider_adapter.provider_name in {"gmail", "outlook"}:
        from lightbulb.communication_dispatch_recovery import (
            finalize_live_communication_dispatch,
        )

        return finalize_live_communication_dispatch(
            provider=provider_adapter.provider_name,
            route=parsed_route,
            thread=parsed_thread,
            draft=parsed_draft,
            policy_decision=parsed_policy,
            approval_grant=parsed_approval,
            reservation_consumption=consumption,
            invocation_request_digest=request.custody_fingerprint(),
            run_ref=clean_run_ref,
            idempotency_key=key,
            connector_result=connector_result,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    if (
        connector_result.error_kind is not None
        or connector_result.error_code is not None
        or connector_result.retryable
    ):
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            approval_ref=parsed_approval.approval_ref,
            approval_receipt_digest=parsed_approval.authority_evidence_digest,
            connector_error_kind=(
                connector_result.error_kind or ConnectorErrorKind.INTERNAL_ERROR
            ),
            connector_error_code=(
                connector_result.error_code or "contradictory_completion"
            ),
            summary="Connector completion carried contradictory failure metadata.",
        )
    provenance = connector_result.provenance
    if provenance is None:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            approval_ref=parsed_approval.approval_ref,
            approval_receipt_digest=parsed_approval.authority_evidence_digest,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="execution_provenance_missing",
            summary="Connector completion lacked immutable execution provenance.",
        )
    if (
        provenance.tool != provider_adapter.tool
        or provenance.tool_version != parsed_route.tool_version
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != parsed_route.connector_account_ref
        or provenance.tenant_connector_id != parsed_route.tenant_connector_id
        or provenance.project_id != parsed_route.project_id
        or provenance.route_digest != parsed_route.route_digest
        or provenance.approval_ref != parsed_approval.approval_ref
        or provenance.approval_receipt_digest
        != parsed_approval.authority_evidence_digest
        or provenance.request_digest != request.custody_fingerprint()
    ):
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            approval_ref=parsed_approval.approval_ref,
            approval_receipt_digest=parsed_approval.authority_evidence_digest,
            connector_error_kind=ConnectorErrorKind.PERMISSION_DENIED,
            connector_error_code="execution_provenance_mismatch",
            summary="Connector provenance did not match Tool, route, account, project, request, and approval.",
        )
    completed_at = _timestamp(provenance.completed_at, label="completed_at")
    consumed_at = _timestamp(consumption.consumed_at, label="consumed_at")
    if completed_at < consumed_at:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            approval_ref=parsed_approval.approval_ref,
            approval_receipt_digest=parsed_approval.authority_evidence_digest,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="completion_time_invalid",
            summary="Connector completion predates contact-reservation consumption.",
        )
    try:
        effect_proof = provider_adapter.validate_effect_output(
            connector_result.output,
            private,
            authority_binding=_authority_binding,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    except ValueError:
        return _result(
            status=CommunicationMaterializationStatus.FAILED,
            draft=parsed_draft,
            run_ref=clean_run_ref,
            idempotency_key=key,
            effect_state=CommunicationExternalEffectState.UNKNOWN,
            connector_status=connector_result.status,
            approval_ref=parsed_approval.approval_ref,
            approval_receipt_digest=parsed_approval.authority_evidence_digest,
            connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
            connector_error_code="provider_effect_proof_invalid",
            summary="Connector output did not prove the exact provider message and conversation.",
        )
    provenance_digest = communication_canonical_digest(
        provenance.model_dump(mode="json", by_alias=True)
    )
    receipt = mint_communication_artifact(
        CommunicationDispatchReceipt,
        {
            "dispatch_ref": f"dispatch:{key[-48:]}",
            "draft_digest": parsed_draft.artifact_digest,
            "policy_decision_digest": parsed_policy.artifact_digest,
            "approval_digest": parsed_approval.artifact_digest,
            "reservation_consumption_digest": consumption.artifact_digest,
            "thread_ref": parsed_thread.thread_ref,
            "thread_digest": parsed_thread.artifact_digest,
            "thread_version": parsed_thread.version,
            "thread_state": parsed_thread.state,
            "thread_participant_party_refs": (
                parsed_thread.participant_party_refs
            ),
            "parent_message_sha256": parsed_thread.parent_message_sha256,
            "purpose": parsed_draft.purpose,
            "channel": expected_channel,
            "connector_account_ref": parsed_route.connector_account_ref,
            "route_digest": parsed_route.route_digest,
            "connector_execution_provenance_digest": provenance_digest,
            "connector_effect_receipt_digest": provenance.receipt_digest,
            "provider_message_sha256": provider_adapter.provider_effect_message_sha256(
                effect_proof,
                authority_binding=_authority_binding,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            ),
            "provider_thread_sha256": provider_adapter.provider_effect_conversation_sha256(
                effect_proof,
                authority_binding=_authority_binding,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            ),
            "state": CommunicationDispatchState.ACCEPTED,
            "attempted_at": consumption.consumed_at,
            "accepted_at": provenance.completed_at,
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=parsed_draft.receipt_key_id,
    )
    materialization_status = (
        CommunicationMaterializationStatus.COMPLETED
        if effect_proof.completed
        else CommunicationMaterializationStatus.ACCEPTED
    )
    effect_state = (
        CommunicationExternalEffectState.COMPLETED
        if effect_proof.completed
        else CommunicationExternalEffectState.ACCEPTED
    )
    if effect_proof.private_dispatch is not None:
        if _authority_binding is None or _private_dispatch_sink is None:
            return _result(
                status=CommunicationMaterializationStatus.FAILED,
                draft=parsed_draft,
                run_ref=clean_run_ref,
                idempotency_key=key,
                effect_state=CommunicationExternalEffectState.UNKNOWN,
                connector_status=connector_result.status,
                approval_ref=parsed_approval.approval_ref,
                approval_receipt_digest=parsed_approval.authority_evidence_digest,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="private_dispatch_custody_unavailable",
                summary=(
                    "Provider accepted the write, but encrypted private-result "
                    "custody was unavailable; safe idempotent recovery is required."
                ),
            )
        try:
            _private_dispatch_sink.store(
                dispatch=receipt,
                authority_binding=_authority_binding,
                private_dispatch=effect_proof.private_dispatch,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            )
        except Exception:
            return _result(
                status=CommunicationMaterializationStatus.FAILED,
                draft=parsed_draft,
                run_ref=clean_run_ref,
                idempotency_key=key,
                effect_state=CommunicationExternalEffectState.UNKNOWN,
                connector_status=connector_result.status,
                approval_ref=parsed_approval.approval_ref,
                approval_receipt_digest=parsed_approval.authority_evidence_digest,
                connector_error_kind=ConnectorErrorKind.INTERNAL_ERROR,
                connector_error_code="private_dispatch_custody_failed",
                summary=(
                    "Provider accepted the write, but encrypted private-result "
                    "custody failed; safe idempotent recovery is required."
                ),
            )
    return _result(
        status=materialization_status,
        draft=parsed_draft,
        run_ref=clean_run_ref,
        idempotency_key=key,
        effect_state=effect_state,
        connector_status=connector_result.status,
        approval_ref=parsed_approval.approval_ref,
        approval_receipt_digest=parsed_approval.authority_evidence_digest,
        receipt=receipt,
        summary=(
            (
                "Completed"
                if effect_proof.completed
                else "Provider accepted; awaiting fresh observation for"
            )
            + " one approved, exact-route "
            + f"{provider_adapter.provider_name} CRM turn and minted its receipt."
        ),
    )


def _materialize_communication_turn(
    *,
    provider_adapter: CommunicationEmailMaterializerAdapter,
    authority_binding: Any = None,
    private_dispatch_sink: CommunicationPrivateDispatchSink | None = None,
    **arguments: Any,
) -> CommunicationMaterializationResult:
    """Invoke shared dispatch authority through one closed SDK provider adapter."""

    return materialize_gmail_communication_turn(
        **arguments,
        _provider_adapter=provider_adapter,
        _authority_binding=authority_binding,
        _private_dispatch_sink=private_dispatch_sink,
    )


_materialize_email_communication_turn = _materialize_communication_turn


__all__ = [
    "COMMUNICATION_GMAIL_ROUTE_SCHEMA",
    "COMMUNICATION_MATERIALIZATION_RESULT_SCHEMA",
    "COMMUNICATION_PRIVATE_GMAIL_MESSAGE_SCHEMA",
    "CommunicationContactReservationAuthority",
    "CommunicationExternalEffectState",
    "CommunicationGmailRoute",
    "CommunicationMaterializationResult",
    "CommunicationMaterializationStatus",
    "CommunicationPrivateGmailMessage",
    "communication_endpoint_address_commitment",
    "materialize_gmail_communication_turn",
]
