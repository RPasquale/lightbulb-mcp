"""Fail-closed WhatsApp webhook observation for Spring-hosted custody.

There is no certified WhatsApp status-read Tool in the SDK.  This module
therefore performs no connector call.  It accepts only an exact-scope,
host-HMAC-sealed artifact that Spring minted after authenticating and retaining
one private webhook payload.  Caller-authored provider claims are never
authenticated here, and provider acceptance is never promoted to delivery,
reply, CRM mutation, or a business outcome.

Spring remains authoritative for webhook signature verification, secret and
payload custody, RBAC, durable event idempotency, persistence, audit, and the
completeness of the retained-event history supplied to this pure evaluator.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.communication_contracts import (
    CommunicationArtifact,
    CommunicationAuthenticityGrade,
    CommunicationChannel,
    CommunicationDispatchReceipt,
    CommunicationDispatchState,
    CommunicationProviderEvent,
    CommunicationProviderEventType,
    CommunicationScopeKeyRing,
    communication_canonical_digest,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.communication_omnichannel import (
    CommunicationOmnichannelTurnBinding,
    CommunicationPrivateWhatsAppDispatch,
    NormalizedOutcome,
    NormalizedTransportState,
    OmnichannelDisposition,
    OmnichannelOutboundMode,
    OmnichannelProvider,
    ProviderObservationInput,
    ProviderObservationProposal,
    communication_mobile_private_identifier_commitment,
    normalize_provider_outcome,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.primitive_runtime import (
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
)


COMMUNICATION_WHATSAPP_WEBHOOK_OBSERVATION_SCHEMA = (
    "lightbulb.communication_whatsapp_webhook_observation.v1"
)
COMMUNICATION_WHATSAPP_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.communication_whatsapp_observation_result.v1"
)

_WHATSAPP_EVENT_ID_DOMAIN = "lightbulb.communication_whatsapp_event_id.v1"
_WHATSAPP_EVENT_IDENTITY_SCHEMA = "lightbulb.communication_whatsapp_event_identity.v1"
_WHATSAPP_WEBHOOK_EVENT_SCHEMA = "lightbulb.communication_whatsapp_webhook_event.v1"
_WHATSAPP_OBSERVATION_OPERATION_SCHEMA = (
    "lightbulb.communication_whatsapp_observation_operation.v1"
)
_ZERO_DIGEST = "0" * 64
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,159}$"
_KEY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$"
_PRIVATE_PROVIDER_ID_PATTERN = r"^[^\s\x00-\x1f\x7f]{1,512}$"
_JURISDICTION_PATTERN = r"^[A-Z]{2}(?:-[A-Z0-9]{1,8})?$"
_MAX_ARTIFACT_LIFETIME = timedelta(minutes=15)
_MAX_WEBHOOK_VERIFICATION_DELAY = timedelta(minutes=15)
_RESULT_SUMMARY = (
    "Verified and normalized one Spring-custodied WhatsApp webhook event; "
    "no connector, CRM, reply, or business-outcome effect was performed."
)

_WHATSAPP_STATUS_EVENT_TYPE: dict[str, CommunicationProviderEventType] = {
    "queued": CommunicationProviderEventType.QUEUED,
    "accepted": CommunicationProviderEventType.ACCEPTED,
    "sent": CommunicationProviderEventType.QUEUED,
    "delivery_delayed": CommunicationProviderEventType.DELIVERY_DELAYED,
    "delivered": CommunicationProviderEventType.DELIVERED,
    "read": CommunicationProviderEventType.OPENED,
    "failed": CommunicationProviderEventType.FAILED,
    "undelivered": CommunicationProviderEventType.FAILED,
}
_WHATSAPP_EVENT_RANK: dict[CommunicationProviderEventType, int] = {
    CommunicationProviderEventType.ACCEPTED: 0,
    CommunicationProviderEventType.QUEUED: 1,
    CommunicationProviderEventType.DELIVERY_DELAYED: 1,
    CommunicationProviderEventType.DELIVERED: 2,
    CommunicationProviderEventType.OPENED: 3,
}


OpaqueRef = Annotated[str, StringConstraints(pattern=_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_DIGEST_PATTERN)]
JurisdictionCode = Annotated[str, StringConstraints(pattern=_JURISDICTION_PATTERN)]
WhatsAppObservedStatus = Literal[
    "queued",
    "accepted",
    "sent",
    "delivery_delayed",
    "delivered",
    "read",
    "failed",
    "undelivered",
]
WhatsAppMode = Literal[
    OmnichannelOutboundMode.WHATSAPP_TEMPLATE,
    OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY,
]


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

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _timestamp(value: str, *, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{label} must be an exact ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    payload = (
        value.model_dump(mode="python")
        if isinstance(value, DynamicWorkflowScope)
        else value
    )
    return DynamicWorkflowScope.model_validate(payload)


def _nonzero_digest(value: str, *, label: str) -> None:
    if value == _ZERO_DIGEST:
        raise ValueError(f"{label} cannot be the zero digest")


def communication_whatsapp_private_event_id_commitment(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    connector_account_ref: str,
    route_digest: str,
    provider_event_id: str,
) -> str:
    """HMAC one private webhook event ID to exact scope, account, and route."""

    workflow_scope = _workflow_scope(scope)
    if not isinstance(key_id, str) or re.fullmatch(_KEY_ID_PATTERN, key_id) is None:
        raise ValueError("key_id must be an exact commitment-key reference")
    if (
        not isinstance(connector_account_ref, str)
        or re.fullmatch(_REF_PATTERN, connector_account_ref) is None
    ):
        raise ValueError("connector_account_ref is invalid")
    if re.fullmatch(_DIGEST_PATTERN, route_digest) is None:
        raise ValueError("route_digest must be lowercase SHA-256")
    if (
        not isinstance(provider_event_id, str)
        or re.fullmatch(_PRIVATE_PROVIDER_ID_PATTERN, provider_event_id) is None
    ):
        raise ValueError("provider_event_id is invalid")
    commitment = scope_keyring.sign(
        key_id,
        _WHATSAPP_EVENT_ID_DOMAIN,
        {
            "schema": _WHATSAPP_EVENT_ID_DOMAIN,
            "tenant_id": workflow_scope.tenant_id,
            "company_id": workflow_scope.company_id,
            "user_id": workflow_scope.user_id,
            "project_ref": workflow_scope.project_ref,
            "connector_account_ref": connector_account_ref,
            "route_digest": route_digest,
            "provider_event_id": provider_event_id,
        },
    )
    if not isinstance(commitment, bytes) or len(commitment) != 32:
        raise ValueError("scope keyring must return one SHA-256 HMAC commitment")
    return commitment.hex()


def whatsapp_provider_event_identity_digest(
    *,
    exact_scope_digest: str,
    dispatch_receipt_digest: str,
    authority_binding_digest: str,
    connector_account_ref: str,
    route_digest: str,
    provider_message_sha256: str,
    provider_event_id_hmac_v1: str,
) -> str:
    """Derive the stable, private-ID-free identity for one provider event."""

    return communication_canonical_digest(
        {
            "schema": _WHATSAPP_EVENT_IDENTITY_SCHEMA,
            "exact_scope_digest": exact_scope_digest,
            "dispatch_receipt_digest": dispatch_receipt_digest,
            "authority_binding_digest": authority_binding_digest,
            "connector_account_ref": connector_account_ref,
            "route_digest": route_digest,
            "provider_message_sha256": provider_message_sha256,
            "provider_event_id_hmac_v1": provider_event_id_hmac_v1,
        }
    )


def whatsapp_webhook_event_digest(
    *,
    provider_event_identity_digest: str,
    provider: OmnichannelProvider,
    channel: CommunicationChannel,
    mode: OmnichannelOutboundMode,
    provider_status: WhatsAppObservedStatus,
    jurisdiction: str,
    provider_conversation_sha256: str,
    body_sha256: str,
    private_payload_ref: str,
    provider_payload_sha256: str,
    authenticity_proof_ref: str,
    authenticity_proof_digest: str,
    webhook_signature_algorithm: str,
    webhook_signature_key_ref: str,
    webhook_signature_key_version: int,
    custody_ref: str,
    custody_digest: str,
    retention_policy_ref: str,
    retained_until: str,
    occurred_at: str,
    received_at: str,
    observed_at: str,
) -> str:
    """Digest the exact public commitments in one private webhook event."""

    return communication_canonical_digest(
        {
            "schema": _WHATSAPP_WEBHOOK_EVENT_SCHEMA,
            "provider_event_identity_digest": provider_event_identity_digest,
            "provider": provider,
            "channel": channel,
            "mode": mode,
            "provider_status": provider_status,
            "jurisdiction": jurisdiction,
            "provider_conversation_sha256": provider_conversation_sha256,
            "body_sha256": body_sha256,
            "private_payload_ref": private_payload_ref,
            "provider_payload_sha256": provider_payload_sha256,
            "authenticity_proof_ref": authenticity_proof_ref,
            "authenticity_proof_digest": authenticity_proof_digest,
            "webhook_signature_algorithm": webhook_signature_algorithm,
            "webhook_signature_key_ref": webhook_signature_key_ref,
            "webhook_signature_key_version": webhook_signature_key_version,
            "custody_ref": custody_ref,
            "custody_digest": custody_digest,
            "retention_policy_ref": retention_policy_ref,
            "retained_until": _timestamp(retained_until, label="retained_until"),
            "occurred_at": _timestamp(occurred_at, label="occurred_at"),
            "received_at": _timestamp(received_at, label="received_at"),
            "observed_at": _timestamp(observed_at, label="observed_at"),
        }
    )


class CommunicationWhatsAppWebhookObservation(CommunicationArtifact):
    """Spring-sealed proof of one authenticated, privately retained webhook."""

    schema_id: Literal["lightbulb.communication_whatsapp_webhook_observation.v1"] = (
        Field(default=COMMUNICATION_WHATSAPP_WEBHOOK_OBSERVATION_SCHEMA, alias="schema")
    )
    observation_ref: OpaqueRef
    event_ref: OpaqueRef
    provider: Literal[OmnichannelProvider.WHATSAPP_CLOUD] = (
        OmnichannelProvider.WHATSAPP_CLOUD
    )
    channel: Literal[CommunicationChannel.WHATSAPP] = CommunicationChannel.WHATSAPP
    mode: WhatsAppMode
    dispatch_receipt_digest: Sha256Digest
    authority_binding_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    provider_message_sha256: Sha256Digest
    provider_conversation_sha256: Sha256Digest
    body_sha256: Sha256Digest
    jurisdiction: JurisdictionCode
    provider_event_id_hmac_v1: Sha256Digest
    provider_event_identity_digest: Sha256Digest
    provider_status: WhatsAppObservedStatus
    private_payload_ref: OpaqueRef
    provider_payload_sha256: Sha256Digest
    webhook_event_digest: Sha256Digest
    authenticity: Literal[CommunicationAuthenticityGrade.VERIFIED] = (
        CommunicationAuthenticityGrade.VERIFIED
    )
    authenticity_proof_ref: OpaqueRef
    authenticity_proof_digest: Sha256Digest
    webhook_signature_algorithm: Literal["hmac_sha256"] = "hmac_sha256"
    webhook_signature_key_ref: OpaqueRef
    webhook_signature_key_version: int = Field(ge=1)
    webhook_signature_verified: Literal[True] = True
    custody: Literal["spring_verified_webhook"] = "spring_verified_webhook"
    custody_ref: OpaqueRef
    custody_digest: Sha256Digest
    private_payload_custodied: Literal[True] = True
    retention_policy_ref: OpaqueRef
    retained_until: str
    occurred_at: str
    received_at: str
    observed_at: str
    valid_until: str

    @field_validator(
        "occurred_at",
        "received_at",
        "observed_at",
        "valid_until",
        "retained_until",
    )
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _spring_proof_is_exact(self) -> "CommunicationWhatsAppWebhookObservation":
        artifact_refs = (
            self.observation_ref,
            self.event_ref,
            self.private_payload_ref,
            self.authenticity_proof_ref,
            self.webhook_signature_key_ref,
            self.custody_ref,
            self.retention_policy_ref,
        )
        if len(set(artifact_refs)) != len(artifact_refs):
            raise ValueError("WhatsApp observation artifact references must be unique")
        for label, value in (
            ("dispatch receipt digest", self.dispatch_receipt_digest),
            ("authority binding digest", self.authority_binding_digest),
            ("provider message commitment", self.provider_message_sha256),
            ("provider conversation commitment", self.provider_conversation_sha256),
            ("body commitment", self.body_sha256),
            ("provider event ID commitment", self.provider_event_id_hmac_v1),
            ("provider event identity digest", self.provider_event_identity_digest),
            ("provider payload commitment", self.provider_payload_sha256),
            ("webhook event digest", self.webhook_event_digest),
            ("authenticity proof digest", self.authenticity_proof_digest),
            ("custody digest", self.custody_digest),
            ("route digest", self.route_digest),
        ):
            _nonzero_digest(value, label=label)
        occurred = _parsed(self.occurred_at)
        received = _parsed(self.received_at)
        observed = _parsed(self.observed_at)
        valid_until = _parsed(self.valid_until)
        retained_until = _parsed(self.retained_until)
        if not occurred <= received <= observed < valid_until:
            raise ValueError(
                "WhatsApp event timestamps must follow occurrence, receipt, "
                "verification, and expiry order"
            )
        if valid_until - observed > _MAX_ARTIFACT_LIFETIME:
            raise ValueError("WhatsApp webhook proof lifetime cannot exceed 15 minutes")
        if observed - received > _MAX_WEBHOOK_VERIFICATION_DELAY:
            raise ValueError(
                "WhatsApp webhook verification delay cannot exceed 15 minutes"
            )
        if retained_until <= valid_until:
            raise ValueError(
                "WhatsApp private payload retention must outlive the observation proof"
            )
        if self.provider_commitment_key_id != self.receipt_key_id:
            raise ValueError(
                "provider commitments and Spring artifact seal require one key epoch"
            )
        expected_identity = whatsapp_provider_event_identity_digest(
            exact_scope_digest=self.exact_scope_digest,
            dispatch_receipt_digest=self.dispatch_receipt_digest,
            authority_binding_digest=self.authority_binding_digest,
            connector_account_ref=self.connector_account_ref,
            route_digest=self.route_digest,
            provider_message_sha256=self.provider_message_sha256,
            provider_event_id_hmac_v1=self.provider_event_id_hmac_v1,
        )
        if not hmac.compare_digest(
            self.provider_event_identity_digest,
            expected_identity,
        ):
            raise ValueError("provider event identity digest is not canonical")
        expected_event = whatsapp_webhook_event_digest(
            provider_event_identity_digest=expected_identity,
            provider=self.provider,
            channel=self.channel,
            mode=self.mode,
            provider_status=self.provider_status,
            jurisdiction=self.jurisdiction,
            provider_conversation_sha256=self.provider_conversation_sha256,
            body_sha256=self.body_sha256,
            private_payload_ref=self.private_payload_ref,
            provider_payload_sha256=self.provider_payload_sha256,
            authenticity_proof_ref=self.authenticity_proof_ref,
            authenticity_proof_digest=self.authenticity_proof_digest,
            webhook_signature_algorithm=self.webhook_signature_algorithm,
            webhook_signature_key_ref=self.webhook_signature_key_ref,
            webhook_signature_key_version=self.webhook_signature_key_version,
            custody_ref=self.custody_ref,
            custody_digest=self.custody_digest,
            retention_policy_ref=self.retention_policy_ref,
            retained_until=self.retained_until,
            occurred_at=self.occurred_at,
            received_at=self.received_at,
            observed_at=self.observed_at,
        )
        if not hmac.compare_digest(self.webhook_event_digest, expected_event):
            raise ValueError("webhook_event_digest is not canonical")
        return self


class WhatsAppObservationEffectBoundary(_StrictModel):
    connector_calls: Literal[0] = 0
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    local_or_host_state_written: Literal[False] = False
    provider_event_persisted: Literal[False] = False
    audit_written: Literal[False] = False
    external_systems_changed: Literal[False] = False
    crm_mutated: Literal[False] = False
    message_dispatched: Literal[False] = False
    provider_acceptance_promoted_to_delivery: Literal[False] = False
    reply_claimed: Literal[False] = False
    business_outcome_claimed: Literal[False] = False
    caller_claims_authenticated: Literal[False] = False
    spring_webhook_authentication_required: Literal[True] = True
    spring_durable_replay_custody_required: Literal[True] = True


def _operation_digest(
    *,
    observation: CommunicationWhatsAppWebhookObservation,
    dispatch_receipt_digest: str,
    authority_binding_digest: str,
    event_digest: str,
    normalized_digest: str,
    retained_event_digests: Sequence[str],
) -> str:
    return communication_canonical_digest(
        {
            "schema": _WHATSAPP_OBSERVATION_OPERATION_SCHEMA,
            "exact_scope_digest": observation.exact_scope_digest,
            "observation_artifact_digest": observation.artifact_digest,
            "dispatch_receipt_digest": dispatch_receipt_digest,
            "authority_binding_digest": authority_binding_digest,
            "event_digest": event_digest,
            "normalized_digest": normalized_digest,
            "retained_event_digests": sorted(retained_event_digests),
        }
    )


class WhatsAppObservationResult(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_whatsapp_observation_result.v1"] = (
        Field(default=COMMUNICATION_WHATSAPP_OBSERVATION_RESULT_SCHEMA, alias="schema")
    )
    status: Literal["completed"] = "completed"
    observation: CommunicationWhatsAppWebhookObservation
    dispatch_receipt_digest: Sha256Digest
    authority_binding_digest: Sha256Digest
    event: CommunicationProviderEvent
    normalized: ProviderObservationProposal
    retained_event_digests: tuple[Sha256Digest, ...] = Field(
        default=(),
        max_length=1_000,
    )
    operation_digest: Sha256Digest
    summary: str = Field(min_length=1, max_length=1_000)
    effect_boundary: WhatsAppObservationEffectBoundary = Field(
        default_factory=WhatsAppObservationEffectBoundary
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)

    @field_validator("retained_event_digests", mode="before")
    @classmethod
    def _retained_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _result_is_self_proving(self) -> "WhatsAppObservationResult":
        if tuple(sorted(self.retained_event_digests)) != self.retained_event_digests:
            raise ValueError("retained event digests must be canonical and sorted")
        if len(set(self.retained_event_digests)) != len(self.retained_event_digests):
            raise ValueError("retained event digests must be unique")
        observation = self.observation
        event = self.event
        normalized = self.normalized
        if event.artifact_digest in self.retained_event_digests:
            raise ValueError("current provider event cannot already be retained")
        if (
            self.receipt_key_id != observation.receipt_key_id
            or event.receipt_key_id != observation.receipt_key_id
            or self.exact_scope_digest != observation.exact_scope_digest
            or event.exact_scope_digest != observation.exact_scope_digest
        ):
            raise ValueError(
                "result, observation, and provider event require one scope and key epoch"
            )
        if (
            self.dispatch_receipt_digest != observation.dispatch_receipt_digest
            or self.authority_binding_digest != observation.authority_binding_digest
            or event.event_ref != observation.event_ref
            or event.dispatch_receipt_digest != self.dispatch_receipt_digest
            or event.connector_account_ref != observation.connector_account_ref
            or event.route_digest != observation.route_digest
            or event.provider_event_sha256 != observation.provider_event_identity_digest
            or event.provider_message_sha256 != observation.provider_message_sha256
            or event.provider_thread_sha256 != observation.provider_conversation_sha256
            or event.authenticity != CommunicationAuthenticityGrade.VERIFIED
            or event.authenticity_evidence_digest
            != observation.authenticity_proof_digest
            or event.private_payload_ref != observation.private_payload_ref
            or event.payload_sha256 != observation.provider_payload_sha256
            or event.occurred_at != observation.occurred_at
            or event.received_at != observation.received_at
        ):
            raise ValueError("provider event does not exactly bind the Spring proof")
        expected_event_type = _WHATSAPP_STATUS_EVENT_TYPE[observation.provider_status]
        if event.event_type != expected_event_type:
            raise ValueError("provider event type does not match the verified status")
        expected_normalized = _expected_normalization(
            observation=observation,
            provider_event_digest=event.artifact_digest,
        )
        if normalized != expected_normalized:
            raise ValueError("normalization does not exactly bind the verified event")
        if self.summary != _RESULT_SUMMARY:
            raise ValueError("result summary cannot claim an unperformed effect")
        expected_operation = _operation_digest(
            observation=observation,
            dispatch_receipt_digest=self.dispatch_receipt_digest,
            authority_binding_digest=self.authority_binding_digest,
            event_digest=event.artifact_digest,
            normalized_digest=normalized.proposal_digest,
            retained_event_digests=self.retained_event_digests,
        )
        if not hmac.compare_digest(self.operation_digest, expected_operation):
            raise ValueError("operation_digest does not bind the exact observation")
        return self


def _verified_retained_events(
    values: Sequence[CommunicationProviderEvent | Mapping[str, Any]],
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: CommunicationScopeKeyRing,
) -> tuple[CommunicationProviderEvent, ...]:
    if len(values) > 1_000:
        raise ValueError("retained WhatsApp event history exceeds 1,000 artifacts")
    retained = tuple(
        verify_communication_artifact(
            value,
            artifact_type=CommunicationProviderEvent,
            scope=scope,
            scope_keyring=scope_keyring,
        )
        for value in values
    )
    for label, identities in (
        ("retained event reference", [item.event_ref for item in retained]),
        (
            "retained provider event identity",
            [item.provider_event_sha256 for item in retained],
        ),
        (
            "retained private payload reference",
            [item.private_payload_ref for item in retained],
        ),
        ("retained event artifact", [item.artifact_digest for item in retained]),
    ):
        if len(identities) != len(set(identities)):
            raise ValueError(f"{label} values must be unique")
    return retained


def _validate_retained_history(
    *,
    observation: CommunicationWhatsAppWebhookObservation,
    retained: Sequence[CommunicationProviderEvent],
    dispatch_accepted_at: str,
) -> None:
    accepted_at = _parsed(dispatch_accepted_at)
    snapshot_at = _parsed(observation.observed_at)
    for prior in retained:
        if (
            prior.receipt_key_id != observation.receipt_key_id
            or prior.exact_scope_digest != observation.exact_scope_digest
            or prior.dispatch_receipt_digest != observation.dispatch_receipt_digest
            or prior.connector_account_ref != observation.connector_account_ref
            or prior.route_digest != observation.route_digest
            or prior.provider_message_sha256 != observation.provider_message_sha256
            or prior.provider_thread_sha256 != observation.provider_conversation_sha256
        ):
            raise ValueError(
                "retained WhatsApp event history is outside the exact dispatch"
            )
        if (
            prior.authenticity != CommunicationAuthenticityGrade.VERIFIED
            or prior.authenticity_evidence_digest is None
            or prior.authenticity_evidence_digest == _ZERO_DIGEST
            or prior.provider_event_sha256 == _ZERO_DIGEST
            or prior.payload_sha256 == _ZERO_DIGEST
        ):
            raise ValueError("retained WhatsApp event lacks verified nonzero evidence")
        if prior.event_type not in _WHATSAPP_EVENT_RANK and (
            prior.event_type != CommunicationProviderEventType.FAILED
        ):
            raise ValueError(
                "retained event type is outside the reviewed WhatsApp status map"
            )
        if _parsed(prior.occurred_at) < accepted_at:
            raise ValueError("retained WhatsApp event predates dispatch acceptance")
        if _parsed(prior.received_at) > snapshot_at:
            raise ValueError(
                "retained WhatsApp history includes evidence after the observation snapshot"
            )

    current_type = _WHATSAPP_STATUS_EVENT_TYPE[observation.provider_status]
    timeline = [
        (
            _parsed(item.occurred_at),
            _parsed(item.received_at),
            item.event_ref,
            item.event_type,
        )
        for item in retained
    ]
    timeline.append(
        (
            _parsed(observation.occurred_at),
            _parsed(observation.received_at),
            observation.event_ref,
            current_type,
        )
    )
    ordered = sorted(
        timeline,
        key=lambda item: (
            item[0],
            (
                4
                if item[3] == CommunicationProviderEventType.FAILED
                else _WHATSAPP_EVENT_RANK[item[3]]
            ),
            item[1],
            item[2],
        ),
    )
    for previous, following in zip(ordered, ordered[1:]):
        previous_type = previous[3]
        following_type = following[3]
        if previous_type == CommunicationProviderEventType.FAILED:
            if following_type != CommunicationProviderEventType.FAILED:
                raise ValueError(
                    "WhatsApp status history regresses after terminal failure"
                )
            continue
        if following_type == CommunicationProviderEventType.FAILED:
            if (
                _WHATSAPP_EVENT_RANK[previous_type]
                >= _WHATSAPP_EVENT_RANK[CommunicationProviderEventType.DELIVERED]
            ):
                raise ValueError("WhatsApp status history regresses after delivery")
            continue
        if _WHATSAPP_EVENT_RANK[following_type] < _WHATSAPP_EVENT_RANK[previous_type]:
            raise ValueError("WhatsApp status history regresses chronologically")


def _reject_replay_or_conflict(
    observation: CommunicationWhatsAppWebhookObservation,
    retained: Sequence[CommunicationProviderEvent],
) -> None:
    for prior in retained:
        if prior.event_ref == observation.event_ref:
            if (
                prior.provider_event_sha256
                == observation.provider_event_identity_digest
                and prior.payload_sha256 == observation.provider_payload_sha256
            ):
                raise ValueError("WhatsApp event was already retained; do not replay")
            raise ValueError("WhatsApp event_ref conflicts with retained evidence")
        if prior.provider_event_sha256 == observation.provider_event_identity_digest:
            raise ValueError(
                "WhatsApp provider event identity was already retained; do not replay"
            )
        if prior.private_payload_ref == observation.private_payload_ref:
            raise ValueError(
                "WhatsApp private payload reference conflicts with retained evidence"
            )


def _normalization_evidence(
    observation: CommunicationWhatsAppWebhookObservation,
) -> PrimitiveEvidenceRef:
    return PrimitiveEvidenceRef(
        evidence_ref=f"whatsapp-auth:{observation.event_ref}",
        kind="provider_event_authenticity",
        issuer_ref="spring-control-plane:whatsapp-webhook-verifier",
        subject_ref=observation.observation_ref,
        sha256=observation.authenticity_proof_digest,
        observed_at=observation.observed_at,
        effective_at=observation.occurred_at,
        verification_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
        classification="restricted",
        retention_policy=observation.retention_policy_ref,
        jurisdiction=observation.jurisdiction,
    )


def _normalization_input(
    *,
    observation: CommunicationWhatsAppWebhookObservation,
    provider_event_digest: str,
    evidence: PrimitiveEvidenceRef,
    analysis_as_of: str,
) -> ProviderObservationInput:
    return ProviderObservationInput(
        observation_ref=observation.observation_ref,
        analysis_as_of=analysis_as_of,
        provider=OmnichannelProvider.WHATSAPP_CLOUD,
        channel=CommunicationChannel.WHATSAPP,
        provider_status=observation.provider_status,
        dispatch_receipt_digest=observation.dispatch_receipt_digest,
        provider_event_digest=provider_event_digest,
        provider_message_digest=observation.provider_message_sha256,
        connector_account_ref=observation.connector_account_ref,
        route_digest=observation.route_digest,
        authenticity=CommunicationAuthenticityGrade.VERIFIED,
        authenticity_evidence_digest=observation.authenticity_proof_digest,
        occurred_at=observation.occurred_at,
        received_at=observation.received_at,
        evidence_refs=(evidence,),
    )


def _expected_normalization(
    *,
    observation: CommunicationWhatsAppWebhookObservation,
    provider_event_digest: str,
) -> ProviderObservationProposal:
    return normalize_provider_outcome(
        _normalization_input(
            observation=observation,
            provider_event_digest=provider_event_digest,
            evidence=_normalization_evidence(observation),
            analysis_as_of=observation.observed_at,
        )
    )


def observe_whatsapp_delivery(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    dispatch_receipt: CommunicationDispatchReceipt | Mapping[str, Any],
    omnichannel_binding: CommunicationOmnichannelTurnBinding | Mapping[str, Any],
    private_dispatch: CommunicationPrivateWhatsAppDispatch | Mapping[str, Any],
    observation_artifact: CommunicationWhatsAppWebhookObservation | Mapping[str, Any],
    observed_at: datetime,
    retained_events: Sequence[CommunicationProviderEvent | Mapping[str, Any]] = (),
) -> WhatsAppObservationResult:
    """Verify and normalize one Spring-authenticated WhatsApp webhook event.

    The function has no executor argument and performs zero provider reads or
    writes.  A signed artifact proves Spring custody; it does not make this SDK
    evaluator a webhook authenticator or a durable replay ledger.
    """

    current = _utc(observed_at, label="observed_at")
    workflow_scope = _workflow_scope(scope)
    receipt = verify_communication_artifact(
        dispatch_receipt,
        artifact_type=CommunicationDispatchReceipt,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    binding = verify_communication_artifact(
        omnichannel_binding,
        artifact_type=CommunicationOmnichannelTurnBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    observation = verify_communication_artifact(
        observation_artifact,
        artifact_type=CommunicationWhatsAppWebhookObservation,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        at=current,
    )
    private = CommunicationPrivateWhatsAppDispatch.model_validate(private_dispatch)
    retained = _verified_retained_events(
        retained_events,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    _reject_replay_or_conflict(observation, retained)

    if (
        binding.channel != CommunicationChannel.WHATSAPP
        or binding.mode
        not in {
            OmnichannelOutboundMode.WHATSAPP_TEMPLATE,
            OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY,
        }
        or binding.status_route_digest is not None
        or binding.status_tool is not None
        or binding.status_tool_version is not None
    ):
        raise ValueError("WhatsApp observation requires a sealed WhatsApp-only binding")
    if binding.project_ref != workflow_scope.project_ref:
        raise ValueError(
            "WhatsApp binding payload does not match authenticated project scope"
        )
    if binding.recipient_party_ref not in binding.thread_participant_party_refs:
        raise ValueError("WhatsApp recipient must be a sealed conversation participant")
    if binding.provider_commitment_key_id != binding.receipt_key_id:
        raise ValueError("WhatsApp binding crosses provider commitment key epochs")
    for label, value in (
        ("binding draft digest", binding.draft_digest),
        ("binding thread digest", binding.thread_digest),
        ("binding jurisdiction policy digest", binding.jurisdiction_policy_digest),
        ("binding sender endpoint digest", binding.sender_endpoint_digest),
        ("binding recipient party digest", binding.recipient_party_digest),
        ("binding recipient endpoint digest", binding.recipient_endpoint_digest),
        ("binding body digest", binding.body_sha256),
        ("binding write route digest", binding.write_route_digest),
        ("binding sender resource commitment", binding.sender_resource_hmac_v1),
        ("binding recipient address commitment", binding.recipient_address_hmac_v1),
        (
            "binding provider conversation commitment",
            binding.provider_conversation_sha256,
        ),
    ):
        _nonzero_digest(value, label=label)
    if (
        receipt.state != CommunicationDispatchState.ACCEPTED
        or receipt.accepted_at is None
        or receipt.channel != CommunicationChannel.WHATSAPP
        or receipt.draft_digest != binding.draft_digest
        or receipt.thread_ref != binding.thread_ref
        or receipt.thread_digest != binding.thread_digest
        or receipt.thread_version != binding.thread_version
        or receipt.thread_state != binding.thread_state
        or receipt.thread_participant_party_refs
        != binding.thread_participant_party_refs
        or receipt.parent_message_sha256 != binding.parent_message_sha256
        or receipt.connector_account_ref != binding.connector_account_ref
        or receipt.route_digest != binding.write_route_digest
        or receipt.receipt_key_id != binding.provider_commitment_key_id
        or receipt.provider_message_sha256 is None
        or receipt.provider_thread_sha256 != binding.provider_conversation_sha256
    ):
        raise ValueError("WhatsApp dispatch receipt does not match sealed authority")
    for label, value in (
        ("dispatch policy decision digest", receipt.policy_decision_digest),
        ("dispatch approval digest", receipt.approval_digest),
        (
            "dispatch reservation consumption digest",
            receipt.reservation_consumption_digest,
        ),
        (
            "dispatch connector execution provenance digest",
            receipt.connector_execution_provenance_digest,
        ),
        (
            "dispatch connector effect receipt digest",
            receipt.connector_effect_receipt_digest,
        ),
    ):
        _nonzero_digest(value, label=label)
    expected_message_commitment = communication_mobile_private_identifier_commitment(
        scope=workflow_scope,
        key_id=binding.provider_commitment_key_id,
        scope_keyring=scope_keyring,
        channel=CommunicationChannel.WHATSAPP,
        connector_account_ref=binding.connector_account_ref,
        route_digest=binding.write_route_digest,
        identifier_kind="provider_message_id",
        value=private.provider_message_id,
    )
    if (
        private.mode != binding.mode
        or private.authority_binding_digest != binding.artifact_digest
        or private.provider_commitment_key_id != binding.provider_commitment_key_id
        or private.provider_commitment_key_id != binding.receipt_key_id
        or not hmac.compare_digest(
            private.provider_message_id_hmac_v1,
            expected_message_commitment,
        )
        or not hmac.compare_digest(
            receipt.provider_message_sha256,
            expected_message_commitment,
        )
        or not hmac.compare_digest(
            private.provider_conversation_sha256,
            binding.provider_conversation_sha256,
        )
        or not hmac.compare_digest(private.body_sha256, binding.body_sha256)
    ):
        raise ValueError(
            "private WhatsApp dispatch does not match retained commitments"
        )
    if (
        observation.mode != binding.mode
        or observation.jurisdiction != binding.jurisdiction
        or observation.dispatch_receipt_digest != receipt.artifact_digest
        or observation.authority_binding_digest != binding.artifact_digest
        or observation.connector_account_ref != binding.connector_account_ref
        or observation.route_digest != binding.write_route_digest
        or observation.provider_commitment_key_id != binding.provider_commitment_key_id
        or not hmac.compare_digest(
            observation.provider_message_sha256,
            expected_message_commitment,
        )
        or not hmac.compare_digest(
            observation.provider_conversation_sha256,
            binding.provider_conversation_sha256,
        )
        or not hmac.compare_digest(observation.body_sha256, binding.body_sha256)
    ):
        raise ValueError(
            "Spring WhatsApp observation does not match dispatch authority"
        )
    bound_at = _parsed(binding.bound_at)
    attempted_at = _parsed(receipt.attempted_at)
    accepted_at = _parsed(receipt.accepted_at)
    if not bound_at <= attempted_at <= accepted_at <= _parsed(observation.occurred_at):
        raise ValueError(
            "WhatsApp observation cannot precede binding, dispatch, or acceptance"
        )
    _validate_retained_history(
        observation=observation,
        retained=retained,
        dispatch_accepted_at=receipt.accepted_at,
    )

    provisional = _expected_normalization(
        observation=observation,
        provider_event_digest=observation.artifact_digest,
    )
    if (
        not provisional.conclusive
        or provisional.proposed_disposition != OmnichannelDisposition.READY
        or provisional.provider_event_type is None
    ):
        raise ValueError("Spring WhatsApp observation did not normalize conclusively")
    event = mint_communication_artifact(
        CommunicationProviderEvent,
        {
            "event_ref": observation.event_ref,
            "event_type": provisional.provider_event_type,
            "dispatch_receipt_digest": receipt.artifact_digest,
            "connector_account_ref": binding.connector_account_ref,
            "route_digest": binding.write_route_digest,
            "provider_event_sha256": observation.provider_event_identity_digest,
            "provider_message_sha256": expected_message_commitment,
            "provider_thread_sha256": binding.provider_conversation_sha256,
            "authenticity": CommunicationAuthenticityGrade.VERIFIED,
            "authenticity_evidence_digest": observation.authenticity_proof_digest,
            "private_payload_ref": observation.private_payload_ref,
            "payload_sha256": observation.provider_payload_sha256,
            "occurred_at": observation.occurred_at,
            "received_at": observation.received_at,
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=binding.provider_commitment_key_id,
    )
    normalized = _expected_normalization(
        observation=observation,
        provider_event_digest=event.artifact_digest,
    )
    if (
        not normalized.conclusive
        or normalized.provider_event_type != event.event_type
        or normalized.transport_state == NormalizedTransportState.UNKNOWN
        or normalized.outcome == NormalizedOutcome.UNKNOWN
    ):
        raise ValueError("final WhatsApp normalization lost verified event meaning")
    retained_digests = tuple(sorted(item.artifact_digest for item in retained))
    operation_digest = _operation_digest(
        observation=observation,
        dispatch_receipt_digest=receipt.artifact_digest,
        authority_binding_digest=binding.artifact_digest,
        event_digest=event.artifact_digest,
        normalized_digest=normalized.proposal_digest,
        retained_event_digests=retained_digests,
    )
    return mint_communication_artifact(
        WhatsAppObservationResult,
        {
            "observation": observation,
            "dispatch_receipt_digest": receipt.artifact_digest,
            "authority_binding_digest": binding.artifact_digest,
            "event": event,
            "normalized": normalized,
            "retained_event_digests": retained_digests,
            "operation_digest": operation_digest,
            "summary": _RESULT_SUMMARY,
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=binding.provider_commitment_key_id,
    )


__all__ = [
    "COMMUNICATION_WHATSAPP_OBSERVATION_RESULT_SCHEMA",
    "COMMUNICATION_WHATSAPP_WEBHOOK_OBSERVATION_SCHEMA",
    "CommunicationWhatsAppWebhookObservation",
    "WhatsAppObservationEffectBoundary",
    "WhatsAppObservationResult",
    "communication_whatsapp_private_event_id_commitment",
    "observe_whatsapp_delivery",
    "whatsapp_provider_event_identity_digest",
    "whatsapp_webhook_event_digest",
]
