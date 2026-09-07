"""Governed omnichannel contracts, planning, materialization, and observation.

This module closes SDK-owned contract gaps without becoming a communication
authority.  Deterministic evaluators perform no connector calls and only emit
content-bound proposals.  SMS and WhatsApp live materializers reuse the shared
communication materialization rail and reject every executor except
``HostedConnectorExecutor``; Spring still resolves tenant/company scope, RBAC,
contact policy, approval, route, credential, idempotency, and audit custody.
Provider runtimes alone perform network effects.

Voice planning remains read-only, while the separate materializer/observer use
only the exact ``twilio.place_call_turn`` and ``twilio.lookup_call_status``
Tools through ``HostedConnectorExecutor``. The SDK never accepts arbitrary
TwiML, callback URLs, transfers, provider credentials, or raw destinations in
durable plans. Legacy ``twilio.place_call`` is never dispatch authority.

Implementation contract
-----------------------

* Cross-channel identity results never merge or mutate identities.
* Jurisdiction policy proposals never grant consent or override suppression.
* Provider acceptance is distinct from delivery, reply, answer, and outcome.
* Unverified, future, stale, mismatched, or weak evidence fails closed.
* Raw addresses, provider identifiers, content, and template parameters remain
  transient; durable contracts retain keyed commitments and opaque references.
* Production writes are possible only through the shared hosted, approved,
  exact-route dispatch rail.  SDK support does not activate a dark Spring Tool.
* SMS/WhatsApp/voice ambiguous acceptance must never be converted into an
  automatic resend. Certified recovery requires Spring journal/outbox custody;
  transports without that custody remain fail-closed and explicitly dark.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any, Literal, Mapping, Sequence
from uuid import UUID

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
    CommunicationConsentStatus,
    CommunicationDispatchReceipt,
    CommunicationEndpointBinding,
    CommunicationFrequencyStatus,
    CommunicationMessageDraft,
    CommunicationPartyKind,
    CommunicationPartyRef,
    CommunicationPolicyDisposition,
    CommunicationProviderEvent,
    CommunicationProviderEventType,
    CommunicationPurpose,
    CommunicationQuietHoursStatus,
    CommunicationScopeKeyRing,
    CommunicationSuppressionStatus,
    CommunicationThreadState,
    CommunicationTrustGrade,
    communication_canonical_digest,
    communication_private_value_digest,
    mint_communication_artifact,
    verify_communication_artifact,
)
from lightbulb.communication_materializer import (
    CommunicationEmailEffectProof,
    CommunicationMaterializationResult,
    CommunicationPrivateDispatchSink,
    _materialize_communication_turn,
)
from lightbulb.communication_twilio_sms import (
    TWILIO_LOOKUP_MESSAGE_STATUS_TOOL,
    TWILIO_SEND_SMS_TOOL,
    CommunicationPrivateTwilioSmsDispatch,
    CommunicationTwilioSmsStatusRoute,
    CommunicationTwilioSmsWriteRoute,
    TwilioSmsAcceptance,
    TwilioSmsProviderStatus,
    TwilioSmsStatus,
    canonical_twilio_e164,
    communication_twilio_sms_private_identifier_commitment,
)
from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorExecutionProvenance,
    ConnectorExecutionRequest,
    ConnectorExecutionResult,
    ConnectorExecutionStatus,
    ExecutionScope,
    HostedConnectorExecutor,
)
from lightbulb.dynamic_workflows import DynamicWorkflowScope
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceRef,
    PrimitiveEvidenceVerificationGrade,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
    PrimitiveOperationFreshnessClass,
    PrimitiveOperationReceipt,
    PrimitiveOperationRecoveryPolicy,
    PrimitiveOperationReplayClass,
    PrimitiveOperationSpec,
    PrimitiveOperationStatus,
    revalidate_model_boundary,
)


WHATSAPP_SEND_TEMPLATE_TOOL = "whatsapp.send_template_turn"
WHATSAPP_REPLY_SERVICE_WINDOW_TOOL = "whatsapp.reply_service_window_turn"
TWILIO_PLACE_CALL_TURN_TOOL = "twilio.place_call_turn"
TWILIO_LOOKUP_CALL_STATUS_TOOL = "twilio.lookup_call_status"

COMMUNICATION_JURISDICTION_POLICY_DECISION_SCHEMA = (
    "lightbulb.communication_jurisdiction_channel_policy_decision.v1"
)
COMMUNICATION_OMNICHANNEL_TURN_BINDING_SCHEMA = (
    "lightbulb.communication_omnichannel_turn_binding.v1"
)
COMMUNICATION_PRIVATE_OMNICHANNEL_TURN_SCHEMA = (
    "lightbulb.communication_private_omnichannel_turn.v1"
)
COMMUNICATION_WHATSAPP_WRITE_ROUTE_SCHEMA = (
    "lightbulb.communication_whatsapp_write_route.v1"
)
COMMUNICATION_PRIVATE_WHATSAPP_DISPATCH_SCHEMA = (
    "lightbulb.communication_private_whatsapp_dispatch.v1"
)
WHATSAPP_ACCEPTANCE_SCHEMA = "lightbulb.whatsapp_acceptance.v1"
CROSS_CHANNEL_IDENTITY_INPUT_SCHEMA = (
    "lightbulb.communication_cross_channel_identity_input.v1"
)
CROSS_CHANNEL_IDENTITY_PROPOSAL_SCHEMA = (
    "lightbulb.communication_cross_channel_identity_proposal.v1"
)
JURISDICTION_CHANNEL_POLICY_INPUT_SCHEMA = (
    "lightbulb.communication_jurisdiction_channel_policy_input.v1"
)
JURISDICTION_CHANNEL_POLICY_PROPOSAL_SCHEMA = (
    "lightbulb.communication_jurisdiction_channel_policy_proposal.v1"
)
VOICE_CALL_PLAN_INPUT_SCHEMA = "lightbulb.communication_voice_call_plan_input.v1"
VOICE_CALL_PLAN_PROPOSAL_SCHEMA = "lightbulb.communication_voice_call_plan_proposal.v1"
PROVIDER_OBSERVATION_INPUT_SCHEMA = (
    "lightbulb.communication_provider_observation_input.v1"
)
PROVIDER_OBSERVATION_PROPOSAL_SCHEMA = (
    "lightbulb.communication_provider_observation_proposal.v1"
)
TWILIO_SMS_OBSERVATION_RESULT_SCHEMA = (
    "lightbulb.communication_twilio_sms_observation_result.v1"
)
TWILIO_VOICE_WRITE_ROUTE_SCHEMA = "lightbulb.communication_twilio_voice_write_route.v1"
TWILIO_VOICE_STATUS_ROUTE_SCHEMA = (
    "lightbulb.communication_twilio_voice_status_route.v1"
)
TWILIO_VOICE_ACCEPTANCE_SCHEMA = "lightbulb.twilio_voice_acceptance.v1"
TWILIO_VOICE_STATUS_SCHEMA = "lightbulb.twilio_voice_status.v1"
TWILIO_VOICE_MATERIALIZATION_SCHEMA = (
    "lightbulb.communication_twilio_voice_materialization.v1"
)
TWILIO_VOICE_OBSERVATION_SCHEMA = "lightbulb.communication_twilio_voice_observation.v1"

_ZERO_DIGEST = "0" * 64
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OPAQUE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_CODE_PATTERN = r"^[a-z][a-z0-9_.-]{0,95}$"
_JURISDICTION_PATTERN = r"^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$"
_TEMPLATE_LANGUAGE_PATTERN = r"^[a-z]{2,3}(?:_[A-Z]{2})?$"
_WHATSAPP_MESSAGE_ID_PATTERN = r"^[^\s\x00-\x1f\x7f]{1,512}$"
_MOBILE_ENDPOINT_DOMAIN = "lightbulb.communication_mobile_endpoint_address.v1"
_MOBILE_IDENTIFIER_DOMAIN = "lightbulb.communication_mobile_identifier.v1"
_MOBILE_CONVERSATION_SCHEMA = "lightbulb.communication_mobile_conversation.v1"
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_TRUST_RANK = {
    CommunicationTrustGrade.UNVERIFIED: 0,
    CommunicationTrustGrade.MODEL_INFERRED: 1,
    CommunicationTrustGrade.PROVIDER_ATTESTED: 2,
    CommunicationTrustGrade.HOST_ATTESTED: 3,
    CommunicationTrustGrade.HUMAN_ATTESTED: 4,
    CommunicationTrustGrade.VERIFIED_ENDPOINT: 5,
}

Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
OpaqueRef = Annotated[str, StringConstraints(pattern=_OPAQUE_REF_PATTERN)]
OpaqueCode = Annotated[str, StringConstraints(pattern=_CODE_PATTERN)]
JurisdictionCode = Annotated[str, StringConstraints(pattern=_JURISDICTION_PATTERN)]


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


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _timestamp(value: str, *, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{label} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    return _utc(parsed, label=label).isoformat().replace("+00:00", "Z")


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_ref(value: str, *, label: str) -> str:
    if value != value.strip() or re.fullmatch(_OPAQUE_REF_PATTERN, value) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _e164(value: str) -> str:
    return canonical_twilio_e164(value)


def _require_unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} values must be unique")


class OmnichannelDisposition(str, Enum):
    READY = "ready"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    BLOCKED = "blocked"
    INDETERMINATE = "indeterminate"


class OmnichannelOutboundMode(str, Enum):
    SMS = "sms"
    WHATSAPP_TEMPLATE = "whatsapp_template"
    WHATSAPP_SERVICE_WINDOW_REPLY = "whatsapp_service_window_reply"

    @property
    def channel(self) -> CommunicationChannel:
        return (
            CommunicationChannel.SMS
            if self is OmnichannelOutboundMode.SMS
            else CommunicationChannel.WHATSAPP
        )

    @property
    def tool(self) -> str:
        return {
            OmnichannelOutboundMode.SMS: TWILIO_SEND_SMS_TOOL,
            OmnichannelOutboundMode.WHATSAPP_TEMPLATE: WHATSAPP_SEND_TEMPLATE_TOOL,
            OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY: (
                WHATSAPP_REPLY_SERVICE_WINDOW_TOOL
            ),
        }[self]


class OmnichannelProvider(str, Enum):
    GMAIL = "gmail"
    MICROSOFT_EMAIL = "microsoft_email"
    SLACK = "slack"
    TEAMS = "teams"
    TWILIO_SMS = "twilio_sms"
    WHATSAPP_CLOUD = "whatsapp_cloud"
    TWILIO_VOICE = "twilio_voice"


class NormalizedTransportState(str, Enum):
    QUEUED = "queued"
    ACCEPTED = "accepted"
    IN_TRANSIT = "in_transit"
    DELIVERED = "delivered"
    FAILED = "failed"
    UNKNOWN = "unknown"


class NormalizedOutcome(str, Enum):
    NONE = "none"
    ENGAGED = "engaged"
    REPLIED = "replied"
    OPTED_OUT = "opted_out"
    ANSWERED = "answered"
    COMPLETED = "completed"
    NOT_ANSWERED = "not_answered"
    BUSY = "busy"
    FAILED = "failed"
    UNKNOWN = "unknown"


class VoiceInstructionCode(str, Enum):
    PLAY_APPROVED_SCRIPT = "play_approved_script"
    COLLECT_SINGLE_DIGIT_RESPONSE = "collect_single_digit_response"
    LEAVE_APPROVED_VOICEMAIL = "leave_approved_voicemail"
    END_CALL = "end_call"


class OmnichannelEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    identities_merged: Literal[False] = False
    consent_changed: Literal[False] = False
    suppression_changed: Literal[False] = False
    message_dispatched: Literal[False] = False
    voice_call_placed: Literal[False] = False
    outcome_written: Literal[False] = False
    external_systems_changed: Literal[False] = False
    spring_system_of_record_authority_required: Literal[True] = True
    spring_rbac_approval_audit_required: Literal[True] = True


class OmnichannelEvidencePolicy(_StrictModel):
    minimum_verification_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.VERIFIED
    )
    maximum_age_minutes: int = Field(default=120, ge=1, le=1_440)


class OmnichannelFinding(_StrictModel):
    code: OpaqueCode
    status: Literal["review", "fail", "indeterminate"]
    message: str = Field(min_length=1, max_length=500)
    subject_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=100)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


def _evidence_findings(
    *,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    analysis_as_of: str,
    subject_ref: str,
    required_kinds: Sequence[str],
    policy: OmnichannelEvidencePolicy,
    jurisdiction: str | None = None,
) -> tuple[tuple[OmnichannelFinding, ...], tuple[PrimitiveEvidenceRef, ...]]:
    as_of = _parsed(analysis_as_of)
    minimum_rank = _GRADE_RANK[policy.minimum_verification_grade]
    usable: list[PrimitiveEvidenceRef] = []
    findings: list[OmnichannelFinding] = []
    ordered = tuple(sorted(evidence_refs, key=lambda item: item.evidence_ref))
    _require_unique([item.evidence_ref for item in ordered], label="evidence reference")
    for item in ordered:
        observed = _parsed(item.observed_at)
        problems: list[tuple[str, str]] = []
        if item.subject_ref != subject_ref:
            problems.append(("scope", "Evidence is outside the evaluated subject."))
        if jurisdiction is not None and item.jurisdiction != jurisdiction:
            problems.append(
                (
                    "jurisdiction",
                    "Evidence is outside the evaluated jurisdiction.",
                )
            )
        if observed > as_of:
            problems.append(("future", "Evidence was observed after the cutoff."))
        elif as_of - observed > timedelta(minutes=policy.maximum_age_minutes):
            problems.append(("stale", "Evidence exceeds the freshness window."))
        if _GRADE_RANK[item.verification_grade] < minimum_rank:
            problems.append(("grade", "Evidence verification is below policy."))
        if item.effective_at is None:
            problems.append(("effective_at", "Evidence has no effective timestamp."))
        elif _parsed(item.effective_at) > as_of:
            problems.append(
                ("future_effective", "Evidence is not effective at the cutoff.")
            )
        if not problems:
            usable.append(item)
        for suffix, message in problems:
            findings.append(
                OmnichannelFinding(
                    code=f"evidence.{suffix}",
                    status="indeterminate",
                    message=message,
                    subject_ref=item.evidence_ref,
                    evidence_refs=(item.evidence_ref,),
                )
            )
    usable_kinds = {item.kind for item in usable}
    for kind in sorted(set(required_kinds) - usable_kinds):
        findings.append(
            OmnichannelFinding(
                code="evidence.required_kind_missing",
                status="indeterminate",
                message=f"No usable evidence was supplied for required kind {kind!r}.",
            )
        )
    return tuple(findings), ordered


def _disposition(findings: Sequence[OmnichannelFinding]) -> OmnichannelDisposition:
    statuses = {item.status for item in findings}
    if "fail" in statuses:
        return OmnichannelDisposition.BLOCKED
    if "indeterminate" in statuses:
        return OmnichannelDisposition.INDETERMINATE
    if "review" in statuses:
        return OmnichannelDisposition.MANUAL_REVIEW_REQUIRED
    return OmnichannelDisposition.READY


def _proposal_digest(model: BaseModel) -> str:
    return _stable_digest(
        model.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_digest"},
            exclude_none=True,
        )
    )


IDENTITY_RESOLUTION_OPERATION = PrimitiveOperationSpec(
    operation_ref="omnichannel-identity.resolve",
    tool="communication.resolve_cross_channel_identity",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
JURISDICTION_POLICY_OPERATION = PrimitiveOperationSpec(
    operation_ref="omnichannel-policy.evaluate",
    tool="communication.evaluate_jurisdiction_channel_policy",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
VOICE_CALL_PLAN_OPERATION = PrimitiveOperationSpec(
    operation_ref="omnichannel-voice.plan",
    tool="communication.plan_governed_voice_call",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
PROVIDER_OBSERVATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="omnichannel-observation.normalize",
    tool="communication.normalize_provider_outcome",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class CrossChannelIdentityInput(_StrictModel):
    schema_id: Literal["lightbulb.communication_cross_channel_identity_input.v1"] = (
        Field(default=CROSS_CHANNEL_IDENTITY_INPUT_SCHEMA, alias="schema")
    )
    resolution_ref: OpaqueRef
    analysis_as_of: str
    party: CommunicationPartyRef
    endpoints: tuple[CommunicationEndpointBinding, ...] = Field(
        min_length=2, max_length=20
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=100
    )
    evidence_policy: OmnichannelEvidencePolicy = Field(
        default_factory=OmnichannelEvidencePolicy
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, label="analysis_as_of")

    @field_validator("endpoints", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_endpoints(self) -> "CrossChannelIdentityInput":
        _require_unique(
            [item.endpoint_ref for item in self.endpoints], label="endpoint reference"
        )
        _require_unique(
            [item.channel.value for item in self.endpoints], label="identity channel"
        )
        return self


class CrossChannelIdentityProposal(_StrictModel):
    schema_id: Literal["lightbulb.communication_cross_channel_identity_proposal.v1"] = (
        Field(default=CROSS_CHANNEL_IDENTITY_PROPOSAL_SCHEMA, alias="schema")
    )
    resolution_ref: OpaqueRef
    party_ref: OpaqueRef
    evaluated_at: str
    proposed_disposition: OmnichannelDisposition
    endpoint_refs: tuple[OpaqueRef, ...]
    channels: tuple[CommunicationChannel, ...]
    findings: tuple[OmnichannelFinding, ...]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    operation_spec: PrimitiveOperationSpec = IDENTITY_RESOLUTION_OPERATION
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    cross_channel_identity_merge_authorized: Literal[False] = False
    identities_merged: Literal[False] = False
    spring_artifact_seal_verification_required: Literal[True] = True
    effect_boundary: OmnichannelEffectBoundary = Field(
        default_factory=OmnichannelEffectBoundary
    )
    proposal_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator(
        "endpoint_refs", "channels", "findings", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @model_validator(mode="after")
    def _content_bound(self) -> "CrossChannelIdentityProposal":
        if self.proposed_disposition != _disposition(self.findings):
            raise ValueError("identity disposition must match findings")
        if self.operation_spec != IDENTITY_RESOLUTION_OPERATION:
            raise ValueError("identity operation must remain read-only")
        expected = _proposal_digest(self)
        if self.proposal_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("proposal_digest does not match identity proposal")
        object.__setattr__(self, "proposal_digest", expected)
        return self


def resolve_cross_channel_identity(
    value: CrossChannelIdentityInput | Mapping[str, Any],
) -> CrossChannelIdentityProposal:
    """Propose one cross-channel identity resolution without merging records."""

    inputs = revalidate_model_boundary(CrossChannelIdentityInput, value)
    findings, evidence_refs = _evidence_findings(
        evidence_refs=inputs.evidence_refs,
        analysis_as_of=inputs.analysis_as_of,
        subject_ref=inputs.party.party_ref,
        required_kinds=("cross_channel_identity",),
        policy=inputs.evidence_policy,
    )
    mutable = list(findings)
    as_of = _parsed(inputs.analysis_as_of)
    for endpoint in sorted(inputs.endpoints, key=lambda item: item.endpoint_ref):
        if (
            endpoint.party_ref != inputs.party.party_ref
            or endpoint.party_digest != inputs.party.artifact_digest
        ):
            mutable.append(
                OmnichannelFinding(
                    code="identity.party_binding_conflict",
                    status="fail",
                    message="An endpoint binds a different sealed party.",
                    subject_ref=endpoint.endpoint_ref,
                )
            )
        if (
            _TRUST_RANK[endpoint.ownership_trust]
            < _TRUST_RANK[CommunicationTrustGrade.PROVIDER_ATTESTED]
        ):
            mutable.append(
                OmnichannelFinding(
                    code="identity.endpoint_trust_insufficient",
                    status="indeterminate",
                    message="Endpoint ownership is inferred or unverified.",
                    subject_ref=endpoint.endpoint_ref,
                )
            )
        if (
            endpoint.verified_at is None
            or endpoint.verification_evidence_digest is None
        ):
            mutable.append(
                OmnichannelFinding(
                    code="identity.endpoint_verification_missing",
                    status="indeterminate",
                    message="Endpoint lacks retained ownership verification.",
                    subject_ref=endpoint.endpoint_ref,
                )
            )
        elif _parsed(endpoint.verified_at) > as_of:
            mutable.append(
                OmnichannelFinding(
                    code="identity.endpoint_verification_future",
                    status="indeterminate",
                    message="Endpoint verification occurs after the cutoff.",
                    subject_ref=endpoint.endpoint_ref,
                )
            )
        elif as_of - _parsed(endpoint.verified_at) > timedelta(
            minutes=inputs.evidence_policy.maximum_age_minutes
        ):
            mutable.append(
                OmnichannelFinding(
                    code="identity.endpoint_verification_stale",
                    status="indeterminate",
                    message="Endpoint verification exceeds the freshness window.",
                    subject_ref=endpoint.endpoint_ref,
                )
            )
    ordered_findings = tuple(
        sorted(mutable, key=lambda item: (item.code, item.subject_ref or ""))
    )
    evidence_digest = _stable_digest([item.to_dict() for item in evidence_refs])
    operation_digest = _stable_digest(
        {
            "operation": IDENTITY_RESOLUTION_OPERATION.to_dict(),
            "input": inputs.to_dict(),
            "evidence_digest": evidence_digest,
        }
    )
    return CrossChannelIdentityProposal(
        resolution_ref=inputs.resolution_ref,
        party_ref=inputs.party.party_ref,
        evaluated_at=inputs.analysis_as_of,
        proposed_disposition=_disposition(ordered_findings),
        endpoint_refs=tuple(sorted(item.endpoint_ref for item in inputs.endpoints)),
        channels=tuple(sorted((item.channel for item in inputs.endpoints), key=str)),
        findings=ordered_findings,
        evidence_refs=evidence_refs,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
    )


class CommunicationJurisdictionPolicyDecision(CommunicationArtifact):
    """Short-lived Spring-issued channel and jurisdiction contact authority."""

    schema_id: Literal[
        "lightbulb.communication_jurisdiction_channel_policy_decision.v1"
    ] = Field(
        default=COMMUNICATION_JURISDICTION_POLICY_DECISION_SCHEMA,
        alias="schema",
    )
    decision_ref: OpaqueRef
    policy_version_ref: OpaqueRef
    draft_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    recipient_endpoint_digest: Sha256Digest
    jurisdiction: JurisdictionCode
    jurisdiction_evidence_digest: Sha256Digest
    lawful_basis_code: OpaqueCode
    lawful_basis_evidence_digest: Sha256Digest
    consent_status: CommunicationConsentStatus
    consent_evidence_digest: Sha256Digest
    suppression_status: CommunicationSuppressionStatus
    suppression_evidence_digest: Sha256Digest
    quiet_hours_status: CommunicationQuietHoursStatus
    quiet_hours_evidence_digest: Sha256Digest
    frequency_status: CommunicationFrequencyStatus
    frequency_evidence_digest: Sha256Digest
    disposition: CommunicationPolicyDisposition
    reason_codes: tuple[OpaqueCode, ...] = Field(default=(), max_length=24)
    source_authority: Literal["spring_control_plane"] = "spring_control_plane"
    observed_at: str
    valid_until: str

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _reasons(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _fail_closed(self) -> "CommunicationJurisdictionPolicyDecision":
        if self.channel not in {
            CommunicationChannel.SMS,
            CommunicationChannel.WHATSAPP,
            CommunicationChannel.VOICE,
        }:
            raise ValueError("jurisdiction decision requires SMS, WhatsApp, or voice")
        lifetime = _parsed(self.valid_until) - _parsed(self.observed_at)
        if lifetime <= timedelta(0) or lifetime > timedelta(minutes=2):
            raise ValueError(
                "jurisdiction policy lifetime must be positive and at most two minutes"
            )
        _require_unique(self.reason_codes, label="policy reason code")
        eligible = (
            self.consent_status
            in {
                CommunicationConsentStatus.GRANTED,
                CommunicationConsentStatus.NOT_REQUIRED,
            }
            and self.suppression_status == CommunicationSuppressionStatus.CLEAR
            and self.quiet_hours_status == CommunicationQuietHoursStatus.CLEAR
            and self.frequency_status == CommunicationFrequencyStatus.WITHIN_LIMIT
        )
        if self.disposition == CommunicationPolicyDisposition.ALLOW:
            if not eligible:
                raise ValueError(
                    "allow requires current consent, suppression, quiet-hours, and frequency evidence"
                )
            if self.reason_codes:
                raise ValueError("allow cannot carry blocking reason codes")
        elif not self.reason_codes:
            raise ValueError("block and review require reason codes")
        return self


class JurisdictionChannelPolicyInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_jurisdiction_channel_policy_input.v1"
    ] = Field(default=JURISDICTION_CHANNEL_POLICY_INPUT_SCHEMA, alias="schema")
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    draft_ref: OpaqueRef
    draft_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    recipient_endpoint_ref: OpaqueRef
    recipient_endpoint_digest: Sha256Digest
    jurisdiction: JurisdictionCode
    lawful_basis_code: OpaqueCode | None = None
    consent_status: CommunicationConsentStatus
    suppression_status: CommunicationSuppressionStatus
    quiet_hours_status: CommunicationQuietHoursStatus
    frequency_status: CommunicationFrequencyStatus
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=100
    )
    evidence_policy: OmnichannelEvidencePolicy = Field(
        default_factory=lambda: OmnichannelEvidencePolicy(maximum_age_minutes=15)
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _as_of(cls, value: str) -> str:
        return _timestamp(value, label="analysis_as_of")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _channel_scope(self) -> "JurisdictionChannelPolicyInput":
        if self.channel not in {
            CommunicationChannel.SMS,
            CommunicationChannel.WHATSAPP,
            CommunicationChannel.VOICE,
        }:
            raise ValueError("jurisdiction evaluation requires SMS, WhatsApp, or voice")
        return self


class JurisdictionChannelPolicyProposal(_StrictModel):
    schema_id: Literal[
        "lightbulb.communication_jurisdiction_channel_policy_proposal.v1"
    ] = Field(default=JURISDICTION_CHANNEL_POLICY_PROPOSAL_SCHEMA, alias="schema")
    evaluation_ref: OpaqueRef
    draft_ref: OpaqueRef
    draft_digest: Sha256Digest
    recipient_endpoint_ref: OpaqueRef
    recipient_endpoint_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    jurisdiction: JurisdictionCode
    evaluated_at: str
    proposed_disposition: OmnichannelDisposition
    findings: tuple[OmnichannelFinding, ...]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    operation_spec: PrimitiveOperationSpec = JURISDICTION_POLICY_OPERATION
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    consent_granted: Literal[False] = False
    suppression_overridden: Literal[False] = False
    dispatch_authorized: Literal[False] = False
    spring_policy_decision_required: Literal[True] = True
    effect_boundary: OmnichannelEffectBoundary = Field(
        default_factory=OmnichannelEffectBoundary
    )
    proposal_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @model_validator(mode="after")
    def _content_bound(self) -> "JurisdictionChannelPolicyProposal":
        if self.proposed_disposition != _disposition(self.findings):
            raise ValueError("policy proposal disposition must match findings")
        if self.operation_spec != JURISDICTION_POLICY_OPERATION:
            raise ValueError("policy proposal operation must remain read-only")
        expected = _proposal_digest(self)
        if self.proposal_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("proposal_digest does not match policy proposal")
        object.__setattr__(self, "proposal_digest", expected)
        return self


def evaluate_jurisdiction_channel_policy(
    value: JurisdictionChannelPolicyInput | Mapping[str, Any],
) -> JurisdictionChannelPolicyProposal:
    """Evaluate jurisdiction-plus-channel evidence without granting authority."""

    inputs = revalidate_model_boundary(JurisdictionChannelPolicyInput, value)
    evidence_findings, evidence_refs = _evidence_findings(
        evidence_refs=inputs.evidence_refs,
        analysis_as_of=inputs.analysis_as_of,
        subject_ref=inputs.recipient_endpoint_ref,
        required_kinds=(
            "jurisdiction",
            "channel_consent",
            "channel_suppression",
            "quiet_hours",
            "contact_frequency",
        ),
        policy=inputs.evidence_policy,
        jurisdiction=inputs.jurisdiction,
    )
    findings = list(evidence_findings)
    if inputs.lawful_basis_code is None:
        findings.append(
            OmnichannelFinding(
                code="policy.lawful_basis_missing",
                status="indeterminate",
                message="No jurisdiction-specific lawful basis was supplied.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    if inputs.consent_status == CommunicationConsentStatus.DENIED:
        findings.append(
            OmnichannelFinding(
                code="policy.consent_denied",
                status="fail",
                message="Channel consent is denied.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    elif inputs.consent_status == CommunicationConsentStatus.UNKNOWN:
        findings.append(
            OmnichannelFinding(
                code="policy.consent_unknown",
                status="indeterminate",
                message="Channel consent is unresolved.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    if inputs.suppression_status == CommunicationSuppressionStatus.SUPPRESSED:
        findings.append(
            OmnichannelFinding(
                code="policy.recipient_suppressed",
                status="fail",
                message="Recipient is suppressed for this channel.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    elif inputs.suppression_status == CommunicationSuppressionStatus.UNKNOWN:
        findings.append(
            OmnichannelFinding(
                code="policy.suppression_unknown",
                status="indeterminate",
                message="Channel suppression is unresolved.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    if inputs.quiet_hours_status == CommunicationQuietHoursStatus.ACTIVE:
        findings.append(
            OmnichannelFinding(
                code="policy.quiet_hours_active",
                status="fail",
                message="The jurisdictional quiet-hours window is active.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    elif inputs.quiet_hours_status == CommunicationQuietHoursStatus.UNKNOWN:
        findings.append(
            OmnichannelFinding(
                code="policy.quiet_hours_unknown",
                status="indeterminate",
                message="Quiet-hours eligibility is unresolved.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    if inputs.frequency_status == CommunicationFrequencyStatus.EXCEEDED:
        findings.append(
            OmnichannelFinding(
                code="policy.frequency_exceeded",
                status="fail",
                message="Channel frequency policy is exceeded.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    elif inputs.frequency_status == CommunicationFrequencyStatus.UNKNOWN:
        findings.append(
            OmnichannelFinding(
                code="policy.frequency_unknown",
                status="indeterminate",
                message="Channel frequency eligibility is unresolved.",
                subject_ref=inputs.recipient_endpoint_ref,
            )
        )
    ordered = tuple(
        sorted(findings, key=lambda item: (item.code, item.subject_ref or ""))
    )
    evidence_digest = _stable_digest([item.to_dict() for item in evidence_refs])
    operation_digest = _stable_digest(
        {
            "operation": JURISDICTION_POLICY_OPERATION.to_dict(),
            "input": inputs.to_dict(),
            "evidence_digest": evidence_digest,
        }
    )
    return JurisdictionChannelPolicyProposal(
        evaluation_ref=inputs.evaluation_ref,
        draft_ref=inputs.draft_ref,
        draft_digest=inputs.draft_digest,
        recipient_endpoint_ref=inputs.recipient_endpoint_ref,
        recipient_endpoint_digest=inputs.recipient_endpoint_digest,
        purpose=inputs.purpose,
        channel=inputs.channel,
        jurisdiction=inputs.jurisdiction,
        evaluated_at=inputs.analysis_as_of,
        proposed_disposition=_disposition(ordered),
        findings=ordered,
        evidence_refs=evidence_refs,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
    )


class VoiceCallPlanInput(_StrictModel):
    schema_id: Literal["lightbulb.communication_voice_call_plan_input.v1"] = Field(
        default=VOICE_CALL_PLAN_INPUT_SCHEMA, alias="schema"
    )
    plan_ref: OpaqueRef
    analysis_as_of: str
    purpose: CommunicationPurpose
    party_ref: OpaqueRef
    voice_endpoint_ref: OpaqueRef
    voice_endpoint_digest: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    identity_resolution_digest: Sha256Digest
    identity_disposition: OmnichannelDisposition
    jurisdiction_policy_digest: Sha256Digest
    jurisdiction_policy_disposition: OmnichannelDisposition
    jurisdiction: JurisdictionCode
    script_ref: OpaqueRef
    script_version: int = Field(ge=1)
    script_digest: Sha256Digest
    script_status: Literal["approved", "pending_review", "rejected", "expired"]
    voice_profile_ref: OpaqueRef
    instruction_codes: tuple[VoiceInstructionCode, ...] = Field(
        min_length=2, max_length=4
    )
    maximum_duration_seconds: int = Field(ge=15, le=600)
    scheduled_for: str
    route_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=100
    )
    evidence_policy: OmnichannelEvidencePolicy = Field(
        default_factory=lambda: OmnichannelEvidencePolicy(maximum_age_minutes=15)
    )

    @field_validator("analysis_as_of", "scheduled_for")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator("instruction_codes", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _closed_instructions(self) -> "VoiceCallPlanInput":
        _require_unique(
            [item.value for item in self.instruction_codes],
            label="voice instruction",
        )
        if self.instruction_codes[0] != VoiceInstructionCode.PLAY_APPROVED_SCRIPT:
            raise ValueError("voice plan must start with the approved script")
        if self.instruction_codes[-1] != VoiceInstructionCode.END_CALL:
            raise ValueError("voice plan must end the call")
        if _parsed(self.scheduled_for) < _parsed(self.analysis_as_of):
            raise ValueError("scheduled_for cannot precede the planning cutoff")
        if _parsed(self.scheduled_for) - _parsed(self.analysis_as_of) > timedelta(
            hours=24
        ):
            raise ValueError("voice plan horizon cannot exceed 24 hours")
        return self


class VoiceCallPlanProposal(_StrictModel):
    schema_id: Literal["lightbulb.communication_voice_call_plan_proposal.v1"] = Field(
        default=VOICE_CALL_PLAN_PROPOSAL_SCHEMA, alias="schema"
    )
    plan_ref: OpaqueRef
    party_ref: OpaqueRef
    voice_endpoint_ref: OpaqueRef
    voice_endpoint_digest: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    jurisdiction: JurisdictionCode
    evaluated_at: str
    scheduled_for: str
    proposed_disposition: OmnichannelDisposition
    script_ref: OpaqueRef
    script_version: int = Field(ge=1)
    script_digest: Sha256Digest
    instruction_codes: tuple[VoiceInstructionCode, ...]
    maximum_duration_seconds: int = Field(ge=15, le=600)
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    governed_tool: Literal["twilio.place_call_turn"] = TWILIO_PLACE_CALL_TURN_TOOL
    findings: tuple[OmnichannelFinding, ...]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    operation_spec: PrimitiveOperationSpec = VOICE_CALL_PLAN_OPERATION
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    call_authorized: Literal[False] = False
    call_placed: Literal[False] = False
    arbitrary_twiml_allowed: Literal[False] = False
    arbitrary_callback_url_allowed: Literal[False] = False
    transfer_allowed: Literal[False] = False
    provider_credentials_present: Literal[False] = False
    raw_destination_present: Literal[False] = False
    hosted_execution_contract_required: Literal[True] = True
    effect_boundary: OmnichannelEffectBoundary = Field(
        default_factory=OmnichannelEffectBoundary
    )
    proposal_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("evaluated_at", "scheduled_for")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator("instruction_codes", "findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _content_bound(self) -> "VoiceCallPlanProposal":
        if self.proposed_disposition != _disposition(self.findings):
            raise ValueError("voice disposition must match findings")
        if self.operation_spec != VOICE_CALL_PLAN_OPERATION:
            raise ValueError("voice planning operation must remain read-only")
        expected = _proposal_digest(self)
        if self.proposal_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("proposal_digest does not match voice plan")
        object.__setattr__(self, "proposal_digest", expected)
        return self


def plan_governed_voice_call(
    value: VoiceCallPlanInput | Mapping[str, Any],
) -> VoiceCallPlanProposal:
    """Plan a closed voice call without placing or authorizing one."""

    inputs = revalidate_model_boundary(VoiceCallPlanInput, value)
    evidence_findings, evidence_refs = _evidence_findings(
        evidence_refs=inputs.evidence_refs,
        analysis_as_of=inputs.analysis_as_of,
        subject_ref=inputs.party_ref,
        required_kinds=(
            "cross_channel_identity",
            "jurisdiction_policy",
            "voice_script",
        ),
        policy=inputs.evidence_policy,
        jurisdiction=inputs.jurisdiction,
    )
    findings = list(evidence_findings)
    if inputs.identity_disposition == OmnichannelDisposition.BLOCKED:
        findings.append(
            OmnichannelFinding(
                code="voice.identity_conflict",
                status="fail",
                message="Cross-channel identity evidence conflicts.",
                subject_ref=inputs.voice_endpoint_ref,
            )
        )
    elif inputs.identity_disposition != OmnichannelDisposition.READY:
        findings.append(
            OmnichannelFinding(
                code="voice.identity_unresolved",
                status="indeterminate",
                message="Cross-channel identity is not conclusively resolved.",
                subject_ref=inputs.voice_endpoint_ref,
            )
        )
    if inputs.jurisdiction_policy_disposition == OmnichannelDisposition.BLOCKED:
        findings.append(
            OmnichannelFinding(
                code="voice.policy_blocked",
                status="fail",
                message="Jurisdiction and channel policy blocks the call.",
                subject_ref=inputs.voice_endpoint_ref,
            )
        )
    elif inputs.jurisdiction_policy_disposition != OmnichannelDisposition.READY:
        findings.append(
            OmnichannelFinding(
                code="voice.policy_unresolved",
                status="indeterminate",
                message="Jurisdiction and channel policy is unresolved.",
                subject_ref=inputs.voice_endpoint_ref,
            )
        )
    if inputs.script_status in {"rejected", "expired"}:
        findings.append(
            OmnichannelFinding(
                code="voice.script_ineligible",
                status="fail",
                message="The approved-script snapshot is rejected or expired.",
                subject_ref=inputs.script_ref,
            )
        )
    elif inputs.script_status != "approved":
        findings.append(
            OmnichannelFinding(
                code="voice.script_pending",
                status="indeterminate",
                message="The script has not completed host review.",
                subject_ref=inputs.script_ref,
            )
        )
    if VoiceInstructionCode.COLLECT_SINGLE_DIGIT_RESPONSE in inputs.instruction_codes:
        findings.append(
            OmnichannelFinding(
                code="voice.response_collection_review",
                status="review",
                message="DTMF response collection requires a host-reviewed data purpose.",
                subject_ref=inputs.plan_ref,
            )
        )
    if VoiceInstructionCode.LEAVE_APPROVED_VOICEMAIL in inputs.instruction_codes:
        findings.append(
            OmnichannelFinding(
                code="voice.voicemail_review",
                status="review",
                message="Voicemail use requires jurisdiction-specific host review.",
                subject_ref=inputs.plan_ref,
            )
        )
    ordered = tuple(
        sorted(findings, key=lambda item: (item.code, item.subject_ref or ""))
    )
    evidence_digest = _stable_digest([item.to_dict() for item in evidence_refs])
    operation_digest = _stable_digest(
        {
            "operation": VOICE_CALL_PLAN_OPERATION.to_dict(),
            "input": inputs.to_dict(),
            "evidence_digest": evidence_digest,
        }
    )
    return VoiceCallPlanProposal(
        plan_ref=inputs.plan_ref,
        party_ref=inputs.party_ref,
        voice_endpoint_ref=inputs.voice_endpoint_ref,
        voice_endpoint_digest=inputs.voice_endpoint_digest,
        recipient_address_hmac_v1=inputs.recipient_address_hmac_v1,
        jurisdiction=inputs.jurisdiction,
        evaluated_at=inputs.analysis_as_of,
        scheduled_for=inputs.scheduled_for,
        proposed_disposition=_disposition(ordered),
        script_ref=inputs.script_ref,
        script_version=inputs.script_version,
        script_digest=inputs.script_digest,
        instruction_codes=inputs.instruction_codes,
        maximum_duration_seconds=inputs.maximum_duration_seconds,
        connector_account_ref=inputs.connector_account_ref,
        route_digest=inputs.route_digest,
        findings=ordered,
        evidence_refs=evidence_refs,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
    )


class CommunicationTwilioVoiceWriteRoute(_StrictModel):
    """Exact Spring-owned project/account route for one voice write."""

    schema_id: Literal["lightbulb.communication_twilio_voice_write_route.v1"] = Field(
        default=TWILIO_VOICE_WRITE_ROUTE_SCHEMA, alias="schema"
    )
    project_id: UUID
    project_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    tenant_connector_id: UUID
    route_digest: Sha256Digest
    tool: Literal["twilio.place_call_turn"] = TWILIO_PLACE_CALL_TURN_TOOL
    tool_version: int = Field(ge=1)


class CommunicationTwilioVoiceStatusRoute(_StrictModel):
    """Exact Spring-owned project/account route for one fresh call-status read."""

    schema_id: Literal["lightbulb.communication_twilio_voice_status_route.v1"] = Field(
        default=TWILIO_VOICE_STATUS_ROUTE_SCHEMA, alias="schema"
    )
    project_id: UUID
    project_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    tenant_connector_id: UUID
    route_digest: Sha256Digest
    tool: Literal["twilio.lookup_call_status"] = TWILIO_LOOKUP_CALL_STATUS_TOOL
    tool_version: int = Field(ge=1)


class CommunicationPrivateTwilioVoiceTurn(_StrictModel):
    """Transient approved voice material; never a durable SDK artifact."""

    recipient_address: str = Field(repr=False)
    recipient_address_hmac_v1: Sha256Digest
    script: str = Field(min_length=1, max_length=5_000, repr=False)
    script_sha256: Sha256Digest
    instruction_codes: tuple[VoiceInstructionCode, ...] = Field(
        min_length=2, max_length=4
    )
    maximum_duration_seconds: int = Field(ge=15, le=600)

    @field_validator("recipient_address")
    @classmethod
    def _recipient(cls, value: str) -> str:
        return _e164(value)

    @field_validator("instruction_codes", mode="before")
    @classmethod
    def _instructions_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _exact_content(self) -> "CommunicationPrivateTwilioVoiceTurn":
        if not hmac.compare_digest(
            self.script_sha256, communication_private_value_digest(self.script)
        ):
            raise ValueError("voice script digest does not match exact script")
        _require_unique(
            [item.value for item in self.instruction_codes],
            label="voice instruction",
        )
        if self.instruction_codes[0] != VoiceInstructionCode.PLAY_APPROVED_SCRIPT:
            raise ValueError("voice turn must start with the approved script")
        if self.instruction_codes[-1] != VoiceInstructionCode.END_CALL:
            raise ValueError("voice turn must end the call")
        return self

    def connector_arguments(self) -> dict[str, Any]:
        return {
            "to": self.recipient_address,
            "script": self.script,
            "script_sha256": self.script_sha256,
            "instruction_codes": [item.value for item in self.instruction_codes],
            "maximum_duration_seconds": self.maximum_duration_seconds,
        }


class TwilioVoiceAcceptance(_StrictModel):
    schema_id: Literal["lightbulb.twilio_voice_acceptance.v1"] = Field(
        default=TWILIO_VOICE_ACCEPTANCE_SCHEMA, alias="schema"
    )
    call_sid: str = Field(alias="callSid", repr=False)
    status: Literal["queued", "initiated", "ringing", "in_progress"]
    script_sha256: Sha256Digest = Field(alias="scriptSha256")
    accepted: Literal[True]
    provider_observed: Literal[True] = Field(alias="providerObserved")

    @field_validator("call_sid")
    @classmethod
    def _call_sid(cls, value: str) -> str:
        if re.fullmatch(r"^CA[0-9A-Fa-f]{32}$", value) is None:
            raise ValueError("Twilio call SID is invalid")
        return value


class TwilioVoiceStatus(_StrictModel):
    schema_id: Literal["lightbulb.twilio_voice_status.v1"] = Field(
        default=TWILIO_VOICE_STATUS_SCHEMA, alias="schema"
    )
    call_sid: str = Field(alias="callSid", repr=False)
    recipient_address: str = Field(alias="to", repr=False)
    status: Literal[
        "queued",
        "initiated",
        "ringing",
        "in_progress",
        "completed",
        "busy",
        "failed",
        "no_answer",
        "canceled",
    ]
    event_type: Literal[
        "queued", "ringing", "answered", "completed", "busy", "not_answered", "failed"
    ] = Field(alias="eventType")
    terminal: bool
    duration_seconds: int | None = Field(
        default=None, alias="durationSeconds", ge=0, le=36_000
    )
    provider_observed: Literal[True] = Field(alias="providerObserved")
    private_data: Literal[True] = Field(alias="privateData")
    retention: Literal["ephemeral_response_only"]

    @field_validator("call_sid")
    @classmethod
    def _call_sid(cls, value: str) -> str:
        if re.fullmatch(r"^CA[0-9A-Fa-f]{32}$", value) is None:
            raise ValueError("Twilio call SID is invalid")
        return value

    @field_validator("recipient_address")
    @classmethod
    def _recipient(cls, value: str) -> str:
        return _e164(value)

    @model_validator(mode="after")
    def _closed_status(self) -> "TwilioVoiceStatus":
        transport, outcome, terminal, _ = _normalized_status(
            CommunicationChannel.VOICE, self.status
        )
        del transport, outcome
        expected_event = {
            "queued": "queued",
            "initiated": "queued",
            "ringing": "ringing",
            "in_progress": "answered",
            "completed": "completed",
            "busy": "busy",
            "no_answer": "not_answered",
            "canceled": "failed",
            "failed": "failed",
        }[self.status]
        if self.terminal != terminal or self.event_type != expected_event:
            raise ValueError("voice status semantics are inconsistent")
        return self


class CommunicationPrivateTwilioVoiceDispatch(_StrictModel):
    """Ephemeral call identity returned only to the host's private custody sink."""

    call_sid: str = Field(repr=False)
    call_sid_hmac_v1: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    script_sha256: Sha256Digest

    @field_validator("call_sid")
    @classmethod
    def _call_sid(cls, value: str) -> str:
        if re.fullmatch(r"^CA[0-9A-Fa-f]{32}$", value) is None:
            raise ValueError("Twilio call SID is invalid")
        return value


class TwilioVoiceExecutionEffectBoundary(_StrictModel):
    connector_reads: int = Field(ge=0, le=1)
    connector_writes: int = Field(ge=0, le=1)
    approvals_consumed: int = Field(ge=0, le=1)
    arbitrary_twiml_allowed: Literal[False] = False
    arbitrary_callback_url_allowed: Literal[False] = False
    transfer_allowed: Literal[False] = False
    spring_route_credential_approval_audit_required: Literal[True] = True


class TwilioVoiceDispatchReceipt(_StrictModel):
    """HMAC-only public receipt; the provider call SID remains in host custody."""

    schema_id: Literal["lightbulb.communication_twilio_voice_dispatch_receipt.v1"] = (
        Field(
            default="lightbulb.communication_twilio_voice_dispatch_receipt.v1",
            alias="schema",
        )
    )
    plan_digest: Sha256Digest
    request_digest: Sha256Digest
    connector_provenance_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    tenant_connector_id: UUID
    project_id: UUID
    write_route_digest: Sha256Digest
    provider_commitment_key_id: OpaqueRef
    call_sid_hmac_v1: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    script_sha256: Sha256Digest
    provider_status: Literal["queued", "initiated", "ringing", "in_progress"]
    accepted: Literal[True]
    provider_observed: Literal[True]
    private_dispatch_custody: Literal["host_private"] = "host_private"


class TwilioVoiceMaterializationResult(_StrictModel):
    schema_id: Literal["lightbulb.communication_twilio_voice_materialization.v1"] = (
        Field(default=TWILIO_VOICE_MATERIALIZATION_SCHEMA, alias="schema")
    )
    status: Literal["preview", "completed", "pending_approval", "blocked", "failed"]
    connector_status: ConnectorExecutionStatus
    request_digest: Sha256Digest
    approval_ref: OpaqueRef | None = None
    dispatch_receipt: TwilioVoiceDispatchReceipt | None = None
    summary: str = Field(min_length=1, max_length=1_000)
    effect_boundary: TwilioVoiceExecutionEffectBoundary

    @model_validator(mode="after")
    def _shape(self) -> "TwilioVoiceMaterializationResult":
        if self.status == "completed":
            if self.dispatch_receipt is None:
                raise ValueError(
                    "completed voice materialization requires a public receipt"
                )
        elif self.dispatch_receipt is not None:
            raise ValueError(
                "non-completed voice materialization cannot carry provider claims"
            )
        return self


class TwilioVoiceObservationResult(_StrictModel):
    schema_id: Literal["lightbulb.communication_twilio_voice_observation.v1"] = Field(
        default=TWILIO_VOICE_OBSERVATION_SCHEMA, alias="schema"
    )
    status: Literal["completed", "blocked", "failed"]
    connector_status: ConnectorExecutionStatus
    request_digest: Sha256Digest
    provider_event_digest: Sha256Digest | None = None
    transport_state: NormalizedTransportState | None = None
    outcome: NormalizedOutcome | None = None
    terminal: bool = False
    duration_seconds: int | None = Field(default=None, ge=0, le=36_000)
    summary: str = Field(min_length=1, max_length=1_000)
    effect_boundary: TwilioVoiceExecutionEffectBoundary


def communication_twilio_voice_private_identifier_commitment(
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    connector_account_ref: str,
    route_digest: str,
    call_sid: str,
) -> str:
    """Key one private call SID to exact scope, account, and write route."""

    if re.fullmatch(r"^CA[0-9A-Fa-f]{32}$", call_sid) is None:
        raise ValueError("Twilio call SID is invalid")
    _safe_ref(connector_account_ref, label="connector_account_ref")
    if re.fullmatch(_SHA256_PATTERN, route_digest) is None:
        raise ValueError("route_digest must be lowercase SHA-256")
    return scope_keyring.sign(
        key_id,
        _MOBILE_IDENTIFIER_DOMAIN,
        {
            "schema": _MOBILE_IDENTIFIER_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "project_ref": scope.project_ref,
            "channel": CommunicationChannel.VOICE,
            "connector_account_ref": connector_account_ref,
            "route_digest": route_digest,
            "identifier_kind": "call_sid",
            "value": call_sid,
        },
    ).hex()


def _require_voice_execution_scope(
    *,
    workflow_scope: DynamicWorkflowScope,
    execution_scope: ExecutionScope,
    project_id: UUID,
    project_ref: str,
) -> None:
    if (
        execution_scope.tenant_ref,
        execution_scope.company_ref,
        execution_scope.project_ref,
        execution_scope.actor_ref,
        execution_scope.project_id,
    ) != (
        workflow_scope.tenant_id,
        workflow_scope.company_id,
        workflow_scope.project_ref,
        workflow_scope.user_id,
        project_id,
    ) or project_ref != workflow_scope.project_ref:
        raise ValueError("voice execution scope does not match authenticated scope")


def materialize_twilio_voice_call(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    route: CommunicationTwilioVoiceWriteRoute | Mapping[str, Any],
    plan: VoiceCallPlanProposal | Mapping[str, Any],
    private_turn: CommunicationPrivateTwilioVoiceTurn | Mapping[str, Any],
    provider_commitment_key_id: str,
    executor: Any,
    idempotency_key: str,
    _private_dispatch_sink: CommunicationPrivateDispatchSink | None = None,
    preview_only: bool = True,
) -> TwilioVoiceMaterializationResult:
    """Preview or dispatch one exact voice turn through Spring authority.

    This function accepts no TwiML, URL, callback, recording, transfer, or
    credential field. A completed result is evidence of provider acceptance,
    never proof of answer or business outcome.
    """

    workflow_scope = _workflow_scope(scope)
    runtime_scope = _execution_scope(execution_scope)
    parsed_route = CommunicationTwilioVoiceWriteRoute.model_validate(route)
    parsed_plan = VoiceCallPlanProposal.model_validate(plan)
    private = CommunicationPrivateTwilioVoiceTurn.model_validate(private_turn)
    _require_voice_execution_scope(
        workflow_scope=workflow_scope,
        execution_scope=runtime_scope,
        project_id=parsed_route.project_id,
        project_ref=parsed_route.project_ref,
    )
    if parsed_plan.proposed_disposition != OmnichannelDisposition.READY:
        raise ValueError("voice plan is not ready for hosted materialization")
    if (
        parsed_plan.connector_account_ref != parsed_route.connector_account_ref
        or parsed_plan.route_digest != parsed_route.route_digest
        or parsed_plan.script_digest != private.script_sha256
        or parsed_plan.instruction_codes != private.instruction_codes
        or parsed_plan.maximum_duration_seconds != private.maximum_duration_seconds
        or parsed_plan.governed_tool != parsed_route.tool
    ):
        raise ValueError("voice materialization crosses sealed plan or route authority")
    recipient_hmac = communication_mobile_endpoint_address_commitment(
        scope=workflow_scope,
        endpoint_ref=parsed_plan.voice_endpoint_ref,
        channel=CommunicationChannel.VOICE,
        address=private.recipient_address,
        key_id=provider_commitment_key_id,
        scope_keyring=scope_keyring,
    )
    if not hmac.compare_digest(
        recipient_hmac, private.recipient_address_hmac_v1
    ) or not hmac.compare_digest(recipient_hmac, parsed_plan.recipient_address_hmac_v1):
        raise ValueError("voice destination does not match the planned endpoint")
    if not idempotency_key or idempotency_key != idempotency_key.strip():
        raise ValueError("voice materialization requires an exact idempotency key")
    request = ConnectorExecutionRequest(
        tool=TWILIO_PLACE_CALL_TURN_TOOL,
        arguments=private.connector_arguments(),
        scope=runtime_scope,
        connector_account_ref=parsed_route.connector_account_ref,
        effect=ConnectorEffect.WRITE,
        approval_required=True,
        preview_only=preview_only,
        idempotency_key=idempotency_key,
        metadata={
            "communication_schema": TWILIO_VOICE_MATERIALIZATION_SCHEMA,
            "voice_plan_digest": parsed_plan.proposal_digest,
            "voice_endpoint_digest": parsed_plan.voice_endpoint_digest,
            "recipient_address_hmac_v1": recipient_hmac,
        },
    )
    request_digest = request.custody_fingerprint()
    if preview_only:
        return TwilioVoiceMaterializationResult(
            status="preview",
            connector_status=ConnectorExecutionStatus.PREVIEW,
            request_digest=request_digest,
            summary="Voice call is planned; no connector or provider call was made.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=0, approvals_consumed=0
            ),
        )
    if not isinstance(executor, HostedConnectorExecutor):
        raise ValueError("live voice dispatch requires HostedConnectorExecutor")
    result: ConnectorExecutionResult = executor.execute(request)
    status_map = {
        ConnectorExecutionStatus.PENDING_APPROVAL: "pending_approval",
        ConnectorExecutionStatus.BLOCKED: "blocked",
        ConnectorExecutionStatus.FAILED: "failed",
    }
    if result.status != ConnectorExecutionStatus.COMPLETED:
        return TwilioVoiceMaterializationResult(
            status=status_map.get(result.status, "failed"),
            connector_status=result.status,
            request_digest=request_digest,
            approval_ref=result.approval_ref,
            summary=result.message
            or "Spring did not complete the governed voice write.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=0, approvals_consumed=0
            ),
        )
    provenance = result.provenance
    if provenance is None or (
        provenance.tool != parsed_route.tool
        or provenance.tool_version != parsed_route.tool_version
        or provenance.server_effect != ConnectorEffect.WRITE
        or provenance.connector_account_ref != parsed_route.connector_account_ref
        or provenance.tenant_connector_id != parsed_route.tenant_connector_id
        or provenance.project_id != parsed_route.project_id
        or provenance.route_digest != parsed_route.route_digest
        or provenance.request_digest != request_digest
        or provenance.approval_ref is None
        or provenance.approval_receipt_digest is None
    ):
        raise ValueError(
            "voice write provenance does not match route, request, and approval"
        )
    try:
        acceptance = TwilioVoiceAcceptance.model_validate(result.output)
    except (TypeError, ValueError):
        raise ValueError("voice provider acceptance is invalid") from None
    if not hmac.compare_digest(acceptance.script_sha256, private.script_sha256):
        raise ValueError("voice provider acceptance does not bind the approved script")
    call_hmac = communication_twilio_voice_private_identifier_commitment(
        scope=workflow_scope,
        key_id=provider_commitment_key_id,
        scope_keyring=scope_keyring,
        connector_account_ref=parsed_route.connector_account_ref,
        route_digest=parsed_route.route_digest,
        call_sid=acceptance.call_sid,
    )
    private_dispatch = CommunicationPrivateTwilioVoiceDispatch(
        call_sid=acceptance.call_sid,
        call_sid_hmac_v1=call_hmac,
        recipient_address_hmac_v1=recipient_hmac,
        script_sha256=private.script_sha256,
    )
    receipt = TwilioVoiceDispatchReceipt(
        plan_digest=parsed_plan.proposal_digest,
        request_digest=request_digest,
        connector_provenance_digest=_provenance_digest(provenance),
        connector_account_ref=parsed_route.connector_account_ref,
        tenant_connector_id=parsed_route.tenant_connector_id,
        project_id=parsed_route.project_id,
        write_route_digest=parsed_route.route_digest,
        provider_commitment_key_id=provider_commitment_key_id,
        call_sid_hmac_v1=call_hmac,
        recipient_address_hmac_v1=recipient_hmac,
        script_sha256=private.script_sha256,
        provider_status=acceptance.status,
        accepted=True,
        provider_observed=True,
    )
    if _private_dispatch_sink is None:
        return TwilioVoiceMaterializationResult(
            status="failed",
            connector_status=result.status,
            request_digest=request_digest,
            approval_ref=provenance.approval_ref,
            summary=(
                "Twilio accepted the call, but encrypted private-result custody "
                "was unavailable; the call must not be retried automatically."
            ),
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=1, approvals_consumed=1
            ),
        )
    try:
        _private_dispatch_sink.store(
            dispatch=receipt,
            authority_binding=parsed_plan,
            private_dispatch=private_dispatch,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
    except Exception:
        return TwilioVoiceMaterializationResult(
            status="failed",
            connector_status=result.status,
            request_digest=request_digest,
            approval_ref=provenance.approval_ref,
            summary=(
                "Twilio accepted the call, but encrypted private-result custody "
                "failed; the call must not be retried automatically."
            ),
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=1, approvals_consumed=1
            ),
        )
    return TwilioVoiceMaterializationResult(
        status="completed",
        connector_status=result.status,
        request_digest=request_digest,
        approval_ref=provenance.approval_ref,
        dispatch_receipt=receipt,
        summary="Twilio accepted the exact governed call; answer and outcome remain unproven.",
        effect_boundary=TwilioVoiceExecutionEffectBoundary(
            connector_reads=0, connector_writes=1, approvals_consumed=1
        ),
    )


def observe_twilio_voice_call(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    route: CommunicationTwilioVoiceStatusRoute | Mapping[str, Any],
    write_route: CommunicationTwilioVoiceWriteRoute | Mapping[str, Any],
    plan: VoiceCallPlanProposal | Mapping[str, Any],
    dispatch_receipt: TwilioVoiceDispatchReceipt | Mapping[str, Any],
    provider_commitment_key_id: str,
    executor: HostedConnectorExecutor,
    _private_dispatch_sink: CommunicationPrivateDispatchSink,
) -> TwilioVoiceObservationResult:
    """Resolve one private SID in trusted custody and read its fresh status.

    The provider identifier is never accepted from caller payload and is never
    returned. Observation cannot retry a call or write a business outcome.
    """

    if not isinstance(executor, HostedConnectorExecutor):
        raise ValueError("voice observation requires HostedConnectorExecutor")
    workflow_scope = _workflow_scope(scope)
    runtime_scope = _execution_scope(execution_scope)
    read_route = CommunicationTwilioVoiceStatusRoute.model_validate(route)
    source_route = CommunicationTwilioVoiceWriteRoute.model_validate(write_route)
    parsed_plan = VoiceCallPlanProposal.model_validate(plan)
    receipt = TwilioVoiceDispatchReceipt.model_validate(dispatch_receipt)
    _require_voice_execution_scope(
        workflow_scope=workflow_scope,
        execution_scope=runtime_scope,
        project_id=read_route.project_id,
        project_ref=read_route.project_ref,
    )
    if (
        read_route.project_id != source_route.project_id
        or read_route.project_ref != source_route.project_ref
        or read_route.connector_account_ref != source_route.connector_account_ref
        or read_route.tenant_connector_id != source_route.tenant_connector_id
        or parsed_plan.route_digest != source_route.route_digest
        or parsed_plan.connector_account_ref != source_route.connector_account_ref
        or receipt.plan_digest != parsed_plan.proposal_digest
        or receipt.connector_account_ref != source_route.connector_account_ref
        or receipt.tenant_connector_id != source_route.tenant_connector_id
        or receipt.project_id != source_route.project_id
        or receipt.write_route_digest != source_route.route_digest
        or receipt.provider_commitment_key_id != provider_commitment_key_id
        or receipt.recipient_address_hmac_v1 != parsed_plan.recipient_address_hmac_v1
        or receipt.script_sha256 != parsed_plan.script_digest
    ):
        raise ValueError("voice observation crosses call, route, or plan authority")
    observation_intent_digest = communication_canonical_digest(
        {
            "schema": TWILIO_VOICE_OBSERVATION_SCHEMA,
            "plan_digest": parsed_plan.proposal_digest,
            "call_sid_hmac_v1": receipt.call_sid_hmac_v1,
            "status_route_digest": read_route.route_digest,
        }
    )
    loader = getattr(_private_dispatch_sink, "load", None)
    if not callable(loader):
        return TwilioVoiceObservationResult(
            status="blocked",
            connector_status=ConnectorExecutionStatus.BLOCKED,
            request_digest=observation_intent_digest,
            summary="Trusted encrypted voice dispatch custody is unavailable.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=0, approvals_consumed=0
            ),
        )
    try:
        loaded = loader(
            dispatch=receipt,
            authority_binding=parsed_plan,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        private = CommunicationPrivateTwilioVoiceDispatch.model_validate(loaded)
    except Exception:
        return TwilioVoiceObservationResult(
            status="failed",
            connector_status=ConnectorExecutionStatus.FAILED,
            request_digest=observation_intent_digest,
            summary="Encrypted voice dispatch custody could not resolve the call.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=0, connector_writes=0, approvals_consumed=0
            ),
        )
    if (
        private.recipient_address_hmac_v1 != receipt.recipient_address_hmac_v1
        or private.script_sha256 != receipt.script_sha256
        or not hmac.compare_digest(private.call_sid_hmac_v1, receipt.call_sid_hmac_v1)
    ):
        raise ValueError("voice private custody does not match the public receipt")
    expected_call_hmac = communication_twilio_voice_private_identifier_commitment(
        scope=workflow_scope,
        key_id=provider_commitment_key_id,
        scope_keyring=scope_keyring,
        connector_account_ref=source_route.connector_account_ref,
        route_digest=source_route.route_digest,
        call_sid=private.call_sid,
    )
    if not hmac.compare_digest(receipt.call_sid_hmac_v1, expected_call_hmac):
        raise ValueError("voice observation call identity is not authentically bound")
    request = ConnectorExecutionRequest(
        tool=TWILIO_LOOKUP_CALL_STATUS_TOOL,
        arguments={"call_sid": private.call_sid},
        scope=runtime_scope,
        connector_account_ref=read_route.connector_account_ref,
        effect=ConnectorEffect.READ,
        approval_required=False,
        preview_only=False,
        metadata={
            "communication_schema": TWILIO_VOICE_OBSERVATION_SCHEMA,
            "voice_plan_digest": parsed_plan.proposal_digest,
            "call_sid_hmac_v1": receipt.call_sid_hmac_v1,
        },
    )
    request_digest = request.custody_fingerprint()
    try:
        result = executor.execute(request)
    except Exception:
        return TwilioVoiceObservationResult(
            status="failed",
            connector_status=ConnectorExecutionStatus.FAILED,
            request_digest=request_digest,
            summary="Spring did not return governed call-status evidence.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=1, connector_writes=0, approvals_consumed=0
            ),
        )
    if result.status != ConnectorExecutionStatus.COMPLETED:
        return TwilioVoiceObservationResult(
            status=(
                "blocked"
                if result.status == ConnectorExecutionStatus.BLOCKED
                else "failed"
            ),
            connector_status=result.status,
            request_digest=request_digest,
            summary=result.message
            or "Spring did not complete the governed call-status read.",
            effect_boundary=TwilioVoiceExecutionEffectBoundary(
                connector_reads=1, connector_writes=0, approvals_consumed=0
            ),
        )
    provenance = result.provenance
    if provenance is None or (
        provenance.tool != read_route.tool
        or provenance.tool_version != read_route.tool_version
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != read_route.connector_account_ref
        or provenance.tenant_connector_id != read_route.tenant_connector_id
        or provenance.project_id != read_route.project_id
        or provenance.route_digest != read_route.route_digest
        or provenance.request_digest != request_digest
    ):
        raise ValueError("voice observation provenance does not match exact read route")
    try:
        status = TwilioVoiceStatus.model_validate(result.output)
    except (TypeError, ValueError):
        raise ValueError("voice provider status is invalid") from None
    if status.call_sid != private.call_sid:
        raise ValueError("voice status substituted a different call identity")
    observed_recipient_hmac = communication_mobile_endpoint_address_commitment(
        scope=workflow_scope,
        endpoint_ref=parsed_plan.voice_endpoint_ref,
        channel=CommunicationChannel.VOICE,
        address=status.recipient_address,
        key_id=provider_commitment_key_id,
        scope_keyring=scope_keyring,
    )
    if not hmac.compare_digest(
        observed_recipient_hmac, private.recipient_address_hmac_v1
    ):
        raise ValueError("voice status substituted a different destination")
    transport, outcome, terminal, _ = _normalized_status(
        CommunicationChannel.VOICE, status.status
    )
    event_digest = communication_canonical_digest(
        {
            "schema": TWILIO_VOICE_STATUS_SCHEMA,
            "call_sid_hmac_v1": receipt.call_sid_hmac_v1,
            "status": status.status,
            "duration_seconds": status.duration_seconds,
            "provenance_digest": _provenance_digest(provenance),
        }
    )
    return TwilioVoiceObservationResult(
        status="completed",
        connector_status=result.status,
        request_digest=request_digest,
        provider_event_digest=event_digest,
        transport_state=transport,
        outcome=outcome,
        terminal=terminal,
        duration_seconds=status.duration_seconds,
        summary="Fresh Twilio call status was normalized without writing an outcome.",
        effect_boundary=TwilioVoiceExecutionEffectBoundary(
            connector_reads=1, connector_writes=0, approvals_consumed=0
        ),
    )


_DIGITAL_PROVIDER_CHANNELS = {
    OmnichannelProvider.GMAIL: CommunicationChannel.EMAIL,
    OmnichannelProvider.MICROSOFT_EMAIL: CommunicationChannel.EMAIL,
    OmnichannelProvider.SLACK: CommunicationChannel.SLACK,
    OmnichannelProvider.TEAMS: CommunicationChannel.TEAMS,
    OmnichannelProvider.TWILIO_SMS: CommunicationChannel.SMS,
    OmnichannelProvider.WHATSAPP_CLOUD: CommunicationChannel.WHATSAPP,
    OmnichannelProvider.TWILIO_VOICE: CommunicationChannel.VOICE,
}
_DIGITAL_STATUSES = frozenset(
    {
        "queued",
        "accepted",
        "sending",
        "sent",
        "delivered",
        "delivery_delayed",
        "failed",
        "canceled",
        "undelivered",
        "bounced",
        "complained",
        "opened",
        "clicked",
        "read",
        "replied",
        "unsubscribed",
    }
)
_VOICE_STATUSES = frozenset(
    {
        "initiated",
        "queued",
        "ringing",
        "in_progress",
        "answered",
        "completed",
        "busy",
        "no_answer",
        "canceled",
        "failed",
    }
)


class ProviderObservationInput(_StrictModel):
    schema_id: Literal["lightbulb.communication_provider_observation_input.v1"] = Field(
        default=PROVIDER_OBSERVATION_INPUT_SCHEMA, alias="schema"
    )
    observation_ref: OpaqueRef
    analysis_as_of: str
    provider: OmnichannelProvider
    channel: CommunicationChannel
    provider_status: OpaqueCode
    dispatch_receipt_digest: Sha256Digest
    provider_event_digest: Sha256Digest
    provider_message_digest: Sha256Digest
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    authenticity: CommunicationAuthenticityGrade
    authenticity_evidence_digest: Sha256Digest | None = None
    occurred_at: str
    received_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=100
    )
    evidence_policy: OmnichannelEvidencePolicy = Field(
        default_factory=lambda: OmnichannelEvidencePolicy(maximum_age_minutes=30)
    )

    @field_validator("analysis_as_of", "occurred_at", "received_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, label=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _provider_shape(self) -> "ProviderObservationInput":
        if _DIGITAL_PROVIDER_CHANNELS[self.provider] != self.channel:
            raise ValueError("provider and channel do not match")
        allowed = (
            _VOICE_STATUSES
            if self.channel == CommunicationChannel.VOICE
            else _DIGITAL_STATUSES
        )
        if self.provider_status not in allowed:
            raise ValueError(
                "provider status is outside the reviewed normalization map"
            )
        if self.authenticity == CommunicationAuthenticityGrade.VERIFIED and (
            self.authenticity_evidence_digest is None
        ):
            raise ValueError("verified observations require authenticity evidence")
        if _parsed(self.received_at) < _parsed(self.occurred_at):
            raise ValueError("provider receipt cannot precede occurrence")
        return self


class ProviderObservationProposal(_StrictModel):
    schema_id: Literal["lightbulb.communication_provider_observation_proposal.v1"] = (
        Field(default=PROVIDER_OBSERVATION_PROPOSAL_SCHEMA, alias="schema")
    )
    observation_ref: OpaqueRef
    provider: OmnichannelProvider
    channel: CommunicationChannel
    provider_status: OpaqueCode
    evaluated_at: str
    proposed_disposition: OmnichannelDisposition
    transport_state: NormalizedTransportState
    outcome: NormalizedOutcome
    conclusive: bool
    terminal: bool
    provider_event_type: CommunicationProviderEventType | None = None
    dispatch_receipt_digest: Sha256Digest
    provider_event_digest: Sha256Digest
    provider_message_digest: Sha256Digest
    findings: tuple[OmnichannelFinding, ...]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    operation_spec: PrimitiveOperationSpec = PROVIDER_OBSERVATION_OPERATION
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    delivery_claim_authorized: Literal[False] = False
    business_outcome_claim_authorized: Literal[False] = False
    crm_mutated: Literal[False] = False
    effect_boundary: OmnichannelEffectBoundary = Field(
        default_factory=OmnichannelEffectBoundary
    )
    proposal_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated(cls, value: str) -> str:
        return _timestamp(value, label="evaluated_at")

    @field_validator("findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _content_bound(self) -> "ProviderObservationProposal":
        if self.proposed_disposition != _disposition(self.findings):
            raise ValueError("observation disposition must match findings")
        if (
            self.conclusive
            and self.proposed_disposition != OmnichannelDisposition.READY
        ):
            raise ValueError("only a ready observation may be conclusive")
        if not self.conclusive and (
            self.transport_state != NormalizedTransportState.UNKNOWN
            or self.outcome != NormalizedOutcome.UNKNOWN
            or self.terminal
            or self.provider_event_type is not None
        ):
            raise ValueError("inconclusive observations cannot retain provider claims")
        if self.operation_spec != PROVIDER_OBSERVATION_OPERATION:
            raise ValueError("observation operation must remain read-only")
        expected = _proposal_digest(self)
        if self.proposal_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("proposal_digest does not match observation")
        object.__setattr__(self, "proposal_digest", expected)
        return self


def _normalized_status(
    channel: CommunicationChannel,
    status: str,
) -> tuple[
    NormalizedTransportState,
    NormalizedOutcome,
    bool,
    CommunicationProviderEventType | None,
]:
    if channel == CommunicationChannel.VOICE:
        mapping = {
            "initiated": (
                NormalizedTransportState.QUEUED,
                NormalizedOutcome.NONE,
                False,
            ),
            "queued": (NormalizedTransportState.QUEUED, NormalizedOutcome.NONE, False),
            "ringing": (
                NormalizedTransportState.IN_TRANSIT,
                NormalizedOutcome.NONE,
                False,
            ),
            "in_progress": (
                NormalizedTransportState.DELIVERED,
                NormalizedOutcome.ANSWERED,
                False,
            ),
            "answered": (
                NormalizedTransportState.DELIVERED,
                NormalizedOutcome.ANSWERED,
                False,
            ),
            "completed": (
                NormalizedTransportState.DELIVERED,
                NormalizedOutcome.COMPLETED,
                True,
            ),
            "busy": (
                NormalizedTransportState.FAILED,
                NormalizedOutcome.BUSY,
                True,
            ),
            "no_answer": (
                NormalizedTransportState.FAILED,
                NormalizedOutcome.NOT_ANSWERED,
                True,
            ),
            "canceled": (
                NormalizedTransportState.FAILED,
                NormalizedOutcome.NOT_ANSWERED,
                True,
            ),
            "failed": (
                NormalizedTransportState.FAILED,
                NormalizedOutcome.FAILED,
                True,
            ),
        }
        transport, outcome, terminal = mapping[status]
        return transport, outcome, terminal, None
    transport = {
        "queued": NormalizedTransportState.QUEUED,
        "accepted": NormalizedTransportState.ACCEPTED,
        "sending": NormalizedTransportState.IN_TRANSIT,
        "sent": NormalizedTransportState.IN_TRANSIT,
        "delivery_delayed": NormalizedTransportState.IN_TRANSIT,
        "delivered": NormalizedTransportState.DELIVERED,
        "opened": NormalizedTransportState.DELIVERED,
        "clicked": NormalizedTransportState.DELIVERED,
        "read": NormalizedTransportState.DELIVERED,
        "replied": NormalizedTransportState.DELIVERED,
        "unsubscribed": NormalizedTransportState.DELIVERED,
        "failed": NormalizedTransportState.FAILED,
        "canceled": NormalizedTransportState.FAILED,
        "undelivered": NormalizedTransportState.FAILED,
        "bounced": NormalizedTransportState.FAILED,
        "complained": NormalizedTransportState.DELIVERED,
    }[status]
    outcome = {
        "opened": NormalizedOutcome.ENGAGED,
        "clicked": NormalizedOutcome.ENGAGED,
        "read": NormalizedOutcome.ENGAGED,
        "replied": NormalizedOutcome.REPLIED,
        "unsubscribed": NormalizedOutcome.OPTED_OUT,
        "failed": NormalizedOutcome.FAILED,
        "canceled": NormalizedOutcome.FAILED,
        "undelivered": NormalizedOutcome.FAILED,
        "bounced": NormalizedOutcome.FAILED,
        "complained": NormalizedOutcome.FAILED,
    }.get(status, NormalizedOutcome.NONE)
    terminal = status in {
        "delivered",
        "failed",
        "canceled",
        "undelivered",
        "bounced",
        "complained",
        "replied",
        "unsubscribed",
    }
    event = {
        "queued": CommunicationProviderEventType.QUEUED,
        "accepted": CommunicationProviderEventType.ACCEPTED,
        "sending": CommunicationProviderEventType.QUEUED,
        "sent": CommunicationProviderEventType.QUEUED,
        "delivery_delayed": CommunicationProviderEventType.DELIVERY_DELAYED,
        "delivered": CommunicationProviderEventType.DELIVERED,
        "failed": CommunicationProviderEventType.FAILED,
        "canceled": CommunicationProviderEventType.FAILED,
        "undelivered": CommunicationProviderEventType.FAILED,
        "bounced": CommunicationProviderEventType.BOUNCED,
        "complained": CommunicationProviderEventType.COMPLAINED,
        "opened": CommunicationProviderEventType.OPENED,
        "clicked": CommunicationProviderEventType.CLICKED,
        "read": CommunicationProviderEventType.OPENED,
        "replied": CommunicationProviderEventType.REPLIED,
        "unsubscribed": CommunicationProviderEventType.UNSUBSCRIBED,
    }[status]
    return transport, outcome, terminal, event


def normalize_provider_outcome(
    value: ProviderObservationInput | Mapping[str, Any],
) -> ProviderObservationProposal:
    """Normalize provider-neutral state without writing CRM.

    WhatsApp and voice inputs are expected to originate from a Spring-verified
    webhook/event receipt.  The evaluator never authenticates a webhook itself.
    """

    inputs = revalidate_model_boundary(ProviderObservationInput, value)
    evidence_findings, evidence_refs = _evidence_findings(
        evidence_refs=inputs.evidence_refs,
        analysis_as_of=inputs.analysis_as_of,
        subject_ref=inputs.observation_ref,
        required_kinds=("provider_event_authenticity",),
        policy=inputs.evidence_policy,
    )
    findings = list(evidence_findings)
    if _parsed(inputs.received_at) > _parsed(inputs.analysis_as_of):
        findings.append(
            OmnichannelFinding(
                code="observation.future",
                status="indeterminate",
                message="Provider observation was received after the cutoff.",
                subject_ref=inputs.observation_ref,
            )
        )
    if inputs.authenticity == CommunicationAuthenticityGrade.FAILED:
        findings.append(
            OmnichannelFinding(
                code="observation.authenticity_failed",
                status="fail",
                message="Provider authenticity verification failed.",
                subject_ref=inputs.observation_ref,
            )
        )
    elif inputs.authenticity != CommunicationAuthenticityGrade.VERIFIED:
        findings.append(
            OmnichannelFinding(
                code="observation.authenticity_unverified",
                status="indeterminate",
                message="Provider authenticity is unverified.",
                subject_ref=inputs.observation_ref,
            )
        )
    ordered = tuple(
        sorted(findings, key=lambda item: (item.code, item.subject_ref or ""))
    )
    disposition = _disposition(ordered)
    conclusive = disposition == OmnichannelDisposition.READY
    if conclusive:
        transport, outcome, terminal, event = _normalized_status(
            inputs.channel, inputs.provider_status
        )
    else:
        transport = NormalizedTransportState.UNKNOWN
        outcome = NormalizedOutcome.UNKNOWN
        terminal = False
        event = None
    evidence_digest = _stable_digest([item.to_dict() for item in evidence_refs])
    operation_digest = _stable_digest(
        {
            "operation": PROVIDER_OBSERVATION_OPERATION.to_dict(),
            "input": inputs.to_dict(),
            "evidence_digest": evidence_digest,
        }
    )
    return ProviderObservationProposal(
        observation_ref=inputs.observation_ref,
        provider=inputs.provider,
        channel=inputs.channel,
        provider_status=inputs.provider_status,
        evaluated_at=inputs.analysis_as_of,
        proposed_disposition=disposition,
        transport_state=transport,
        outcome=outcome,
        conclusive=conclusive,
        terminal=terminal,
        provider_event_type=event,
        dispatch_receipt_digest=inputs.dispatch_receipt_digest,
        provider_event_digest=inputs.provider_event_digest,
        provider_message_digest=inputs.provider_message_digest,
        findings=ordered,
        evidence_refs=evidence_refs,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
    )


def communication_mobile_endpoint_address_commitment(
    *,
    scope: DynamicWorkflowScope,
    endpoint_ref: str,
    channel: CommunicationChannel,
    address: str,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Bind one private E.164 destination to an exact endpoint and channel."""

    if channel not in {
        CommunicationChannel.SMS,
        CommunicationChannel.WHATSAPP,
        CommunicationChannel.VOICE,
    }:
        raise ValueError("mobile endpoint commitment requires a mobile channel")
    _safe_ref(endpoint_ref, label="endpoint_ref")
    canonical = _e164(address)
    return scope_keyring.sign(
        key_id,
        _MOBILE_ENDPOINT_DOMAIN,
        {
            "schema": _MOBILE_ENDPOINT_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "endpoint_ref": endpoint_ref,
            "channel": channel,
            "address": canonical,
        },
    ).hex()


def communication_mobile_private_identifier_commitment(
    *,
    scope: DynamicWorkflowScope,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
    channel: CommunicationChannel,
    connector_account_ref: str,
    route_digest: str,
    identifier_kind: Literal["provider_message_id"],
    value: str,
) -> str:
    """Key one private provider identifier to exact scope, channel, and route."""

    if channel != CommunicationChannel.WHATSAPP:
        raise ValueError("generic mobile identifiers currently support WhatsApp only")
    _safe_ref(connector_account_ref, label="connector_account_ref")
    if re.fullmatch(_SHA256_PATTERN, route_digest) is None:
        raise ValueError("route_digest must be lowercase SHA-256")
    if re.fullmatch(_WHATSAPP_MESSAGE_ID_PATTERN, value) is None:
        raise ValueError("provider message identifier is invalid")
    return scope_keyring.sign(
        key_id,
        _MOBILE_IDENTIFIER_DOMAIN,
        {
            "schema": _MOBILE_IDENTIFIER_DOMAIN,
            "tenant_id": scope.tenant_id,
            "company_id": scope.company_id,
            "project_ref": scope.project_ref,
            "channel": channel,
            "connector_account_ref": connector_account_ref,
            "route_digest": route_digest,
            "identifier_kind": identifier_kind,
            "value": value,
        },
    ).hex()


def communication_mobile_conversation_digest(
    *,
    channel: CommunicationChannel,
    sender_resource_hmac_v1: str,
    recipient_address_hmac_v1: str,
) -> str:
    """Derive a provider-neutral mobile conversation commitment."""

    if channel not in {CommunicationChannel.SMS, CommunicationChannel.WHATSAPP}:
        raise ValueError("mobile conversation requires SMS or WhatsApp")
    if any(
        re.fullmatch(_SHA256_PATTERN, value) is None
        for value in (sender_resource_hmac_v1, recipient_address_hmac_v1)
    ):
        raise ValueError("mobile conversation inputs must be SHA-256 commitments")
    return communication_canonical_digest(
        {
            "schema": _MOBILE_CONVERSATION_SCHEMA,
            "channel": channel,
            "sender_resource_hmac_v1": sender_resource_hmac_v1,
            "recipient_address_hmac_v1": recipient_address_hmac_v1,
        }
    )


class CommunicationWhatsAppWriteRoute(_StrictModel):
    schema_id: Literal["lightbulb.communication_whatsapp_write_route.v1"] = Field(
        default=COMMUNICATION_WHATSAPP_WRITE_ROUTE_SCHEMA, alias="schema"
    )
    mode: Literal[
        OmnichannelOutboundMode.WHATSAPP_TEMPLATE,
        OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY,
    ]
    project_id: UUID
    project_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    tenant_connector_id: UUID
    route_digest: Sha256Digest
    tool: Literal[
        "whatsapp.send_template_turn",
        "whatsapp.reply_service_window_turn",
    ]
    tool_version: int = Field(ge=1)

    @model_validator(mode="after")
    def _exact_tool(self) -> "CommunicationWhatsAppWriteRoute":
        if self.tool != self.mode.tool:
            raise ValueError("WhatsApp route tool does not match message mode")
        return self


class CommunicationOmnichannelTurnBinding(CommunicationArtifact):
    """Sealed exact mobile audience, content, policy, route, and mode authority."""

    schema_id: Literal["lightbulb.communication_omnichannel_turn_binding.v1"] = Field(
        default=COMMUNICATION_OMNICHANNEL_TURN_BINDING_SCHEMA, alias="schema"
    )
    binding_ref: OpaqueRef
    mode: OmnichannelOutboundMode
    channel: CommunicationChannel
    thread_ref: OpaqueRef
    thread_digest: Sha256Digest
    thread_version: int = Field(ge=1)
    thread_state: CommunicationThreadState
    thread_participant_party_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2, max_length=100
    )
    draft_digest: Sha256Digest
    jurisdiction_policy_digest: Sha256Digest
    jurisdiction: JurisdictionCode
    sender_endpoint_digest: Sha256Digest
    recipient_party_ref: OpaqueRef
    recipient_party_digest: Sha256Digest
    recipient_endpoint_ref: OpaqueRef
    recipient_endpoint_digest: Sha256Digest
    body_sha256: Sha256Digest
    parent_message_sha256: Sha256Digest | None = None
    template_ref: OpaqueRef | None = None
    template_version: int | None = Field(default=None, ge=1)
    template_digest: Sha256Digest | None = None
    provider_template_name_sha256: Sha256Digest | None = None
    template_language: str | None = Field(
        default=None, pattern=_TEMPLATE_LANGUAGE_PATTERN
    )
    template_parameters_sha256: Sha256Digest | None = None
    project_id: UUID
    project_ref: OpaqueRef
    connector_account_ref: OpaqueRef
    tenant_connector_id: UUID
    write_route_digest: Sha256Digest
    write_tool: Literal[
        "twilio.send_sms_turn",
        "whatsapp.send_template_turn",
        "whatsapp.reply_service_window_turn",
    ]
    write_tool_version: int = Field(ge=1)
    status_route_digest: Sha256Digest | None = None
    status_tool: Literal["twilio.lookup_message_status"] | None = None
    status_tool_version: int | None = Field(default=None, ge=1)
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    sender_resource_hmac_v1: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    provider_conversation_sha256: Sha256Digest
    bound_at: str
    dispatch_claimed: Literal[False] = False
    delivery_claimed: Literal[False] = False
    reply_claimed: Literal[False] = False

    @field_validator("thread_participant_party_refs", mode="before")
    @classmethod
    def _participants(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("bound_at")
    @classmethod
    def _bound(cls, value: str) -> str:
        return _timestamp(value, label="bound_at")

    @model_validator(mode="after")
    def _closed_shape(self) -> "CommunicationOmnichannelTurnBinding":
        if self.channel != self.mode.channel or self.write_tool != self.mode.tool:
            raise ValueError("omnichannel binding mixes channel or Tool authority")
        if self.thread_state == CommunicationThreadState.CLOSED:
            raise ValueError("closed communication threads are nondispatchable")
        _require_unique(self.thread_participant_party_refs, label="thread participant")
        status_fields = (
            self.status_route_digest,
            self.status_tool,
            self.status_tool_version,
        )
        if self.mode == OmnichannelOutboundMode.SMS:
            if not all(item is not None for item in status_fields):
                raise ValueError("SMS binding requires the exact status-observer route")
        elif any(item is not None for item in status_fields):
            raise ValueError(
                "WhatsApp binding cannot carry the Twilio SMS status route"
            )
        template_fields = (
            self.template_ref,
            self.template_version,
            self.template_digest,
            self.provider_template_name_sha256,
            self.template_language,
            self.template_parameters_sha256,
        )
        if self.mode == OmnichannelOutboundMode.WHATSAPP_TEMPLATE:
            if not all(item is not None for item in template_fields):
                raise ValueError("WhatsApp template binding is incomplete")
            if self.parent_message_sha256 is not None:
                raise ValueError("WhatsApp template turns cannot carry a parent")
        elif any(item is not None for item in template_fields):
            raise ValueError("non-template turns cannot carry template authority")
        if (
            self.mode == OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY
            and self.parent_message_sha256 is None
        ):
            raise ValueError("WhatsApp service-window replies require a parent")
        if self.mode == OmnichannelOutboundMode.SMS and (
            self.parent_message_sha256 is not None
        ):
            raise ValueError("SMS send contracts do not invent provider threading")
        expected_conversation = communication_mobile_conversation_digest(
            channel=self.channel,
            sender_resource_hmac_v1=self.sender_resource_hmac_v1,
            recipient_address_hmac_v1=self.recipient_address_hmac_v1,
        )
        if not hmac.compare_digest(
            self.provider_conversation_sha256, expected_conversation
        ):
            raise ValueError("mobile conversation commitment is not canonical")
        return self


class CommunicationPrivateOmnichannelTurn(_StrictModel):
    """Transient content/destination loaded by the trusted host at dispatch."""

    schema_id: Literal["lightbulb.communication_private_omnichannel_turn.v1"] = Field(
        default=COMMUNICATION_PRIVATE_OMNICHANNEL_TURN_SCHEMA, alias="schema"
    )
    mode: OmnichannelOutboundMode
    authority_binding_digest: Sha256Digest
    jurisdiction_policy_digest: Sha256Digest
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    sender_resource_hmac_v1: Sha256Digest
    recipient_address_hmac_v1: Sha256Digest
    provider_conversation_sha256: Sha256Digest
    private_content_ref: OpaqueRef
    sender_endpoint_ref: OpaqueRef
    recipient_endpoint_ref: OpaqueRef
    recipient_address: str = Field(min_length=9, max_length=16, repr=False)
    body: str = Field(min_length=1, max_length=1_600, repr=False)
    in_reply_to_message_id: str | None = Field(default=None, max_length=512, repr=False)
    template_ref: OpaqueRef | None = None
    template_version: int | None = Field(default=None, ge=1)
    template_digest: Sha256Digest | None = None
    provider_template_name: str | None = Field(default=None, max_length=512, repr=False)
    template_language: str | None = Field(
        default=None, pattern=_TEMPLATE_LANGUAGE_PATTERN
    )
    template_parameters: tuple[str, ...] | None = Field(
        default=None, max_length=100, repr=False
    )

    @field_validator("recipient_address")
    @classmethod
    def _recipient(cls, value: str) -> str:
        return _e164(value)

    @field_validator("body")
    @classmethod
    def _body(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("mobile body must not contain NUL")
        return value

    @field_validator("in_reply_to_message_id")
    @classmethod
    def _parent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if re.fullmatch(_WHATSAPP_MESSAGE_ID_PATTERN, value) is None:
            raise ValueError("WhatsApp parent message identifier is invalid")
        return value

    @field_validator("template_parameters", mode="before")
    @classmethod
    def _parameters_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _mode_shape(self) -> "CommunicationPrivateOmnichannelTurn":
        expected_conversation = communication_mobile_conversation_digest(
            channel=self.mode.channel,
            sender_resource_hmac_v1=self.sender_resource_hmac_v1,
            recipient_address_hmac_v1=self.recipient_address_hmac_v1,
        )
        if not hmac.compare_digest(
            self.provider_conversation_sha256, expected_conversation
        ):
            raise ValueError("private mobile conversation is not canonical")
        template_fields = (
            self.template_ref,
            self.template_version,
            self.template_digest,
            self.provider_template_name,
            self.template_language,
            self.template_parameters,
        )
        if self.mode == OmnichannelOutboundMode.WHATSAPP_TEMPLATE:
            if not all(item is not None for item in template_fields):
                raise ValueError("private WhatsApp template turn is incomplete")
            assert self.provider_template_name is not None
            if (
                re.fullmatch(r"^[a-z][a-z0-9_]{0,511}$", self.provider_template_name)
                is None
            ):
                raise ValueError("provider template name is invalid")
            assert self.template_parameters is not None
            if any(
                not item or len(item) > 1_000 or "\x00" in item or item != item.strip()
                for item in self.template_parameters
            ):
                raise ValueError("template parameters must be bounded exact strings")
            if self.in_reply_to_message_id is not None:
                raise ValueError("WhatsApp template turn cannot carry a parent")
        elif any(item is not None for item in template_fields):
            raise ValueError("non-template turn cannot carry template inputs")
        if (
            self.mode == OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY
            and self.in_reply_to_message_id is None
        ):
            raise ValueError("service-window reply requires one exact inbound parent")
        if self.mode == OmnichannelOutboundMode.SMS and (
            self.in_reply_to_message_id is not None
        ):
            raise ValueError("SMS turn cannot carry WhatsApp parent authority")
        return self

    def connector_arguments(self) -> dict[str, Any]:
        if self.mode == OmnichannelOutboundMode.SMS:
            return {"to": self.recipient_address, "body": self.body}
        if self.mode == OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY:
            return {
                "to": self.recipient_address,
                "body": self.body,
                "in_reply_to_message_id": self.in_reply_to_message_id,
            }
        return {
            "to": self.recipient_address,
            "template_name": self.provider_template_name,
            "template_language": self.template_language,
            "parameters": list(self.template_parameters or ()),
        }


class WhatsAppAcceptance(_StrictModel):
    """Exact private provider acceptance returned through Spring custody."""

    schema_id: Literal["lightbulb.whatsapp_acceptance.v1"] = Field(
        default=WHATSAPP_ACCEPTANCE_SCHEMA, alias="schema"
    )
    provider_message_id: str = Field(alias="messageId", repr=False)
    status: Literal["accepted", "queued", "sent"]
    body_sha256: Sha256Digest = Field(alias="bodySha256")
    accepted: Literal[True]
    provider_observed: Literal[True] = Field(alias="providerObserved")

    @field_validator("provider_message_id")
    @classmethod
    def _message_id(cls, value: str) -> str:
        if re.fullmatch(_WHATSAPP_MESSAGE_ID_PATTERN, value) is None:
            raise ValueError("WhatsApp message identifier is invalid")
        return value


class CommunicationPrivateWhatsAppDispatch(_StrictModel):
    """Encrypted-outbox-only WhatsApp provider identity and proof."""

    schema_id: Literal["lightbulb.communication_private_whatsapp_dispatch.v1"] = Field(
        default=COMMUNICATION_PRIVATE_WHATSAPP_DISPATCH_SCHEMA, alias="schema"
    )
    mode: Literal[
        OmnichannelOutboundMode.WHATSAPP_TEMPLATE,
        OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY,
    ]
    authority_binding_digest: Sha256Digest
    provider_commitment_key_id: str = Field(min_length=8, max_length=80)
    provider_conversation_sha256: Sha256Digest
    provider_message_id: str = Field(repr=False)
    provider_message_id_hmac_v1: Sha256Digest
    body_sha256: Sha256Digest
    accepted: Literal[True]
    provider_observed: Literal[True]

    @field_validator("provider_message_id")
    @classmethod
    def _message_id(cls, value: str) -> str:
        if re.fullmatch(_WHATSAPP_MESSAGE_ID_PATTERN, value) is None:
            raise ValueError("WhatsApp message identifier is invalid")
        return value


@dataclass(frozen=True, slots=True)
class _OmnichannelMaterializerAdapter:
    mode: OmnichannelOutboundMode

    @property
    def channel(self) -> CommunicationChannel:
        return self.mode.channel

    @property
    def provider_name(self) -> str:
        return "twilio_sms" if self.mode == OmnichannelOutboundMode.SMS else "whatsapp"

    @property
    def tool(self) -> str:
        return self.mode.tool

    def parse_route(self, value: Any) -> Any:
        if self.mode == OmnichannelOutboundMode.SMS:
            return CommunicationTwilioSmsWriteRoute.model_validate(value)
        route = CommunicationWhatsAppWriteRoute.model_validate(value)
        if route.mode != self.mode or route.tool != self.tool:
            raise ValueError("WhatsApp route crosses message-mode authority")
        return route

    def parse_private_message(self, value: Any) -> CommunicationPrivateOmnichannelTurn:
        private = CommunicationPrivateOmnichannelTurn.model_validate(value)
        if private.mode != self.mode:
            raise ValueError("private mobile turn crosses message-mode authority")
        return private

    def connector_arguments(
        self, value: CommunicationPrivateOmnichannelTurn
    ) -> dict[str, Any]:
        return value.connector_arguments()

    def provider_conversation_id(
        self, value: CommunicationPrivateOmnichannelTurn
    ) -> str:
        return value.provider_conversation_sha256

    def provider_conversation_sha256(
        self, value: CommunicationPrivateOmnichannelTurn
    ) -> str:
        return value.provider_conversation_sha256

    def parent_message_sha256(
        self, value: CommunicationPrivateOmnichannelTurn
    ) -> str | None:
        if value.in_reply_to_message_id is None:
            return None
        return communication_private_value_digest(value.in_reply_to_message_id)

    def recipient_address(self, value: CommunicationPrivateOmnichannelTurn) -> str:
        return value.recipient_address

    def subject(self, value: CommunicationPrivateOmnichannelTurn) -> None:
        return None

    def body(self, value: CommunicationPrivateOmnichannelTurn) -> str:
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
        return communication_mobile_endpoint_address_commitment(
            scope=scope,
            endpoint_ref=endpoint_ref,
            channel=self.channel,
            address=address,
            key_id=key_id,
            scope_keyring=scope_keyring,
        )

    def validate_authority_binding(self, **values: Any) -> None:
        binding = values.get("authority_binding")
        if not isinstance(binding, CommunicationOmnichannelTurnBinding):
            raise ValueError("mobile dispatch requires one sealed authority binding")
        route = values["route"]
        thread = values["thread"]
        recipient_party = values["recipient_party"]
        sender = values["sender_endpoint"]
        recipient = values["recipient_endpoint"]
        draft = values["draft"]
        private = values["private_message"]
        scope = values["scope"]
        scope_keyring = values["scope_keyring"]
        recipient_commitment = communication_mobile_endpoint_address_commitment(
            scope=scope,
            endpoint_ref=recipient.endpoint_ref,
            channel=self.channel,
            address=private.recipient_address,
            key_id=binding.provider_commitment_key_id,
            scope_keyring=scope_keyring,
        )
        parent_digest = self.parent_message_sha256(private)
        template_name_digest = (
            communication_private_value_digest(private.provider_template_name)
            if private.provider_template_name is not None
            else None
        )
        parameters_digest = (
            _stable_digest(list(private.template_parameters))
            if private.template_parameters is not None
            else None
        )
        expected = (
            self.mode,
            self.channel,
            thread.thread_ref,
            thread.artifact_digest,
            thread.version,
            thread.state,
            thread.participant_party_refs,
            draft.artifact_digest,
            private.jurisdiction_policy_digest,
            sender.artifact_digest,
            recipient_party.party_ref,
            recipient_party.artifact_digest,
            recipient.endpoint_ref,
            recipient.artifact_digest,
            draft.body_sha256,
            parent_digest,
            draft.template_ref,
            draft.template_version,
            draft.template_digest,
            template_name_digest,
            private.template_language,
            parameters_digest,
            route.project_id,
            route.project_ref,
            route.connector_account_ref,
            route.tenant_connector_id,
            route.route_digest,
            route.tool,
            route.tool_version,
            private.provider_commitment_key_id,
            private.sender_resource_hmac_v1,
            recipient_commitment,
            private.provider_conversation_sha256,
        )
        actual = (
            binding.mode,
            binding.channel,
            binding.thread_ref,
            binding.thread_digest,
            binding.thread_version,
            binding.thread_state,
            binding.thread_participant_party_refs,
            binding.draft_digest,
            binding.jurisdiction_policy_digest,
            binding.sender_endpoint_digest,
            binding.recipient_party_ref,
            binding.recipient_party_digest,
            binding.recipient_endpoint_ref,
            binding.recipient_endpoint_digest,
            binding.body_sha256,
            binding.parent_message_sha256,
            binding.template_ref,
            binding.template_version,
            binding.template_digest,
            binding.provider_template_name_sha256,
            binding.template_language,
            binding.template_parameters_sha256,
            binding.project_id,
            binding.project_ref,
            binding.connector_account_ref,
            binding.tenant_connector_id,
            binding.write_route_digest,
            binding.write_tool,
            binding.write_tool_version,
            binding.provider_commitment_key_id,
            binding.sender_resource_hmac_v1,
            binding.recipient_address_hmac_v1,
            binding.provider_conversation_sha256,
        )
        if actual != expected:
            raise ValueError(
                "mobile binding does not match exact scope/route/audience/content/policy"
            )
        if private.authority_binding_digest != binding.artifact_digest:
            raise ValueError("private mobile turn does not bind the sealed authority")
        if binding.provider_commitment_key_id != binding.receipt_key_id:
            raise ValueError(
                "mobile provider commitments must use the binding key epoch"
            )
        if binding.provider_commitment_key_id != draft.receipt_key_id:
            raise ValueError("mobile binding and draft must use one receipt key epoch")

    def validate_effect_output(
        self,
        output: Mapping[str, Any],
        private_message: CommunicationPrivateOmnichannelTurn,
        *,
        authority_binding: Any,
        scope: DynamicWorkflowScope,
        scope_keyring: CommunicationScopeKeyRing,
    ) -> CommunicationEmailEffectProof:
        if not isinstance(authority_binding, CommunicationOmnichannelTurnBinding):
            raise ValueError("mobile effect lacks sealed binding")
        body_digest = communication_private_value_digest(private_message.body)
        if self.mode == OmnichannelOutboundMode.SMS:
            parsed = TwilioSmsAcceptance.model_validate(output)
            if not hmac.compare_digest(parsed.body_sha256, body_digest):
                raise ValueError("Twilio output does not prove the approved body")
            commitment = communication_twilio_sms_private_identifier_commitment(
                scope=scope,
                key_id=private_message.provider_commitment_key_id,
                scope_keyring=scope_keyring,
                connector_account_ref=authority_binding.connector_account_ref,
                route_digest=authority_binding.write_route_digest,
                identifier_kind="message_sid",
                value=parsed.message_sid,
            )
            private_dispatch: Any = CommunicationPrivateTwilioSmsDispatch(
                provider_message_sid=parsed.message_sid,
                provider_commitment_key_id=private_message.provider_commitment_key_id,
                provider_message_sid_hmac_v1=commitment,
                body_sha256=parsed.body_sha256,
                accepted=True,
                provider_observed=True,
            )
            provider_message_id = parsed.message_sid
        else:
            parsed_whatsapp = WhatsAppAcceptance.model_validate(output)
            if not hmac.compare_digest(parsed_whatsapp.body_sha256, body_digest):
                raise ValueError("WhatsApp output does not prove the approved body")
            commitment = communication_mobile_private_identifier_commitment(
                scope=scope,
                key_id=private_message.provider_commitment_key_id,
                scope_keyring=scope_keyring,
                channel=CommunicationChannel.WHATSAPP,
                connector_account_ref=authority_binding.connector_account_ref,
                route_digest=authority_binding.write_route_digest,
                identifier_kind="provider_message_id",
                value=parsed_whatsapp.provider_message_id,
            )
            private_dispatch = CommunicationPrivateWhatsAppDispatch(
                mode=self.mode,
                authority_binding_digest=private_message.authority_binding_digest,
                provider_commitment_key_id=private_message.provider_commitment_key_id,
                provider_conversation_sha256=(
                    private_message.provider_conversation_sha256
                ),
                provider_message_id=parsed_whatsapp.provider_message_id,
                provider_message_id_hmac_v1=commitment,
                body_sha256=parsed_whatsapp.body_sha256,
                accepted=True,
                provider_observed=True,
            )
            provider_message_id = parsed_whatsapp.provider_message_id
        return CommunicationEmailEffectProof(
            provider_message_id=provider_message_id,
            provider_conversation_id=private_message.provider_conversation_sha256,
            completed=False,
            provider_message_sha256=commitment,
            provider_conversation_sha256=(private_message.provider_conversation_sha256),
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
        if not isinstance(authority_binding, CommunicationOmnichannelTurnBinding):
            raise ValueError("mobile effect lacks sealed binding")
        if self.mode == OmnichannelOutboundMode.SMS:
            return communication_twilio_sms_private_identifier_commitment(
                scope=scope,
                key_id=authority_binding.provider_commitment_key_id,
                scope_keyring=scope_keyring,
                connector_account_ref=authority_binding.connector_account_ref,
                route_digest=authority_binding.write_route_digest,
                identifier_kind="message_sid",
                value=proof.provider_message_id,
            )
        return communication_mobile_private_identifier_commitment(
            scope=scope,
            key_id=authority_binding.provider_commitment_key_id,
            scope_keyring=scope_keyring,
            channel=CommunicationChannel.WHATSAPP,
            connector_account_ref=authority_binding.connector_account_ref,
            route_digest=authority_binding.write_route_digest,
            identifier_kind="provider_message_id",
            value=proof.provider_message_id,
        )

    def provider_effect_conversation_sha256(
        self,
        proof: CommunicationEmailEffectProof,
        *,
        authority_binding: Any,
        **_: Any,
    ) -> str:
        if not isinstance(authority_binding, CommunicationOmnichannelTurnBinding):
            raise ValueError("mobile effect lacks sealed binding")
        if not hmac.compare_digest(
            proof.provider_conversation_id,
            authority_binding.provider_conversation_sha256,
        ):
            raise ValueError("mobile effect conversation does not match binding")
        return authority_binding.provider_conversation_sha256


_TWILIO_SMS_MATERIALIZER_ADAPTER = _OmnichannelMaterializerAdapter(
    OmnichannelOutboundMode.SMS
)
_WHATSAPP_TEMPLATE_MATERIALIZER_ADAPTER = _OmnichannelMaterializerAdapter(
    OmnichannelOutboundMode.WHATSAPP_TEMPLATE
)
_WHATSAPP_SERVICE_WINDOW_MATERIALIZER_ADAPTER = _OmnichannelMaterializerAdapter(
    OmnichannelOutboundMode.WHATSAPP_SERVICE_WINDOW_REPLY
)


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(value, DynamicWorkflowScope):
        return DynamicWorkflowScope.model_validate(value.model_dump(mode="python"))
    return DynamicWorkflowScope.model_validate(value)


def _materialize_mobile_turn(
    *,
    provider_adapter: _OmnichannelMaterializerAdapter,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    jurisdiction_policy_decision: CommunicationJurisdictionPolicyDecision
    | Mapping[str, Any],
    omnichannel_binding: CommunicationOmnichannelTurnBinding | Mapping[str, Any],
    recipient_endpoint: CommunicationEndpointBinding | Mapping[str, Any],
    draft: CommunicationMessageDraft | Mapping[str, Any],
    executor: Any,
    now: datetime,
    private_dispatch_sink: CommunicationPrivateDispatchSink,
    preview_only: bool = True,
    **arguments: Any,
) -> CommunicationMaterializationResult:
    workflow_scope = _workflow_scope(scope)
    current = _utc(now, label="now")
    policy = verify_communication_artifact(
        jurisdiction_policy_decision,
        artifact_type=CommunicationJurisdictionPolicyDecision,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        at=current,
    )
    binding = verify_communication_artifact(
        omnichannel_binding,
        artifact_type=CommunicationOmnichannelTurnBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    trusted_draft = verify_communication_artifact(
        draft,
        artifact_type=CommunicationMessageDraft,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    trusted_recipient = verify_communication_artifact(
        recipient_endpoint,
        artifact_type=CommunicationEndpointBinding,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    )
    if policy.disposition != CommunicationPolicyDisposition.ALLOW:
        raise ValueError("jurisdiction policy does not allow dispatch")
    expected_policy = (
        trusted_draft.artifact_digest,
        trusted_draft.purpose,
        provider_adapter.channel,
        trusted_recipient.artifact_digest,
    )
    actual_policy = (
        policy.draft_digest,
        policy.purpose,
        policy.channel,
        policy.recipient_endpoint_digest,
    )
    if actual_policy != expected_policy:
        raise ValueError(
            "jurisdiction policy does not bind the exact draft and endpoint"
        )
    if (
        binding.mode != provider_adapter.mode
        or binding.jurisdiction_policy_digest != policy.artifact_digest
        or binding.jurisdiction != policy.jurisdiction
        or binding.draft_digest != trusted_draft.artifact_digest
        or binding.recipient_endpoint_digest != trusted_recipient.artifact_digest
    ):
        raise ValueError(
            "omnichannel binding does not bind exact policy/draft/endpoint"
        )
    if not preview_only and not isinstance(executor, HostedConnectorExecutor):
        raise ValueError(
            "live mobile dispatch requires HostedConnectorExecutor and Spring custody"
        )
    if arguments.get("_recovery_authority") is not None:
        raise ValueError(
            "mobile crash recovery is not certified; ambiguous acceptance must not resend"
        )
    return _materialize_communication_turn(
        provider_adapter=provider_adapter,
        authority_binding=binding,
        private_dispatch_sink=private_dispatch_sink,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        recipient_endpoint=trusted_recipient,
        draft=trusted_draft,
        executor=executor,
        now=current,
        preview_only=preview_only,
        **arguments,
    )


def materialize_twilio_sms_communication_turn(
    **arguments: Any,
) -> CommunicationMaterializationResult:
    """Preview or host-dispatch one exact governed Twilio SMS turn."""

    return _materialize_mobile_turn(
        provider_adapter=_TWILIO_SMS_MATERIALIZER_ADAPTER,
        **arguments,
    )


def materialize_whatsapp_template_communication_turn(
    **arguments: Any,
) -> CommunicationMaterializationResult:
    """Preview or host-dispatch one exact governed WhatsApp template turn."""

    return _materialize_mobile_turn(
        provider_adapter=_WHATSAPP_TEMPLATE_MATERIALIZER_ADAPTER,
        **arguments,
    )


def materialize_whatsapp_service_window_communication_turn(
    **arguments: Any,
) -> CommunicationMaterializationResult:
    """Preview or host-dispatch one exact service-window WhatsApp reply."""

    return _materialize_mobile_turn(
        provider_adapter=_WHATSAPP_SERVICE_WINDOW_MATERIALIZER_ADAPTER,
        **arguments,
    )


class TwilioSmsObservationEffectBoundary(_StrictModel):
    connector_reads: Literal[1] = 1
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    external_systems_changed: Literal[False] = False
    delivery_claim_authorized: Literal[False] = False
    outcome_written: Literal[False] = False
    spring_route_and_audit_authority_required: Literal[True] = True


class TwilioSmsObservationResult(_StrictModel):
    schema_id: Literal["lightbulb.communication_twilio_sms_observation_result.v1"] = (
        Field(default=TWILIO_SMS_OBSERVATION_RESULT_SCHEMA, alias="schema")
    )
    status: Literal["completed", "blocked", "failed"]
    dispatch_receipt_digest: Sha256Digest
    connector_status: ConnectorExecutionStatus
    event: CommunicationProviderEvent | None = None
    normalized: ProviderObservationProposal | None = None
    operation_digest: Sha256Digest
    summary: str = Field(min_length=1, max_length=1_000)
    effect_boundary: TwilioSmsObservationEffectBoundary = Field(
        default_factory=TwilioSmsObservationEffectBoundary
    )

    @model_validator(mode="after")
    def _shape(self) -> "TwilioSmsObservationResult":
        if self.status == "completed":
            if (
                self.connector_status != ConnectorExecutionStatus.COMPLETED
                or self.event is None
                or self.normalized is None
            ):
                raise ValueError(
                    "completed SMS observation requires event and normalization"
                )
        elif self.event is not None or self.normalized is not None:
            raise ValueError(
                "non-completed SMS observation cannot carry provider claims"
            )
        return self


def _execution_scope(value: ExecutionScope | Mapping[str, Any]) -> ExecutionScope:
    if isinstance(value, ExecutionScope):
        return ExecutionScope.model_validate(value.model_dump(mode="python"))
    return ExecutionScope.model_validate(value)


def _require_observation_scope(
    *,
    workflow_scope: DynamicWorkflowScope,
    execution_scope: ExecutionScope,
    route: CommunicationTwilioSmsStatusRoute,
) -> None:
    actual = (
        execution_scope.tenant_ref,
        execution_scope.company_ref,
        execution_scope.project_ref,
        execution_scope.actor_ref,
        execution_scope.project_id,
    )
    expected = (
        workflow_scope.tenant_id,
        workflow_scope.company_id,
        workflow_scope.project_ref,
        workflow_scope.user_id,
        route.project_id,
    )
    if actual != expected or route.project_ref != workflow_scope.project_ref:
        raise ValueError("SMS observation scope does not match authenticated scope")


def _provenance_digest(provenance: ConnectorExecutionProvenance) -> str:
    return communication_canonical_digest(
        provenance.model_dump(mode="json", by_alias=True)
    )


def observe_twilio_sms_delivery(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    execution_scope: ExecutionScope | Mapping[str, Any],
    route: CommunicationTwilioSmsStatusRoute | Mapping[str, Any],
    dispatch_receipt: CommunicationDispatchReceipt | Mapping[str, Any],
    omnichannel_binding: CommunicationOmnichannelTurnBinding | Mapping[str, Any],
    private_dispatch: CommunicationPrivateTwilioSmsDispatch | Mapping[str, Any],
    executor: HostedConnectorExecutor,
    event_ref: str,
    private_payload_ref: str,
    observed_at: datetime,
) -> TwilioSmsObservationResult:
    """Read and normalize one SMS delivery status through Spring custody.

    This observer performs one governed read.  It never treats acceptance as
    delivery, never retries a send, and never writes a CRM outcome.
    """

    if not isinstance(executor, HostedConnectorExecutor):
        raise ValueError("SMS observation requires HostedConnectorExecutor")
    current = _utc(observed_at, label="observed_at")
    workflow_scope = _workflow_scope(scope)
    runtime_scope = _execution_scope(execution_scope)
    parsed_route = CommunicationTwilioSmsStatusRoute.model_validate(route)
    _require_observation_scope(
        workflow_scope=workflow_scope,
        execution_scope=runtime_scope,
        route=parsed_route,
    )
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
    private = CommunicationPrivateTwilioSmsDispatch.model_validate(private_dispatch)
    _safe_ref(event_ref, label="event_ref")
    _safe_ref(private_payload_ref, label="private_payload_ref")
    if (
        binding.mode != OmnichannelOutboundMode.SMS
        or binding.status_route_digest != parsed_route.route_digest
        or binding.status_tool != parsed_route.tool
        or binding.status_tool_version != parsed_route.tool_version
        or binding.project_id != parsed_route.project_id
        or binding.project_ref != parsed_route.project_ref
        or binding.connector_account_ref != parsed_route.connector_account_ref
        or binding.tenant_connector_id != parsed_route.tenant_connector_id
    ):
        raise ValueError("SMS observer route does not match sealed dispatch binding")
    if (
        receipt.channel != CommunicationChannel.SMS
        or receipt.draft_digest != binding.draft_digest
        or receipt.thread_ref != binding.thread_ref
        or receipt.thread_digest != binding.thread_digest
        or receipt.route_digest != binding.write_route_digest
        or receipt.connector_account_ref != binding.connector_account_ref
        or receipt.provider_message_sha256 is None
        or receipt.provider_thread_sha256 != binding.provider_conversation_sha256
    ):
        raise ValueError("SMS dispatch receipt does not match sealed binding")
    expected_sid_hmac = communication_twilio_sms_private_identifier_commitment(
        scope=workflow_scope,
        key_id=binding.provider_commitment_key_id,
        scope_keyring=scope_keyring,
        connector_account_ref=binding.connector_account_ref,
        route_digest=binding.write_route_digest,
        identifier_kind="message_sid",
        value=private.provider_message_sid,
    )
    if (
        private.provider_commitment_key_id != binding.provider_commitment_key_id
        or not hmac.compare_digest(
            private.provider_message_sid_hmac_v1, expected_sid_hmac
        )
        or not hmac.compare_digest(receipt.provider_message_sha256, expected_sid_hmac)
        or not hmac.compare_digest(private.body_sha256, binding.body_sha256)
    ):
        raise ValueError("private SMS dispatch does not match retained commitments")
    request = ConnectorExecutionRequest(
        tool=TWILIO_LOOKUP_MESSAGE_STATUS_TOOL,
        arguments={"message_sid": private.provider_message_sid},
        scope=runtime_scope,
        connector_account_ref=parsed_route.connector_account_ref,
        effect=ConnectorEffect.READ,
        approval_required=False,
        preview_only=False,
        metadata={
            "communication_schema": "lightbulb.governed_sms_observation.v1",
            "dispatch_receipt_digest": receipt.artifact_digest,
            "authority_binding_digest": binding.artifact_digest,
        },
    )
    result = executor.execute(request)
    operation_digest = request.custody_fingerprint()
    if result.status != ConnectorExecutionStatus.COMPLETED:
        status: Literal["blocked", "failed"] = (
            "blocked" if result.status == ConnectorExecutionStatus.BLOCKED else "failed"
        )
        return TwilioSmsObservationResult(
            status=status,
            dispatch_receipt_digest=receipt.artifact_digest,
            connector_status=result.status,
            operation_digest=operation_digest,
            summary=(
                "Spring blocked the SMS delivery observation before provider evidence."
                if status == "blocked"
                else "SMS delivery observation did not return trustworthy evidence."
            ),
        )
    provenance = result.provenance
    if provenance is None or (
        provenance.tool != parsed_route.tool
        or provenance.tool_version != parsed_route.tool_version
        or provenance.server_effect != ConnectorEffect.READ
        or provenance.connector_account_ref != parsed_route.connector_account_ref
        or provenance.tenant_connector_id != parsed_route.tenant_connector_id
        or provenance.project_id != parsed_route.project_id
        or provenance.route_digest != parsed_route.route_digest
        or provenance.request_digest != operation_digest
    ):
        return TwilioSmsObservationResult(
            status="failed",
            dispatch_receipt_digest=receipt.artifact_digest,
            connector_status=result.status,
            operation_digest=operation_digest,
            summary="SMS observation provenance did not match the exact route and request.",
        )
    try:
        raw_status = dict(result.output)
        status_output = TwilioSmsStatus.model_validate(
            {
                **raw_status,
                "status": TwilioSmsProviderStatus(raw_status.get("status")),
                "eventType": CommunicationProviderEventType(
                    raw_status.get("eventType")
                ),
            }
        )
    except Exception:
        return TwilioSmsObservationResult(
            status="failed",
            dispatch_receipt_digest=receipt.artifact_digest,
            connector_status=result.status,
            operation_digest=operation_digest,
            summary="SMS provider status failed the reviewed output contract.",
        )
    observed_recipient_hmac = communication_mobile_endpoint_address_commitment(
        scope=workflow_scope,
        endpoint_ref=binding.recipient_endpoint_ref,
        channel=CommunicationChannel.SMS,
        address=status_output.recipient_address,
        key_id=binding.provider_commitment_key_id,
        scope_keyring=scope_keyring,
    )
    if (
        status_output.message_sid != private.provider_message_sid
        or not hmac.compare_digest(status_output.body_sha256, binding.body_sha256)
        or not hmac.compare_digest(
            observed_recipient_hmac, binding.recipient_address_hmac_v1
        )
    ):
        return TwilioSmsObservationResult(
            status="failed",
            dispatch_receipt_digest=receipt.artifact_digest,
            connector_status=result.status,
            operation_digest=operation_digest,
            summary="SMS provider status did not match message, recipient, and content.",
        )
    occurred_at = (
        _parsed(status_output.provider_updated_at)
        if status_output.provider_updated_at is not None
        else _parsed(provenance.completed_at)
    )
    if occurred_at > current:
        return TwilioSmsObservationResult(
            status="failed",
            dispatch_receipt_digest=receipt.artifact_digest,
            connector_status=result.status,
            operation_digest=operation_digest,
            summary="SMS provider status occurrence is after the observation cutoff.",
        )
    provenance_digest = _provenance_digest(provenance)
    private_payload_digest = communication_canonical_digest(
        {
            "schema": "lightbulb.communication_twilio_sms_status_commitment.v1",
            "dispatch_receipt_digest": receipt.artifact_digest,
            "provider_message_sid_hmac_v1": expected_sid_hmac,
            "recipient_address_hmac_v1": observed_recipient_hmac,
            "body_sha256": status_output.body_sha256,
            "status": status_output.status,
            "event_type": status_output.event_type,
            "terminal": status_output.terminal,
            "error_code": status_output.error_code,
            "provider_updated_at": status_output.provider_updated_at,
        }
    )
    provider_event_digest = communication_canonical_digest(
        {
            "schema": "lightbulb.communication_twilio_sms_provider_event.v1",
            "route_digest": parsed_route.route_digest,
            "provider_message_sid_hmac_v1": expected_sid_hmac,
            "payload_sha256": private_payload_digest,
            "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        }
    )
    event = mint_communication_artifact(
        CommunicationProviderEvent,
        {
            "event_ref": event_ref,
            "event_type": status_output.event_type,
            "dispatch_receipt_digest": receipt.artifact_digest,
            "connector_account_ref": parsed_route.connector_account_ref,
            "route_digest": parsed_route.route_digest,
            "provider_event_sha256": provider_event_digest,
            "provider_message_sha256": expected_sid_hmac,
            "provider_thread_sha256": binding.provider_conversation_sha256,
            "authenticity": CommunicationAuthenticityGrade.VERIFIED,
            "authenticity_evidence_digest": provenance_digest,
            "private_payload_ref": private_payload_ref,
            "payload_sha256": private_payload_digest,
            "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
            "received_at": current.isoformat().replace("+00:00", "Z"),
        },
        scope=workflow_scope,
        scope_keyring=scope_keyring,
        scope_key_id=binding.provider_commitment_key_id,
    )
    normalization_evidence = PrimitiveEvidenceRef(
        evidence_ref=f"sms-observation:{event_ref}",
        kind="provider_event_authenticity",
        issuer_ref="spring-governed-connector-runtime",
        subject_ref=f"sms-observation:{event_ref}",
        sha256=provenance_digest,
        observed_at=current.isoformat().replace("+00:00", "Z"),
        effective_at=occurred_at.isoformat().replace("+00:00", "Z"),
        verification_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
        classification="confidential",
        retention_policy="communication-provider-evidence",
        jurisdiction=binding.jurisdiction,
    )
    normalized = normalize_provider_outcome(
        ProviderObservationInput(
            observation_ref=f"sms-observation:{event_ref}",
            analysis_as_of=current.isoformat().replace("+00:00", "Z"),
            provider=OmnichannelProvider.TWILIO_SMS,
            channel=CommunicationChannel.SMS,
            provider_status=status_output.status.value,
            dispatch_receipt_digest=receipt.artifact_digest,
            provider_event_digest=event.artifact_digest,
            provider_message_digest=expected_sid_hmac,
            connector_account_ref=parsed_route.connector_account_ref,
            route_digest=parsed_route.route_digest,
            authenticity=CommunicationAuthenticityGrade.VERIFIED,
            authenticity_evidence_digest=provenance_digest,
            occurred_at=occurred_at.isoformat().replace("+00:00", "Z"),
            received_at=current.isoformat().replace("+00:00", "Z"),
            evidence_refs=(normalization_evidence,),
        )
    )
    return TwilioSmsObservationResult(
        status="completed",
        dispatch_receipt_digest=receipt.artifact_digest,
        connector_status=result.status,
        event=event,
        normalized=normalized,
        operation_digest=operation_digest,
        summary=(
            "Observed and normalized one exact SMS provider status; no CRM or "
            "external record was mutated."
        ),
    )


def _example_evidence(
    *,
    evidence_ref: str,
    kind: str,
    subject_ref: str,
    character: str,
    jurisdiction: str = "US",
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": "spring-communication-authority",
        "subject_ref": subject_ref,
        "sha256": character * 64,
        "observed_at": "2026-08-24T11:55:00Z",
        "effective_at": "2026-08-24T11:50:00Z",
        "verification_grade": "verified",
        "classification": "confidential",
        "retention_policy": "communication-controls-seven-years",
        "jurisdiction": jurisdiction,
    }


def _example_party_and_endpoints() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    party = CommunicationPartyRef.model_validate(
        {
            "schema": "lightbulb.communication_party_ref.v1",
            "receipt_key_id": "receipt-key-2026",
            "exact_scope_digest": "a" * 64,
            "artifact_digest": _ZERO_DIGEST,
            "artifact_hmac": "b" * 64,
            "party_ref": "contact-example",
            "party_kind": CommunicationPartyKind.EXTERNAL_PERSON,
            "identity_claim_digest": "c" * 64,
            "identity_trust": CommunicationTrustGrade.VERIFIED_ENDPOINT,
            "observed_at": "2026-08-24T11:55:00Z",
        }
    )
    endpoints: list[dict[str, Any]] = []
    for index, channel in enumerate(
        (
            CommunicationChannel.SMS,
            CommunicationChannel.WHATSAPP,
            CommunicationChannel.VOICE,
        ),
        start=1,
    ):
        endpoint = CommunicationEndpointBinding.model_validate(
            {
                "schema": "lightbulb.communication_endpoint_binding.v1",
                "receipt_key_id": "receipt-key-2026",
                "exact_scope_digest": "a" * 64,
                "artifact_digest": _ZERO_DIGEST,
                "artifact_hmac": str(index) * 64,
                "endpoint_ref": f"endpoint-{channel.value}",
                "party_ref": party.party_ref,
                "party_digest": party.artifact_digest,
                "channel": channel,
                "address_sha256": format(index + 3, "x") * 64,
                "connector_account_ref": f"account-{channel.value}",
                "route_digest": format(index + 6, "x") * 64,
                "ownership_trust": CommunicationTrustGrade.VERIFIED_ENDPOINT,
                "verification_evidence_digest": format(index + 9, "x") * 64,
                "verified_at": "2026-08-24T11:55:00Z",
            }
        )
        endpoints.append(endpoint.model_dump(mode="python", by_alias=True))
    return party.model_dump(mode="python", by_alias=True), endpoints


def _identity_example_inputs() -> dict[str, Any]:
    party, endpoints = _example_party_and_endpoints()
    return {
        "schema": CROSS_CHANNEL_IDENTITY_INPUT_SCHEMA,
        "resolution_ref": "identity-resolution-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "party": party,
        "endpoints": endpoints,
        "evidence_refs": [
            _example_evidence(
                evidence_ref="evidence-cross-channel-identity",
                kind="cross_channel_identity",
                subject_ref="contact-example",
                character="d",
            )
        ],
    }


def _policy_example_inputs() -> dict[str, Any]:
    kinds = (
        "jurisdiction",
        "channel_consent",
        "channel_suppression",
        "quiet_hours",
        "contact_frequency",
    )
    return {
        "schema": JURISDICTION_CHANNEL_POLICY_INPUT_SCHEMA,
        "evaluation_ref": "jurisdiction-policy-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "draft_ref": "draft-example",
        "draft_digest": "1" * 64,
        "purpose": CommunicationPurpose.SERVICE,
        "channel": CommunicationChannel.SMS,
        "recipient_endpoint_ref": "endpoint-sms",
        "recipient_endpoint_digest": "2" * 64,
        "jurisdiction": "US-NY",
        "lawful_basis_code": "express_consent",
        "consent_status": CommunicationConsentStatus.GRANTED,
        "suppression_status": CommunicationSuppressionStatus.CLEAR,
        "quiet_hours_status": CommunicationQuietHoursStatus.CLEAR,
        "frequency_status": CommunicationFrequencyStatus.WITHIN_LIMIT,
        "evidence_refs": [
            _example_evidence(
                evidence_ref=f"evidence-policy-{index}",
                kind=kind,
                subject_ref="endpoint-sms",
                character=str(index),
                jurisdiction="US-NY",
            )
            for index, kind in enumerate(kinds, start=3)
        ],
    }


def _voice_example_inputs() -> dict[str, Any]:
    kinds = ("cross_channel_identity", "jurisdiction_policy", "voice_script")
    return {
        "schema": VOICE_CALL_PLAN_INPUT_SCHEMA,
        "plan_ref": "voice-plan-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "purpose": CommunicationPurpose.SERVICE,
        "party_ref": "contact-example",
        "voice_endpoint_ref": "endpoint-voice",
        "voice_endpoint_digest": "3" * 64,
        "recipient_address_hmac_v1": "4" * 64,
        "identity_resolution_digest": "5" * 64,
        "identity_disposition": OmnichannelDisposition.READY,
        "jurisdiction_policy_digest": "6" * 64,
        "jurisdiction_policy_disposition": OmnichannelDisposition.READY,
        "jurisdiction": "US-NY",
        "script_ref": "voice-script-example",
        "script_version": 2,
        "script_digest": "6" * 64,
        "script_status": "approved",
        "voice_profile_ref": "voice-profile-approved",
        "instruction_codes": [
            VoiceInstructionCode.PLAY_APPROVED_SCRIPT,
            VoiceInstructionCode.END_CALL,
        ],
        "maximum_duration_seconds": 120,
        "scheduled_for": "2026-08-24T12:05:00Z",
        "route_digest": "7" * 64,
        "connector_account_ref": "account-voice",
        "evidence_refs": [
            _example_evidence(
                evidence_ref=f"evidence-voice-{index}",
                kind=kind,
                subject_ref="contact-example",
                character=character,
                jurisdiction="US-NY",
            )
            for index, (kind, character) in enumerate(
                zip(kinds, ("8", "9", "a"), strict=True), start=1
            )
        ],
    }


def _observation_example_inputs() -> dict[str, Any]:
    return {
        "schema": PROVIDER_OBSERVATION_INPUT_SCHEMA,
        "observation_ref": "observation-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "provider": OmnichannelProvider.WHATSAPP_CLOUD,
        "channel": CommunicationChannel.WHATSAPP,
        "provider_status": "delivered",
        "dispatch_receipt_digest": "a" * 64,
        "provider_event_digest": "b" * 64,
        "provider_message_digest": "c" * 64,
        "connector_account_ref": "account-whatsapp",
        "route_digest": "d" * 64,
        "authenticity": CommunicationAuthenticityGrade.VERIFIED,
        "authenticity_evidence_digest": "e" * 64,
        "occurred_at": "2026-08-24T11:58:00Z",
        "received_at": "2026-08-24T11:59:00Z",
        "evidence_refs": [
            _example_evidence(
                evidence_ref="evidence-provider-event",
                kind="provider_event_authenticity",
                subject_ref="observation-example",
                character="f",
            )
        ],
    }


def _implementation_contract(
    *, operation: PrimitiveOperationSpec, boundary: OmnichannelEffectBoundary
) -> dict[str, Any]:
    return {
        "operation_contract": operation.to_dict(),
        "effect_boundary": boundary.to_dict(),
        "authority_boundary": {
            "sdk": "deterministic_read_only_proposal",
            "system_of_record": "spring_control_plane",
            "tenant_company_scope": "spring_control_plane",
            "rbac": "spring_control_plane",
            "consent_and_suppression": "spring_control_plane",
            "approvals": "spring_control_plane",
            "audit_and_provider_id_custody": "spring_control_plane",
            "provider_execution": "connector_runtime",
        },
    }


class ResolveCrossChannelIdentityPrimitive(
    BusinessProcessPrimitive[CrossChannelIdentityInput, CrossChannelIdentityProposal]
):
    primitive_ref = "communication.resolve_cross_channel_identity"
    version = "1.0.0"
    title = "Resolve cross-channel communication identity"
    description = "Propose endpoint identity linkage without merging identity records."
    input_model = CrossChannelIdentityInput
    output_model = CrossChannelIdentityProposal
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _identity_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract.update(
            _implementation_contract(
                operation=IDENTITY_RESOLUTION_OPERATION,
                boundary=OmnichannelEffectBoundary(),
            )
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CrossChannelIdentityInput,
    ) -> PrimitiveExecutionResult[CrossChannelIdentityProposal]:
        del context
        output = resolve_cross_channel_identity(inputs)
        return _read_only_primitive_result(
            primitive=self,
            output=output,
            summary=(
                "Cross-channel identity evaluated without merging or mutating records."
            ),
            event_type="communication.cross_channel_identity_evaluated",
            artifact_kind="cross_channel_identity_proposal",
        )


class EvaluateJurisdictionChannelPolicyPrimitive(
    BusinessProcessPrimitive[
        JurisdictionChannelPolicyInput,
        JurisdictionChannelPolicyProposal,
    ]
):
    primitive_ref = "communication.evaluate_jurisdiction_channel_policy"
    version = "1.0.0"
    title = "Evaluate jurisdiction and channel policy"
    description = "Evaluate consent and suppression without granting contact authority."
    input_model = JurisdictionChannelPolicyInput
    output_model = JurisdictionChannelPolicyProposal
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _policy_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract.update(
            _implementation_contract(
                operation=JURISDICTION_POLICY_OPERATION,
                boundary=OmnichannelEffectBoundary(),
            )
        )
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: JurisdictionChannelPolicyInput,
    ) -> PrimitiveExecutionResult[JurisdictionChannelPolicyProposal]:
        del context
        output = evaluate_jurisdiction_channel_policy(inputs)
        return _read_only_primitive_result(
            primitive=self,
            output=output,
            summary="Jurisdiction and channel policy evaluated without granting consent.",
            event_type="communication.jurisdiction_channel_policy_evaluated",
            artifact_kind="jurisdiction_channel_policy_proposal",
        )


class PlanGovernedVoiceCallPrimitive(
    BusinessProcessPrimitive[VoiceCallPlanInput, VoiceCallPlanProposal]
):
    primitive_ref = "communication.plan_governed_voice_call"
    version = "1.0.0"
    title = "Plan a governed voice call"
    description = "Plan a closed voice instruction sequence without placing a call."
    input_model = VoiceCallPlanInput
    output_model = VoiceCallPlanProposal
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _voice_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract.update(
            _implementation_contract(
                operation=VOICE_CALL_PLAN_OPERATION,
                boundary=OmnichannelEffectBoundary(),
            )
        )
        contract["voice_execution"] = {
            "status": "exact_hosted_route_required",
            "governed_tool": TWILIO_PLACE_CALL_TURN_TOOL,
            "arbitrary_twiml": False,
            "arbitrary_callback_url": False,
            "transfer": False,
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: VoiceCallPlanInput,
    ) -> PrimitiveExecutionResult[VoiceCallPlanProposal]:
        del context
        output = plan_governed_voice_call(inputs)
        return _read_only_primitive_result(
            primitive=self,
            output=output,
            summary="Voice call planned without placing or authorizing a call.",
            event_type="communication.voice_call_planned",
            artifact_kind="voice_call_plan_proposal",
        )


class NormalizeProviderOutcomePrimitive(
    BusinessProcessPrimitive[ProviderObservationInput, ProviderObservationProposal]
):
    primitive_ref = "communication.normalize_provider_outcome"
    version = "1.0.0"
    title = "Normalize provider delivery and outcome evidence"
    description = "Normalize authenticated provider state without writing CRM outcomes."
    input_model = ProviderObservationInput
    output_model = ProviderObservationProposal
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _observation_example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract.update(
            _implementation_contract(
                operation=PROVIDER_OBSERVATION_OPERATION,
                boundary=OmnichannelEffectBoundary(),
            )
        )
        contract["normalization_boundary"] = {
            "provider_acceptance_is_delivery": False,
            "provider_delivery_is_reply": False,
            "reply_is_business_outcome": False,
            "unverified_events_are_conclusive": False,
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProviderObservationInput,
    ) -> PrimitiveExecutionResult[ProviderObservationProposal]:
        del context
        output = normalize_provider_outcome(inputs)
        return _read_only_primitive_result(
            primitive=self,
            output=output,
            summary="Provider evidence normalized without writing a business outcome.",
            event_type="communication.provider_outcome_normalized",
            artifact_kind="provider_observation_proposal",
        )


def _read_only_primitive_result(
    *,
    primitive: Any,
    output: Any,
    summary: str,
    event_type: str,
    artifact_kind: str,
) -> PrimitiveExecutionResult[Any]:
    receipt = PrimitiveOperationReceipt(
        spec=output.operation_spec,
        status=PrimitiveOperationStatus.COMPLETED,
        request_digest=output.operation_digest,
        evidence_refs=list(output.evidence_refs),
    )
    return PrimitiveExecutionResult[Any](
        status=PrimitiveExecutionStatus.COMPLETED,
        primitive_ref=primitive.primitive_ref,
        primitive_version=primitive.version,
        summary=summary,
        output=output,
        events=[
            PrimitiveEvent(
                type=event_type,
                payload={
                    "proposed_disposition": output.proposed_disposition.value,
                    "operation_digest": output.operation_digest,
                    "proposal_digest": output.proposal_digest,
                    "external_systems_changed": False,
                },
            )
        ],
        evidence=[
            PrimitiveEvidence(
                kind=artifact_kind,
                summary=summary,
                labels=[
                    output.proposed_disposition.value,
                    "read_only",
                    "spring_authority_required",
                ],
                refs={
                    "operation_digest": output.operation_digest,
                    "evidence_digest": output.evidence_digest,
                    "proposal_digest": output.proposal_digest,
                },
            )
        ],
        evidence_refs=list(output.evidence_refs),
        operation_receipts=[receipt],
        retryable=False,
    )


__all__ = [
    "COMMUNICATION_JURISDICTION_POLICY_DECISION_SCHEMA",
    "COMMUNICATION_OMNICHANNEL_TURN_BINDING_SCHEMA",
    "COMMUNICATION_PRIVATE_OMNICHANNEL_TURN_SCHEMA",
    "COMMUNICATION_PRIVATE_WHATSAPP_DISPATCH_SCHEMA",
    "COMMUNICATION_WHATSAPP_WRITE_ROUTE_SCHEMA",
    "CROSS_CHANNEL_IDENTITY_INPUT_SCHEMA",
    "CROSS_CHANNEL_IDENTITY_PROPOSAL_SCHEMA",
    "CommunicationJurisdictionPolicyDecision",
    "CommunicationOmnichannelTurnBinding",
    "CommunicationPrivateOmnichannelTurn",
    "CommunicationPrivateTwilioVoiceTurn",
    "CommunicationPrivateWhatsAppDispatch",
    "CommunicationTwilioVoiceStatusRoute",
    "CommunicationTwilioVoiceWriteRoute",
    "CommunicationWhatsAppWriteRoute",
    "CrossChannelIdentityInput",
    "CrossChannelIdentityProposal",
    "EvaluateJurisdictionChannelPolicyPrimitive",
    "IDENTITY_RESOLUTION_OPERATION",
    "JURISDICTION_CHANNEL_POLICY_INPUT_SCHEMA",
    "JURISDICTION_CHANNEL_POLICY_PROPOSAL_SCHEMA",
    "JURISDICTION_POLICY_OPERATION",
    "JurisdictionChannelPolicyInput",
    "JurisdictionChannelPolicyProposal",
    "NormalizeProviderOutcomePrimitive",
    "NormalizedOutcome",
    "NormalizedTransportState",
    "OmnichannelDisposition",
    "OmnichannelEffectBoundary",
    "OmnichannelEvidencePolicy",
    "OmnichannelFinding",
    "OmnichannelOutboundMode",
    "OmnichannelProvider",
    "PROVIDER_OBSERVATION_INPUT_SCHEMA",
    "PROVIDER_OBSERVATION_OPERATION",
    "PROVIDER_OBSERVATION_PROPOSAL_SCHEMA",
    "PlanGovernedVoiceCallPrimitive",
    "ProviderObservationInput",
    "ProviderObservationProposal",
    "ResolveCrossChannelIdentityPrimitive",
    "TWILIO_SMS_OBSERVATION_RESULT_SCHEMA",
    "TWILIO_LOOKUP_CALL_STATUS_TOOL",
    "TWILIO_PLACE_CALL_TURN_TOOL",
    "TwilioSmsObservationEffectBoundary",
    "TwilioSmsObservationResult",
    "TWILIO_VOICE_ACCEPTANCE_SCHEMA",
    "TWILIO_VOICE_MATERIALIZATION_SCHEMA",
    "TWILIO_VOICE_OBSERVATION_SCHEMA",
    "TWILIO_VOICE_STATUS_ROUTE_SCHEMA",
    "TWILIO_VOICE_STATUS_SCHEMA",
    "TWILIO_VOICE_WRITE_ROUTE_SCHEMA",
    "TwilioVoiceDispatchReceipt",
    "TwilioVoiceExecutionEffectBoundary",
    "TwilioVoiceMaterializationResult",
    "TwilioVoiceObservationResult",
    "VOICE_CALL_PLAN_INPUT_SCHEMA",
    "VOICE_CALL_PLAN_OPERATION",
    "VOICE_CALL_PLAN_PROPOSAL_SCHEMA",
    "VoiceCallPlanInput",
    "VoiceCallPlanProposal",
    "VoiceInstructionCode",
    "WHATSAPP_ACCEPTANCE_SCHEMA",
    "WHATSAPP_REPLY_SERVICE_WINDOW_TOOL",
    "WHATSAPP_SEND_TEMPLATE_TOOL",
    "WhatsAppAcceptance",
    "communication_mobile_conversation_digest",
    "communication_mobile_endpoint_address_commitment",
    "communication_mobile_private_identifier_commitment",
    "communication_twilio_voice_private_identifier_commitment",
    "evaluate_jurisdiction_channel_policy",
    "materialize_twilio_sms_communication_turn",
    "materialize_twilio_voice_call",
    "materialize_whatsapp_service_window_communication_turn",
    "materialize_whatsapp_template_communication_turn",
    "normalize_provider_outcome",
    "observe_twilio_sms_delivery",
    "observe_twilio_voice_call",
    "plan_governed_voice_call",
    "resolve_cross_channel_identity",
]
