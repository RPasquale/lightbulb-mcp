"""Privacy-minimised contracts for governed business communication.

The contracts in this module deliberately contain no raw address, subject,
message body, provider payload, or credential fields. Hosts retain those values
in private stores and place only opaque references and SHA-256 commitments on
the durable workflow rail.

Every top-level artifact is bound to one exact :class:`DynamicWorkflowScope`
by a host-keyed digest and a domain-separated HMAC. Constructing a model does
not make it trusted; callers must use :func:`mint_communication_artifact` and
verify it at every authority boundary with
:func:`verify_communication_artifact`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Annotated,
    Any,
    Literal,
    Mapping,
    Protocol,
    TypeVar,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_serializer,
    model_validator,
)

from lightbulb.dynamic_workflows import DynamicWorkflowScope


COMMUNICATION_PARTY_REF_SCHEMA = "lightbulb.communication_party_ref.v1"
COMMUNICATION_ENDPOINT_BINDING_SCHEMA = "lightbulb.communication_endpoint_binding.v1"
COMMUNICATION_THREAD_BINDING_SCHEMA = "lightbulb.communication_thread_binding.v1"
COMMUNICATION_CONTEXT_SNAPSHOT_SCHEMA = "lightbulb.communication_context_snapshot.v1"
COMMUNICATION_MESSAGE_DRAFT_SCHEMA = "lightbulb.communication_message_draft.v1"
COMMUNICATION_CONTACT_POLICY_DECISION_SCHEMA = (
    "lightbulb.communication_contact_policy_decision.v1"
)
COMMUNICATION_CONTACT_RESERVATION_REQUEST_SCHEMA = (
    "lightbulb.communication_contact_reservation_request.v1"
)
COMMUNICATION_CONTACT_RESERVATION_SCHEMA = (
    "lightbulb.communication_contact_reservation.v1"
)
COMMUNICATION_CONTACT_RESERVATION_CONSUMPTION_SCHEMA = (
    "lightbulb.communication_contact_reservation_consumption.v1"
)
COMMUNICATION_APPROVAL_GRANT_SCHEMA = "lightbulb.communication_approval_grant.v1"
COMMUNICATION_DISPATCH_RECEIPT_SCHEMA = "lightbulb.communication_dispatch_receipt.v1"
COMMUNICATION_PROVIDER_EVENT_SCHEMA = "lightbulb.communication_provider_event.v1"
COMMUNICATION_INBOUND_MESSAGE_SCHEMA = "lightbulb.communication_inbound_message.v1"
COMMUNICATION_REPLY_INTERPRETATION_SCHEMA = (
    "lightbulb.communication_reply_interpretation.v1"
)
CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA = "lightbulb.crm_touchpoint_receipt.v1"
CRM_TOUCHPOINT_RECEIPT_SCHEMA = "lightbulb.crm_touchpoint_receipt.v2"
COMMUNICATION_OUTCOME_OBSERVATION_SCHEMA = (
    "lightbulb.communication_outcome_observation.v1"
)
COMMUNICATION_HANDOFF_SCHEMA = "lightbulb.communication_handoff.v1"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OPAQUE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_CODE_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_CAPABILITY_PATTERN = r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$"
_KEY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$"
_ZERO_DIGEST = "0" * 64
_COMPANY_CONTACT_SCOPE_DOMAIN = "lightbulb.communication_company_contact_scope.v1"
_RECIPIENT_CONTACT_DOMAIN = "lightbulb.communication_recipient_contact.v1"
_RECIPIENT_ADDRESS_DOMAIN = "lightbulb.communication_recipient_address.v1"

Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=200,
        pattern=_OPAQUE_REF_PATTERN,
    ),
]
OpaqueCode = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=_CODE_PATTERN),
]
CapabilityRef = Annotated[
    str,
    StringConstraints(min_length=3, max_length=192, pattern=_CAPABILITY_PATTERN),
]


class CommunicationPurpose(str, Enum):
    TRANSACTIONAL = "transactional"
    SERVICE = "service"
    SUPPORT = "support"
    SALES = "sales"
    MARKETING = "marketing"
    COLLECTIONS = "collections"
    OPERATIONS = "operations"
    SECURITY = "security"
    LEGAL = "legal"
    INTERNAL_COLLABORATION = "internal_collaboration"
    HUMAN_APPROVAL = "human_approval"


class CommunicationChannel(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    VOICE = "voice"
    WHATSAPP = "whatsapp"
    SLACK = "slack"
    TEAMS = "teams"
    LIGHTBULB = "lightbulb"
    WEBCHAT = "webchat"
    AGENT_BUS = "agent_bus"


class CommunicationPartyKind(str, Enum):
    CRM_CONTACT = "crm_contact"
    CRM_ACCOUNT = "crm_account"
    HUMAN_USER = "human_user"
    AGENT_WORKER = "agent_worker"
    SERVICE = "service"
    EXTERNAL_PERSON = "external_person"


class CommunicationTrustGrade(str, Enum):
    HUMAN_ATTESTED = "human_attested"
    HOST_ATTESTED = "host_attested"
    PROVIDER_ATTESTED = "provider_attested"
    VERIFIED_ENDPOINT = "verified_endpoint"
    MODEL_INFERRED = "model_inferred"
    UNVERIFIED = "unverified"


class CommunicationAuthenticityGrade(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNVERIFIED = "unverified"


class CommunicationThreadState(str, Enum):
    OPEN = "open"
    AWAITING_REPLY = "awaiting_reply"
    REPLIED = "replied"
    CLOSED = "closed"


class CommunicationDataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CommunicationPolicyDisposition(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"


class CommunicationConsentStatus(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"
    UNKNOWN = "unknown"
    NOT_REQUIRED = "not_required"


class CommunicationSuppressionStatus(str, Enum):
    CLEAR = "clear"
    SUPPRESSED = "suppressed"
    UNKNOWN = "unknown"


class CommunicationQuietHoursStatus(str, Enum):
    CLEAR = "clear"
    ACTIVE = "active"
    UNKNOWN = "unknown"


class CommunicationFrequencyStatus(str, Enum):
    WITHIN_LIMIT = "within_limit"
    EXCEEDED = "exceeded"
    UNKNOWN = "unknown"


class CommunicationApprovalDisposition(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"


class CommunicationDispatchState(str, Enum):
    ACCEPTED = "accepted"
    AMBIGUOUS = "ambiguous"
    FAILED = "failed"


class CommunicationProviderEventType(str, Enum):
    QUEUED = "queued"
    ACCEPTED = "accepted"
    DELIVERED = "delivered"
    DELIVERY_DELAYED = "delivery_delayed"
    FAILED = "failed"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    OPENED = "opened"
    CLICKED = "clicked"
    REPLIED = "replied"
    UNSUBSCRIBED = "unsubscribed"


class CommunicationOutcomeDimension(str, Enum):
    TRANSPORT = "transport"
    COMPLIANCE = "compliance"
    CONVERSATION = "conversation"
    CRM = "crm"


class CommunicationTouchpointType(str, Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    DELIVERY = "delivery"
    REPLY = "reply"
    OUTCOME = "outcome"


class CommunicationHandoffEffect(str, Enum):
    READ = "read"
    DRAFT = "draft"
    WRITE = "write"


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


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, datetime):
        return _normalized_timestamp(value.isoformat())
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported canonical communication value: {type(value)!r}")


def communication_canonical_json(value: Any) -> bytes:
    """Serialize supported values as deterministic, bounded JSON bytes."""

    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def communication_canonical_digest(value: Any) -> str:
    """Return the canonical SHA-256 digest for a communication value."""

    return hashlib.sha256(communication_canonical_json(value)).hexdigest()


def communication_private_value_digest(value: str) -> str:
    """Commit a private boundary value without retaining it in an artifact."""

    if not isinstance(value, str) or not value:
        raise ValueError("private value must be a non-empty string")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str, *, label: str = "timestamp") -> str:
    return _parse_timestamp(value, label=label).isoformat().replace("+00:00", "Z")


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _immutable_sequence(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


class CommunicationScopeKeyRing(Protocol):
    """Trusted host contract for exact-scope digests and HMAC signatures."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


class CommunicationArtifact(_StrictModel):
    """Common integrity envelope for every durable communication artifact."""

    schema_id: str = Field(alias="schema")
    receipt_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=_KEY_ID_PATTERN,
    )
    exact_scope_digest: Sha256Digest
    artifact_digest: Sha256Digest
    artifact_hmac: Sha256Digest

    @model_validator(mode="after")
    def _canonical_artifact_digest(self) -> "CommunicationArtifact":
        expected = communication_canonical_digest(self.digest_payload())
        if self.artifact_digest not in {_ZERO_DIGEST, expected}:
            raise ValueError("artifact digest does not match canonical payload")
        object.__setattr__(self, "artifact_digest", expected)
        return self

    def digest_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"artifact_digest", "artifact_hmac"},
        )

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"artifact_hmac"},
        )


class GrowthSourceBinding(_StrictModel):
    """Opaque provenance link only; no Growth learning or plan content."""

    source_ref: OpaqueRef
    source_digest: Sha256Digest


class CommunicationPartyRef(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_party_ref.v1"] = Field(
        default=COMMUNICATION_PARTY_REF_SCHEMA,
        alias="schema",
    )
    party_ref: OpaqueRef
    party_kind: CommunicationPartyKind
    identity_claim_digest: Sha256Digest
    identity_trust: CommunicationTrustGrade
    crm_contact_ref: OpaqueRef | None = None
    crm_account_ref: OpaqueRef | None = None
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def _observed_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="observed_at")

    @model_validator(mode="after")
    def _crm_identity_shape(self) -> "CommunicationPartyRef":
        if self.party_kind == CommunicationPartyKind.CRM_CONTACT and (
            self.crm_contact_ref is None
        ):
            raise ValueError("CRM contact parties require crm_contact_ref")
        if self.party_kind == CommunicationPartyKind.CRM_ACCOUNT and (
            self.crm_account_ref is None
        ):
            raise ValueError("CRM account parties require crm_account_ref")
        return self


class CommunicationEndpointBinding(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_endpoint_binding.v1"] = Field(
        default=COMMUNICATION_ENDPOINT_BINDING_SCHEMA,
        alias="schema",
    )
    endpoint_ref: OpaqueRef
    party_ref: OpaqueRef
    party_digest: Sha256Digest
    channel: CommunicationChannel
    address_sha256: Sha256Digest
    connector_account_ref: OpaqueRef | None = None
    route_digest: Sha256Digest | None = None
    ownership_trust: CommunicationTrustGrade
    verification_evidence_digest: Sha256Digest | None = None
    verified_at: str | None = None

    @field_validator("verified_at")
    @classmethod
    def _verified_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, label="verified_at")

    @model_validator(mode="after")
    def _complete_route_and_verification(self) -> "CommunicationEndpointBinding":
        routed = (self.connector_account_ref, self.route_digest)
        if any(item is not None for item in routed) and not all(
            item is not None for item in routed
        ):
            raise ValueError("connector account and route digest must be paired")
        if self.channel not in {
            CommunicationChannel.LIGHTBULB,
            CommunicationChannel.WEBCHAT,
            CommunicationChannel.AGENT_BUS,
        } and not all(item is not None for item in routed):
            raise ValueError("external endpoints require an exact connector route")
        verification = (self.verification_evidence_digest, self.verified_at)
        if any(item is not None for item in verification) and not all(
            item is not None for item in verification
        ):
            raise ValueError("endpoint verification fields must be paired")
        if self.ownership_trust in {
            CommunicationTrustGrade.HUMAN_ATTESTED,
            CommunicationTrustGrade.HOST_ATTESTED,
            CommunicationTrustGrade.PROVIDER_ATTESTED,
            CommunicationTrustGrade.VERIFIED_ENDPOINT,
        } and not all(item is not None for item in verification):
            raise ValueError(
                "attested endpoint ownership requires verification evidence"
            )
        return self


class CommunicationThreadBinding(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_thread_binding.v1"] = Field(
        default=COMMUNICATION_THREAD_BINDING_SCHEMA,
        alias="schema",
    )
    thread_ref: OpaqueRef
    purpose: CommunicationPurpose
    primary_channel: CommunicationChannel
    participant_party_refs: tuple[OpaqueRef, ...] = Field(min_length=2, max_length=100)
    crm_trace_binding_digest: Sha256Digest | None = None
    provider_thread_sha256: Sha256Digest | None = None
    parent_message_sha256: Sha256Digest | None = None
    connector_account_ref: OpaqueRef | None = None
    route_digest: Sha256Digest | None = None
    state: CommunicationThreadState
    version: int = Field(ge=1)
    created_at: str
    last_activity_at: str

    @field_validator("participant_party_refs", mode="before")
    @classmethod
    def _participants_tuple(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("created_at", "last_activity_at")
    @classmethod
    def _thread_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _thread_binding_shape(self) -> "CommunicationThreadBinding":
        if len(self.participant_party_refs) != len(set(self.participant_party_refs)):
            raise ValueError("thread participants must be unique")
        provider_binding = (
            self.provider_thread_sha256,
            self.connector_account_ref,
            self.route_digest,
        )
        if any(item is not None for item in provider_binding) and not all(
            item is not None for item in provider_binding
        ):
            raise ValueError("provider thread binding fields must be supplied together")
        if self.parent_message_sha256 is not None and (
            self.provider_thread_sha256 is None
        ):
            raise ValueError(
                "parent message binding requires a provider thread binding"
            )
        if _parse_timestamp(
            self.last_activity_at,
            label="last_activity_at",
        ) < _parse_timestamp(self.created_at, label="created_at"):
            raise ValueError("last activity cannot precede thread creation")
        return self


class CommunicationContextFact(_StrictModel):
    fact_code: OpaqueCode
    value_digest: Sha256Digest
    source_ref: OpaqueRef
    source_digest: Sha256Digest
    observed_at: str

    @field_validator("observed_at")
    @classmethod
    def _fact_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="observed_at")


class CommunicationContextSnapshot(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_context_snapshot.v1"] = Field(
        default=COMMUNICATION_CONTEXT_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    context_ref: OpaqueRef
    thread_ref: OpaqueRef
    party_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    facts: tuple[CommunicationContextFact, ...] = Field(max_length=64)
    missing_fact_codes: tuple[OpaqueCode, ...] = Field(default=(), max_length=32)
    classification: CommunicationDataClassification
    observed_at: str
    valid_until: str
    growth_source: GrowthSourceBinding | None = None

    @field_validator("party_refs", "facts", "missing_fact_codes", mode="before")
    @classmethod
    def _context_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _context_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_context(self) -> "CommunicationContextSnapshot":
        observed = _parse_timestamp(self.observed_at, label="observed_at")
        valid_until = _parse_timestamp(self.valid_until, label="valid_until")
        if valid_until <= observed or (valid_until - observed).total_seconds() > 86_400:
            raise ValueError(
                "context lifetime must be greater than zero and at most 24 hours"
            )
        if len(self.party_refs) != len(set(self.party_refs)):
            raise ValueError("context parties must be unique")
        fact_codes = [fact.fact_code for fact in self.facts]
        if len(fact_codes) != len(set(fact_codes)):
            raise ValueError("context fact codes must be unique")
        if len(self.missing_fact_codes) != len(set(self.missing_fact_codes)):
            raise ValueError("missing context fact codes must be unique")
        if set(fact_codes).intersection(self.missing_fact_codes):
            raise ValueError("a context fact cannot also be declared missing")
        return self


class CommunicationMessageDraft(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_message_draft.v1"] = Field(
        default=COMMUNICATION_MESSAGE_DRAFT_SCHEMA,
        alias="schema",
    )
    draft_ref: OpaqueRef
    thread_ref: OpaqueRef
    thread_digest: Sha256Digest
    thread_version: int = Field(ge=1)
    thread_state: CommunicationThreadState
    thread_participant_party_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=100,
    )
    parent_message_sha256: Sha256Digest | None = None
    context_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    sender_endpoint_ref: OpaqueRef
    sender_endpoint_digest: Sha256Digest
    recipient_endpoint_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    recipient_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    contact_token_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=_KEY_ID_PATTERN,
    )
    company_contact_scope_digest: Sha256Digest
    recipient_contact_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    recipient_address_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    private_content_ref: OpaqueRef
    subject_sha256: Sha256Digest | None = None
    body_sha256: Sha256Digest
    attachment_sha256s: tuple[Sha256Digest, ...] = Field(default=(), max_length=20)
    template_ref: OpaqueRef | None = None
    template_version: int | None = Field(default=None, ge=1)
    template_digest: Sha256Digest | None = None
    growth_source: GrowthSourceBinding | None = None
    drafted_at: str

    @field_validator(
        "recipient_endpoint_refs",
        "recipient_endpoint_digests",
        "recipient_contact_digests",
        "recipient_address_digests",
        "thread_participant_party_refs",
        "attachment_sha256s",
        mode="before",
    )
    @classmethod
    def _draft_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("drafted_at")
    @classmethod
    def _drafted_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="drafted_at")

    @model_validator(mode="after")
    def _content_binding(self) -> "CommunicationMessageDraft":
        if self.contact_token_key_id == self.receipt_key_id:
            raise ValueError(
                "contact tokenization key must be independent from artifact seal key"
            )
        recipient_lengths = {
            len(self.recipient_endpoint_refs),
            len(self.recipient_endpoint_digests),
            len(self.recipient_contact_digests),
            len(self.recipient_address_digests),
        }
        if len(recipient_lengths) != 1:
            raise ValueError(
                "recipient references and endpoint/contact/address digests must have equal length"
            )
        if len(set(self.recipient_endpoint_refs)) != len(self.recipient_endpoint_refs):
            raise ValueError("draft recipients must be unique")
        if len(set(self.recipient_contact_digests)) != len(
            self.recipient_contact_digests
        ):
            raise ValueError("draft recipient contacts must be unique")
        if len(set(self.recipient_address_digests)) != len(
            self.recipient_address_digests
        ):
            raise ValueError("draft recipient addresses must be unique")
        if len(set(self.thread_participant_party_refs)) != len(
            self.thread_participant_party_refs
        ):
            raise ValueError("draft thread participants must be unique")
        template = (self.template_ref, self.template_version, self.template_digest)
        if any(item is not None for item in template) and not all(
            item is not None for item in template
        ):
            raise ValueError(
                "template reference, version, and digest must be supplied together"
            )
        if self.channel == CommunicationChannel.EMAIL and self.subject_sha256 is None:
            raise ValueError("email drafts require a subject commitment")
        return self


class CommunicationContactPolicyDecision(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_contact_policy_decision.v1"] = Field(
        default=COMMUNICATION_CONTACT_POLICY_DECISION_SCHEMA,
        alias="schema",
    )
    decision_ref: OpaqueRef
    policy_version_ref: OpaqueRef
    draft_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    recipient_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    disposition: CommunicationPolicyDisposition
    consent_status: CommunicationConsentStatus
    consent_evidence_digest: Sha256Digest | None = None
    suppression_status: CommunicationSuppressionStatus
    suppression_evidence_digest: Sha256Digest | None = None
    quiet_hours_status: CommunicationQuietHoursStatus
    quiet_hours_evidence_digest: Sha256Digest | None = None
    frequency_status: CommunicationFrequencyStatus
    frequency_evidence_digest: Sha256Digest | None = None
    reason_codes: tuple[OpaqueCode, ...] = Field(default=(), max_length=16)
    observed_at: str
    valid_until: str

    @field_validator("recipient_endpoint_digests", "reason_codes", mode="before")
    @classmethod
    def _policy_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("observed_at", "valid_until")
    @classmethod
    def _policy_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _fail_closed(self) -> "CommunicationContactPolicyDecision":
        observed = _parse_timestamp(self.observed_at, label="observed_at")
        valid_until = _parse_timestamp(self.valid_until, label="valid_until")
        lifetime = valid_until - observed
        if lifetime.total_seconds() <= 0 or lifetime.total_seconds() > 900:
            raise ValueError(
                "contact policy lifetime must be greater than zero and at most 15 minutes"
            )
        if len(set(self.recipient_endpoint_digests)) != len(
            self.recipient_endpoint_digests
        ):
            raise ValueError("policy recipients must be unique")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("policy reason codes must be unique")
        consent_ok = self.consent_status in {
            CommunicationConsentStatus.GRANTED,
            CommunicationConsentStatus.NOT_REQUIRED,
        }
        evidence_complete = all(
            digest is not None
            for digest in (
                self.consent_evidence_digest,
                self.suppression_evidence_digest,
                self.quiet_hours_evidence_digest,
                self.frequency_evidence_digest,
            )
        )
        eligible = (
            consent_ok
            and self.suppression_status == CommunicationSuppressionStatus.CLEAR
            and self.quiet_hours_status == CommunicationQuietHoursStatus.CLEAR
            and self.frequency_status == CommunicationFrequencyStatus.WITHIN_LIMIT
            and evidence_complete
        )
        if self.disposition == CommunicationPolicyDisposition.ALLOW:
            if not eligible:
                raise ValueError(
                    "allow policy requires current consent, suppression, quiet-hours, and frequency evidence"
                )
            if self.reason_codes:
                raise ValueError("allow policy must not carry blocking reason codes")
        elif not self.reason_codes:
            raise ValueError("block and review policies require reason codes")
        return self


class CommunicationContactReservationRequest(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_contact_reservation_request.v1"] = (
        Field(
            default=COMMUNICATION_CONTACT_RESERVATION_REQUEST_SCHEMA,
            alias="schema",
        )
    )
    request_ref: OpaqueRef
    draft_digest: Sha256Digest
    policy_decision_digest: Sha256Digest
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    recipient_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    contact_token_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=_KEY_ID_PATTERN,
    )
    company_contact_scope_digest: Sha256Digest
    recipient_contact_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    recipient_address_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    contact_window_ref: OpaqueRef
    run_ref: OpaqueRef
    requested_at: str
    slot_digest: Sha256Digest

    @field_validator(
        "recipient_endpoint_digests",
        "recipient_contact_digests",
        "recipient_address_digests",
        mode="before",
    )
    @classmethod
    def _reservation_recipients(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("requested_at")
    @classmethod
    def _requested_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="requested_at")

    @model_validator(mode="after")
    def _slot_binding(self) -> "CommunicationContactReservationRequest":
        if self.contact_token_key_id == self.receipt_key_id:
            raise ValueError(
                "contact tokenization key must be independent from artifact seal key"
            )
        if len(set(self.recipient_endpoint_digests)) != len(
            self.recipient_endpoint_digests
        ):
            raise ValueError("reservation recipients must be unique")
        if not (
            len(self.recipient_endpoint_digests)
            == len(self.recipient_contact_digests)
            == len(self.recipient_address_digests)
        ):
            raise ValueError("reservation endpoint/contact/address digests must align")
        expected = communication_contact_slot_digest(
            contact_token_key_id=self.contact_token_key_id,
            company_contact_scope_digest=self.company_contact_scope_digest,
            recipient_contact_digests=self.recipient_contact_digests,
            recipient_address_digests=self.recipient_address_digests,
            contact_window_ref=self.contact_window_ref,
        )
        if not hmac.compare_digest(self.slot_digest, expected):
            raise ValueError("contact reservation slot digest mismatch")
        return self


class CommunicationContactReservation(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_contact_reservation.v1"] = Field(
        default=COMMUNICATION_CONTACT_RESERVATION_SCHEMA, alias="schema"
    )
    reservation_ref: OpaqueRef
    request_digest: Sha256Digest
    slot_digest: Sha256Digest
    reserved_at: str
    valid_until: str

    @field_validator("reserved_at", "valid_until")
    @classmethod
    def _reservation_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_reservation(self) -> "CommunicationContactReservation":
        reserved = _parse_timestamp(self.reserved_at, label="reserved_at")
        valid_until = _parse_timestamp(self.valid_until, label="valid_until")
        lifetime = valid_until - reserved
        if lifetime.total_seconds() <= 0 or lifetime.total_seconds() > 900:
            raise ValueError(
                "contact reservation lifetime must be greater than zero and at most 15 minutes"
            )
        return self


class CommunicationContactReservationConsumption(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_contact_reservation_consumption.v1"] = (
        Field(
            default=COMMUNICATION_CONTACT_RESERVATION_CONSUMPTION_SCHEMA,
            alias="schema",
        )
    )
    consumption_ref: OpaqueRef
    reservation_ref: OpaqueRef
    request_digest: Sha256Digest
    slot_digest: Sha256Digest
    consumed_at: str

    @field_validator("consumed_at")
    @classmethod
    def _consumed_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="consumed_at")


class CommunicationApprovalGrant(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_approval_grant.v1"] = Field(
        default=COMMUNICATION_APPROVAL_GRANT_SCHEMA,
        alias="schema",
    )
    approval_ref: OpaqueRef
    disposition: CommunicationApprovalDisposition
    authenticated_actor_digest: Sha256Digest
    authority_evidence_digest: Sha256Digest
    draft_digest: Sha256Digest
    policy_decision_digest: Sha256Digest
    thread_digest: Sha256Digest
    thread_version: int = Field(ge=1)
    thread_state: CommunicationThreadState
    thread_participant_party_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=100,
    )
    parent_message_sha256: Sha256Digest | None = None
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    sender_endpoint_digest: Sha256Digest
    recipient_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    subject_sha256: Sha256Digest | None = None
    body_sha256: Sha256Digest
    attachment_sha256s: tuple[Sha256Digest, ...] = Field(default=(), max_length=20)
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    schedule_digest: Sha256Digest
    approved_at: str
    valid_until: str

    @field_validator(
        "recipient_endpoint_digests",
        "thread_participant_party_refs",
        "attachment_sha256s",
        mode="before",
    )
    @classmethod
    def _approval_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("approved_at", "valid_until")
    @classmethod
    def _approval_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_approval(self) -> "CommunicationApprovalGrant":
        approved_at = _parse_timestamp(self.approved_at, label="approved_at")
        valid_until = _parse_timestamp(self.valid_until, label="valid_until")
        lifetime = valid_until - approved_at
        if lifetime.total_seconds() <= 0 or lifetime.total_seconds() > 86_400:
            raise ValueError("communication approval lifetime must be at most 24 hours")
        if len(set(self.recipient_endpoint_digests)) != len(
            self.recipient_endpoint_digests
        ):
            raise ValueError("approval recipients must be unique")
        if len(set(self.thread_participant_party_refs)) != len(
            self.thread_participant_party_refs
        ):
            raise ValueError("approval thread participants must be unique")
        return self


class CommunicationDispatchReceipt(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_dispatch_receipt.v1"] = Field(
        default=COMMUNICATION_DISPATCH_RECEIPT_SCHEMA,
        alias="schema",
    )
    dispatch_ref: OpaqueRef
    draft_digest: Sha256Digest
    policy_decision_digest: Sha256Digest
    approval_digest: Sha256Digest
    reservation_consumption_digest: Sha256Digest
    thread_ref: OpaqueRef
    thread_digest: Sha256Digest
    thread_version: int = Field(ge=1)
    thread_state: CommunicationThreadState
    thread_participant_party_refs: tuple[OpaqueRef, ...] = Field(
        min_length=2,
        max_length=100,
    )
    parent_message_sha256: Sha256Digest | None = None
    purpose: CommunicationPurpose
    channel: CommunicationChannel
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    connector_execution_provenance_digest: Sha256Digest
    connector_effect_receipt_digest: Sha256Digest
    provider_message_sha256: Sha256Digest | None = None
    provider_thread_sha256: Sha256Digest | None = None
    state: CommunicationDispatchState
    attempted_at: str
    accepted_at: str | None = None

    @field_validator("thread_participant_party_refs", mode="before")
    @classmethod
    def _dispatch_participants(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("attempted_at", "accepted_at")
    @classmethod
    def _dispatch_timestamps(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _dispatch_state_shape(self) -> "CommunicationDispatchReceipt":
        if len(set(self.thread_participant_party_refs)) != len(
            self.thread_participant_party_refs
        ):
            raise ValueError("dispatch thread participants must be unique")
        if self.state == CommunicationDispatchState.ACCEPTED:
            if self.accepted_at is None or self.provider_message_sha256 is None:
                raise ValueError(
                    "accepted dispatch requires accepted_at and provider message commitment"
                )
        elif self.accepted_at is not None:
            raise ValueError("only accepted dispatch may carry accepted_at")
        return self


class CommunicationProviderEvent(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_provider_event.v1"] = Field(
        default=COMMUNICATION_PROVIDER_EVENT_SCHEMA,
        alias="schema",
    )
    event_ref: OpaqueRef
    event_type: CommunicationProviderEventType
    dispatch_receipt_digest: Sha256Digest | None = None
    connector_account_ref: OpaqueRef
    route_digest: Sha256Digest
    provider_event_sha256: Sha256Digest
    provider_message_sha256: Sha256Digest | None = None
    provider_thread_sha256: Sha256Digest | None = None
    authenticity: CommunicationAuthenticityGrade
    authenticity_evidence_digest: Sha256Digest | None = None
    private_payload_ref: OpaqueRef
    payload_sha256: Sha256Digest
    occurred_at: str
    received_at: str

    @field_validator("occurred_at", "received_at")
    @classmethod
    def _provider_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _provider_evidence(self) -> "CommunicationProviderEvent":
        if self.authenticity == CommunicationAuthenticityGrade.VERIFIED and (
            self.authenticity_evidence_digest is None
        ):
            raise ValueError("verified provider events require authenticity evidence")
        if _parse_timestamp(self.received_at, label="received_at") < _parse_timestamp(
            self.occurred_at,
            label="occurred_at",
        ):
            raise ValueError("provider event receipt cannot precede occurrence")
        return self


class CommunicationInboundMessage(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_inbound_message.v1"] = Field(
        default=COMMUNICATION_INBOUND_MESSAGE_SCHEMA,
        alias="schema",
    )
    inbound_ref: OpaqueRef
    thread_ref: OpaqueRef
    provider_event_digest: Sha256Digest
    sender_endpoint_ref: OpaqueRef
    sender_endpoint_digest: Sha256Digest
    recipient_endpoint_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=100,
    )
    private_content_ref: OpaqueRef
    content_sha256: Sha256Digest
    provider_message_sha256: Sha256Digest
    provider_thread_sha256: Sha256Digest | None = None
    in_reply_to_message_sha256: Sha256Digest | None = None
    authenticity: CommunicationAuthenticityGrade
    identity_trust: CommunicationTrustGrade
    received_at: str

    @field_validator("recipient_endpoint_digests", mode="before")
    @classmethod
    def _inbound_recipients(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("received_at")
    @classmethod
    def _received_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="received_at")

    @model_validator(mode="after")
    def _untrusted_inbound_boundary(self) -> "CommunicationInboundMessage":
        if len(set(self.recipient_endpoint_digests)) != len(
            self.recipient_endpoint_digests
        ):
            raise ValueError("inbound recipients must be unique")
        if self.identity_trust == CommunicationTrustGrade.MODEL_INFERRED and (
            self.authenticity == CommunicationAuthenticityGrade.VERIFIED
        ):
            # Authentic transport does not upgrade an inferred sender identity.
            return self
        return self


class CommunicationIntentScore(_StrictModel):
    intent_code: OpaqueCode
    confidence: float = Field(ge=0.0, le=1.0)


class CommunicationReplyInterpretation(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_reply_interpretation.v1"] = Field(
        default=COMMUNICATION_REPLY_INTERPRETATION_SCHEMA,
        alias="schema",
    )
    interpretation_ref: OpaqueRef
    inbound_message_digest: Sha256Digest
    taxonomy_ref: OpaqueRef
    taxonomy_version: int = Field(ge=1)
    intent_scores: tuple[CommunicationIntentScore, ...] = Field(
        min_length=1,
        max_length=32,
    )
    risk_codes: tuple[OpaqueCode, ...] = Field(default=(), max_length=32)
    requires_human_review: bool
    proposed_action_capabilities: tuple[CapabilityRef, ...] = Field(
        default=(),
        max_length=16,
    )
    model_provenance_digest: Sha256Digest
    trust: Literal[CommunicationTrustGrade.MODEL_INFERRED] = (
        CommunicationTrustGrade.MODEL_INFERRED
    )
    interpreted_at: str

    @field_validator(
        "intent_scores",
        "risk_codes",
        "proposed_action_capabilities",
        mode="before",
    )
    @classmethod
    def _interpretation_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("interpreted_at")
    @classmethod
    def _interpreted_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="interpreted_at")

    @model_validator(mode="after")
    def _inference_only(self) -> "CommunicationReplyInterpretation":
        intents = [score.intent_code for score in self.intent_scores]
        if len(intents) != len(set(intents)):
            raise ValueError("reply intents must be unique")
        if len(set(self.risk_codes)) != len(self.risk_codes):
            raise ValueError("reply risk codes must be unique")
        if len(set(self.proposed_action_capabilities)) != len(
            self.proposed_action_capabilities
        ):
            raise ValueError("proposed reply actions must be unique")
        return self


class CrmTouchpointReceipt(CommunicationArtifact):
    model_config = ConfigDict(revalidate_instances="never")

    schema_id: Literal[
        "lightbulb.crm_touchpoint_receipt.v1",
        "lightbulb.crm_touchpoint_receipt.v2",
    ] = Field(
        default=CRM_TOUCHPOINT_RECEIPT_SCHEMA,
        alias="schema",
    )
    touchpoint_ref: OpaqueRef
    touchpoint_type: CommunicationTouchpointType
    channel: CommunicationChannel = CommunicationChannel.EMAIL
    crm_contact_ref: OpaqueRef
    crm_account_ref: OpaqueRef | None = None
    crm_deal_ref: OpaqueRef | None = None
    crm_activity_ref: OpaqueRef
    thread_ref: OpaqueRef
    message_artifact_digest: Sha256Digest
    source_evidence_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=16,
    )
    recorded_at: str

    @model_validator(mode="before")
    @classmethod
    def _closed_schema_shape(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        schema = value.get(
            "schema", value.get("schema_id", CRM_TOUCHPOINT_RECEIPT_SCHEMA)
        )
        if schema == CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA and "channel" in value:
            raise ValueError("legacy CRM touchpoint receipts cannot carry channel")
        if schema == CRM_TOUCHPOINT_RECEIPT_SCHEMA and "channel" not in value:
            raise ValueError("CRM touchpoint receipt v2 requires sealed channel")
        return value

    @field_validator("source_evidence_digests", mode="before")
    @classmethod
    def _touchpoint_evidence(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("recorded_at")
    @classmethod
    def _recorded_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="recorded_at")

    @model_serializer(mode="wrap")
    def _serialize_closed_schema(self, handler: Any) -> dict[str, Any]:
        payload = handler(self)
        if self.schema_id == CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA:
            payload.pop("channel", None)
        return payload

    def digest_payload(self) -> dict[str, Any]:
        payload = super().digest_payload()
        if self.schema_id == CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA:
            payload.pop("channel", None)
        return payload

    def hmac_payload(self) -> dict[str, Any]:
        payload = super().hmac_payload()
        if self.schema_id == CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA:
            payload.pop("channel", None)
        return payload


class CommunicationOutcomeFact(_StrictModel):
    dimension: CommunicationOutcomeDimension
    fact_code: OpaqueCode
    value_code: OpaqueCode | None = None
    numeric_value: float | None = None
    boolean_value: bool | None = None
    source_evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def _one_typed_value(self) -> "CommunicationOutcomeFact":
        values = (self.value_code, self.numeric_value, self.boolean_value)
        if sum(value is not None for value in values) != 1:
            raise ValueError("outcome facts require exactly one typed value")
        return self


class CommunicationOutcomeObservation(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_outcome_observation.v1"] = Field(
        default=COMMUNICATION_OUTCOME_OBSERVATION_SCHEMA,
        alias="schema",
    )
    observation_ref: OpaqueRef
    thread_ref: OpaqueRef
    dispatch_receipt_digest: Sha256Digest | None = None
    inbound_message_digest: Sha256Digest | None = None
    touchpoint_receipt_digest: Sha256Digest | None = None
    facts: tuple[CommunicationOutcomeFact, ...] = Field(min_length=1, max_length=32)
    associated_source_ref: OpaqueRef
    associated_source_digest: Sha256Digest
    growth_source: GrowthSourceBinding | None = None
    observed_at: str
    causal_claim_ready: Literal[False] = False

    @field_validator("facts", mode="before")
    @classmethod
    def _outcome_facts(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("observed_at")
    @classmethod
    def _outcome_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value, label="observed_at")

    @model_validator(mode="after")
    def _fact_identity(self) -> "CommunicationOutcomeObservation":
        identities = [(fact.dimension, fact.fact_code) for fact in self.facts]
        if len(identities) != len(set(identities)):
            raise ValueError("outcome facts must be unique by dimension and code")
        if not any(
            digest is not None
            for digest in (
                self.dispatch_receipt_digest,
                self.inbound_message_digest,
                self.touchpoint_receipt_digest,
            )
        ):
            raise ValueError("outcome observation requires communication evidence")
        return self


class CommunicationHandoff(CommunicationArtifact):
    schema_id: Literal["lightbulb.communication_handoff.v1"] = Field(
        default=COMMUNICATION_HANDOFF_SCHEMA,
        alias="schema",
    )
    handoff_ref: OpaqueRef
    sender_party_ref: OpaqueRef
    sender_party_digest: Sha256Digest
    recipient_party_ref: OpaqueRef
    recipient_party_digest: Sha256Digest
    private_objective_ref: OpaqueRef
    objective_sha256: Sha256Digest
    request_schema_ref: OpaqueRef
    response_schema_ref: OpaqueRef
    artifact_refs: tuple[OpaqueRef, ...] = Field(default=(), max_length=64)
    artifact_digests: tuple[Sha256Digest, ...] = Field(default=(), max_length=64)
    allowed_capabilities: tuple[CapabilityRef, ...] = Field(default=(), max_length=64)
    allowed_effects: tuple[CommunicationHandoffEffect, ...] = Field(
        default=(),
        max_length=3,
    )
    authority_limit_digest: Sha256Digest
    classification: CommunicationDataClassification
    deadline_at: str
    requires_acknowledgement: bool
    trace_ref: OpaqueRef
    idempotency_digest: Sha256Digest
    created_at: str

    @field_validator(
        "artifact_refs",
        "artifact_digests",
        "allowed_capabilities",
        "allowed_effects",
        mode="before",
    )
    @classmethod
    def _handoff_tuples(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("deadline_at", "created_at")
    @classmethod
    def _handoff_timestamps(cls, value: str, info: Any) -> str:
        return _normalized_timestamp(value, label=info.field_name)

    @model_validator(mode="after")
    def _bounded_handoff(self) -> "CommunicationHandoff":
        if len(self.artifact_refs) != len(self.artifact_digests):
            raise ValueError("handoff artifact references and digests must align")
        if len(set(self.artifact_refs)) != len(self.artifact_refs):
            raise ValueError("handoff artifact references must be unique")
        if len(set(self.allowed_capabilities)) != len(self.allowed_capabilities):
            raise ValueError("handoff capabilities must be unique")
        if len(set(self.allowed_effects)) != len(self.allowed_effects):
            raise ValueError("handoff effects must be unique")
        if _parse_timestamp(self.deadline_at, label="deadline_at") <= _parse_timestamp(
            self.created_at,
            label="created_at",
        ):
            raise ValueError("handoff deadline must follow creation")
        return self


CommunicationArtifactT = TypeVar(
    "CommunicationArtifactT",
    bound=CommunicationArtifact,
)


def _workflow_scope(
    value: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(value, DynamicWorkflowScope):
        return DynamicWorkflowScope.model_validate(value.model_dump(mode="python"))
    return DynamicWorkflowScope.model_validate(value)


def communication_company_contact_scope_digest(
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Return a host-HMAC tenant/company scope independent of actor/project."""

    workflow_scope = _workflow_scope(scope)
    return scope_keyring.sign(
        key_id,
        _COMPANY_CONTACT_SCOPE_DOMAIN,
        {
            "schema": _COMPANY_CONTACT_SCOPE_DOMAIN,
            "tenant_id": workflow_scope.tenant_id,
            "company_id": workflow_scope.company_id,
        },
    ).hex()


def communication_recipient_contact_commitment(
    *,
    company_contact_scope_digest: str,
    party_ref: str,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Commit a company-local contact identity without exposing its reference."""

    return scope_keyring.sign(
        key_id,
        _RECIPIENT_CONTACT_DOMAIN,
        {
            "schema": _RECIPIENT_CONTACT_DOMAIN,
            "company_contact_scope_digest": company_contact_scope_digest,
            "party_ref": party_ref,
        },
    ).hex()


def communication_recipient_address_commitment(
    *,
    company_contact_scope_digest: str,
    channel: CommunicationChannel,
    address: str,
    key_id: str,
    scope_keyring: CommunicationScopeKeyRing,
) -> str:
    """Commit a normalized company-local destination without retaining it."""

    normalized = address.strip()
    if not normalized:
        raise ValueError("recipient address must be non-empty")
    if channel == CommunicationChannel.SMS:
        if re.fullmatch(r"\+[1-9][0-9]{7,14}", normalized) is None:
            raise ValueError("SMS recipient address must be canonical E.164")
    else:
        normalized = normalized.casefold()
    return scope_keyring.sign(
        key_id,
        _RECIPIENT_ADDRESS_DOMAIN,
        {
            "schema": _RECIPIENT_ADDRESS_DOMAIN,
            "company_contact_scope_digest": company_contact_scope_digest,
            "channel": channel,
            "address": normalized,
        },
    ).hex()


def communication_contact_slot_digest(
    *,
    contact_token_key_id: str,
    company_contact_scope_digest: str,
    recipient_contact_digests: tuple[str, ...],
    recipient_address_digests: tuple[str, ...],
    contact_window_ref: str,
) -> str:
    """Derive a company/contact/window slot independent of actor and project."""

    if len(recipient_contact_digests) != len(recipient_address_digests):
        raise ValueError("recipient contact/address commitments must align")
    recipient_bindings = sorted(
        communication_canonical_digest(
            {
                "schema": "lightbulb.communication_recipient_slot_binding.v1",
                "contact_digest": contact_digest,
                "address_digest": address_digest,
            }
        )
        for contact_digest, address_digest in zip(
            recipient_contact_digests,
            recipient_address_digests,
            strict=True,
        )
    )
    return communication_canonical_digest(
        {
            "schema": "lightbulb.communication_contact_slot.v1",
            "contact_token_key_id": contact_token_key_id,
            "company_contact_scope_digest": company_contact_scope_digest,
            "recipient_bindings": recipient_bindings,
            "contact_window_ref": contact_window_ref,
        }
    )


def mint_communication_artifact(
    artifact_type: type[CommunicationArtifactT],
    payload: Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    scope_key_id: str | None = None,
) -> CommunicationArtifactT:
    """Validate, exact-scope bind, digest, and host-HMAC one artifact."""

    if not issubclass(artifact_type, CommunicationArtifact):
        raise TypeError("artifact_type must derive from CommunicationArtifact")
    forbidden = {
        "receipt_key_id",
        "exact_scope_digest",
        "artifact_digest",
        "artifact_hmac",
    }
    if forbidden.intersection(payload):
        raise ValueError("communication artifact seal fields are host-owned")
    workflow_scope = _workflow_scope(scope)
    key_id = str(scope_key_id or scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    fields = dict(payload)
    if artifact_type is CommunicationContactReservationRequest:
        fields["slot_digest"] = communication_contact_slot_digest(
            contact_token_key_id=fields["contact_token_key_id"],
            company_contact_scope_digest=fields["company_contact_scope_digest"],
            recipient_contact_digests=tuple(fields["recipient_contact_digests"]),
            recipient_address_digests=tuple(fields["recipient_address_digests"]),
            contact_window_ref=fields["contact_window_ref"],
        )
    draft = artifact_type.model_validate(
        {
            **fields,
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "artifact_digest": _ZERO_DIGEST,
            "artifact_hmac": _ZERO_DIGEST,
        }
    )
    signature = scope_keyring.sign(
        key_id,
        draft.schema_id,
        draft.hmac_payload(),
    ).hex()
    return artifact_type.model_validate(
        {
            **draft.model_dump(mode="python", by_alias=True),
            "artifact_hmac": signature,
        }
    )


def verify_communication_artifact(
    value: CommunicationArtifactT | Mapping[str, Any],
    *,
    artifact_type: type[CommunicationArtifactT],
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: CommunicationScopeKeyRing,
    at: datetime | None = None,
) -> CommunicationArtifactT:
    """Verify canonical digest, exact authenticated scope, HMAC, and freshness."""

    artifact = artifact_type.model_validate(
        value.model_dump(mode="python", by_alias=True)
        if isinstance(value, CommunicationArtifact)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = scope_keyring.exact_scope_digest(
        key_id=artifact.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(
        artifact.exact_scope_digest,
        expected_scope_digest,
    ):
        raise ValueError(
            "communication artifact scope does not match authenticated scope"
        )
    expected_hmac = scope_keyring.sign(
        artifact.receipt_key_id,
        artifact.schema_id,
        artifact.hmac_payload(),
    ).hex()
    if not hmac.compare_digest(artifact.artifact_hmac, expected_hmac):
        raise ValueError("communication artifact HMAC is invalid")
    if at is not None and hasattr(artifact, "valid_until"):
        timestamp = _utc(at, label="at")
        valid_until = _parse_timestamp(
            getattr(artifact, "valid_until"),
            label="valid_until",
        )
        start_value = next(
            (
                getattr(artifact, name)
                for name in ("reserved_at", "approved_at", "observed_at")
                if hasattr(artifact, name)
            ),
            None,
        )
        if start_value is not None and timestamp < _parse_timestamp(
            start_value,
            label="valid_from",
        ):
            raise ValueError("communication artifact is not yet current")
        if timestamp >= valid_until:
            raise ValueError("communication artifact is stale")
    return artifact


__all__ = [
    "CRM_TOUCHPOINT_RECEIPT_V1_SCHEMA",
    "CRM_TOUCHPOINT_RECEIPT_SCHEMA",
    "COMMUNICATION_APPROVAL_GRANT_SCHEMA",
    "COMMUNICATION_CONTACT_POLICY_DECISION_SCHEMA",
    "COMMUNICATION_CONTACT_RESERVATION_CONSUMPTION_SCHEMA",
    "COMMUNICATION_CONTACT_RESERVATION_REQUEST_SCHEMA",
    "COMMUNICATION_CONTACT_RESERVATION_SCHEMA",
    "COMMUNICATION_CONTEXT_SNAPSHOT_SCHEMA",
    "COMMUNICATION_DISPATCH_RECEIPT_SCHEMA",
    "COMMUNICATION_ENDPOINT_BINDING_SCHEMA",
    "COMMUNICATION_HANDOFF_SCHEMA",
    "COMMUNICATION_INBOUND_MESSAGE_SCHEMA",
    "COMMUNICATION_MESSAGE_DRAFT_SCHEMA",
    "COMMUNICATION_OUTCOME_OBSERVATION_SCHEMA",
    "COMMUNICATION_PARTY_REF_SCHEMA",
    "COMMUNICATION_PROVIDER_EVENT_SCHEMA",
    "COMMUNICATION_REPLY_INTERPRETATION_SCHEMA",
    "COMMUNICATION_THREAD_BINDING_SCHEMA",
    "CommunicationApprovalDisposition",
    "CommunicationApprovalGrant",
    "CommunicationArtifact",
    "CommunicationAuthenticityGrade",
    "CommunicationChannel",
    "CommunicationConsentStatus",
    "CommunicationContactPolicyDecision",
    "CommunicationContactReservation",
    "CommunicationContactReservationConsumption",
    "CommunicationContactReservationRequest",
    "CommunicationContextFact",
    "CommunicationContextSnapshot",
    "CommunicationDataClassification",
    "CommunicationDispatchReceipt",
    "CommunicationDispatchState",
    "CommunicationEndpointBinding",
    "CommunicationFrequencyStatus",
    "CommunicationHandoff",
    "CommunicationHandoffEffect",
    "CommunicationInboundMessage",
    "CommunicationIntentScore",
    "CommunicationMessageDraft",
    "CommunicationOutcomeDimension",
    "CommunicationOutcomeFact",
    "CommunicationOutcomeObservation",
    "CommunicationPartyKind",
    "CommunicationPartyRef",
    "CommunicationPolicyDisposition",
    "CommunicationProviderEvent",
    "CommunicationProviderEventType",
    "CommunicationPurpose",
    "CommunicationQuietHoursStatus",
    "CommunicationReplyInterpretation",
    "CommunicationScopeKeyRing",
    "CommunicationSuppressionStatus",
    "CommunicationThreadBinding",
    "CommunicationThreadState",
    "CommunicationTouchpointType",
    "CommunicationTrustGrade",
    "CrmTouchpointReceipt",
    "GrowthSourceBinding",
    "communication_canonical_digest",
    "communication_canonical_json",
    "communication_company_contact_scope_digest",
    "communication_contact_slot_digest",
    "communication_private_value_digest",
    "communication_recipient_address_commitment",
    "communication_recipient_contact_commitment",
    "mint_communication_artifact",
    "verify_communication_artifact",
]
