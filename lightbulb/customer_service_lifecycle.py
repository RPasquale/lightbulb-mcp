"""Evidence-bound customer-service lifecycle primitives.

This module owns deterministic SDK mechanics for case intake/classification,
SLA calculation, governed routing/escalation, resolution verification, and
refund/credit/RMA authorization *proposals*.  It does not persist a case,
authorize money or a return, call a provider, or claim a production outcome.

Spring remains authoritative for authenticated scope, current-state fencing,
RBAC, approval, separation-of-duties enforcement, durable idempotency, audit,
and any later governed Connector Execution.  The portable receipts below are
content-bound proposal evidence; they are never live-effect provenance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect, ExecutionScope
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
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
    PrimitiveRecoveryDisposition,
    PrimitiveRecoveryPlan,
)


SERVICE_SCOPE_BINDING_SCHEMA = "lightbulb.service_scope_binding.v1"
SERVICE_CONTACT_POLICY_BINDING_SCHEMA = "lightbulb.service_contact_policy_binding.v1"
SERVICE_SLA_POLICY_SCHEMA = "lightbulb.service_sla_policy.v1"
SERVICE_TRANSITION_FENCE_SCHEMA = "lightbulb.service_transition_fence.v1"
SERVICE_CASE_LIFECYCLE_SNAPSHOT_SCHEMA = "lightbulb.service_case_lifecycle_snapshot.v1"
SERVICE_CASE_INTAKE_INPUT_SCHEMA = "lightbulb.service_case_intake_input.v1"
SERVICE_CASE_ROUTE_INPUT_SCHEMA = "lightbulb.service_case_route_input.v1"
SERVICE_RESOLUTION_SUBMISSION_INPUT_SCHEMA = (
    "lightbulb.service_resolution_submission_input.v1"
)
SERVICE_RESOLUTION_VERIFICATION_INPUT_SCHEMA = (
    "lightbulb.service_resolution_verification_input.v1"
)
SERVICE_REMEDY_PROPOSAL_INPUT_SCHEMA = "lightbulb.service_remedy_proposal_input.v1"
SERVICE_REMEDY_AUTHORIZATION_PROPOSAL_SCHEMA = (
    "lightbulb.service_remedy_authorization_proposal.v1"
)
SERVICE_REMEDY_PROPOSAL_RESULT_SCHEMA = "lightbulb.service_remedy_proposal_result.v1"
SERVICE_RESOLUTION_VERIFICATION_COMMITMENT_SCHEMA = (
    "lightbulb.service_resolution_verification_commitment.v1"
)
SPRING_SERVICE_EVIDENCE_ISSUER = "spring-service-authority"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PORTABLE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_MAX_EVIDENCE = 64
_MAX_TRANSITIONS = 32
_MAX_STAGE_EVIDENCE_AGE = timedelta(days=7)
_MAX_POLICY_EVIDENCE_AGE = timedelta(days=366)
_MONEY_QUANTUM = Decimal("0.01")
_RATIO_QUANTUM = Decimal("0.000001")


def _bounded_visible(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("reference must contain visible characters without whitespace")
    return value


def _bounded_text(value: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError("text must be trimmed and contain no control characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
    AfterValidator(_bounded_visible),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
BoundedText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4_000, strip_whitespace=False),
]

Channel = Literal["email", "web", "chat", "sms", "voice", "whatsapp", "social"]
Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["low", "medium", "high", "critical"]
CaseState = Literal[
    "classified",
    "classification_review",
    "assigned",
    "escalated",
    "resolution_pending_verification",
    "resolution_verified",
    "reopened",
    "remedy_pending_approval",
]
RemedyKind = Literal["refund", "credit", "rma"]

_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _stable_digest(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _timestamp(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _decimal(value: Any, *, quantum: Decimal, upper: Decimal | None = None) -> Decimal:
    if isinstance(value, (bool, float)) or not isinstance(value, (str, int, Decimal)):
        raise ValueError("decimal values must be strings, integers, or Decimal values")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("decimal values must use bounded notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("decimal value must be finite") from exc
    if not parsed.is_finite() or parsed != normalized or parsed < 0:
        raise ValueError("decimal value is negative or exceeds supported precision")
    if upper is not None and parsed > upper:
        raise ValueError(f"decimal value must be at most {upper}")
    return normalized


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _strong_evidence(evidence: PrimitiveEvidenceRef) -> bool:
    return (
        _GRADE_RANK[evidence.verification_grade]
        >= _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
    )


class ServiceScopeBinding(_StrictModel):
    """Expected organizational scope; authenticated context remains authoritative."""

    schema_id: Literal["lightbulb.service_scope_binding.v1"] = Field(
        default=SERVICE_SCOPE_BINDING_SCHEMA,
        alias="schema",
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID

    @field_validator("project_id", mode="before")
    @classmethod
    def _project_uuid(cls, value: Any) -> UUID:
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("project_id must be a canonical UUID")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value.lower():
            raise ValueError("project_id must be a canonical UUID")
        return parsed


class ServiceContactPolicyBinding(_StrictModel):
    """Content-bound customer/channel consent and suppression decision."""

    schema_id: Literal["lightbulb.service_contact_policy_binding.v1"] = Field(
        default=SERVICE_CONTACT_POLICY_BINDING_SCHEMA,
        alias="schema",
    )
    customer_ref: OpaqueRef
    party_ref: OpaqueRef
    channel: Channel
    endpoint_binding_ref: OpaqueRef
    purpose: Literal["customer_support"] = "customer_support"
    jurisdiction: Annotated[str, StringConstraints(min_length=2, max_length=80)]
    consent_state: Literal["granted", "not_required", "withdrawn", "unknown"]
    suppression_state: Literal["clear", "suppressed", "unknown"]
    decision_ref: OpaqueRef
    decided_at: str
    expires_at: str
    decision_digest: Sha256Digest
    evidence: PrimitiveEvidenceRef

    @field_validator("decided_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _decision_is_exact(self) -> "ServiceContactPolicyBinding":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.decided_at):
            raise ValueError("contact-policy expiry must follow the decision time")
        expected = service_contact_policy_digest(self)
        if self.decision_digest != expected or self.evidence.sha256 != expected:
            raise ValueError(
                "contact-policy decision digest does not match its exact binding"
            )
        if self.evidence.subject_ref != self.decision_ref or not _strong_evidence(
            self.evidence
        ):
            raise ValueError("contact-policy evidence must attest the exact decision")
        if self.evidence.issuer_ref != SPRING_SERVICE_EVIDENCE_ISSUER:
            raise ValueError("contact-policy evidence requires Spring issuer custody")
        if self.evidence.jurisdiction not in {None, self.jurisdiction}:
            raise ValueError("contact-policy evidence jurisdiction does not match")
        if _parsed_timestamp(self.evidence.observed_at) < _parsed_timestamp(
            self.decided_at
        ):
            raise ValueError("contact-policy evidence cannot predate the decision")
        return self


def service_contact_policy_digest(
    value: ServiceContactPolicyBinding | Mapping[str, Any],
) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=False, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    material = {
        key: payload[key]
        for key in (
            "customer_ref",
            "party_ref",
            "channel",
            "endpoint_binding_ref",
            "purpose",
            "jurisdiction",
            "consent_state",
            "suppression_state",
            "decision_ref",
            "decided_at",
            "expires_at",
        )
    }
    material["schema"] = SERVICE_CONTACT_POLICY_BINDING_SCHEMA
    return _stable_digest(material)


class ServiceSlaTarget(_StrictModel):
    first_response_minutes: int = Field(ge=1, le=10_080)
    resolution_minutes: int = Field(ge=1, le=43_200)

    @model_validator(mode="after")
    def _resolution_follows_response(self) -> "ServiceSlaTarget":
        if self.resolution_minutes < self.first_response_minutes:
            raise ValueError("resolution target cannot precede first-response target")
        return self


class ServiceSlaPolicy(_StrictModel):
    schema_id: Literal["lightbulb.service_sla_policy.v1"] = Field(
        default=SERVICE_SLA_POLICY_SCHEMA,
        alias="schema",
    )
    policy_ref: OpaqueRef
    policy_version: int = Field(ge=1, le=1_000_000)
    low: ServiceSlaTarget
    medium: ServiceSlaTarget
    high: ServiceSlaTarget
    critical: ServiceSlaTarget
    policy_digest: Sha256Digest
    evidence: PrimitiveEvidenceRef

    @model_validator(mode="after")
    def _policy_is_exact(self) -> "ServiceSlaPolicy":
        expected = service_sla_policy_digest(self)
        if self.policy_digest != expected or self.evidence.sha256 != expected:
            raise ValueError("SLA policy digest does not match its exact targets")
        if self.evidence.subject_ref != self.policy_ref or not _strong_evidence(
            self.evidence
        ):
            raise ValueError("SLA evidence must attest the exact policy revision")
        if self.evidence.issuer_ref != SPRING_SERVICE_EVIDENCE_ISSUER:
            raise ValueError("SLA evidence requires Spring issuer custody")
        ordered = (self.low, self.medium, self.high, self.critical)
        if any(
            later.first_response_minutes > earlier.first_response_minutes
            or later.resolution_minutes > earlier.resolution_minutes
            for earlier, later in zip(ordered, ordered[1:])
        ):
            raise ValueError(
                "higher-severity SLA targets cannot be slower than lower-severity targets"
            )
        return self

    def target_for(self, severity: Severity) -> ServiceSlaTarget:
        return getattr(self, severity)


def service_sla_policy_digest(value: ServiceSlaPolicy | Mapping[str, Any]) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=False, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    material = {
        "schema": SERVICE_SLA_POLICY_SCHEMA,
        "policy_ref": payload["policy_ref"],
        "policy_version": payload["policy_version"],
        "low": payload["low"],
        "medium": payload["medium"],
        "high": payload["high"],
        "critical": payload["critical"],
    }
    return _stable_digest(material)


class ServiceRiskSignals(_StrictModel):
    schema_id: Literal["lightbulb.service_risk_signals.v1"] = Field(
        default="lightbulb.service_risk_signals.v1",
        alias="schema",
    )
    safety_hazard: bool = False
    security_or_privacy_incident: bool = False
    regulatory_deadline: bool = False
    fraud_suspected: bool = False
    vulnerable_customer: bool = False
    repeated_service_failure: bool = False
    financial_exposure: Decimal = Decimal("0.00")

    @field_validator("financial_exposure", mode="before")
    @classmethod
    def _money(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class ServiceTransitionFence(_StrictModel):
    schema_id: Literal["lightbulb.service_transition_fence.v1"] = Field(
        default=SERVICE_TRANSITION_FENCE_SCHEMA,
        alias="schema",
    )
    transition_ref: OpaqueRef
    expected_revision: int = Field(ge=0, le=_MAX_TRANSITIONS)
    expected_snapshot_digest: Sha256Digest | None = None
    idempotency_key_digest: Sha256Digest

    @model_validator(mode="after")
    def _fresh_intake_or_bound_transition(self) -> "ServiceTransitionFence":
        if (self.expected_revision == 0) != (self.expected_snapshot_digest is None):
            raise ValueError(
                "revision zero is only valid for intake without a prior snapshot digest"
            )
        return self


class ServiceCaseLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.service_case_lifecycle_snapshot.v1"] = Field(
        default=SERVICE_CASE_LIFECYCLE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    party_ref: OpaqueRef
    channel: Channel
    endpoint_binding_ref: OpaqueRef
    contact_policy_decision_ref: OpaqueRef
    contact_policy_digest: Sha256Digest
    contact_policy_expires_at: str
    outbound_contact_permitted: bool
    category_ref: OpaqueRef
    classification_confidence: Decimal
    requested_severity: Severity
    severity_floor: Severity
    effective_severity: Severity
    state: CaseState
    summary_digest: Sha256Digest
    opened_at: str
    updated_at: str
    sla_policy_ref: OpaqueRef
    sla_policy_digest: Sha256Digest
    first_response_due_at: str
    resolution_due_at: str
    owner_ref: OpaqueRef | None = None
    assigned_at: str | None = None
    first_response_at: str | None = None
    escalation_ref: OpaqueRef | None = None
    escalation_owner_ref: OpaqueRef | None = None
    escalated_at: str | None = None
    resolution_ref: OpaqueRef | None = None
    resolver_ref: OpaqueRef | None = None
    resolution_submitted_at: str | None = None
    resolution_digest: Sha256Digest | None = None
    resolution_verification: Literal[
        "not_submitted", "pending", "confirmed", "rejected", "unreachable"
    ] = "not_submitted"
    outcome_verified: bool = False
    pending_remedy_proposal_digest: Sha256Digest | None = None
    revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    transition_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=_MAX_TRANSITIONS,
    )
    idempotency_key_digests: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=_MAX_TRANSITIONS,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE,
    )
    state_digest: Sha256Digest

    @field_validator("classification_confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATIO_QUANTUM, upper=Decimal("1"))

    @field_validator(
        "opened_at",
        "updated_at",
        "first_response_due_at",
        "resolution_due_at",
        "contact_policy_expires_at",
        "assigned_at",
        "first_response_at",
        "escalated_at",
        "resolution_submitted_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator(
        "transition_refs", "idempotency_key_digests", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_is_coherent_and_content_bound(self) -> "ServiceCaseLifecycleSnapshot":
        if self.revision != len(self.transition_refs) or self.revision != len(
            self.idempotency_key_digests
        ):
            raise ValueError("snapshot revision must match its transition histories")
        if len(set(self.transition_refs)) != len(self.transition_refs) or len(
            set(self.idempotency_key_digests)
        ) != len(self.idempotency_key_digests):
            raise ValueError("snapshot transition histories must be unique")
        evidence_ids = [item.evidence_ref for item in self.evidence_refs]
        evidence_digests = [item.sha256 for item in self.evidence_refs]
        if len(evidence_ids) != len(set(evidence_ids)) or len(evidence_digests) != len(
            set(evidence_digests)
        ):
            raise ValueError("snapshot evidence references and digests must be unique")
        if any(
            item.issuer_ref != SPRING_SERVICE_EVIDENCE_ISSUER
            or not _strong_evidence(item)
            for item in self.evidence_refs
        ):
            raise ValueError(
                "snapshot evidence requires attested Spring issuer custody"
            )
        if (
            _RANK[self.severity_floor] > _RANK[self.effective_severity]
            or _RANK[self.requested_severity] > _RANK[self.effective_severity]
        ):
            raise ValueError(
                "effective severity cannot be below a requested or derived floor"
            )
        opened_at = _parsed_timestamp(self.opened_at)
        updated_at = _parsed_timestamp(self.updated_at)
        if updated_at < opened_at:
            raise ValueError("snapshot update cannot precede intake")
        if _parsed_timestamp(self.first_response_due_at) < _parsed_timestamp(
            self.opened_at
        ) or _parsed_timestamp(self.resolution_due_at) < _parsed_timestamp(
            self.first_response_due_at
        ):
            raise ValueError("snapshot SLA clock is inconsistent")
        for field_name in (
            "assigned_at",
            "first_response_at",
            "escalated_at",
            "resolution_submitted_at",
        ):
            timestamp = getattr(self, field_name)
            if timestamp is not None and not (
                opened_at <= _parsed_timestamp(timestamp) <= updated_at
            ):
                raise ValueError(
                    f"snapshot {field_name} must fall within the retained case timeline"
                )
        if self.first_response_at is not None and (
            not self.outbound_contact_permitted
            or _parsed_timestamp(self.first_response_at)
            > _parsed_timestamp(self.contact_policy_expires_at)
        ):
            raise ValueError(
                "first response requires an unexpired permitted contact binding"
            )
        if any(
            _parsed_timestamp(item.observed_at) > updated_at
            or (
                item.effective_at is not None
                and _parsed_timestamp(item.effective_at) > updated_at
            )
            for item in self.evidence_refs
        ):
            raise ValueError("snapshot cannot retain evidence from its future")
        owner_states = {
            "assigned",
            "escalated",
            "resolution_pending_verification",
            "resolution_verified",
            "reopened",
            "remedy_pending_approval",
        }
        if (self.state in owner_states) != (
            self.owner_ref is not None and self.assigned_at is not None
        ):
            raise ValueError(
                "routed case states require an exact owner and assignment time"
            )
        escalation_fields = (
            self.escalation_ref,
            self.escalation_owner_ref,
            self.escalated_at,
        )
        if any(value is not None for value in escalation_fields) and any(
            value is None for value in escalation_fields
        ):
            raise ValueError(
                "escalation identity, owner, and time must be bound together"
            )
        if self.state == "escalated" and self.escalation_ref is None:
            raise ValueError("escalated state requires exact escalation identity")
        if self.state in {"classified", "classification_review", "assigned"} and (
            self.escalation_ref is not None
        ):
            raise ValueError(
                "pre-escalation case states cannot retain escalation identity"
            )
        resolution_fields = (
            self.resolution_ref,
            self.resolver_ref,
            self.resolution_submitted_at,
            self.resolution_digest,
        )
        resolution_present = all(value is not None for value in resolution_fields)
        resolution_absent = all(value is None for value in resolution_fields)
        if not resolution_present and not resolution_absent:
            raise ValueError(
                "resolution identity, resolver, time, and digest must be bound together"
            )
        if self.resolution_verification == "not_submitted" and resolution_present:
            raise ValueError(
                "unsubmitted resolution cannot contain resolution evidence"
            )
        if self.resolution_verification != "not_submitted" and not resolution_present:
            raise ValueError(
                "resolution verification requires an exact submitted resolution"
            )
        if self.outcome_verified != (self.resolution_verification == "confirmed"):
            raise ValueError("only confirmed verification may claim a verified outcome")
        if self.state in {"classified", "classification_review"} and (
            self.resolution_verification != "not_submitted"
        ):
            raise ValueError("unrouted case states cannot contain resolution outcomes")
        if self.state in {
            "assigned",
            "escalated",
        } and self.resolution_verification not in {
            "not_submitted",
            "rejected",
        }:
            raise ValueError("routed case state conflicts with resolution verification")
        if self.state == "resolution_pending_verification" and (
            self.resolution_verification not in {"pending", "unreachable"}
        ):
            raise ValueError(
                "pending resolution state requires pending or unreachable verification"
            )
        if (
            self.state == "resolution_verified"
            and self.resolution_verification != "confirmed"
        ):
            raise ValueError(
                "verified resolution state requires confirmed verification"
            )
        if self.state == "reopened" and self.resolution_verification != "rejected":
            raise ValueError("reopened state requires rejected resolution verification")
        if (self.state == "remedy_pending_approval") != (
            self.pending_remedy_proposal_digest is not None
        ):
            raise ValueError(
                "pending remedy state requires exactly one proposal digest"
            )
        expected_digest = service_case_snapshot_digest(self)
        if self.state_digest != expected_digest:
            raise ValueError("case snapshot digest does not match its exact content")
        return self


def service_case_snapshot_digest(
    value: ServiceCaseLifecycleSnapshot | Mapping[str, Any],
) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    payload.pop("state_digest", None)
    return _stable_digest(payload)


def service_transition_idempotency_digest(
    scope: ExecutionScope,
    idempotency_key: str,
) -> str:
    clean = str(idempotency_key).strip()
    if (
        not clean
        or clean != idempotency_key
        or len(clean) > 500
        or any(ord(character) < 33 for character in clean)
    ):
        raise ValueError("idempotency key must be 1 to 500 visible characters")
    return _stable_digest(
        {
            "schema": "lightbulb.service_transition_idempotency.v1",
            "tenant_ref": scope.tenant_ref,
            "company_ref": scope.company_ref,
            "project_ref": scope.project_ref,
            "project_id": str(scope.project_id or ""),
            "actor_ref": scope.actor_ref,
            "idempotency_key": clean,
        }
    )


class IntakeServiceCaseInput(_StrictModel):
    schema_id: Literal["lightbulb.service_case_intake_input.v1"] = Field(
        default=SERVICE_CASE_INTAKE_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    fence: ServiceTransitionFence
    acting_ref: OpaqueRef
    analysis_as_of: str
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    contact_policy: ServiceContactPolicyBinding
    received_at: str
    summary: BoundedText
    category_ref: OpaqueRef
    classification_confidence: Decimal
    requested_severity: Severity
    risk_signals: ServiceRiskSignals = Field(default_factory=ServiceRiskSignals)
    sla_policy: ServiceSlaPolicy
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("analysis_as_of", "received_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("classification_confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATIO_QUANTUM, upper=Decimal("1"))

    @field_validator("summary")
    @classmethod
    def _summary_text(cls, value: str) -> str:
        return _bounded_text(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _customer_binding_matches(self) -> "IntakeServiceCaseInput":
        if self.customer_ref != self.contact_policy.customer_ref:
            raise ValueError("case customer must match the contact-policy customer")
        if _parsed_timestamp(self.received_at) > _parsed_timestamp(self.analysis_as_of):
            raise ValueError("received_at cannot follow analysis_as_of")
        return self


class RouteServiceCaseInput(_StrictModel):
    schema_id: Literal["lightbulb.service_case_route_input.v1"] = Field(
        default=SERVICE_CASE_ROUTE_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    fence: ServiceTransitionFence
    acting_ref: OpaqueRef
    analysis_as_of: str
    case: ServiceCaseLifecycleSnapshot
    owner_ref: OpaqueRef
    first_response_at: str | None = None
    escalation_ref: OpaqueRef | None = None
    escalation_owner_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("analysis_as_of", "first_response_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _escalation_fields_are_bound(self) -> "RouteServiceCaseInput":
        if (self.escalation_ref is None) != (self.escalation_owner_ref is None):
            raise ValueError("escalation reference and owner must be supplied together")
        return self


class SubmitServiceResolutionInput(_StrictModel):
    schema_id: Literal["lightbulb.service_resolution_submission_input.v1"] = Field(
        default=SERVICE_RESOLUTION_SUBMISSION_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    fence: ServiceTransitionFence
    acting_ref: OpaqueRef
    analysis_as_of: str
    case: ServiceCaseLifecycleSnapshot
    resolution_ref: OpaqueRef
    resolver_ref: OpaqueRef
    resolved_at: str
    root_cause_ref: OpaqueRef
    resolution_summary: BoundedText
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("analysis_as_of", "resolved_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("resolution_summary")
    @classmethod
    def _resolution_text(cls, value: str) -> str:
        return _bounded_text(value)


class VerifyServiceResolutionInput(_StrictModel):
    schema_id: Literal["lightbulb.service_resolution_verification_input.v1"] = Field(
        default=SERVICE_RESOLUTION_VERIFICATION_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    fence: ServiceTransitionFence
    acting_ref: OpaqueRef
    analysis_as_of: str
    case: ServiceCaseLifecycleSnapshot
    expected_resolution_digest: Sha256Digest
    verifier_ref: OpaqueRef
    verified_at: str
    customer_ref: OpaqueRef
    channel: Channel
    contact_policy_decision_ref: OpaqueRef
    outcome: Literal["confirmed", "rejected", "unreachable"]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("analysis_as_of", "verified_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ProposeServiceRemedyInput(_StrictModel):
    schema_id: Literal["lightbulb.service_remedy_proposal_input.v1"] = Field(
        default=SERVICE_REMEDY_PROPOSAL_INPUT_SCHEMA,
        alias="schema",
    )
    scope: ServiceScopeBinding
    fence: ServiceTransitionFence
    acting_ref: OpaqueRef
    analysis_as_of: str
    case: ServiceCaseLifecycleSnapshot
    remedy_ref: OpaqueRef
    kind: RemedyKind
    reason_ref: OpaqueRef
    requested_risk: RiskLevel = "low"
    proposer_ref: OpaqueRef
    required_approver_ref: OpaqueRef
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    original_transaction_ref: OpaqueRef | None = None
    product_ref: OpaqueRef | None = None
    asset_ref: OpaqueRef | None = None
    serial_ref: OpaqueRef | None = None
    hazardous_return: bool = False
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_time(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal | None:
        return None if value is None else _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _remedy_fields_are_exact(self) -> "ProposeServiceRemedyInput":
        if self.kind in {"refund", "credit"}:
            if (
                self.amount is None
                or self.amount <= 0
                or self.currency is None
                or self.original_transaction_ref is None
            ):
                raise ValueError(
                    "refund and credit proposals require positive amount, currency, and transaction"
                )
            if (
                any(
                    value is not None
                    for value in (self.product_ref, self.asset_ref, self.serial_ref)
                )
                or self.hazardous_return
            ):
                raise ValueError("return fields are valid only for an RMA proposal")
        else:
            if (
                self.product_ref is None
                or self.asset_ref is None
                or self.original_transaction_ref is None
            ):
                raise ValueError(
                    "RMA proposals require product, asset, and original transaction"
                )
            if self.amount is not None or self.currency is not None:
                raise ValueError(
                    "RMA proposals cannot carry refund or credit amount fields"
                )
        return self


class ServiceRemedyAuthorizationProposal(_StrictModel):
    schema_id: Literal["lightbulb.service_remedy_authorization_proposal.v1"] = Field(
        default=SERVICE_REMEDY_AUTHORIZATION_PROPOSAL_SCHEMA, alias="schema"
    )
    scope: ServiceScopeBinding
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    channel: Channel
    endpoint_binding_ref: OpaqueRef
    contact_policy_decision_ref: OpaqueRef
    contact_policy_digest: Sha256Digest
    source_snapshot_digest: Sha256Digest
    source_revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    source_effective_severity: Severity
    remedy_ref: OpaqueRef
    kind: RemedyKind
    reason_ref: OpaqueRef
    requested_risk: RiskLevel
    risk_floor: RiskLevel
    effective_risk: RiskLevel
    proposer_ref: OpaqueRef
    required_approver_ref: OpaqueRef
    required_approver_role: Literal["finance_authorizer", "returns_authorizer"]
    required_approver_ref_authoritative: Literal[False] = False
    spring_approver_revalidation_required: Literal[True] = True
    amount: Decimal | None = None
    currency: CurrencyCode | None = None
    original_transaction_ref: OpaqueRef
    product_ref: OpaqueRef | None = None
    asset_ref: OpaqueRef | None = None
    serial_ref: OpaqueRef | None = None
    hazardous_return: bool = False
    proposed_at: str
    expires_at: str
    idempotency_key_digest: Sha256Digest
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=16)
    approval_required: Literal[True] = True
    separation_of_duties_required: Literal[True] = True
    authorization_status: Literal["pending_approval"] = "pending_approval"
    authorization_granted: Literal[False] = False
    live_system_changed: Literal[False] = False
    provider_effect_executed: Literal[False] = False
    proposal_digest: Sha256Digest

    @field_validator("proposed_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("amount", mode="before")
    @classmethod
    def _amount(cls, value: Any) -> Decimal | None:
        return None if value is None else _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _proposal_is_non_authoritative_and_bound(
        self,
    ) -> "ServiceRemedyAuthorizationProposal":
        if self.proposer_ref == self.required_approver_ref:
            raise ValueError("remedy proposer and required approver must be different")
        expected_role = (
            "finance_authorizer"
            if self.kind in {"refund", "credit"}
            else "returns_authorizer"
        )
        if self.required_approver_role != expected_role:
            raise ValueError("remedy kind requires its exact independent approver role")
        if self.kind in {"refund", "credit"}:
            if (
                self.amount is None
                or self.amount <= 0
                or self.currency is None
                or self.original_transaction_ref is None
            ):
                raise ValueError(
                    "refund and credit proposals require positive amount, currency, and transaction"
                )
            if (
                any(
                    value is not None
                    for value in (self.product_ref, self.asset_ref, self.serial_ref)
                )
                or self.hazardous_return
            ):
                raise ValueError("return fields are valid only for an RMA proposal")
        elif (
            self.product_ref is None
            or self.asset_ref is None
            or self.original_transaction_ref is None
        ):
            raise ValueError(
                "RMA proposals require product, asset, and original transaction"
            )
        elif self.amount is not None or self.currency is not None:
            raise ValueError(
                "RMA proposals cannot carry refund or credit amount fields"
            )
        expected_floor = _remedy_risk_floor_for(
            kind=self.kind,
            amount=self.amount,
            hazardous_return=self.hazardous_return,
            serial_ref=self.serial_ref,
            case_severity=self.source_effective_severity,
        )
        if self.risk_floor != expected_floor:
            raise ValueError("remedy risk floor does not match exact proposal content")
        if self.effective_risk != _max_level(self.requested_risk, expected_floor):
            raise ValueError("effective remedy risk does not match its exact floors")
        proposed_at = _parsed_timestamp(self.proposed_at)
        if _parsed_timestamp(self.expires_at) != proposed_at + timedelta(hours=24):
            raise ValueError(
                "remedy proposal requires the exact 24-hour approval window"
            )
        evidence_ids = [item.evidence_ref for item in self.evidence_refs]
        evidence_digests = [item.sha256 for item in self.evidence_refs]
        if len(evidence_ids) != len(set(evidence_ids)) or len(evidence_digests) != len(
            set(evidence_digests)
        ):
            raise ValueError("remedy proposal evidence must be unique")
        for item in self.evidence_refs:
            observed_at = _parsed_timestamp(item.observed_at)
            if (
                item.issuer_ref != SPRING_SERVICE_EVIDENCE_ISSUER
                or item.subject_ref != self.remedy_ref
                or not _strong_evidence(item)
            ):
                raise ValueError(
                    "remedy proposal evidence requires exact Spring custody and subject binding"
                )
            if (
                observed_at > proposed_at
                or proposed_at - observed_at > _MAX_STAGE_EVIDENCE_AGE
                or (
                    item.effective_at is not None
                    and _parsed_timestamp(item.effective_at) > proposed_at
                )
            ):
                raise ValueError("remedy proposal evidence is stale or from the future")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("proposal_digest", None)
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError(
                "remedy proposal digest does not match exact proposal content"
            )
        return self


class ServiceRemedyProposalResult(_StrictModel):
    schema_id: Literal["lightbulb.service_remedy_proposal_result.v1"] = Field(
        default=SERVICE_REMEDY_PROPOSAL_RESULT_SCHEMA,
        alias="schema",
    )
    proposal: ServiceRemedyAuthorizationProposal
    case: ServiceCaseLifecycleSnapshot
    authorization_granted: Literal[False] = False
    live_system_changed: Literal[False] = False
    provider_effect_executed: Literal[False] = False

    @model_validator(mode="after")
    def _proposal_matches_pending_case(self) -> "ServiceRemedyProposalResult":
        proposal = self.proposal
        case = self.case
        if case.pending_remedy_proposal_digest != proposal.proposal_digest:
            raise ValueError("pending case must bind the exact remedy proposal")
        if case.state != "remedy_pending_approval":
            raise ValueError("remedy proposal result requires a pending-approval case")
        if (
            proposal.scope != case.scope
            or proposal.case_ref != case.case_ref
            or proposal.customer_ref != case.customer_ref
            or proposal.channel != case.channel
            or proposal.endpoint_binding_ref != case.endpoint_binding_ref
            or proposal.contact_policy_decision_ref != case.contact_policy_decision_ref
            or proposal.contact_policy_digest != case.contact_policy_digest
        ):
            raise ValueError(
                "remedy proposal scope and customer custody must match case"
            )
        if (
            proposal.source_revision + 1 != case.revision
            or proposal.source_effective_severity != case.effective_severity
            or case.updated_at != proposal.proposed_at
            or case.idempotency_key_digests[-1] != proposal.idempotency_key_digest
        ):
            raise ValueError("remedy proposal does not match the exact case transition")
        if tuple(case.evidence_refs[-len(proposal.evidence_refs) :]) != tuple(
            proposal.evidence_refs
        ):
            raise ValueError("remedy proposal evidence is not retained by the case")
        if proposal.required_approver_ref in {
            proposal.proposer_ref,
            case.owner_ref,
            case.resolver_ref,
        }:
            raise ValueError("remedy proposal violates separation of duties")
        return self


CASE_INTAKE_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-case.intake",
    tool="service.prepare_case_intake",
    effect=ConnectorEffect.DRAFT,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
CASE_ROUTING_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-case.route",
    tool="service.prepare_case_route",
    effect=ConnectorEffect.DRAFT,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
RESOLUTION_SUBMISSION_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-case.submit-resolution",
    tool="service.prepare_resolution_submission",
    effect=ConnectorEffect.DRAFT,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
RESOLUTION_VERIFICATION_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-case.verify-resolution",
    tool="service.evaluate_resolution_verification",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)
REMEDY_PROPOSAL_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-case.propose-remedy-authorization",
    tool="service.prepare_remedy_authorization",
    effect=ConnectorEffect.DRAFT,
    approval_required=True,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class _LifecycleFault(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _no_effect_recovery() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.NONE,
        disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
        instructions=(
            "No provider effect was attempted. Submit a fresh, exact-state transition "
            "through the authoritative host when inputs or authority change."
        ),
    )


def _receipt(
    *,
    spec: PrimitiveOperationSpec,
    status: PrimitiveOperationStatus,
    request_digest: str,
    evidence_refs: Sequence[PrimitiveEvidenceRef] = (),
    external_refs: Mapping[str, str] | None = None,
    error: PrimitiveBlocker | None = None,
) -> PrimitiveOperationReceipt:
    return PrimitiveOperationReceipt(
        spec=spec,
        status=status,
        request_digest=request_digest,
        external_refs=dict(external_refs or {}),
        evidence_refs=list(evidence_refs),
        replayed=False,
        recovery_disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
        recovery_plan=_no_effect_recovery(),
        error=error,
    )


def _blocked(
    primitive: BusinessProcessPrimitive[Any, Any],
    *,
    spec: PrimitiveOperationSpec,
    fence: ServiceTransitionFence,
    fault: _LifecycleFault,
    evidence_refs: Sequence[PrimitiveEvidenceRef] = (),
) -> PrimitiveExecutionResult[Any]:
    blocker = PrimitiveBlocker(
        code=fault.code,
        message=fault.message,
        retryable=False,
    )
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.BLOCKED,
        primitive_ref=primitive.primitive_ref,
        primitive_version=primitive.version,
        summary=fault.message,
        blockers=[blocker],
        evidence_refs=list(evidence_refs),
        operation_receipts=[
            _receipt(
                spec=spec,
                status=PrimitiveOperationStatus.BLOCKED,
                request_digest=fence.idempotency_key_digest,
                evidence_refs=evidence_refs,
                error=blocker,
            )
        ],
        retryable=False,
    )


def _scope_and_fence(
    context: PrimitiveExecutionContext,
    *,
    scope: ServiceScopeBinding,
    acting_ref: str,
    fence: ServiceTransitionFence,
    case: ServiceCaseLifecycleSnapshot | None,
) -> None:
    context_scope = context.scope
    if (
        scope.tenant_ref != context_scope.tenant_ref
        or scope.company_ref != context_scope.company_ref
        or scope.project_ref != context_scope.project_ref
        or context_scope.project_id is None
        or scope.project_id != context_scope.project_id
    ):
        raise _LifecycleFault(
            "service_scope_mismatch",
            "The expected tenant/company/project scope does not match authenticated context.",
        )
    if context_scope.actor_ref is None or acting_ref != context_scope.actor_ref:
        raise _LifecycleFault(
            "service_actor_mismatch",
            "The transition actor must exactly match authenticated context.",
        )
    if context.idempotency_key is None:
        raise _LifecycleFault(
            "service_idempotency_required",
            "Customer-service transitions require an exact host idempotency key.",
        )
    else:
        expected_key_digest = service_transition_idempotency_digest(
            context_scope,
            context.idempotency_key,
        )
        if fence.idempotency_key_digest != expected_key_digest:
            raise _LifecycleFault(
                "service_idempotency_mismatch",
                "The transition fence is not bound to the current scope, actor, and idempotency key.",
            )
    if case is None:
        if fence.expected_revision != 0 or fence.expected_snapshot_digest is not None:
            raise _LifecycleFault(
                "service_intake_fence_invalid",
                "A new intake must start at revision zero without a prior snapshot digest.",
            )
        return
    if case.scope != scope:
        raise _LifecycleFault(
            "service_case_scope_mismatch",
            "The case snapshot is outside the exact requested scope.",
        )
    if (
        fence.expected_revision != case.revision
        or fence.expected_snapshot_digest != case.state_digest
    ):
        raise _LifecycleFault(
            "service_stale_snapshot",
            "The case transition fence does not match the current revision and digest.",
        )
    if fence.transition_ref in case.transition_refs:
        raise _LifecycleFault(
            "service_duplicate_transition",
            "The transition reference was already applied to this case.",
        )
    if fence.idempotency_key_digest in case.idempotency_key_digests:
        raise _LifecycleFault(
            "service_replayed_idempotency_key",
            "The idempotency key was already applied to this case.",
        )
    if case.revision >= _MAX_TRANSITIONS:
        raise _LifecycleFault(
            "service_transition_limit_reached",
            "The portable case artifact reached its bounded transition limit.",
        )


def _validate_evidence(
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    *,
    subject_ref: str,
    analysis_as_of: str,
    prior: Sequence[PrimitiveEvidenceRef] = (),
    maximum_age: timedelta = _MAX_STAGE_EVIDENCE_AGE,
    require_verified: bool = False,
) -> None:
    names = [item.evidence_ref for item in evidence_refs]
    digests = [item.sha256 for item in evidence_refs]
    if len(names) != len(set(names)) or len(digests) != len(set(digests)):
        raise _LifecycleFault(
            "service_duplicate_evidence",
            "Evidence references and content digests within a transition must be unique.",
        )
    prior_names = {item.evidence_ref for item in prior}
    prior_digests = {item.sha256 for item in prior}
    if prior_names.intersection(names) or prior_digests.intersection(digests):
        raise _LifecycleFault(
            "service_replayed_evidence",
            "A transition cannot reuse evidence already retained by the case.",
        )
    cutoff = _parsed_timestamp(analysis_as_of)
    for item in evidence_refs:
        observed = _parsed_timestamp(item.observed_at)
        if item.issuer_ref != SPRING_SERVICE_EVIDENCE_ISSUER:
            raise _LifecycleFault(
                "service_evidence_issuer_mismatch",
                "Transition evidence is not under Spring service-authority custody.",
            )
        if item.subject_ref != subject_ref:
            raise _LifecycleFault(
                "service_evidence_subject_mismatch",
                "Evidence is not bound to the exact case, resolution, or remedy subject.",
            )
        if observed > cutoff:
            raise _LifecycleFault(
                "service_future_evidence",
                "Evidence was observed after the transition analysis cutoff.",
            )
        if (
            item.effective_at is not None
            and _parsed_timestamp(item.effective_at) > cutoff
        ):
            raise _LifecycleFault(
                "service_future_evidence",
                "Evidence was not effective by the transition analysis cutoff.",
            )
        if cutoff - observed > maximum_age:
            raise _LifecycleFault(
                "service_stale_evidence",
                "Evidence exceeds the bounded freshness window for this transition.",
            )
        minimum = (
            PrimitiveEvidenceVerificationGrade.VERIFIED
            if require_verified
            else PrimitiveEvidenceVerificationGrade.ATTESTED
        )
        if _GRADE_RANK[item.verification_grade] < _GRADE_RANK[minimum]:
            raise _LifecycleFault(
                "service_evidence_grade_insufficient",
                "Evidence verification grade is below the transition requirement.",
            )


def _severity_floor(signals: ServiceRiskSignals) -> Severity:
    if (
        signals.safety_hazard
        or signals.security_or_privacy_incident
        or signals.regulatory_deadline
    ):
        return "critical"
    if (
        signals.fraud_suspected
        or signals.vulnerable_customer
        or signals.financial_exposure >= Decimal("10000.00")
    ):
        return "high"
    if signals.repeated_service_failure or signals.financial_exposure >= Decimal(
        "1000.00"
    ):
        return "medium"
    return "low"


def _max_level(first: Severity, second: Severity) -> Severity:
    return first if _RANK[first] >= _RANK[second] else second


def _new_snapshot(payload: Mapping[str, Any]) -> ServiceCaseLifecycleSnapshot:
    provisional = ServiceCaseLifecycleSnapshot.model_construct(
        **dict(payload),
        state_digest="0" * 64,
    )
    normalized = provisional.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"state_digest"},
    )
    normalized["state_digest"] = _stable_digest(normalized)
    return ServiceCaseLifecycleSnapshot.model_validate(normalized)


def _advance_snapshot(
    case: ServiceCaseLifecycleSnapshot,
    *,
    fence: ServiceTransitionFence,
    analysis_as_of: str,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    updates: Mapping[str, Any],
) -> ServiceCaseLifecycleSnapshot:
    payload = {
        field_name: getattr(case, field_name)
        for field_name in ServiceCaseLifecycleSnapshot.model_fields
        if field_name not in {"schema_id", "state_digest"}
    }
    payload.update(updates)
    payload.update(
        {
            "updated_at": analysis_as_of,
            "revision": case.revision + 1,
            "transition_refs": (*case.transition_refs, fence.transition_ref),
            "idempotency_key_digests": (
                *case.idempotency_key_digests,
                fence.idempotency_key_digest,
            ),
            "evidence_refs": (*case.evidence_refs, *evidence_refs),
        }
    )
    if len(payload["evidence_refs"]) > _MAX_EVIDENCE:
        raise _LifecycleFault(
            "service_evidence_limit_reached",
            "The portable case artifact reached its bounded evidence limit.",
        )
    return _new_snapshot(payload)


def _resolution_digest(inputs: SubmitServiceResolutionInput) -> str:
    return _stable_digest(
        {
            "schema": "lightbulb.service_resolution_commitment.v1",
            "case_ref": inputs.case.case_ref,
            "customer_ref": inputs.case.customer_ref,
            "resolution_ref": inputs.resolution_ref,
            "resolver_ref": inputs.resolver_ref,
            "resolved_at": inputs.resolved_at,
            "root_cause_ref": inputs.root_cause_ref,
            "resolution_summary": inputs.resolution_summary,
            "evidence": [
                item.to_dict()
                for item in sorted(
                    inputs.evidence_refs, key=lambda item: item.evidence_ref
                )
            ],
        }
    )


def service_resolution_verification_digest(
    *,
    case_ref: str,
    resolution_ref: str,
    resolution_digest: str,
    verifier_ref: str,
    verified_at: str,
    customer_ref: str,
    channel: Channel,
    contact_policy_decision_ref: str,
    outcome: Literal["confirmed", "rejected", "unreachable"],
) -> str:
    """Bind independent verification evidence to one exact claimed outcome."""

    return _stable_digest(
        {
            "schema": SERVICE_RESOLUTION_VERIFICATION_COMMITMENT_SCHEMA,
            "case_ref": case_ref,
            "resolution_ref": resolution_ref,
            "resolution_digest": resolution_digest,
            "verifier_ref": verifier_ref,
            "verified_at": _timestamp(verified_at, field_name="verified_at"),
            "customer_ref": customer_ref,
            "channel": channel,
            "contact_policy_decision_ref": contact_policy_decision_ref,
            "outcome": outcome,
        }
    )


def _remedy_risk_floor(inputs: ProposeServiceRemedyInput) -> RiskLevel:
    return _remedy_risk_floor_for(
        kind=inputs.kind,
        amount=inputs.amount,
        hazardous_return=inputs.hazardous_return,
        serial_ref=inputs.serial_ref,
        case_severity=inputs.case.effective_severity,
    )


def _remedy_risk_floor_for(
    *,
    kind: RemedyKind,
    amount: Decimal | None,
    hazardous_return: bool,
    serial_ref: str | None,
    case_severity: Severity,
) -> RiskLevel:
    case_floor: RiskLevel = case_severity
    if kind in {"refund", "credit"}:
        if amount is None:
            raise ValueError("money remedy risk requires an exact amount")
        remedy_floor: RiskLevel
        if amount >= Decimal("10000.00"):
            remedy_floor = "critical"
        elif amount >= Decimal("1000.00"):
            remedy_floor = "high"
        else:
            remedy_floor = "medium"
    elif hazardous_return:
        remedy_floor = "critical"
    elif serial_ref is not None:
        remedy_floor = "high"
    else:
        remedy_floor = "medium"
    return _max_level(case_floor, remedy_floor)


class _NoEffectPrimitive(BusinessProcessPrimitive[Any, Any]):
    connector_tools = ()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False

    def _finish_result(
        self,
        context: PrimitiveExecutionContext,
        result: PrimitiveExecutionResult[Any],
    ) -> PrimitiveExecutionResult[Any]:
        if not context.preview_only:
            return result
        receipts = [
            receipt.model_copy(update={"status": PrimitiveOperationStatus.PLANNED})
            for receipt in result.operation_receipts
        ]
        return result.model_copy(
            update={
                "status": PrimitiveExecutionStatus.PREVIEW,
                "summary": (
                    "Preview only; deterministic customer-service checks passed. "
                    "Spring authority and any live execution remain pending."
                ),
                "events": [],
                "operation_receipts": receipts,
                "approval_ref": None,
                "approval_refs": {},
            }
        )

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "case_persisted_or_mutated": False,
            "assignment_or_escalation_applied": False,
            "refund_credit_or_rma_authorized": False,
            "provider_effect_executed": False,
            "production_outcome_claimed": False,
            "spring_authority_required": True,
        }
        contract["portable_receipts_are_execution_authority"] = False
        return contract


class IntakeAndClassifyServiceCasePrimitive(_NoEffectPrimitive):
    primitive_ref = "service.intake_and_classify_case"
    version = "1.0.0"
    title = "Prepare customer-service case intake and SLA clock"
    description = (
        "Bind normalized intake, customer/channel consent, risk floors, and a "
        "deterministic SLA schedule without mutating a case system."
    )
    input_model = IntakeServiceCaseInput
    output_model = ServiceCaseLifecycleSnapshot
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {}

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: IntakeServiceCaseInput,
    ) -> PrimitiveExecutionResult[ServiceCaseLifecycleSnapshot]:
        all_evidence = (
            *inputs.evidence_refs,
            inputs.contact_policy.evidence,
            inputs.sla_policy.evidence,
        )
        try:
            _scope_and_fence(
                context,
                scope=inputs.scope,
                acting_ref=inputs.acting_ref,
                fence=inputs.fence,
                case=None,
            )
            _validate_evidence(
                inputs.evidence_refs,
                subject_ref=inputs.case_ref,
                analysis_as_of=inputs.analysis_as_of,
            )
            if len({item.evidence_ref for item in all_evidence}) != len(
                all_evidence
            ) or len({item.sha256 for item in all_evidence}) != len(all_evidence):
                raise _LifecycleFault(
                    "service_duplicate_evidence",
                    "Intake, consent, and SLA evidence references and digests must be unique.",
                )
            _validate_evidence(
                (inputs.contact_policy.evidence,),
                subject_ref=inputs.contact_policy.decision_ref,
                analysis_as_of=inputs.analysis_as_of,
                maximum_age=_MAX_POLICY_EVIDENCE_AGE,
            )
            _validate_evidence(
                (inputs.sla_policy.evidence,),
                subject_ref=inputs.sla_policy.policy_ref,
                analysis_as_of=inputs.analysis_as_of,
                maximum_age=_MAX_POLICY_EVIDENCE_AGE,
            )
        except _LifecycleFault as fault:
            return _blocked(
                self,
                spec=CASE_INTAKE_OPERATION,
                fence=inputs.fence,
                fault=fault,
                evidence_refs=all_evidence,
            )

        floor = _severity_floor(inputs.risk_signals)
        effective = _max_level(inputs.requested_severity, floor)
        target = inputs.sla_policy.target_for(effective)
        received = _parsed_timestamp(inputs.received_at)
        response_due = received + timedelta(minutes=target.first_response_minutes)
        resolution_due = received + timedelta(minutes=target.resolution_minutes)
        contact_permitted = (
            inputs.contact_policy.consent_state in {"granted", "not_required"}
            and inputs.contact_policy.suppression_state == "clear"
            and _parsed_timestamp(inputs.contact_policy.expires_at)
            >= _parsed_timestamp(inputs.analysis_as_of)
        )
        state: CaseState = (
            "classified"
            if inputs.classification_confidence >= Decimal("0.800000")
            else "classification_review"
        )
        snapshot = _new_snapshot(
            {
                "scope": inputs.scope,
                "case_ref": inputs.case_ref,
                "customer_ref": inputs.customer_ref,
                "party_ref": inputs.contact_policy.party_ref,
                "channel": inputs.contact_policy.channel,
                "endpoint_binding_ref": inputs.contact_policy.endpoint_binding_ref,
                "contact_policy_decision_ref": inputs.contact_policy.decision_ref,
                "contact_policy_digest": inputs.contact_policy.decision_digest,
                "contact_policy_expires_at": inputs.contact_policy.expires_at,
                "outbound_contact_permitted": contact_permitted,
                "category_ref": inputs.category_ref,
                "classification_confidence": inputs.classification_confidence,
                "requested_severity": inputs.requested_severity,
                "severity_floor": floor,
                "effective_severity": effective,
                "state": state,
                "summary_digest": _stable_digest(inputs.summary),
                "opened_at": inputs.received_at,
                "updated_at": inputs.analysis_as_of,
                "sla_policy_ref": inputs.sla_policy.policy_ref,
                "sla_policy_digest": inputs.sla_policy.policy_digest,
                "first_response_due_at": response_due.isoformat().replace(
                    "+00:00", "Z"
                ),
                "resolution_due_at": resolution_due.isoformat().replace("+00:00", "Z"),
                "revision": 1,
                "transition_refs": (inputs.fence.transition_ref,),
                "idempotency_key_digests": (inputs.fence.idempotency_key_digest,),
                "evidence_refs": tuple(all_evidence),
            }
        )
        receipt = _receipt(
            spec=CASE_INTAKE_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=inputs.fence.idempotency_key_digest,
            evidence_refs=all_evidence,
            external_refs={
                "case_ref": snapshot.case_ref,
                "snapshot_digest": snapshot.state_digest,
            },
        )
        result = PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Case intake proposal is classified and SLA-bound; no case system changed."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="service.case_intake_prepared",
                    payload={
                        "case_ref": snapshot.case_ref,
                        "state": snapshot.state,
                        "effective_severity": snapshot.effective_severity,
                        "snapshot_digest": snapshot.state_digest,
                        "live_system_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="service_case_intake_proposal",
                    summary="Content-bound case intake and SLA proposal with no live effect.",
                    labels=[
                        snapshot.state,
                        snapshot.effective_severity,
                        "no_connector_call",
                    ],
                    refs={"snapshot_digest": snapshot.state_digest},
                )
            ],
            evidence_refs=list(all_evidence),
            operation_receipts=[receipt],
            retryable=False,
        )
        return self._finish_result(context, result)


class RouteAndEscalateServiceCasePrimitive(_NoEffectPrimitive):
    primitive_ref = "service.route_and_escalate_case"
    version = "1.0.0"
    title = "Prepare service-case assignment or escalation"
    description = (
        "Evaluate exact case state and SLA clocks, enforcing critical and breached-case "
        "escalation floors without applying assignment changes."
    )
    input_model = RouteServiceCaseInput
    output_model = ServiceCaseLifecycleSnapshot
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {}

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: RouteServiceCaseInput,
    ) -> PrimitiveExecutionResult[ServiceCaseLifecycleSnapshot]:
        try:
            _scope_and_fence(
                context,
                scope=inputs.scope,
                acting_ref=inputs.acting_ref,
                fence=inputs.fence,
                case=inputs.case,
            )
            _validate_evidence(
                inputs.evidence_refs,
                subject_ref=inputs.case.case_ref,
                analysis_as_of=inputs.analysis_as_of,
                prior=inputs.case.evidence_refs,
            )
            analysis = _parsed_timestamp(inputs.analysis_as_of)
            if analysis < _parsed_timestamp(inputs.case.updated_at):
                raise _LifecycleFault(
                    "service_non_monotonic_transition",
                    "Routing time cannot precede the current case snapshot.",
                )
            if inputs.case.state == "classification_review":
                raise _LifecycleFault(
                    "service_classification_review_required",
                    "Low-confidence classification requires authoritative review before routing.",
                )
            if inputs.case.state not in {
                "classified",
                "assigned",
                "escalated",
                "reopened",
            }:
                raise _LifecycleFault(
                    "service_route_state_invalid",
                    "The current case state cannot accept an assignment transition.",
                )
            if inputs.first_response_at is not None:
                response = _parsed_timestamp(inputs.first_response_at)
                if (
                    response < _parsed_timestamp(inputs.case.opened_at)
                    or response > analysis
                ):
                    raise _LifecycleFault(
                        "service_first_response_time_invalid",
                        "First response must fall between case intake and the analysis cutoff.",
                    )
                if inputs.case.first_response_at not in {
                    None,
                    inputs.first_response_at,
                }:
                    raise _LifecycleFault(
                        "service_first_response_conflict",
                        "A different first response is already bound to the case.",
                    )
                if (
                    not inputs.case.outbound_contact_permitted
                    or response
                    > _parsed_timestamp(inputs.case.contact_policy_expires_at)
                ):
                    raise _LifecycleFault(
                        "service_first_response_contact_not_permitted",
                        "First response requires an unexpired permitted customer contact binding.",
                    )
            recorded_response = (
                inputs.first_response_at or inputs.case.first_response_at
            )
            response_breached = (
                analysis > _parsed_timestamp(inputs.case.first_response_due_at)
                if recorded_response is None
                else _parsed_timestamp(recorded_response)
                > _parsed_timestamp(inputs.case.first_response_due_at)
            )
            resolution_breached = analysis > _parsed_timestamp(
                inputs.case.resolution_due_at
            )
            escalation_required = (
                inputs.case.effective_severity == "critical"
                or response_breached
                or resolution_breached
            )
            has_escalation = (
                inputs.escalation_ref is not None
                or inputs.case.escalation_ref is not None
            )
            if escalation_required and not has_escalation:
                raise _LifecycleFault(
                    "service_escalation_required",
                    "Critical severity or a breached SLA requires an exact escalation owner and reference.",
                )
            effective_escalation_owner = (
                inputs.escalation_owner_ref or inputs.case.escalation_owner_ref
            )
            if has_escalation and effective_escalation_owner == inputs.owner_ref:
                raise _LifecycleFault(
                    "service_escalation_separation_of_duties",
                    "Escalation ownership must remain independent of case ownership.",
                )
        except _LifecycleFault as fault:
            return _blocked(
                self,
                spec=CASE_ROUTING_OPERATION,
                fence=inputs.fence,
                fault=fault,
                evidence_refs=inputs.evidence_refs,
            )

        new_escalation = inputs.escalation_ref is not None
        has_escalation = new_escalation or inputs.case.escalation_ref is not None
        snapshot = _advance_snapshot(
            inputs.case,
            fence=inputs.fence,
            analysis_as_of=inputs.analysis_as_of,
            evidence_refs=inputs.evidence_refs,
            updates={
                "state": "escalated" if has_escalation else "assigned",
                "owner_ref": inputs.owner_ref,
                "assigned_at": (
                    inputs.case.assigned_at
                    if inputs.case.owner_ref == inputs.owner_ref
                    and inputs.case.assigned_at is not None
                    else inputs.analysis_as_of
                ),
                "first_response_at": inputs.first_response_at
                or inputs.case.first_response_at,
                "escalation_ref": inputs.escalation_ref or inputs.case.escalation_ref,
                "escalation_owner_ref": (
                    inputs.escalation_owner_ref or inputs.case.escalation_owner_ref
                ),
                "escalated_at": (
                    inputs.analysis_as_of
                    if new_escalation
                    else inputs.case.escalated_at
                ),
            },
        )
        result = PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Escalation proposal prepared; no case system changed."
                if has_escalation
                else "Assignment proposal prepared; no case system changed."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="service.case_route_prepared",
                    payload={
                        "case_ref": snapshot.case_ref,
                        "state": snapshot.state,
                        "snapshot_digest": snapshot.state_digest,
                        "live_system_changed": False,
                    },
                )
            ],
            evidence_refs=list(inputs.evidence_refs),
            operation_receipts=[
                _receipt(
                    spec=CASE_ROUTING_OPERATION,
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.fence.idempotency_key_digest,
                    evidence_refs=inputs.evidence_refs,
                    external_refs={"snapshot_digest": snapshot.state_digest},
                )
            ],
        )
        return self._finish_result(context, result)


class SubmitServiceResolutionPrimitive(_NoEffectPrimitive):
    primitive_ref = "service.submit_resolution_for_verification"
    version = "1.0.0"
    title = "Prepare service resolution for independent verification"
    description = "Content-bind a proposed resolution without closing a case or claiming an outcome."
    input_model = SubmitServiceResolutionInput
    output_model = ServiceCaseLifecycleSnapshot
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {}

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: SubmitServiceResolutionInput,
    ) -> PrimitiveExecutionResult[ServiceCaseLifecycleSnapshot]:
        try:
            _scope_and_fence(
                context,
                scope=inputs.scope,
                acting_ref=inputs.acting_ref,
                fence=inputs.fence,
                case=inputs.case,
            )
            _validate_evidence(
                inputs.evidence_refs,
                subject_ref=inputs.resolution_ref,
                analysis_as_of=inputs.analysis_as_of,
                prior=inputs.case.evidence_refs,
            )
            if inputs.resolver_ref != inputs.acting_ref:
                raise _LifecycleFault(
                    "service_resolver_actor_mismatch",
                    "The proposed resolver must match the authenticated transition actor.",
                )
            if inputs.case.state not in {"assigned", "escalated", "reopened"}:
                raise _LifecycleFault(
                    "service_resolution_state_invalid",
                    "Only a routed or reopened case can submit a resolution.",
                )
            resolved_at = _parsed_timestamp(inputs.resolved_at)
            if resolved_at < _parsed_timestamp(
                inputs.case.updated_at
            ) or resolved_at > _parsed_timestamp(inputs.analysis_as_of):
                raise _LifecycleFault(
                    "service_resolution_time_invalid",
                    "Resolution time must be monotonic and no later than analysis cutoff.",
                )
            if (
                resolved_at > _parsed_timestamp(inputs.case.resolution_due_at)
                and inputs.case.escalation_ref is None
            ):
                raise _LifecycleFault(
                    "service_resolution_breach_not_escalated",
                    "An overdue resolution requires retained escalation evidence.",
                )
        except _LifecycleFault as fault:
            return _blocked(
                self,
                spec=RESOLUTION_SUBMISSION_OPERATION,
                fence=inputs.fence,
                fault=fault,
                evidence_refs=inputs.evidence_refs,
            )

        resolution_digest = _resolution_digest(inputs)
        snapshot = _advance_snapshot(
            inputs.case,
            fence=inputs.fence,
            analysis_as_of=inputs.analysis_as_of,
            evidence_refs=inputs.evidence_refs,
            updates={
                "state": "resolution_pending_verification",
                "resolution_ref": inputs.resolution_ref,
                "resolver_ref": inputs.resolver_ref,
                "resolution_submitted_at": inputs.resolved_at,
                "resolution_digest": resolution_digest,
                "resolution_verification": "pending",
                "outcome_verified": False,
            },
        )
        result = PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary="Resolution proposal is bound for independent verification; the case remains open.",
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="service.resolution_submitted_for_verification",
                    payload={
                        "case_ref": snapshot.case_ref,
                        "resolution_ref": inputs.resolution_ref,
                        "resolution_digest": resolution_digest,
                        "outcome_verified": False,
                    },
                )
            ],
            evidence_refs=list(inputs.evidence_refs),
            operation_receipts=[
                _receipt(
                    spec=RESOLUTION_SUBMISSION_OPERATION,
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.fence.idempotency_key_digest,
                    evidence_refs=inputs.evidence_refs,
                    external_refs={
                        "resolution_digest": resolution_digest,
                        "snapshot_digest": snapshot.state_digest,
                    },
                )
            ],
        )
        return self._finish_result(context, result)


class VerifyServiceResolutionPrimitive(_NoEffectPrimitive):
    primitive_ref = "service.verify_case_resolution"
    version = "1.0.0"
    title = "Evaluate independent customer resolution verification"
    description = "Verify exact customer/resolution evidence without closing the case in a live system."
    input_model = VerifyServiceResolutionInput
    output_model = ServiceCaseLifecycleSnapshot
    risk_level = "medium"
    approval_required = False
    example_inputs: Mapping[str, Any] = {}

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: VerifyServiceResolutionInput,
    ) -> PrimitiveExecutionResult[ServiceCaseLifecycleSnapshot]:
        subject = inputs.case.resolution_ref or inputs.case.case_ref
        try:
            _scope_and_fence(
                context,
                scope=inputs.scope,
                acting_ref=inputs.acting_ref,
                fence=inputs.fence,
                case=inputs.case,
            )
            _validate_evidence(
                inputs.evidence_refs,
                subject_ref=subject,
                analysis_as_of=inputs.analysis_as_of,
                prior=inputs.case.evidence_refs,
                require_verified=inputs.outcome == "confirmed",
            )
            if inputs.case.state != "resolution_pending_verification":
                raise _LifecycleFault(
                    "service_verification_state_invalid",
                    "Only a pending submitted resolution can be verified.",
                )
            if inputs.expected_resolution_digest != inputs.case.resolution_digest:
                raise _LifecycleFault(
                    "service_resolution_digest_mismatch",
                    "Verification evidence is not bound to the submitted resolution digest.",
                )
            if inputs.verifier_ref != inputs.acting_ref:
                raise _LifecycleFault(
                    "service_verifier_actor_mismatch",
                    "The verifier must match the authenticated transition actor.",
                )
            forbidden_verifiers = {inputs.case.resolver_ref, inputs.case.owner_ref}
            if inputs.verifier_ref in forbidden_verifiers:
                raise _LifecycleFault(
                    "service_resolution_separation_of_duties",
                    "Resolution verification must be independent of the resolver and case owner.",
                )
            if (
                inputs.customer_ref != inputs.case.customer_ref
                or inputs.channel != inputs.case.channel
                or inputs.contact_policy_decision_ref
                != inputs.case.contact_policy_decision_ref
            ):
                raise _LifecycleFault(
                    "service_resolution_customer_binding_mismatch",
                    "Verification must match the exact customer, channel, and contact-policy decision.",
                )
            if not inputs.case.outbound_contact_permitted:
                raise _LifecycleFault(
                    "service_resolution_contact_not_permitted",
                    "Resolution verification cannot use a disallowed customer contact binding.",
                )
            verified_at = _parsed_timestamp(inputs.verified_at)
            if verified_at < _parsed_timestamp(
                inputs.case.resolution_submitted_at or inputs.case.updated_at
            ) or verified_at > _parsed_timestamp(inputs.analysis_as_of):
                raise _LifecycleFault(
                    "service_verification_time_invalid",
                    "Verification time must follow submission and not exceed analysis cutoff.",
                )
            if verified_at > _parsed_timestamp(inputs.case.contact_policy_expires_at):
                raise _LifecycleFault(
                    "service_resolution_contact_policy_expired",
                    "Resolution verification occurred after the bound contact-policy decision expired.",
                )
            assert inputs.case.resolution_ref is not None
            assert inputs.case.resolution_digest is not None
            verification_digest = service_resolution_verification_digest(
                case_ref=inputs.case.case_ref,
                resolution_ref=inputs.case.resolution_ref,
                resolution_digest=inputs.case.resolution_digest,
                verifier_ref=inputs.verifier_ref,
                verified_at=inputs.verified_at,
                customer_ref=inputs.customer_ref,
                channel=inputs.channel,
                contact_policy_decision_ref=inputs.contact_policy_decision_ref,
                outcome=inputs.outcome,
            )
            if not any(
                item.kind == "service_resolution_verification"
                and item.sha256 == verification_digest
                for item in inputs.evidence_refs
            ):
                raise _LifecycleFault(
                    "service_verification_evidence_mismatch",
                    "Evidence does not commit to the exact resolution, customer, verifier, time, and outcome.",
                )
        except _LifecycleFault as fault:
            return _blocked(
                self,
                spec=RESOLUTION_VERIFICATION_OPERATION,
                fence=inputs.fence,
                fault=fault,
                evidence_refs=inputs.evidence_refs,
            )

        next_state: CaseState
        if inputs.outcome == "confirmed":
            next_state = "resolution_verified"
        elif inputs.outcome == "rejected":
            next_state = "reopened"
        else:
            next_state = "resolution_pending_verification"
        snapshot = _advance_snapshot(
            inputs.case,
            fence=inputs.fence,
            analysis_as_of=inputs.analysis_as_of,
            evidence_refs=inputs.evidence_refs,
            updates={
                "state": next_state,
                "resolution_verification": inputs.outcome,
                "outcome_verified": inputs.outcome == "confirmed",
            },
        )
        result = PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Resolution verification evidence confirmed the proposed outcome; no live case was closed."
                if inputs.outcome == "confirmed"
                else "Resolution verification did not confirm the outcome; no live case was closed."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="service.resolution_verification_evaluated",
                    payload={
                        "case_ref": snapshot.case_ref,
                        "resolution_ref": snapshot.resolution_ref,
                        "outcome": inputs.outcome,
                        "outcome_verified": snapshot.outcome_verified,
                        "live_system_changed": False,
                    },
                )
            ],
            evidence_refs=list(inputs.evidence_refs),
            operation_receipts=[
                _receipt(
                    spec=RESOLUTION_VERIFICATION_OPERATION,
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.fence.idempotency_key_digest,
                    evidence_refs=inputs.evidence_refs,
                    external_refs={"snapshot_digest": snapshot.state_digest},
                )
            ],
        )
        return self._finish_result(context, result)


class ProposeServiceRemedyAuthorizationPrimitive(_NoEffectPrimitive):
    primitive_ref = "service.propose_remedy_authorization"
    version = "1.0.0"
    title = "Prepare governed refund, credit, or RMA authorization proposal"
    description = (
        "Prepare an exact-scope, risk-floored, separation-of-duties authorization "
        "proposal without approving or executing money or returns."
    )
    input_model = ProposeServiceRemedyInput
    output_model = ServiceRemedyProposalResult
    risk_level = "high"
    approval_required = True
    example_inputs: Mapping[str, Any] = {}

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProposeServiceRemedyInput,
    ) -> PrimitiveExecutionResult[ServiceRemedyProposalResult]:
        try:
            _scope_and_fence(
                context,
                scope=inputs.scope,
                acting_ref=inputs.acting_ref,
                fence=inputs.fence,
                case=inputs.case,
            )
            _validate_evidence(
                inputs.evidence_refs,
                subject_ref=inputs.remedy_ref,
                analysis_as_of=inputs.analysis_as_of,
                prior=inputs.case.evidence_refs,
            )
            if inputs.proposer_ref != inputs.acting_ref:
                raise _LifecycleFault(
                    "service_remedy_proposer_actor_mismatch",
                    "The remedy proposer must match the authenticated transition actor.",
                )
            forbidden_approvers = {
                inputs.proposer_ref,
                inputs.case.owner_ref,
                inputs.case.resolver_ref,
            }
            if inputs.required_approver_ref in forbidden_approvers:
                raise _LifecycleFault(
                    "service_remedy_separation_of_duties",
                    "Money and return proposals require an approver independent of proposer, owner, and resolver.",
                )
            if inputs.case.state not in {
                "assigned",
                "escalated",
                "resolution_pending_verification",
                "resolution_verified",
                "reopened",
            }:
                raise _LifecycleFault(
                    "service_remedy_state_invalid",
                    "A remedy proposal requires a routed case with no existing pending proposal.",
                )
            if _parsed_timestamp(inputs.analysis_as_of) < _parsed_timestamp(
                inputs.case.updated_at
            ):
                raise _LifecycleFault(
                    "service_non_monotonic_transition",
                    "Remedy proposal time cannot precede current case state.",
                )
        except _LifecycleFault as fault:
            return _blocked(
                self,
                spec=REMEDY_PROPOSAL_OPERATION,
                fence=inputs.fence,
                fault=fault,
                evidence_refs=inputs.evidence_refs,
            )

        floor = _remedy_risk_floor(inputs)
        effective = _max_level(inputs.requested_risk, floor)
        proposed_at = inputs.analysis_as_of
        expires_at = (
            (_parsed_timestamp(proposed_at) + timedelta(hours=24))
            .isoformat()
            .replace("+00:00", "Z")
        )
        proposal_payload: dict[str, Any] = {
            "scope": inputs.scope,
            "case_ref": inputs.case.case_ref,
            "customer_ref": inputs.case.customer_ref,
            "channel": inputs.case.channel,
            "endpoint_binding_ref": inputs.case.endpoint_binding_ref,
            "contact_policy_decision_ref": inputs.case.contact_policy_decision_ref,
            "contact_policy_digest": inputs.case.contact_policy_digest,
            "source_snapshot_digest": inputs.case.state_digest,
            "source_revision": inputs.case.revision,
            "source_effective_severity": inputs.case.effective_severity,
            "remedy_ref": inputs.remedy_ref,
            "kind": inputs.kind,
            "reason_ref": inputs.reason_ref,
            "requested_risk": inputs.requested_risk,
            "risk_floor": floor,
            "effective_risk": effective,
            "proposer_ref": inputs.proposer_ref,
            "required_approver_ref": inputs.required_approver_ref,
            "required_approver_role": (
                "finance_authorizer"
                if inputs.kind in {"refund", "credit"}
                else "returns_authorizer"
            ),
            "amount": inputs.amount,
            "currency": inputs.currency,
            "original_transaction_ref": inputs.original_transaction_ref,
            "product_ref": inputs.product_ref,
            "asset_ref": inputs.asset_ref,
            "serial_ref": inputs.serial_ref,
            "hazardous_return": inputs.hazardous_return,
            "proposed_at": proposed_at,
            "expires_at": expires_at,
            "idempotency_key_digest": inputs.fence.idempotency_key_digest,
            "evidence_refs": inputs.evidence_refs,
        }
        provisional = ServiceRemedyAuthorizationProposal.model_construct(
            **proposal_payload,
            proposal_digest="0" * 64,
        )
        normalized = provisional.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"proposal_digest"},
        )
        normalized["proposal_digest"] = _stable_digest(normalized)
        proposal = ServiceRemedyAuthorizationProposal.model_validate(normalized)
        snapshot = _advance_snapshot(
            inputs.case,
            fence=inputs.fence,
            analysis_as_of=inputs.analysis_as_of,
            evidence_refs=inputs.evidence_refs,
            updates={
                "state": "remedy_pending_approval",
                "pending_remedy_proposal_digest": proposal.proposal_digest,
            },
        )
        output = ServiceRemedyProposalResult(proposal=proposal, case=snapshot)
        result = PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.PENDING_APPROVAL,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Remedy proposal is pending independent host authorization; no money or return was authorized."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="service.remedy_authorization_proposed",
                    payload={
                        "case_ref": inputs.case.case_ref,
                        "remedy_ref": proposal.remedy_ref,
                        "kind": proposal.kind,
                        "effective_risk": proposal.effective_risk,
                        "proposal_digest": proposal.proposal_digest,
                        "authorization_granted": False,
                        "provider_effect_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="service_remedy_authorization_proposal",
                    summary="Exact-scope proposal evidence; Spring approval and governed execution remain required.",
                    labels=[proposal.kind, proposal.effective_risk, "pending_approval"],
                    refs={"proposal_digest": proposal.proposal_digest},
                )
            ],
            evidence_refs=list(inputs.evidence_refs),
            operation_receipts=[
                _receipt(
                    spec=REMEDY_PROPOSAL_OPERATION,
                    status=PrimitiveOperationStatus.PENDING_APPROVAL,
                    request_digest=proposal.proposal_digest,
                    evidence_refs=inputs.evidence_refs,
                    external_refs={
                        "proposal_digest": proposal.proposal_digest,
                        "snapshot_digest": snapshot.state_digest,
                    },
                )
            ],
            retryable=False,
        )
        return self._finish_result(context, result)


def _example_evidence(
    evidence_ref: str,
    *,
    subject_ref: str,
    observed_at: str,
    sha256: str | None = None,
    kind: str = "normalized_customer_service_evidence",
    grade: Literal["attested", "verified"] = "attested",
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": SPRING_SERVICE_EVIDENCE_ISSUER,
        "subject_ref": subject_ref,
        "sha256": sha256 or _stable_digest({"example_evidence_ref": evidence_ref}),
        "observed_at": observed_at,
        "verification_grade": grade,
        "classification": "confidential",
        "retention_policy": "customer-service-seven-years",
        "jurisdiction": "US",
    }


def _example_scope() -> dict[str, Any]:
    return {
        "schema": SERVICE_SCOPE_BINDING_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000751",
    }


def _example_contact_policy() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "customer_ref": "customer-example",
        "party_ref": "party-example",
        "channel": "email",
        "endpoint_binding_ref": "endpoint-example",
        "purpose": "customer_support",
        "jurisdiction": "US",
        "consent_state": "granted",
        "suppression_state": "clear",
        "decision_ref": "contact-policy-example",
        "decided_at": "2026-08-25T12:00:00Z",
        "expires_at": "2026-08-26T12:00:00Z",
    }
    digest = service_contact_policy_digest(payload)
    return {
        "schema": SERVICE_CONTACT_POLICY_BINDING_SCHEMA,
        **payload,
        "decision_digest": digest,
        "evidence": _example_evidence(
            "evidence-contact-policy-example",
            subject_ref=payload["decision_ref"],
            observed_at=payload["decided_at"],
            sha256=digest,
            kind="service_contact_policy_decision",
        ),
    }


def _example_sla_policy() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "policy_ref": "sla-policy-example",
        "policy_version": 1,
        "low": {"first_response_minutes": 240, "resolution_minutes": 2880},
        "medium": {"first_response_minutes": 120, "resolution_minutes": 1440},
        "high": {"first_response_minutes": 60, "resolution_minutes": 480},
        "critical": {"first_response_minutes": 15, "resolution_minutes": 120},
    }
    digest = service_sla_policy_digest(payload)
    return {
        "schema": SERVICE_SLA_POLICY_SCHEMA,
        **payload,
        "policy_digest": digest,
        "evidence": _example_evidence(
            "evidence-sla-policy-example",
            subject_ref=payload["policy_ref"],
            observed_at="2026-08-24T12:00:00Z",
            sha256=digest,
            kind="service_sla_policy",
        ),
    }


def _example_case(
    state: Literal["classified", "assigned", "resolution_pending_verification"],
) -> ServiceCaseLifecycleSnapshot:
    revision = {
        "classified": 1,
        "assigned": 2,
        "resolution_pending_verification": 3,
    }[state]
    payload: dict[str, Any] = {
        "scope": ServiceScopeBinding.model_validate(_example_scope()),
        "case_ref": "case-example",
        "customer_ref": "customer-example",
        "party_ref": "party-example",
        "channel": "email",
        "endpoint_binding_ref": "endpoint-example",
        "contact_policy_decision_ref": "contact-policy-example",
        "contact_policy_digest": _stable_digest("contact-policy-example"),
        "contact_policy_expires_at": "2026-08-26T12:00:00Z",
        "outbound_contact_permitted": True,
        "category_ref": "service-question",
        "classification_confidence": Decimal("0.950000"),
        "requested_severity": "medium",
        "severity_floor": "low",
        "effective_severity": "medium",
        "state": state,
        "summary_digest": _stable_digest("example service case"),
        "opened_at": "2026-08-25T13:00:00Z",
        "updated_at": "2026-08-25T14:00:00Z",
        "sla_policy_ref": "sla-policy-example",
        "sla_policy_digest": _stable_digest("sla-policy-example"),
        "first_response_due_at": "2026-08-25T15:00:00Z",
        "resolution_due_at": "2026-08-26T13:00:00Z",
        "revision": revision,
        "transition_refs": tuple(
            f"transition-example-{index}" for index in range(1, revision + 1)
        ),
        "idempotency_key_digests": tuple(
            _stable_digest(f"idempotency-example-{index}")
            for index in range(1, revision + 1)
        ),
        "evidence_refs": (
            PrimitiveEvidenceRef.model_validate(
                _example_evidence(
                    "evidence-case-example",
                    subject_ref="case-example",
                    observed_at="2026-08-25T13:55:00Z",
                )
            ),
        ),
    }
    if state != "classified":
        payload.update(
            {
                "owner_ref": "owner-example",
                "assigned_at": "2026-08-25T14:00:00Z",
            }
        )
    if state == "resolution_pending_verification":
        payload.update(
            {
                "updated_at": "2026-08-25T14:25:00Z",
                "resolution_ref": "resolution-example",
                "resolver_ref": "resolver-example",
                "resolution_submitted_at": "2026-08-25T14:20:00Z",
                "resolution_digest": _stable_digest("resolution-example"),
                "resolution_verification": "pending",
                "outcome_verified": False,
            }
        )
    return _new_snapshot(payload)


def _example_fence(
    transition_ref: str,
    *,
    acting_ref: str,
    case: ServiceCaseLifecycleSnapshot | None = None,
) -> dict[str, Any]:
    scope = _example_scope()
    idempotency_key = f"idempotency-{transition_ref}"
    execution_scope = ExecutionScope(
        tenant_ref=scope["tenant_ref"],
        company_ref=scope["company_ref"],
        project_ref=scope["project_ref"],
        project_id=UUID(scope["project_id"]),
        actor_ref=acting_ref,
    )
    return {
        "schema": SERVICE_TRANSITION_FENCE_SCHEMA,
        "transition_ref": transition_ref,
        "expected_revision": case.revision if case is not None else 0,
        "expected_snapshot_digest": case.state_digest if case is not None else None,
        "idempotency_key_digest": service_transition_idempotency_digest(
            execution_scope,
            idempotency_key,
        ),
    }


def _intake_example_inputs() -> dict[str, Any]:
    return IntakeServiceCaseInput.model_validate(
        {
            "schema": SERVICE_CASE_INTAKE_INPUT_SCHEMA,
            "scope": _example_scope(),
            "fence": _example_fence(
                "transition-intake-example",
                acting_ref="intake-agent-example",
            ),
            "acting_ref": "intake-agent-example",
            "analysis_as_of": "2026-08-25T14:00:00Z",
            "case_ref": "case-example",
            "customer_ref": "customer-example",
            "contact_policy": _example_contact_policy(),
            "received_at": "2026-08-25T13:00:00Z",
            "summary": "Customer requests help with an order.",
            "category_ref": "service-question",
            "classification_confidence": "0.950000",
            "requested_severity": "medium",
            "risk_signals": {
                "schema": "lightbulb.service_risk_signals.v1",
                "financial_exposure": "25.00",
            },
            "sla_policy": _example_sla_policy(),
            "evidence_refs": [
                _example_evidence(
                    "evidence-intake-example",
                    subject_ref="case-example",
                    observed_at="2026-08-25T13:55:00Z",
                )
            ],
        }
    ).to_dict()


def _route_example_inputs() -> dict[str, Any]:
    case = _example_case("classified")
    return RouteServiceCaseInput.model_validate(
        {
            "schema": SERVICE_CASE_ROUTE_INPUT_SCHEMA,
            "scope": _example_scope(),
            "fence": _example_fence(
                "transition-route-example",
                acting_ref="dispatcher-example",
                case=case,
            ),
            "acting_ref": "dispatcher-example",
            "analysis_as_of": "2026-08-25T14:05:00Z",
            "case": case.to_dict(),
            "owner_ref": "owner-example",
            "first_response_at": "2026-08-25T13:50:00Z",
            "evidence_refs": [
                _example_evidence(
                    "evidence-route-example",
                    subject_ref=case.case_ref,
                    observed_at="2026-08-25T14:01:00Z",
                )
            ],
        }
    ).to_dict()


def _submit_resolution_example_inputs() -> dict[str, Any]:
    case = _example_case("assigned")
    return SubmitServiceResolutionInput.model_validate(
        {
            "schema": SERVICE_RESOLUTION_SUBMISSION_INPUT_SCHEMA,
            "scope": _example_scope(),
            "fence": _example_fence(
                "transition-resolution-example",
                acting_ref="resolver-example",
                case=case,
            ),
            "acting_ref": "resolver-example",
            "analysis_as_of": "2026-08-25T14:25:00Z",
            "case": case.to_dict(),
            "resolution_ref": "resolution-example",
            "resolver_ref": "resolver-example",
            "resolved_at": "2026-08-25T14:20:00Z",
            "root_cause_ref": "order-status-sync",
            "resolution_summary": "Order status was synchronized and confirmed.",
            "evidence_refs": [
                _example_evidence(
                    "evidence-resolution-example",
                    subject_ref="resolution-example",
                    observed_at="2026-08-25T14:20:00Z",
                )
            ],
        }
    ).to_dict()


def _verify_resolution_example_inputs() -> dict[str, Any]:
    case = _example_case("resolution_pending_verification")
    verification_digest = service_resolution_verification_digest(
        case_ref=case.case_ref,
        resolution_ref=case.resolution_ref or "",
        resolution_digest=case.resolution_digest or "",
        verifier_ref="verifier-example",
        verified_at="2026-08-25T14:30:00Z",
        customer_ref=case.customer_ref,
        channel=case.channel,
        contact_policy_decision_ref=case.contact_policy_decision_ref,
        outcome="confirmed",
    )
    return VerifyServiceResolutionInput.model_validate(
        {
            "schema": SERVICE_RESOLUTION_VERIFICATION_INPUT_SCHEMA,
            "scope": _example_scope(),
            "fence": _example_fence(
                "transition-verification-example",
                acting_ref="verifier-example",
                case=case,
            ),
            "acting_ref": "verifier-example",
            "analysis_as_of": "2026-08-25T14:35:00Z",
            "case": case.to_dict(),
            "expected_resolution_digest": case.resolution_digest,
            "verifier_ref": "verifier-example",
            "verified_at": "2026-08-25T14:30:00Z",
            "customer_ref": case.customer_ref,
            "channel": case.channel,
            "contact_policy_decision_ref": case.contact_policy_decision_ref,
            "outcome": "confirmed",
            "evidence_refs": [
                _example_evidence(
                    "evidence-verification-example",
                    subject_ref=case.resolution_ref or "",
                    observed_at="2026-08-25T14:30:00Z",
                    sha256=verification_digest,
                    kind="service_resolution_verification",
                    grade="verified",
                )
            ],
        }
    ).to_dict()


def _remedy_example_inputs() -> dict[str, Any]:
    case = _example_case("assigned")
    return ProposeServiceRemedyInput.model_validate(
        {
            "schema": SERVICE_REMEDY_PROPOSAL_INPUT_SCHEMA,
            "scope": _example_scope(),
            "fence": _example_fence(
                "transition-remedy-example",
                acting_ref="remedy-proposer-example",
                case=case,
            ),
            "acting_ref": "remedy-proposer-example",
            "analysis_as_of": "2026-08-25T14:20:00Z",
            "case": case.to_dict(),
            "remedy_ref": "credit-example",
            "kind": "credit",
            "reason_ref": "service-recovery",
            "requested_risk": "low",
            "proposer_ref": "remedy-proposer-example",
            "required_approver_ref": "finance-authorizer-example",
            "amount": "25.00",
            "currency": "USD",
            "original_transaction_ref": "transaction-example",
            "evidence_refs": [
                _example_evidence(
                    "evidence-remedy-example",
                    subject_ref="credit-example",
                    observed_at="2026-08-25T14:15:00Z",
                )
            ],
        }
    ).to_dict()


IntakeAndClassifyServiceCasePrimitive.example_inputs = _intake_example_inputs()
RouteAndEscalateServiceCasePrimitive.example_inputs = _route_example_inputs()
SubmitServiceResolutionPrimitive.example_inputs = _submit_resolution_example_inputs()
VerifyServiceResolutionPrimitive.example_inputs = _verify_resolution_example_inputs()
ProposeServiceRemedyAuthorizationPrimitive.example_inputs = _remedy_example_inputs()


CUSTOMER_SERVICE_LIFECYCLE_EXECUTABLE_PRIMITIVES = (
    IntakeAndClassifyServiceCasePrimitive(),
    RouteAndEscalateServiceCasePrimitive(),
    SubmitServiceResolutionPrimitive(),
    VerifyServiceResolutionPrimitive(),
    ProposeServiceRemedyAuthorizationPrimitive(),
)


__all__ = [
    "CASE_INTAKE_OPERATION",
    "CASE_ROUTING_OPERATION",
    "CUSTOMER_SERVICE_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "IntakeAndClassifyServiceCasePrimitive",
    "IntakeServiceCaseInput",
    "ProposeServiceRemedyAuthorizationPrimitive",
    "ProposeServiceRemedyInput",
    "REMEDY_PROPOSAL_OPERATION",
    "RESOLUTION_SUBMISSION_OPERATION",
    "RESOLUTION_VERIFICATION_OPERATION",
    "RouteAndEscalateServiceCasePrimitive",
    "RouteServiceCaseInput",
    "SERVICE_CASE_INTAKE_INPUT_SCHEMA",
    "SERVICE_CASE_LIFECYCLE_SNAPSHOT_SCHEMA",
    "SERVICE_CASE_ROUTE_INPUT_SCHEMA",
    "SERVICE_CONTACT_POLICY_BINDING_SCHEMA",
    "SERVICE_REMEDY_AUTHORIZATION_PROPOSAL_SCHEMA",
    "SERVICE_REMEDY_PROPOSAL_INPUT_SCHEMA",
    "SERVICE_REMEDY_PROPOSAL_RESULT_SCHEMA",
    "SERVICE_RESOLUTION_SUBMISSION_INPUT_SCHEMA",
    "SERVICE_RESOLUTION_VERIFICATION_COMMITMENT_SCHEMA",
    "SERVICE_RESOLUTION_VERIFICATION_INPUT_SCHEMA",
    "SERVICE_SCOPE_BINDING_SCHEMA",
    "SERVICE_SLA_POLICY_SCHEMA",
    "SERVICE_TRANSITION_FENCE_SCHEMA",
    "SPRING_SERVICE_EVIDENCE_ISSUER",
    "ServiceCaseLifecycleSnapshot",
    "ServiceContactPolicyBinding",
    "ServiceRemedyAuthorizationProposal",
    "ServiceRemedyProposalResult",
    "ServiceRiskSignals",
    "ServiceScopeBinding",
    "ServiceSlaPolicy",
    "ServiceSlaTarget",
    "ServiceTransitionFence",
    "SubmitServiceResolutionInput",
    "SubmitServiceResolutionPrimitive",
    "VerifyServiceResolutionInput",
    "VerifyServiceResolutionPrimitive",
    "service_case_snapshot_digest",
    "service_contact_policy_digest",
    "service_resolution_verification_digest",
    "service_sla_policy_digest",
    "service_transition_idempotency_digest",
]
