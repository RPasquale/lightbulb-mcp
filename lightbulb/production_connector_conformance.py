"""Evidence-bound verification of production connector conformance.

The verifier consumes normalized Spring and provider attestations.  It never
calls a connector, performs a provider write, accepts caller-authored pass
flags, or grants production certification.  A passing result is only a
deterministic certification candidate for Spring or an operator to admit into
the operational-readiness process.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import (
    ConnectorEffect,
    ConnectorErrorKind,
    ConnectorExecutionProvenance,
)
from lightbulb.operational_readiness import ConnectorConformanceCertification
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
    PrimitiveRecoveryAttestation,
    PrimitiveRecoveryOutcome,
)


PRODUCTION_CONNECTOR_CONFORMANCE_INPUT_SCHEMA = (
    "lightbulb.production_connector_conformance_input.v1"
)
PRODUCTION_CONNECTOR_CONFORMANCE_RESULT_SCHEMA = (
    "lightbulb.production_connector_conformance_result.v1"
)
HOSTED_TOOL_SCHEMA_ATTESTATION_SCHEMA = "lightbulb.hosted_tool_schema_attestation.v1"
EXACT_CONNECTOR_ROUTE_ATTESTATION_SCHEMA = (
    "lightbulb.exact_connector_route_attestation.v1"
)
GOVERNED_WRITE_ATTESTATION_SCHEMA = "lightbulb.governed_write_attestation.v1"
PROVIDER_READBACK_ATTESTATION_SCHEMA = "lightbulb.provider_readback_attestation.v1"
IDEMPOTENT_REPLAY_ATTESTATION_SCHEMA = "lightbulb.idempotent_replay_attestation.v1"
PAYLOAD_CONFLICT_ATTESTATION_SCHEMA = "lightbulb.payload_conflict_attestation.v1"
NORMALIZED_ERROR_ATTESTATION_SCHEMA = (
    "lightbulb.normalized_connector_error_attestation.v1"
)
AMBIGUOUS_RECOVERY_ATTESTATION_SCHEMA = (
    "lightbulb.ambiguous_dispatch_recovery_attestation.v1"
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ZERO_DIGEST = "0" * 64
_MAX_TOOL_PROOFS = 100
_MAX_EVIDENCE_PER_TOOL = 165
_MAX_EVIDENCE = _MAX_TOOL_PROOFS * _MAX_EVIDENCE_PER_TOOL


def _visible(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible characters only")
    return value


def _uuid_ref(value: str) -> str:
    from uuid import UUID

    try:
        canonical = str(UUID(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("scope identity must be a canonical UUID") from exc
    if canonical != value.lower():
        raise ValueError("scope identity must use canonical UUID form")
    return canonical


OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$",
    ),
    AfterValidator(_visible),
]
EvidenceRefId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=200),
    AfterValidator(_visible),
]
ToolName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9_-]{0,63}(?:\.[a-z0-9][a-z0-9_.-]{0,63})+$",
    ),
]
ProviderName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]{0,63}$"),
]
UuidRef = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
        )
    ),
    AfterValidator(_uuid_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]

ConformanceGate = Literal[
    "evidence",
    "hosted_schema",
    "exact_route",
    "spring_approval_journal",
    "live_write_readback",
    "idempotent_replay",
    "payload_conflict",
    "error_normalization",
    "rate_limit",
    "ambiguous_recovery",
]
ConformanceGateStatus = Literal["pass", "fail", "indeterminate"]
ProductionConformanceDisposition = Literal[
    "ready_for_operator_certification",
    "blocked",
    "indeterminate",
]

_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

_GATE_ORDER: tuple[ConformanceGate, ...] = (
    "evidence",
    "hosted_schema",
    "exact_route",
    "spring_approval_journal",
    "live_write_readback",
    "idempotent_replay",
    "payload_conflict",
    "error_normalization",
    "rate_limit",
    "ambiguous_recovery",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        revalidate_instances="always",
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _detached_validation_payload(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _detached_validation_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_detached_validation_payload(item) for item in value]
    return value


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


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def production_attestation_digest(
    attestation: BaseModel | Mapping[str, Any],
) -> str:
    """Digest one attestation payload without its detached evidence envelopes."""

    if isinstance(attestation, BaseModel):
        payload = attestation.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
    elif isinstance(attestation, Mapping):
        payload = dict(attestation)
    else:
        raise TypeError("attestation must be a Pydantic model or mapping")
    for field_name in (
        "evidence_refs",
        "spring_evidence_refs",
        "provider_evidence_refs",
    ):
        payload.pop(field_name, None)
    return _stable_digest(payload)


def _issuer_matches(
    issuer_ref: str,
    *,
    authority: Literal["spring", "provider"],
    provider: str,
) -> bool:
    normalized = issuer_ref.lower()
    if authority == "spring":
        return normalized.startswith(("spring-", "spring:"))
    return normalized == provider or normalized.startswith(
        (f"{provider}-", f"{provider}:", f"provider:{provider}")
    )


def _require_bound_evidence(
    attestation: BaseModel,
    refs: Sequence[PrimitiveEvidenceRef],
    *,
    expected_kind: str,
    authority: Literal["spring", "provider"],
    provider: str,
) -> None:
    if not refs:
        raise ValueError("attestation requires content-bound evidence")
    if len({evidence.evidence_ref for evidence in refs}) != len(refs):
        raise ValueError("attestation evidence references must be unique")
    expected_digest = production_attestation_digest(attestation)
    attestation_ref = str(getattr(attestation, "attestation_ref"))
    observed_at = _parsed_timestamp(str(getattr(attestation, "observed_at")))
    for evidence in refs:
        if evidence.kind != expected_kind:
            raise ValueError(f"attestation evidence kind must be {expected_kind}")
        if evidence.subject_ref != attestation_ref:
            raise ValueError("attestation evidence subject must match attestation_ref")
        if evidence.sha256 != expected_digest:
            raise ValueError("attestation evidence digest does not bind its payload")
        if evidence.verification_grade not in {
            PrimitiveEvidenceVerificationGrade.ATTESTED,
            PrimitiveEvidenceVerificationGrade.VERIFIED,
        }:
            raise ValueError("production proof requires attested or verified evidence")
        if not _issuer_matches(
            evidence.issuer_ref,
            authority=authority,
            provider=provider,
        ):
            raise ValueError(f"{authority} evidence issuer is not authoritative")
        if _parsed_timestamp(evidence.observed_at) < observed_at:
            raise ValueError("evidence cannot predate the attested observation")


def _validate_provider(tool: str, provider: str) -> None:
    if tool.split(".", 1)[0] != provider:
        raise ValueError("provider must match the Tool prefix")


class RouteIsolationObservation(_StrictModel):
    attempted_scope: Literal["tenant", "company", "project", "account"]
    response_status: Literal["denied", "not_found", "bad_request", "conflict"]
    error_code: OpaqueRef
    provider_dispatch_count: Literal[0]


class HostedToolSchemaAttestation(_StrictModel):
    schema_id: Literal["lightbulb.hosted_tool_schema_attestation.v1"] = Field(
        default=HOSTED_TOOL_SCHEMA_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    hosted_schema_identity: OpaqueRef
    catalog_version: OpaqueRef
    tool_version: int = Field(ge=1, le=1_000_000)
    server_effect: Literal["write"]
    input_schema_sha256: Sha256Digest
    output_schema_sha256: Sha256Digest
    observed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bound(self) -> "HostedToolSchemaAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="hosted_tool_schema",
            authority="spring",
            provider=self.provider,
        )
        return self


class ExactConnectorRouteAttestation(_StrictModel):
    schema_id: Literal["lightbulb.exact_connector_route_attestation.v1"] = Field(
        default=EXACT_CONNECTOR_ROUTE_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    connector_account_ref: OpaqueRef
    target_resource_ref: OpaqueRef
    project_connector_binding_id: UuidRef
    tenant_tool_binding_id: UuidRef
    tenant_connector_id: UuidRef
    connector_id: UuidRef
    adapter_identity: OpaqueRef
    handler_identity: OpaqueRef
    tool_version: int = Field(ge=1, le=1_000_000)
    target_sha256: Sha256Digest
    route_sha256: Sha256Digest
    isolation_observations: tuple[RouteIsolationObservation, ...] = Field(
        min_length=4,
        max_length=4,
    )
    observed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("isolation_observations", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bound_and_complete(self) -> "ExactConnectorRouteAttestation":
        _validate_provider(self.tool, self.provider)
        scopes = tuple(item.attempted_scope for item in self.isolation_observations)
        if len(scopes) != len(set(scopes)) or set(scopes) != {
            "tenant",
            "company",
            "project",
            "account",
        }:
            raise ValueError(
                "route isolation must cover tenant, company, project, and account"
            )
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="exact_connector_route",
            authority="spring",
            provider=self.provider,
        )
        return self


class GovernedWriteAttestation(_StrictModel):
    schema_id: Literal["lightbulb.governed_write_attestation.v1"] = Field(
        default=GOVERNED_WRITE_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    user_id: UuidRef
    project_id: UuidRef
    connector_account_ref: OpaqueRef
    effect_catalog_version: OpaqueRef
    idempotency_key_sha256: Sha256Digest
    payload_sha256: Sha256Digest
    approval_status: Literal["approved", "consumed", "rejected", "expired"]
    journal_status: Literal[
        "prepared", "dispatching", "succeeded", "failed", "ambiguous"
    ]
    provenance: ConnectorExecutionProvenance
    provider_effect_ref: OpaqueRef
    provider_output_sha256: Sha256Digest
    observed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bound_and_provenanced(self) -> "GovernedWriteAttestation":
        _validate_provider(self.tool, self.provider)
        if (
            self.provenance.tool != self.tool
            or self.provenance.server_effect != ConnectorEffect.WRITE
            or str(self.provenance.project_id) != self.project_id
            or self.provenance.connector_account_ref != self.connector_account_ref
        ):
            raise ValueError(
                "Spring provenance does not match the governed write scope"
            )
        if self.provenance.request_digest == self.payload_sha256:
            raise ValueError(
                "payload and canonical custody digests must remain distinct"
            )
        if _parsed_timestamp(self.provenance.completed_at) > _parsed_timestamp(
            self.observed_at
        ):
            raise ValueError("write evidence cannot be observed before completion")
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="governed_connector_write",
            authority="spring",
            provider=self.provider,
        )
        return self


class ProviderReadbackAttestation(_StrictModel):
    schema_id: Literal["lightbulb.provider_readback_attestation.v1"] = Field(
        default=PROVIDER_READBACK_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    write_tool: ToolName
    readback_tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    connector_account_ref: OpaqueRef
    provider_effect_ref: OpaqueRef
    write_output_sha256: Sha256Digest
    readback_state_sha256: Sha256Digest
    provider_version_ref: OpaqueRef
    outcome: Literal["applied", "not_found", "mismatched", "indeterminate"]
    readback_at: str
    observed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("readback_at", "observed_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bound(self) -> "ProviderReadbackAttestation":
        _validate_provider(self.write_tool, self.provider)
        _validate_provider(self.readback_tool, self.provider)
        if self.readback_at > self.observed_at:
            raise ValueError("provider readback cannot be observed before it occurs")
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="provider_authoritative_readback",
            authority="provider",
            provider=self.provider,
        )
        return self


class IdempotentReplayAttestation(_StrictModel):
    schema_id: Literal["lightbulb.idempotent_replay_attestation.v1"] = Field(
        default=IDEMPOTENT_REPLAY_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    original_journal_ref: OpaqueRef
    replay_journal_ref: OpaqueRef
    original_request_sha256: Sha256Digest
    replay_request_sha256: Sha256Digest
    original_receipt_sha256: Sha256Digest
    replay_receipt_sha256: Sha256Digest
    original_provider_effect_ref: OpaqueRef
    replay_provider_effect_ref: OpaqueRef
    original_provider_effect_count: int = Field(ge=0, le=1_000_000)
    replay_provider_effect_count: int = Field(ge=0, le=1_000_000)
    replay_disposition: Literal["cached", "redispatched", "ambiguous"]
    observed_at: str
    spring_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )
    provider_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("spring_evidence_refs", "provider_evidence_refs", mode="before")
    @classmethod
    def _evidence_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _jointly_bound(self) -> "IdempotentReplayAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.spring_evidence_refs,
            expected_kind="idempotent_replay",
            authority="spring",
            provider=self.provider,
        )
        _require_bound_evidence(
            self,
            self.provider_evidence_refs,
            expected_kind="provider_idempotent_replay_effect_count",
            authority="provider",
            provider=self.provider,
        )
        return self


class PayloadConflictRejectionAttestation(_StrictModel):
    schema_id: Literal["lightbulb.payload_conflict_attestation.v1"] = Field(
        default=PAYLOAD_CONFLICT_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    idempotency_key_sha256: Sha256Digest
    accepted_request_sha256: Sha256Digest
    conflicting_request_sha256: Sha256Digest
    journal_ref_before: OpaqueRef
    journal_ref_after: OpaqueRef
    provider_dispatch_count_before: int = Field(ge=0, le=1_000_000)
    provider_dispatch_count_after: int = Field(ge=0, le=1_000_000)
    response_status: Literal["conflict", "failed", "completed"]
    normalized_error_kind: ConnectorErrorKind
    normalized_error_code: OpaqueRef
    retry_disposition: Literal["blocked", "retryable"]
    observed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=5)

    @field_validator("normalized_error_kind", mode="before")
    @classmethod
    def _error_kind(cls, value: Any) -> ConnectorErrorKind:
        if isinstance(value, ConnectorErrorKind):
            return value
        return ConnectorErrorKind(str(value))

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _bound(self) -> "PayloadConflictRejectionAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="idempotency_payload_conflict",
            authority="spring",
            provider=self.provider,
        )
        return self


class NormalizedConnectorErrorAttestation(_StrictModel):
    schema_id: Literal["lightbulb.normalized_connector_error_attestation.v1"] = Field(
        default=NORMALIZED_ERROR_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    injected_condition: ConnectorErrorKind
    provider_status_code: int = Field(ge=100, le=599)
    provider_error_sha256: Sha256Digest
    normalized_error_kind: ConnectorErrorKind
    normalized_error_code: OpaqueRef
    response_status: Literal["failed", "blocked"]
    retry_disposition: Literal["retryable", "blocked"]
    observed_at: str
    spring_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )
    provider_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )

    @field_validator("injected_condition", "normalized_error_kind", mode="before")
    @classmethod
    def _error_kinds(cls, value: Any) -> ConnectorErrorKind:
        if isinstance(value, ConnectorErrorKind):
            return value
        return ConnectorErrorKind(str(value))

    @field_validator("observed_at")
    @classmethod
    def _observed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="observed_at")

    @field_validator(
        "spring_evidence_refs",
        "provider_evidence_refs",
        mode="before",
    )
    @classmethod
    def _evidence_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _jointly_bound(self) -> "NormalizedConnectorErrorAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.spring_evidence_refs,
            expected_kind="spring_connector_error_normalization",
            authority="spring",
            provider=self.provider,
        )
        _require_bound_evidence(
            self,
            self.provider_evidence_refs,
            expected_kind="provider_connector_error",
            authority="provider",
            provider=self.provider,
        )
        return self


class AmbiguousDispatchRecoveryAttestation(_StrictModel):
    schema_id: Literal["lightbulb.ambiguous_dispatch_recovery_attestation.v1"] = Field(
        default=AMBIGUOUS_RECOVERY_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    operation_ref: OpaqueRef
    journal_ref: OpaqueRef
    request_sha256: Sha256Digest
    initial_journal_status: Literal["dispatching", "ambiguous", "succeeded", "failed"]
    initial_error_code: OpaqueRef
    initial_retry_disposition: Literal["blocked", "retryable"]
    provider_dispatch_count_at_ambiguity: int = Field(ge=0, le=1_000_000)
    provider_dispatch_count_before_resolution: int = Field(ge=0, le=1_000_000)
    resolution_path: Literal["status_probe", "manual_reconciliation"]
    recovery_attestation: PrimitiveRecoveryAttestation
    final_journal_status: Literal["succeeded", "failed", "ambiguous"]
    final_provider_effect_ref: OpaqueRef | None = None
    final_provider_dispatch_count: int = Field(ge=0, le=1_000_000)
    resolved_at: str
    observed_at: str
    spring_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )
    provider_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=5,
    )

    @field_validator("resolved_at", "observed_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "spring_evidence_refs",
        "provider_evidence_refs",
        mode="before",
    )
    @classmethod
    def _evidence_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _jointly_bound(self) -> "AmbiguousDispatchRecoveryAttestation":
        _validate_provider(self.tool, self.provider)
        if self.resolved_at > self.observed_at:
            raise ValueError("recovery cannot be observed before resolution")
        if (
            self.recovery_attestation.request_digest != self.request_sha256
            or self.recovery_attestation.operation_ref != self.operation_ref
        ):
            raise ValueError(
                "recovery attestation does not match the ambiguous operation"
            )
        if _parsed_timestamp(self.recovery_attestation.attested_at) > _parsed_timestamp(
            self.observed_at
        ):
            raise ValueError("recovery evidence cannot postdate its observation")
        _require_bound_evidence(
            self,
            self.spring_evidence_refs,
            expected_kind="spring_ambiguous_dispatch_drill",
            authority="spring",
            provider=self.provider,
        )
        _require_bound_evidence(
            self,
            self.provider_evidence_refs,
            expected_kind="provider_ambiguous_dispatch_probe",
            authority="provider",
            provider=self.provider,
        )
        return self


class ProductionToolConformanceRequirement(_StrictModel):
    tool: ToolName
    provider: ProviderName
    hosted_schema_identity: OpaqueRef
    catalog_version: OpaqueRef
    tool_version: int = Field(ge=1, le=1_000_000)
    authoritative_readback_tool: ToolName
    required_normalized_error_kinds: tuple[ConnectorErrorKind, ...] = Field(
        min_length=2,
        max_length=10,
    )

    @field_validator("required_normalized_error_kinds", mode="before")
    @classmethod
    def _error_kinds(cls, value: Any) -> Any:
        values = _as_tuple(value)
        if not isinstance(values, tuple):
            return values
        return tuple(
            item
            if isinstance(item, ConnectorErrorKind)
            else ConnectorErrorKind(str(item))
            for item in values
        )

    @model_validator(mode="after")
    def _provider_and_errors(self) -> "ProductionToolConformanceRequirement":
        _validate_provider(self.tool, self.provider)
        _validate_provider(self.authoritative_readback_tool, self.provider)
        if len(self.required_normalized_error_kinds) != len(
            set(self.required_normalized_error_kinds)
        ):
            raise ValueError("required normalized error kinds must be unique")
        if ConnectorErrorKind.RATE_LIMITED not in self.required_normalized_error_kinds:
            raise ValueError("rate_limited must be a required normalized error kind")
        return self


class ProductionConnectorConformancePolicy(_StrictModel):
    requirements: tuple[ProductionToolConformanceRequirement, ...] = Field(
        min_length=1,
        max_length=_MAX_TOOL_PROOFS,
    )
    maximum_attestation_age_hours: int = Field(default=168, ge=1, le=8_760)
    certification_candidate_validity_hours: int = Field(
        default=24,
        ge=1,
        le=168,
    )

    @field_validator("requirements", mode="before")
    @classmethod
    def _requirements_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _requirements_unique(self) -> "ProductionConnectorConformancePolicy":
        tools = tuple(item.tool for item in self.requirements)
        if len(tools) != len(set(tools)):
            raise ValueError("production connector requirements must be unique by Tool")
        return self


class ProductionToolConformanceProof(_StrictModel):
    tool: ToolName
    provider: ProviderName
    schema_attestation: HostedToolSchemaAttestation
    route_attestation: ExactConnectorRouteAttestation
    write_attestation: GovernedWriteAttestation
    readback_attestation: ProviderReadbackAttestation
    replay_attestation: IdempotentReplayAttestation
    conflict_attestation: PayloadConflictRejectionAttestation
    error_attestations: tuple[NormalizedConnectorErrorAttestation, ...] = Field(
        min_length=2,
        max_length=10,
    )
    recovery_attestation: AmbiguousDispatchRecoveryAttestation

    @field_validator("error_attestations", mode="before")
    @classmethod
    def _errors_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _one_tool_and_provider(self) -> "ProductionToolConformanceProof":
        _validate_provider(self.tool, self.provider)
        observed_tools = {
            self.schema_attestation.tool,
            self.route_attestation.tool,
            self.write_attestation.tool,
            self.readback_attestation.write_tool,
            self.replay_attestation.tool,
            self.conflict_attestation.tool,
            self.recovery_attestation.tool,
            *(item.tool for item in self.error_attestations),
        }
        observed_providers = {
            self.schema_attestation.provider,
            self.route_attestation.provider,
            self.write_attestation.provider,
            self.readback_attestation.provider,
            self.replay_attestation.provider,
            self.conflict_attestation.provider,
            self.recovery_attestation.provider,
            *(item.provider for item in self.error_attestations),
        }
        if observed_tools != {self.tool} or observed_providers != {self.provider}:
            raise ValueError(
                "all conformance attestations must bind one exact Tool/provider"
            )
        if (
            len(
                {
                    self.route_attestation.connector_account_ref,
                    self.write_attestation.connector_account_ref,
                    self.readback_attestation.connector_account_ref,
                }
            )
            != 1
        ):
            raise ValueError(
                "route, write, and readback must bind one exact connector account"
            )
        error_kinds = tuple(item.injected_condition for item in self.error_attestations)
        if len(error_kinds) != len(set(error_kinds)):
            raise ValueError("error attestations must be unique by injected condition")
        return self


class ProductionConnectorConformanceInput(_StrictModel):
    schema_id: Literal["lightbulb.production_connector_conformance_input.v1"] = Field(
        default=PRODUCTION_CONNECTOR_CONFORMANCE_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    evaluated_at: str
    policy: ProductionConnectorConformancePolicy
    tool_proofs: tuple[ProductionToolConformanceProof, ...] = Field(
        max_length=_MAX_TOOL_PROOFS
    )

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator("tool_proofs", mode="before")
    @classmethod
    def _proofs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _scope_and_tools_are_exact(self) -> "ProductionConnectorConformanceInput":
        proof_tools = tuple(item.tool for item in self.tool_proofs)
        if len(proof_tools) != len(set(proof_tools)):
            raise ValueError("production Tool proofs must be unique")
        required_tools = {item.tool for item in self.policy.requirements}
        if not set(proof_tools).issubset(required_tools):
            raise ValueError("Tool proofs cannot exceed the declared conformance scope")
        for proof in self.tool_proofs:
            for scoped in (
                proof.route_attestation,
                proof.write_attestation,
                proof.readback_attestation,
            ):
                if (
                    scoped.tenant_id != self.tenant_id
                    or scoped.company_id != self.company_id
                    or scoped.project_id != self.project_id
                ):
                    raise ValueError(
                        "attested tenant/company/project scope must match evaluation scope"
                    )
        evidence = _all_input_evidence(self)
        if len(evidence) > _MAX_EVIDENCE:
            raise ValueError("production conformance evidence exceeds its bound")
        return self


class ProductionConformanceFinding(_StrictModel):
    tool: ToolName
    provider: ProviderName
    gate: ConformanceGate
    status: ConformanceGateStatus
    code: OpaqueRef
    message: str = Field(min_length=1, max_length=500)
    evidence_refs: tuple[EvidenceRefId, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_EVIDENCE_PER_TOOL,
    )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ProductionToolConformanceResult(_StrictModel):
    tool: ToolName
    provider: ProviderName
    status: ConformanceGateStatus
    gates: tuple[ProductionConformanceFinding, ...] = Field(
        min_length=len(_GATE_ORDER),
        max_length=len(_GATE_ORDER),
    )
    evidence_refs: tuple[EvidenceRefId, ...] = Field(max_length=_MAX_EVIDENCE_PER_TOOL)

    @field_validator("gates", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _gate_set_and_status(self) -> "ProductionToolConformanceResult":
        if tuple(item.gate for item in self.gates) != _GATE_ORDER:
            raise ValueError(
                "Tool result must contain the exact conformance gate order"
            )
        expected: ConformanceGateStatus = (
            "fail"
            if any(item.status == "fail" for item in self.gates)
            else "indeterminate"
            if any(item.status == "indeterminate" for item in self.gates)
            else "pass"
        )
        if self.status != expected:
            raise ValueError("Tool status must match gate statuses")
        return self


class ProductionConnectorConformanceEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    provider_dispatches: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    journals_mutated: Literal[0] = 0
    production_certified: Literal[False] = False
    certification_authorized: Literal[False] = False
    external_systems_changed: Literal[False] = False


def _conformance_evaluation_digest(
    *,
    evaluation_ref: str,
    disposition: ProductionConformanceDisposition,
    tool_results: Sequence[ProductionToolConformanceResult],
    certification_candidates: Sequence[ConnectorConformanceCertification],
    input_digest: str,
    evidence_digest: str,
) -> str:
    return _stable_digest(
        {
            "evaluation_ref": evaluation_ref,
            "disposition": disposition,
            "tool_results": [item.to_dict() for item in tool_results],
            "certification_candidates": [
                item.to_dict() for item in certification_candidates
            ],
            "input_digest": input_digest,
            "evidence_digest": evidence_digest,
        }
    )


class ProductionConnectorConformanceResult(_StrictModel):
    schema_id: Literal["lightbulb.production_connector_conformance_result.v1"] = Field(
        default=PRODUCTION_CONNECTOR_CONFORMANCE_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    evaluated_at: str
    disposition: ProductionConformanceDisposition
    assurance_grade: PrimitiveEvidenceVerificationGrade
    tool_results: tuple[ProductionToolConformanceResult, ...] = Field(
        min_length=1,
        max_length=_MAX_TOOL_PROOFS,
    )
    findings: tuple[ProductionConformanceFinding, ...] = Field(
        min_length=len(_GATE_ORDER),
        max_length=_MAX_TOOL_PROOFS * len(_GATE_ORDER),
    )
    certification_candidates: tuple[ConnectorConformanceCertification, ...] = Field(
        max_length=_MAX_TOOL_PROOFS
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(max_length=_MAX_EVIDENCE)
    input_digest: Sha256Digest
    evidence_digest: Sha256Digest
    evaluation_digest: Sha256Digest
    operation_spec: PrimitiveOperationSpec
    effect_boundary: ProductionConnectorConformanceEffectBoundary = Field(
        default_factory=ProductionConnectorConformanceEffectBoundary
    )
    production_certified: Literal[False] = False
    certification_authorized: Literal[False] = False
    result_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator(
        "tool_results",
        "findings",
        "certification_candidates",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("evaluated_at")
    @classmethod
    def _evaluated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator("assurance_grade", mode="before")
    @classmethod
    def _grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @model_validator(mode="after")
    def _result_is_sound(self) -> "ProductionConnectorConformanceResult":
        if self.operation_spec != PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION:
            raise ValueError("operation_spec must identify this verifier")
        statuses = {item.status for item in self.tool_results}
        expected_disposition: ProductionConformanceDisposition = (
            "blocked"
            if "fail" in statuses
            else "indeterminate"
            if "indeterminate" in statuses
            else "ready_for_operator_certification"
        )
        if self.disposition != expected_disposition:
            raise ValueError("disposition must match Tool results")
        if self.disposition != "ready_for_operator_certification" and (
            self.certification_candidates
        ):
            raise ValueError("blocked or indeterminate results cannot emit candidates")
        if (
            tuple(finding for item in self.tool_results for finding in item.gates)
            != self.findings
        ):
            raise ValueError("findings must exactly flatten Tool gate results")
        if len({item.evidence_ref for item in self.evidence_refs}) != len(
            self.evidence_refs
        ):
            raise ValueError("result evidence references must be unique")
        evidence_by_ref = {item.evidence_ref: item for item in self.evidence_refs}
        if len({item.tool for item in self.tool_results}) != len(self.tool_results):
            raise ValueError("Tool results must be unique by Tool")
        results_by_tool = {item.tool: item for item in self.tool_results}
        expected_evidence_by_tool: dict[str, tuple[PrimitiveEvidenceRef, ...]] = {}
        for tool_result in self.tool_results:
            _validate_provider(tool_result.tool, tool_result.provider)
            if len(set(tool_result.evidence_refs)) != len(tool_result.evidence_refs):
                raise ValueError("Tool result evidence references must be unique")
            try:
                expected_evidence_by_tool[tool_result.tool] = tuple(
                    evidence_by_ref[ref] for ref in tool_result.evidence_refs
                )
            except KeyError as exc:
                raise ValueError(
                    "Tool result evidence must exist in result evidence"
                ) from exc
        if self.disposition == "ready_for_operator_certification" and len(
            self.certification_candidates
        ) != len(self.tool_results):
            raise ValueError("ready results require one candidate per exact Tool")
        candidate_tools: set[str] = set()
        for candidate in self.certification_candidates:
            tool = candidate.required_tools[0]
            if tool in candidate_tools:
                raise ValueError("certification candidates must be unique by Tool")
            candidate_tools.add(tool)
            tool_result = results_by_tool.get(tool)
            if tool_result is None or candidate.provider != tool_result.provider:
                raise ValueError("candidate must match one exact Tool result")
            if candidate.certified_at != self.evaluated_at:
                raise ValueError("candidate certification time must match evaluation")
            if candidate.evidence_refs != expected_evidence_by_tool[tool]:
                raise ValueError(
                    "candidate evidence must exactly match its Tool result proof"
                )
            if not all(
                (
                    candidate.tenant_isolation_verified,
                    candidate.project_account_binding_verified,
                    candidate.schema_drift_check_passed,
                    candidate.error_normalization_verified,
                    candidate.rate_limit_behavior_verified,
                )
            ):
                raise ValueError("candidate flags must be derived as true")
        expected_grade = min(
            (item.verification_grade for item in self.evidence_refs),
            key=lambda grade: _GRADE_RANK[grade],
            default=PrimitiveEvidenceVerificationGrade.UNVERIFIED,
        )
        if self.assurance_grade != expected_grade:
            raise ValueError("assurance_grade must match result evidence")
        expected_evidence_digest = _stable_digest(
            [item.to_dict() for item in self.evidence_refs]
        )
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match result evidence")
        expected_evaluation_digest = _conformance_evaluation_digest(
            evaluation_ref=self.evaluation_ref,
            disposition=self.disposition,
            tool_results=self.tool_results,
            certification_candidates=self.certification_candidates,
            input_digest=self.input_digest,
            evidence_digest=self.evidence_digest,
        )
        if self.evaluation_digest != expected_evaluation_digest:
            raise ValueError("evaluation_digest does not match result evaluation")
        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(digest_payload)
        if self.result_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("result_digest does not match result")
        object.__setattr__(self, "result_digest", expected_digest)
        return self


PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION = PrimitiveOperationSpec(
    operation_ref="production-connector-conformance.evaluate",
    tool="operations.evaluate_production_connector_conformance",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _proof_attestations(
    proof: ProductionToolConformanceProof,
) -> tuple[BaseModel, ...]:
    return (
        proof.schema_attestation,
        proof.route_attestation,
        proof.write_attestation,
        proof.readback_attestation,
        proof.replay_attestation,
        proof.conflict_attestation,
        *proof.error_attestations,
        proof.recovery_attestation,
    )


def _attestation_evidence(attestation: BaseModel) -> tuple[PrimitiveEvidenceRef, ...]:
    values: list[PrimitiveEvidenceRef] = []
    for field_name in (
        "evidence_refs",
        "spring_evidence_refs",
        "provider_evidence_refs",
    ):
        candidate = getattr(attestation, field_name, ())
        values.extend(candidate)
    if isinstance(attestation, AmbiguousDispatchRecoveryAttestation):
        values.extend(attestation.recovery_attestation.evidence_refs)
    return tuple(values)


def _all_input_evidence(
    inputs: ProductionConnectorConformanceInput,
) -> tuple[PrimitiveEvidenceRef, ...]:
    by_ref: dict[str, PrimitiveEvidenceRef] = {}
    for proof in inputs.tool_proofs:
        for attestation in _proof_attestations(proof):
            for evidence in _attestation_evidence(attestation):
                previous = by_ref.get(evidence.evidence_ref)
                if previous is not None and previous != evidence:
                    raise ValueError(
                        "one evidence_ref cannot identify conflicting production proof"
                    )
                by_ref[evidence.evidence_ref] = evidence
    return tuple(by_ref[key] for key in sorted(by_ref))


def _proof_evidence(
    proof: ProductionToolConformanceProof,
) -> tuple[PrimitiveEvidenceRef, ...]:
    by_ref: dict[str, PrimitiveEvidenceRef] = {}
    for attestation in _proof_attestations(proof):
        for evidence in _attestation_evidence(attestation):
            by_ref[evidence.evidence_ref] = evidence
    return tuple(by_ref[key] for key in sorted(by_ref))


def _evidence_refs_for(*attestations: BaseModel) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                evidence.evidence_ref
                for attestation in attestations
                for evidence in _attestation_evidence(attestation)
            }
        )
    )


def _evidence_gate_status(
    proof: ProductionToolConformanceProof,
    *,
    evaluated_at: datetime,
    maximum_age_hours: int,
) -> ConformanceGateStatus:
    stale = False
    for attestation in _proof_attestations(proof):
        observed_at = _parsed_timestamp(str(getattr(attestation, "observed_at")))
        if observed_at > evaluated_at:
            return "fail"
        if (evaluated_at - observed_at).total_seconds() / 3_600 > maximum_age_hours:
            stale = True
        for evidence in _attestation_evidence(attestation):
            evidence_at = _parsed_timestamp(evidence.observed_at)
            if evidence_at > evaluated_at:
                return "fail"
            if (
                evidence.effective_at is not None
                and _parsed_timestamp(evidence.effective_at) > evaluated_at
            ):
                return "fail"
            if (evaluated_at - evidence_at).total_seconds() / 3_600 > maximum_age_hours:
                stale = True
    return "indeterminate" if stale else "pass"


def _gate_finding(
    *,
    proof: ProductionToolConformanceProof,
    gate: ConformanceGate,
    status: ConformanceGateStatus,
    code: str,
    message: str,
    evidence_refs: Sequence[str],
) -> ProductionConformanceFinding:
    return ProductionConformanceFinding(
        tool=proof.tool,
        provider=proof.provider,
        gate=gate,
        status=status,
        code=code,
        message=message,
        evidence_refs=tuple(sorted(set(evidence_refs))),
    )


def _semantic_status(value: bool) -> ConformanceGateStatus:
    return "pass" if value else "fail"


def _evaluate_tool_proof(
    requirement: ProductionToolConformanceRequirement,
    proof: ProductionToolConformanceProof,
    *,
    evaluated_at: datetime,
    maximum_age_hours: int,
) -> ProductionToolConformanceResult:
    schema = proof.schema_attestation
    route = proof.route_attestation
    write = proof.write_attestation
    readback = proof.readback_attestation
    replay = proof.replay_attestation
    conflict = proof.conflict_attestation
    recovery = proof.recovery_attestation

    evidence_status = _evidence_gate_status(
        proof,
        evaluated_at=evaluated_at,
        maximum_age_hours=maximum_age_hours,
    )
    gates: list[ProductionConformanceFinding] = [
        _gate_finding(
            proof=proof,
            gate="evidence",
            status=evidence_status,
            code=f"production_conformance.evidence.{evidence_status}",
            message=(
                "Production attestations are current and evidence-bound."
                if evidence_status == "pass"
                else "Production attestations are future-dated or stale."
            ),
            evidence_refs=(
                evidence.evidence_ref for evidence in _proof_evidence(proof)
            ),
        )
    ]

    schema_passed = all(
        (
            schema.hosted_schema_identity == requirement.hosted_schema_identity,
            schema.catalog_version == requirement.catalog_version,
            schema.tool_version == requirement.tool_version,
            schema.server_effect == "write",
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="hosted_schema",
            status=_semantic_status(schema_passed),
            code=(
                "production_conformance.hosted_schema.exact"
                if schema_passed
                else "production_conformance.hosted_schema.drift"
            ),
            message=(
                "Hosted Tool schema identity, catalog version, and Tool version match."
                if schema_passed
                else "Hosted Tool schema identity or version drifted from policy."
            ),
            evidence_refs=_evidence_refs_for(schema),
        )
    )

    route_passed = all(
        (
            route.tool_version == requirement.tool_version,
            route.target_sha256 != route.route_sha256,
            set(item.attempted_scope for item in route.isolation_observations)
            == {"tenant", "company", "project", "account"},
            all(
                item.provider_dispatch_count == 0
                for item in route.isolation_observations
            ),
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="exact_route",
            status=_semantic_status(route_passed),
            code=(
                "production_conformance.route.exact"
                if route_passed
                else "production_conformance.route.invalid"
            ),
            message=(
                "Tenant/company/project/account route and isolation probes are exact."
                if route_passed
                else "Exact route identity or isolation probes did not conform."
            ),
            evidence_refs=_evidence_refs_for(route),
        )
    )

    provenance = write.provenance
    journal_passed = all(
        (
            write.approval_status == "consumed",
            write.journal_status == "succeeded",
            write.effect_catalog_version == requirement.catalog_version,
            provenance.tool_version == requirement.tool_version,
            str(provenance.tenant_connector_id) == route.tenant_connector_id,
            provenance.route_digest == route.route_sha256,
            provenance.approval_ref is not None,
            provenance.approval_receipt_digest is not None,
            provenance.receipt_digest != provenance.request_digest,
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="spring_approval_journal",
            status=_semantic_status(journal_passed),
            code=(
                "production_conformance.spring_journal.complete"
                if journal_passed
                else "production_conformance.spring_journal.invalid"
            ),
            message=(
                "Spring approval consumption, journal, and provenance are exact."
                if journal_passed
                else "Spring approval, journal, or provenance proof did not conform."
            ),
            evidence_refs=_evidence_refs_for(write),
        )
    )

    readback_passed = all(
        (
            readback.readback_tool == requirement.authoritative_readback_tool,
            readback.provider_effect_ref == write.provider_effect_ref,
            readback.write_output_sha256 == write.provider_output_sha256,
            readback.outcome == "applied",
            _parsed_timestamp(readback.readback_at)
            >= _parsed_timestamp(provenance.completed_at),
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="live_write_readback",
            status=_semantic_status(readback_passed),
            code=(
                "production_conformance.write_readback.confirmed"
                if readback_passed
                else "production_conformance.write_readback.unconfirmed"
            ),
            message=(
                "Provider-authoritative readback confirms the live write outcome."
                if readback_passed
                else "Live write lacks matching authoritative provider readback."
            ),
            evidence_refs=_evidence_refs_for(write, readback),
        )
    )

    replay_passed = all(
        (
            replay.original_journal_ref == provenance.journal_ref,
            replay.replay_journal_ref == provenance.journal_ref,
            replay.original_request_sha256 == provenance.request_digest,
            replay.replay_request_sha256 == provenance.request_digest,
            replay.original_receipt_sha256 == provenance.receipt_digest,
            replay.replay_receipt_sha256 == provenance.receipt_digest,
            replay.original_provider_effect_ref == write.provider_effect_ref,
            replay.replay_provider_effect_ref == write.provider_effect_ref,
            replay.original_provider_effect_count == 1,
            replay.replay_provider_effect_count == 1,
            replay.replay_disposition == "cached",
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="idempotent_replay",
            status=_semantic_status(replay_passed),
            code=(
                "production_conformance.replay.stable"
                if replay_passed
                else "production_conformance.replay.duplicate_or_drifted"
            ),
            message=(
                "Stable replay returned the same journal, receipt, and provider effect."
                if replay_passed
                else "Replay changed identity or caused a duplicate provider effect."
            ),
            evidence_refs=_evidence_refs_for(write, replay),
        )
    )

    conflict_passed = all(
        (
            conflict.idempotency_key_sha256 == write.idempotency_key_sha256,
            conflict.accepted_request_sha256 == provenance.request_digest,
            conflict.conflicting_request_sha256 != conflict.accepted_request_sha256,
            conflict.journal_ref_before == provenance.journal_ref,
            conflict.journal_ref_after == provenance.journal_ref,
            conflict.provider_dispatch_count_before
            == conflict.provider_dispatch_count_after
            == 1,
            conflict.response_status == "conflict",
            conflict.normalized_error_kind == ConnectorErrorKind.IDEMPOTENCY_CONFLICT,
            conflict.normalized_error_code == "idempotency_payload_mismatch",
            conflict.retry_disposition == "blocked",
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="payload_conflict",
            status=_semantic_status(conflict_passed),
            code=(
                "production_conformance.payload_conflict.rejected"
                if conflict_passed
                else "production_conformance.payload_conflict.not_rejected"
            ),
            message=(
                "Changed payload under the same idempotency identity was rejected."
                if conflict_passed
                else "Payload-conflict behavior was not stable or fail-closed."
            ),
            evidence_refs=_evidence_refs_for(write, conflict),
        )
    )

    errors_by_kind = {
        item.injected_condition: item for item in proof.error_attestations
    }
    required_errors = set(requirement.required_normalized_error_kinds)
    error_normalization_passed = required_errors.issubset(errors_by_kind) and all(
        item.normalized_error_kind == kind
        and item.response_status in {"failed", "blocked"}
        for kind, item in errors_by_kind.items()
        if kind in required_errors
    )
    error_evidence_refs = tuple(
        sorted(
            {
                ref
                for kind in required_errors
                if kind in errors_by_kind
                for ref in _evidence_refs_for(errors_by_kind[kind])
            }
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="error_normalization",
            status=_semantic_status(error_normalization_passed),
            code=(
                "production_conformance.errors.normalized"
                if error_normalization_passed
                else "production_conformance.errors.incomplete"
            ),
            message=(
                "Required provider failures map to stable Connector Error Kinds."
                if error_normalization_passed
                else "Required normalized provider error evidence is incomplete."
            ),
            evidence_refs=error_evidence_refs,
        )
    )

    rate_limit = errors_by_kind.get(ConnectorErrorKind.RATE_LIMITED)
    rate_limit_passed = rate_limit is not None and all(
        (
            rate_limit.provider_status_code == 429,
            rate_limit.normalized_error_kind == ConnectorErrorKind.RATE_LIMITED,
            rate_limit.response_status == "failed",
            rate_limit.retry_disposition == "retryable",
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="rate_limit",
            status=_semantic_status(rate_limit_passed),
            code=(
                "production_conformance.rate_limit.normalized"
                if rate_limit_passed
                else "production_conformance.rate_limit.invalid"
            ),
            message=(
                "Provider HTTP 429 is normalized as retryable rate_limited."
                if rate_limit_passed
                else "Rate-limit normalization did not conform."
            ),
            evidence_refs=(
                _evidence_refs_for(rate_limit) if rate_limit is not None else ()
            ),
        )
    )

    recovery_outcome = recovery.recovery_attestation.outcome
    recovery_terminal = (
        recovery.resolution_path == "status_probe"
        and recovery.final_journal_status == "succeeded"
        and recovery.final_provider_effect_ref is not None
        if recovery_outcome == PrimitiveRecoveryOutcome.EFFECT_CONFIRMED
        else recovery.resolution_path == "status_probe"
        and recovery.final_journal_status == "failed"
        and recovery.final_provider_effect_ref is None
        if recovery_outcome == PrimitiveRecoveryOutcome.EFFECT_NOT_APPLIED
        else recovery.resolution_path == "manual_reconciliation"
        and recovery.final_journal_status != "ambiguous"
        if recovery_outcome
        in {
            PrimitiveRecoveryOutcome.MANUALLY_RECONCILED,
            PrimitiveRecoveryOutcome.COMPENSATED,
        }
        else False
    )
    recovery_passed = all(
        (
            recovery.initial_journal_status == "ambiguous",
            recovery.initial_error_code == "GOVERNED_EXECUTION_AMBIGUOUS",
            recovery.initial_retry_disposition == "blocked",
            recovery.provider_dispatch_count_at_ambiguity
            == recovery.provider_dispatch_count_before_resolution
            == recovery.final_provider_dispatch_count
            == 1,
            recovery_terminal,
        )
    )
    gates.append(
        _gate_finding(
            proof=proof,
            gate="ambiguous_recovery",
            status=_semantic_status(recovery_passed),
            code=(
                "production_conformance.ambiguous_recovery.resolved"
                if recovery_passed
                else "production_conformance.ambiguous_recovery.invalid"
            ),
            message=(
                "Ambiguous dispatch blocked auto-retry and resolved from attested proof."
                if recovery_passed
                else "Ambiguous-dispatch recovery did not fail closed or resolve safely."
            ),
            evidence_refs=_evidence_refs_for(recovery),
        )
    )

    status: ConformanceGateStatus = (
        "fail"
        if any(item.status == "fail" for item in gates)
        else "indeterminate"
        if any(item.status == "indeterminate" for item in gates)
        else "pass"
    )
    return ProductionToolConformanceResult(
        tool=proof.tool,
        provider=proof.provider,
        status=status,
        gates=tuple(gates),
        evidence_refs=tuple(
            evidence.evidence_ref for evidence in _proof_evidence(proof)
        ),
    )


def _missing_tool_result(
    requirement: ProductionToolConformanceRequirement,
) -> ProductionToolConformanceResult:
    gates = tuple(
        ProductionConformanceFinding(
            tool=requirement.tool,
            provider=requirement.provider,
            gate=gate,
            status="fail",
            code="production_conformance.proof.missing",
            message="Required production Tool proof is missing.",
        )
        for gate in _GATE_ORDER
    )
    return ProductionToolConformanceResult(
        tool=requirement.tool,
        provider=requirement.provider,
        status="fail",
        gates=gates,
        evidence_refs=(),
    )


def evaluate_production_connector_conformance(
    inputs: ProductionConnectorConformanceInput | Mapping[str, Any],
) -> ProductionConnectorConformanceResult:
    """Verify supplied production proof without executing or certifying anything."""

    parsed = ProductionConnectorConformanceInput.model_validate(
        _detached_validation_payload(inputs)
    )
    evaluated_at = _parsed_timestamp(parsed.evaluated_at)
    proofs_by_tool = {proof.tool: proof for proof in parsed.tool_proofs}
    results: list[ProductionToolConformanceResult] = []
    for requirement in sorted(parsed.policy.requirements, key=lambda item: item.tool):
        proof = proofs_by_tool.get(requirement.tool)
        results.append(
            _missing_tool_result(requirement)
            if proof is None
            else _evaluate_tool_proof(
                requirement,
                proof,
                evaluated_at=evaluated_at,
                maximum_age_hours=parsed.policy.maximum_attestation_age_hours,
            )
        )

    statuses = {item.status for item in results}
    disposition: ProductionConformanceDisposition = (
        "blocked"
        if "fail" in statuses
        else "indeterminate"
        if "indeterminate" in statuses
        else "ready_for_operator_certification"
    )
    all_evidence = _all_input_evidence(parsed)
    assurance_grade = min(
        (item.verification_grade for item in all_evidence),
        key=lambda grade: _GRADE_RANK[grade],
        default=PrimitiveEvidenceVerificationGrade.UNVERIFIED,
    )
    candidates: list[ConnectorConformanceCertification] = []
    if disposition == "ready_for_operator_certification":
        expires_at = (
            (
                evaluated_at
                + timedelta(hours=parsed.policy.certification_candidate_validity_hours)
            )
            .isoformat()
            .replace("+00:00", "Z")
        )
        for requirement in sorted(
            parsed.policy.requirements,
            key=lambda item: item.tool,
        ):
            proof = proofs_by_tool[requirement.tool]
            candidates.append(
                ConnectorConformanceCertification(
                    provider=requirement.provider,
                    environment="production",
                    required_tools=(requirement.tool,),
                    certified_tools=(requirement.tool,),
                    tenant_isolation_verified=True,
                    project_account_binding_verified=True,
                    schema_drift_check_passed=True,
                    error_normalization_verified=True,
                    rate_limit_behavior_verified=True,
                    certified_at=parsed.evaluated_at,
                    expires_at=expires_at,
                    evidence_refs=_proof_evidence(proof),
                )
            )

    findings = tuple(finding for result in results for finding in result.gates)
    input_digest = _stable_digest(parsed.to_dict())
    evidence_digest = _stable_digest([item.to_dict() for item in all_evidence])
    evaluation_digest = _conformance_evaluation_digest(
        evaluation_ref=parsed.evaluation_ref,
        disposition=disposition,
        tool_results=results,
        certification_candidates=candidates,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
    )
    return ProductionConnectorConformanceResult(
        evaluation_ref=parsed.evaluation_ref,
        environment=parsed.environment,
        tenant_id=parsed.tenant_id,
        company_id=parsed.company_id,
        project_id=parsed.project_id,
        evaluated_at=parsed.evaluated_at,
        disposition=disposition,
        assurance_grade=assurance_grade,
        tool_results=tuple(results),
        findings=findings,
        certification_candidates=tuple(candidates),
        evidence_refs=all_evidence,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        evaluation_digest=evaluation_digest,
        operation_spec=PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION,
    )


def _execution_scope_matches_input(
    context: PrimitiveExecutionContext,
    inputs: ProductionConnectorConformanceInput,
) -> bool:
    return (
        context.scope.tenant_ref == inputs.tenant_id
        and context.scope.company_ref == inputs.company_id
        and context.scope.project_id is not None
        and str(context.scope.project_id) == inputs.project_id
    )


def _example_evidence(
    payload: Mapping[str, Any],
    *,
    evidence_ref: str,
    kind: str,
    issuer_ref: str,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": issuer_ref,
        "subject_ref": payload["attestation_ref"],
        "sha256": production_attestation_digest(payload),
        "observed_at": observed_at,
        "effective_at": observed_at,
        "verification_grade": "attested",
        "classification": "restricted",
        "retention_policy": "production-conformance-two-years",
    }


def _example_inputs() -> dict[str, Any]:
    tenant_id = "11111111-1111-4111-8111-111111111111"
    company_id = "22222222-2222-4222-8222-222222222222"
    project_id = "33333333-3333-4333-8333-333333333333"
    user_id = "44444444-4444-4444-8444-444444444444"
    project_binding_id = "55555555-5555-4555-8555-555555555555"
    tenant_tool_binding_id = "66666666-6666-4666-8666-666666666666"
    tenant_connector_id = "77777777-7777-4777-8777-777777777777"
    connector_id = "88888888-8888-4888-8888-888888888888"
    approval_ref = "99999999-9999-4999-8999-999999999999"
    tool = "quickbooks.create_journal_entry"
    readback_tool = "quickbooks.get_journal_entry"
    provider = "quickbooks"
    catalog_version = "finance-governed-writes-v1"

    schema: dict[str, Any] = {
        "schema": HOSTED_TOOL_SCHEMA_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-schema",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "hosted_schema_identity": "lightbulb.hosted_tool_contract.v1",
        "catalog_version": catalog_version,
        "tool_version": 1,
        "server_effect": "write",
        "input_schema_sha256": "a" * 64,
        "output_schema_sha256": "b" * 64,
        "observed_at": "2026-08-24T12:00:00Z",
    }
    schema["evidence_refs"] = [
        _example_evidence(
            schema,
            evidence_ref="evidence-qb-je-schema",
            kind="hosted_tool_schema",
            issuer_ref="spring-governed-connector-authority",
            observed_at=schema["observed_at"],
        )
    ]

    route: dict[str, Any] = {
        "schema": EXACT_CONNECTOR_ROUTE_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-route",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "connector_account_ref": "quickbooks-primary",
        "target_resource_ref": "quickbooks-company-913",
        "project_connector_binding_id": project_binding_id,
        "tenant_tool_binding_id": tenant_tool_binding_id,
        "tenant_connector_id": tenant_connector_id,
        "connector_id": connector_id,
        "adapter_identity": "QuickBooksAdapter",
        "handler_identity": "quickbooks.create_journal_entry",
        "tool_version": 1,
        "target_sha256": "2" * 64,
        "route_sha256": "3" * 64,
        "isolation_observations": [
            {
                "attempted_scope": scope,
                "response_status": "denied",
                "error_code": f"{scope}_scope_denied",
                "provider_dispatch_count": 0,
            }
            for scope in ("tenant", "company", "project", "account")
        ],
        "observed_at": "2026-08-24T12:05:00Z",
    }
    route["evidence_refs"] = [
        _example_evidence(
            route,
            evidence_ref="evidence-qb-je-route",
            kind="exact_connector_route",
            issuer_ref="spring-governed-connector-authority",
            observed_at=route["observed_at"],
        )
    ]

    provenance = {
        "schema": "lightbulb.connector_execution_provenance.v1",
        "tool": tool,
        "tool_version": 1,
        "server_effect": "write",
        "connector_account_ref": "quickbooks-primary",
        "tenant_connector_id": tenant_connector_id,
        "project_id": project_id,
        "route_digest": route["route_sha256"],
        "journal_ref": "journal-qb-je-1001",
        "request_digest": "4" * 64,
        "receipt_digest": "5" * 64,
        "approval_ref": approval_ref,
        "approval_receipt_digest": "6" * 64,
        "completed_at": "2026-08-24T12:10:00Z",
    }
    write: dict[str, Any] = {
        "schema": GOVERNED_WRITE_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-write",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "user_id": user_id,
        "project_id": project_id,
        "connector_account_ref": "quickbooks-primary",
        "effect_catalog_version": catalog_version,
        "idempotency_key_sha256": "7" * 64,
        "payload_sha256": "8" * 64,
        "approval_status": "consumed",
        "journal_status": "succeeded",
        "provenance": provenance,
        "provider_effect_ref": "qb-journal-entry-1001",
        "provider_output_sha256": "9" * 64,
        "observed_at": "2026-08-24T12:12:00Z",
    }
    write["evidence_refs"] = [
        _example_evidence(
            write,
            evidence_ref="evidence-qb-je-write",
            kind="governed_connector_write",
            issuer_ref="spring-governed-connector-authority",
            observed_at=write["observed_at"],
        )
    ]

    readback: dict[str, Any] = {
        "schema": PROVIDER_READBACK_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-readback",
        "write_tool": tool,
        "readback_tool": readback_tool,
        "provider": provider,
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "connector_account_ref": "quickbooks-primary",
        "provider_effect_ref": write["provider_effect_ref"],
        "write_output_sha256": write["provider_output_sha256"],
        "readback_state_sha256": "c" * 64,
        "provider_version_ref": "quickbooks-sync-token-1001",
        "outcome": "applied",
        "readback_at": "2026-08-24T12:15:00Z",
        "observed_at": "2026-08-24T12:16:00Z",
    }
    readback["evidence_refs"] = [
        _example_evidence(
            readback,
            evidence_ref="evidence-qb-je-readback",
            kind="provider_authoritative_readback",
            issuer_ref="quickbooks-production-api",
            observed_at=readback["observed_at"],
        )
    ]

    replay: dict[str, Any] = {
        "schema": IDEMPOTENT_REPLAY_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-replay",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "original_journal_ref": provenance["journal_ref"],
        "replay_journal_ref": provenance["journal_ref"],
        "original_request_sha256": provenance["request_digest"],
        "replay_request_sha256": provenance["request_digest"],
        "original_receipt_sha256": provenance["receipt_digest"],
        "replay_receipt_sha256": provenance["receipt_digest"],
        "original_provider_effect_ref": write["provider_effect_ref"],
        "replay_provider_effect_ref": write["provider_effect_ref"],
        "original_provider_effect_count": 1,
        "replay_provider_effect_count": 1,
        "replay_disposition": "cached",
        "observed_at": "2026-08-24T12:20:00Z",
    }
    replay["spring_evidence_refs"] = [
        _example_evidence(
            replay,
            evidence_ref="evidence-qb-je-replay-spring",
            kind="idempotent_replay",
            issuer_ref="spring-governed-connector-authority",
            observed_at=replay["observed_at"],
        )
    ]
    replay["provider_evidence_refs"] = [
        _example_evidence(
            replay,
            evidence_ref="evidence-qb-je-replay-provider",
            kind="provider_idempotent_replay_effect_count",
            issuer_ref="quickbooks-production-api",
            observed_at=replay["observed_at"],
        )
    ]

    conflict: dict[str, Any] = {
        "schema": PAYLOAD_CONFLICT_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-conflict",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "idempotency_key_sha256": write["idempotency_key_sha256"],
        "accepted_request_sha256": provenance["request_digest"],
        "conflicting_request_sha256": "d" * 64,
        "journal_ref_before": provenance["journal_ref"],
        "journal_ref_after": provenance["journal_ref"],
        "provider_dispatch_count_before": 1,
        "provider_dispatch_count_after": 1,
        "response_status": "conflict",
        "normalized_error_kind": "idempotency_conflict",
        "normalized_error_code": "idempotency_payload_mismatch",
        "retry_disposition": "blocked",
        "observed_at": "2026-08-24T12:25:00Z",
    }
    conflict["evidence_refs"] = [
        _example_evidence(
            conflict,
            evidence_ref="evidence-qb-je-conflict",
            kind="idempotency_payload_conflict",
            issuer_ref="spring-governed-connector-authority",
            observed_at=conflict["observed_at"],
        )
    ]

    errors: list[dict[str, Any]] = []
    for index, (kind, status_code, code, retry) in enumerate(
        (
            ("rate_limited", 429, "QUICKBOOKS_RATE_LIMITED", "retryable"),
            ("vendor_error", 500, "QUICKBOOKS_PROVIDER_ERROR", "blocked"),
        ),
        start=1,
    ):
        error: dict[str, Any] = {
            "schema": NORMALIZED_ERROR_ATTESTATION_SCHEMA,
            "attestation_ref": f"attestation-qb-je-error-{kind}",
            "tool": tool,
            "provider": provider,
            "environment": "production",
            "injected_condition": kind,
            "provider_status_code": status_code,
            "provider_error_sha256": str(index) * 64,
            "normalized_error_kind": kind,
            "normalized_error_code": code,
            "response_status": "failed",
            "retry_disposition": retry,
            "observed_at": f"2026-08-24T12:{25 + index:02d}:00Z",
        }
        error["spring_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=f"evidence-qb-je-error-{kind}-spring",
                kind="spring_connector_error_normalization",
                issuer_ref="spring-governed-connector-authority",
                observed_at=error["observed_at"],
            )
        ]
        error["provider_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=f"evidence-qb-je-error-{kind}-provider",
                kind="provider_connector_error",
                issuer_ref="quickbooks-production-api",
                observed_at=error["observed_at"],
            )
        ]
        errors.append(error)

    recovery_request_digest = "e" * 64
    primitive_recovery_evidence = {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": "evidence-qb-je-recovery-probe",
        "kind": "provider_recovery_probe",
        "issuer_ref": "quickbooks-production-api",
        "subject_ref": "qb-je-ambiguous-drill",
        "sha256": "f" * 64,
        "observed_at": "2026-08-24T12:35:00Z",
        "effective_at": "2026-08-24T12:35:00Z",
        "verification_grade": "attested",
        "classification": "restricted",
    }
    recovery: dict[str, Any] = {
        "schema": AMBIGUOUS_RECOVERY_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qb-je-ambiguous-recovery",
        "tool": tool,
        "provider": provider,
        "environment": "production",
        "operation_ref": "qb-je-ambiguous-drill",
        "journal_ref": "journal-qb-je-ambiguous-1002",
        "request_sha256": recovery_request_digest,
        "initial_journal_status": "ambiguous",
        "initial_error_code": "GOVERNED_EXECUTION_AMBIGUOUS",
        "initial_retry_disposition": "blocked",
        "provider_dispatch_count_at_ambiguity": 1,
        "provider_dispatch_count_before_resolution": 1,
        "resolution_path": "status_probe",
        "recovery_attestation": {
            "schema": "lightbulb.primitive_recovery_attestation.v1",
            "request_digest": recovery_request_digest,
            "operation_ref": "qb-je-ambiguous-drill",
            "outcome": "effect_confirmed",
            "replay_permitted": False,
            "evidence_refs": [primitive_recovery_evidence],
            "attested_by_ref": "spring-governed-connector-authority",
            "attested_at": "2026-08-24T12:35:00Z",
        },
        "final_journal_status": "succeeded",
        "final_provider_effect_ref": "qb-journal-entry-1002",
        "final_provider_dispatch_count": 1,
        "resolved_at": "2026-08-24T12:35:00Z",
        "observed_at": "2026-08-24T12:40:00Z",
    }
    recovery["spring_evidence_refs"] = [
        _example_evidence(
            recovery,
            evidence_ref="evidence-qb-je-recovery-spring",
            kind="spring_ambiguous_dispatch_drill",
            issuer_ref="spring-governed-connector-authority",
            observed_at=recovery["observed_at"],
        )
    ]
    recovery["provider_evidence_refs"] = [
        _example_evidence(
            recovery,
            evidence_ref="evidence-qb-je-recovery-provider",
            kind="provider_ambiguous_dispatch_probe",
            issuer_ref="quickbooks-production-api",
            observed_at=recovery["observed_at"],
        )
    ]

    return {
        "schema": PRODUCTION_CONNECTOR_CONFORMANCE_INPUT_SCHEMA,
        "evaluation_ref": "connector-conformance-qb-je-2026-08-24",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "evaluated_at": "2026-08-24T13:00:00Z",
        "policy": {
            "requirements": [
                {
                    "tool": tool,
                    "provider": provider,
                    "hosted_schema_identity": schema["hosted_schema_identity"],
                    "catalog_version": catalog_version,
                    "tool_version": 1,
                    "authoritative_readback_tool": readback_tool,
                    "required_normalized_error_kinds": [
                        "rate_limited",
                        "vendor_error",
                    ],
                }
            ],
            "maximum_attestation_age_hours": 168,
            "certification_candidate_validity_hours": 24,
        },
        "tool_proofs": [
            {
                "tool": tool,
                "provider": provider,
                "schema_attestation": schema,
                "route_attestation": route,
                "write_attestation": write,
                "readback_attestation": readback,
                "replay_attestation": replay,
                "conflict_attestation": conflict,
                "error_attestations": errors,
                "recovery_attestation": recovery,
            }
        ],
    }


class EvaluateProductionConnectorConformancePrimitive(
    BusinessProcessPrimitive[
        ProductionConnectorConformanceInput,
        ProductionConnectorConformanceResult,
    ]
):
    primitive_ref = "operations.evaluate_production_connector_conformance"
    version = "1.0.0"
    title = "Evaluate production connector conformance"
    description = (
        "Verify per-Tool production schema, route, approval, journal, write/readback, "
        "replay, conflict, error, and recovery attestations without connector calls "
        "or certification authority."
    )
    input_model = ProductionConnectorConformanceInput
    output_model = ProductionConnectorConformanceResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    example_inputs = _example_inputs()
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = (
            PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION.to_dict()
        )
        contract["effect_boundary"] = (
            ProductionConnectorConformanceEffectBoundary().to_dict()
        )
        contract["authority_boundary"] = {
            "sdk": "attestation_validation_and_certification_candidate_only",
            "spring": [
                "authenticated_tenant_company_project_scope",
                "tool_schema_and_effect_catalog",
                "route_and_credential_custody",
                "approval_consumption",
                "journal_provenance_persistence_and_audit",
                "production_certification_admission",
            ],
            "connector_runtime_and_provider": [
                "live_dispatch",
                "authoritative_readback",
                "provider_effect_count",
                "provider_error_and_recovery_observation",
            ],
        }
        contract["recovery_semantics"] = {
            "external_operations": 0,
            "replay_class": "safe",
            "crash_recovery": "not_required",
            "ambiguous_dispatches_observed_only": True,
        }
        contract["certification_authority"] = "spring_or_human_operator_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProductionConnectorConformanceInput,
    ) -> PrimitiveExecutionResult[ProductionConnectorConformanceResult]:
        if not _execution_scope_matches_input(context, inputs):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project UUID scope must exactly match "
                    "the production connector conformance input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[ProductionConnectorConformanceResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Production connector conformance evaluation rejected at the "
                    "trusted runtime scope boundary."
                ),
                blockers=[blocker],
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs.to_dict()),
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        output = evaluate_production_connector_conformance(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.input_digest,
            external_refs={
                "evaluation_digest": output.evaluation_digest,
                "result_digest": output.result_digest,
            },
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult[ProductionConnectorConformanceResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Production connector conformance evidence evaluated; disposition "
                f"is {output.disposition}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="operations.production_connector_conformance_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "disposition": output.disposition,
                        "tool_count": len(output.tool_results),
                        "candidate_count": len(output.certification_candidates),
                        "production_certified": False,
                        "certification_authorized": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="production_connector_conformance_evaluation",
                    summary=(
                        "Attested production connector proof was evaluated without "
                        "connector calls or certification authority."
                    ),
                    labels=[
                        output.disposition,
                        "read_only",
                        "operator_certification_required",
                    ],
                    refs={
                        "input_sha256": output.input_digest,
                        "evidence_sha256": output.evidence_digest,
                        "evaluation_sha256": output.evaluation_digest,
                        "result_sha256": output.result_digest,
                    },
                )
            ],
            evidence_refs=list(output.evidence_refs),
            operation_receipts=[receipt],
            retryable=False,
        )


PRODUCTION_CONNECTOR_CONFORMANCE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluateProductionConnectorConformancePrimitive(),)


__all__ = [
    "AMBIGUOUS_RECOVERY_ATTESTATION_SCHEMA",
    "EXACT_CONNECTOR_ROUTE_ATTESTATION_SCHEMA",
    "GOVERNED_WRITE_ATTESTATION_SCHEMA",
    "HOSTED_TOOL_SCHEMA_ATTESTATION_SCHEMA",
    "IDEMPOTENT_REPLAY_ATTESTATION_SCHEMA",
    "NORMALIZED_ERROR_ATTESTATION_SCHEMA",
    "PAYLOAD_CONFLICT_ATTESTATION_SCHEMA",
    "PRODUCTION_CONNECTOR_CONFORMANCE_EXECUTABLE_PRIMITIVES",
    "PRODUCTION_CONNECTOR_CONFORMANCE_INPUT_SCHEMA",
    "PRODUCTION_CONNECTOR_CONFORMANCE_OPERATION",
    "PRODUCTION_CONNECTOR_CONFORMANCE_RESULT_SCHEMA",
    "PROVIDER_READBACK_ATTESTATION_SCHEMA",
    "AmbiguousDispatchRecoveryAttestation",
    "ConformanceGate",
    "ConformanceGateStatus",
    "EvaluateProductionConnectorConformancePrimitive",
    "ExactConnectorRouteAttestation",
    "GovernedWriteAttestation",
    "HostedToolSchemaAttestation",
    "IdempotentReplayAttestation",
    "NormalizedConnectorErrorAttestation",
    "PayloadConflictRejectionAttestation",
    "ProductionConformanceDisposition",
    "ProductionConformanceFinding",
    "ProductionConnectorConformanceEffectBoundary",
    "ProductionConnectorConformanceInput",
    "ProductionConnectorConformancePolicy",
    "ProductionConnectorConformanceResult",
    "ProductionToolConformanceProof",
    "ProductionToolConformanceRequirement",
    "ProductionToolConformanceResult",
    "ProviderReadbackAttestation",
    "RouteIsolationObservation",
    "evaluate_production_connector_conformance",
    "production_attestation_digest",
]
