"""Evidence-bound conformance verification for governed production reads.

This module deliberately keeps read certification separate from the production
write verifier.  It consumes Spring and provider attestations only: evaluating
a packet performs no connector call, does not persist evidence, and never grants
production certification.
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
)
from lightbulb.production_connector_conformance import (
    ExactConnectorRouteAttestation,
    NormalizedConnectorErrorAttestation,
    production_attestation_digest,
)


PRODUCTION_CONNECTOR_READ_CONFORMANCE_INPUT_SCHEMA = (
    "lightbulb.production_connector_read_conformance_input.v1"
)
PRODUCTION_CONNECTOR_READ_CONFORMANCE_RESULT_SCHEMA = (
    "lightbulb.production_connector_read_conformance_result.v1"
)
HOSTED_READ_SCHEMA_ATTESTATION_SCHEMA = "lightbulb.hosted_read_schema_attestation.v1"
GOVERNED_READ_ATTESTATION_SCHEMA = "lightbulb.governed_read_attestation.v1"
PROVIDER_READ_OUTCOME_ATTESTATION_SCHEMA = (
    "lightbulb.provider_read_outcome_attestation.v1"
)
GOVERNED_OUTPUT_COMMITMENT_SCHEMA = "lightbulb.governed_connector_output_commitment.v1"
GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA = "lightbulb.governed_finance_read_result.v1"
GovernedReadCommitmentSchema = Literal[
    "lightbulb.governed_connector_output_commitment.v1",
    "lightbulb.governed_finance_read_result.v1",
]
_EXACT_FINANCE_READ_TOOLS = frozenset(
    {
        "quickbooks.get_journal_entry",
        "quickbooks.list_accounts",
    }
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ZERO_DIGEST = "0" * 64
_MAX_TOOL_PROOFS = 100
_MAX_EVIDENCE_PER_TOOL = 120
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


def _require_exact_commitment_schema(tool: str, commitment_schema: str) -> None:
    if (
        tool in _EXACT_FINANCE_READ_TOOLS
        and commitment_schema != GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA
    ):
        raise ValueError(
            "governed finance READ proof requires the finance commitment schema"
        )


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

ReadConformanceGate = Literal[
    "evidence",
    "hosted_read_schema",
    "exact_route",
    "spring_read_journal",
    "live_read_commitment",
    "error_normalization",
    "rate_limit",
]
ReadConformanceGateStatus = Literal["pass", "fail", "indeterminate"]
ProductionReadConformanceDisposition = Literal[
    "ready_for_operator_certification",
    "blocked",
    "indeterminate",
]

_GATE_ORDER: tuple[ReadConformanceGate, ...] = (
    "evidence",
    "hosted_read_schema",
    "exact_route",
    "spring_read_journal",
    "live_read_commitment",
    "error_normalization",
    "rate_limit",
)
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


def _validate_provider(tool: str, provider: str) -> None:
    if tool.split(".", 1)[0] != provider:
        raise ValueError("provider must match the Tool prefix")


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


class HostedReadSchemaAttestation(_StrictModel):
    schema_id: Literal["lightbulb.hosted_read_schema_attestation.v1"] = Field(
        default=HOSTED_READ_SCHEMA_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    hosted_schema_identity: OpaqueRef
    catalog_version: OpaqueRef
    tool_version: int = Field(ge=1, le=1_000_000)
    server_effect: Literal["read"]
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
    def _bound(self) -> "HostedReadSchemaAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="hosted_read_tool_schema",
            authority="spring",
            provider=self.provider,
        )
        return self


class GovernedReadAttestation(_StrictModel):
    schema_id: Literal["lightbulb.governed_read_attestation.v1"] = Field(
        default=GOVERNED_READ_ATTESTATION_SCHEMA,
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
    journal_status: Literal["succeeded", "failed", "ambiguous"]
    provenance: ConnectorExecutionProvenance
    provider_output_sha256: Sha256Digest
    durable_commitment_schema: GovernedReadCommitmentSchema
    durable_provider_output_sha256: Sha256Digest
    durable_record_count: int = Field(ge=0, le=1_000_000)
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
    def _read_provenance_and_evidence(self) -> "GovernedReadAttestation":
        _validate_provider(self.tool, self.provider)
        _require_exact_commitment_schema(self.tool, self.durable_commitment_schema)
        if (
            self.provenance.tool != self.tool
            or self.provenance.server_effect != ConnectorEffect.READ
            or str(self.provenance.project_id) != self.project_id
            or self.provenance.connector_account_ref != self.connector_account_ref
        ):
            raise ValueError("Spring provenance does not match the governed read scope")
        if (
            self.provenance.approval_ref is not None
            or self.provenance.approval_receipt_digest is not None
        ):
            raise ValueError(
                "governed READ provenance cannot carry write approval proof"
            )
        if _parsed_timestamp(self.provenance.completed_at) > _parsed_timestamp(
            self.observed_at
        ):
            raise ValueError("read evidence cannot be observed before completion")
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="governed_connector_read",
            authority="spring",
            provider=self.provider,
        )
        return self


class ProviderReadOutcomeAttestation(_StrictModel):
    schema_id: Literal["lightbulb.provider_read_outcome_attestation.v1"] = Field(
        default=PROVIDER_READ_OUTCOME_ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_ref: OpaqueRef
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    connector_account_ref: OpaqueRef
    provider_request_ref: OpaqueRef
    provider_output_sha256: Sha256Digest
    record_count: int = Field(ge=0, le=1_000_000)
    outcome: Literal["completed", "failed", "indeterminate"]
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
    def _bound(self) -> "ProviderReadOutcomeAttestation":
        _validate_provider(self.tool, self.provider)
        _require_bound_evidence(
            self,
            self.evidence_refs,
            expected_kind="provider_authoritative_read",
            authority="provider",
            provider=self.provider,
        )
        return self


class ProductionReadToolRequirement(_StrictModel):
    tool: ToolName
    provider: ProviderName
    hosted_schema_identity: OpaqueRef
    catalog_version: OpaqueRef
    tool_version: int = Field(ge=1, le=1_000_000)
    input_schema_sha256: Sha256Digest
    output_schema_sha256: Sha256Digest
    durable_commitment_schema: GovernedReadCommitmentSchema = (
        GOVERNED_OUTPUT_COMMITMENT_SCHEMA
    )
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
    def _provider_and_errors(self) -> "ProductionReadToolRequirement":
        _validate_provider(self.tool, self.provider)
        _require_exact_commitment_schema(self.tool, self.durable_commitment_schema)
        if len(self.required_normalized_error_kinds) != len(
            set(self.required_normalized_error_kinds)
        ):
            raise ValueError("required normalized error kinds must be unique")
        if ConnectorErrorKind.RATE_LIMITED not in self.required_normalized_error_kinds:
            raise ValueError("rate_limited must be a required normalized error kind")
        return self


class ProductionConnectorReadConformancePolicy(_StrictModel):
    requirements: tuple[ProductionReadToolRequirement, ...] = Field(
        min_length=1,
        max_length=_MAX_TOOL_PROOFS,
    )
    maximum_attestation_age_hours: int = Field(default=168, ge=1, le=8_760)
    certification_candidate_validity_hours: int = Field(default=24, ge=1, le=168)

    @field_validator("requirements", mode="before")
    @classmethod
    def _requirements_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_tools(self) -> "ProductionConnectorReadConformancePolicy":
        tools = tuple(item.tool for item in self.requirements)
        if len(tools) != len(set(tools)):
            raise ValueError("production read requirements must be unique by Tool")
        return self


class ProductionReadToolProof(_StrictModel):
    tool: ToolName
    provider: ProviderName
    schema_attestation: HostedReadSchemaAttestation
    route_attestation: ExactConnectorRouteAttestation
    read_attestation: GovernedReadAttestation
    provider_outcome_attestation: ProviderReadOutcomeAttestation
    error_attestations: tuple[NormalizedConnectorErrorAttestation, ...] = Field(
        min_length=2,
        max_length=10,
    )

    @field_validator("error_attestations", mode="before")
    @classmethod
    def _errors_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _one_tool_provider_and_account(self) -> "ProductionReadToolProof":
        _validate_provider(self.tool, self.provider)
        observed_tools = {
            self.schema_attestation.tool,
            self.route_attestation.tool,
            self.read_attestation.tool,
            self.provider_outcome_attestation.tool,
            *(item.tool for item in self.error_attestations),
        }
        observed_providers = {
            self.schema_attestation.provider,
            self.route_attestation.provider,
            self.read_attestation.provider,
            self.provider_outcome_attestation.provider,
            *(item.provider for item in self.error_attestations),
        }
        if observed_tools != {self.tool} or observed_providers != {self.provider}:
            raise ValueError("all read attestations must bind one exact Tool/provider")
        if (
            len(
                {
                    self.route_attestation.connector_account_ref,
                    self.read_attestation.connector_account_ref,
                    self.provider_outcome_attestation.connector_account_ref,
                }
            )
            != 1
        ):
            raise ValueError("route and read proof must bind one connector account")
        error_kinds = tuple(item.injected_condition for item in self.error_attestations)
        if len(error_kinds) != len(set(error_kinds)):
            raise ValueError("error attestations must be unique by injected condition")
        return self


def _proof_attestations(proof: ProductionReadToolProof) -> tuple[BaseModel, ...]:
    return (
        proof.schema_attestation,
        proof.route_attestation,
        proof.read_attestation,
        proof.provider_outcome_attestation,
        *proof.error_attestations,
    )


def _attestation_evidence(attestation: BaseModel) -> tuple[PrimitiveEvidenceRef, ...]:
    values: list[PrimitiveEvidenceRef] = []
    for field_name in (
        "evidence_refs",
        "spring_evidence_refs",
        "provider_evidence_refs",
    ):
        values.extend(getattr(attestation, field_name, ()))
    return tuple(values)


def _proof_evidence(proof: ProductionReadToolProof) -> tuple[PrimitiveEvidenceRef, ...]:
    by_ref: dict[str, PrimitiveEvidenceRef] = {}
    for attestation in _proof_attestations(proof):
        for evidence in _attestation_evidence(attestation):
            previous = by_ref.get(evidence.evidence_ref)
            if previous is not None and previous != evidence:
                raise ValueError(
                    "one evidence_ref cannot identify conflicting production read proof"
                )
            by_ref[evidence.evidence_ref] = evidence
    return tuple(by_ref[key] for key in sorted(by_ref))


def _all_input_evidence(
    inputs: "ProductionConnectorReadConformanceInput",
) -> tuple[PrimitiveEvidenceRef, ...]:
    by_ref: dict[str, PrimitiveEvidenceRef] = {}
    for proof in inputs.tool_proofs:
        for evidence in _proof_evidence(proof):
            previous = by_ref.get(evidence.evidence_ref)
            if previous is not None and previous != evidence:
                raise ValueError(
                    "one evidence_ref cannot identify conflicting production read proof"
                )
            by_ref[evidence.evidence_ref] = evidence
    return tuple(by_ref[key] for key in sorted(by_ref))


class ProductionConnectorReadConformanceInput(_StrictModel):
    schema_id: Literal["lightbulb.production_connector_read_conformance_input.v1"] = (
        Field(
            default=PRODUCTION_CONNECTOR_READ_CONFORMANCE_INPUT_SCHEMA, alias="schema"
        )
    )
    evaluation_ref: OpaqueRef
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    evaluated_at: str
    policy: ProductionConnectorReadConformancePolicy
    tool_proofs: tuple[ProductionReadToolProof, ...] = Field(
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
    def _scope_tools_and_evidence_are_exact(
        self,
    ) -> "ProductionConnectorReadConformanceInput":
        proof_tools = tuple(item.tool for item in self.tool_proofs)
        if len(proof_tools) != len(set(proof_tools)):
            raise ValueError("production read Tool proofs must be unique")
        required_tools = {item.tool for item in self.policy.requirements}
        if not set(proof_tools).issubset(required_tools):
            raise ValueError("read Tool proofs cannot exceed the declared scope")
        for proof in self.tool_proofs:
            for scoped in (proof.route_attestation, proof.read_attestation):
                if (
                    scoped.tenant_id != self.tenant_id
                    or scoped.company_id != self.company_id
                    or scoped.project_id != self.project_id
                ):
                    raise ValueError(
                        "attested tenant/company/project scope must match evaluation scope"
                    )
        if len(_all_input_evidence(self)) > _MAX_EVIDENCE:
            raise ValueError("production read conformance evidence exceeds its bound")
        return self


class ProductionReadConformanceFinding(_StrictModel):
    tool: ToolName
    provider: ProviderName
    gate: ReadConformanceGate
    status: ReadConformanceGateStatus
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


class ProductionReadToolResult(_StrictModel):
    tool: ToolName
    provider: ProviderName
    status: ReadConformanceGateStatus
    gates: tuple[ProductionReadConformanceFinding, ...] = Field(
        min_length=len(_GATE_ORDER),
        max_length=len(_GATE_ORDER),
    )
    evidence_refs: tuple[EvidenceRefId, ...] = Field(max_length=_MAX_EVIDENCE_PER_TOOL)

    @field_validator("gates", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _gate_set_and_status(self) -> "ProductionReadToolResult":
        if tuple(item.gate for item in self.gates) != _GATE_ORDER:
            raise ValueError("read Tool result must contain the exact gate order")
        expected: ReadConformanceGateStatus = (
            "fail"
            if any(item.status == "fail" for item in self.gates)
            else "indeterminate"
            if any(item.status == "indeterminate" for item in self.gates)
            else "pass"
        )
        if self.status != expected:
            raise ValueError("read Tool status must match gate statuses")
        return self


class ProductionConnectorReadConformanceEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    provider_dispatches: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    journals_mutated: Literal[0] = 0
    production_certified: Literal[False] = False
    certification_authorized: Literal[False] = False
    external_systems_changed: Literal[False] = False


PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION = PrimitiveOperationSpec(
    operation_ref="production-connector-read-conformance.evaluate",
    tool="operations.evaluate_production_connector_read_conformance",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _read_conformance_evaluation_digest(
    *,
    evaluation_ref: str,
    disposition: ProductionReadConformanceDisposition,
    tool_results: Sequence[ProductionReadToolResult],
    certification_candidates: Sequence[ConnectorConformanceCertification],
    input_digest: str,
    evidence_digest: str,
) -> str:
    return _stable_digest(
        {
            "certification_scope": "governed_read",
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


class ProductionConnectorReadConformanceResult(_StrictModel):
    schema_id: Literal["lightbulb.production_connector_read_conformance_result.v1"] = (
        Field(
            default=PRODUCTION_CONNECTOR_READ_CONFORMANCE_RESULT_SCHEMA, alias="schema"
        )
    )
    evaluation_ref: OpaqueRef
    environment: Literal["production"]
    tenant_id: UuidRef
    company_id: UuidRef
    project_id: UuidRef
    evaluated_at: str
    certification_scope: Literal["governed_read"] = "governed_read"
    disposition: ProductionReadConformanceDisposition
    assurance_grade: PrimitiveEvidenceVerificationGrade
    tool_results: tuple[ProductionReadToolResult, ...] = Field(
        min_length=1,
        max_length=_MAX_TOOL_PROOFS,
    )
    findings: tuple[ProductionReadConformanceFinding, ...] = Field(
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
    effect_boundary: ProductionConnectorReadConformanceEffectBoundary = Field(
        default_factory=ProductionConnectorReadConformanceEffectBoundary
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
    def _result_is_sound(self) -> "ProductionConnectorReadConformanceResult":
        if self.operation_spec != PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION:
            raise ValueError("operation_spec must identify the read verifier")
        statuses = {item.status for item in self.tool_results}
        expected: ProductionReadConformanceDisposition = (
            "blocked"
            if "fail" in statuses
            else "indeterminate"
            if "indeterminate" in statuses
            else "ready_for_operator_certification"
        )
        if self.disposition != expected:
            raise ValueError("disposition must match read Tool results")
        if self.disposition != "ready_for_operator_certification" and (
            self.certification_candidates
        ):
            raise ValueError("blocked or indeterminate reads cannot emit candidates")
        if (
            tuple(finding for item in self.tool_results for finding in item.gates)
            != self.findings
        ):
            raise ValueError("findings must exactly flatten read Tool gates")
        if len({item.evidence_ref for item in self.evidence_refs}) != len(
            self.evidence_refs
        ):
            raise ValueError("result evidence references must be unique")
        evidence_by_ref = {item.evidence_ref: item for item in self.evidence_refs}
        if len({item.tool for item in self.tool_results}) != len(self.tool_results):
            raise ValueError("read Tool results must be unique by Tool")
        results_by_tool = {item.tool: item for item in self.tool_results}
        expected_evidence_by_tool: dict[str, tuple[PrimitiveEvidenceRef, ...]] = {}
        for tool_result in self.tool_results:
            _validate_provider(tool_result.tool, tool_result.provider)
            if len(set(tool_result.evidence_refs)) != len(tool_result.evidence_refs):
                raise ValueError("read Tool result evidence references must be unique")
            try:
                expected_evidence_by_tool[tool_result.tool] = tuple(
                    evidence_by_ref[ref] for ref in tool_result.evidence_refs
                )
            except KeyError as exc:
                raise ValueError(
                    "read Tool result evidence must exist in result evidence"
                ) from exc
        if self.disposition == "ready_for_operator_certification" and len(
            self.certification_candidates
        ) != len(self.tool_results):
            raise ValueError("ready read results require one candidate per exact Tool")
        candidate_tools: set[str] = set()
        for candidate in self.certification_candidates:
            tool = candidate.required_tools[0]
            if tool in candidate_tools:
                raise ValueError("read certification candidates must be unique by Tool")
            candidate_tools.add(tool)
            tool_result = results_by_tool.get(tool)
            if tool_result is None or candidate.provider != tool_result.provider:
                raise ValueError("read candidate must match one exact Tool result")
            if candidate.certified_at != self.evaluated_at:
                raise ValueError(
                    "read candidate certification time must match evaluation"
                )
            if candidate.evidence_refs != expected_evidence_by_tool[tool]:
                raise ValueError(
                    "read candidate evidence must exactly match its Tool result proof"
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
                raise ValueError("read candidate flags must be derived as true")
        expected_grade = min(
            (item.verification_grade for item in self.evidence_refs),
            key=lambda grade: _GRADE_RANK[grade],
            default=PrimitiveEvidenceVerificationGrade.UNVERIFIED,
        )
        if self.assurance_grade != expected_grade:
            raise ValueError("assurance_grade must match read result evidence")
        expected_evidence_digest = _stable_digest(
            [item.to_dict() for item in self.evidence_refs]
        )
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match read result evidence")
        expected_evaluation_digest = _read_conformance_evaluation_digest(
            evaluation_ref=self.evaluation_ref,
            disposition=self.disposition,
            tool_results=self.tool_results,
            certification_candidates=self.certification_candidates,
            input_digest=self.input_digest,
            evidence_digest=self.evidence_digest,
        )
        if self.evaluation_digest != expected_evaluation_digest:
            raise ValueError("evaluation_digest does not match read result evaluation")
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
    proof: ProductionReadToolProof,
    *,
    evaluated_at: datetime,
    maximum_age_hours: int,
) -> ReadConformanceGateStatus:
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


def _finding(
    proof: ProductionReadToolProof,
    *,
    gate: ReadConformanceGate,
    status: ReadConformanceGateStatus,
    code: str,
    message: str,
    evidence_refs: Sequence[str],
) -> ProductionReadConformanceFinding:
    return ProductionReadConformanceFinding(
        tool=proof.tool,
        provider=proof.provider,
        gate=gate,
        status=status,
        code=code,
        message=message,
        evidence_refs=tuple(sorted(set(evidence_refs))),
    )


def _semantic_status(value: bool) -> ReadConformanceGateStatus:
    return "pass" if value else "fail"


def _evaluate_tool(
    requirement: ProductionReadToolRequirement,
    proof: ProductionReadToolProof,
    *,
    evaluated_at: datetime,
    maximum_age_hours: int,
) -> ProductionReadToolResult:
    schema = proof.schema_attestation
    route = proof.route_attestation
    read = proof.read_attestation
    provider = proof.provider_outcome_attestation
    evidence_status = _evidence_gate_status(
        proof,
        evaluated_at=evaluated_at,
        maximum_age_hours=maximum_age_hours,
    )
    gates = [
        _finding(
            proof,
            gate="evidence",
            status=evidence_status,
            code=f"production_read_conformance.evidence.{evidence_status}",
            message=(
                "Production read attestations are current and evidence-bound."
                if evidence_status == "pass"
                else "Production read attestations are future-dated or stale."
            ),
            evidence_refs=(item.evidence_ref for item in _proof_evidence(proof)),
        )
    ]

    schema_passed = all(
        (
            schema.server_effect == "read",
            schema.hosted_schema_identity == requirement.hosted_schema_identity,
            schema.catalog_version == requirement.catalog_version,
            schema.tool_version == requirement.tool_version,
            schema.input_schema_sha256 == requirement.input_schema_sha256,
            schema.output_schema_sha256 == requirement.output_schema_sha256,
        )
    )
    gates.append(
        _finding(
            proof,
            gate="hosted_read_schema",
            status=_semantic_status(schema_passed),
            code=(
                "production_read_conformance.schema.exact"
                if schema_passed
                else "production_read_conformance.schema.drift"
            ),
            message=(
                "Hosted READ schema identity, effect, catalog, and version match."
                if schema_passed
                else "Hosted READ schema, effect, catalog, or version drifted."
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
        _finding(
            proof,
            gate="exact_route",
            status=_semantic_status(route_passed),
            code=(
                "production_read_conformance.route.exact"
                if route_passed
                else "production_read_conformance.route.invalid"
            ),
            message=(
                "Tenant/company/project/account route and isolation probes are exact."
                if route_passed
                else "Exact route identity or isolation probes did not conform."
            ),
            evidence_refs=_evidence_refs_for(route),
        )
    )

    provenance = read.provenance
    spring_passed = all(
        (
            read.effect_catalog_version == requirement.catalog_version,
            read.journal_status == "succeeded",
            provenance.server_effect == ConnectorEffect.READ,
            provenance.tool_version == requirement.tool_version,
            str(provenance.tenant_connector_id) == route.tenant_connector_id,
            provenance.route_digest == route.route_sha256,
            provenance.approval_ref is None,
            provenance.approval_receipt_digest is None,
            provenance.receipt_digest != provenance.request_digest,
        )
    )
    gates.append(
        _finding(
            proof,
            gate="spring_read_journal",
            status=_semantic_status(spring_passed),
            code=(
                "production_read_conformance.spring_read.complete"
                if spring_passed
                else "production_read_conformance.spring_read.invalid"
            ),
            message=(
                "Spring READ journal and provenance are exact and approval-free."
                if spring_passed
                else "Spring READ journal or provenance did not conform."
            ),
            evidence_refs=_evidence_refs_for(read),
        )
    )

    commitment_passed = all(
        (
            provider.outcome == "completed",
            provider.provider_output_sha256 == read.provider_output_sha256,
            read.durable_provider_output_sha256 == read.provider_output_sha256,
            read.durable_commitment_schema == requirement.durable_commitment_schema,
            provider.record_count == read.durable_record_count,
            _parsed_timestamp(provider.observed_at)
            >= _parsed_timestamp(provenance.completed_at),
        )
    )
    gates.append(
        _finding(
            proof,
            gate="live_read_commitment",
            status=_semantic_status(commitment_passed),
            code=(
                "production_read_conformance.output.committed"
                if commitment_passed
                else "production_read_conformance.output.unverified"
            ),
            message=(
                "Provider live READ output matches Spring's minimized commitment."
                if commitment_passed
                else "Live READ outcome and durable commitment do not match."
            ),
            evidence_refs=_evidence_refs_for(read, provider),
        )
    )

    errors_by_kind = {
        item.injected_condition: item for item in proof.error_attestations
    }
    required_errors = set(requirement.required_normalized_error_kinds)
    normalized = required_errors.issubset(errors_by_kind) and all(
        item.normalized_error_kind == kind
        and item.response_status in {"failed", "blocked"}
        for kind, item in errors_by_kind.items()
        if kind in required_errors
    )
    error_refs = tuple(
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
        _finding(
            proof,
            gate="error_normalization",
            status=_semantic_status(normalized),
            code=(
                "production_read_conformance.errors.normalized"
                if normalized
                else "production_read_conformance.errors.incomplete"
            ),
            message=(
                "Required provider READ failures map to stable Connector Error Kinds."
                if normalized
                else "Required normalized provider READ errors are incomplete."
            ),
            evidence_refs=error_refs,
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
        _finding(
            proof,
            gate="rate_limit",
            status=_semantic_status(rate_limit_passed),
            code=(
                "production_read_conformance.rate_limit.normalized"
                if rate_limit_passed
                else "production_read_conformance.rate_limit.invalid"
            ),
            message=(
                "Provider HTTP 429 is normalized as retryable rate_limited."
                if rate_limit_passed
                else "READ rate-limit normalization did not conform."
            ),
            evidence_refs=(
                _evidence_refs_for(rate_limit) if rate_limit is not None else ()
            ),
        )
    )

    status: ReadConformanceGateStatus = (
        "fail"
        if any(item.status == "fail" for item in gates)
        else "indeterminate"
        if any(item.status == "indeterminate" for item in gates)
        else "pass"
    )
    return ProductionReadToolResult(
        tool=proof.tool,
        provider=proof.provider,
        status=status,
        gates=tuple(gates),
        evidence_refs=tuple(item.evidence_ref for item in _proof_evidence(proof)),
    )


def _missing_tool_result(
    requirement: ProductionReadToolRequirement,
) -> ProductionReadToolResult:
    gates = tuple(
        ProductionReadConformanceFinding(
            tool=requirement.tool,
            provider=requirement.provider,
            gate=gate,
            status="fail",
            code="production_read_conformance.proof.missing",
            message="Required production READ proof is missing.",
        )
        for gate in _GATE_ORDER
    )
    return ProductionReadToolResult(
        tool=requirement.tool,
        provider=requirement.provider,
        status="fail",
        gates=gates,
        evidence_refs=(),
    )


def evaluate_production_connector_read_conformance(
    inputs: ProductionConnectorReadConformanceInput | Mapping[str, Any],
) -> ProductionConnectorReadConformanceResult:
    """Verify supplied production READ proof without executing or certifying."""

    parsed = ProductionConnectorReadConformanceInput.model_validate(
        _detached_validation_payload(inputs)
    )
    evaluated_at = _parsed_timestamp(parsed.evaluated_at)
    proofs_by_tool = {proof.tool: proof for proof in parsed.tool_proofs}
    results = tuple(
        _missing_tool_result(requirement)
        if (proof := proofs_by_tool.get(requirement.tool)) is None
        else _evaluate_tool(
            requirement,
            proof,
            evaluated_at=evaluated_at,
            maximum_age_hours=parsed.policy.maximum_attestation_age_hours,
        )
        for requirement in sorted(
            parsed.policy.requirements, key=lambda item: item.tool
        )
    )
    statuses = {item.status for item in results}
    disposition: ProductionReadConformanceDisposition = (
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

    findings = tuple(finding for item in results for finding in item.gates)
    input_digest = _stable_digest(parsed.to_dict())
    evidence_digest = _stable_digest([item.to_dict() for item in all_evidence])
    evaluation_digest = _read_conformance_evaluation_digest(
        evaluation_ref=parsed.evaluation_ref,
        disposition=disposition,
        tool_results=results,
        certification_candidates=candidates,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
    )
    return ProductionConnectorReadConformanceResult(
        evaluation_ref=parsed.evaluation_ref,
        environment=parsed.environment,
        tenant_id=parsed.tenant_id,
        company_id=parsed.company_id,
        project_id=parsed.project_id,
        evaluated_at=parsed.evaluated_at,
        disposition=disposition,
        assurance_grade=assurance_grade,
        tool_results=results,
        findings=findings,
        certification_candidates=tuple(candidates),
        evidence_refs=all_evidence,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        evaluation_digest=evaluation_digest,
        operation_spec=PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION,
    )


def _execution_scope_matches_input(
    context: PrimitiveExecutionContext,
    inputs: ProductionConnectorReadConformanceInput,
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
        "classification": "internal",
        "retention_policy": "connector-conformance-1y",
    }


def _bind_example(
    payload: dict[str, Any],
    *,
    slug: str,
    kind: str,
    authority: Literal["spring", "provider"],
) -> None:
    issuer = (
        "spring-production-control-plane"
        if authority == "spring"
        else "quickbooks-production-api"
    )
    payload["evidence_refs"] = [
        _example_evidence(
            payload,
            evidence_ref=f"evidence-{slug}",
            kind=kind,
            issuer_ref=issuer,
            observed_at=payload["observed_at"],
        )
    ]


def _example_inputs() -> dict[str, Any]:
    observed_at = "2026-08-24T12:00:00Z"
    tenant_id = "11111111-1111-4111-8111-111111111111"
    company_id = "22222222-2222-4222-8222-222222222222"
    user_id = "33333333-3333-4333-8333-333333333333"
    project_id = "44444444-4444-4444-8444-444444444444"
    tenant_connector_id = "55555555-5555-4555-8555-555555555555"

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    schema = {
        "schema": HOSTED_READ_SCHEMA_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-list-accounts-schema",
        "tool": "quickbooks.list_accounts",
        "provider": "quickbooks",
        "environment": "production",
        "hosted_schema_identity": "quickbooks-list-accounts-v2",
        "catalog_version": "finance-governed-reads-v2",
        "tool_version": 2,
        "server_effect": "read",
        "input_schema_sha256": digest("quickbooks.list_accounts:input:v2"),
        "output_schema_sha256": digest("quickbooks.list_accounts:output:v2"),
        "observed_at": observed_at,
    }
    _bind_example(
        schema,
        slug="qbo-list-accounts-schema",
        kind="hosted_read_tool_schema",
        authority="spring",
    )

    route = {
        "schema": "lightbulb.exact_connector_route_attestation.v1",
        "attestation_ref": "attestation-qbo-list-accounts-route",
        "tool": "quickbooks.list_accounts",
        "provider": "quickbooks",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "connector_account_ref": "finance-primary",
        "target_resource_ref": "realm-913034",
        "project_connector_binding_id": "66666666-6666-4666-8666-666666666666",
        "tenant_tool_binding_id": "77777777-7777-4777-8777-777777777777",
        "tenant_connector_id": tenant_connector_id,
        "connector_id": "88888888-8888-4888-8888-888888888888",
        "adapter_identity": "quickbooks-adapter-v1",
        "handler_identity": "quickbooks-list-accounts-handler-v2",
        "tool_version": 2,
        "target_sha256": digest("realm-913034"),
        "route_sha256": digest("tenant/company/project/finance-primary/realm-913034"),
        "isolation_observations": [
            {
                "attempted_scope": scope,
                "response_status": "denied",
                "error_code": f"{scope}-scope-denied",
                "provider_dispatch_count": 0,
            }
            for scope in ("tenant", "company", "project", "account")
        ],
        "observed_at": observed_at,
    }
    _bind_example(
        route,
        slug="qbo-list-accounts-route",
        kind="exact_connector_route",
        authority="spring",
    )

    provider_output_sha256 = digest("canonical-live-qbo-account-output")
    governed_read = {
        "schema": GOVERNED_READ_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-list-accounts-read",
        "tool": "quickbooks.list_accounts",
        "provider": "quickbooks",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "user_id": user_id,
        "project_id": project_id,
        "connector_account_ref": "finance-primary",
        "effect_catalog_version": "finance-governed-reads-v2",
        "journal_status": "succeeded",
        "provenance": {
            "schema": "lightbulb.connector_execution_provenance.v1",
            "tool": "quickbooks.list_accounts",
            "tool_version": 2,
            "server_effect": "read",
            "connector_account_ref": "finance-primary",
            "tenant_connector_id": tenant_connector_id,
            "project_id": project_id,
            "route_digest": route["route_sha256"],
            "journal_ref": "journal-qbo-list-accounts",
            "request_digest": digest("qbo-list-accounts-canonical-request"),
            "receipt_digest": digest("qbo-list-accounts-spring-receipt"),
            "completed_at": observed_at,
        },
        "provider_output_sha256": provider_output_sha256,
        "durable_commitment_schema": GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA,
        "durable_provider_output_sha256": provider_output_sha256,
        "durable_record_count": 2,
        "observed_at": observed_at,
    }
    _bind_example(
        governed_read,
        slug="qbo-list-accounts-read",
        kind="governed_connector_read",
        authority="spring",
    )

    provider_outcome = {
        "schema": PROVIDER_READ_OUTCOME_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-list-accounts-provider",
        "tool": "quickbooks.list_accounts",
        "provider": "quickbooks",
        "environment": "production",
        "connector_account_ref": "finance-primary",
        "provider_request_ref": "quickbooks-request-913034-20260824",
        "provider_output_sha256": provider_output_sha256,
        "record_count": 2,
        "outcome": "completed",
        "observed_at": observed_at,
    }
    _bind_example(
        provider_outcome,
        slug="qbo-list-accounts-provider",
        kind="provider_authoritative_read",
        authority="provider",
    )

    errors: list[dict[str, Any]] = []
    for index, (kind, status, retry) in enumerate(
        (
            ("rate_limited", 429, "retryable"),
            ("auth_error", 401, "blocked"),
        ),
        start=1,
    ):
        error = {
            "schema": "lightbulb.normalized_connector_error_attestation.v1",
            "attestation_ref": f"attestation-qbo-list-accounts-error-{kind}",
            "tool": "quickbooks.list_accounts",
            "provider": "quickbooks",
            "environment": "production",
            "injected_condition": kind,
            "provider_status_code": status,
            "provider_error_sha256": digest(f"quickbooks-error-{kind}"),
            "normalized_error_kind": kind,
            "normalized_error_code": f"QUICKBOOKS_ERROR_{index}",
            "response_status": "failed",
            "retry_disposition": retry,
            "observed_at": observed_at,
        }
        error["spring_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=f"evidence-qbo-list-accounts-error-{kind}-spring",
                kind="spring_connector_error_normalization",
                issuer_ref="spring-production-control-plane",
                observed_at=observed_at,
            )
        ]
        error["provider_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=f"evidence-qbo-list-accounts-error-{kind}-provider",
                kind="provider_connector_error",
                issuer_ref="quickbooks-production-api",
                observed_at=observed_at,
            )
        ]
        errors.append(error)

    journal_schema = {
        "schema": HOSTED_READ_SCHEMA_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-get-journal-entry-schema",
        "tool": "quickbooks.get_journal_entry",
        "provider": "quickbooks",
        "environment": "production",
        "hosted_schema_identity": "quickbooks-get-journal-entry-v1",
        "catalog_version": "finance-governed-reads-v2",
        "tool_version": 1,
        "server_effect": "read",
        "input_schema_sha256": digest("quickbooks.get_journal_entry:input:v1"),
        "output_schema_sha256": digest("quickbooks.get_journal_entry:output:v1"),
        "observed_at": observed_at,
    }
    _bind_example(
        journal_schema,
        slug="qbo-get-journal-entry-schema",
        kind="hosted_read_tool_schema",
        authority="spring",
    )

    journal_route = {
        "schema": "lightbulb.exact_connector_route_attestation.v1",
        "attestation_ref": "attestation-qbo-get-journal-entry-route",
        "tool": "quickbooks.get_journal_entry",
        "provider": "quickbooks",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "connector_account_ref": "finance-primary",
        "target_resource_ref": "realm-913034",
        "project_connector_binding_id": "66666666-6666-4666-8666-666666666666",
        "tenant_tool_binding_id": "77777777-7777-4777-8777-777777777777",
        "tenant_connector_id": tenant_connector_id,
        "connector_id": "88888888-8888-4888-8888-888888888888",
        "adapter_identity": "quickbooks-adapter-v1",
        "handler_identity": "quickbooks-get-journal-entry-handler-v1",
        "tool_version": 1,
        "target_sha256": digest("realm-913034"),
        "route_sha256": digest("tenant/company/project/finance-primary/realm-913034"),
        "isolation_observations": [
            {
                "attempted_scope": scope,
                "response_status": "denied",
                "error_code": f"{scope}-scope-denied",
                "provider_dispatch_count": 0,
            }
            for scope in ("tenant", "company", "project", "account")
        ],
        "observed_at": observed_at,
    }
    _bind_example(
        journal_route,
        slug="qbo-get-journal-entry-route",
        kind="exact_connector_route",
        authority="spring",
    )

    journal_provider_output_sha256 = digest("canonical-live-qbo-journal-entry-output")
    journal_read = {
        "schema": GOVERNED_READ_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-get-journal-entry-read",
        "tool": "quickbooks.get_journal_entry",
        "provider": "quickbooks",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "user_id": user_id,
        "project_id": project_id,
        "connector_account_ref": "finance-primary",
        "effect_catalog_version": "finance-governed-reads-v2",
        "journal_status": "succeeded",
        "provenance": {
            "schema": "lightbulb.connector_execution_provenance.v1",
            "tool": "quickbooks.get_journal_entry",
            "tool_version": 1,
            "server_effect": "read",
            "connector_account_ref": "finance-primary",
            "tenant_connector_id": tenant_connector_id,
            "project_id": project_id,
            "route_digest": journal_route["route_sha256"],
            "journal_ref": "journal-qbo-get-journal-entry",
            "request_digest": digest("qbo-get-journal-entry-canonical-request"),
            "receipt_digest": digest("qbo-get-journal-entry-spring-receipt"),
            "completed_at": observed_at,
        },
        "provider_output_sha256": journal_provider_output_sha256,
        "durable_commitment_schema": GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA,
        "durable_provider_output_sha256": journal_provider_output_sha256,
        "durable_record_count": 2,
        "observed_at": observed_at,
    }
    _bind_example(
        journal_read,
        slug="qbo-get-journal-entry-read",
        kind="governed_connector_read",
        authority="spring",
    )

    journal_provider_outcome = {
        "schema": PROVIDER_READ_OUTCOME_ATTESTATION_SCHEMA,
        "attestation_ref": "attestation-qbo-get-journal-entry-provider",
        "tool": "quickbooks.get_journal_entry",
        "provider": "quickbooks",
        "environment": "production",
        "connector_account_ref": "finance-primary",
        "provider_request_ref": "quickbooks-request-journal-913034-20260824",
        "provider_output_sha256": journal_provider_output_sha256,
        "record_count": 2,
        "outcome": "completed",
        "observed_at": observed_at,
    }
    _bind_example(
        journal_provider_outcome,
        slug="qbo-get-journal-entry-provider",
        kind="provider_authoritative_read",
        authority="provider",
    )

    journal_errors: list[dict[str, Any]] = []
    for index, (kind, status, retry) in enumerate(
        (
            ("rate_limited", 429, "retryable"),
            ("auth_error", 401, "blocked"),
        ),
        start=1,
    ):
        error = {
            "schema": "lightbulb.normalized_connector_error_attestation.v1",
            "attestation_ref": f"attestation-qbo-get-journal-entry-error-{kind}",
            "tool": "quickbooks.get_journal_entry",
            "provider": "quickbooks",
            "environment": "production",
            "injected_condition": kind,
            "provider_status_code": status,
            "provider_error_sha256": digest(f"quickbooks-journal-error-{kind}"),
            "normalized_error_kind": kind,
            "normalized_error_code": f"QUICKBOOKS_JOURNAL_ERROR_{index}",
            "response_status": "failed",
            "retry_disposition": retry,
            "observed_at": observed_at,
        }
        error["spring_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=(f"evidence-qbo-get-journal-entry-error-{kind}-spring"),
                kind="spring_connector_error_normalization",
                issuer_ref="spring-production-control-plane",
                observed_at=observed_at,
            )
        ]
        error["provider_evidence_refs"] = [
            _example_evidence(
                error,
                evidence_ref=(f"evidence-qbo-get-journal-entry-error-{kind}-provider"),
                kind="provider_connector_error",
                issuer_ref="quickbooks-production-api",
                observed_at=observed_at,
            )
        ]
        journal_errors.append(error)

    return {
        "schema": PRODUCTION_CONNECTOR_READ_CONFORMANCE_INPUT_SCHEMA,
        "evaluation_ref": "qbo-list-accounts-production-read-review",
        "environment": "production",
        "tenant_id": tenant_id,
        "company_id": company_id,
        "project_id": project_id,
        "evaluated_at": "2026-08-24T13:00:00Z",
        "policy": {
            "requirements": [
                {
                    "tool": "quickbooks.get_journal_entry",
                    "provider": "quickbooks",
                    "hosted_schema_identity": "quickbooks-get-journal-entry-v1",
                    "catalog_version": "finance-governed-reads-v2",
                    "tool_version": 1,
                    "input_schema_sha256": journal_schema["input_schema_sha256"],
                    "output_schema_sha256": journal_schema["output_schema_sha256"],
                    "durable_commitment_schema": GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA,
                    "required_normalized_error_kinds": [
                        "rate_limited",
                        "auth_error",
                    ],
                },
                {
                    "tool": "quickbooks.list_accounts",
                    "provider": "quickbooks",
                    "hosted_schema_identity": "quickbooks-list-accounts-v2",
                    "catalog_version": "finance-governed-reads-v2",
                    "tool_version": 2,
                    "input_schema_sha256": schema["input_schema_sha256"],
                    "output_schema_sha256": schema["output_schema_sha256"],
                    "durable_commitment_schema": GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA,
                    "required_normalized_error_kinds": [
                        "rate_limited",
                        "auth_error",
                    ],
                },
            ],
            "maximum_attestation_age_hours": 168,
            "certification_candidate_validity_hours": 24,
        },
        "tool_proofs": [
            {
                "tool": "quickbooks.get_journal_entry",
                "provider": "quickbooks",
                "schema_attestation": journal_schema,
                "route_attestation": journal_route,
                "read_attestation": journal_read,
                "provider_outcome_attestation": journal_provider_outcome,
                "error_attestations": journal_errors,
            },
            {
                "tool": "quickbooks.list_accounts",
                "provider": "quickbooks",
                "schema_attestation": schema,
                "route_attestation": route,
                "read_attestation": governed_read,
                "provider_outcome_attestation": provider_outcome,
                "error_attestations": errors,
            },
        ],
    }


class EvaluateProductionConnectorReadConformancePrimitive(
    BusinessProcessPrimitive[
        ProductionConnectorReadConformanceInput,
        ProductionConnectorReadConformanceResult,
    ]
):
    primitive_ref = "operations.evaluate_production_connector_read_conformance"
    version = "1.0.0"
    title = "Evaluate production connector READ conformance"
    description = (
        "Verify per-Tool production READ schema, exact route, Spring provenance, "
        "live provider output commitment, and normalized errors without connector "
        "calls or certification authority."
    )
    input_model = ProductionConnectorReadConformanceInput
    output_model = ProductionConnectorReadConformanceResult
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
            PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION.to_dict()
        )
        contract["effect_boundary"] = (
            ProductionConnectorReadConformanceEffectBoundary().to_dict()
        )
        contract["authority_boundary"] = {
            "sdk": "attestation_validation_and_read_candidate_only",
            "spring": [
                "authenticated_tenant_company_project_scope",
                "reviewed_read_schema_and_effect_catalog",
                "route_and_credential_custody",
                "read_journal_provenance_and_durable_commitment",
                "production_read_certification_admission",
            ],
            "provider": [
                "live_read_output_observation",
                "provider_error_observation",
            ],
        }
        contract["read_write_separation"] = {
            "write_attestations_accepted": False,
            "write_replay_or_approval_inferred": False,
            "write_catalog_certification_inherited": False,
        }
        contract["recovery_semantics"] = {
            "external_operations": 0,
            "replay_class": "safe",
            "crash_recovery": "not_required",
        }
        contract["certification_authority"] = "spring_or_human_operator_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ProductionConnectorReadConformanceInput,
    ) -> PrimitiveExecutionResult[ProductionConnectorReadConformanceResult]:
        if not _execution_scope_matches_input(context, inputs):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project UUID scope must exactly match "
                    "the production connector READ conformance input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[ProductionConnectorReadConformanceResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Production connector READ conformance evaluation rejected at "
                    "the trusted runtime scope boundary."
                ),
                blockers=[blocker],
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs.to_dict()),
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        output = evaluate_production_connector_read_conformance(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.input_digest,
            external_refs={
                "evaluation_digest": output.evaluation_digest,
                "result_digest": output.result_digest,
            },
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult[ProductionConnectorReadConformanceResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Production connector READ evidence evaluated; disposition is "
                f"{output.disposition}."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="operations.production_connector_read_conformance_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "disposition": output.disposition,
                        "tool_count": len(output.tool_results),
                        "candidate_count": len(output.certification_candidates),
                        "certification_scope": "governed_read",
                        "production_certified": False,
                        "certification_authorized": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="production_connector_read_conformance_evaluation",
                    summary=(
                        "Attested production READ proof was evaluated without "
                        "connector calls or certification authority."
                    ),
                    labels=[
                        output.disposition,
                        "governed_read",
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


PRODUCTION_CONNECTOR_READ_CONFORMANCE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluateProductionConnectorReadConformancePrimitive(),)


__all__ = [
    "GOVERNED_FINANCE_READ_COMMITMENT_SCHEMA",
    "GOVERNED_OUTPUT_COMMITMENT_SCHEMA",
    "GOVERNED_READ_ATTESTATION_SCHEMA",
    "HOSTED_READ_SCHEMA_ATTESTATION_SCHEMA",
    "PRODUCTION_CONNECTOR_READ_CONFORMANCE_EXECUTABLE_PRIMITIVES",
    "PRODUCTION_CONNECTOR_READ_CONFORMANCE_INPUT_SCHEMA",
    "PRODUCTION_CONNECTOR_READ_CONFORMANCE_OPERATION",
    "PRODUCTION_CONNECTOR_READ_CONFORMANCE_RESULT_SCHEMA",
    "PROVIDER_READ_OUTCOME_ATTESTATION_SCHEMA",
    "EvaluateProductionConnectorReadConformancePrimitive",
    "GovernedReadAttestation",
    "HostedReadSchemaAttestation",
    "ProductionConnectorReadConformanceEffectBoundary",
    "ProductionConnectorReadConformanceInput",
    "ProductionConnectorReadConformancePolicy",
    "ProductionConnectorReadConformanceResult",
    "ProductionReadConformanceDisposition",
    "ProductionReadConformanceFinding",
    "ProductionReadToolProof",
    "ProductionReadToolRequirement",
    "ProductionReadToolResult",
    "ProviderReadOutcomeAttestation",
    "ReadConformanceGate",
    "ReadConformanceGateStatus",
    "evaluate_production_connector_read_conformance",
]
