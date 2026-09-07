"""Evidence-bound production execution readiness evaluation.

This module turns operational claims into typed, expiring evidence gates.  It
does not certify a deployment by itself: Spring or an operator must supply the
production attestations, and the result can only propose readiness for human
certification.  No connector, deployment, incident, or business-system effect
is performed here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
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
)


OPERATIONAL_READINESS_INPUT_SCHEMA = "lightbulb.operational_readiness_input.v1"
OPERATIONAL_READINESS_RESULT_SCHEMA = "lightbulb.operational_readiness_result.v1"
_MAX_CONNECTOR_CERTIFICATION_EVIDENCE = 165
_MAX_CONNECTOR_CERTIFICATIONS = 1_000

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$",
    ),
]
ToolName = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9_-]{0,63}(?:\.[a-z0-9][a-z0-9_-]{0,63})+$",
    ),
]
ProviderName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
SloRef = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,119}$")]

ReadinessGate = Literal[
    "hosted_writes",
    "bounded_loops",
    "publication_recovery",
    "connector_conformance",
    "transport_recovery",
    "replay_guarantees",
    "service_levels",
    "incident_response",
    "business_outcomes",
]
ReadinessGateStatus = Literal["pass", "fail", "indeterminate"]
ReadinessDisposition = Literal[
    "ready_for_operator_certification", "blocked", "indeterminate"
]
Channel = Literal["email", "sms", "voice", "whatsapp"]
Comparison = Literal["at_least", "at_most"]
MetricUnit = Literal["percent", "milliseconds", "seconds", "minutes", "count"]
OutcomeDirection = Literal["increase", "decrease"]

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
        return value.model_dump(mode="python", by_alias=True, exclude_none=True)
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


def _number(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("metric values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError("metric values must use bounded notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("metric values must be finite decimals") from exc
    if not parsed.is_finite() or abs(parsed) > Decimal("1e24"):
        raise ValueError("metric values must be bounded finite decimals")
    return parsed


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique(values: tuple[Any, ...], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


class HostedWriteCertification(_StrictModel):
    tool: ToolName
    provider: ProviderName
    environment: Literal["production"]
    catalog_version: OpaqueRef
    certified_at: str
    expires_at: str
    exact_project_account_route_verified: bool
    spring_approval_verified: bool
    durable_idempotency_verified: bool
    ambiguous_outcome_recovery_verified: bool
    native_adapter_dispatch_verified: bool
    live_write_readback_verified: bool
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _chronology_and_provider_are_exact(self) -> "HostedWriteCertification":
        if self.certified_at >= self.expires_at:
            raise ValueError(
                "hosted-write certification must expire after certification"
            )
        if self.tool.split(".", 1)[0] != self.provider:
            raise ValueError("hosted-write provider must match tool prefix")
        return self


class BoundedLoopCertification(_StrictModel):
    compiler_contract_version: OpaqueRef
    runtime_contract_version: OpaqueRef
    loop_workflow_count: int = Field(ge=0, le=1_000_000)
    bounded_workflow_count: int = Field(ge=0, le=1_000_000)
    durable_iteration_state_verified: bool
    exhaustion_fails_closed: bool
    crash_resume_preserves_budget: bool
    certified_at: str
    expires_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _counts_and_chronology(self) -> "BoundedLoopCertification":
        if self.bounded_workflow_count > self.loop_workflow_count:
            raise ValueError("bounded workflow count cannot exceed loop workflow count")
        if self.certified_at >= self.expires_at:
            raise ValueError("loop certification must expire after certification")
        return self


class WorkflowPublicationRecoveryCertification(_StrictModel):
    """Crash-recovery proof for Spring-owned workflow publication boundaries."""

    environment: Literal["production"]
    outbox_contract_version: OpaqueRef
    authorized_spring_step_lane_count: int = Field(ge=1, le=10_000)
    outboxed_spring_step_lane_count: int = Field(ge=0, le=10_000)
    workflow_requests_transactional: bool
    step_requests_transactional: bool
    hitl_requests_transactional: bool
    hitl_decisions_transactional: bool
    encrypted_payload_custody_verified: bool
    relay_scope_generation_fencing_verified: bool
    relay_actor_authority_recheck_verified: bool
    consumer_duplicate_suppression_verified: bool
    recoverable_failures_retained: bool
    corrupt_rows_parked_and_alerted: bool
    unsupported_worker_publications_disabled: bool
    unsupported_principals_fail_closed: bool
    direct_event_dlq_recovery_procedure_verified: bool
    crash_points_tested: int = Field(ge=1, le=1_000)
    certified_at: str
    expires_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=30)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _coverage_and_chronology(self) -> "WorkflowPublicationRecoveryCertification":
        if (
            self.outboxed_spring_step_lane_count
            > self.authorized_spring_step_lane_count
        ):
            raise ValueError(
                "outboxed Spring step lanes cannot exceed authorized Spring step lanes"
            )
        if self.certified_at >= self.expires_at:
            raise ValueError(
                "workflow-publication certification must expire after certification"
            )
        return self


class ConnectorConformanceCertification(_StrictModel):
    provider: ProviderName
    environment: Literal["production"]
    required_tools: tuple[ToolName, ...] = Field(min_length=1, max_length=1)
    certified_tools: tuple[ToolName, ...] = Field(min_length=1, max_length=1)
    tenant_isolation_verified: bool
    project_account_binding_verified: bool
    schema_drift_check_passed: bool
    error_normalization_verified: bool
    rate_limit_behavior_verified: bool
    certified_at: str
    expires_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_CONNECTOR_CERTIFICATION_EVIDENCE,
    )

    @field_validator(
        "required_tools", "certified_tools", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _tool_scope_and_chronology(self) -> "ConnectorConformanceCertification":
        _unique(self.required_tools, label="required connector tools")
        _unique(self.certified_tools, label="certified connector tools")
        if any(tool.split(".", 1)[0] != self.provider for tool in self.required_tools):
            raise ValueError("required connector tools must match provider")
        if any(tool.split(".", 1)[0] != self.provider for tool in self.certified_tools):
            raise ValueError("certified connector tools must match provider")
        if set(self.required_tools) != set(self.certified_tools):
            raise ValueError(
                "connector certification must certify its exact required tool scope"
            )
        if self.certified_at >= self.expires_at:
            raise ValueError("connector certification must expire after certification")
        return self


class TransportRecoveryCertification(_StrictModel):
    channel: Channel
    provider: ProviderName
    environment: Literal["production"]
    materializer_authoritative: bool
    observer_authoritative: bool
    consent_and_suppression_verified: bool
    cross_channel_identity_verified: bool
    delivery_outcome_normalized: bool
    crash_recovery_verified: bool
    duplicate_effect_suppression_verified: bool
    certified_at: str
    expires_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=30)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _chronology(self) -> "TransportRecoveryCertification":
        if self.certified_at >= self.expires_at:
            raise ValueError("transport certification must expire after certification")
        return self


class ReplayGuaranteeCertification(_StrictModel):
    operation_class_ref: OpaqueRef
    guarantee: Literal[
        "safe_replay",
        "idempotent_effect",
        "status_probe_before_replay",
        "manual_reconciliation_no_replay",
    ]
    durable_request_digest_verified: bool
    recovery_attestation_verified: bool
    ambiguous_effect_auto_retry_blocked: bool
    crash_points_tested: int = Field(ge=1, le=1_000)
    certified_at: str
    expires_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=30)

    @field_validator("certified_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _chronology(self) -> "ReplayGuaranteeCertification":
        if self.certified_at >= self.expires_at:
            raise ValueError("replay certification must expire after certification")
        return self


class ServiceLevelMeasurement(_StrictModel):
    slo_ref: SloRef
    indicator: Literal[
        "availability",
        "successful_execution",
        "latency",
        "recovery_time",
        "delivery_outcome_observed",
        "duplicate_effect_rate",
    ]
    comparison: Comparison
    unit: MetricUnit
    target: Decimal
    observed: Decimal
    sample_count: int = Field(ge=1, le=1_000_000_000)
    window_started_at: str
    window_ended_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("target", "observed", mode="before")
    @classmethod
    def _metrics(cls, value: Any) -> Decimal:
        return _number(value)

    @field_validator("window_started_at", "window_ended_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _window_and_units(self) -> "ServiceLevelMeasurement":
        if self.window_started_at >= self.window_ended_at:
            raise ValueError("SLO measurement window must be ordered")
        if self.unit == "percent" and not (
            Decimal("0") <= self.target <= Decimal("100")
            and Decimal("0") <= self.observed <= Decimal("100")
        ):
            raise ValueError("percent SLO values must be between zero and 100")
        return self


class IncidentProcedureCertification(_StrictModel):
    runbook_ref: OpaqueRef
    runbook_version: OpaqueRef
    on_call_owner_ref: OpaqueRef
    severity_levels: tuple[Literal["sev1", "sev2", "sev3", "sev4"], ...] = Field(
        min_length=1, max_length=4
    )
    provider_escalation_paths_verified: bool
    customer_communication_path_verified: bool
    ambiguous_effect_procedure_verified: bool
    replay_and_reconciliation_procedure_verified: bool
    last_exercised_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=30)

    @field_validator("severity_levels", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("last_exercised_at")
    @classmethod
    def _exercise_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="last_exercised_at")

    @model_validator(mode="after")
    def _severity_levels_are_unique(self) -> "IncidentProcedureCertification":
        _unique(self.severity_levels, label="incident severity levels")
        return self


class BusinessOutcomeMeasurement(_StrictModel):
    outcome_ref: OpaqueRef
    metric_name: OpaqueRef
    direction: OutcomeDirection
    unit: MetricUnit
    baseline: Decimal
    observed: Decimal
    target: Decimal
    sample_count: int = Field(ge=1, le=1_000_000_000)
    measured_at: str
    source_system_ref: OpaqueRef
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("baseline", "observed", "target", mode="before")
    @classmethod
    def _metrics(cls, value: Any) -> Decimal:
        return _number(value)

    @field_validator("measured_at")
    @classmethod
    def _measurement_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="measured_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class OperationalReadinessPolicy(_StrictModel):
    required_hosted_write_tools: tuple[ToolName, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    required_connector_providers: tuple[ProviderName, ...] = Field(
        default_factory=tuple, max_length=100
    )
    required_connector_tools: tuple[ToolName, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    required_channels: tuple[Channel, ...] = Field(default_factory=tuple, max_length=4)
    required_replay_classes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    required_slos: tuple[SloRef, ...] = Field(default_factory=tuple, max_length=100)
    required_business_outcomes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    maximum_incident_exercise_age_hours: int = Field(default=2_160, ge=1, le=17_520)
    maximum_business_measurement_age_hours: int = Field(default=744, ge=1, le=8_760)
    minimum_slo_sample_count: int = Field(default=100, ge=1, le=1_000_000_000)

    @field_validator(
        "required_hosted_write_tools",
        "required_connector_providers",
        "required_connector_tools",
        "required_channels",
        "required_replay_classes",
        "required_slos",
        "required_business_outcomes",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _minimum_evidence_grade(cls, value: Any) -> Any:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        if isinstance(value, str):
            try:
                return PrimitiveEvidenceVerificationGrade(value)
            except ValueError:
                return value
        return value

    @model_validator(mode="after")
    def _requirements_are_unique(self) -> "OperationalReadinessPolicy":
        for label, values in (
            ("required hosted-write tools", self.required_hosted_write_tools),
            ("required connector providers", self.required_connector_providers),
            ("required connector tools", self.required_connector_tools),
            ("required channels", self.required_channels),
            ("required replay classes", self.required_replay_classes),
            ("required SLOs", self.required_slos),
            ("required business outcomes", self.required_business_outcomes),
        ):
            if not values:
                raise ValueError(f"{label} must contain at least one requirement")
            _unique(values, label=label)
        required_providers = set(self.required_connector_providers)
        tool_providers = {
            tool.split(".", 1)[0] for tool in self.required_connector_tools
        }
        if not tool_providers.issubset(required_providers):
            raise ValueError(
                "required connector tools must match a required connector provider"
            )
        if tool_providers != required_providers:
            raise ValueError(
                "every required connector provider must declare a required connector tool"
            )
        if (
            _GRADE_RANK[self.minimum_evidence_grade]
            < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
        ):
            raise ValueError(
                "minimum_evidence_grade must be attested or independently verified"
            )
        return self


class OperationalReadinessInput(_StrictModel):
    schema_id: Literal["lightbulb.operational_readiness_input.v1"] = Field(
        default=OPERATIONAL_READINESS_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    environment_ref: OpaqueRef
    evaluated_at: str
    policy: OperationalReadinessPolicy
    hosted_writes: tuple[HostedWriteCertification, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    bounded_loops: BoundedLoopCertification
    publication_recovery: WorkflowPublicationRecoveryCertification | None = None
    connector_conformance: tuple[ConnectorConformanceCertification, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_CONNECTOR_CERTIFICATIONS,
    )
    transports: tuple[TransportRecoveryCertification, ...] = Field(
        default_factory=tuple, max_length=100
    )
    replay_guarantees: tuple[ReplayGuaranteeCertification, ...] = Field(
        default_factory=tuple, max_length=100
    )
    service_levels: tuple[ServiceLevelMeasurement, ...] = Field(
        default_factory=tuple, max_length=100
    )
    incident_procedure: IncidentProcedureCertification
    business_outcomes: tuple[BusinessOutcomeMeasurement, ...] = Field(
        default_factory=tuple, max_length=100
    )

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator(
        "hosted_writes",
        "connector_conformance",
        "transports",
        "replay_guarantees",
        "service_levels",
        "business_outcomes",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _certification_keys_are_unique(self) -> "OperationalReadinessInput":
        for label, values in (
            ("hosted-write tools", tuple(item.tool for item in self.hosted_writes)),
            ("transport channels", tuple(item.channel for item in self.transports)),
            (
                "replay operation classes",
                tuple(item.operation_class_ref for item in self.replay_guarantees),
            ),
            ("SLO references", tuple(item.slo_ref for item in self.service_levels)),
            (
                "business outcome references",
                tuple(item.outcome_ref for item in self.business_outcomes),
            ),
        ):
            _unique(values, label=label)
        connector_tool_claims = tuple(
            (item.provider, tool)
            for item in self.connector_conformance
            for tool in item.required_tools
        )
        _unique(
            connector_tool_claims,
            label="connector conformance provider/tool claims",
        )
        return self


class OperationalReadinessFinding(_StrictModel):
    gate: ReadinessGate
    code: SloRef
    status: ReadinessGateStatus
    message: str = Field(min_length=1, max_length=500)
    affected_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("affected_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


def _readiness_evaluation_digest(
    *,
    evaluation_ref: str,
    environment_ref: str,
    evaluated_at: str,
    disposition: ReadinessDisposition,
    findings: tuple[OperationalReadinessFinding, ...],
    passed_count: int,
    failed_count: int,
    indeterminate_count: int,
    input_digest: str,
    evidence_digest: str,
) -> str:
    return _stable_digest(
        {
            "schema": OPERATIONAL_READINESS_RESULT_SCHEMA,
            "evaluation_ref": evaluation_ref,
            "environment_ref": environment_ref,
            "evaluated_at": evaluated_at,
            "disposition": disposition,
            "findings": [item.to_dict() for item in findings],
            "passed_count": passed_count,
            "failed_count": failed_count,
            "indeterminate_count": indeterminate_count,
            "input_digest": input_digest,
            "evidence_digest": evidence_digest,
            "production_certified": False,
            "deployment_authorized": False,
            "incident_closed": False,
        }
    )


class OperationalReadinessResult(_StrictModel):
    schema_id: Literal["lightbulb.operational_readiness_result.v1"] = Field(
        default=OPERATIONAL_READINESS_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    environment_ref: OpaqueRef
    evaluated_at: str
    disposition: ReadinessDisposition
    findings: tuple[OperationalReadinessFinding, ...]
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    indeterminate_count: int = Field(ge=0)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_spec: PrimitiveOperationSpec
    production_certified: Literal[False] = False
    deployment_authorized: Literal[False] = False
    incident_closed: Literal[False] = False

    @field_validator("evaluated_at")
    @classmethod
    def _evaluation_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator("findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _counts_and_operation_are_exact(self) -> "OperationalReadinessResult":
        actual = {
            status: sum(finding.status == status for finding in self.findings)
            for status in ("pass", "fail", "indeterminate")
        }
        expected = {
            "pass": self.passed_count,
            "fail": self.failed_count,
            "indeterminate": self.indeterminate_count,
        }
        if actual != expected:
            raise ValueError("finding counts must match findings")
        expected_disposition: ReadinessDisposition = (
            "blocked"
            if self.failed_count
            else "indeterminate"
            if self.indeterminate_count
            else "ready_for_operator_certification"
        )
        if self.disposition != expected_disposition:
            raise ValueError("readiness disposition must match exact finding counts")
        if self.operation_spec != OPERATIONAL_READINESS_OPERATION:
            raise ValueError("operation_spec must identify this evaluator")
        evidence_refs = tuple(item.evidence_ref for item in self.evidence_refs)
        _unique(evidence_refs, label="result evidence references")
        if evidence_refs != tuple(sorted(evidence_refs)):
            raise ValueError("result evidence references must use canonical order")
        expected_evidence_digest = _stable_digest(
            [evidence.to_dict() for evidence in self.evidence_refs]
        )
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest must match exact retained evidence")
        expected_evaluation_digest = _readiness_evaluation_digest(
            evaluation_ref=self.evaluation_ref,
            environment_ref=self.environment_ref,
            evaluated_at=self.evaluated_at,
            disposition=self.disposition,
            findings=self.findings,
            passed_count=self.passed_count,
            failed_count=self.failed_count,
            indeterminate_count=self.indeterminate_count,
            input_digest=self.input_digest,
            evidence_digest=self.evidence_digest,
        )
        if self.evaluation_digest != expected_evaluation_digest:
            raise ValueError("evaluation_digest must match exact readiness result")
        return self


OPERATIONAL_READINESS_OPERATION = PrimitiveOperationSpec(
    operation_ref="production-execution-readiness.evaluate",
    tool="operations.evaluate_production_execution_readiness",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _all_evidence(
    inputs: OperationalReadinessInput,
) -> tuple[PrimitiveEvidenceRef, ...]:
    groups: list[tuple[PrimitiveEvidenceRef, ...]] = [
        inputs.bounded_loops.evidence_refs,
        inputs.incident_procedure.evidence_refs,
    ]
    if inputs.publication_recovery is not None:
        groups.append(inputs.publication_recovery.evidence_refs)
    groups.extend(item.evidence_refs for item in inputs.hosted_writes)
    groups.extend(item.evidence_refs for item in inputs.connector_conformance)
    groups.extend(item.evidence_refs for item in inputs.transports)
    groups.extend(item.evidence_refs for item in inputs.replay_guarantees)
    groups.extend(item.evidence_refs for item in inputs.service_levels)
    groups.extend(item.evidence_refs for item in inputs.business_outcomes)
    by_ref: dict[str, PrimitiveEvidenceRef] = {}
    for group in groups:
        for evidence in group:
            prior = by_ref.get(evidence.evidence_ref)
            if prior is not None and prior != evidence:
                raise ValueError(
                    "one evidence_ref cannot identify conflicting readiness evidence"
                )
            by_ref[evidence.evidence_ref] = evidence
    return tuple(by_ref[key] for key in sorted(by_ref))


def _evidence_status(
    evidence_refs: tuple[PrimitiveEvidenceRef, ...],
    *,
    evaluated_at: datetime,
    policy: OperationalReadinessPolicy,
) -> ReadinessGateStatus:
    if not evidence_refs:
        return "indeterminate"
    for evidence in evidence_refs:
        observed_at = _parsed_timestamp(evidence.observed_at)
        if observed_at > evaluated_at:
            return "fail"
        if (
            evidence.effective_at is not None
            and _parsed_timestamp(evidence.effective_at) > evaluated_at
        ):
            return "fail"
        if (
            _GRADE_RANK[evidence.verification_grade]
            < _GRADE_RANK[policy.minimum_evidence_grade]
        ):
            return "indeterminate"
    return "pass"


def _finding(
    findings: list[OperationalReadinessFinding],
    *,
    gate: ReadinessGate,
    code: str,
    status: ReadinessGateStatus,
    message: str,
    refs: tuple[str, ...] = (),
) -> None:
    findings.append(
        OperationalReadinessFinding(
            gate=gate,
            code=code,
            status=status,
            message=message,
            affected_refs=refs,
        )
    )


def _certification_status(
    *,
    checks: tuple[bool, ...],
    certified_at: str,
    expires_at: str,
    evidence_refs: tuple[PrimitiveEvidenceRef, ...],
    evaluated_at: datetime,
    policy: OperationalReadinessPolicy,
) -> ReadinessGateStatus:
    certified_timestamp = _parsed_timestamp(certified_at)
    if certified_timestamp > evaluated_at:
        return "fail"
    if _parsed_timestamp(expires_at) <= evaluated_at:
        return "indeterminate"
    if any(
        _parsed_timestamp(evidence.observed_at) > certified_timestamp
        or (
            evidence.effective_at is not None
            and _parsed_timestamp(evidence.effective_at) > certified_timestamp
        )
        for evidence in evidence_refs
    ):
        return "fail"
    evidence_status = _evidence_status(
        evidence_refs, evaluated_at=evaluated_at, policy=policy
    )
    if evidence_status != "pass":
        return evidence_status
    return "pass" if all(checks) else "fail"


def evaluate_operational_readiness(
    inputs: OperationalReadinessInput | dict[str, Any],
) -> OperationalReadinessResult:
    """Evaluate production execution evidence without granting certification."""

    parsed = OperationalReadinessInput.model_validate(
        _detached_validation_payload(inputs)
    )
    evaluated_at = _parsed_timestamp(parsed.evaluated_at)
    findings: list[OperationalReadinessFinding] = []

    hosted_by_tool = {item.tool: item for item in parsed.hosted_writes}
    for tool in parsed.policy.required_hosted_write_tools:
        item = hosted_by_tool.get(tool)
        if item is None:
            _finding(
                findings,
                gate="hosted_writes",
                code="hosted_writes.missing",
                status="fail",
                message="Required hosted-write certification is missing.",
                refs=(tool,),
            )
            continue
        status = _certification_status(
            checks=(
                item.exact_project_account_route_verified,
                item.spring_approval_verified,
                item.durable_idempotency_verified,
                item.ambiguous_outcome_recovery_verified,
                item.native_adapter_dispatch_verified,
                item.live_write_readback_verified,
            ),
            certified_at=item.certified_at,
            expires_at=item.expires_at,
            evidence_refs=item.evidence_refs,
            evaluated_at=evaluated_at,
            policy=parsed.policy,
        )
        _finding(
            findings,
            gate="hosted_writes",
            code="hosted_writes.certification",
            status=status,
            message=f"Hosted write certification for {tool} is {status}.",
            refs=(tool,),
        )

    loops = parsed.bounded_loops
    loop_status = _certification_status(
        checks=(
            loops.bounded_workflow_count == loops.loop_workflow_count,
            loops.durable_iteration_state_verified,
            loops.exhaustion_fails_closed,
            loops.crash_resume_preserves_budget,
        ),
        certified_at=loops.certified_at,
        expires_at=loops.expires_at,
        evidence_refs=loops.evidence_refs,
        evaluated_at=evaluated_at,
        policy=parsed.policy,
    )
    _finding(
        findings,
        gate="bounded_loops",
        code="bounded_loops.certification",
        status=loop_status,
        message=f"Bounded-loop compiler and runtime certification is {loop_status}.",
    )

    publication = parsed.publication_recovery
    if publication is None:
        _finding(
            findings,
            gate="publication_recovery",
            code="publication_recovery.missing",
            status="fail",
            message="Workflow-publication recovery certification is missing.",
        )
    else:
        publication_status = _certification_status(
            checks=(
                publication.outboxed_spring_step_lane_count
                == publication.authorized_spring_step_lane_count,
                publication.workflow_requests_transactional,
                publication.step_requests_transactional,
                publication.hitl_requests_transactional,
                publication.hitl_decisions_transactional,
                publication.encrypted_payload_custody_verified,
                publication.relay_scope_generation_fencing_verified,
                publication.relay_actor_authority_recheck_verified,
                publication.consumer_duplicate_suppression_verified,
                publication.recoverable_failures_retained,
                publication.corrupt_rows_parked_and_alerted,
                publication.unsupported_worker_publications_disabled,
                publication.unsupported_principals_fail_closed,
                publication.direct_event_dlq_recovery_procedure_verified,
            ),
            certified_at=publication.certified_at,
            expires_at=publication.expires_at,
            evidence_refs=publication.evidence_refs,
            evaluated_at=evaluated_at,
            policy=parsed.policy,
        )
        _finding(
            findings,
            gate="publication_recovery",
            code="publication_recovery.certification",
            status=publication_status,
            message=(
                "Workflow request, step, HITL, relay, duplicate-suppression, and "
                f"direct-topic recovery certification is {publication_status}."
            ),
            refs=(publication.outbox_contract_version,),
        )

    conformance_by_provider: dict[str, list[ConnectorConformanceCertification]] = {}
    for item in parsed.connector_conformance:
        conformance_by_provider.setdefault(item.provider, []).append(item)
    for provider in parsed.policy.required_connector_providers:
        items = conformance_by_provider.get(provider, [])
        if not items:
            _finding(
                findings,
                gate="connector_conformance",
                code="connector_conformance.missing",
                status="fail",
                message="Required production connector certification is missing.",
                refs=(provider,),
            )
            continue
        required_tools = tuple(
            tool
            for tool in parsed.policy.required_connector_tools
            if tool.split(".", 1)[0] == provider
        )
        scoped_items: tuple[tuple[str, ConnectorConformanceCertification], ...]
        if required_tools:
            resolved: list[tuple[str, ConnectorConformanceCertification]] = []
            for tool in required_tools:
                item = next(
                    (
                        candidate
                        for candidate in items
                        if tool in candidate.required_tools
                    ),
                    None,
                )
                if item is None:
                    _finding(
                        findings,
                        gate="connector_conformance",
                        code="connector_conformance.tool_missing",
                        status="fail",
                        message=(
                            "Required production connector Tool certification is "
                            "missing; a provider-level or write-only packet cannot "
                            "substitute for the exact Tool."
                        ),
                        refs=(provider, tool),
                    )
                    continue
                resolved.append((tool, item))
            scoped_items = tuple(resolved)
        else:
            scoped_items = tuple((item.provider, item) for item in items)

        for required_ref, item in scoped_items:
            status = _certification_status(
                checks=(
                    set(item.required_tools) == set(item.certified_tools),
                    item.tenant_isolation_verified,
                    item.project_account_binding_verified,
                    item.schema_drift_check_passed,
                    item.error_normalization_verified,
                    item.rate_limit_behavior_verified,
                ),
                certified_at=item.certified_at,
                expires_at=item.expires_at,
                evidence_refs=item.evidence_refs,
                evaluated_at=evaluated_at,
                policy=parsed.policy,
            )
            _finding(
                findings,
                gate="connector_conformance",
                code="connector_conformance.certification",
                status=status,
                message=(
                    f"Production connector certification for {required_ref} is "
                    f"{status}."
                ),
                refs=(provider, required_ref),
            )

    transport_by_channel = {item.channel: item for item in parsed.transports}
    for channel in parsed.policy.required_channels:
        item = transport_by_channel.get(channel)
        if item is None:
            _finding(
                findings,
                gate="transport_recovery",
                code="transport_recovery.missing",
                status="fail",
                message="Required transport recovery certification is missing.",
                refs=(channel,),
            )
            continue
        status = _certification_status(
            checks=(
                item.materializer_authoritative,
                item.observer_authoritative,
                item.consent_and_suppression_verified,
                item.cross_channel_identity_verified,
                item.delivery_outcome_normalized,
                item.crash_recovery_verified,
                item.duplicate_effect_suppression_verified,
            ),
            certified_at=item.certified_at,
            expires_at=item.expires_at,
            evidence_refs=item.evidence_refs,
            evaluated_at=evaluated_at,
            policy=parsed.policy,
        )
        _finding(
            findings,
            gate="transport_recovery",
            code="transport_recovery.certification",
            status=status,
            message=f"Production transport certification for {channel} is {status}.",
            refs=(channel, item.provider),
        )

    replay_by_ref = {
        item.operation_class_ref: item for item in parsed.replay_guarantees
    }
    for operation_class in parsed.policy.required_replay_classes:
        item = replay_by_ref.get(operation_class)
        if item is None:
            _finding(
                findings,
                gate="replay_guarantees",
                code="replay_guarantees.missing",
                status="fail",
                message="Required replay-guarantee certification is missing.",
                refs=(operation_class,),
            )
            continue
        status = _certification_status(
            checks=(
                item.durable_request_digest_verified,
                item.recovery_attestation_verified,
                item.ambiguous_effect_auto_retry_blocked,
            ),
            certified_at=item.certified_at,
            expires_at=item.expires_at,
            evidence_refs=item.evidence_refs,
            evaluated_at=evaluated_at,
            policy=parsed.policy,
        )
        _finding(
            findings,
            gate="replay_guarantees",
            code="replay_guarantees.certification",
            status=status,
            message=f"Replay guarantee for {operation_class} is {status}.",
            refs=(operation_class,),
        )

    slos_by_ref = {item.slo_ref: item for item in parsed.service_levels}
    for slo_ref in parsed.policy.required_slos:
        item = slos_by_ref.get(slo_ref)
        if item is None:
            _finding(
                findings,
                gate="service_levels",
                code="service_levels.missing",
                status="fail",
                message="Required service-level measurement is missing.",
                refs=(slo_ref,),
            )
            continue
        evidence_status = _evidence_status(
            item.evidence_refs, evaluated_at=evaluated_at, policy=parsed.policy
        )
        if _parsed_timestamp(item.window_ended_at) > evaluated_at:
            status: ReadinessGateStatus = "fail"
        elif item.sample_count < parsed.policy.minimum_slo_sample_count:
            status = "indeterminate"
        elif evidence_status != "pass":
            status = evidence_status
        else:
            target_met = (
                item.observed >= item.target
                if item.comparison == "at_least"
                else item.observed <= item.target
            )
            status = "pass" if target_met else "fail"
        _finding(
            findings,
            gate="service_levels",
            code="service_levels.measurement",
            status=status,
            message=f"Service-level objective {slo_ref} is {status}.",
            refs=(slo_ref,),
        )

    incident = parsed.incident_procedure
    exercise_at = _parsed_timestamp(incident.last_exercised_at)
    exercise_age = (evaluated_at - exercise_at).total_seconds() / 3_600
    if exercise_at > evaluated_at:
        incident_status: ReadinessGateStatus = "fail"
    elif exercise_age > parsed.policy.maximum_incident_exercise_age_hours:
        incident_status = "indeterminate"
    else:
        evidence_status = _evidence_status(
            incident.evidence_refs,
            evaluated_at=evaluated_at,
            policy=parsed.policy,
        )
        incident_status = (
            evidence_status
            if evidence_status != "pass"
            else "pass"
            if all(
                (
                    incident.provider_escalation_paths_verified,
                    incident.customer_communication_path_verified,
                    incident.ambiguous_effect_procedure_verified,
                    incident.replay_and_reconciliation_procedure_verified,
                    set(incident.severity_levels) == {"sev1", "sev2", "sev3", "sev4"},
                )
            )
            else "fail"
        )
    _finding(
        findings,
        gate="incident_response",
        code="incident_response.procedure",
        status=incident_status,
        message=f"Incident procedure and exercise evidence is {incident_status}.",
        refs=(incident.runbook_ref,),
    )

    outcome_by_ref = {item.outcome_ref: item for item in parsed.business_outcomes}
    for outcome_ref in parsed.policy.required_business_outcomes:
        item = outcome_by_ref.get(outcome_ref)
        if item is None:
            _finding(
                findings,
                gate="business_outcomes",
                code="business_outcomes.missing",
                status="fail",
                message="Required real business-outcome measurement is missing.",
                refs=(outcome_ref,),
            )
            continue
        measured_at = _parsed_timestamp(item.measured_at)
        age_hours = (evaluated_at - measured_at).total_seconds() / 3_600
        evidence_status = _evidence_status(
            item.evidence_refs, evaluated_at=evaluated_at, policy=parsed.policy
        )
        if measured_at > evaluated_at:
            status = "fail"
        elif age_hours > parsed.policy.maximum_business_measurement_age_hours:
            status = "indeterminate"
        elif evidence_status != "pass":
            status = evidence_status
        else:
            target_met = (
                item.observed >= item.target
                if item.direction == "increase"
                else item.observed <= item.target
            )
            improved = (
                item.observed > item.baseline
                if item.direction == "increase"
                else item.observed < item.baseline
            )
            status = "pass" if target_met and improved else "fail"
        _finding(
            findings,
            gate="business_outcomes",
            code="business_outcomes.measurement",
            status=status,
            message=f"Business outcome {outcome_ref} is {status} against baseline and target.",
            refs=(outcome_ref, item.source_system_ref),
        )

    evidence_refs = _all_evidence(parsed)
    passed_count = sum(item.status == "pass" for item in findings)
    failed_count = sum(item.status == "fail" for item in findings)
    indeterminate_count = sum(item.status == "indeterminate" for item in findings)
    disposition: ReadinessDisposition = (
        "blocked"
        if failed_count
        else "indeterminate"
        if indeterminate_count
        else "ready_for_operator_certification"
    )
    input_digest = _stable_digest(parsed.to_dict())
    evidence_digest = _stable_digest([evidence.to_dict() for evidence in evidence_refs])
    evaluation_digest = _readiness_evaluation_digest(
        evaluation_ref=parsed.evaluation_ref,
        environment_ref=parsed.environment_ref,
        evaluated_at=parsed.evaluated_at,
        disposition=disposition,
        findings=tuple(findings),
        passed_count=passed_count,
        failed_count=failed_count,
        indeterminate_count=indeterminate_count,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
    )
    return OperationalReadinessResult(
        evaluation_ref=parsed.evaluation_ref,
        environment_ref=parsed.environment_ref,
        evaluated_at=parsed.evaluated_at,
        disposition=disposition,
        findings=tuple(findings),
        passed_count=passed_count,
        failed_count=failed_count,
        indeterminate_count=indeterminate_count,
        evidence_refs=evidence_refs,
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        evaluation_digest=evaluation_digest,
        operation_spec=OPERATIONAL_READINESS_OPERATION,
    )


def _evidence(ref: str, kind: str, character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": kind,
        "issuer_ref": "spring-production-authority",
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "restricted",
        "retention_policy": "production-readiness-two-years",
    }


def _example_inputs() -> dict[str, Any]:
    start = "2026-08-01T00:00:00Z"
    certified = "2026-08-24T12:00:00Z"
    expires = "2026-11-24T12:00:00Z"
    tool = "quickbooks.create_journal_entry"
    provider = "quickbooks"
    return {
        "schema": OPERATIONAL_READINESS_INPUT_SCHEMA,
        "evaluation_ref": "prod-readiness-2026-08-24",
        "environment_ref": "production-us-east-1",
        "evaluated_at": "2026-08-24T13:00:00Z",
        "policy": {
            "required_hosted_write_tools": [tool],
            "required_connector_providers": [provider],
            "required_connector_tools": [tool],
            "required_channels": ["email"],
            "required_replay_classes": ["governed_connector_write"],
            "required_slos": ["connector.success_rate"],
            "required_business_outcomes": ["close_cycle_time"],
        },
        "hosted_writes": [
            {
                "tool": tool,
                "provider": provider,
                "environment": "production",
                "catalog_version": "finance-governed-writes-v1",
                "certified_at": certified,
                "expires_at": expires,
                "exact_project_account_route_verified": True,
                "spring_approval_verified": True,
                "durable_idempotency_verified": True,
                "ambiguous_outcome_recovery_verified": True,
                "native_adapter_dispatch_verified": True,
                "live_write_readback_verified": True,
                "evidence_refs": [
                    _evidence("evidence-hosted-write", "live_write", "1")
                ],
            }
        ],
        "bounded_loops": {
            "compiler_contract_version": "bounded-loop-v1",
            "runtime_contract_version": "bounded-loop-v1",
            "loop_workflow_count": 4,
            "bounded_workflow_count": 4,
            "durable_iteration_state_verified": True,
            "exhaustion_fails_closed": True,
            "crash_resume_preserves_budget": True,
            "certified_at": certified,
            "expires_at": expires,
            "evidence_refs": [_evidence("evidence-bounded-loop", "loop_drill", "2")],
        },
        "publication_recovery": {
            "environment": "production",
            "outbox_contract_version": "workflow-publication-outbox-v2",
            "authorized_spring_step_lane_count": 13,
            "outboxed_spring_step_lane_count": 13,
            "workflow_requests_transactional": True,
            "step_requests_transactional": True,
            "hitl_requests_transactional": True,
            "hitl_decisions_transactional": True,
            "encrypted_payload_custody_verified": True,
            "relay_scope_generation_fencing_verified": True,
            "relay_actor_authority_recheck_verified": True,
            "consumer_duplicate_suppression_verified": True,
            "recoverable_failures_retained": True,
            "corrupt_rows_parked_and_alerted": True,
            "unsupported_worker_publications_disabled": True,
            "unsupported_principals_fail_closed": True,
            "direct_event_dlq_recovery_procedure_verified": True,
            "crash_points_tested": 8,
            "certified_at": certified,
            "expires_at": expires,
            "evidence_refs": [
                _evidence("evidence-publication-recovery", "outbox_recovery_drill", "9")
            ],
        },
        "connector_conformance": [
            {
                "provider": provider,
                "environment": "production",
                "required_tools": [tool],
                "certified_tools": [tool],
                "tenant_isolation_verified": True,
                "project_account_binding_verified": True,
                "schema_drift_check_passed": True,
                "error_normalization_verified": True,
                "rate_limit_behavior_verified": True,
                "certified_at": certified,
                "expires_at": expires,
                "evidence_refs": [
                    _evidence("evidence-conformance", "connector_test", "3")
                ],
            }
        ],
        "transports": [
            {
                "channel": "email",
                "provider": "gmail",
                "environment": "production",
                "materializer_authoritative": True,
                "observer_authoritative": True,
                "consent_and_suppression_verified": True,
                "cross_channel_identity_verified": True,
                "delivery_outcome_normalized": True,
                "crash_recovery_verified": True,
                "duplicate_effect_suppression_verified": True,
                "certified_at": certified,
                "expires_at": expires,
                "evidence_refs": [_evidence("evidence-email", "transport_drill", "4")],
            }
        ],
        "replay_guarantees": [
            {
                "operation_class_ref": "governed_connector_write",
                "guarantee": "manual_reconciliation_no_replay",
                "durable_request_digest_verified": True,
                "recovery_attestation_verified": True,
                "ambiguous_effect_auto_retry_blocked": True,
                "crash_points_tested": 7,
                "certified_at": certified,
                "expires_at": expires,
                "evidence_refs": [_evidence("evidence-replay", "replay_drill", "5")],
            }
        ],
        "service_levels": [
            {
                "slo_ref": "connector.success_rate",
                "indicator": "successful_execution",
                "comparison": "at_least",
                "unit": "percent",
                "target": "99.0",
                "observed": "99.7",
                "sample_count": 1000,
                "window_started_at": start,
                "window_ended_at": "2026-08-24T12:00:00Z",
                "evidence_refs": [_evidence("evidence-slo", "slo_measurement", "6")],
            }
        ],
        "incident_procedure": {
            "runbook_ref": "runbook-sdk-production-execution",
            "runbook_version": "v1",
            "on_call_owner_ref": "team-platform-oncall",
            "severity_levels": ["sev1", "sev2", "sev3", "sev4"],
            "provider_escalation_paths_verified": True,
            "customer_communication_path_verified": True,
            "ambiguous_effect_procedure_verified": True,
            "replay_and_reconciliation_procedure_verified": True,
            "last_exercised_at": "2026-08-24T12:00:00Z",
            "evidence_refs": [_evidence("evidence-incident", "incident_exercise", "7")],
        },
        "business_outcomes": [
            {
                "outcome_ref": "close_cycle_time",
                "metric_name": "period_close_cycle_minutes",
                "direction": "decrease",
                "unit": "minutes",
                "baseline": "900",
                "observed": "540",
                "target": "600",
                "sample_count": 12,
                "measured_at": "2026-08-24T12:00:00Z",
                "source_system_ref": "spring-business-outcomes-ledger",
                "evidence_refs": [
                    _evidence("evidence-outcome", "business_outcome", "8")
                ],
            }
        ],
    }


class EvaluateOperationalReadinessPrimitive(
    BusinessProcessPrimitive[OperationalReadinessInput, OperationalReadinessResult]
):
    primitive_ref = "operations.evaluate_production_execution_readiness"
    version = "1.1.0"
    title = "Evaluate production execution readiness"
    description = (
        "Evaluate hosted writes, bounded loops, workflow publication, "
        "connector/transport recovery, replay, SLO, incident, and real "
        "business-outcome evidence without certifying deployment."
    )
    input_model = OperationalReadinessInput
    output_model = OperationalReadinessResult
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
        contract["operation_contract"] = OPERATIONAL_READINESS_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "deployment_changes": 0,
            "incident_mutations": 0,
            "production_certified": False,
            "deployment_authorized": False,
        }
        contract["certification_authority"] = "spring_or_human_operator_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: OperationalReadinessInput,
    ) -> PrimitiveExecutionResult[OperationalReadinessResult]:
        del context
        output = evaluate_operational_readiness(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=OPERATIONAL_READINESS_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.input_digest,
            external_refs={"evaluation_digest": output.evaluation_digest},
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"Production execution readiness evaluated: {output.disposition}.",
            output=output,
            events=[
                PrimitiveEvent(
                    type="operations.production_readiness_evaluated",
                    payload={
                        "disposition": output.disposition,
                        "evaluation_digest": output.evaluation_digest,
                        "production_certified": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="operational_readiness_evaluation",
                    summary="Production execution evidence evaluated without granting certification.",
                    labels=[
                        output.disposition,
                        "read_only",
                        "operator_certification_required",
                    ],
                    refs={
                        "input_digest": output.input_digest,
                        "evidence_digest": output.evidence_digest,
                        "evaluation_digest": output.evaluation_digest,
                    },
                )
            ],
            evidence_refs=list(output.evidence_refs),
            operation_receipts=[receipt],
        )


OPERATIONAL_READINESS_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (EvaluateOperationalReadinessPrimitive(),)


__all__ = [
    "BoundedLoopCertification",
    "BusinessOutcomeMeasurement",
    "Channel",
    "ConnectorConformanceCertification",
    "EvaluateOperationalReadinessPrimitive",
    "HostedWriteCertification",
    "IncidentProcedureCertification",
    "OPERATIONAL_READINESS_EXECUTABLE_PRIMITIVES",
    "OPERATIONAL_READINESS_INPUT_SCHEMA",
    "OPERATIONAL_READINESS_OPERATION",
    "OPERATIONAL_READINESS_RESULT_SCHEMA",
    "OperationalReadinessFinding",
    "OperationalReadinessInput",
    "OperationalReadinessPolicy",
    "OperationalReadinessResult",
    "ReadinessDisposition",
    "ReadinessGate",
    "ReadinessGateStatus",
    "ReplayGuaranteeCertification",
    "ServiceLevelMeasurement",
    "TransportRecoveryCertification",
    "WorkflowPublicationRecoveryCertification",
    "evaluate_operational_readiness",
]
