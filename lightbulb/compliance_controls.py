"""Deterministic controls for compliance and regulated operations.

The SDK evaluates normalized, evidence-bound snapshots. It never performs
screening, files a report, approves a customer, disposes a record, deploys a
model, or mutates a regulated system. Spring remains authoritative for scope,
RBAC, approvals, persistence, audit, and governed connector execution.
"""

from __future__ import annotations

import hashlib
import json
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
    revalidate_model_boundary,
)


REGULATED_CONTROLS_INPUT_SCHEMA = "lightbulb.regulated_controls_input.v1"
REGULATED_CONTROLS_RESULT_SCHEMA = "lightbulb.regulated_controls_result.v1"
_ZERO_DIGEST = "0" * 64

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
FindingMessage = Annotated[str, StringConstraints(min_length=1, max_length=600)]

ComplianceGate = Literal[
    "evidence",
    "policy_controls",
    "assessments",
    "incident_reporting",
    "kyc_aml",
    "regulated_quality",
    "export_controls",
    "records_retention",
    "model_risk",
]
GateStatus = Literal["pass", "review", "fail", "indeterminate", "not_applicable"]
FindingSeverity = Literal["info", "review", "blocking", "indeterminate"]
ComplianceDisposition = Literal[
    "controls_satisfied",
    "manual_review_required",
    "blocked",
    "indeterminate",
]
RegulatedDomain = Literal[
    "clinical",
    "regulatory",
    "gmp",
    "qms",
    "safety",
    "certification",
]


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
        return self.model_dump(mode="json", by_alias=True)


def _tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


def _timestamp(value: str, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parsed(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def regulated_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    """Return a stable digest for one normalized regulated snapshot."""

    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _digest(payload)


def _unique(values: Sequence[Any], field: str, label: str) -> None:
    refs = [str(getattr(value, field)) for value in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{label} references must be unique")


class ComplianceApplicability(_StrictModel):
    policy_controls: bool = True
    assessments: bool = True
    incident_reporting: bool = True
    kyc_aml: bool = False
    export_controls: bool = False
    records_retention: bool = True
    model_risk: bool = False
    regulated_domains: tuple[RegulatedDomain, ...] = Field(default_factory=tuple)

    @field_validator("regulated_domains", mode="before")
    @classmethod
    def _domains_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _unique_domains(self) -> "ComplianceApplicability":
        if len(self.regulated_domains) != len(set(self.regulated_domains)):
            raise ValueError("regulated_domains must be unique")
        return self


def _has_applicable_control_domain(applicability: ComplianceApplicability) -> bool:
    return any(
        (
            applicability.policy_controls,
            applicability.assessments,
            applicability.incident_reporting,
            applicability.kyc_aml,
            applicability.export_controls,
            applicability.records_retention,
            applicability.model_risk,
            bool(applicability.regulated_domains),
        )
    )


class RegulatedControlPolicy(_StrictModel):
    applicability: ComplianceApplicability = Field(
        default_factory=ComplianceApplicability
    )
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=720, ge=1, le=87_600)
    maximum_control_test_age_days: int = Field(default=365, ge=1, le=3_650)
    maximum_assessment_age_days: int = Field(default=365, ge=1, le=3_650)
    maximum_kyc_review_age_days: int = Field(default=365, ge=1, le=3_650)
    incident_report_deadline_hours: int = Field(default=72, ge=1, le=720)
    maximum_model_validation_age_days: int = Field(default=365, ge=1, le=3_650)

    @field_validator("minimum_evidence_grade", mode="before")
    @classmethod
    def _grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))


class PolicyControlSnapshot(_StrictModel):
    control_ref: OpaqueRef
    policy_ref: OpaqueRef
    framework_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=30)
    owner_ref: OpaqueRef
    implementation_status: Literal[
        "effective", "partially_effective", "ineffective", "not_implemented"
    ]
    test_status: Literal["passed", "exceptions", "failed", "not_tested"]
    last_tested_at: str | None = None
    next_test_due_at: str | None = None
    open_exception_count: int = Field(default=0, ge=0, le=1_000_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("framework_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @field_validator("last_tested_at", "next_test_due_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, info.field_name)

    @model_validator(mode="after")
    def _test_chronology_is_valid(self) -> "PolicyControlSnapshot":
        if (
            self.last_tested_at is not None
            and self.next_test_due_at is not None
            and _parsed(self.next_test_due_at) <= _parsed(self.last_tested_at)
        ):
            raise ValueError("next control test must be due after the completed test")
        return self


class ComplianceAssessmentSnapshot(_StrictModel):
    assessment_ref: OpaqueRef
    framework_ref: OpaqueRef
    status: Literal["complete", "in_progress", "failed", "expired"]
    assessed_at: str
    material_finding_count: int = Field(default=0, ge=0, le=1_000_000)
    remediation_overdue_count: int = Field(default=0, ge=0, le=1_000_000)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("assessed_at")
    @classmethod
    def _assessed_at(cls, value: str) -> str:
        return _timestamp(value, "assessed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)


class IncidentReportingSnapshot(_StrictModel):
    incident_ref: OpaqueRef
    incident_type: Literal[
        "security_incident",
        "privacy_breach",
        "safety_event",
        "quality_event",
        "regulatory_event",
    ]
    severity: Literal["low", "moderate", "high", "critical"]
    status: Literal["open", "contained", "reported", "closed"]
    discovered_at: str
    contained_at: str | None = None
    report_due_at: str | None = None
    reported_at: str | None = None
    jurisdiction_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("discovered_at", "contained_at", "report_due_at", "reported_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, info.field_name)

    @field_validator("jurisdiction_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _incident_chronology_is_valid(self) -> "IncidentReportingSnapshot":
        discovered = _parsed(self.discovered_at)
        for field_name in ("contained_at", "reported_at"):
            value = getattr(self, field_name)
            if value is not None and _parsed(value) < discovered:
                raise ValueError(f"{field_name} cannot precede discovered_at")
        if self.report_due_at is not None and _parsed(self.report_due_at) <= discovered:
            raise ValueError("report_due_at must be after discovered_at")
        return self


class KycAmlSnapshot(_StrictModel):
    subject_ref: OpaqueRef
    status: Literal["approved", "pending", "rejected", "expired"]
    risk_rating: Literal["low", "medium", "high", "prohibited"]
    beneficial_ownership_verified: bool
    sanctions_status: Literal[
        "clear", "possible_match", "confirmed_match", "not_screened"
    ]
    pep_status: Literal["clear", "possible_match", "confirmed_match", "not_screened"]
    adverse_media_status: Literal["clear", "review", "material", "not_screened"]
    reviewed_at: str
    next_review_due_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("reviewed_at", "next_review_due_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _review_chronology_is_valid(self) -> "KycAmlSnapshot":
        if _parsed(self.next_review_due_at) <= _parsed(self.reviewed_at):
            raise ValueError("next KYC review must be due after the completed review")
        return self


class RegulatedProcessSnapshot(_StrictModel):
    process_ref: OpaqueRef
    domain: RegulatedDomain
    status: Literal[
        "validated", "certified", "qualified", "conditional", "suspended", "expired"
    ]
    validation_ref: OpaqueRef | None = None
    valid_until: str | None = None
    open_deviation_count: int = Field(default=0, ge=0, le=1_000_000)
    overdue_capa_count: int = Field(default=0, ge=0, le=1_000_000)
    release_blocked: bool = False
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("valid_until")
    @classmethod
    def _valid_until(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "valid_until")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)


class ExportControlSnapshot(_StrictModel):
    transaction_ref: OpaqueRef
    item_classification_ref: OpaqueRef | None = None
    destination_jurisdiction: OpaqueRef
    party_screening_status: Literal[
        "clear", "possible_match", "denied_party", "not_screened"
    ]
    destination_status: Literal["permitted", "restricted", "embargoed", "not_screened"]
    license_required: bool
    license_ref: OpaqueRef | None = None
    license_valid_until: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("license_valid_until")
    @classmethod
    def _license_until(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "license_valid_until")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)


class RetentionRecordSnapshot(_StrictModel):
    record_set_ref: OpaqueRef
    category_ref: OpaqueRef
    created_at: str
    retain_until: str
    legal_hold: bool = False
    disposition_status: Literal[
        "retained", "disposition_due", "disposition_approved", "disposed"
    ]
    disposed_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("created_at", "retain_until", "disposed_at")
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _retention_chronology_is_valid(self) -> "RetentionRecordSnapshot":
        created = _parsed(self.created_at)
        if _parsed(self.retain_until) <= created:
            raise ValueError("record retention must extend beyond record creation")
        if self.disposed_at is not None and _parsed(self.disposed_at) < created:
            raise ValueError("disposed_at cannot precede created_at")
        if (self.disposition_status == "disposed") != (self.disposed_at is not None):
            raise ValueError(
                "disposed status and disposed_at must be supplied together"
            )
        return self


class ModelRiskSnapshot(_StrictModel):
    model_ref: OpaqueRef
    risk_tier: Literal["low", "medium", "high", "critical"]
    inventory_status: Literal["registered", "unregistered", "retired"]
    validation_status: Literal["approved", "conditional", "failed", "not_validated"]
    validated_at: str | None = None
    approved_use_ref: OpaqueRef | None = None
    monitoring_status: Literal["within_limits", "warning", "breach", "not_monitored"]
    drift_threshold_breached: bool = False
    bias_threshold_breached: bool = False
    latest_change_approved: bool = True
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("validated_at")
    @classmethod
    def _validated_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "validated_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _tuple(value)


class RegulatedControlsInput(_StrictModel):
    schema_id: Literal["lightbulb.regulated_controls_input.v1"] = Field(
        default=REGULATED_CONTROLS_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    policy_controls: tuple[PolicyControlSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    assessments: tuple[ComplianceAssessmentSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    incidents: tuple[IncidentReportingSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    kyc_aml_subjects: tuple[KycAmlSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    regulated_processes: tuple[RegulatedProcessSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    export_transactions: tuple[ExportControlSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    retention_records: tuple[RetentionRecordSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    models: tuple[ModelRiskSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=100_000,
    )
    policy: RegulatedControlPolicy = Field(default_factory=RegulatedControlPolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, "analysis_as_of")

    @field_validator(
        "policy_controls",
        "assessments",
        "incidents",
        "kyc_aml_subjects",
        "regulated_processes",
        "export_transactions",
        "retention_records",
        "models",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _unique_and_consistent(self) -> "RegulatedControlsInput":
        for values, field, label in (
            (self.policy_controls, "control_ref", "control"),
            (self.assessments, "assessment_ref", "assessment"),
            (self.incidents, "incident_ref", "incident"),
            (self.kyc_aml_subjects, "subject_ref", "KYC/AML subject"),
            (self.regulated_processes, "process_ref", "regulated process"),
            (self.export_transactions, "transaction_ref", "export transaction"),
            (self.retention_records, "record_set_ref", "record set"),
            (self.models, "model_ref", "model"),
        ):
            _unique(values, field, label)
        evidence: dict[str, PrimitiveEvidenceRef] = {}
        for item in (
            *self.policy_controls,
            *self.assessments,
            *self.incidents,
            *self.kyc_aml_subjects,
            *self.regulated_processes,
            *self.export_transactions,
            *self.retention_records,
            *self.models,
        ):
            for ref in item.evidence_refs:
                previous = evidence.setdefault(ref.evidence_ref, ref)
                if previous != ref:
                    raise ValueError(
                        "one evidence_ref cannot identify conflicting evidence"
                    )
        return self


class RegulatedControlFinding(_StrictModel):
    code: OpaqueRef
    gate: ComplianceGate
    severity: FindingSeverity
    message: FindingMessage
    subject_ref: OpaqueRef | None = None


class RegulatedGateResult(_StrictModel):
    gate: ComplianceGate
    status: GateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=10_000
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _tuple(value)


class ComplianceObligationProposal(_StrictModel):
    obligation_ref: OpaqueRef
    gate: ComplianceGate
    action: Literal[
        "collect_evidence",
        "test_control",
        "complete_assessment",
        "review_incident_reporting",
        "complete_kyc_review",
        "remediate_regulated_process",
        "review_export_transaction",
        "review_record_disposition",
        "validate_model",
    ]
    subject_ref: OpaqueRef | None = None
    due_at: str | None = None
    requires_authorized_reviewer: Literal[True] = True
    executed: Literal[False] = False

    @field_validator("due_at")
    @classmethod
    def _due_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "due_at")


class ComplianceEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    reports_or_filings_submitted: Literal[False] = False
    subjects_approved: Literal[False] = False
    records_disposed: Literal[False] = False
    models_deployed: Literal[False] = False
    regulated_systems_changed: Literal[False] = False
    external_systems_changed: Literal[False] = False


REGULATED_CONTROLS_OPERATION = PrimitiveOperationSpec(
    operation_ref="regulated-controls.evaluate",
    tool="compliance.evaluate_regulated_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class RegulatedControlsResult(_StrictModel):
    schema_id: Literal["lightbulb.regulated_controls_result.v1"] = Field(
        default=REGULATED_CONTROLS_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    assurance_grade: PrimitiveEvidenceVerificationGrade
    applicability: ComplianceApplicability
    proposed_disposition: ComplianceDisposition
    gates: tuple[RegulatedGateResult, ...]
    findings: tuple[RegulatedControlFinding, ...]
    obligation_proposals: tuple[ComplianceObligationProposal, ...]
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[OpaqueRef, ...]
    effect_boundary: ComplianceEffectBoundary = Field(
        default_factory=ComplianceEffectBoundary
    )
    result_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator(
        "gates", "findings", "obligation_proposals", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _tuple(value)

    @model_validator(mode="after")
    def _result_is_coherent_and_content_bound(self) -> "RegulatedControlsResult":
        expected_findings = tuple(
            sorted(
                self.findings,
                key=lambda item: (
                    _GATES.index(item.gate),
                    item.subject_ref or "",
                    item.code,
                ),
            )
        )
        if self.findings != expected_findings:
            raise ValueError("findings must be in canonical order")
        if tuple(gate.gate for gate in self.gates) != _GATES:
            raise ValueError("gates must be complete and in canonical order")
        has_applicable_domain = _has_applicable_control_domain(self.applicability)
        applicable_gates = {
            "evidence": has_applicable_domain,
            "policy_controls": self.applicability.policy_controls,
            "assessments": self.applicability.assessments,
            "incident_reporting": self.applicability.incident_reporting,
            "kyc_aml": self.applicability.kyc_aml,
            "regulated_quality": bool(self.applicability.regulated_domains),
            "export_controls": self.applicability.export_controls,
            "records_retention": self.applicability.records_retention,
            "model_risk": self.applicability.model_risk,
        }
        for gate in self.gates:
            gate_findings = [item for item in self.findings if item.gate == gate.gate]
            expected_codes = tuple(sorted({item.code for item in gate_findings}))
            if gate.finding_codes != expected_codes:
                raise ValueError("gate finding_codes must match findings")
            if not applicable_gates[gate.gate]:
                if gate.status != "not_applicable":
                    raise ValueError("inapplicable gates must be marked not_applicable")
                if gate_findings:
                    raise ValueError("not-applicable gates cannot contain findings")
                continue
            if gate.status == "not_applicable":
                raise ValueError("applicable gates cannot be marked not_applicable")
            expected_status: GateStatus = (
                "fail"
                if any(item.severity == "blocking" for item in gate_findings)
                else "indeterminate"
                if any(item.severity == "indeterminate" for item in gate_findings)
                else "review"
                if any(item.severity == "review" for item in gate_findings)
                else "pass"
            )
            if gate.status != expected_status:
                raise ValueError("gate status must match findings")
        expected_disposition: ComplianceDisposition
        if not has_applicable_domain:
            expected_disposition = "indeterminate"
        elif any(gate.status == "fail" for gate in self.gates):
            expected_disposition = "blocked"
        elif any(gate.status == "indeterminate" for gate in self.gates):
            expected_disposition = "indeterminate"
        elif any(gate.status == "review" for gate in self.gates):
            expected_disposition = "manual_review_required"
        else:
            expected_disposition = "controls_satisfied"
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match gate results")
        if (
            not has_applicable_domain
            and self.assurance_grade != PrimitiveEvidenceVerificationGrade.UNVERIFIED
        ):
            raise ValueError("no-applicability results cannot claim assurance")
        if self.obligation_proposals != tuple(
            sorted(self.obligation_proposals, key=lambda item: item.obligation_ref)
        ) or len({item.obligation_ref for item in self.obligation_proposals}) != len(
            self.obligation_proposals
        ):
            raise ValueError("obligation proposals must be canonical and unique")
        if any(
            not any(
                finding.gate == proposal.gate
                and finding.subject_ref == proposal.subject_ref
                for finding in self.findings
            )
            for proposal in self.obligation_proposals
        ):
            raise ValueError("obligation proposals must be supported by findings")
        required_sources = {"policy"}
        allowed_prefixes = (
            "control:",
            "assessment:",
            "incident:",
            "kyc:",
            "regulated_process:",
            "export:",
            "retention:",
            "model:",
        )
        if not required_sources.issubset(self.source_snapshot_digests) or any(
            key not in required_sources and not key.startswith(allowed_prefixes)
            for key in self.source_snapshot_digests
        ):
            raise ValueError("source_snapshot_digests contains an invalid source set")
        if any(
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in self.source_snapshot_digests.values()
        ):
            raise ValueError("source snapshot digests must be lowercase SHA-256 values")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("evidence_refs must be unique and in canonical order")
        expected_digest = _digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"result_digest"},
                exclude_none=True,
            )
        )
        if self.result_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("result_digest does not match result")
        object.__setattr__(self, "result_digest", expected_digest)
        return self


_GRADE = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_GATES: tuple[ComplianceGate, ...] = (
    "evidence",
    "policy_controls",
    "assessments",
    "incident_reporting",
    "kyc_aml",
    "regulated_quality",
    "export_controls",
    "records_retention",
    "model_risk",
)


def _all_items(inputs: RegulatedControlsInput) -> tuple[Any, ...]:
    applicability = inputs.policy.applicability
    required_domains = set(applicability.regulated_domains)
    return (
        *(inputs.policy_controls if applicability.policy_controls else ()),
        *(inputs.assessments if applicability.assessments else ()),
        *(inputs.incidents if applicability.incident_reporting else ()),
        *(inputs.kyc_aml_subjects if applicability.kyc_aml else ()),
        *(
            item
            for item in inputs.regulated_processes
            if item.domain in required_domains
        ),
        *(inputs.export_transactions if applicability.export_controls else ()),
        *(inputs.retention_records if applicability.records_retention else ()),
        *(inputs.models if applicability.model_risk else ()),
    )


def _applicable(inputs: RegulatedControlsInput, gate: ComplianceGate) -> bool:
    applicability = inputs.policy.applicability
    return {
        "evidence": _has_applicable_control_domain(applicability),
        "policy_controls": applicability.policy_controls,
        "assessments": applicability.assessments,
        "incident_reporting": applicability.incident_reporting,
        "kyc_aml": applicability.kyc_aml,
        "regulated_quality": bool(applicability.regulated_domains),
        "export_controls": applicability.export_controls,
        "records_retention": applicability.records_retention,
        "model_risk": applicability.model_risk,
    }[gate]


def evaluate_regulated_controls(
    inputs: RegulatedControlsInput | Mapping[str, Any],
) -> RegulatedControlsResult:
    """Evaluate regulated controls without performing a regulated action."""

    inputs = revalidate_model_boundary(RegulatedControlsInput, inputs)
    as_of = _parsed(inputs.analysis_as_of)
    findings: list[RegulatedControlFinding] = []
    proposals: list[ComplianceObligationProposal] = []

    def add(
        code: str,
        gate: ComplianceGate,
        severity: FindingSeverity,
        message: str,
        *,
        subject_ref: str | None = None,
        action: str | None = None,
        due_at: str | None = None,
    ) -> None:
        findings.append(
            RegulatedControlFinding(
                code=code,
                gate=gate,
                severity=severity,
                message=message,
                subject_ref=subject_ref,
            )
        )
        if action is not None:
            proposals.append(
                ComplianceObligationProposal(
                    obligation_ref=f"obligation:{gate}:{subject_ref or code}:{code}",
                    gate=gate,
                    action=action,
                    subject_ref=subject_ref,
                    due_at=due_at,
                )
            )

    evidence_refs: dict[str, PrimitiveEvidenceRef] = {}
    for item in _all_items(inputs):
        for evidence in item.evidence_refs:
            evidence_refs[evidence.evidence_ref] = evidence
            observed = _parsed(evidence.observed_at)
            if observed > as_of:
                add(
                    "evidence_observed_in_future",
                    "evidence",
                    "indeterminate",
                    "Evidence was observed after the analysis timestamp.",
                    subject_ref=evidence.evidence_ref,
                    action="collect_evidence",
                )
            if (
                evidence.effective_at is not None
                and _parsed(evidence.effective_at) > as_of
            ):
                add(
                    "evidence_effective_in_future",
                    "evidence",
                    "indeterminate",
                    "Evidence does not become effective until after the analysis timestamp.",
                    subject_ref=evidence.evidence_ref,
                    action="collect_evidence",
                )
            if as_of - observed > timedelta(hours=inputs.policy.max_evidence_age_hours):
                add(
                    "evidence_stale",
                    "evidence",
                    "indeterminate",
                    "Evidence exceeds the configured maximum age.",
                    subject_ref=evidence.evidence_ref,
                    action="collect_evidence",
                )
            if (
                _GRADE[evidence.verification_grade]
                < _GRADE[inputs.policy.minimum_evidence_grade]
            ):
                add(
                    "evidence_grade_below_policy",
                    "evidence",
                    "indeterminate",
                    "Evidence verification grade is below policy.",
                    subject_ref=evidence.evidence_ref,
                    action="collect_evidence",
                )

    applicability = inputs.policy.applicability
    required_collections: tuple[tuple[bool, Sequence[Any], ComplianceGate], ...] = (
        (applicability.policy_controls, inputs.policy_controls, "policy_controls"),
        (applicability.assessments, inputs.assessments, "assessments"),
        (applicability.incident_reporting, inputs.incidents, "incident_reporting"),
        (applicability.kyc_aml, inputs.kyc_aml_subjects, "kyc_aml"),
        (applicability.export_controls, inputs.export_transactions, "export_controls"),
        (
            applicability.records_retention,
            inputs.retention_records,
            "records_retention",
        ),
        (applicability.model_risk, inputs.models, "model_risk"),
    )
    for required, collection, gate in required_collections:
        if required and not collection:
            add(
                f"{gate}_evidence_missing",
                gate,
                "indeterminate",
                f"{gate.replace('_', ' ').title()} is applicable but no snapshot was supplied.",
                action={
                    "policy_controls": "test_control",
                    "assessments": "complete_assessment",
                    "incident_reporting": "review_incident_reporting",
                    "kyc_aml": "complete_kyc_review",
                    "export_controls": "review_export_transaction",
                    "records_retention": "review_record_disposition",
                    "model_risk": "validate_model",
                }[gate],
            )

    required_domains = set(applicability.regulated_domains)
    supplied_domains = {item.domain for item in inputs.regulated_processes}
    for domain in sorted(required_domains - supplied_domains):
        add(
            "regulated_domain_evidence_missing",
            "regulated_quality",
            "indeterminate",
            f"Required regulated domain {domain} has no supplied process snapshot.",
            subject_ref=domain,
            action="remediate_regulated_process",
        )

    for control in inputs.policy_controls:
        if not applicability.policy_controls:
            continue
        if (
            control.last_tested_at is not None
            and _parsed(control.last_tested_at) > as_of
        ):
            add(
                "control_test_in_future",
                "policy_controls",
                "indeterminate",
                "A control test is dated after the analysis timestamp.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )
        if control.implementation_status in {"ineffective", "not_implemented"}:
            add(
                "control_not_effective",
                "policy_controls",
                "blocking",
                "A required policy control is not effective.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )
        elif control.implementation_status == "partially_effective":
            add(
                "control_partially_effective",
                "policy_controls",
                "review",
                "A policy control is only partially effective.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )
        if control.test_status in {"failed", "not_tested"}:
            add(
                "control_test_not_satisfied",
                "policy_controls",
                "blocking",
                "A required control test has not passed.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )
        elif control.test_status == "exceptions" or control.open_exception_count:
            add(
                "control_test_exception_open",
                "policy_controls",
                "review",
                "A control test has open exceptions.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )
        if control.last_tested_at is None or as_of - _parsed(
            control.last_tested_at
        ) > timedelta(days=inputs.policy.maximum_control_test_age_days):
            add(
                "control_test_stale",
                "policy_controls",
                "review",
                "A control test is missing or older than policy permits.",
                subject_ref=control.control_ref,
                action="test_control",
                due_at=control.next_test_due_at,
            )

    for assessment in inputs.assessments:
        if not applicability.assessments:
            continue
        if _parsed(assessment.assessed_at) > as_of:
            add(
                "assessment_in_future",
                "assessments",
                "indeterminate",
                "A compliance assessment is dated after the analysis timestamp.",
                subject_ref=assessment.assessment_ref,
                action="complete_assessment",
            )
        if assessment.status != "complete":
            add(
                "assessment_not_complete",
                "assessments",
                "blocking",
                "A required compliance assessment is not complete.",
                subject_ref=assessment.assessment_ref,
                action="complete_assessment",
            )
        if as_of - _parsed(assessment.assessed_at) > timedelta(
            days=inputs.policy.maximum_assessment_age_days
        ):
            add(
                "assessment_stale",
                "assessments",
                "review",
                "A compliance assessment is older than policy permits.",
                subject_ref=assessment.assessment_ref,
                action="complete_assessment",
            )
        if assessment.material_finding_count or assessment.remediation_overdue_count:
            add(
                "assessment_material_findings_open",
                "assessments",
                "blocking" if assessment.remediation_overdue_count else "review",
                "A compliance assessment has open material findings.",
                subject_ref=assessment.assessment_ref,
                action="complete_assessment",
            )

    for incident in inputs.incidents:
        if not applicability.incident_reporting:
            continue
        if _parsed(incident.discovered_at) > as_of:
            add(
                "incident_discovered_in_future",
                "incident_reporting",
                "indeterminate",
                "An incident discovery is dated after the analysis timestamp.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
            )
        if incident.contained_at is not None and _parsed(incident.contained_at) > as_of:
            add(
                "incident_contained_in_future",
                "incident_reporting",
                "indeterminate",
                "Incident containment is dated after the analysis timestamp.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
            )
        if incident.reported_at is not None and _parsed(incident.reported_at) > as_of:
            add(
                "incident_reported_in_future",
                "incident_reporting",
                "indeterminate",
                "Incident reporting is dated after the analysis timestamp.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
            )
        due_at = incident.report_due_at or (
            _parsed(incident.discovered_at)
            + timedelta(hours=inputs.policy.incident_report_deadline_hours)
        ).isoformat().replace("+00:00", "Z")
        if incident.status == "open" and incident.severity in {"high", "critical"}:
            add(
                "material_incident_not_contained",
                "incident_reporting",
                "blocking",
                "A material incident is not contained.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
                due_at=due_at,
            )
        reported_after_deadline = incident.reported_at is not None and _parsed(
            incident.reported_at
        ) > _parsed(due_at)
        if reported_after_deadline or (
            as_of > _parsed(due_at) and incident.reported_at is None
        ):
            add(
                "incident_reporting_deadline_missed",
                "incident_reporting",
                "blocking",
                "An applicable incident reporting deadline passed without evidence of reporting.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
                due_at=due_at,
            )
        elif incident.reported_at is None and incident.status != "closed":
            add(
                "incident_reporting_review_required",
                "incident_reporting",
                "review",
                "Incident reporting applicability requires authorized review.",
                subject_ref=incident.incident_ref,
                action="review_incident_reporting",
                due_at=due_at,
            )

    for subject in inputs.kyc_aml_subjects:
        if not applicability.kyc_aml:
            continue
        if _parsed(subject.reviewed_at) > as_of:
            add(
                "kyc_review_in_future",
                "kyc_aml",
                "indeterminate",
                "A KYC/AML review is dated after the analysis timestamp.",
                subject_ref=subject.subject_ref,
                action="complete_kyc_review",
                due_at=subject.next_review_due_at,
            )
        blocking = (
            subject.status in {"rejected", "expired"}
            or subject.risk_rating == "prohibited"
            or subject.sanctions_status == "confirmed_match"
            or subject.pep_status == "confirmed_match"
            or not subject.beneficial_ownership_verified
        )
        unresolved = (
            subject.status == "pending"
            or subject.sanctions_status in {"possible_match", "not_screened"}
            or subject.pep_status in {"possible_match", "not_screened"}
            or subject.adverse_media_status in {"review", "material", "not_screened"}
            or as_of > _parsed(subject.next_review_due_at)
            or as_of - _parsed(subject.reviewed_at)
            > timedelta(days=inputs.policy.maximum_kyc_review_age_days)
        )
        if blocking:
            add(
                "kyc_aml_subject_blocked",
                "kyc_aml",
                "blocking",
                "KYC/AML evidence contains a blocking status or confirmed match.",
                subject_ref=subject.subject_ref,
                action="complete_kyc_review",
                due_at=subject.next_review_due_at,
            )
        elif unresolved:
            add(
                "kyc_aml_review_required",
                "kyc_aml",
                "review",
                "KYC/AML review is incomplete, stale, or contains an unresolved signal.",
                subject_ref=subject.subject_ref,
                action="complete_kyc_review",
                due_at=subject.next_review_due_at,
            )

    for process in inputs.regulated_processes:
        if process.domain not in required_domains:
            continue
        expired = process.valid_until is not None and as_of > _parsed(
            process.valid_until
        )
        if (
            process.status in {"suspended", "expired"}
            or expired
            or process.release_blocked
            or process.overdue_capa_count
        ):
            add(
                "regulated_process_blocked",
                "regulated_quality",
                "blocking",
                "A regulated process is suspended, expired, release-blocked, or has overdue CAPA.",
                subject_ref=process.process_ref,
                action="remediate_regulated_process",
                due_at=process.valid_until,
            )
        elif process.status == "conditional" or process.open_deviation_count:
            add(
                "regulated_process_review_required",
                "regulated_quality",
                "review",
                "A regulated process is conditional or has open deviations.",
                subject_ref=process.process_ref,
                action="remediate_regulated_process",
                due_at=process.valid_until,
            )

    for transaction in inputs.export_transactions:
        if not applicability.export_controls:
            continue
        license_missing = (
            transaction.license_required and transaction.license_ref is None
        )
        license_expired = (
            transaction.license_valid_until is not None
            and as_of > _parsed(transaction.license_valid_until)
        )
        if (
            transaction.party_screening_status == "denied_party"
            or transaction.destination_status == "embargoed"
            or license_missing
            or license_expired
        ):
            add(
                "export_transaction_blocked",
                "export_controls",
                "blocking",
                "Export transaction evidence contains a denied party, embargo, or invalid license.",
                subject_ref=transaction.transaction_ref,
                action="review_export_transaction",
                due_at=transaction.license_valid_until,
            )
        elif (
            transaction.item_classification_ref is None
            or transaction.party_screening_status in {"possible_match", "not_screened"}
            or transaction.destination_status in {"restricted", "not_screened"}
        ):
            add(
                "export_transaction_review_required",
                "export_controls",
                "review",
                "Export classification, screening, or destination review is incomplete.",
                subject_ref=transaction.transaction_ref,
                action="review_export_transaction",
                due_at=transaction.license_valid_until,
            )

    for record in inputs.retention_records:
        if not applicability.records_retention:
            continue
        if _parsed(record.created_at) > as_of:
            add(
                "record_created_in_future",
                "records_retention",
                "indeterminate",
                "A retained record set is dated after the analysis timestamp.",
                subject_ref=record.record_set_ref,
                action="review_record_disposition",
                due_at=record.retain_until,
            )
        if record.disposed_at is not None and _parsed(record.disposed_at) > as_of:
            add(
                "record_disposed_in_future",
                "records_retention",
                "indeterminate",
                "Record disposition is dated after the analysis timestamp.",
                subject_ref=record.record_set_ref,
                action="review_record_disposition",
                due_at=record.retain_until,
            )
        retain_until = _parsed(record.retain_until)
        disposed_early = (
            record.disposition_status == "disposed"
            and record.disposed_at is not None
            and _parsed(record.disposed_at) < retain_until
        )
        if record.legal_hold and record.disposition_status in {
            "disposition_approved",
            "disposed",
        }:
            add(
                "record_disposition_conflicts_with_legal_hold",
                "records_retention",
                "blocking",
                "Record disposition conflicts with an active legal hold.",
                subject_ref=record.record_set_ref,
                action="review_record_disposition",
                due_at=record.retain_until,
            )
        elif disposed_early:
            add(
                "record_disposed_before_retention_end",
                "records_retention",
                "blocking",
                "A record set was disposed before its retention period ended.",
                subject_ref=record.record_set_ref,
                action="review_record_disposition",
                due_at=record.retain_until,
            )
        elif as_of >= retain_until and record.disposition_status == "retained":
            add(
                "record_disposition_review_due",
                "records_retention",
                "review",
                "A retained record set reached its disposition review date.",
                subject_ref=record.record_set_ref,
                action="review_record_disposition",
                due_at=record.retain_until,
            )

    for model in inputs.models:
        if not applicability.model_risk:
            continue
        if model.validated_at is not None and _parsed(model.validated_at) > as_of:
            add(
                "model_validation_in_future",
                "model_risk",
                "indeterminate",
                "Model validation is dated after the analysis timestamp.",
                subject_ref=model.model_ref,
                action="validate_model",
            )
        validation_stale = model.validated_at is None or as_of - _parsed(
            model.validated_at
        ) > timedelta(days=inputs.policy.maximum_model_validation_age_days)
        if (
            model.inventory_status == "unregistered"
            or model.validation_status in {"failed", "not_validated"}
            or model.approved_use_ref is None
            or model.monitoring_status == "breach"
            or model.drift_threshold_breached
            or model.bias_threshold_breached
            or not model.latest_change_approved
        ):
            add(
                "model_risk_control_blocked",
                "model_risk",
                "blocking",
                "Model-risk evidence contains an unapproved use, failed control, or limit breach.",
                subject_ref=model.model_ref,
                action="validate_model",
            )
        elif (
            model.validation_status == "conditional"
            or model.monitoring_status in {"warning", "not_monitored"}
            or validation_stale
        ):
            add(
                "model_risk_review_required",
                "model_risk",
                "review",
                "Model validation or monitoring requires authorized review.",
                subject_ref=model.model_ref,
                action="validate_model",
            )

    gates: list[RegulatedGateResult] = []
    for gate in _GATES:
        gate_findings = [finding for finding in findings if finding.gate == gate]
        if not _applicable(inputs, gate):
            status: GateStatus = "not_applicable"
        elif any(finding.severity == "blocking" for finding in gate_findings):
            status = "fail"
        elif any(finding.severity == "indeterminate" for finding in gate_findings):
            status = "indeterminate"
        elif any(finding.severity == "review" for finding in gate_findings):
            status = "review"
        else:
            status = "pass"
        gates.append(
            RegulatedGateResult(
                gate=gate,
                status=status,
                finding_codes=tuple(
                    sorted({finding.code for finding in gate_findings})
                ),
            )
        )

    has_applicable_domain = _has_applicable_control_domain(applicability)
    disposition: ComplianceDisposition
    if not has_applicable_domain:
        disposition = "indeterminate"
    elif any(gate.status == "fail" for gate in gates):
        disposition = "blocked"
    elif any(gate.status == "indeterminate" for gate in gates):
        disposition = "indeterminate"
    elif any(gate.status == "review" for gate in gates):
        disposition = "manual_review_required"
    else:
        disposition = "controls_satisfied"

    assurance_grade = (
        min(
            (ref.verification_grade for ref in evidence_refs.values()),
            key=lambda grade: _GRADE[grade],
            default=PrimitiveEvidenceVerificationGrade.UNVERIFIED,
        )
        if has_applicable_domain
        else PrimitiveEvidenceVerificationGrade.UNVERIFIED
    )
    snapshots: dict[str, str] = {"policy": regulated_snapshot_digest(inputs.policy)}
    for prefix, values, field in (
        ("control", inputs.policy_controls, "control_ref"),
        ("assessment", inputs.assessments, "assessment_ref"),
        ("incident", inputs.incidents, "incident_ref"),
        ("kyc", inputs.kyc_aml_subjects, "subject_ref"),
        ("regulated_process", inputs.regulated_processes, "process_ref"),
        ("export", inputs.export_transactions, "transaction_ref"),
        ("retention", inputs.retention_records, "record_set_ref"),
        ("model", inputs.models, "model_ref"),
    ):
        snapshots.update(
            {
                f"{prefix}:{getattr(item, field)}": regulated_snapshot_digest(item)
                for item in values
            }
        )
    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda finding: (
                _GATES.index(finding.gate),
                finding.subject_ref or "",
                finding.code,
            ),
        )
    )
    ordered_proposals = tuple(
        sorted(
            {proposal.obligation_ref: proposal for proposal in proposals}.values(),
            key=lambda proposal: proposal.obligation_ref,
        )
    )
    return RegulatedControlsResult(
        evaluation_ref=inputs.evaluation_ref,
        analysis_as_of=inputs.analysis_as_of,
        assurance_grade=assurance_grade,
        applicability=inputs.policy.applicability,
        proposed_disposition=disposition,
        gates=tuple(gates),
        findings=ordered_findings,
        obligation_proposals=ordered_proposals,
        source_snapshot_digests=snapshots,
        evidence_refs=tuple(sorted(evidence_refs)),
    )


def _example_evidence(ref: str, character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": "normalized_regulated_snapshot",
        "issuer_ref": "spring-compliance-authority",
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "restricted",
        "retention_policy": "regulated-seven-years",
        "jurisdiction": "US",
    }


class EvaluateRegulatedControlsPrimitive(
    BusinessProcessPrimitive[RegulatedControlsInput, RegulatedControlsResult]
):
    primitive_ref = "compliance.evaluate_regulated_controls"
    version = "1.0.0"
    title = "Evaluate regulated controls"
    description = (
        "Evaluate evidence-bound policy, incident, KYC/AML, regulated quality, "
        "export, retention, and model-risk controls without performing a regulated action."
    )
    input_model = RegulatedControlsInput
    output_model = RegulatedControlsResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "evaluation_ref": "regulated-review-2026-q3",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "policy_controls": [
            {
                "control_ref": "control-access-review",
                "policy_ref": "policy-security-v3",
                "framework_refs": ["soc2-cc6"],
                "owner_ref": "security-owner",
                "implementation_status": "effective",
                "test_status": "passed",
                "last_tested_at": "2026-08-01T00:00:00Z",
                "next_test_due_at": "2027-08-01T00:00:00Z",
                "evidence_refs": [_example_evidence("control-evidence", "a")],
            }
        ],
        "assessments": [
            {
                "assessment_ref": "assessment-soc2-2026",
                "framework_ref": "soc2",
                "status": "complete",
                "assessed_at": "2026-08-01T00:00:00Z",
                "evidence_refs": [_example_evidence("assessment-evidence", "b")],
            }
        ],
        "incidents": [
            {
                "incident_ref": "incident-closed-1",
                "incident_type": "security_incident",
                "severity": "low",
                "status": "closed",
                "discovered_at": "2026-08-20T00:00:00Z",
                "contained_at": "2026-08-20T01:00:00Z",
                "reported_at": "2026-08-20T02:00:00Z",
                "jurisdiction_refs": ["US"],
                "evidence_refs": [_example_evidence("incident-evidence", "c")],
            }
        ],
        "retention_records": [
            {
                "record_set_ref": "records-finance-2026",
                "category_ref": "finance-records",
                "created_at": "2026-01-01T00:00:00Z",
                "retain_until": "2033-01-01T00:00:00Z",
                "disposition_status": "retained",
                "evidence_refs": [_example_evidence("retention-evidence", "d")],
            }
        ],
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = REGULATED_CONTROLS_OPERATION.to_dict()
        contract["capability_hints"] = [
            "governance.list_controls",
            "governance.list_assessments",
            "security.list_incidents",
            "identity.get_kyc_profile",
            "quality.list_capa",
            "records.list_retention_state",
            "models.get_validation_state",
        ]
        contract["capability_hints_are_dispatch_authority"] = False
        contract["effect_boundary"] = ComplianceEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "sdk": "deterministic_control_evaluation_only",
            "spring": [
                "tenant_and_company_scope",
                "rbac",
                "source_normalization",
                "approval_authority",
                "persistence_and_audit",
            ],
            "connectors": "governed_reads_and_writes_via_trusted_host_only",
            "filing_and_reporting_authority": "never_granted_by_this_primitive",
            "record_disposition_authority": "never_granted_by_this_primitive",
            "model_deployment_authority": "never_granted_by_this_primitive",
        }
        contract["recovery_semantics"] = {
            "external_operations": 0,
            "replay_class": "safe",
            "crash_recovery": "not_required",
            "same_input_same_result_digest": True,
            "source_refresh_owned_by": "trusted_host",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: RegulatedControlsInput,
    ) -> PrimitiveExecutionResult[RegulatedControlsResult]:
        del context
        output = evaluate_regulated_controls(inputs)
        evidence_by_ref = {
            evidence.evidence_ref: evidence
            for item in _all_items(inputs)
            for evidence in item.evidence_refs
        }
        evidence_refs = [evidence_by_ref[ref] for ref in sorted(evidence_by_ref)]
        receipt = PrimitiveOperationReceipt(
            spec=REGULATED_CONTROLS_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=regulated_snapshot_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[RegulatedControlsResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Regulated controls evaluated with proposed disposition "
                f"{output.proposed_disposition}; no regulated action was performed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="compliance.regulated_controls_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "proposed_disposition": output.proposed_disposition,
                        "finding_count": len(output.findings),
                        "regulated_actions_performed": 0,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="regulated_control_result",
                    summary=(
                        "The SDK evaluated normalized regulated evidence without "
                        "filing, approving, disposing, deploying, or mutating systems."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "REGULATED_CONTROLS_INPUT_SCHEMA",
    "REGULATED_CONTROLS_RESULT_SCHEMA",
    "REGULATED_CONTROLS_OPERATION",
    "ComplianceApplicability",
    "ComplianceAssessmentSnapshot",
    "ComplianceEffectBoundary",
    "ComplianceObligationProposal",
    "EvaluateRegulatedControlsPrimitive",
    "ExportControlSnapshot",
    "IncidentReportingSnapshot",
    "KycAmlSnapshot",
    "ModelRiskSnapshot",
    "PolicyControlSnapshot",
    "RegulatedControlFinding",
    "RegulatedControlPolicy",
    "RegulatedControlsInput",
    "RegulatedControlsResult",
    "RegulatedGateResult",
    "RegulatedProcessSnapshot",
    "RetentionRecordSnapshot",
    "evaluate_regulated_controls",
    "regulated_snapshot_digest",
]
