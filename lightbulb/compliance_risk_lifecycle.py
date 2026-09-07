"""Deterministic compliance, risk, and regulated-operations case lifecycles.

This module materializes portable, immutable candidate projections for
independent, exactly scoped case tracks.  Policy/control ownership, control
testing, and compliance assessment form one ordered three-stage track;
incident/breach, KYC/AML, regulated quality, export control, retention/legal
hold, and model-risk reviews are separate bounded tracks.  It never
authenticates an actor, decides a legal obligation, submits a filing, applies
a hold, approves an account, accepts risk, persists an approval, writes an
audit record, or invokes a connector.

Spring and the relevant regulated systems remain authoritative for identity,
RBAC, legal and regulatory determinations, filings, holds, account decisions,
risk acceptance, persistence, approvals, audit, and external effects.
Structural separation-of-duties checks here are proposal-time guards only;
Spring must authenticate every actor and verify every role assignment.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
from lightbulb.primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveEvidenceClassification,
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


COMPLIANCE_RISK_SCOPE_SCHEMA = "lightbulb.compliance_risk_scope.v2"
COMPLIANCE_RISK_SNAPSHOT_SCHEMA = "lightbulb.compliance_risk_lifecycle_snapshot.v2"
COMPLIANCE_RISK_COMMAND_SCHEMA = "lightbulb.compliance_risk_transition_command.v2"
COMPLIANCE_RISK_INPUT_SCHEMA = "lightbulb.compliance_risk_lifecycle_input.v2"
COMPLIANCE_RISK_RECEIPT_SCHEMA = "lightbulb.compliance_risk_transition_receipt.v2"
COMPLIANCE_RISK_RESULT_SCHEMA = "lightbulb.compliance_risk_lifecycle_result.v2"

GENESIS_STATE_DIGEST = "0" * 64
MAX_COMPLIANCE_RISK_TRANSITIONS = 3
MINIMUM_EVIDENCE_RETENTION_YEARS = 7
MAXIMUM_EVIDENCE_AGE_HOURS = 720

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("references must contain visible non-whitespace characters")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


def _integer_literal(value: Any) -> Any:
    if isinstance(value, bool):
        raise ValueError("integer fields cannot use boolean values")
    return value


def _boolean_literal(value: Any) -> Any:
    if not isinstance(value, bool):
        raise ValueError("boolean fields require JSON boolean values")
    return value


StrictZero = Annotated[Literal[0], BeforeValidator(_integer_literal)]
StrictOne = Annotated[Literal[1], BeforeValidator(_integer_literal)]
StrictTwo = Annotated[Literal[2], BeforeValidator(_integer_literal)]
StrictBool = Annotated[bool, BeforeValidator(_boolean_literal)]
StrictTrue = Annotated[Literal[True], BeforeValidator(_boolean_literal)]
StrictFalse = Annotated[Literal[False], BeforeValidator(_boolean_literal)]

TransitionKind = Literal[
    "establish_policy_control",
    "test_control",
    "complete_compliance_assessment",
    "review_incident_breach",
    "review_kyc_aml_case",
    "review_regulated_quality",
    "review_export_control",
    "review_retention_legal_hold",
    "review_model_risk",
]
ComplianceRiskCaseKind = Literal[
    "policy_control_assessment",
    "incident_breach",
    "kyc_aml",
    "regulated_quality",
    "export_control",
    "retention_legal_hold",
    "model_risk",
]
RegulatedDomain = Literal[
    "clinical",
    "regulatory",
    "gmp",
    "qms",
    "safety",
    "certification",
]
LifecycleStatus = Literal[
    "policy_control_established",
    "control_tested",
    "assessment_completed",
    "incident_breach_reviewed",
    "kyc_aml_reviewed",
    "regulated_quality_reviewed",
    "export_control_reviewed",
    "retention_legal_hold_reviewed",
    "model_risk_reviewed",
]

_CASE_TRANSITION_SEQUENCE: dict[ComplianceRiskCaseKind, tuple[TransitionKind, ...]] = {
    "policy_control_assessment": (
        "establish_policy_control",
        "test_control",
        "complete_compliance_assessment",
    ),
    "incident_breach": ("review_incident_breach",),
    "kyc_aml": ("review_kyc_aml_case",),
    "regulated_quality": ("review_regulated_quality",),
    "export_control": ("review_export_control",),
    "retention_legal_hold": ("review_retention_legal_hold",),
    "model_risk": ("review_model_risk",),
}
_STATUS_BY_COMMAND: dict[TransitionKind, LifecycleStatus] = {
    "establish_policy_control": "policy_control_established",
    "test_control": "control_tested",
    "complete_compliance_assessment": "assessment_completed",
    "review_incident_breach": "incident_breach_reviewed",
    "review_kyc_aml_case": "kyc_aml_reviewed",
    "review_regulated_quality": "regulated_quality_reviewed",
    "review_export_control": "export_control_reviewed",
    "review_retention_legal_hold": "retention_legal_hold_reviewed",
    "review_model_risk": "model_risk_reviewed",
}

_REQUIRED_EVIDENCE_KINDS: dict[TransitionKind, frozenset[str]] = {
    "establish_policy_control": frozenset({"policy_text", "control_ownership"}),
    "test_control": frozenset({"control_test", "test_workpaper"}),
    "complete_compliance_assessment": frozenset(
        {"compliance_assessment", "remediation_status"}
    ),
    "review_incident_breach": frozenset(
        {"incident_record", "legal_analysis", "regulatory_reporting"}
    ),
    "review_kyc_aml_case": frozenset(
        {
            "identity_verification",
            "beneficial_ownership",
            "sanctions_screening",
            "aml_review",
        }
    ),
    "review_regulated_quality": frozenset(),
    "review_export_control": frozenset(
        {
            "export_classification",
            "denied_party_screening",
            "destination_screening",
            "license_analysis",
        }
    ),
    "review_retention_legal_hold": frozenset(
        {"retention_schedule", "legal_hold_request", "custody_record"}
    ),
    "review_model_risk": frozenset(
        {"model_inventory", "model_validation", "model_monitoring", "model_risk_review"}
    ),
}
_QUALITY_EVIDENCE_KIND: dict[RegulatedDomain, str] = {
    "clinical": "clinical_record",
    "regulatory": "regulatory_record",
    "gmp": "gmp_record",
    "qms": "qms_record",
    "safety": "safety_record",
    "certification": "certification_record",
}
_VERIFIED_EVIDENCE_STAGES = frozenset(
    {
        "review_incident_breach",
        "review_kyc_aml_case",
        "review_regulated_quality",
        "review_export_control",
        "review_retention_legal_hold",
        "review_model_risk",
    }
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


def _calendar_years_after(value: datetime, years: int) -> datetime:
    try:
        return value.replace(year=value.year + years)
    except ValueError:
        # A February 29 anniversary expires at the end of February in a
        # non-leap target year, never a fixed-day approximation before it.
        return value.replace(year=value.year + years, day=28)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def _sorted_unique_tuple(value: Any, *, label: str) -> tuple[str, ...]:
    items = _as_tuple(value)
    if not isinstance(items, tuple):
        return items
    _unique(list(items), label=label)
    return tuple(sorted(items))


def _distinct_actors(*actors: str, label: str) -> None:
    if len(actors) != len(set(actors)):
        raise ValueError(f"{label} requires structurally distinct actors")


class ComplianceRiskScope(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_scope.v2"] = Field(
        default=COMPLIANCE_RISK_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    jurisdiction_ref: OpaqueRef
    regime_ref: OpaqueRef
    case_ref: OpaqueRef
    case_kind: ComplianceRiskCaseKind
    subject_ref: OpaqueRef
    model_ref: OpaqueRef | None = None
    applicable_quality_domains: tuple[RegulatedDomain, ...] = Field(
        default_factory=tuple,
        max_length=6,
    )
    evidence_custody_ref: OpaqueRef
    authorized_evidence_issuer_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @field_validator("project_id", mode="before")
    @classmethod
    def _canonical_project_id(cls, value: Any) -> UUID:
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("project_id must be a canonical UUID")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("project_id must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError("project_id must be a canonical UUID")
        return parsed

    @field_validator("authorized_evidence_issuer_refs", mode="before")
    @classmethod
    def _issuer_refs_tuple(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="authorized evidence issuers")

    @field_validator("applicable_quality_domains", mode="before")
    @classmethod
    def _quality_domains_tuple(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="applicable quality domains")

    @model_validator(mode="after")
    def _conditional_scope_is_exact(self) -> "ComplianceRiskScope":
        if self.case_kind == "regulated_quality":
            if not self.applicable_quality_domains:
                raise ValueError(
                    "regulated-quality scope requires applicable quality domains"
                )
        elif self.applicable_quality_domains:
            raise ValueError("only regulated-quality scope may declare quality domains")
        if self.case_kind == "model_risk":
            if self.model_ref is None:
                raise ValueError("model-risk scope requires model_ref")
        elif self.model_ref is not None:
            raise ValueError("only model-risk scope may declare model_ref")
        return self


def compliance_risk_scope_digest(
    scope: ComplianceRiskScope | Mapping[str, Any],
) -> str:
    parsed = ComplianceRiskScope.model_validate(_detached_validation_payload(scope))
    return _stable_digest(parsed.to_dict())


class RegulatedEvidenceEnvelope(_StrictModel):
    schema_id: Literal["lightbulb.regulated_evidence_envelope.v1"] = Field(
        default="lightbulb.regulated_evidence_envelope.v1", alias="schema"
    )
    sequence: int = Field(ge=1, le=500)
    use_ref: OpaqueRef
    artifact_ref: OpaqueRef
    artifact_digest: Sha256Digest
    predecessor_lineage_digest: Sha256Digest
    lineage_digest: Sha256Digest
    custody_ref: OpaqueRef
    retained_until: str
    single_use: StrictTrue = True
    reference: PrimitiveEvidenceRef

    @field_validator("reference", mode="before")
    @classmethod
    def _reference_is_revalidated(cls, value: Any) -> Any:
        # PrimitiveEvidenceRef is a shared v1 contract whose own configuration
        # predates always-on instance revalidation.  Detach it here so a caller
        # cannot smuggle a model_copy-forged reference through this v2 boundary.
        return _detached_validation_payload(value)

    @field_validator("retained_until")
    @classmethod
    def _retained_until(cls, value: str) -> str:
        return _timestamp(value, field_name="retained_until")


class _PackageBase(_StrictModel):
    revision: StrictOne = 1
    evidence_use_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("evidence_use_refs", mode="before")
    @classmethod
    def _evidence_refs_tuple(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="package evidence use references")


class PolicyControlOwnershipPackage(_PackageBase):
    kind: Literal["establish_policy_control"] = "establish_policy_control"
    policy_ref: OpaqueRef
    control_ref: OpaqueRef
    framework_ref: OpaqueRef
    policy_revision: StrictOne = 1
    control_revision: StrictOne = 1
    owner_ref: OpaqueRef
    prepared_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef
    implementation_status: Literal["effective"] = "effective"
    owner_acknowledged: StrictTrue = True

    @model_validator(mode="after")
    def _ownership_is_separated(self) -> "PolicyControlOwnershipPackage":
        _distinct_actors(
            self.owner_ref,
            self.prepared_by_ref,
            self.reviewed_by_ref,
            label="policy/control preparation, ownership, and review",
        )
        return self


class ControlTestEvidencePackage(_PackageBase):
    kind: Literal["test_control"] = "test_control"
    policy_ref: OpaqueRef
    control_ref: OpaqueRef
    owner_ref: OpaqueRef
    control_revision: StrictTwo = 2
    test_ref: OpaqueRef
    test_result: Literal["passed"] = "passed"
    tested_at: str
    next_test_due_at: str
    exception_count: StrictZero = 0
    tested_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef

    @field_validator("tested_at", "next_test_due_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _test_is_independent(self) -> "ControlTestEvidencePackage":
        if _parsed_timestamp(self.next_test_due_at) <= _parsed_timestamp(
            self.tested_at
        ):
            raise ValueError("next control test must be due after the completed test")
        _distinct_actors(
            self.owner_ref,
            self.tested_by_ref,
            self.reviewed_by_ref,
            label="control owner, tester, and reviewer",
        )
        return self


class ComplianceAssessmentPackage(_PackageBase):
    kind: Literal["complete_compliance_assessment"] = "complete_compliance_assessment"
    policy_ref: OpaqueRef
    control_ref: OpaqueRef
    control_test_ref: OpaqueRef
    assessment_ref: OpaqueRef
    framework_ref: OpaqueRef
    status: Literal["complete"] = "complete"
    assessed_at: str
    material_finding_count: StrictZero = 0
    remediation_overdue_count: StrictZero = 0
    assessor_ref: OpaqueRef
    regulatory_reviewer_ref: OpaqueRef

    @field_validator("assessed_at")
    @classmethod
    def _assessed_at(cls, value: str) -> str:
        return _timestamp(value, field_name="assessed_at")

    @model_validator(mode="after")
    def _assessment_is_independent(self) -> "ComplianceAssessmentPackage":
        _distinct_actors(
            self.assessor_ref,
            self.regulatory_reviewer_ref,
            label="assessment and regulatory review",
        )
        return self


class IncidentBreachPackage(_PackageBase):
    kind: Literal["review_incident_breach"] = "review_incident_breach"
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
    report_due_at: str
    reported_at: str | None = None
    closed_at: str | None = None
    closure_candidate_ref: OpaqueRef | None = None
    jurisdiction_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    reporting_candidate_ref: OpaqueRef
    reported_by_ref: OpaqueRef
    legal_reviewer_ref: OpaqueRef
    regulatory_reviewer_ref: OpaqueRef

    @field_validator(
        "discovered_at",
        "contained_at",
        "report_due_at",
        "reported_at",
        "closed_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("jurisdiction_refs", mode="before")
    @classmethod
    def _jurisdictions(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="incident jurisdictions")

    @model_validator(mode="after")
    def _incident_timeline_is_fail_closed(self) -> "IncidentBreachPackage":
        discovered = _parsed_timestamp(self.discovered_at)
        due = _parsed_timestamp(self.report_due_at)
        maximum_hours = {"critical": 24, "high": 48, "moderate": 72, "low": 168}[
            self.severity
        ]
        if due <= discovered or due > discovered + timedelta(hours=maximum_hours):
            raise ValueError("incident reporting deadline exceeds the severity floor")
        if (
            self.contained_at is not None
            and _parsed_timestamp(self.contained_at) < discovered
        ):
            raise ValueError("incident containment cannot precede discovery")
        if self.severity in {"critical", "high"} and self.status not in {
            "reported",
            "closed",
        }:
            raise ValueError("high and critical incidents require reported status")
        if self.status in {"reported", "closed"}:
            if self.reported_at is None or _parsed_timestamp(self.reported_at) > due:
                raise ValueError(
                    "reported incidents require timely reported_at evidence"
                )
            if _parsed_timestamp(self.reported_at) < discovered:
                raise ValueError("incident reporting cannot precede discovery")
        elif self.reported_at is not None:
            raise ValueError("unreported incident status cannot carry reported_at")
        if self.status == "closed":
            if (
                self.closed_at is None
                or self.closure_candidate_ref is None
                or self.contained_at is None
            ):
                raise ValueError(
                    "closed incident candidate requires containment and closure evidence"
                )
            closure = _parsed_timestamp(self.closed_at)
            if closure < _parsed_timestamp(self.reported_at):
                raise ValueError("incident closure cannot precede reporting")
            if closure < _parsed_timestamp(self.contained_at):
                raise ValueError("incident closure cannot precede containment")
        elif self.closed_at is not None or self.closure_candidate_ref is not None:
            raise ValueError("only closed incident candidates may carry closure fields")
        _distinct_actors(
            self.reported_by_ref,
            self.legal_reviewer_ref,
            self.regulatory_reviewer_ref,
            label="incident reporter, legal reviewer, and regulatory reviewer",
        )
        return self


class KycAmlCasePackage(_PackageBase):
    kind: Literal["review_kyc_aml_case"] = "review_kyc_aml_case"
    case_ref: OpaqueRef
    subject_ref: OpaqueRef
    case_status: Literal["review_recommended"] = "review_recommended"
    risk_rating: Literal["low", "medium", "high"]
    beneficial_ownership_verified: StrictTrue = True
    sanctions_status: Literal["clear"] = "clear"
    pep_status: Literal["clear"] = "clear"
    adverse_media_status: Literal["clear"] = "clear"
    reviewed_at: str
    next_review_due_at: str
    analyst_ref: OpaqueRef
    aml_reviewer_ref: OpaqueRef
    account_decision_route: Literal["authoritative_system_required"] = (
        "authoritative_system_required"
    )

    @field_validator("reviewed_at", "next_review_due_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _kyc_review_is_independent(self) -> "KycAmlCasePackage":
        if _parsed_timestamp(self.next_review_due_at) <= _parsed_timestamp(
            self.reviewed_at
        ):
            raise ValueError("KYC/AML next review must follow the current review")
        _distinct_actors(
            self.analyst_ref,
            self.aml_reviewer_ref,
            label="KYC/AML analyst and reviewer",
        )
        return self


_REGULATED_DOMAINS = frozenset(
    {"clinical", "regulatory", "gmp", "qms", "safety", "certification"}
)


class RegulatedQualityRecord(_StrictModel):
    domain: RegulatedDomain
    record_ref: OpaqueRef
    revision: StrictOne = 1
    status: Literal["validated", "certified", "qualified"]
    validation_ref: OpaqueRef
    valid_until: str
    open_deviation_count: StrictZero = 0
    overdue_capa_count: StrictZero = 0
    release_blocked: StrictFalse = False
    reviewed_by_ref: OpaqueRef

    @field_validator("valid_until")
    @classmethod
    def _valid_until(cls, value: str) -> str:
        return _timestamp(value, field_name="valid_until")


class RegulatedQualityPackage(_PackageBase):
    kind: Literal["review_regulated_quality"] = "review_regulated_quality"
    record_set_ref: OpaqueRef
    applicable_domains: tuple[RegulatedDomain, ...] = Field(min_length=1, max_length=6)
    quality_owner_ref: OpaqueRef
    regulatory_reviewer_ref: OpaqueRef
    records: tuple[RegulatedQualityRecord, ...] = Field(min_length=1, max_length=6)

    @field_validator("applicable_domains", mode="before")
    @classmethod
    def _applicable_domains_tuple(cls, value: Any) -> Any:
        return _sorted_unique_tuple(value, label="applicable quality domains")

    @field_validator("records", mode="before")
    @classmethod
    def _records_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _applicable_regulated_domains_are_covered(self) -> "RegulatedQualityPackage":
        domains = [item.domain for item in self.records]
        if not frozenset(self.applicable_domains).issubset(_REGULATED_DOMAINS):
            raise ValueError("regulated quality package contains an unknown domain")
        if tuple(domains) != self.applicable_domains or len(domains) != len(
            set(domains)
        ):
            raise ValueError(
                "regulated quality records must exactly match applicable domains"
            )
        if tuple(domains) != tuple(sorted(domains)):
            raise ValueError(
                "regulated quality records must use canonical domain order"
            )
        _unique(
            [item.record_ref for item in self.records], label="regulated record refs"
        )
        _unique(
            [item.validation_ref for item in self.records],
            label="regulated validation refs",
        )
        if any(item.reviewed_by_ref == self.quality_owner_ref for item in self.records):
            raise ValueError(
                "regulated record reviewers must differ from the quality owner"
            )
        if any(
            item.reviewed_by_ref == self.regulatory_reviewer_ref
            for item in self.records
        ):
            raise ValueError(
                "regulated record reviewers must differ from regulatory review"
            )
        _distinct_actors(
            self.quality_owner_ref,
            self.regulatory_reviewer_ref,
            label="quality ownership and regulatory review",
        )
        return self


class ExportControlPackage(_PackageBase):
    kind: Literal["review_export_control"] = "review_export_control"
    screening_ref: OpaqueRef
    transaction_ref: OpaqueRef
    subject_ref: OpaqueRef
    destination_jurisdiction: OpaqueRef
    item_classification_ref: OpaqueRef
    party_screening_status: Literal["clear"] = "clear"
    destination_status: Literal["permitted"] = "permitted"
    license_required: bool
    license_ref: OpaqueRef | None = None
    license_valid_until: str | None = None
    screened_by_ref: OpaqueRef
    export_reviewer_ref: OpaqueRef
    disposition_candidate: Literal["authoritative_decision_required"] = (
        "authoritative_decision_required"
    )

    @field_validator("license_valid_until")
    @classmethod
    def _license_valid_until(cls, value: str | None) -> str | None:
        return (
            None
            if value is None
            else _timestamp(value, field_name="license_valid_until")
        )

    @model_validator(mode="after")
    def _license_gate_is_exact(self) -> "ExportControlPackage":
        if self.license_required != (self.license_ref is not None):
            raise ValueError("license requirement and license reference must agree")
        if self.license_required != (self.license_valid_until is not None):
            raise ValueError("required export license needs a validity deadline")
        _distinct_actors(
            self.screened_by_ref,
            self.export_reviewer_ref,
            label="export screening and review",
        )
        return self


class RetentionLegalHoldPackage(_PackageBase):
    kind: Literal["review_retention_legal_hold"] = "review_retention_legal_hold"
    record_set_ref: OpaqueRef
    category_ref: OpaqueRef
    retention_policy_ref: OpaqueRef
    created_at: str
    retain_until: str
    legal_hold_required: StrictBool
    legal_hold_request_ref: OpaqueRef | None = None
    disposition_status: Literal["retained"] = "retained"
    custodian_ref: OpaqueRef
    legal_reviewer_ref: OpaqueRef

    @field_validator("created_at", "retain_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _retention_is_fail_closed(self) -> "RetentionLegalHoldPackage":
        if _parsed_timestamp(self.retain_until) <= _parsed_timestamp(self.created_at):
            raise ValueError("record retention must extend beyond record creation")
        if self.legal_hold_required != (self.legal_hold_request_ref is not None):
            raise ValueError(
                "legal-hold request reference must exactly match hold applicability"
            )
        _distinct_actors(
            self.custodian_ref,
            self.legal_reviewer_ref,
            label="record custody and legal-hold review",
        )
        return self


class ModelRiskPackage(_PackageBase):
    kind: Literal["review_model_risk"] = "review_model_risk"
    review_ref: OpaqueRef
    model_ref: OpaqueRef
    risk_tier: Literal["low", "medium", "high", "critical"]
    inventory_status: Literal["registered"] = "registered"
    validation_status: Literal["approved"] = "approved"
    validated_at: str
    approved_use_ref: OpaqueRef
    monitoring_status: Literal["within_limits"] = "within_limits"
    drift_threshold_breached: StrictFalse = False
    bias_threshold_breached: StrictFalse = False
    latest_change_approved: StrictTrue = True
    model_owner_ref: OpaqueRef
    validator_ref: OpaqueRef
    risk_reviewer_ref: OpaqueRef
    deployment_route: Literal["authoritative_system_required"] = (
        "authoritative_system_required"
    )

    @field_validator("validated_at")
    @classmethod
    def _validated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="validated_at")

    @model_validator(mode="after")
    def _model_review_is_independent(self) -> "ModelRiskPackage":
        _distinct_actors(
            self.model_owner_ref,
            self.validator_ref,
            self.risk_reviewer_ref,
            label="model ownership, validation, and risk review",
        )
        return self


ComplianceDomainPackage = Annotated[
    PolicyControlOwnershipPackage
    | ControlTestEvidencePackage
    | ComplianceAssessmentPackage
    | IncidentBreachPackage
    | KycAmlCasePackage
    | RegulatedQualityPackage
    | ExportControlPackage
    | RetentionLegalHoldPackage
    | ModelRiskPackage,
    Field(discriminator="kind"),
]


def _evidence_lineage_digest(
    envelope: Mapping[str, Any] | RegulatedEvidenceEnvelope,
) -> str:
    payload = (
        envelope.to_dict()
        if isinstance(envelope, RegulatedEvidenceEnvelope)
        else dict(envelope)
    )
    payload.pop("lineage_digest", None)
    return _stable_digest(payload)


class ComplianceRiskTransitionCommand(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_transition_command.v2"] = Field(
        default=COMPLIANCE_RISK_COMMAND_SCHEMA, alias="schema"
    )
    kind: TransitionKind
    scope: ComplianceRiskScope
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_COMPLIANCE_RISK_TRANSITIONS)
    expected_state_digest: Sha256Digest
    expected_evidence_lineage_digest: Sha256Digest
    occurred_at: str
    host_outcome_report: Literal[
        "reported_certain", "reported_in_doubt", "unreported"
    ] = "reported_certain"
    requested_by_ref: OpaqueRef
    evidence_custody_ref: OpaqueRef
    required_evidence_retention_until: str
    evidence: tuple[RegulatedEvidenceEnvelope, ...] = Field(min_length=1, max_length=20)
    package: ComplianceDomainPackage
    request_digest: Sha256Digest = GENESIS_STATE_DIGEST

    @field_validator("occurred_at", "required_evidence_retention_until")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _command_is_exact(
        self, info: ValidationInfo
    ) -> "ComplianceRiskTransitionCommand":
        if self.kind != self.package.kind:
            raise ValueError(
                "command kind must exactly match its tagged domain package"
            )
        if self.package.evidence_use_refs != tuple(
            sorted(item.use_ref for item in self.evidence)
        ):
            raise ValueError(
                "domain package must retain every exact evidence use reference"
            )
        _validate_package_against_command(self)
        _validate_command_evidence(
            self,
            skip_digests=bool((info.context or {}).get("skip_compliance_digests")),
        )
        if not (info.context or {}).get("skip_compliance_digests"):
            if self.request_digest != compliance_risk_command_digest(self):
                raise ValueError(
                    "request_digest must commit the exact normalized command"
                )
        return self


def _validate_package_against_command(command: ComplianceRiskTransitionCommand) -> None:
    package = command.package
    occurred = _parsed_timestamp(command.occurred_at)
    scope = command.scope
    if command.kind not in _CASE_TRANSITION_SEQUENCE[scope.case_kind]:
        raise ValueError("command kind must exactly match the scoped case track")
    if command.requested_by_ref in _package_reviewers(package):
        raise ValueError(
            "requester must be separate from legal, regulatory, or risk review"
        )
    if isinstance(package, PolicyControlOwnershipPackage):
        if (
            package.framework_ref != scope.regime_ref
            or package.control_ref != scope.case_ref
        ):
            raise ValueError(
                "policy/control framework and control must exactly match scoped regime and case"
            )
    elif isinstance(package, ControlTestEvidencePackage):
        if package.control_ref != scope.case_ref:
            raise ValueError("control test must exactly match the scoped case")
        if _parsed_timestamp(package.tested_at) > occurred:
            raise ValueError("control test cannot occur after transition time")
        if _parsed_timestamp(package.next_test_due_at) <= occurred:
            raise ValueError("control next-test deadline must remain current")
    elif isinstance(package, ComplianceAssessmentPackage):
        if (
            package.framework_ref != scope.regime_ref
            or package.control_ref != scope.case_ref
        ):
            raise ValueError(
                "assessment framework and control must exactly match scoped regime and case"
            )
        if _parsed_timestamp(package.assessed_at) > occurred:
            raise ValueError("assessment cannot occur after transition time")
    elif isinstance(package, IncidentBreachPackage):
        if package.incident_ref != scope.case_ref:
            raise ValueError("incident must exactly match the scoped case")
        if package.jurisdiction_refs != (scope.jurisdiction_ref,):
            raise ValueError("incident jurisdiction must exactly match lifecycle scope")
        if _parsed_timestamp(package.discovered_at) > occurred:
            raise ValueError("incident discovery cannot occur after transition time")
        if package.contained_at is not None and (
            _parsed_timestamp(package.contained_at) > occurred
        ):
            raise ValueError("incident containment cannot occur after transition time")
        if package.reported_at is not None and (
            _parsed_timestamp(package.reported_at) > occurred
        ):
            raise ValueError("incident reporting cannot occur after transition time")
        if (
            package.closed_at is not None
            and _parsed_timestamp(package.closed_at) > occurred
        ):
            raise ValueError("incident closure cannot occur after transition time")
        if (
            package.status not in {"reported", "closed"}
            and _parsed_timestamp(package.report_due_at) <= occurred
        ):
            raise ValueError("an overdue incident cannot remain unreported")
    elif isinstance(package, KycAmlCasePackage):
        if (
            package.case_ref != scope.case_ref
            or package.subject_ref != scope.subject_ref
        ):
            raise ValueError(
                "KYC/AML case and subject must exactly match lifecycle scope"
            )
        if _parsed_timestamp(package.reviewed_at) > occurred:
            raise ValueError("KYC/AML review cannot occur after transition time")
        if _parsed_timestamp(package.next_review_due_at) <= occurred:
            raise ValueError("KYC/AML next-review deadline must remain current")
    elif isinstance(package, RegulatedQualityPackage):
        if (
            package.record_set_ref != scope.case_ref
            or package.applicable_domains != scope.applicable_quality_domains
        ):
            raise ValueError(
                "regulated-quality record set and applicable domains must exactly match scope"
            )
        if any(
            _parsed_timestamp(item.valid_until) <= occurred for item in package.records
        ):
            raise ValueError(
                "every regulated record must remain valid at transition time"
            )
    elif isinstance(package, ExportControlPackage):
        if (
            package.transaction_ref != scope.case_ref
            or package.subject_ref != scope.subject_ref
        ):
            raise ValueError(
                "export transaction and subject must exactly match lifecycle scope"
            )
        if package.destination_jurisdiction != scope.jurisdiction_ref:
            raise ValueError(
                "export destination must exactly match scoped jurisdiction"
            )
        if package.license_valid_until is not None and (
            _parsed_timestamp(package.license_valid_until) <= occurred
        ):
            raise ValueError("required export license must remain valid")
    elif isinstance(package, RetentionLegalHoldPackage):
        if package.record_set_ref != scope.case_ref:
            raise ValueError("retention record set must exactly match the scoped case")
        if package.category_ref != scope.regime_ref:
            raise ValueError("retention category must exactly match scoped regime")
        if _parsed_timestamp(package.created_at) > occurred:
            raise ValueError("retention record cannot be created after transition time")
        if _parsed_timestamp(package.retain_until) < _parsed_timestamp(
            command.required_evidence_retention_until
        ):
            raise ValueError(
                "record retention cannot be shorter than evidence retention"
            )
    elif isinstance(package, ModelRiskPackage):
        if package.review_ref != scope.case_ref or package.model_ref != scope.model_ref:
            raise ValueError(
                "model-risk review and model must exactly match lifecycle scope"
            )
        if _parsed_timestamp(package.validated_at) > occurred:
            raise ValueError("model validation cannot occur after transition time")
        maximum_age = timedelta(
            days=365 if package.risk_tier in {"high", "critical"} else 730
        )
        if occurred - _parsed_timestamp(package.validated_at) > maximum_age:
            raise ValueError("model validation is stale for its risk tier")


def _package_reviewers(package: ComplianceDomainPackage) -> frozenset[str]:
    if isinstance(package, PolicyControlOwnershipPackage):
        return frozenset({package.reviewed_by_ref})
    if isinstance(package, ControlTestEvidencePackage):
        return frozenset({package.reviewed_by_ref})
    if isinstance(package, ComplianceAssessmentPackage):
        return frozenset({package.regulatory_reviewer_ref})
    if isinstance(package, IncidentBreachPackage):
        return frozenset({package.legal_reviewer_ref, package.regulatory_reviewer_ref})
    if isinstance(package, KycAmlCasePackage):
        return frozenset({package.aml_reviewer_ref})
    if isinstance(package, RegulatedQualityPackage):
        return frozenset({package.regulatory_reviewer_ref})
    if isinstance(package, ExportControlPackage):
        return frozenset({package.export_reviewer_ref})
    if isinstance(package, RetentionLegalHoldPackage):
        return frozenset({package.legal_reviewer_ref})
    return frozenset({package.risk_reviewer_ref})


def _new_package_artifact_refs(package: ComplianceDomainPackage) -> tuple[str, ...]:
    if isinstance(package, PolicyControlOwnershipPackage):
        return (package.policy_ref, package.control_ref)
    if isinstance(package, ControlTestEvidencePackage):
        return (package.test_ref,)
    if isinstance(package, ComplianceAssessmentPackage):
        return (package.assessment_ref,)
    if isinstance(package, IncidentBreachPackage):
        refs = [package.incident_ref, package.reporting_candidate_ref]
        if package.closure_candidate_ref is not None:
            refs.append(package.closure_candidate_ref)
        return tuple(refs)
    if isinstance(package, KycAmlCasePackage):
        return (package.case_ref,)
    if isinstance(package, RegulatedQualityPackage):
        return (
            package.record_set_ref,
            *(item.record_ref for item in package.records),
            *(item.validation_ref for item in package.records),
        )
    if isinstance(package, ExportControlPackage):
        refs = [
            package.screening_ref,
            package.transaction_ref,
            package.item_classification_ref,
        ]
        if package.license_ref is not None:
            refs.append(package.license_ref)
        return tuple(refs)
    if isinstance(package, RetentionLegalHoldPackage):
        refs = [
            package.record_set_ref,
            package.retention_policy_ref,
        ]
        if package.legal_hold_request_ref is not None:
            refs.append(package.legal_hold_request_ref)
        return tuple(refs)
    return (package.review_ref, package.approved_use_ref)


def _validate_command_evidence(
    command: ComplianceRiskTransitionCommand,
    *,
    skip_digests: bool,
) -> None:
    evidence = command.evidence
    _unique([item.use_ref for item in evidence], label="evidence use references")
    _unique([item.artifact_ref for item in evidence], label="evidence artifacts")
    _unique(
        [item.artifact_digest for item in evidence], label="evidence artifact digests"
    )
    _unique(
        [item.reference.evidence_ref for item in evidence],
        label="portable evidence references",
    )
    if [item.sequence for item in evidence] != list(range(1, len(evidence) + 1)):
        raise ValueError("evidence sequence must be contiguous and ordered")
    kinds = [item.reference.kind for item in evidence]
    required_kinds = _REQUIRED_EVIDENCE_KINDS[command.kind]
    if isinstance(command.package, RegulatedQualityPackage):
        required_kinds = frozenset(
            _QUALITY_EVIDENCE_KIND[domain]
            for domain in command.package.applicable_domains
        )
    elif isinstance(command.package, RetentionLegalHoldPackage) and not (
        command.package.legal_hold_required
    ):
        required_kinds = frozenset({"retention_schedule", "custody_record"})
    if frozenset(kinds) != required_kinds or len(kinds) != len(set(kinds)):
        raise ValueError("transition requires the exact governed evidence-kind set")

    occurred = _parsed_timestamp(command.occurred_at)
    required_retention = _parsed_timestamp(command.required_evidence_retention_until)
    if command.evidence_custody_ref != command.scope.evidence_custody_ref:
        raise ValueError("command evidence custody must exactly match lifecycle scope")
    if required_retention < _calendar_years_after(
        occurred,
        MINIMUM_EVIDENCE_RETENTION_YEARS,
    ):
        raise ValueError("regulated evidence retention must cover at least seven years")
    minimum_grade = (
        PrimitiveEvidenceVerificationGrade.VERIFIED
        if command.kind in _VERIFIED_EVIDENCE_STAGES
        else PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    predecessor = command.expected_evidence_lineage_digest
    content_digest = (
        None if skip_digests else compliance_risk_command_content_digest(command)
    )
    for envelope in evidence:
        reference = envelope.reference
        observed = _parsed_timestamp(reference.observed_at)
        if envelope.custody_ref != command.evidence_custody_ref:
            raise ValueError("evidence custody must exactly match the command custody")
        if reference.issuer_ref not in command.scope.authorized_evidence_issuer_refs:
            raise ValueError("evidence issuer is not authorized by lifecycle scope")
        if _parsed_timestamp(envelope.retained_until) < required_retention:
            raise ValueError("evidence envelope retention is shorter than required")
        if reference.subject_ref != command.transition_ref:
            raise ValueError("evidence must bind the exact transition reference")
        if reference.jurisdiction != command.scope.jurisdiction_ref:
            raise ValueError("evidence jurisdiction must exactly match lifecycle scope")
        if reference.retention_policy != command.scope.regime_ref:
            raise ValueError(
                "evidence retention policy must exactly match scoped regime"
            )
        if observed > occurred:
            raise ValueError("evidence cannot be observed after the transition")
        if occurred - observed > timedelta(hours=MAXIMUM_EVIDENCE_AGE_HOURS):
            raise ValueError(
                "evidence is stale for regulated transition materialization"
            )
        if reference.effective_at is None:
            raise ValueError("regulated evidence requires an effective timestamp")
        if _parsed_timestamp(reference.effective_at) > occurred:
            raise ValueError("evidence cannot become effective after the transition")
        if reference.classification == PrimitiveEvidenceClassification.PUBLIC:
            raise ValueError("regulated evidence cannot use public classification")
        if _GRADE_RANK[reference.verification_grade] < _GRADE_RANK[minimum_grade]:
            raise ValueError("evidence verification grade is below the stage minimum")
        if not skip_digests:
            if envelope.predecessor_lineage_digest != predecessor:
                raise ValueError("evidence lineage predecessor is discontinuous")
            if envelope.lineage_digest != _evidence_lineage_digest(envelope):
                raise ValueError("evidence lineage digest does not match its envelope")
            if reference.sha256 != content_digest:
                raise ValueError("evidence reference must commit exact command content")
        predecessor = envelope.lineage_digest


def _normalized_command_payload(
    command: ComplianceRiskTransitionCommand | Mapping[str, Any],
) -> dict[str, Any]:
    detached = _detached_validation_payload(command)
    if not isinstance(detached, Mapping):
        raise TypeError("compliance command must be a model or mapping")
    raw = dict(detached)
    raw.setdefault("request_digest", GENESIS_STATE_DIGEST)
    parsed = ComplianceRiskTransitionCommand.model_validate(
        raw,
        context={"skip_compliance_digests": True},
    )
    return parsed.to_dict()


def compliance_risk_command_content_digest(
    command: ComplianceRiskTransitionCommand | Mapping[str, Any],
) -> str:
    """Digest normalized command content without circular digest fields."""

    payload = _normalized_command_payload(command)
    payload.pop("request_digest", None)
    for envelope in payload["evidence"]:
        envelope["predecessor_lineage_digest"] = GENESIS_STATE_DIGEST
        envelope["lineage_digest"] = GENESIS_STATE_DIGEST
        envelope["reference"]["sha256"] = GENESIS_STATE_DIGEST
    return _stable_digest(payload)


def compliance_risk_command_digest(
    command: ComplianceRiskTransitionCommand | Mapping[str, Any],
) -> str:
    """Digest the full normalized command, excluding only request_digest."""

    payload = _normalized_command_payload(command)
    payload.pop("request_digest", None)
    return _stable_digest(payload)


def seal_compliance_risk_command(command: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and content-seal one caller-prepared transition command."""

    payload = _normalized_command_payload(command)
    content_digest = compliance_risk_command_content_digest(payload)
    predecessor = payload["expected_evidence_lineage_digest"]
    for envelope in payload["evidence"]:
        envelope["predecessor_lineage_digest"] = predecessor
        envelope["reference"]["sha256"] = content_digest
        envelope["lineage_digest"] = _evidence_lineage_digest(envelope)
        predecessor = envelope["lineage_digest"]
    payload["request_digest"] = compliance_risk_command_digest(payload)
    return ComplianceRiskTransitionCommand.model_validate(payload).to_dict()


def _evidence_digest(evidence: Sequence[RegulatedEvidenceEnvelope]) -> str:
    return _stable_digest([item.to_dict() for item in evidence])


def _transition_digest_payload(
    *,
    to_version: int,
    prior_state_digest: str,
    scope_digest: str,
    command_content_digest: str,
    evidence_digest: str,
    command: ComplianceRiskTransitionCommand,
) -> dict[str, Any]:
    return {
        "to_version": to_version,
        "prior_state_digest": prior_state_digest,
        "scope_digest": scope_digest,
        "command_content_digest": command_content_digest,
        "evidence_digest": evidence_digest,
        "request_digest": command.request_digest,
        "transition_ref": command.transition_ref,
        "idempotency_key": command.idempotency_key,
        "kind": command.kind,
    }


class ComplianceRiskTransitionCandidate(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_transition_candidate.v2"] = Field(
        default="lightbulb.compliance_risk_transition_candidate.v2", alias="schema"
    )
    to_version: int = Field(ge=1, le=MAX_COMPLIANCE_RISK_TRANSITIONS)
    prior_state_digest: Sha256Digest
    scope_digest: Sha256Digest
    command_content_digest: Sha256Digest
    evidence_digest: Sha256Digest
    transition_digest: Sha256Digest
    command: ComplianceRiskTransitionCommand

    @model_validator(mode="after")
    def _candidate_is_self_proving(self) -> "ComplianceRiskTransitionCandidate":
        if self.command.expected_version != self.to_version - 1:
            raise ValueError("candidate version must match command revision fence")
        if self.command.expected_state_digest != self.prior_state_digest:
            raise ValueError("candidate prior digest must match command state fence")
        if self.scope_digest != compliance_risk_scope_digest(self.command.scope):
            raise ValueError("candidate scope digest does not match command scope")
        if self.command_content_digest != compliance_risk_command_content_digest(
            self.command
        ):
            raise ValueError("candidate command-content digest is invalid")
        if self.evidence_digest != _evidence_digest(self.command.evidence):
            raise ValueError("candidate evidence digest is invalid")
        expected = _stable_digest(
            _transition_digest_payload(
                to_version=self.to_version,
                prior_state_digest=self.prior_state_digest,
                scope_digest=self.scope_digest,
                command_content_digest=self.command_content_digest,
                evidence_digest=self.evidence_digest,
                command=self.command,
            )
        )
        if self.transition_digest != expected:
            raise ValueError("transition digest must commit the exact candidate")
        return self


def _derived_packages(
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> dict[str, ComplianceDomainPackage]:
    field_by_kind: dict[TransitionKind, str] = {
        "establish_policy_control": "policy_control",
        "test_control": "control_test",
        "complete_compliance_assessment": "assessment",
        "review_incident_breach": "incident_breach",
        "review_kyc_aml_case": "kyc_aml_case",
        "review_regulated_quality": "regulated_quality",
        "review_export_control": "export_control",
        "review_retention_legal_hold": "retention_legal_hold",
        "review_model_risk": "model_risk",
    }
    return {field_by_kind[item.command.kind]: item.command.package for item in history}


def _snapshot_payload(
    scope: ComplianceRiskScope,
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> dict[str, Any]:
    packages = _derived_packages(history)
    return {
        "schema": COMPLIANCE_RISK_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "status": _STATUS_BY_COMMAND[history[-1].command.kind],
        "version": len(history),
        "transition_history": [item.to_dict() for item in history],
        "evidence_lineage_digest": history[-1].command.evidence[-1].lineage_digest,
        **{name: package.to_dict() for name, package in packages.items()},
    }


def _snapshot_digest(
    scope: ComplianceRiskScope,
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> str:
    return _stable_digest(_snapshot_payload(scope, history))


def _prior_state_digest(
    scope: ComplianceRiskScope,
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> str:
    return GENESIS_STATE_DIGEST if not history else _snapshot_digest(scope, history)


def _prior_evidence_lineage(
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> str:
    return (
        GENESIS_STATE_DIGEST
        if not history
        else history[-1].command.evidence[-1].lineage_digest
    )


class ComplianceRiskLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_lifecycle_snapshot.v2"] = Field(
        default=COMPLIANCE_RISK_SNAPSHOT_SCHEMA, alias="schema"
    )
    scope: ComplianceRiskScope
    status: LifecycleStatus
    version: int = Field(ge=1, le=MAX_COMPLIANCE_RISK_TRANSITIONS)
    transition_history: tuple[ComplianceRiskTransitionCandidate, ...] = Field(
        min_length=1, max_length=MAX_COMPLIANCE_RISK_TRANSITIONS
    )
    evidence_lineage_digest: Sha256Digest
    policy_control: PolicyControlOwnershipPackage | None = None
    control_test: ControlTestEvidencePackage | None = None
    assessment: ComplianceAssessmentPackage | None = None
    incident_breach: IncidentBreachPackage | None = None
    kyc_aml_case: KycAmlCasePackage | None = None
    regulated_quality: RegulatedQualityPackage | None = None
    export_control: ExportControlPackage | None = None
    retention_legal_hold: RetentionLegalHoldPackage | None = None
    model_risk: ModelRiskPackage | None = None
    state_digest: Sha256Digest

    @field_validator("transition_history", mode="before")
    @classmethod
    def _history_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> "ComplianceRiskLifecycleSnapshot":
        history = self.transition_history
        command_order = _CASE_TRANSITION_SEQUENCE[self.scope.case_kind]
        if self.version != len(history):
            raise ValueError("snapshot version must equal transition count")
        if self.status != _STATUS_BY_COMMAND[history[-1].command.kind]:
            raise ValueError("snapshot status must match its bounded lifecycle stage")
        if [item.command.kind for item in history] != list(
            command_order[: self.version]
        ):
            raise ValueError(
                "compliance transitions must be an ordered prefix of one case track"
            )
        if [item.to_version for item in history] != list(range(1, self.version + 1)):
            raise ValueError("transition candidate versions must be contiguous")
        for candidate in history:
            if candidate.command.scope != self.scope:
                raise ValueError("every retained transition must match snapshot scope")
        _validate_history_uniqueness(history)
        prefix: tuple[ComplianceRiskTransitionCandidate, ...] = ()
        for index, candidate in enumerate(history):
            try:
                _validate_transition_against_prefix(
                    self.scope, candidate.command, prefix
                )
            except _TransitionRejected as exc:
                raise ValueError(
                    f"historical transition {index + 1} is invalid: {exc.code}"
                ) from exc
            if candidate.prior_state_digest != _prior_state_digest(self.scope, prefix):
                raise ValueError(
                    "historical transition has a discontinuous state digest"
                )
            prefix = (*prefix, candidate)
        derived = _derived_packages(history)
        for field_name in (
            "policy_control",
            "control_test",
            "assessment",
            "incident_breach",
            "kyc_aml_case",
            "regulated_quality",
            "export_control",
            "retention_legal_hold",
            "model_risk",
        ):
            if getattr(self, field_name) != derived.get(field_name):
                raise ValueError(f"snapshot {field_name} must be derived from history")
        if self.evidence_lineage_digest != _prior_evidence_lineage(history):
            raise ValueError("snapshot evidence lineage head is invalid")
        if self.state_digest != _snapshot_digest(self.scope, history):
            raise ValueError("state_digest must commit the exact lifecycle snapshot")
        return self


def _validate_history_uniqueness(
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> None:
    commands = [item.command for item in history]
    for field_name in ("transition_ref", "idempotency_key", "request_digest"):
        _unique(
            [str(getattr(command, field_name)) for command in commands],
            label=f"historical {field_name} values",
        )
    envelopes = [envelope for command in commands for envelope in command.evidence]
    for field_name in (
        "use_ref",
        "artifact_ref",
        "artifact_digest",
        "lineage_digest",
    ):
        _unique(
            [str(getattr(envelope, field_name)) for envelope in envelopes],
            label=f"historical evidence {field_name} values",
        )
    _unique(
        [envelope.reference.evidence_ref for envelope in envelopes],
        label="historical portable evidence references",
    )


class ComplianceRiskLifecycleInput(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_lifecycle_input.v2"] = Field(
        default=COMPLIANCE_RISK_INPUT_SCHEMA, alias="schema"
    )
    scope: ComplianceRiskScope
    command: ComplianceRiskTransitionCommand
    current_snapshot: ComplianceRiskLifecycleSnapshot | None = None

    @model_validator(mode="after")
    def _scope_is_exact(self) -> "ComplianceRiskLifecycleInput":
        if self.command.scope != self.scope:
            raise ValueError("command scope must exactly match lifecycle input scope")
        if (
            self.current_snapshot is not None
            and self.current_snapshot.scope != self.scope
        ):
            raise ValueError("snapshot scope must exactly match lifecycle input scope")
        return self


RecoveryDisposition = Literal[
    "not_required",
    "do_not_replay",
    "refresh_snapshot",
    "correct_input",
    "manual_reconciliation",
]


class ComplianceRiskRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: StrictFalse = False
    instructions: str | None = Field(default=None, min_length=1, max_length=700)

    @model_validator(mode="after")
    def _recovery_is_bounded(self) -> "ComplianceRiskRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError("recovery instructions must match recovery disposition")
        return self


class ComplianceRiskEffectBoundary(_StrictModel):
    sdk_candidate_only: StrictTrue = True
    identity_or_rbac_changed: StrictFalse = False
    legal_determination_made: StrictFalse = False
    filing_or_report_submitted: StrictFalse = False
    legal_hold_applied: StrictFalse = False
    account_decision_made: StrictFalse = False
    risk_accepted: StrictFalse = False
    persistence_written: StrictFalse = False
    approval_recorded: StrictFalse = False
    audit_record_written: StrictFalse = False
    regulated_system_changed: StrictFalse = False
    connector_effect_executed: StrictFalse = False


class ComplianceRiskTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_transition_receipt.v2"] = Field(
        default=COMPLIANCE_RISK_RECEIPT_SCHEMA, alias="schema"
    )
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: TransitionKind
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_version: int = Field(ge=0, le=MAX_COMPLIANCE_RISK_TRANSITIONS)
    to_version: int = Field(ge=0, le=MAX_COMPLIANCE_RISK_TRANSITIONS)
    from_state_digest: Sha256Digest
    to_state_digest: Sha256Digest
    evidence_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: ComplianceRiskRecovery
    effect_boundary: ComplianceRiskEffectBoundary = Field(
        default_factory=ComplianceRiskEffectBoundary
    )

    @model_validator(mode="after")
    def _receipt_is_coherent(self) -> "ComplianceRiskTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1:
                raise ValueError(
                    "materialized candidate must advance exactly one version"
                )
            if self.to_state_digest == self.from_state_digest:
                raise ValueError("materialized candidate must advance the state digest")
            if (
                self.rejection_code is not None
                or self.recovery.disposition != "not_required"
            ):
                raise ValueError(
                    "materialized candidate cannot carry rejection recovery"
                )
        else:
            if self.to_version != self.from_version:
                raise ValueError(
                    "rejected or in-doubt transition cannot advance version"
                )
            if self.to_state_digest != self.from_state_digest:
                raise ValueError("rejected or in-doubt transition cannot change state")
            if (
                self.rejection_code is None
                or self.recovery.disposition == "not_required"
            ):
                raise ValueError(
                    "rejected transition requires a code and recovery route"
                )
        if (
            self.status == "in_doubt"
            and self.recovery.disposition != "manual_reconciliation"
        ):
            raise ValueError("in-doubt transition requires manual reconciliation")
        return self


class ComplianceRiskLifecycleResult(_StrictModel):
    schema_id: Literal["lightbulb.compliance_risk_lifecycle_result.v2"] = Field(
        default=COMPLIANCE_RISK_RESULT_SCHEMA, alias="schema"
    )
    candidate_validated: bool
    snapshot: ComplianceRiskLifecycleSnapshot | None = None
    transition_receipt: ComplianceRiskTransitionReceipt
    effect_boundary: ComplianceRiskEffectBoundary = Field(
        default_factory=ComplianceRiskEffectBoundary
    )

    @model_validator(mode="after")
    def _result_is_coherent(self) -> "ComplianceRiskLifecycleResult":
        if self.candidate_validated != (
            self.transition_receipt.status == "candidate_materialized"
        ):
            raise ValueError("candidate flag must match transition receipt")
        if self.candidate_validated and self.snapshot is None:
            raise ValueError("validated candidate requires a resulting snapshot")
        if self.snapshot is not None and (
            self.snapshot.version != self.transition_receipt.to_version
            or self.snapshot.state_digest != self.transition_receipt.to_state_digest
        ):
            raise ValueError("result snapshot must match transition receipt")
        if self.candidate_validated and self.snapshot is not None:
            latest = self.snapshot.transition_history[-1]
            command = latest.command
            receipt = self.transition_receipt
            if (
                receipt.transition_ref != command.transition_ref
                or receipt.idempotency_key != command.idempotency_key
                or receipt.request_digest != command.request_digest
                or receipt.command_kind != command.kind
                or receipt.from_version != latest.to_version - 1
                or receipt.from_state_digest != latest.prior_state_digest
                or receipt.evidence_digest != latest.evidence_digest
            ):
                raise ValueError(
                    "candidate receipt must bind the exact retained transition"
                )
        return self


class _TransitionRejected(ValueError):
    def __init__(
        self,
        code: str,
        instructions: str,
        recovery: RecoveryDisposition,
        *,
        in_doubt: bool = False,
    ) -> None:
        super().__init__(instructions)
        self.code = code
        self.instructions = instructions
        self.recovery = recovery
        self.in_doubt = in_doubt


def _validate_transition_against_prefix(
    scope: ComplianceRiskScope,
    command: ComplianceRiskTransitionCommand,
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> None:
    version = len(history)
    command_order = _CASE_TRANSITION_SEQUENCE[scope.case_kind]
    if version >= len(command_order):
        raise _TransitionRejected(
            "LIFECYCLE_COMPLETE",
            "No transition exists after this bounded compliance case track.",
            "do_not_replay",
        )
    if command.kind != command_order[version]:
        raise _TransitionRejected(
            "OUT_OF_ORDER_TRANSITION",
            "Submit exactly the next transition for this compliance case track.",
            "correct_input",
        )
    if command.expected_version != version:
        raise _TransitionRejected(
            "STALE_VERSION",
            "Refresh the authoritative candidate snapshot before retrying.",
            "refresh_snapshot",
        )
    expected_digest = _prior_state_digest(scope, history)
    if command.expected_state_digest != expected_digest:
        raise _TransitionRejected(
            "STALE_STATE_DIGEST",
            "Refresh the authoritative candidate snapshot before retrying.",
            "refresh_snapshot",
        )
    if command.expected_evidence_lineage_digest != _prior_evidence_lineage(history):
        raise _TransitionRejected(
            "STALE_EVIDENCE_LINEAGE",
            "Refresh the authoritative evidence-chain head before retrying.",
            "refresh_snapshot",
        )
    if history and _parsed_timestamp(command.occurred_at) <= _parsed_timestamp(
        history[-1].command.occurred_at
    ):
        raise _TransitionRejected(
            "NON_MONOTONIC_TRANSITION_TIME",
            "Use a transition time strictly after the retained candidate history.",
            "correct_input",
        )
    if history:
        earliest = _parsed_timestamp(history[-1].command.occurred_at)
        if any(
            _parsed_timestamp(item.reference.observed_at) < earliest
            for item in command.evidence
        ):
            raise _TransitionRejected(
                "PRE_STAGE_EVIDENCE",
                "Use fresh evidence observed no earlier than the prior transition.",
                "correct_input",
            )
    current_artifact_refs = _new_package_artifact_refs(command.package)
    if len(current_artifact_refs) != len(set(current_artifact_refs)):
        raise _TransitionRejected(
            "ARTIFACT_REF_COLLISION",
            "New package artifact references must be unique within the transition.",
            "correct_input",
        )
    retained_artifact_refs = {
        ref
        for candidate in history
        for ref in _new_package_artifact_refs(candidate.command.package)
    }
    if retained_artifact_refs & set(current_artifact_refs):
        raise _TransitionRejected(
            "ARTIFACT_REF_COLLISION",
            "New package artifact references cannot collide with retained history.",
            "correct_input",
        )
    _validate_policy_track_links(command, history)


def _validate_policy_track_links(
    command: ComplianceRiskTransitionCommand,
    history: Sequence[ComplianceRiskTransitionCandidate],
) -> None:
    package = command.package
    if not history:
        return
    packages = [item.command.package for item in history]
    previous = packages[-1]
    linked = True
    if isinstance(package, ControlTestEvidencePackage):
        policy = packages[0]
        linked = isinstance(policy, PolicyControlOwnershipPackage) and (
            package.policy_ref == policy.policy_ref
            and package.control_ref == policy.control_ref
            and package.owner_ref == policy.owner_ref
            and _parsed_timestamp(package.tested_at)
            >= _parsed_timestamp(history[0].command.occurred_at)
        )
    elif isinstance(package, ComplianceAssessmentPackage):
        policy = packages[0]
        linked = (
            isinstance(policy, PolicyControlOwnershipPackage)
            and isinstance(previous, ControlTestEvidencePackage)
            and package.policy_ref == policy.policy_ref
            and package.control_ref == policy.control_ref
            and package.control_test_ref == previous.test_ref
            and _parsed_timestamp(package.assessed_at)
            >= _parsed_timestamp(previous.tested_at)
            and _parsed_timestamp(package.assessed_at)
            >= _parsed_timestamp(history[-1].command.occurred_at)
        )
    if not linked:
        raise _TransitionRejected(
            "CROSS_STAGE_REFERENCE_MISMATCH",
            "Pin the exact immutable references retained by prior lifecycle stages.",
            "correct_input",
        )


def _check_history_conflicts(
    history: Sequence[ComplianceRiskTransitionCandidate],
    command: ComplianceRiskTransitionCommand,
) -> None:
    for candidate in history:
        retained = candidate.command
        if retained.transition_ref == command.transition_ref:
            code = (
                "DUPLICATE_TRANSITION"
                if retained.request_digest == command.request_digest
                else "TRANSITION_REF_CONFLICT"
            )
            raise _TransitionRejected(
                code,
                "Do not replay; reconcile against Spring's durable transition ledger.",
                "do_not_replay",
            )
        if retained.idempotency_key == command.idempotency_key:
            code = (
                "DUPLICATE_IDEMPOTENCY_KEY"
                if retained.request_digest == command.request_digest
                else "IDEMPOTENCY_KEY_CONFLICT"
            )
            raise _TransitionRejected(
                code,
                "Use Spring's durable idempotency result; do not reapply this key.",
                "do_not_replay",
            )
        if retained.request_digest == command.request_digest:
            raise _TransitionRejected(
                "DUPLICATE_REQUEST",
                "Do not replay an already retained command digest.",
                "do_not_replay",
            )
    old_envelopes = [
        item for candidate in history for item in candidate.command.evidence
    ]
    reused = any(
        new.use_ref == old.use_ref
        or new.artifact_ref == old.artifact_ref
        or new.artifact_digest == old.artifact_digest
        or new.lineage_digest == old.lineage_digest
        or new.reference.evidence_ref == old.reference.evidence_ref
        for new in command.evidence
        for old in old_envelopes
    )
    if reused:
        raise _TransitionRejected(
            "EVIDENCE_REUSE",
            "Single-use regulated evidence cannot be reused across transitions.",
            "do_not_replay",
        )


def _candidate_for(
    scope: ComplianceRiskScope,
    history: Sequence[ComplianceRiskTransitionCandidate],
    command: ComplianceRiskTransitionCommand,
) -> ComplianceRiskTransitionCandidate:
    to_version = len(history) + 1
    prior_digest = _prior_state_digest(scope, history)
    scope_digest = compliance_risk_scope_digest(scope)
    content_digest = compliance_risk_command_content_digest(command)
    evidence_digest = _evidence_digest(command.evidence)
    transition_digest = _stable_digest(
        _transition_digest_payload(
            to_version=to_version,
            prior_state_digest=prior_digest,
            scope_digest=scope_digest,
            command_content_digest=content_digest,
            evidence_digest=evidence_digest,
            command=command,
        )
    )
    return ComplianceRiskTransitionCandidate(
        to_version=to_version,
        prior_state_digest=prior_digest,
        scope_digest=scope_digest,
        command_content_digest=content_digest,
        evidence_digest=evidence_digest,
        transition_digest=transition_digest,
        command=command,
    )


def _materialize_snapshot(
    scope: ComplianceRiskScope,
    history: tuple[ComplianceRiskTransitionCandidate, ...],
) -> ComplianceRiskLifecycleSnapshot:
    payload = _snapshot_payload(scope, history)
    payload["state_digest"] = _snapshot_digest(scope, history)
    return ComplianceRiskLifecycleSnapshot.model_validate(payload)


def _materialize_candidate_transition(
    inputs: ComplianceRiskLifecycleInput,
) -> ComplianceRiskLifecycleSnapshot:
    command = inputs.command
    snapshot = inputs.current_snapshot
    if command.host_outcome_report != "reported_certain":
        raise _TransitionRejected(
            "AMBIGUOUS_HOST_OUTCOME",
            "Do not retry automatically; Spring must reconcile its durable ledger.",
            "manual_reconciliation",
            in_doubt=True,
        )
    history: tuple[ComplianceRiskTransitionCandidate, ...] = (
        snapshot.transition_history if snapshot is not None else ()
    )
    if snapshot is not None:
        _check_history_conflicts(history, command)
    elif command.kind != _CASE_TRANSITION_SEQUENCE[inputs.scope.case_kind][0]:
        raise _TransitionRejected(
            "MISSING_SNAPSHOT",
            "Refresh the authoritative lifecycle snapshot for a non-genesis transition.",
            "refresh_snapshot",
        )
    _validate_transition_against_prefix(inputs.scope, command, history)
    candidate = _candidate_for(inputs.scope, history, command)
    return _materialize_snapshot(inputs.scope, (*history, candidate))


def _rejected_result(
    inputs: ComplianceRiskLifecycleInput,
    exc: _TransitionRejected,
) -> ComplianceRiskLifecycleResult:
    snapshot = inputs.current_snapshot
    version = snapshot.version if snapshot is not None else 0
    digest = snapshot.state_digest if snapshot is not None else GENESIS_STATE_DIGEST
    return ComplianceRiskLifecycleResult(
        candidate_validated=False,
        snapshot=snapshot,
        transition_receipt=ComplianceRiskTransitionReceipt(
            transition_ref=inputs.command.transition_ref,
            idempotency_key=inputs.command.idempotency_key,
            request_digest=inputs.command.request_digest,
            command_kind=inputs.command.kind,
            status="in_doubt" if exc.in_doubt else "rejected",
            from_version=version,
            to_version=version,
            from_state_digest=digest,
            to_state_digest=digest,
            evidence_digest=_evidence_digest(inputs.command.evidence),
            rejection_code=exc.code,
            recovery=ComplianceRiskRecovery(
                disposition=exc.recovery,
                instructions=exc.instructions,
            ),
        ),
    )


def materialize_compliance_risk_candidate(
    inputs: ComplianceRiskLifecycleInput | Mapping[str, Any],
) -> ComplianceRiskLifecycleResult:
    """Materialize exactly one bounded, SDK-only regulated candidate transition."""

    payload = _detached_validation_payload(inputs)
    # model_copy(update=...) deliberately skips validation.  Public materialization
    # always revalidates the serialized boundary so forged snapshots and packages
    # cannot bypass digest, evidence, or semantic-history checks.
    parsed = ComplianceRiskLifecycleInput.model_validate(payload)
    snapshot = parsed.current_snapshot
    from_version = snapshot.version if snapshot is not None else 0
    from_digest = (
        snapshot.state_digest if snapshot is not None else GENESIS_STATE_DIGEST
    )
    try:
        resulting_snapshot = _materialize_candidate_transition(parsed)
    except _TransitionRejected as exc:
        return _rejected_result(parsed, exc)
    receipt = ComplianceRiskTransitionReceipt(
        transition_ref=parsed.command.transition_ref,
        idempotency_key=parsed.command.idempotency_key,
        request_digest=parsed.command.request_digest,
        command_kind=parsed.command.kind,
        status="candidate_materialized",
        from_version=from_version,
        to_version=resulting_snapshot.version,
        from_state_digest=from_digest,
        to_state_digest=resulting_snapshot.state_digest,
        evidence_digest=_evidence_digest(parsed.command.evidence),
        recovery=ComplianceRiskRecovery(disposition="not_required"),
    )
    return ComplianceRiskLifecycleResult(
        candidate_validated=True,
        snapshot=resulting_snapshot,
        transition_receipt=receipt,
    )


COMPLIANCE_RISK_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="compliance_risk_materialize_transition",
    tool="sdk.compliance.materialize_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)


def _scope_matches_context(
    inputs: ComplianceRiskLifecycleInput,
    context: PrimitiveExecutionContext,
) -> bool:
    scope = inputs.scope
    command = inputs.command
    return (
        scope.tenant_ref == context.scope.tenant_ref
        and scope.company_ref == context.scope.company_ref
        and scope.project_ref == context.scope.project_ref
        and context.scope.project_id is not None
        and scope.project_id == context.scope.project_id
        and context.scope.actor_ref is not None
        and command.requested_by_ref == context.scope.actor_ref
        and context.idempotency_key is not None
        and command.idempotency_key == context.idempotency_key
    )


def _example_evidence(
    *,
    sequence: int,
    kind: str,
    transition_ref: str,
    observed_at: str,
    retained_until: str,
) -> dict[str, Any]:
    suffix = kind.replace("_", "-")
    return {
        "schema": "lightbulb.regulated_evidence_envelope.v1",
        "sequence": sequence,
        "use_ref": f"use-{suffix}-example",
        "artifact_ref": f"artifact-{suffix}-example",
        "artifact_digest": hashlib.sha256(f"artifact:{kind}".encode()).hexdigest(),
        "predecessor_lineage_digest": GENESIS_STATE_DIGEST,
        "lineage_digest": GENESIS_STATE_DIGEST,
        "custody_ref": "custody-example",
        "retained_until": retained_until,
        "single_use": True,
        "reference": {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": f"evidence-{suffix}-example",
            "kind": kind,
            "issuer_ref": "regulated-host-example",
            "subject_ref": transition_ref,
            "sha256": GENESIS_STATE_DIGEST,
            "observed_at": observed_at,
            "effective_at": observed_at,
            "verification_grade": "attested",
            "classification": "restricted",
            "retention_policy": "regime-example",
            "jurisdiction": "US-NY",
        },
    }


def _compliance_risk_example_inputs() -> dict[str, Any]:
    transition_ref = "transition-policy-control-example"
    occurred_at = "2026-08-25T12:00:00Z"
    retained_until = "2034-01-01T00:00:00Z"
    evidence = [
        _example_evidence(
            sequence=index,
            kind=kind,
            transition_ref=transition_ref,
            observed_at="2026-08-25T11:00:00Z",
            retained_until=retained_until,
        )
        for index, kind in enumerate(("policy_text", "control_ownership"), start=1)
    ]
    scope = {
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "40100000-0000-4000-8000-000000000001",
        "jurisdiction_ref": "US-NY",
        "regime_ref": "regime-example",
        "case_ref": "control-example",
        "case_kind": "policy_control_assessment",
        "subject_ref": "subject-example",
        "evidence_custody_ref": "custody-example",
        "authorized_evidence_issuer_refs": ["regulated-host-example"],
    }
    command = seal_compliance_risk_command(
        {
            "kind": "establish_policy_control",
            "scope": scope,
            "transition_ref": transition_ref,
            "idempotency_key": "idem-policy-control-example",
            "expected_version": 0,
            "expected_state_digest": GENESIS_STATE_DIGEST,
            "expected_evidence_lineage_digest": GENESIS_STATE_DIGEST,
            "occurred_at": occurred_at,
            "host_outcome_report": "reported_certain",
            "requested_by_ref": "actor-requester-example",
            "evidence_custody_ref": "custody-example",
            "required_evidence_retention_until": retained_until,
            "evidence": evidence,
            "package": {
                "kind": "establish_policy_control",
                "revision": 1,
                "evidence_use_refs": sorted(item["use_ref"] for item in evidence),
                "policy_ref": "policy-example",
                "control_ref": "control-example",
                "framework_ref": "regime-example",
                "policy_revision": 1,
                "control_revision": 1,
                "owner_ref": "actor-control-owner-example",
                "prepared_by_ref": "actor-policy-author-example",
                "reviewed_by_ref": "actor-policy-reviewer-example",
                "implementation_status": "effective",
                "owner_acknowledged": True,
            },
        }
    )
    return {"scope": scope, "command": command}


class ProposeComplianceRiskTransitionPrimitive(
    BusinessProcessPrimitive[
        ComplianceRiskLifecycleInput,
        ComplianceRiskLifecycleResult,
    ]
):
    primitive_ref = "compliance.propose_regulated_operations_transition"
    version = "2.0.0"
    title = "Propose a bounded compliance and regulated-operations transition"
    description = (
        "Validate and materialize one scope-, revision-, idempotency-, and "
        "evidence-lineage-bound SDK candidate without making any legal, filing, "
        "hold, account, risk, approval, persistence, audit, or connector decision."
    )
    input_model = ComplianceRiskLifecycleInput
    output_model = ComplianceRiskLifecycleResult
    connector_tools = ()
    risk_level = "high"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _compliance_risk_example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = COMPLIANCE_RISK_TRANSITION_OPERATION.to_dict()
        contract["effect_boundary"] = ComplianceRiskEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "spring_and_regulated_systems": (
                "identity, RBAC, legal determinations, filings, holds, account "
                "decisions, risk acceptance, persistence, approvals, audit, and effects"
            ),
            "sdk": "deterministic non-authoritative candidate materialization only",
            "actor_separation": (
                "structural proposal guard only; authenticated roles remain host-owned"
            ),
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_COMPLIANCE_RISK_TRANSITIONS,
            "scope_binding": (
                "exact tenant, company, project reference and UUID, jurisdiction, regime, "
                "case, case kind, subject, model, and applicable regulated-quality domains"
            ),
            "runtime_attribution": (
                "runtime project UUID, authenticated actor, and idempotency key must be "
                "present and exactly match the validated transition command"
            ),
            "case_tracks": (
                "one ordered policy/control/assessment track plus independent bounded "
                "incident, KYC/AML, regulated-quality, export, retention, and model-risk tracks"
            ),
            "history": (
                "case-track-local ordered semantic replay with canonical state and "
                "transition digests"
            ),
            "evidence": (
                "immutable authorized-issuer and custody-bound global lineage, "
                "freshness, retention, and single-use"
            ),
            "genesis_replay": "durable Spring idempotency ledger remains required",
            "ambiguous_outcome": "fail closed; manual Spring reconciliation; never auto-retry",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ComplianceRiskLifecycleInput,
    ) -> PrimitiveExecutionResult[ComplianceRiskLifecycleResult]:
        evidence_refs = [item.reference for item in inputs.command.evidence]
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project UUID, actor, and idempotency key must "
                    "be present and exactly match the regulated lifecycle input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[ComplianceRiskLifecycleResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Compliance/risk transition rejected at the scope boundary.",
                blockers=[blocker],
                evidence_refs=evidence_refs,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=COMPLIANCE_RISK_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.command.request_digest,
                        evidence_refs=evidence_refs,
                        error=blocker,
                    )
                ],
            )
        output = materialize_compliance_risk_candidate(inputs)
        blocker: PrimitiveBlocker | None
        recovery_plan: PrimitiveRecoveryPlan | None
        if output.candidate_validated:
            receipt_status = PrimitiveOperationStatus.PREVIEW
            execution_status = PrimitiveExecutionStatus.PREVIEW
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            recovery_plan = None
            blocker = None
        elif output.transition_receipt.status == "in_doubt":
            receipt_status = PrimitiveOperationStatus.IN_DOUBT
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_disposition = (
                PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            )
            recovery_plan = PrimitiveRecoveryPlan(
                policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                disposition=recovery_disposition,
                instructions=output.transition_receipt.recovery.instructions,
            )
            blocker = PrimitiveBlocker(
                code=output.transition_receipt.rejection_code or "OUTCOME_IN_DOUBT",
                message=output.transition_receipt.recovery.instructions
                or "Manual reconciliation is required.",
                retryable=False,
            )
        else:
            receipt_status = PrimitiveOperationStatus.BLOCKED
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            recovery_plan = None
            blocker = PrimitiveBlocker(
                code=output.transition_receipt.rejection_code or "TRANSITION_REJECTED",
                message=output.transition_receipt.recovery.instructions
                or "Compliance/risk candidate was rejected.",
                retryable=False,
            )
        operation_receipt = PrimitiveOperationReceipt(
            spec=COMPLIANCE_RISK_TRANSITION_OPERATION,
            status=receipt_status,
            request_digest=inputs.command.request_digest,
            evidence_refs=evidence_refs,
            external_refs=(
                {
                    "state_digest": output.snapshot.state_digest,
                    "transition_ref": inputs.command.transition_ref,
                }
                if output.candidate_validated and output.snapshot is not None
                else {}
            ),
            recovery_disposition=recovery_disposition,
            recovery_plan=recovery_plan,
            error=blocker,
        )
        return PrimitiveExecutionResult[ComplianceRiskLifecycleResult](
            status=execution_status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Compliance/risk candidate validated with no authoritative effect."
                if output.candidate_validated
                else "Compliance/risk candidate rejected without changing live state."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="compliance.regulated_operations_candidate_evaluated",
                    payload={
                        "transition_ref": inputs.command.transition_ref,
                        "command_kind": inputs.command.kind,
                        "candidate_validated": output.candidate_validated,
                        "request_digest": inputs.command.request_digest,
                        "regulated_system_changed": False,
                        "connector_effect_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="compliance_risk_candidate_receipt",
                    summary=(
                        "Portable SDK candidate receipt; not an approval, filing, hold, "
                        "account decision, risk acceptance, or audit record."
                    ),
                    refs={
                        "transition_ref": inputs.command.transition_ref,
                        "request_digest": inputs.command.request_digest,
                    },
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[operation_receipt],
            recovery_plan=recovery_plan,
            blockers=[blocker] if blocker is not None else [],
        )


COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeComplianceRiskTransitionPrimitive(),)


__all__ = [
    "COMPLIANCE_RISK_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "COMPLIANCE_RISK_COMMAND_SCHEMA",
    "COMPLIANCE_RISK_INPUT_SCHEMA",
    "COMPLIANCE_RISK_RECEIPT_SCHEMA",
    "COMPLIANCE_RISK_RESULT_SCHEMA",
    "COMPLIANCE_RISK_SCOPE_SCHEMA",
    "COMPLIANCE_RISK_SNAPSHOT_SCHEMA",
    "COMPLIANCE_RISK_TRANSITION_OPERATION",
    "GENESIS_STATE_DIGEST",
    "MAX_COMPLIANCE_RISK_TRANSITIONS",
    "ComplianceRiskCaseKind",
    "ComplianceRiskEffectBoundary",
    "ComplianceRiskLifecycleInput",
    "ComplianceRiskLifecycleResult",
    "ComplianceRiskLifecycleSnapshot",
    "ComplianceRiskScope",
    "ComplianceRiskTransitionCandidate",
    "ComplianceRiskTransitionCommand",
    "ProposeComplianceRiskTransitionPrimitive",
    "RegulatedDomain",
    "RegulatedEvidenceEnvelope",
    "compliance_risk_command_content_digest",
    "compliance_risk_command_digest",
    "compliance_risk_scope_digest",
    "materialize_compliance_risk_candidate",
    "seal_compliance_risk_command",
]
