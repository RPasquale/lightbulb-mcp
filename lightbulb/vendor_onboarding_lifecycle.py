"""Bounded, evidence-bound vendor onboarding transition proposals.

This module materializes deterministic SDK candidate snapshots only.  It does
not authenticate scope, authorize a vendor, verify private artifacts, create or
change vendor-master or payment data, persist state, activate a supplier, or
call a provider.  Spring remains authoritative for scope, RBAC, evidence and
approval verification, persistence, audit, idempotency admission, and writes;
governed procurement, KYC/AML, ERP, and payment systems remain authoritative
for live facts and effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Mapping, Sequence, Union
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
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


VENDOR_ONBOARDING_SCOPE_SCHEMA = "lightbulb.vendor_onboarding_scope.v1"
VENDOR_ONBOARDING_EVIDENCE_SCHEMA = "lightbulb.vendor_onboarding_evidence.v1"
VENDOR_ONBOARDING_TRANSITION_SCHEMA = "lightbulb.vendor_onboarding_transition.v1"
VENDOR_ONBOARDING_SNAPSHOT_SCHEMA = "lightbulb.vendor_onboarding_snapshot.v1"
VENDOR_ONBOARDING_REQUEST_SCHEMA = "lightbulb.vendor_onboarding_request.v1"
VENDOR_ONBOARDING_PROPOSAL_SCHEMA = "lightbulb.vendor_onboarding_proposal.v1"
VENDOR_ONBOARDING_RECEIPT_SCHEMA = "lightbulb.vendor_onboarding_receipt.v1"
VENDOR_ONBOARDING_RESULT_SCHEMA = "lightbulb.vendor_onboarding_result.v1"
VENDOR_ONBOARDING_ZERO_DIGEST = "0" * 64
MAX_VENDOR_ONBOARDING_TRANSITIONS = 7
EVIDENCE_PER_VENDOR_TRANSITION = 2
MAX_EVIDENCE_AGE = timedelta(hours=72)
MAX_LIFECYCLE_WINDOW = timedelta(days=365)
MIN_EVIDENCE_RETENTION_YEARS = 7
MAX_QUALIFICATION_VALIDITY = timedelta(days=366)


VendorOnboardingState = Literal[
    "identity_captured",
    "due_diligence_cleared",
    "qualification_assessed",
    "approval_candidate",
    "bank_control_verified",
    "setup_ready",
    "activation_candidate",
]
RiskTier = Literal["low", "medium", "high", "critical"]
SourceOutcomeReport = Literal["reported_certain", "reported_in_doubt"]
RecoveryDisposition = Literal[
    "not_required",
    "correct_input",
    "refresh_snapshot",
    "do_not_replay",
    "manual_reconciliation",
]


class VendorOnboardingLifecycleError(ValueError):
    """Stable fail-closed error for an unparseable lifecycle request."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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


_PRIVATE_REF_RE = re.compile(
    r"^(?:artifact|evidence|private|secret|vault):[A-Za-z0-9][A-Za-z0-9._:/-]{0,181}$"
)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _stable_digest(value: Any) -> str:
    encoded = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _visible(value: Any, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise ValueError(
            f"{name} must contain visible ASCII characters without whitespace"
        )
    return value


def _private_ref(value: Any, *, name: str) -> str:
    parsed = _visible(value, name=name)
    if not _PRIVATE_REF_RE.fullmatch(parsed):
        raise ValueError(
            f"{name} must be an opaque private-artifact reference, never raw private data"
        )
    return parsed


def _utc(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"{name} must be an ISO-8601 string without whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _retention_floor(observed_at: str) -> datetime:
    observed = _dt(observed_at)
    target_year = observed.year + MIN_EVIDENCE_RETENTION_YEARS
    try:
        return observed.replace(year=target_year)
    except ValueError:
        return observed.replace(year=target_year, month=3, day=1)


def _as_tuple(value: Any, *, name: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    return tuple(value)


def _unique(values: Sequence[str], *, name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")


def _reject(
    code: str,
    instructions: str,
    recovery: RecoveryDisposition = "correct_input",
    *,
    in_doubt: bool = False,
) -> None:
    raise _TransitionRejected(
        code,
        instructions,
        recovery,
        in_doubt=in_doubt,
    )


class VendorOnboardingScope(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_scope.v1"] = Field(
        default=VENDOR_ONBOARDING_SCOPE_SCHEMA, alias="schema"
    )
    tenant_ref: str = Field(min_length=1, max_length=160)
    company_ref: str = Field(min_length=1, max_length=160)
    project_ref: str = Field(min_length=1, max_length=160)
    project_id: UUID
    procurement_org_ref: str = Field(min_length=1, max_length=160)
    vendor_ref: str = Field(min_length=1, max_length=160)
    category_ref: str = Field(min_length=1, max_length=160)
    site_ref: str = Field(min_length=1, max_length=160)
    jurisdiction_ref: str = Field(min_length=2, max_length=80)
    retention_policy_ref: str = Field(min_length=1, max_length=160)
    evidence_custodian_ref: str = Field(min_length=1, max_length=200)
    spring_authority_ref: str = Field(min_length=1, max_length=200)

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
        if str(parsed) != value.lower():
            raise ValueError("project_id must be a canonical UUID")
        return parsed

    @field_validator(
        "tenant_ref",
        "company_ref",
        "project_ref",
        "procurement_org_ref",
        "vendor_ref",
        "category_ref",
        "site_ref",
        "jurisdiction_ref",
        "retention_policy_ref",
        "evidence_custodian_ref",
        "spring_authority_ref",
    )
    @classmethod
    def _exact_refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)


def vendor_onboarding_scope_digest(
    scope: VendorOnboardingScope | Mapping[str, Any],
) -> str:
    parsed = VendorOnboardingScope.model_validate(_jsonable(scope))
    return _stable_digest(parsed)


class VendorOnboardingEvidence(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_evidence.v1"] = Field(
        default=VENDOR_ONBOARDING_EVIDENCE_SCHEMA, alias="schema"
    )
    sequence: int = Field(
        ge=1,
        le=MAX_VENDOR_ONBOARDING_TRANSITIONS * EVIDENCE_PER_VENDOR_TRANSITION,
    )
    evidence_ref: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=100)
    issuer_ref: str = Field(min_length=1, max_length=200)
    custodian_ref: str = Field(min_length=1, max_length=200)
    subject_ref: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    effective_at: str
    verification_grade: PrimitiveEvidenceVerificationGrade
    classification: PrimitiveEvidenceClassification
    retention_policy: str = Field(min_length=1, max_length=160)
    jurisdiction: str = Field(min_length=2, max_length=80)
    retained_until: str
    single_use: Literal[True] = True
    causal_revision: int = Field(ge=0, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    causal_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    predecessor_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "evidence_ref",
        "kind",
        "issuer_ref",
        "custodian_ref",
        "subject_ref",
        "retention_policy",
        "jurisdiction",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("verification_grade", mode="before")
    @classmethod
    def _grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        if not isinstance(value, str):
            raise ValueError("verification_grade must be an exact enum value")
        try:
            return PrimitiveEvidenceVerificationGrade(value)
        except ValueError as exc:
            raise ValueError("verification_grade must be an exact enum value") from exc

    @field_validator("classification", mode="before")
    @classmethod
    def _classification(cls, value: Any) -> PrimitiveEvidenceClassification:
        if isinstance(value, PrimitiveEvidenceClassification):
            return value
        if not isinstance(value, str):
            raise ValueError("classification must be an exact enum value")
        try:
            return PrimitiveEvidenceClassification(value)
        except ValueError as exc:
            raise ValueError("classification must be an exact enum value") from exc

    @model_validator(mode="after")
    def _chronology_and_lineage(self) -> "VendorOnboardingEvidence":
        if _dt(self.effective_at) > _dt(self.observed_at):
            raise ValueError("evidence effective_at cannot follow observed_at")
        if _dt(self.retained_until) < _retention_floor(self.observed_at):
            raise ValueError("evidence retention must cover seven calendar years")
        if self.lineage_digest != vendor_onboarding_evidence_lineage_digest(self):
            raise ValueError("evidence lineage_digest does not match its content")
        return self

    def portable_ref(self) -> PrimitiveEvidenceRef:
        return PrimitiveEvidenceRef(
            evidence_ref=self.evidence_ref,
            kind=self.kind,
            issuer_ref=self.issuer_ref,
            subject_ref=self.subject_ref,
            sha256=self.sha256,
            observed_at=self.observed_at,
            effective_at=self.effective_at,
            verification_grade=self.verification_grade,
            classification=self.classification,
            retention_policy=self.retention_policy,
            jurisdiction=self.jurisdiction,
        )


def vendor_onboarding_evidence_lineage_digest(
    evidence: VendorOnboardingEvidence | Mapping[str, Any],
) -> str:
    payload = _jsonable(evidence)
    if not isinstance(payload, Mapping):
        raise ValueError("evidence must be a mapping")
    content = dict(payload)
    content.pop("lineage_digest", None)
    return _stable_digest(content)


class QualificationCondition(_StrictModel):
    condition_ref: str = Field(min_length=1, max_length=160)
    control_ref: str = Field(min_length=1, max_length=160)
    owner_role_ref: str = Field(min_length=1, max_length=160)
    severity: Literal["advisory", "material", "critical"]
    due_at: str

    @field_validator("condition_ref", "control_ref", "owner_role_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("due_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="due_at")


class _Command(_StrictModel):
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    source_outcome_report: SourceOutcomeReport = "reported_certain"

    @field_validator("transition_ref", "idempotency_key")
    @classmethod
    def _base_refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)


class CaptureVendorIdentityCommand(_Command):
    kind: Literal["capture_vendor_identity"] = "capture_vendor_identity"
    requester_ref: str = Field(min_length=1, max_length=160)
    vendor_ref: str = Field(min_length=1, max_length=160)
    legal_entity_ref: str = Field(min_length=1, max_length=160)
    legal_name_commitment: str = Field(pattern=r"^[0-9a-f]{64}$")
    registration_artifact_ref: str = Field(min_length=10, max_length=200)
    registration_artifact_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tax_identity_artifact_ref: str = Field(min_length=10, max_length=200)
    tax_identity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    beneficial_owner_artifact_ref: str = Field(min_length=10, max_length=200)
    beneficial_owner_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    registered_site_ref: str = Field(min_length=1, max_length=160)
    captured_at: str

    @field_validator(
        "requester_ref", "vendor_ref", "legal_entity_ref", "registered_site_ref"
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator(
        "registration_artifact_ref",
        "tax_identity_artifact_ref",
        "beneficial_owner_artifact_ref",
    )
    @classmethod
    def _private_artifact_refs(cls, value: str, info: Any) -> str:
        return _private_ref(value, name=info.field_name)

    @field_validator("captured_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="captured_at")

    @model_validator(mode="after")
    def _artifacts_are_distinct(self) -> "CaptureVendorIdentityCommand":
        _unique(
            [
                self.registration_artifact_ref,
                self.tax_identity_artifact_ref,
                self.beneficial_owner_artifact_ref,
            ],
            name="private identity artifact references",
        )
        _unique(
            [
                self.legal_name_commitment,
                self.registration_artifact_digest,
                self.tax_identity_digest,
                self.beneficial_owner_digest,
            ],
            name="private identity commitments",
        )
        return self


class ClearVendorDueDiligenceCommand(_Command):
    kind: Literal["clear_vendor_due_diligence"] = "clear_vendor_due_diligence"
    due_diligence_assessor_ref: str = Field(min_length=1, max_length=160)
    identity_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    beneficial_owner_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanctions_screening_ref: str = Field(min_length=1, max_length=200)
    sanctions_screening_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanctions_status: Literal["clear"]
    kyc_aml_screening_ref: str = Field(min_length=1, max_length=200)
    kyc_aml_screening_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    kyc_aml_status: Literal["cleared"]
    conflict_screening_ref: str = Field(min_length=1, max_length=200)
    conflict_screening_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    conflict_status: Literal["clear"]
    screened_at: str
    valid_until: str

    @field_validator(
        "due_diligence_assessor_ref",
        "sanctions_screening_ref",
        "kyc_aml_screening_ref",
        "conflict_screening_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("screened_at", "valid_until")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _screenings_are_distinct_and_bounded(self) -> "ClearVendorDueDiligenceCommand":
        _unique(
            [
                self.sanctions_screening_ref,
                self.kyc_aml_screening_ref,
                self.conflict_screening_ref,
            ],
            name="due-diligence evidence references",
        )
        _unique(
            [
                self.sanctions_screening_digest,
                self.kyc_aml_screening_digest,
                self.conflict_screening_digest,
            ],
            name="due-diligence evidence digests",
        )
        if not _dt(self.screened_at) < _dt(self.valid_until):
            raise ValueError("due diligence must remain valid after screening")
        if _dt(self.valid_until) - _dt(self.screened_at) > MAX_QUALIFICATION_VALIDITY:
            raise ValueError("due-diligence validity exceeds the bounded window")
        return self


class AssessVendorQualificationCommand(_Command):
    kind: Literal["assess_vendor_qualification"] = "assess_vendor_qualification"
    assessor_ref: str = Field(min_length=1, max_length=160)
    due_diligence_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_evidence_ref: str = Field(min_length=1, max_length=200)
    capability_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_score: int = Field(ge=0, le=100)
    quality_evidence_ref: str = Field(min_length=1, max_length=200)
    quality_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    quality_score: int = Field(ge=0, le=100)
    financial_evidence_ref: str = Field(min_length=1, max_length=200)
    financial_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    financial_score: int = Field(ge=0, le=100)
    cyber_evidence_ref: str = Field(min_length=1, max_length=200)
    cyber_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    cyber_score: int = Field(ge=0, le=100)
    ehs_evidence_ref: str = Field(min_length=1, max_length=200)
    ehs_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    ehs_score: int = Field(ge=0, le=100)
    insurance_artifact_ref: str = Field(min_length=10, max_length=200)
    insurance_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    insurance_valid_until: str
    certification_artifact_ref: str = Field(min_length=10, max_length=200)
    certification_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    certifications_valid_until: str
    assessed_at: str

    @field_validator(
        "assessor_ref",
        "capability_evidence_ref",
        "quality_evidence_ref",
        "financial_evidence_ref",
        "cyber_evidence_ref",
        "ehs_evidence_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("insurance_artifact_ref", "certification_artifact_ref")
    @classmethod
    def _private_artifact_refs(cls, value: str, info: Any) -> str:
        return _private_ref(value, name=info.field_name)

    @field_validator(
        "insurance_valid_until", "certifications_valid_until", "assessed_at"
    )
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _assessment_artifacts_are_distinct(self) -> "AssessVendorQualificationCommand":
        _unique(
            [
                self.capability_evidence_ref,
                self.quality_evidence_ref,
                self.financial_evidence_ref,
                self.cyber_evidence_ref,
                self.ehs_evidence_ref,
                self.insurance_artifact_ref,
                self.certification_artifact_ref,
            ],
            name="qualification evidence references",
        )
        _unique(
            [
                self.capability_evidence_digest,
                self.quality_evidence_digest,
                self.financial_evidence_digest,
                self.cyber_evidence_digest,
                self.ehs_evidence_digest,
                self.insurance_digest,
                self.certification_digest,
            ],
            name="qualification evidence digests",
        )
        for label, value in (
            ("insurance", self.insurance_valid_until),
            ("certification", self.certifications_valid_until),
        ):
            if not _dt(self.assessed_at) < _dt(value):
                raise ValueError(f"{label} validity must follow assessment")
            if _dt(value) - _dt(self.assessed_at) > MAX_QUALIFICATION_VALIDITY:
                raise ValueError(f"{label} validity exceeds the bounded window")
        return self


class ProposeVendorApprovalCommand(_Command):
    kind: Literal["propose_vendor_approval"] = "propose_vendor_approval"
    approver_ref: str = Field(min_length=1, max_length=160)
    assessment_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: Literal["approved_with_controls"] = "approved_with_controls"
    risk_tier: RiskTier
    conditions: tuple[QualificationCondition, ...] = Field(
        default_factory=tuple, max_length=20
    )
    monitoring_interval_days: int = Field(ge=1, le=365)
    approved_at: str
    approval_valid_until: str
    renewal_due_at: str

    @field_validator("approver_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _visible(value, name="approver_ref")

    @field_validator("approved_at", "approval_valid_until", "renewal_due_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("conditions", mode="before")
    @classmethod
    def _condition_array(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="conditions")

    @model_validator(mode="after")
    def _conditions_and_validity_are_canonical(self) -> "ProposeVendorApprovalCommand":
        refs = [item.condition_ref for item in self.conditions]
        _unique(refs, name="qualification condition references")
        if refs != sorted(refs):
            raise ValueError(
                "qualification conditions must use canonical reference order"
            )
        if self.risk_tier in {"high", "critical"} and not self.conditions:
            raise ValueError(
                "high or critical risk requires bounded qualification conditions"
            )
        if self.risk_tier == "high" and not any(
            item.severity in {"material", "critical"} for item in self.conditions
        ):
            raise ValueError(
                "high risk requires a material or critical control condition"
            )
        if self.risk_tier == "critical" and not any(
            item.severity == "critical" for item in self.conditions
        ):
            raise ValueError("critical risk requires a critical control condition")
        if not (
            _dt(self.approved_at)
            < _dt(self.renewal_due_at)
            <= _dt(self.approval_valid_until)
        ):
            raise ValueError(
                "renewal must follow approval and not exceed approval validity"
            )
        if (
            _dt(self.approval_valid_until) - _dt(self.approved_at)
            > MAX_QUALIFICATION_VALIDITY
        ):
            raise ValueError("approval validity exceeds the bounded window")
        if any(_dt(item.due_at) > _dt(self.renewal_due_at) for item in self.conditions):
            raise ValueError(
                "qualification conditions cannot outlive the renewal fence"
            )
        return self


class VerifyVendorBankControlCommand(_Command):
    kind: Literal["verify_vendor_bank_control"] = "verify_vendor_bank_control"
    approval_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bank_submitter_ref: str = Field(min_length=1, max_length=160)
    bank_verifier_ref: str = Field(min_length=1, max_length=160)
    bank_account_artifact_ref: str = Field(min_length=10, max_length=200)
    bank_account_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bank_change_kind: Literal["initial", "change"]
    prior_bank_account_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    bank_change_request_ref: str | None = Field(
        default=None, min_length=1, max_length=200
    )
    bank_change_request_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    verification_evidence_ref: str = Field(min_length=1, max_length=200)
    verification_evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification_method: Literal[
        "independent_callback", "microdeposit", "verified_bank_letter"
    ]
    submitted_at: str
    verified_at: str

    @field_validator(
        "bank_submitter_ref",
        "bank_verifier_ref",
        "bank_change_request_ref",
        "verification_evidence_ref",
    )
    @classmethod
    def _refs(cls, value: str | None, info: Any) -> str | None:
        if value is None:
            return None
        return _visible(value, name=info.field_name)

    @field_validator("bank_account_artifact_ref")
    @classmethod
    def _private_artifact_ref(cls, value: str) -> str:
        return _private_ref(value, name="bank_account_artifact_ref")

    @field_validator("submitted_at", "verified_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _dual_control_and_change_fence(self) -> "VerifyVendorBankControlCommand":
        if self.bank_submitter_ref == self.bank_verifier_ref:
            raise ValueError(
                "bank setup and independent verification require two actors"
            )
        if _dt(self.verified_at) < _dt(self.submitted_at):
            raise ValueError("bank verification cannot predate submission")
        references = [
            self.bank_account_artifact_ref,
            self.verification_evidence_ref,
        ]
        commitments = [
            self.bank_account_digest,
            self.verification_evidence_digest,
        ]
        if self.bank_change_kind == "change":
            if (
                self.prior_bank_account_digest is None
                or self.bank_change_request_ref is None
                or self.bank_change_request_digest is None
            ):
                raise ValueError(
                    "bank change requires prior commitment and a bound change request"
                )
            if self.prior_bank_account_digest == self.bank_account_digest:
                raise ValueError("bank change must commit a different account artifact")
            references.append(self.bank_change_request_ref)
            commitments.extend(
                [
                    self.prior_bank_account_digest,
                    self.bank_change_request_digest,
                ]
            )
        elif any(
            item is not None
            for item in (
                self.prior_bank_account_digest,
                self.bank_change_request_ref,
                self.bank_change_request_digest,
            )
        ):
            raise ValueError("initial bank setup cannot claim a prior change fence")
        _unique(references, name="bank-control evidence references")
        _unique(commitments, name="bank-control evidence commitments")
        return self


class RecordVendorSetupReadinessCommand(_Command):
    kind: Literal["record_vendor_setup_readiness"] = "record_vendor_setup_readiness"
    setup_specialist_ref: str = Field(min_length=1, max_length=160)
    bank_control_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bank_account_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    purchasing_vendor_ref: str = Field(min_length=1, max_length=200)
    payment_vendor_ref: str = Field(min_length=1, max_length=200)
    category_assignment_ref: str = Field(min_length=1, max_length=200)
    category_ref: str = Field(min_length=1, max_length=160)
    site_assignment_ref: str = Field(min_length=1, max_length=200)
    site_ref: str = Field(min_length=1, max_length=160)
    payment_terms_ref: str = Field(min_length=1, max_length=160)
    purchasing_ready: Literal[True] = True
    payment_ready: Literal[True] = True
    category_ready: Literal[True] = True
    site_ready: Literal[True] = True
    setup_at: str

    @field_validator(
        "setup_specialist_ref",
        "purchasing_vendor_ref",
        "payment_vendor_ref",
        "category_assignment_ref",
        "category_ref",
        "site_assignment_ref",
        "site_ref",
        "payment_terms_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("setup_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="setup_at")

    @model_validator(mode="after")
    def _setup_refs_are_distinct(self) -> "RecordVendorSetupReadinessCommand":
        _unique(
            [
                self.purchasing_vendor_ref,
                self.payment_vendor_ref,
                self.category_assignment_ref,
                self.site_assignment_ref,
            ],
            name="vendor setup references",
        )
        return self


class ProposeVendorActivationCommand(_Command):
    kind: Literal["propose_vendor_activation"] = "propose_vendor_activation"
    activator_ref: str = Field(min_length=1, max_length=160)
    setup_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bank_control_command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    bank_account_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    monitoring_plan_ref: str = Field(min_length=1, max_length=200)
    monitoring_plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    suspension_policy_ref: str = Field(min_length=1, max_length=200)
    suspension_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanctions_rescreen_due_at: str
    renewal_due_at: str
    activation_candidate_at: str
    automatic_activation: Literal[False] = False

    @field_validator("activator_ref", "monitoring_plan_ref", "suspension_policy_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator(
        "sanctions_rescreen_due_at", "renewal_due_at", "activation_candidate_at"
    )
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _monitoring_fences_are_ordered(self) -> "ProposeVendorActivationCommand":
        if not (
            _dt(self.activation_candidate_at)
            < _dt(self.sanctions_rescreen_due_at)
            <= _dt(self.renewal_due_at)
        ):
            raise ValueError(
                "activation, sanctions rescreen, and renewal fences must be ordered"
            )
        if self.monitoring_plan_ref == self.suspension_policy_ref:
            raise ValueError(
                "monitoring and suspension controls require distinct references"
            )
        if self.monitoring_plan_digest == self.suspension_policy_digest:
            raise ValueError(
                "monitoring and suspension controls require distinct commitments"
            )
        return self


VendorOnboardingCommand = Annotated[
    Union[
        CaptureVendorIdentityCommand,
        ClearVendorDueDiligenceCommand,
        AssessVendorQualificationCommand,
        ProposeVendorApprovalCommand,
        VerifyVendorBankControlCommand,
        RecordVendorSetupReadinessCommand,
        ProposeVendorActivationCommand,
    ],
    Field(discriminator="kind"),
]
_COMMAND_ADAPTER = TypeAdapter(VendorOnboardingCommand)


def vendor_onboarding_command_digest(
    command: VendorOnboardingCommand | Mapping[str, Any],
) -> str:
    parsed = _COMMAND_ADAPTER.validate_python(_jsonable(command), strict=True)
    return _stable_digest(parsed)


_STATE_FOR_KIND: dict[str, VendorOnboardingState] = {
    "capture_vendor_identity": "identity_captured",
    "clear_vendor_due_diligence": "due_diligence_cleared",
    "assess_vendor_qualification": "qualification_assessed",
    "propose_vendor_approval": "approval_candidate",
    "verify_vendor_bank_control": "bank_control_verified",
    "record_vendor_setup_readiness": "setup_ready",
    "propose_vendor_activation": "activation_candidate",
}
_COMMAND_KIND_ORDER = tuple(_STATE_FOR_KIND)
_STATE_ORDER = tuple(_STATE_FOR_KIND.values())

_FACT_KIND: dict[str, str] = {
    "capture_vendor_identity": "vendor_legal_identity_private_artifact_commitment",
    "clear_vendor_due_diligence": "vendor_sanctions_kyc_aml_conflict_clearance",
    "assess_vendor_qualification": "vendor_multidomain_qualification_assessment",
    "propose_vendor_approval": "vendor_risk_conditions_approval_candidate",
    "verify_vendor_bank_control": "vendor_bank_dual_control_verification",
    "record_vendor_setup_readiness": "vendor_procurement_payment_setup_readiness",
    "propose_vendor_activation": "vendor_activation_monitoring_renewal_suspension_candidate",
}


def _command_occurred_at(command: VendorOnboardingCommand) -> str:
    if isinstance(command, CaptureVendorIdentityCommand):
        return command.captured_at
    if isinstance(command, ClearVendorDueDiligenceCommand):
        return command.screened_at
    if isinstance(command, AssessVendorQualificationCommand):
        return command.assessed_at
    if isinstance(command, ProposeVendorApprovalCommand):
        return command.approved_at
    if isinstance(command, VerifyVendorBankControlCommand):
        return command.verified_at
    if isinstance(command, RecordVendorSetupReadinessCommand):
        return command.setup_at
    return command.activation_candidate_at


def _primary_actor(command: VendorOnboardingCommand) -> str:
    if isinstance(command, CaptureVendorIdentityCommand):
        return command.requester_ref
    if isinstance(command, ClearVendorDueDiligenceCommand):
        return command.due_diligence_assessor_ref
    if isinstance(command, AssessVendorQualificationCommand):
        return command.assessor_ref
    if isinstance(command, ProposeVendorApprovalCommand):
        return command.approver_ref
    if isinstance(command, VerifyVendorBankControlCommand):
        return command.bank_verifier_ref
    if isinstance(command, RecordVendorSetupReadinessCommand):
        return command.setup_specialist_ref
    return command.activator_ref


def _fact_subject_ref(command: VendorOnboardingCommand) -> str:
    if isinstance(command, CaptureVendorIdentityCommand):
        return command.legal_entity_ref
    if isinstance(command, ClearVendorDueDiligenceCommand):
        return command.sanctions_screening_ref
    if isinstance(command, AssessVendorQualificationCommand):
        return command.capability_evidence_ref
    if isinstance(command, ProposeVendorApprovalCommand):
        return command.approver_ref
    if isinstance(command, VerifyVendorBankControlCommand):
        return command.verification_evidence_ref
    if isinstance(command, RecordVendorSetupReadinessCommand):
        return command.purchasing_vendor_ref
    return command.monitoring_plan_ref


def vendor_onboarding_idempotency_digest(
    scope: VendorOnboardingScope | Mapping[str, Any],
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    return _stable_digest(
        {
            "scope_digest": vendor_onboarding_scope_digest(scope),
            "lifecycle_ref": _visible(lifecycle_ref, name="lifecycle_ref"),
            "idempotency_key": _visible(idempotency_key, name="idempotency_key"),
        }
    )


def _transition_content_payload(
    *,
    scope_digest: str,
    lifecycle_ref: str,
    source_revision: int,
    source_state: VendorOnboardingState | None,
    source_state_digest: str,
    source_evidence_lineage_digest: str,
    transition_ref: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
    command_digest: str,
) -> dict[str, Any]:
    return {
        "schema": VENDOR_ONBOARDING_REQUEST_SCHEMA,
        "scope_digest": scope_digest,
        "lifecycle_ref": lifecycle_ref,
        "source_revision": source_revision,
        "source_state": source_state,
        "source_state_digest": source_state_digest,
        "source_evidence_lineage_digest": source_evidence_lineage_digest,
        "transition_ref": transition_ref,
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": requested_by_ref,
        "proposed_at": proposed_at,
        "command_digest": command_digest,
    }


def vendor_onboarding_fact_evidence_digest(
    scope: VendorOnboardingScope | Mapping[str, Any],
    lifecycle_ref: str,
    transition_ref: str,
    command: VendorOnboardingCommand | Mapping[str, Any],
) -> str:
    return _stable_digest(
        {
            "scope_digest": vendor_onboarding_scope_digest(scope),
            "lifecycle_ref": _visible(lifecycle_ref, name="lifecycle_ref"),
            "transition_ref": _visible(transition_ref, name="transition_ref"),
            "command_digest": vendor_onboarding_command_digest(command),
        }
    )


def vendor_onboarding_transition_commitment_digest(
    *, content_digest: str, fact_evidence_digest: str
) -> str:
    return _stable_digest(
        {
            "content_digest": content_digest,
            "fact_evidence_digest": fact_evidence_digest,
        }
    )


class VendorOnboardingTransitionRecord(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_transition.v1"] = Field(
        default=VENDOR_ONBOARDING_TRANSITION_SCHEMA, alias="schema"
    )
    revision: int = Field(ge=1, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    prior_state: VendorOnboardingState | None = None
    prior_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: VendorOnboardingState
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: VendorOnboardingCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: tuple[VendorOnboardingEvidence, ...] = Field(
        min_length=EVIDENCE_PER_VENDOR_TRANSITION,
        max_length=EVIDENCE_PER_VENDOR_TRANSITION,
    )
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative_scope_verified: Literal[False] = False
    rbac_authorized: Literal[False] = False
    authoritative_evidence_verified: Literal[False] = False
    authoritative_approval_recorded: Literal[False] = False
    vendor_master_persisted: Literal[False] = False
    payment_setup_persisted: Literal[False] = False
    live_effect_executed: Literal[False] = False
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "lifecycle_ref", "transition_ref", "idempotency_key", "requested_by_ref"
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_array(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="evidence")

    @model_validator(mode="after")
    def _record_is_content_bound(self) -> "VendorOnboardingTransitionRecord":
        command = _COMMAND_ADAPTER.validate_python(_jsonable(self.command), strict=True)
        evidence = tuple(
            VendorOnboardingEvidence.model_validate(_jsonable(item))
            for item in self.evidence
        )
        if command != self.command or evidence != self.evidence:
            raise ValueError("transition nested contracts must revalidate exactly")
        if self.transition_ref != command.transition_ref:
            raise ValueError("transition_ref must match the sealed command")
        if self.idempotency_key != command.idempotency_key:
            raise ValueError("idempotency_key must match the sealed command")
        if self.requested_by_ref != _primary_actor(command):
            raise ValueError("requested_by_ref must match the command's primary actor")
        if self.command_digest != vendor_onboarding_command_digest(command):
            raise ValueError("transition command_digest does not match command")
        if self.idempotency_digest != _stable_digest(
            {
                "scope_digest": self.scope_digest,
                "lifecycle_ref": self.lifecycle_ref,
                "idempotency_key": self.idempotency_key,
            }
        ):
            raise ValueError("transition idempotency fence does not match")
        expected_content = _stable_digest(
            _transition_content_payload(
                scope_digest=self.scope_digest,
                lifecycle_ref=self.lifecycle_ref,
                source_revision=self.revision - 1,
                source_state=self.prior_state,
                source_state_digest=self.prior_state_digest,
                source_evidence_lineage_digest=self.prior_evidence_lineage_digest,
                transition_ref=self.transition_ref,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
                command_digest=self.command_digest,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("transition content_digest does not match content")
        if self.state != _STATE_FOR_KIND[command.kind]:
            raise ValueError("transition state does not match command kind")
        if self.evidence_digest != _stable_digest(evidence):
            raise ValueError("transition evidence_digest does not match evidence")
        if self.evidence_lineage_digest != evidence[-1].lineage_digest:
            raise ValueError("transition evidence lineage must end at final evidence")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"transition_digest"},
        )
        if self.transition_digest != _stable_digest(payload):
            raise ValueError("transition_digest does not match transition content")
        return self


def _snapshot_payload(
    *,
    scope: VendorOnboardingScope,
    lifecycle_ref: str,
    history: Sequence[VendorOnboardingTransitionRecord],
) -> dict[str, Any]:
    return {
        "schema": VENDOR_ONBOARDING_SNAPSHOT_SCHEMA,
        "scope": scope,
        "scope_digest": vendor_onboarding_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        "revision": len(history),
        "state": history[-1].state,
        "history": tuple(history),
        "evidence_lineage_digest": history[-1].evidence_lineage_digest,
    }


def vendor_onboarding_snapshot_digest(
    snapshot: "VendorOnboardingSnapshot" | Mapping[str, Any],
) -> str:
    payload = _jsonable(snapshot)
    if not isinstance(payload, Mapping):
        raise ValueError("snapshot must be a mapping")
    content = dict(payload)
    content.pop("state_digest", None)
    return _stable_digest(content)


class VendorOnboardingSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_snapshot.v1"] = Field(
        default=VENDOR_ONBOARDING_SNAPSHOT_SCHEMA, alias="schema"
    )
    scope: VendorOnboardingScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    revision: int = Field(ge=1, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    state: VendorOnboardingState
    history: tuple[VendorOnboardingTransitionRecord, ...] = Field(
        min_length=1, max_length=MAX_VENDOR_ONBOARDING_TRANSITIONS
    )
    evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _visible(value, name="lifecycle_ref")

    @field_validator("history", mode="before")
    @classmethod
    def _history_array(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="history")

    @model_validator(mode="after")
    def _snapshot_is_canonical(self) -> "VendorOnboardingSnapshot":
        scope = VendorOnboardingScope.model_validate(_jsonable(self.scope))
        history = tuple(
            VendorOnboardingTransitionRecord.model_validate(_jsonable(item))
            for item in self.history
        )
        if scope != self.scope or history != self.history:
            raise ValueError("snapshot nested contracts must revalidate exactly")
        if self.scope_digest != vendor_onboarding_scope_digest(scope):
            raise ValueError("snapshot scope_digest does not match exact scope")
        if self.revision != len(history):
            raise ValueError("snapshot revision must equal history length")
        transition_refs: list[str] = []
        idempotency_digests: list[str] = []
        evidence_refs: list[str] = []
        evidence_sha256s: list[str] = []
        evidence_lineages: list[str] = []
        prior_state: VendorOnboardingState | None = None
        prior_state_digest = VENDOR_ONBOARDING_ZERO_DIGEST
        prior_lineage = VENDOR_ONBOARDING_ZERO_DIGEST
        for expected_revision, record in enumerate(history, start=1):
            if (
                record.revision != expected_revision
                or record.scope_digest != self.scope_digest
                or record.lifecycle_ref != self.lifecycle_ref
                or record.prior_state != prior_state
                or record.prior_state_digest != prior_state_digest
                or record.prior_evidence_lineage_digest != prior_lineage
            ):
                raise ValueError("snapshot transition chain is not canonical")
            transition_refs.append(record.transition_ref)
            idempotency_digests.append(record.idempotency_digest)
            evidence_refs.extend(item.evidence_ref for item in record.evidence)
            evidence_sha256s.extend(item.sha256 for item in record.evidence)
            evidence_lineages.extend(item.lineage_digest for item in record.evidence)
            prefix = _snapshot_payload(
                scope=scope,
                lifecycle_ref=self.lifecycle_ref,
                history=history[:expected_revision],
            )
            prefix["state_digest"] = _stable_digest(prefix)
            prior_state = record.state
            prior_state_digest = prefix["state_digest"]
            prior_lineage = record.evidence_lineage_digest
        _unique(transition_refs, name="transition references")
        _unique(idempotency_digests, name="idempotency digests")
        _unique(evidence_refs, name="single-use evidence references")
        _unique(evidence_sha256s, name="single-use evidence content digests")
        _unique(evidence_lineages, name="evidence lineage digests")
        if self.state != history[-1].state:
            raise ValueError("snapshot state does not match final transition")
        if self.evidence_lineage_digest != history[-1].evidence_lineage_digest:
            raise ValueError("snapshot lineage does not match final transition")
        if self.state_digest != vendor_onboarding_snapshot_digest(self):
            raise ValueError("snapshot state_digest does not match snapshot content")
        _validate_history_semantics(self)
        return self


class VendorOnboardingTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_request.v1"] = Field(
        default=VENDOR_ONBOARDING_REQUEST_SCHEMA, alias="schema"
    )
    scope: VendorOnboardingScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    expected_revision: int = Field(ge=0, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    expected_state: VendorOnboardingState | None = None
    expected_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_snapshot: VendorOnboardingSnapshot | None = None
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: VendorOnboardingCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: tuple[VendorOnboardingEvidence, ...] = Field(
        min_length=EVIDENCE_PER_VENDOR_TRANSITION,
        max_length=EVIDENCE_PER_VENDOR_TRANSITION,
    )

    @field_validator(
        "lifecycle_ref", "transition_ref", "idempotency_key", "requested_by_ref"
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence_array(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="evidence")

    @model_validator(mode="after")
    def _fences_and_digests(self) -> "VendorOnboardingTransitionRequest":
        scope = VendorOnboardingScope.model_validate(_jsonable(self.scope))
        command = _COMMAND_ADAPTER.validate_python(_jsonable(self.command), strict=True)
        evidence = tuple(
            VendorOnboardingEvidence.model_validate(_jsonable(item))
            for item in self.evidence
        )
        if scope != self.scope or command != self.command or evidence != self.evidence:
            raise ValueError("request nested contracts must revalidate exactly")
        if self.scope_digest != vendor_onboarding_scope_digest(scope):
            raise ValueError("request scope_digest does not match exact scope")
        if self.transition_ref != command.transition_ref:
            raise ValueError("request transition_ref must match sealed command")
        if self.idempotency_key != command.idempotency_key:
            raise ValueError("request idempotency_key must match sealed command")
        if self.requested_by_ref != _primary_actor(command):
            raise ValueError("requested_by_ref must match the command's primary actor")
        if self.command_digest != vendor_onboarding_command_digest(command):
            raise ValueError("request command_digest does not match command")
        if self.idempotency_digest != vendor_onboarding_idempotency_digest(
            scope, self.lifecycle_ref, self.idempotency_key
        ):
            raise ValueError("request idempotency digest does not match exact fence")
        expected_content = _stable_digest(
            _transition_content_payload(
                scope_digest=self.scope_digest,
                lifecycle_ref=self.lifecycle_ref,
                source_revision=self.expected_revision,
                source_state=self.expected_state,
                source_state_digest=self.expected_state_digest,
                source_evidence_lineage_digest=self.expected_evidence_lineage_digest,
                transition_ref=self.transition_ref,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
                command_digest=self.command_digest,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("request content_digest does not match transition content")
        if self.expected_revision == 0:
            if (
                self.expected_snapshot is not None
                or self.expected_state is not None
                or self.expected_state_digest != VENDOR_ONBOARDING_ZERO_DIGEST
                or self.expected_evidence_lineage_digest
                != VENDOR_ONBOARDING_ZERO_DIGEST
            ):
                raise ValueError("revision zero must use the exact genesis fence")
        else:
            if self.expected_snapshot is None:
                raise ValueError("nonzero revision requires the exact prior snapshot")
            snapshot = VendorOnboardingSnapshot.model_validate(
                _jsonable(self.expected_snapshot)
            )
            if (
                snapshot.scope != scope
                or snapshot.lifecycle_ref != self.lifecycle_ref
                or snapshot.revision != self.expected_revision
                or snapshot.state != self.expected_state
                or snapshot.state_digest != self.expected_state_digest
                or snapshot.evidence_lineage_digest
                != self.expected_evidence_lineage_digest
            ):
                raise ValueError(
                    "expected snapshot does not match exact revision fences"
                )
        return self


def vendor_onboarding_transition_content_digest(
    request: VendorOnboardingTransitionRequest | Mapping[str, Any],
) -> str:
    if isinstance(request, VendorOnboardingTransitionRequest):
        parsed = VendorOnboardingTransitionRequest.model_validate(_jsonable(request))
        return _stable_digest(
            _transition_content_payload(
                scope_digest=parsed.scope_digest,
                lifecycle_ref=parsed.lifecycle_ref,
                source_revision=parsed.expected_revision,
                source_state=parsed.expected_state,
                source_state_digest=parsed.expected_state_digest,
                source_evidence_lineage_digest=parsed.expected_evidence_lineage_digest,
                transition_ref=parsed.transition_ref,
                idempotency_digest=parsed.idempotency_digest,
                requested_by_ref=parsed.requested_by_ref,
                proposed_at=parsed.proposed_at,
                command_digest=parsed.command_digest,
            )
        )
    payload = dict(request)
    scope = VendorOnboardingScope.model_validate(payload["scope"])
    lifecycle_ref = _visible(payload["lifecycle_ref"], name="lifecycle_ref")
    idempotency_key = _visible(payload["idempotency_key"], name="idempotency_key")
    return _stable_digest(
        _transition_content_payload(
            scope_digest=vendor_onboarding_scope_digest(scope),
            lifecycle_ref=lifecycle_ref,
            source_revision=payload["expected_revision"],
            source_state=payload.get("expected_state"),
            source_state_digest=payload["expected_state_digest"],
            source_evidence_lineage_digest=payload["expected_evidence_lineage_digest"],
            transition_ref=_visible(payload["transition_ref"], name="transition_ref"),
            idempotency_digest=vendor_onboarding_idempotency_digest(
                scope, lifecycle_ref, idempotency_key
            ),
            requested_by_ref=_visible(
                payload["requested_by_ref"], name="requested_by_ref"
            ),
            proposed_at=_utc(payload["proposed_at"], name="proposed_at"),
            command_digest=vendor_onboarding_command_digest(payload["command"]),
        )
    )


class VendorOnboardingEffectBoundary(_StrictModel):
    authoritative_scope_verified: Literal[False] = False
    rbac_authorized: Literal[False] = False
    authoritative_evidence_verified: Literal[False] = False
    authoritative_approval_recorded: Literal[False] = False
    private_artifacts_read: Literal[False] = False
    vendor_master_created_or_changed: Literal[False] = False
    payment_data_created_or_changed: Literal[False] = False
    purchase_or_payment_authorized: Literal[False] = False
    supplier_activated: Literal[False] = False
    supplier_suspended: Literal[False] = False
    persistence_executed: Literal[False] = False
    provider_write_executed: Literal[False] = False
    spring_submission_executed: Literal[False] = False


class VendorOnboardingTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_proposal.v1"] = Field(
        default=VENDOR_ONBOARDING_PROPOSAL_SCHEMA, alias="schema"
    )
    scope: VendorOnboardingScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    source_revision: int = Field(ge=0, lt=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    source_state: VendorOnboardingState | None = None
    source_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_revision: int = Field(ge=1, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    target_state: VendorOnboardingState
    transition_ref: str = Field(min_length=1, max_length=160)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    effect_boundary: VendorOnboardingEffectBoundary
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref", "transition_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @model_validator(mode="after")
    def _proposal_is_bound(self) -> "VendorOnboardingTransitionProposal":
        scope = VendorOnboardingScope.model_validate(_jsonable(self.scope))
        if scope != self.scope or self.scope_digest != vendor_onboarding_scope_digest(
            scope
        ):
            raise ValueError("proposal scope digest does not match exact scope")
        if self.target_revision != self.source_revision + 1:
            raise ValueError("proposal must advance exactly one revision")
        expected_source_state = (
            None
            if self.source_revision == 0
            else _STATE_ORDER[self.source_revision - 1]
        )
        if self.source_state != expected_source_state:
            raise ValueError("proposal source state does not match source revision")
        if self.target_state != _STATE_ORDER[self.target_revision - 1]:
            raise ValueError("proposal target state does not match target revision")
        if self.source_revision == 0:
            if (
                self.source_state_digest != VENDOR_ONBOARDING_ZERO_DIGEST
                or self.source_evidence_lineage_digest != VENDOR_ONBOARDING_ZERO_DIGEST
            ):
                raise ValueError("genesis proposal must retain exact zero fences")
        elif (
            self.source_state_digest == VENDOR_ONBOARDING_ZERO_DIGEST
            or self.source_evidence_lineage_digest == VENDOR_ONBOARDING_ZERO_DIGEST
        ):
            raise ValueError("non-genesis proposal cannot use zero source fences")
        if (
            self.candidate_state_digest == self.source_state_digest
            or self.candidate_evidence_lineage_digest
            == self.source_evidence_lineage_digest
        ):
            raise ValueError("proposal candidate fences must advance source fences")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"proposal_digest"},
        )
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("proposal_digest does not match proposal content")
        return self


_EXPECTED_COMMAND_TYPES: tuple[type[_Command], ...] = (
    CaptureVendorIdentityCommand,
    ClearVendorDueDiligenceCommand,
    AssessVendorQualificationCommand,
    ProposeVendorApprovalCommand,
    VerifyVendorBankControlCommand,
    RecordVendorSetupReadinessCommand,
    ProposeVendorActivationCommand,
)


def _validate_evidence(
    *,
    scope: VendorOnboardingScope,
    lifecycle_ref: str,
    revision: int,
    prior_state_digest: str,
    prior_lineage_digest: str,
    transition_ref: str,
    proposed_at: str,
    command: VendorOnboardingCommand,
    content_digest: str,
    evidence: Sequence[VendorOnboardingEvidence],
) -> None:
    if len(evidence) != EVIDENCE_PER_VENDOR_TRANSITION:
        _reject(
            "vendor_onboarding_evidence_count_invalid",
            "Each transition requires exactly one verified fact and one attested commitment.",
        )
    parsed = tuple(
        VendorOnboardingEvidence.model_validate(_jsonable(item)) for item in evidence
    )
    refs = [item.evidence_ref for item in parsed]
    sha256s = [item.sha256 for item in parsed]
    lineages = [item.lineage_digest for item in parsed]
    try:
        _unique(refs, name="transition evidence references")
        _unique(sha256s, name="transition evidence content digests")
        _unique(lineages, name="transition evidence lineage digests")
    except ValueError as exc:
        _reject(
            "vendor_onboarding_evidence_duplicate",
            "Transition evidence references, content, and lineage must be unique.",
        )
        raise AssertionError("unreachable") from exc
    fact, commitment = parsed
    expected_fact_digest = vendor_onboarding_fact_evidence_digest(
        scope, lifecycle_ref, transition_ref, command
    )
    expected_commitment_digest = vendor_onboarding_transition_commitment_digest(
        content_digest=content_digest,
        fact_evidence_digest=expected_fact_digest,
    )
    expected_sequences = (
        (revision - 1) * EVIDENCE_PER_VENDOR_TRANSITION + 1,
        (revision - 1) * EVIDENCE_PER_VENDOR_TRANSITION + 2,
    )
    if (fact.sequence, commitment.sequence) != expected_sequences:
        _reject(
            "vendor_onboarding_evidence_sequence_invalid",
            "Evidence sequence must continue the exact append-only lifecycle order.",
        )
    for index, item in enumerate(parsed):
        if (
            item.issuer_ref != scope.spring_authority_ref
            or item.custodian_ref != scope.evidence_custodian_ref
            or item.retention_policy != scope.retention_policy_ref
            or item.jurisdiction != scope.jurisdiction_ref
            or item.classification != PrimitiveEvidenceClassification.RESTRICTED
        ):
            _reject(
                "vendor_onboarding_evidence_custody_mismatch",
                "Evidence must retain the exact Spring issuer, custodian, jurisdiction, classification, and retention policy.",
            )
        if (
            item.causal_revision != revision - 1
            or item.causal_state_digest != prior_state_digest
        ):
            _reject(
                "vendor_onboarding_evidence_causal_fence_mismatch",
                "Evidence must bind the exact prior revision and state digest.",
            )
        expected_predecessor = (
            prior_lineage_digest if index == 0 else parsed[index - 1].lineage_digest
        )
        if item.predecessor_lineage_digest != expected_predecessor:
            _reject(
                "vendor_onboarding_evidence_lineage_mismatch",
                "Evidence lineage must continue from the exact prior commitment.",
            )
    occurred_at = _command_occurred_at(command)
    if (
        fact.kind != _FACT_KIND[command.kind]
        or fact.subject_ref != _fact_subject_ref(command)
        or fact.sha256 != expected_fact_digest
        or fact.verification_grade != PrimitiveEvidenceVerificationGrade.VERIFIED
        or fact.effective_at != occurred_at
    ):
        _reject(
            "vendor_onboarding_fact_evidence_mismatch",
            "Fact evidence must exactly bind the command, subject, effective time, and verified grade.",
        )
    if (
        commitment.kind != "vendor_onboarding_transition_commitment"
        or commitment.subject_ref != transition_ref
        or commitment.sha256 != expected_commitment_digest
        or commitment.verification_grade != PrimitiveEvidenceVerificationGrade.ATTESTED
        or commitment.effective_at != commitment.observed_at
    ):
        _reject(
            "vendor_onboarding_commitment_evidence_mismatch",
            "Commitment evidence must exactly bind the transition content and fact.",
        )
    proposal_time = _dt(proposed_at)
    if not (
        _dt(occurred_at)
        <= _dt(fact.observed_at)
        <= _dt(commitment.observed_at)
        <= proposal_time
    ):
        _reject(
            "vendor_onboarding_evidence_chronology_invalid",
            "Evidence observation must follow the fact and precede the proposal in causal order.",
        )
    if proposal_time - _dt(fact.observed_at) > MAX_EVIDENCE_AGE:
        _reject(
            "vendor_onboarding_evidence_stale",
            "Transition fact evidence exceeds the bounded freshness window.",
            "refresh_snapshot",
        )


def _qualification_risk_tier(
    command: AssessVendorQualificationCommand,
) -> Literal["low", "medium", "high"]:
    floor = min(
        command.capability_score,
        command.quality_score,
        command.financial_score,
        command.cyber_score,
        command.ehs_score,
    )
    if floor >= 85:
        return "low"
    if floor >= 70:
        return "medium"
    return "high"


def _validate_semantic_transition(
    *,
    scope: VendorOnboardingScope,
    prior_records: Sequence[VendorOnboardingTransitionRecord],
    requested_by_ref: str,
    command: VendorOnboardingCommand,
    proposed_at: str,
) -> None:
    revision = len(prior_records) + 1
    if revision > MAX_VENDOR_ONBOARDING_TRANSITIONS:
        _reject(
            "vendor_onboarding_transition_limit_reached",
            "The bounded vendor-onboarding lifecycle is already complete.",
            "do_not_replay",
        )
    expected_type = _EXPECTED_COMMAND_TYPES[revision - 1]
    if not isinstance(command, expected_type):
        _reject(
            "vendor_onboarding_transition_out_of_order",
            "Apply exactly the next ordered vendor-onboarding transition.",
        )
    if command.source_outcome_report == "reported_in_doubt":
        _reject(
            "vendor_onboarding_authoritative_source_in_doubt",
            "Do not replay automatically; Spring must reconcile the authoritative source outcome and issue fresh evidence.",
            "manual_reconciliation",
            in_doubt=True,
        )
    if requested_by_ref != _primary_actor(command):
        _reject(
            "vendor_onboarding_actor_binding_mismatch",
            "The transition requester must be the command's exact primary actor.",
        )
    proposal_time = _dt(proposed_at)
    occurred_at = _dt(_command_occurred_at(command))
    if occurred_at > proposal_time:
        _reject(
            "vendor_onboarding_future_fact",
            "A transition cannot rely on a fact reported after proposal time.",
        )
    if prior_records:
        previous_time = _dt(_command_occurred_at(prior_records[-1].command))
        previous_proposal_time = _dt(prior_records[-1].proposed_at)
        first_time = _dt(_command_occurred_at(prior_records[0].command))
        if occurred_at < previous_time:
            _reject(
                "vendor_onboarding_transition_chronology_invalid",
                "Lifecycle facts must remain in nondecreasing causal order.",
            )
        if occurred_at < previous_proposal_time:
            _reject(
                "vendor_onboarding_predecessor_chronology_invalid",
                "A transition fact cannot predate materialization of its exact predecessor candidate.",
            )
        if proposal_time - first_time > MAX_LIFECYCLE_WINDOW:
            _reject(
                "vendor_onboarding_lifecycle_window_exceeded",
                "Refresh onboarding after the bounded lifecycle window expires.",
                "refresh_snapshot",
            )

    if isinstance(command, CaptureVendorIdentityCommand):
        if (
            command.vendor_ref != scope.vendor_ref
            or command.registered_site_ref != scope.site_ref
        ):
            _reject(
                "vendor_onboarding_identity_scope_mismatch",
                "Legal identity must bind the exact scoped vendor and site.",
            )
        return

    identity = prior_records[0].command
    assert isinstance(identity, CaptureVendorIdentityCommand)
    requester = identity.requester_ref

    if isinstance(command, ClearVendorDueDiligenceCommand):
        if (
            command.identity_command_digest != prior_records[0].command_digest
            or command.beneficial_owner_digest != identity.beneficial_owner_digest
        ):
            _reject(
                "vendor_onboarding_identity_binding_mismatch",
                "Due diligence must bind the exact identity and beneficial-owner commitments.",
            )
        if command.due_diligence_assessor_ref == requester:
            _reject(
                "vendor_onboarding_assessor_sod_violation",
                "Due-diligence assessment must be independent of the requester.",
            )
        if _dt(command.screened_at) < _dt(identity.captured_at):
            _reject(
                "vendor_onboarding_screening_predates_identity",
                "Due-diligence screening cannot predate identity capture.",
            )
        if _dt(command.valid_until) <= proposal_time:
            _reject(
                "vendor_onboarding_due_diligence_expired",
                "Due-diligence clearance must remain current at proposal time.",
                "refresh_snapshot",
            )
        return

    diligence = prior_records[1].command
    assert isinstance(diligence, ClearVendorDueDiligenceCommand)

    if isinstance(command, AssessVendorQualificationCommand):
        if command.due_diligence_command_digest != prior_records[1].command_digest:
            _reject(
                "vendor_onboarding_due_diligence_binding_mismatch",
                "Qualification must bind the exact due-diligence transition.",
            )
        if command.assessor_ref in {
            requester,
            diligence.due_diligence_assessor_ref,
        }:
            _reject(
                "vendor_onboarding_assessor_sod_violation",
                "Qualification assessment must be independent of the requester and due-diligence assessor.",
            )
        if _dt(command.assessed_at) < _dt(diligence.screened_at):
            _reject(
                "vendor_onboarding_assessment_predates_diligence",
                "Qualification assessment cannot predate due diligence.",
            )
        if _dt(diligence.valid_until) <= proposal_time:
            _reject(
                "vendor_onboarding_due_diligence_expired",
                "Due diligence expired before qualification assessment.",
                "refresh_snapshot",
            )
        if (
            min(
                command.capability_score,
                command.quality_score,
                command.financial_score,
                command.cyber_score,
                command.ehs_score,
            )
            < 60
        ):
            _reject(
                "vendor_onboarding_qualification_threshold_not_met",
                "Every required qualification domain must meet the minimum score.",
            )
        if (
            _dt(command.insurance_valid_until) <= proposal_time
            or _dt(command.certifications_valid_until) <= proposal_time
        ):
            _reject(
                "vendor_onboarding_qualification_artifact_expired",
                "Insurance and certification commitments must remain current.",
                "refresh_snapshot",
            )
        return

    assessment = prior_records[2].command
    assert isinstance(assessment, AssessVendorQualificationCommand)
    assessor_refs = {
        diligence.due_diligence_assessor_ref,
        assessment.assessor_ref,
    }

    if isinstance(command, ProposeVendorApprovalCommand):
        if command.assessment_command_digest != prior_records[2].command_digest:
            _reject(
                "vendor_onboarding_assessment_binding_mismatch",
                "Approval must bind the exact qualification assessment.",
            )
        if command.approver_ref in {requester, *assessor_refs}:
            _reject(
                "vendor_onboarding_approver_sod_violation",
                "Approval must be independent of requester and assessors.",
            )
        if _dt(command.approved_at) < _dt(assessment.assessed_at):
            _reject(
                "vendor_onboarding_approval_predates_assessment",
                "Approval cannot predate qualification assessment.",
            )
        if command.risk_tier != _qualification_risk_tier(assessment):
            _reject(
                "vendor_onboarding_risk_tier_mismatch",
                "Risk tier must match the deterministic qualification floor.",
            )
        risk_interval_ceiling = {"low": 365, "medium": 180, "high": 90}
        if command.monitoring_interval_days > risk_interval_ceiling[command.risk_tier]:
            _reject(
                "vendor_onboarding_monitoring_interval_too_long",
                "Monitoring cadence exceeds the exact risk-tier ceiling.",
            )
        if any(
            _dt(item.due_at) <= _dt(command.approved_at) for item in command.conditions
        ):
            _reject(
                "vendor_onboarding_condition_due_time_invalid",
                "Qualification condition due dates must follow approval.",
            )
        if (
            _dt(diligence.valid_until) <= proposal_time
            or _dt(assessment.insurance_valid_until) <= proposal_time
            or _dt(assessment.certifications_valid_until) <= proposal_time
        ):
            _reject(
                "vendor_onboarding_approval_source_expired",
                "Approval sources must remain current at proposal time.",
                "refresh_snapshot",
            )
        return

    approval = prior_records[3].command
    assert isinstance(approval, ProposeVendorApprovalCommand)

    if isinstance(command, VerifyVendorBankControlCommand):
        if command.approval_command_digest != prior_records[3].command_digest:
            _reject(
                "vendor_onboarding_approval_binding_mismatch",
                "Bank control must bind the exact approval candidate.",
            )
        prohibited = {requester, *assessor_refs, approval.approver_ref}
        if (
            command.bank_submitter_ref in prohibited
            or command.bank_verifier_ref in prohibited
        ):
            _reject(
                "vendor_onboarding_bank_control_sod_violation",
                "Bank submission and verification must be independent of requester, assessors, and approver.",
            )
        if _dt(command.submitted_at) < _dt(approval.approved_at):
            _reject(
                "vendor_onboarding_bank_setup_predates_approval",
                "Bank setup cannot predate the approval candidate.",
            )
        if _dt(approval.approval_valid_until) <= proposal_time:
            _reject(
                "vendor_onboarding_approval_expired",
                "Approval expired before bank verification.",
                "refresh_snapshot",
            )
        bank_refs = {
            command.bank_account_artifact_ref,
            command.verification_evidence_ref,
            *(
                (command.bank_change_request_ref,)
                if command.bank_change_request_ref is not None
                else ()
            ),
        }
        identity_refs = {
            identity.registration_artifact_ref,
            identity.tax_identity_artifact_ref,
            identity.beneficial_owner_artifact_ref,
        }
        bank_commitments = {
            command.bank_account_digest,
            command.verification_evidence_digest,
            *(
                (command.prior_bank_account_digest,)
                if command.prior_bank_account_digest is not None
                else ()
            ),
            *(
                (command.bank_change_request_digest,)
                if command.bank_change_request_digest is not None
                else ()
            ),
        }
        identity_commitments = {
            identity.legal_name_commitment,
            identity.registration_artifact_digest,
            identity.tax_identity_digest,
            identity.beneficial_owner_digest,
        }
        if bank_refs.intersection(identity_refs) or bank_commitments.intersection(
            identity_commitments
        ):
            _reject(
                "vendor_onboarding_private_commitment_reuse",
                "Bank and identity artifacts require distinct private references and commitments.",
            )
        return

    bank = prior_records[4].command
    assert isinstance(bank, VerifyVendorBankControlCommand)

    if isinstance(command, RecordVendorSetupReadinessCommand):
        if (
            command.bank_control_command_digest != prior_records[4].command_digest
            or command.bank_account_digest != bank.bank_account_digest
        ):
            _reject(
                "vendor_onboarding_bank_binding_mismatch",
                "Setup readiness must bind the exact bank-control commitment.",
            )
        prohibited = {
            requester,
            *assessor_refs,
            approval.approver_ref,
            bank.bank_submitter_ref,
            bank.bank_verifier_ref,
        }
        if command.setup_specialist_ref in prohibited:
            _reject(
                "vendor_onboarding_setup_sod_violation",
                "Setup specialist must be independent of prior request, assessment, approval, and bank-control actors.",
            )
        if (
            command.category_ref != scope.category_ref
            or command.site_ref != scope.site_ref
        ):
            _reject(
                "vendor_onboarding_setup_scope_mismatch",
                "Category and site assignments must match the exact onboarding scope.",
            )
        if _dt(command.setup_at) < _dt(bank.verified_at):
            _reject(
                "vendor_onboarding_setup_predates_bank_control",
                "Setup readiness cannot predate bank verification.",
            )
        if _dt(approval.approval_valid_until) <= proposal_time:
            _reject(
                "vendor_onboarding_approval_expired",
                "Approval expired before setup readiness.",
                "refresh_snapshot",
            )
        return

    setup = prior_records[5].command
    assert isinstance(setup, RecordVendorSetupReadinessCommand)
    assert isinstance(command, ProposeVendorActivationCommand)
    if (
        command.setup_command_digest != prior_records[5].command_digest
        or command.approval_command_digest != prior_records[3].command_digest
        or command.bank_control_command_digest != prior_records[4].command_digest
        or command.bank_account_digest != bank.bank_account_digest
    ):
        _reject(
            "vendor_onboarding_activation_binding_mismatch",
            "Activation must bind exact approval, bank-control, setup, and account commitments.",
        )
    prohibited = {
        requester,
        *assessor_refs,
        approval.approver_ref,
        bank.bank_submitter_ref,
        bank.bank_verifier_ref,
        setup.setup_specialist_ref,
    }
    if command.activator_ref in prohibited:
        _reject(
            "vendor_onboarding_activator_sod_violation",
            "Activation review must be independent of all prior onboarding actors.",
        )
    if _dt(command.activation_candidate_at) < _dt(setup.setup_at):
        _reject(
            "vendor_onboarding_activation_predates_setup",
            "Activation candidate cannot predate setup readiness.",
        )
    if command.renewal_due_at != approval.renewal_due_at:
        _reject(
            "vendor_onboarding_renewal_fence_mismatch",
            "Activation must preserve the exact approved renewal fence.",
        )
    if _dt(command.sanctions_rescreen_due_at) > _dt(diligence.valid_until):
        _reject(
            "vendor_onboarding_rescreen_fence_too_late",
            "Sanctions rescreen must occur before current due diligence expires.",
        )
    if _dt(command.sanctions_rescreen_due_at) > _dt(
        command.activation_candidate_at
    ) + timedelta(days=approval.monitoring_interval_days):
        _reject(
            "vendor_onboarding_monitoring_fence_too_late",
            "The first sanctions rescreen must fit the approved risk-tier monitoring cadence.",
        )
    if any(
        deadline <= proposal_time
        for deadline in (
            _dt(diligence.valid_until),
            _dt(assessment.insurance_valid_until),
            _dt(assessment.certifications_valid_until),
            _dt(approval.approval_valid_until),
            _dt(approval.renewal_due_at),
        )
    ):
        _reject(
            "vendor_onboarding_activation_source_expired",
            "Due diligence, insurance, certifications, approval, and renewal must remain current.",
            "refresh_snapshot",
        )
    if any(item.severity == "critical" for item in approval.conditions):
        _reject(
            "vendor_onboarding_critical_condition_open",
            "An unresolved critical condition blocks activation candidacy.",
        )
    if any(
        item.severity == "material" and _dt(item.due_at) <= proposal_time
        for item in approval.conditions
    ):
        _reject(
            "vendor_onboarding_material_condition_overdue",
            "An unresolved material condition due by proposal time blocks activation candidacy.",
        )


def _validate_history_semantics(snapshot: VendorOnboardingSnapshot) -> None:
    prior: list[VendorOnboardingTransitionRecord] = []
    for record in snapshot.history:
        _validate_evidence(
            scope=snapshot.scope,
            lifecycle_ref=snapshot.lifecycle_ref,
            revision=record.revision,
            prior_state_digest=record.prior_state_digest,
            prior_lineage_digest=record.prior_evidence_lineage_digest,
            transition_ref=record.transition_ref,
            proposed_at=record.proposed_at,
            command=record.command,
            content_digest=record.content_digest,
            evidence=record.evidence,
        )
        _validate_semantic_transition(
            scope=snapshot.scope,
            prior_records=prior,
            requested_by_ref=record.requested_by_ref,
            command=record.command,
            proposed_at=record.proposed_at,
        )
        prior.append(record)


def _materialize_candidate(
    request: VendorOnboardingTransitionRequest,
) -> tuple[
    VendorOnboardingSnapshot,
    VendorOnboardingTransitionProposal,
    VendorOnboardingTransitionRecord,
]:
    history = (
        list(request.expected_snapshot.history)
        if request.expected_snapshot is not None
        else []
    )
    if len(history) >= MAX_VENDOR_ONBOARDING_TRANSITIONS:
        _reject(
            "vendor_onboarding_transition_limit_reached",
            "The bounded vendor-onboarding lifecycle is already complete.",
            "do_not_replay",
        )
    for record in history:
        if record.transition_ref == request.transition_ref:
            _reject(
                "vendor_onboarding_duplicate_transition",
                "The transition identity is already present; do not append it again.",
                "do_not_replay",
            )
        if (
            record.idempotency_key == request.idempotency_key
            or record.idempotency_digest == request.idempotency_digest
        ):
            _reject(
                "vendor_onboarding_idempotency_conflict",
                "The idempotency identity conflicts with prior transition content.",
                "do_not_replay",
            )
    prior_evidence_refs = {
        item.evidence_ref for record in history for item in record.evidence
    }
    prior_evidence_sha256s = {
        item.sha256 for record in history for item in record.evidence
    }
    current_refs = [item.evidence_ref for item in request.evidence]
    current_sha256s = [item.sha256 for item in request.evidence]
    if len(set(current_refs)) != len(current_refs) or len(set(current_sha256s)) != len(
        current_sha256s
    ):
        _reject(
            "vendor_onboarding_duplicate_current_evidence",
            "Current evidence references and content digests must be unique.",
        )
    if prior_evidence_refs.intersection(
        current_refs
    ) or prior_evidence_sha256s.intersection(current_sha256s):
        _reject(
            "vendor_onboarding_evidence_reuse",
            "Single-use evidence reference or content was already consumed.",
            "do_not_replay",
        )
    _validate_evidence(
        scope=request.scope,
        lifecycle_ref=request.lifecycle_ref,
        revision=request.expected_revision + 1,
        prior_state_digest=request.expected_state_digest,
        prior_lineage_digest=request.expected_evidence_lineage_digest,
        transition_ref=request.transition_ref,
        proposed_at=request.proposed_at,
        command=request.command,
        content_digest=request.content_digest,
        evidence=request.evidence,
    )
    _validate_semantic_transition(
        scope=request.scope,
        prior_records=history,
        requested_by_ref=request.requested_by_ref,
        command=request.command,
        proposed_at=request.proposed_at,
    )
    record_payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_TRANSITION_SCHEMA,
        "revision": request.expected_revision + 1,
        "scope_digest": request.scope_digest,
        "lifecycle_ref": request.lifecycle_ref,
        "prior_state": request.expected_state,
        "prior_state_digest": request.expected_state_digest,
        "prior_evidence_lineage_digest": request.expected_evidence_lineage_digest,
        "state": _STATE_FOR_KIND[request.command.kind],
        "transition_ref": request.transition_ref,
        "idempotency_key": request.idempotency_key,
        "idempotency_digest": request.idempotency_digest,
        "requested_by_ref": request.requested_by_ref,
        "proposed_at": request.proposed_at,
        "command": request.command,
        "command_digest": request.command_digest,
        "content_digest": request.content_digest,
        "evidence": request.evidence,
        "evidence_digest": _stable_digest(request.evidence),
        "evidence_lineage_digest": request.evidence[-1].lineage_digest,
        "authoritative_scope_verified": False,
        "rbac_authorized": False,
        "authoritative_evidence_verified": False,
        "authoritative_approval_recorded": False,
        "vendor_master_persisted": False,
        "payment_setup_persisted": False,
        "live_effect_executed": False,
    }
    record_payload["transition_digest"] = _stable_digest(
        {key: value for key, value in record_payload.items() if value is not None}
    )
    record = VendorOnboardingTransitionRecord.model_validate(record_payload)
    next_history = [*history, record]
    snapshot_payload = _snapshot_payload(
        scope=request.scope,
        lifecycle_ref=request.lifecycle_ref,
        history=next_history,
    )
    snapshot_payload["state_digest"] = _stable_digest(snapshot_payload)
    snapshot = VendorOnboardingSnapshot.model_validate(snapshot_payload)
    proposal_payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_PROPOSAL_SCHEMA,
        "scope": request.scope,
        "scope_digest": request.scope_digest,
        "lifecycle_ref": request.lifecycle_ref,
        "source_revision": request.expected_revision,
        "source_state": request.expected_state,
        "source_state_digest": request.expected_state_digest,
        "source_evidence_lineage_digest": request.expected_evidence_lineage_digest,
        "target_revision": snapshot.revision,
        "target_state": snapshot.state,
        "transition_ref": request.transition_ref,
        "command_digest": request.command_digest,
        "content_digest": request.content_digest,
        "idempotency_digest": request.idempotency_digest,
        "evidence_digest": _stable_digest(request.evidence),
        "transition_digest": record.transition_digest,
        "candidate_state_digest": snapshot.state_digest,
        "candidate_evidence_lineage_digest": snapshot.evidence_lineage_digest,
        "effect_boundary": VendorOnboardingEffectBoundary(),
    }
    proposal_payload["proposal_digest"] = _stable_digest(
        {key: value for key, value in proposal_payload.items() if value is not None}
    )
    proposal = VendorOnboardingTransitionProposal.model_validate(proposal_payload)
    return snapshot, proposal, record


class VendorOnboardingRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: str | None = Field(default=None, min_length=1, max_length=600)

    @model_validator(mode="after")
    def _recovery_is_bounded(self) -> "VendorOnboardingRecovery":
        if self.disposition == "not_required" and self.instructions is not None:
            raise ValueError("successful candidate needs no recovery instructions")
        if self.disposition != "not_required" and self.instructions is None:
            raise ValueError(
                "non-success outcome requires bounded recovery instructions"
            )
        return self


class VendorOnboardingTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_receipt.v1"] = Field(
        default=VENDOR_ONBOARDING_RECEIPT_SCHEMA, alias="schema"
    )
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    command_kind: str = Field(min_length=1, max_length=100)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_revision: int = Field(ge=0, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    to_revision: int = Field(ge=0, le=MAX_VENDOR_ONBOARDING_TRANSITIONS)
    from_state: VendorOnboardingState | None = None
    to_state: VendorOnboardingState | None = None
    from_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    to_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    from_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    to_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transition_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    proposal_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: VendorOnboardingRecovery
    authoritative_scope_verified: Literal[False] = False
    authoritative_approval_recorded: Literal[False] = False
    live_systems_changed: Literal[False] = False
    supplier_activated: Literal[False] = False
    receipt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("transition_ref", "idempotency_key", "command_kind")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @model_validator(mode="after")
    def _receipt_is_coherent(self) -> "VendorOnboardingTransitionReceipt":
        if self.command_kind not in _STATE_FOR_KIND:
            raise ValueError("receipt command kind is not a vendor-onboarding command")
        expected_from_state = (
            None if self.from_revision == 0 else _STATE_ORDER[self.from_revision - 1]
        )
        if self.from_state != expected_from_state:
            raise ValueError("receipt from_state does not match from_revision")
        if self.from_revision == 0:
            if (
                self.from_state_digest != VENDOR_ONBOARDING_ZERO_DIGEST
                or self.from_evidence_lineage_digest != VENDOR_ONBOARDING_ZERO_DIGEST
            ):
                raise ValueError("genesis receipt must retain exact zero fences")
        elif (
            self.from_state_digest == VENDOR_ONBOARDING_ZERO_DIGEST
            or self.from_evidence_lineage_digest == VENDOR_ONBOARDING_ZERO_DIGEST
        ):
            raise ValueError("non-genesis receipt cannot use zero source fences")
        if self.status == "candidate_materialized":
            if (
                self.to_revision != self.from_revision + 1
                or self.to_state is None
                or self.transition_digest is None
                or self.proposal_digest is None
                or self.rejection_code is not None
                or self.recovery.disposition != "not_required"
            ):
                raise ValueError("candidate receipt must prove one exact transition")
            if (
                self.command_kind != _COMMAND_KIND_ORDER[self.to_revision - 1]
                or self.to_state != _STATE_ORDER[self.to_revision - 1]
            ):
                raise ValueError(
                    "candidate receipt command and state must match target revision"
                )
            if (
                self.to_state_digest == self.from_state_digest
                or self.to_evidence_lineage_digest == self.from_evidence_lineage_digest
            ):
                raise ValueError(
                    "candidate receipt must advance state and evidence fences"
                )
        else:
            if (
                self.to_revision != self.from_revision
                or self.to_state != self.from_state
                or self.to_state_digest != self.from_state_digest
                or self.to_evidence_lineage_digest != self.from_evidence_lineage_digest
                or self.transition_digest is not None
                or self.proposal_digest is not None
                or self.rejection_code is None
                or self.recovery.disposition == "not_required"
            ):
                raise ValueError("non-success receipt must preserve exact prior state")
        if self.status == "in_doubt" and self.recovery.disposition != (
            "manual_reconciliation"
        ):
            raise ValueError("in-doubt receipt requires manual reconciliation")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"receipt_digest"},
        )
        if self.receipt_digest != _stable_digest(payload):
            raise ValueError("receipt_digest does not match receipt content")
        return self


class VendorOnboardingTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.vendor_onboarding_result.v1"] = Field(
        default=VENDOR_ONBOARDING_RESULT_SCHEMA, alias="schema"
    )
    candidate_validated: bool
    evaluated_request: VendorOnboardingTransitionRequest
    snapshot: VendorOnboardingSnapshot | None = None
    proposal: VendorOnboardingTransitionProposal | None = None
    transition_receipt: VendorOnboardingTransitionReceipt
    authority_boundary: Literal[
        "sdk_candidate_only_spring_and_governed_systems_authoritative"
    ] = "sdk_candidate_only_spring_and_governed_systems_authoritative"
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _result_is_request_and_outcome_bound(
        self,
    ) -> "VendorOnboardingTransitionResult":
        request = VendorOnboardingTransitionRequest.model_validate(
            _jsonable(self.evaluated_request)
        )
        receipt = VendorOnboardingTransitionReceipt.model_validate(
            _jsonable(self.transition_receipt)
        )
        expected_from_state = request.expected_state
        expected_evidence_digest = _stable_digest(request.evidence)
        if (
            receipt.transition_ref != request.transition_ref
            or receipt.idempotency_key != request.idempotency_key
            or receipt.request_digest != request.content_digest
            or receipt.command_kind != request.command.kind
            or receipt.command_digest != request.command_digest
            or receipt.evidence_digest != expected_evidence_digest
            or receipt.from_revision != request.expected_revision
            or receipt.from_state != expected_from_state
            or receipt.from_state_digest != request.expected_state_digest
            or receipt.from_evidence_lineage_digest
            != request.expected_evidence_lineage_digest
        ):
            raise ValueError("transition receipt must bind the exact evaluated request")
        succeeded = receipt.status == "candidate_materialized"
        if self.candidate_validated != succeeded:
            raise ValueError("candidate_validated must match receipt status")
        if succeeded:
            if self.snapshot is None or self.proposal is None:
                raise ValueError("validated candidate requires snapshot and proposal")
            replay_snapshot, replay_proposal, replay_record = _materialize_candidate(
                request
            )
            if self.snapshot != replay_snapshot or self.proposal != replay_proposal:
                raise ValueError("candidate result must equal deterministic replay")
            if (
                receipt.to_revision != replay_snapshot.revision
                or receipt.to_state != replay_snapshot.state
                or receipt.to_state_digest != replay_snapshot.state_digest
                or receipt.to_evidence_lineage_digest
                != replay_snapshot.evidence_lineage_digest
                or receipt.transition_digest != replay_record.transition_digest
                or receipt.proposal_digest != replay_proposal.proposal_digest
            ):
                raise ValueError("candidate receipt does not prove resulting snapshot")
        else:
            if self.proposal is not None or self.snapshot != request.expected_snapshot:
                raise ValueError(
                    "non-success result must preserve the exact prior snapshot"
                )
            try:
                _materialize_candidate(request)
            except _TransitionRejected as exc:
                expected_status = "in_doubt" if exc.in_doubt else "rejected"
                if (
                    receipt.status != expected_status
                    or receipt.rejection_code != exc.code
                    or receipt.recovery.disposition != exc.recovery
                    or receipt.recovery.instructions != exc.instructions
                ):
                    raise ValueError(
                        "non-success receipt does not retain deterministic rejection"
                    ) from exc
            else:
                raise ValueError(
                    "a materializable request cannot carry rejection receipt"
                )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"result_digest"},
        )
        if self.result_digest != _stable_digest(payload):
            raise ValueError("result_digest does not match result content")
        return self


def _current_fences(
    request: VendorOnboardingTransitionRequest,
) -> tuple[int, VendorOnboardingState | None, str, str]:
    return (
        request.expected_revision,
        request.expected_state,
        request.expected_state_digest,
        request.expected_evidence_lineage_digest,
    )


def _receipt_payload(
    request: VendorOnboardingTransitionRequest,
    *,
    status: Literal["candidate_materialized", "rejected", "in_doubt"],
    snapshot: VendorOnboardingSnapshot | None,
    proposal: VendorOnboardingTransitionProposal | None,
    record: VendorOnboardingTransitionRecord | None,
    rejection_code: str | None,
    recovery: VendorOnboardingRecovery,
) -> dict[str, Any]:
    from_revision, from_state, from_digest, from_lineage = _current_fences(request)
    payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_RECEIPT_SCHEMA,
        "transition_ref": request.transition_ref,
        "idempotency_key": request.idempotency_key,
        "request_digest": request.content_digest,
        "command_kind": request.command.kind,
        "command_digest": request.command_digest,
        "evidence_digest": _stable_digest(request.evidence),
        "status": status,
        "from_revision": from_revision,
        "to_revision": snapshot.revision
        if status == "candidate_materialized"
        else from_revision,
        "from_state": from_state,
        "to_state": snapshot.state
        if status == "candidate_materialized"
        else from_state,
        "from_state_digest": from_digest,
        "to_state_digest": (
            snapshot.state_digest if status == "candidate_materialized" else from_digest
        ),
        "from_evidence_lineage_digest": from_lineage,
        "to_evidence_lineage_digest": (
            snapshot.evidence_lineage_digest
            if status == "candidate_materialized"
            else from_lineage
        ),
        "transition_digest": record.transition_digest if record is not None else None,
        "proposal_digest": proposal.proposal_digest if proposal is not None else None,
        "rejection_code": rejection_code,
        "recovery": recovery,
        "authoritative_scope_verified": False,
        "authoritative_approval_recorded": False,
        "live_systems_changed": False,
        "supplier_activated": False,
    }
    payload["receipt_digest"] = _stable_digest(
        {key: value for key, value in payload.items() if value is not None}
    )
    return payload


def _result_payload(
    *,
    candidate_validated: bool,
    request: VendorOnboardingTransitionRequest,
    snapshot: VendorOnboardingSnapshot | None,
    proposal: VendorOnboardingTransitionProposal | None,
    receipt: VendorOnboardingTransitionReceipt,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_RESULT_SCHEMA,
        "candidate_validated": candidate_validated,
        "evaluated_request": request,
        "snapshot": snapshot,
        "proposal": proposal,
        "transition_receipt": receipt,
        "authority_boundary": (
            "sdk_candidate_only_spring_and_governed_systems_authoritative"
        ),
    }
    payload["result_digest"] = _stable_digest(
        {key: value for key, value in payload.items() if value is not None}
    )
    return payload


def propose_vendor_onboarding_transition(
    request: VendorOnboardingTransitionRequest | Mapping[str, Any],
) -> VendorOnboardingTransitionResult:
    """Validate one exact transition and return a sealed SDK-only outcome."""

    try:
        parsed = VendorOnboardingTransitionRequest.model_validate(_jsonable(request))
    except (ValidationError, ValueError, TypeError, KeyError) as exc:
        raise VendorOnboardingLifecycleError(
            "vendor_onboarding_request_invalid",
            "Vendor-onboarding request failed strict schema, nesting, or digest validation.",
        ) from exc
    try:
        snapshot, proposal, record = _materialize_candidate(parsed)
    except _TransitionRejected as exc:
        recovery = VendorOnboardingRecovery(
            disposition=exc.recovery,
            instructions=exc.instructions,
        )
        receipt_payload = _receipt_payload(
            parsed,
            status="in_doubt" if exc.in_doubt else "rejected",
            snapshot=None,
            proposal=None,
            record=None,
            rejection_code=exc.code,
            recovery=recovery,
        )
        receipt = VendorOnboardingTransitionReceipt.model_validate(receipt_payload)
        return VendorOnboardingTransitionResult.model_validate(
            _result_payload(
                candidate_validated=False,
                request=parsed,
                snapshot=parsed.expected_snapshot,
                proposal=None,
                receipt=receipt,
            )
        )
    receipt = VendorOnboardingTransitionReceipt.model_validate(
        _receipt_payload(
            parsed,
            status="candidate_materialized",
            snapshot=snapshot,
            proposal=proposal,
            record=record,
            rejection_code=None,
            recovery=VendorOnboardingRecovery(disposition="not_required"),
        )
    )
    return VendorOnboardingTransitionResult.model_validate(
        _result_payload(
            candidate_validated=True,
            request=parsed,
            snapshot=snapshot,
            proposal=proposal,
            receipt=receipt,
        )
    )


VENDOR_ONBOARDING_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="vendor-onboarding.materialize-transition-candidate.v1",
    tool="sdk.procurement.propose_vendor_onboarding_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)


def _scope_matches_context(
    request: VendorOnboardingTransitionRequest,
    context: PrimitiveExecutionContext,
) -> bool:
    return (
        request.scope.tenant_ref == context.scope.tenant_ref
        and request.scope.company_ref == context.scope.company_ref
        and request.scope.project_ref == context.scope.project_ref
        and request.scope.project_id == context.scope.project_id
        and context.scope.actor_ref is not None
        and request.requested_by_ref == context.scope.actor_ref
        and context.idempotency_key is not None
        and request.idempotency_key == context.idempotency_key
    )


def _example_evidence_payload(
    *,
    scope: Mapping[str, Any],
    sequence: int,
    evidence_ref: str,
    kind: str,
    subject_ref: str,
    sha256: str,
    observed_at: str,
    effective_at: str,
    grade: Literal["attested", "verified"],
    causal_revision: int,
    causal_state_digest: str,
    predecessor_lineage_digest: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_EVIDENCE_SCHEMA,
        "sequence": sequence,
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": scope["spring_authority_ref"],
        "custodian_ref": scope["evidence_custodian_ref"],
        "subject_ref": subject_ref,
        "sha256": sha256,
        "observed_at": observed_at,
        "effective_at": effective_at,
        "verification_grade": grade,
        "classification": "restricted",
        "retention_policy": scope["retention_policy_ref"],
        "jurisdiction": scope["jurisdiction_ref"],
        "retained_until": "2034-09-01T00:00:00Z",
        "single_use": True,
        "causal_revision": causal_revision,
        "causal_state_digest": causal_state_digest,
        "predecessor_lineage_digest": predecessor_lineage_digest,
    }
    payload["lineage_digest"] = vendor_onboarding_evidence_lineage_digest(payload)
    return payload


def _example_inputs() -> dict[str, Any]:
    scope: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_SCOPE_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000941",
        "procurement_org_ref": "procurement-org-example",
        "vendor_ref": "vendor-example",
        "category_ref": "category-components",
        "site_ref": "site-example",
        "jurisdiction_ref": "US-NY",
        "retention_policy_ref": "vendor-onboarding-seven-years",
        "evidence_custodian_ref": "spring:vendor-evidence-vault",
        "spring_authority_ref": "spring:vendor-authority",
    }
    command: dict[str, Any] = {
        "kind": "capture_vendor_identity",
        "transition_ref": "vendor-transition-identity-example",
        "idempotency_key": "vendor-idempotency-identity-example",
        "source_outcome_report": "reported_certain",
        "requester_ref": "vendor-requester-example",
        "vendor_ref": scope["vendor_ref"],
        "legal_entity_ref": "legal-entity-example",
        "legal_name_commitment": _stable_digest("legal-name-example"),
        "registration_artifact_ref": "vault:vendor-registration-example",
        "registration_artifact_digest": _stable_digest("registration-example"),
        "tax_identity_artifact_ref": "vault:vendor-tax-example",
        "tax_identity_digest": _stable_digest("tax-example"),
        "beneficial_owner_artifact_ref": "vault:vendor-beneficial-owner-example",
        "beneficial_owner_digest": _stable_digest("beneficial-owner-example"),
        "registered_site_ref": scope["site_ref"],
        "captured_at": "2026-08-25T10:00:00Z",
    }
    lifecycle_ref = "vendor-onboarding-example"
    proposed_at = "2026-08-25T10:05:00Z"
    request_payload: dict[str, Any] = {
        "schema": VENDOR_ONBOARDING_REQUEST_SCHEMA,
        "scope": scope,
        "scope_digest": vendor_onboarding_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        "expected_revision": 0,
        "expected_state": None,
        "expected_state_digest": VENDOR_ONBOARDING_ZERO_DIGEST,
        "expected_evidence_lineage_digest": VENDOR_ONBOARDING_ZERO_DIGEST,
        "transition_ref": command["transition_ref"],
        "idempotency_key": command["idempotency_key"],
        "idempotency_digest": vendor_onboarding_idempotency_digest(
            scope, lifecycle_ref, command["idempotency_key"]
        ),
        "requested_by_ref": command["requester_ref"],
        "proposed_at": proposed_at,
        "command": command,
        "command_digest": vendor_onboarding_command_digest(command),
    }
    request_payload["content_digest"] = vendor_onboarding_transition_content_digest(
        request_payload
    )
    fact_digest = vendor_onboarding_fact_evidence_digest(
        scope, lifecycle_ref, command["transition_ref"], command
    )
    fact = _example_evidence_payload(
        scope=scope,
        sequence=1,
        evidence_ref="vendor-evidence-identity-example",
        kind=_FACT_KIND[command["kind"]],
        subject_ref=command["legal_entity_ref"],
        sha256=fact_digest,
        observed_at="2026-08-25T10:01:00Z",
        effective_at=command["captured_at"],
        grade="verified",
        causal_revision=0,
        causal_state_digest=VENDOR_ONBOARDING_ZERO_DIGEST,
        predecessor_lineage_digest=VENDOR_ONBOARDING_ZERO_DIGEST,
    )
    commitment = _example_evidence_payload(
        scope=scope,
        sequence=2,
        evidence_ref="vendor-evidence-commitment-example",
        kind="vendor_onboarding_transition_commitment",
        subject_ref=command["transition_ref"],
        sha256=vendor_onboarding_transition_commitment_digest(
            content_digest=request_payload["content_digest"],
            fact_evidence_digest=fact_digest,
        ),
        observed_at="2026-08-25T10:04:00Z",
        effective_at="2026-08-25T10:04:00Z",
        grade="attested",
        causal_revision=0,
        causal_state_digest=VENDOR_ONBOARDING_ZERO_DIGEST,
        predecessor_lineage_digest=fact["lineage_digest"],
    )
    request_payload["evidence"] = [fact, commitment]
    return VendorOnboardingTransitionRequest.model_validate(request_payload).to_dict()


class ProposeVendorOnboardingTransitionPrimitive(
    BusinessProcessPrimitive[
        VendorOnboardingTransitionRequest,
        VendorOnboardingTransitionResult,
    ]
):
    primitive_ref = "procurement.propose_vendor_onboarding_transition"
    version = "1.0.0"
    title = "Propose a bounded vendor-onboarding transition"
    description = (
        "Validate one exact-scope, evidence-bound vendor-onboarding candidate "
        "without reading private artifacts, authorizing or persisting a vendor, "
        "changing payment data, activating a supplier, or calling a provider."
    )
    input_model = VendorOnboardingTransitionRequest
    output_model = VendorOnboardingTransitionResult
    connector_tools = ()
    risk_level = "high"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = (
            VENDOR_ONBOARDING_TRANSITION_OPERATION.to_dict()
        )
        contract["effect_boundary"] = VendorOnboardingEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "spring_control_plane": (
                "authenticated tenant/company/project/procurement scope, RBAC, "
                "private-artifact and evidence verification, approval, persistence, "
                "audit, idempotency admission, and governed write authorization"
            ),
            "governed_operational_systems": (
                "KYC/AML and sanctions facts, vendor master and purchasing setup, "
                "payment data, activation, monitoring, renewal, and suspension"
            ),
            "sdk": "strict deterministic read-only candidate materialization",
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_VENDOR_ONBOARDING_TRANSITIONS,
            "scope": (
                "exact tenant/company/project/project-id/procurement-org/vendor/category/site"
            ),
            "private_data": "opaque artifact refs and SHA-256 commitments only",
            "history": "immutable append-only command, evidence, transition, and state digests",
            "evidence": (
                "exact issuer, custodian, retention, jurisdiction, freshness, grade, "
                "subject, causal revision, and lineage fences"
            ),
            "segregation_of_duties": (
                "requester, assessor, approver, bank submitter/verifier, setup, and activation review"
            ),
            "live_effects": False,
        }
        contract["portable_evidence_is_execution_authority"] = False
        contract["non_preview_result_is_still_preview"] = True
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: VendorOnboardingTransitionRequest,
    ) -> PrimitiveExecutionResult[VendorOnboardingTransitionResult]:
        portable_evidence = [item.portable_ref() for item in inputs.evidence]
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="vendor_onboarding_runtime_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, project-id, actor, and "
                    "idempotency fences are required and must exactly match the request."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Vendor-onboarding candidate rejected at runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=VENDOR_ONBOARDING_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.content_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        try:
            output = propose_vendor_onboarding_transition(inputs)
        except VendorOnboardingLifecycleError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Vendor-onboarding request failed strict validation.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=VENDOR_ONBOARDING_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.content_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )

        receipt = output.transition_receipt
        if receipt.status != "candidate_materialized":
            blocker = PrimitiveBlocker(
                code=receipt.rejection_code or "vendor_onboarding_transition_rejected",
                message=(
                    receipt.recovery.instructions
                    or "Vendor-onboarding transition was rejected."
                ),
                retryable=False,
            )
            if receipt.status == "in_doubt":
                recovery_plan = PrimitiveRecoveryPlan(
                    policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                    disposition=(
                        PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
                    ),
                    instructions=receipt.recovery.instructions,
                )
                return PrimitiveExecutionResult(
                    status=PrimitiveExecutionStatus.FAILED,
                    primitive_ref=self.primitive_ref,
                    primitive_version=self.version,
                    summary=(
                        "Vendor-onboarding source outcome is in doubt; no SDK or live state changed."
                    ),
                    output=output,
                    blockers=[blocker],
                    evidence_refs=portable_evidence,
                    operation_receipts=[
                        PrimitiveOperationReceipt(
                            spec=VENDOR_ONBOARDING_TRANSITION_OPERATION,
                            status=PrimitiveOperationStatus.IN_DOUBT,
                            request_digest=inputs.content_digest,
                            evidence_refs=portable_evidence,
                            recovery_disposition=(
                                PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
                            ),
                            recovery_plan=recovery_plan,
                            error=blocker,
                        )
                    ],
                    recovery_plan=recovery_plan,
                    retryable=False,
                )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Vendor-onboarding transition failed deterministic validation.",
                output=output,
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=VENDOR_ONBOARDING_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.content_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )

        proposal = output.proposal
        assert proposal is not None
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Vendor-onboarding candidate passed deterministic validation; no "
                "Spring, procurement, vendor-master, payment, or provider state changed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="procurement.vendor_onboarding_transition_candidate_validated",
                    payload={
                        "lifecycle_ref": proposal.lifecycle_ref,
                        "transition_ref": proposal.transition_ref,
                        "target_state": proposal.target_state,
                        "proposal_digest": proposal.proposal_digest,
                        "authoritative_scope_verified": False,
                        "authoritative_approval_recorded": False,
                        "private_artifacts_read": False,
                        "vendor_master_changed": False,
                        "payment_data_changed": False,
                        "supplier_activated": False,
                        "provider_write_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="vendor_onboarding_transition_candidate",
                    summary=(
                        "Content-bound SDK candidate; Spring and governed operational "
                        "systems retain fact, scope, approval, persistence, and effect authority."
                    ),
                    labels=[
                        inputs.command.kind,
                        proposal.target_state,
                        "preview_only",
                        "no_live_effect",
                    ],
                    refs={
                        "proposal_digest": proposal.proposal_digest,
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "receipt_digest": receipt.receipt_digest,
                    },
                )
            ],
            evidence_refs=portable_evidence,
            operation_receipts=[
                PrimitiveOperationReceipt(
                    spec=VENDOR_ONBOARDING_TRANSITION_OPERATION,
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.content_digest,
                    external_refs={
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "proposal_digest": proposal.proposal_digest,
                        "transition_digest": proposal.transition_digest,
                        "receipt_digest": receipt.receipt_digest,
                    },
                    evidence_refs=portable_evidence,
                    replayed=False,
                )
            ],
            retryable=False,
        )


VENDOR_ONBOARDING_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeVendorOnboardingTransitionPrimitive(),)


__all__ = [
    "EVIDENCE_PER_VENDOR_TRANSITION",
    "MAX_VENDOR_ONBOARDING_TRANSITIONS",
    "VENDOR_ONBOARDING_EVIDENCE_SCHEMA",
    "VENDOR_ONBOARDING_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "VENDOR_ONBOARDING_PROPOSAL_SCHEMA",
    "VENDOR_ONBOARDING_RECEIPT_SCHEMA",
    "VENDOR_ONBOARDING_REQUEST_SCHEMA",
    "VENDOR_ONBOARDING_RESULT_SCHEMA",
    "VENDOR_ONBOARDING_SCOPE_SCHEMA",
    "VENDOR_ONBOARDING_SNAPSHOT_SCHEMA",
    "VENDOR_ONBOARDING_TRANSITION_OPERATION",
    "VENDOR_ONBOARDING_TRANSITION_SCHEMA",
    "VENDOR_ONBOARDING_ZERO_DIGEST",
    "AssessVendorQualificationCommand",
    "CaptureVendorIdentityCommand",
    "ClearVendorDueDiligenceCommand",
    "ProposeVendorActivationCommand",
    "ProposeVendorApprovalCommand",
    "ProposeVendorOnboardingTransitionPrimitive",
    "QualificationCondition",
    "RecordVendorSetupReadinessCommand",
    "VendorOnboardingCommand",
    "VendorOnboardingEffectBoundary",
    "VendorOnboardingEvidence",
    "VendorOnboardingLifecycleError",
    "VendorOnboardingRecovery",
    "VendorOnboardingScope",
    "VendorOnboardingSnapshot",
    "VendorOnboardingTransitionProposal",
    "VendorOnboardingTransitionReceipt",
    "VendorOnboardingTransitionRecord",
    "VendorOnboardingTransitionRequest",
    "VendorOnboardingTransitionResult",
    "VerifyVendorBankControlCommand",
    "propose_vendor_onboarding_transition",
    "vendor_onboarding_command_digest",
    "vendor_onboarding_evidence_lineage_digest",
    "vendor_onboarding_fact_evidence_digest",
    "vendor_onboarding_idempotency_digest",
    "vendor_onboarding_scope_digest",
    "vendor_onboarding_snapshot_digest",
    "vendor_onboarding_transition_commitment_digest",
    "vendor_onboarding_transition_content_digest",
]
