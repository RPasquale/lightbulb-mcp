"""Deterministic, no-effect people-operations lifecycle proposals.

The SDK owns portable contract validation and candidate-state projection only.
It does not hire, schedule, approve time or leave, change compensation, export
payroll, terminate employment, revoke access, persist state, or call a provider.
Spring remains authoritative for authenticated scope, identity/RBAC, employment
and compensation decisions, approvals, durable idempotency, persistence, audit,
payroll/HCM/IAM writes, and verification of access-revocation provenance.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from typing import Annotated, Any, Literal, Union
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    field_validator,
    model_validator,
)

from lightbulb.connector_execution import ConnectorEffect
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


PEOPLE_OPERATIONS_SCOPE_SCHEMA = "lightbulb.people_operations_scope.v1"
PEOPLE_PAY_PERIOD_SCHEMA = "lightbulb.people_pay_period.v1"
PEOPLE_APPROVAL_EVIDENCE_SCHEMA = "lightbulb.people_approval_evidence.v1"
PEOPLE_TRANSITION_REQUEST_SCHEMA = "lightbulb.people_transition_request.v1"
PEOPLE_TRANSITION_CANDIDATE_SCHEMA = "lightbulb.people_transition_candidate.v1"
PEOPLE_OPERATIONS_SNAPSHOT_SCHEMA = "lightbulb.people_operations_snapshot.v1"
PEOPLE_TRANSITION_PROPOSAL_SCHEMA = "lightbulb.people_transition_proposal.v1"
PEOPLE_TRANSITION_RESULT_SCHEMA = "lightbulb.people_transition_result.v1"
PEOPLE_TRANSITION_EVIDENCE_COMMITMENT_SCHEMA = (
    "lightbulb.people_transition_evidence_commitment.v1"
)
PEOPLE_PAYROLL_CALCULATION_BASIS_SCHEMA = (
    "lightbulb.people_payroll_calculation_basis.v1"
)
PEOPLE_ACCESS_REVOCATION_EVIDENCE_SCHEMA = (
    "lightbulb.people_access_revocation_evidence.v1"
)
SPRING_PEOPLE_EVIDENCE_ISSUER = "spring-people-authority"
ZERO_DIGEST = "0" * 64

_MAX_TRANSITIONS = 32
_MAX_EVIDENCE_PER_TRANSITION = 12
_MAX_CERTIFICATIONS = 24
_MAX_ACCESS_SYSTEMS = 24
_MAX_EVIDENCE_AGE = timedelta(days=7)
_MONEY_QUANTUM = Decimal("0.01")
_HOURS_QUANTUM = Decimal("0.001")
_RATIO_QUANTUM = Decimal("0.001")
_MAX_MONEY = Decimal("9999999999999999.99")
_MAX_HOURS = Decimal("744.000")
_MAX_PAY_PERIODS_PER_YEAR = 366
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_JURISDICTION_PATTERN = r"^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$"


def _bounded_visible(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError("reference must contain visible characters without whitespace")
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_bounded_visible),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
JurisdictionCode = Annotated[
    str,
    StringConstraints(pattern=_JURISDICTION_PATTERN),
]

PayRateUom = Literal["hour", "year"]
SalaryPeriodBasis = Literal["full_period_unprorated"]
PayPeriodsPerYear = Annotated[
    int,
    Field(strict=True, ge=1, le=_MAX_PAY_PERIODS_PER_YEAR),
]
HoursUom = Literal["hour"]
CandidateStage = Literal[
    "sourced", "screened", "interviewed", "offer_approved", "hired"
]
PeopleLifecycleState = Literal[
    "candidate_sourced",
    "candidate_screened",
    "candidate_interviewed",
    "offer_approved",
    "active",
    "offboarding_pending",
    "revocation_verified",
    "offboarded",
]
ApprovalRole = Literal[
    "workforce_authorizer",
    "recruiting_authorizer",
    "people_operations_authorizer",
    "workforce_scheduler",
    "time_authorizer",
    "leave_authorizer",
    "compensation_authorizer",
    "payroll_authorizer",
    "offboarding_authorizer",
]

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


def _stable_digest(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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


def _date(value: str, *, field_name: str) -> str:
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid ISO date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{field_name} must be a canonical ISO date")
    return value


def _decimal(
    value: Any,
    *,
    quantum: Decimal,
    upper: Decimal,
    signed: bool = False,
) -> Decimal:
    if isinstance(value, (bool, float)) or not isinstance(value, (str, int, Decimal)):
        raise ValueError("decimal values must be strings, integers, or Decimal values")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("decimal values must use bounded canonical notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(
            "decimal value must be finite and within supported precision"
        ) from exc
    if not parsed.is_finite() or parsed != normalized or abs(parsed) > upper:
        raise ValueError("decimal value exceeds supported precision or bounds")
    if not signed and parsed < 0:
        raise ValueError("decimal value cannot be negative")
    return normalized


def _money(value: Any, *, signed: bool = False) -> Decimal:
    return _decimal(
        value,
        quantum=_MONEY_QUANTUM,
        upper=_MAX_MONEY,
        signed=signed,
    )


def _hours(value: Any) -> Decimal:
    return _decimal(value, quantum=_HOURS_QUANTUM, upper=_MAX_HOURS)


def _ratio(value: Any) -> Decimal:
    return _decimal(value, quantum=_RATIO_QUANTUM, upper=Decimal("10.000"))


def _elapsed_hours(start: str, end: str, *, break_minutes: int = 0) -> Decimal:
    delta = _parsed_timestamp(end) - _parsed_timestamp(start)
    microseconds = (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000 + delta.microseconds
    net_microseconds = microseconds - break_minutes * 60 * 1_000_000
    if net_microseconds <= 0:
        raise ValueError("time interval must remain positive after breaks")
    hours = Decimal(net_microseconds) / Decimal(3_600_000_000)
    try:
        normalized = hours.quantize(_HOURS_QUANTUM)
    except InvalidOperation as exc:
        raise ValueError("time interval exceeds supported precision") from exc
    if hours != normalized:
        raise ValueError(
            "time interval must resolve to exact thousandth-hour precision"
        )
    return normalized


def _annual_salary_period_gross(
    annual_rate: Decimal,
    pay_periods_per_year: int,
) -> Decimal:
    """Return the deterministic cents amount for one full salary period."""

    with localcontext() as context:
        context.prec = 64
        context.rounding = ROUND_HALF_EVEN
        return (annual_rate / Decimal(pay_periods_per_year)).quantize(
            _MONEY_QUANTUM,
            rounding=ROUND_HALF_EVEN,
        )


class PeopleOperationsScope(_StrictModel):
    schema_id: Literal["lightbulb.people_operations_scope.v1"] = Field(
        default=PEOPLE_OPERATIONS_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    worker_ref: OpaqueRef
    candidate_ref: OpaqueRef
    position_ref: OpaqueRef
    jurisdiction: JurisdictionCode
    payroll_currency: CurrencyCode
    pay_rate_uom: PayRateUom
    pay_periods_per_year: PayPeriodsPerYear | None = None

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

    @model_validator(mode="after")
    def _annual_salary_frequency_is_exact(self) -> "PeopleOperationsScope":
        if self.pay_rate_uom == "year" and self.pay_periods_per_year is None:
            raise ValueError("annual salary scope requires exact pay periods per year")
        if self.pay_rate_uom == "hour" and self.pay_periods_per_year is not None:
            raise ValueError("hourly scope cannot declare annual salary pay periods")
        return self


def people_scope_digest(value: PeopleOperationsScope | Mapping[str, Any]) -> str:
    parsed = PeopleOperationsScope.model_validate(value)
    return _stable_digest(parsed.to_dict())


class PeoplePayPeriod(_StrictModel):
    schema_id: Literal["lightbulb.people_pay_period.v1"] = Field(
        default=PEOPLE_PAY_PERIOD_SCHEMA,
        alias="schema",
    )
    pay_period_ref: OpaqueRef
    starts_on: str
    ends_on: str
    jurisdiction: JurisdictionCode
    currency: CurrencyCode

    @field_validator("starts_on", "ends_on")
    @classmethod
    def _dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _period_is_bounded(self) -> "PeoplePayPeriod":
        starts = date.fromisoformat(self.starts_on)
        ends = date.fromisoformat(self.ends_on)
        if ends < starts or (ends - starts).days > 45:
            raise ValueError("pay period must be ordered and no longer than 46 days")
        return self


class PeopleApprovalEvidence(_StrictModel):
    schema_id: Literal["lightbulb.people_approval_evidence.v1"] = Field(
        default=PEOPLE_APPROVAL_EVIDENCE_SCHEMA,
        alias="schema",
    )
    approval_ref: OpaqueRef
    approval_receipt_digest: Sha256Digest
    scope_digest: Sha256Digest
    lifecycle_ref: OpaqueRef
    transition_ref: OpaqueRef
    command_digest: Sha256Digest
    idempotency_digest: Sha256Digest
    approved_by_ref: OpaqueRef
    approver_role: ApprovalRole
    approved_at: str
    expires_at: str
    decision: Literal["approved"] = "approved"
    single_use: Literal[True] = True
    sdk_execution_authority_granted: Literal[False] = False
    evidence: PrimitiveEvidenceRef
    approval_digest: Sha256Digest

    @field_validator("approved_at", "expires_at")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _approval_is_content_bound(self) -> "PeopleApprovalEvidence":
        approved_at = _parsed_timestamp(self.approved_at)
        expires_at = _parsed_timestamp(self.expires_at)
        if expires_at <= approved_at or expires_at - approved_at > timedelta(hours=24):
            raise ValueError("approval evidence must expire within 24 hours")
        expected = people_approval_digest(self)
        if self.approval_digest != expected or self.evidence.sha256 != expected:
            raise ValueError("approval digest does not match exact approval content")
        if (
            self.evidence.issuer_ref != SPRING_PEOPLE_EVIDENCE_ISSUER
            or self.evidence.subject_ref != self.approval_ref
            or self.evidence.kind != "people_approval_decision"
            or self.evidence.verification_grade
            != PrimitiveEvidenceVerificationGrade.VERIFIED
        ):
            raise ValueError("approval requires exact verified Spring evidence custody")
        observed_at = _parsed_timestamp(self.evidence.observed_at)
        if observed_at < approved_at or observed_at > expires_at:
            raise ValueError(
                "approval evidence observation must fall inside its validity window"
            )
        return self


def people_approval_digest(value: PeopleApprovalEvidence | Mapping[str, Any]) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    payload.pop("approval_digest", None)
    payload.pop("evidence", None)
    return _stable_digest(payload)


class _PeopleCommand(_StrictModel):
    worker_ref: OpaqueRef
    candidate_ref: OpaqueRef
    position_ref: OpaqueRef
    jurisdiction: JurisdictionCode
    approval: PeopleApprovalEvidence | None = None


class CreateCandidateCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_create_candidate_command.v1"] = Field(
        default="lightbulb.people_create_candidate_command.v1",
        alias="schema",
    )
    kind: Literal["create_candidate"] = "create_candidate"
    recruiting_source_ref: OpaqueRef
    headcount_plan_ref: OpaqueRef
    position_authorization_ref: OpaqueRef
    position_status: Literal["approved_open"] = "approved_open"


class AdvanceCandidateCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_advance_candidate_command.v1"] = Field(
        default="lightbulb.people_advance_candidate_command.v1",
        alias="schema",
    )
    kind: Literal["advance_candidate"] = "advance_candidate"
    target_stage: Literal["screened", "interviewed", "offer_approved"]
    evaluation_ref: OpaqueRef


class ActivateWorkerCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_activate_worker_command.v1"] = Field(
        default="lightbulb.people_activate_worker_command.v1",
        alias="schema",
    )
    kind: Literal["activate_worker"] = "activate_worker"
    worker_activation_ref: OpaqueRef
    employment_agreement_ref: OpaqueRef
    compensation_ref: OpaqueRef
    employment_starts_at: str
    base_pay_rate: Decimal
    currency: CurrencyCode
    pay_rate_uom: PayRateUom

    @field_validator("employment_starts_at")
    @classmethod
    def _start_time(cls, value: str) -> str:
        return _timestamp(value, field_name="employment_starts_at")

    @field_validator("base_pay_rate", mode="before")
    @classmethod
    def _base_rate(cls, value: Any) -> Decimal:
        parsed = _money(value)
        if parsed <= 0:
            raise ValueError("base pay rate must be positive")
        return parsed


class ScheduleShiftCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_schedule_shift_command.v1"] = Field(
        default="lightbulb.people_schedule_shift_command.v1",
        alias="schema",
    )
    kind: Literal["schedule_shift"] = "schedule_shift"
    shift_ref: OpaqueRef
    starts_at: str
    ends_at: str
    break_minutes: int = Field(ge=0, le=720)
    scheduled_hours: Decimal
    hours_uom: HoursUom = "hour"

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("scheduled_hours", mode="before")
    @classmethod
    def _scheduled_hours(cls, value: Any) -> Decimal:
        parsed = _hours(value)
        if parsed <= 0 or parsed > Decimal("24.000"):
            raise ValueError("scheduled shift hours must be positive and at most 24")
        return parsed

    @model_validator(mode="after")
    def _shift_math_is_exact(self) -> "ScheduleShiftCommand":
        if (
            _elapsed_hours(
                self.starts_at,
                self.ends_at,
                break_minutes=self.break_minutes,
            )
            != self.scheduled_hours
        ):
            raise ValueError(
                "scheduled hours do not match exact shift duration and break"
            )
        return self


class RecordApprovedTimecardCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_record_timecard_command.v1"] = Field(
        default="lightbulb.people_record_timecard_command.v1",
        alias="schema",
    )
    kind: Literal["record_approved_timecard"] = "record_approved_timecard"
    timecard_ref: OpaqueRef
    shift_ref: OpaqueRef
    pay_period: PeoplePayPeriod
    regular_hours: Decimal
    overtime_hours: Decimal
    worked_hours: Decimal
    paid_leave_hours: Decimal = Decimal("0.000")
    hours_uom: HoursUom = "hour"

    @field_validator(
        "regular_hours",
        "overtime_hours",
        "worked_hours",
        "paid_leave_hours",
        mode="before",
    )
    @classmethod
    def _hour_values(cls, value: Any) -> Decimal:
        return _hours(value)

    @model_validator(mode="after")
    def _timecard_math_is_exact(self) -> "RecordApprovedTimecardCommand":
        if self.regular_hours + self.overtime_hours != self.worked_hours:
            raise ValueError("worked hours must equal regular plus overtime hours")
        return self


class RecordApprovedLeaveCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_record_leave_command.v1"] = Field(
        default="lightbulb.people_record_leave_command.v1",
        alias="schema",
    )
    kind: Literal["record_approved_leave"] = "record_approved_leave"
    leave_ref: OpaqueRef
    leave_type_ref: OpaqueRef
    pay_period: PeoplePayPeriod
    starts_at: str
    ends_at: str
    requested_hours: Decimal
    balance_before_hours: Decimal
    balance_after_hours: Decimal
    paid_leave: bool
    payroll_reconciled: bool
    hours_uom: HoursUom = "hour"

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "requested_hours",
        "balance_before_hours",
        "balance_after_hours",
        mode="before",
    )
    @classmethod
    def _hour_values(cls, value: Any) -> Decimal:
        return _hours(value)

    @model_validator(mode="after")
    def _leave_math_is_exact(self) -> "RecordApprovedLeaveCommand":
        if self.requested_hours <= 0:
            raise ValueError("leave hours must be positive")
        if self.requested_hours > _elapsed_hours(self.starts_at, self.ends_at):
            raise ValueError("leave hours cannot exceed the exact leave interval")
        if self.balance_before_hours - self.requested_hours != self.balance_after_hours:
            raise ValueError("leave balance does not reconcile exactly")
        return self


class RecordPerformanceCompensationCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_performance_compensation_command.v1"] = Field(
        default="lightbulb.people_performance_compensation_command.v1",
        alias="schema",
    )
    kind: Literal["record_performance_compensation"] = "record_performance_compensation"
    performance_review_ref: OpaqueRef
    performance_cycle_ref: OpaqueRef
    reviewer_ref: OpaqueRef
    compensation_ref: OpaqueRef
    old_base_pay_rate: Decimal
    compensation_change: Decimal
    new_base_pay_rate: Decimal
    currency: CurrencyCode
    pay_rate_uom: PayRateUom
    effective_at: str

    @field_validator("old_base_pay_rate", "new_base_pay_rate", mode="before")
    @classmethod
    def _rates(cls, value: Any) -> Decimal:
        return _money(value)

    @field_validator("compensation_change", mode="before")
    @classmethod
    def _change(cls, value: Any) -> Decimal:
        return _money(value, signed=True)

    @field_validator("effective_at")
    @classmethod
    def _effective_time(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_at")

    @model_validator(mode="after")
    def _compensation_math_is_exact(self) -> "RecordPerformanceCompensationCommand":
        if self.new_base_pay_rate <= 0:
            raise ValueError("new base pay rate must be positive")
        if self.old_base_pay_rate + self.compensation_change != self.new_base_pay_rate:
            raise ValueError("compensation change does not reconcile old and new rate")
        return self


class RecordCertificationCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_certification_command.v1"] = Field(
        default="lightbulb.people_certification_command.v1",
        alias="schema",
    )
    kind: Literal["record_certification"] = "record_certification"
    learning_record_ref: OpaqueRef
    certification_ref: OpaqueRef
    credential_ref: OpaqueRef
    issued_on: str
    expires_on: str
    status: Literal["current"] = "current"
    required_for_position: bool

    @field_validator("issued_on", "expires_on")
    @classmethod
    def _dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _certification_window_is_valid(self) -> "RecordCertificationCommand":
        if date.fromisoformat(self.expires_on) <= date.fromisoformat(self.issued_on):
            raise ValueError("certification expiry must follow issuance")
        return self


class PreparePayrollHandoffCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_payroll_handoff_command.v1"] = Field(
        default="lightbulb.people_payroll_handoff_command.v1",
        alias="schema",
    )
    kind: Literal["prepare_payroll_handoff"] = "prepare_payroll_handoff"
    payroll_handoff_ref: OpaqueRef
    payroll_account_ref: OpaqueRef
    pay_period: PeoplePayPeriod
    timecard_ref: OpaqueRef
    compensation_ref: OpaqueRef
    base_pay_rate: Decimal
    overtime_multiplier: Decimal = Decimal("1.500")
    gross_pay_amount: Decimal
    calculation_basis_digest: Sha256Digest
    currency: CurrencyCode
    pay_rate_uom: PayRateUom
    pay_periods_per_year: PayPeriodsPerYear | None = None
    salary_period_basis: SalaryPeriodBasis | None = None

    @field_validator("base_pay_rate", "gross_pay_amount", mode="before")
    @classmethod
    def _money_values(cls, value: Any) -> Decimal:
        return _money(value)

    @field_validator("overtime_multiplier", mode="before")
    @classmethod
    def _multiplier(cls, value: Any) -> Decimal:
        parsed = _ratio(value)
        if parsed < Decimal("1.000"):
            raise ValueError("overtime multiplier cannot be below one")
        return parsed

    @model_validator(mode="after")
    def _pay_basis_is_explicit(self) -> "PreparePayrollHandoffCommand":
        if self.pay_rate_uom == "year":
            if self.pay_periods_per_year is None:
                raise ValueError(
                    "annual salary handoff requires exact pay periods per year"
                )
            if self.salary_period_basis != "full_period_unprorated":
                raise ValueError(
                    "annual salary handoff supports only a full unprorated period"
                )
            if self.overtime_multiplier != Decimal("1.000"):
                raise ValueError(
                    "annual salary handoff cannot apply an overtime multiplier"
                )
        elif (
            self.pay_periods_per_year is not None
            or self.salary_period_basis is not None
        ):
            raise ValueError(
                "hourly payroll handoff cannot declare annual salary basis fields"
            )
        return self


class InitiateOffboardingCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_initiate_offboarding_command.v1"] = Field(
        default="lightbulb.people_initiate_offboarding_command.v1",
        alias="schema",
    )
    kind: Literal["initiate_offboarding"] = "initiate_offboarding"
    offboarding_ref: OpaqueRef
    last_working_at: str
    final_pay_period: PeoplePayPeriod
    final_payroll_handoff_ref: OpaqueRef
    expected_access_system_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1,
        max_length=_MAX_ACCESS_SYSTEMS,
    )

    @field_validator("last_working_at")
    @classmethod
    def _last_working_time(cls, value: str) -> str:
        return _timestamp(value, field_name="last_working_at")

    @field_validator("expected_access_system_refs", mode="before")
    @classmethod
    def _access_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _access_plan_is_canonical(self) -> "InitiateOffboardingCommand":
        if len(set(self.expected_access_system_refs)) != len(
            self.expected_access_system_refs
        ):
            raise ValueError("expected access systems must be unique")
        if (
            tuple(sorted(self.expected_access_system_refs))
            != self.expected_access_system_refs
        ):
            raise ValueError("expected access systems must use canonical sorted order")
        return self


class VerifyAccessRevocationCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_verify_access_revocation_command.v1"] = Field(
        default="lightbulb.people_verify_access_revocation_command.v1",
        alias="schema",
    )
    kind: Literal["verify_access_revocation"] = "verify_access_revocation"
    offboarding_ref: OpaqueRef
    system_ref: OpaqueRef
    account_ref: OpaqueRef
    revocation_verification_ref: OpaqueRef
    claimed_provider_effect_receipt_digest: Sha256Digest
    revoked_at: str

    @field_validator("revoked_at")
    @classmethod
    def _revoked_time(cls, value: str) -> str:
        return _timestamp(value, field_name="revoked_at")


class CompleteOffboardingCommand(_PeopleCommand):
    schema_id: Literal["lightbulb.people_complete_offboarding_command.v1"] = Field(
        default="lightbulb.people_complete_offboarding_command.v1",
        alias="schema",
    )
    kind: Literal["complete_offboarding"] = "complete_offboarding"
    offboarding_ref: OpaqueRef
    final_payroll_handoff_ref: OpaqueRef
    completed_at: str

    @field_validator("completed_at")
    @classmethod
    def _completed_time(cls, value: str) -> str:
        return _timestamp(value, field_name="completed_at")


PeopleCommand = Annotated[
    Union[
        CreateCandidateCommand,
        AdvanceCandidateCommand,
        ActivateWorkerCommand,
        ScheduleShiftCommand,
        RecordApprovedTimecardCommand,
        RecordApprovedLeaveCommand,
        RecordPerformanceCompensationCommand,
        RecordCertificationCommand,
        PreparePayrollHandoffCommand,
        InitiateOffboardingCommand,
        VerifyAccessRevocationCommand,
        CompleteOffboardingCommand,
    ],
    Field(discriminator="kind"),
]

_PEOPLE_COMMAND_ADAPTER = TypeAdapter(PeopleCommand)


def people_command_digest(value: _PeopleCommand | Mapping[str, Any]) -> str:
    parsed = _PEOPLE_COMMAND_ADAPTER.validate_python(value)
    payload = parsed.model_dump(mode="json", by_alias=True, exclude_none=True)
    payload.pop("approval", None)
    return _stable_digest(payload)


class PeopleTransitionCandidate(_StrictModel):
    schema_id: Literal["lightbulb.people_transition_candidate.v1"] = Field(
        default=PEOPLE_TRANSITION_CANDIDATE_SCHEMA,
        alias="schema",
    )
    lifecycle_ref: OpaqueRef
    revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    scope_digest: Sha256Digest
    transition_ref: OpaqueRef
    prior_state_digest: Sha256Digest
    command: PeopleCommand
    command_digest: Sha256Digest
    idempotency_digest: Sha256Digest
    requested_by_ref: OpaqueRef
    proposed_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_PER_TRANSITION,
    )
    evidence_digest: Sha256Digest
    required_approver_role: ApprovalRole | None = None
    approval_ref: OpaqueRef | None = None
    approval_receipt_digest: Sha256Digest | None = None
    authoritative_state_changed: Literal[False] = False
    provider_effect_executed: Literal[False] = False
    transition_digest: Sha256Digest

    @field_validator("proposed_at")
    @classmethod
    def _proposed_time(cls, value: str) -> str:
        return _timestamp(value, field_name="proposed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _candidate_is_exact(self) -> "PeopleTransitionCandidate":
        if self.command_digest != people_command_digest(self.command):
            raise ValueError("candidate command digest does not match exact command")
        refs = [item.evidence_ref for item in self.evidence_refs]
        digests = [item.sha256 for item in self.evidence_refs]
        if len(refs) != len(set(refs)) or len(digests) != len(set(digests)):
            raise ValueError("candidate evidence references and digests must be unique")
        if tuple(sorted(refs)) != tuple(refs):
            raise ValueError("candidate evidence must use canonical reference order")
        if self.evidence_digest != _evidence_digest(self.evidence_refs):
            raise ValueError(
                "candidate evidence digest does not match retained evidence"
            )
        approval = self.command.approval
        if approval is None:
            if any(
                value is not None
                for value in (
                    self.required_approver_role,
                    self.approval_ref,
                    self.approval_receipt_digest,
                )
            ):
                raise ValueError(
                    "candidate without approval cannot claim approval fields"
                )
        elif (
            self.required_approver_role != approval.approver_role
            or self.approval_ref != approval.approval_ref
            or self.approval_receipt_digest != approval.approval_receipt_digest
        ):
            raise ValueError(
                "candidate approval fields must match exact approval evidence"
            )
        if self.transition_digest != people_transition_candidate_digest(self):
            raise ValueError("candidate transition digest does not match exact content")
        return self


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest([item.to_dict() for item in evidence_refs])


def people_transition_candidate_digest(
    value: PeopleTransitionCandidate | Mapping[str, Any],
) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    payload.pop("transition_digest", None)
    return _stable_digest(payload)


class CertificationProjection(_StrictModel):
    certification_ref: OpaqueRef
    learning_record_ref: OpaqueRef
    credential_ref: OpaqueRef
    issued_on: str
    expires_on: str
    required_for_position: bool

    @field_validator("issued_on", "expires_on")
    @classmethod
    def _dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)


class AccessRevocationProjection(_StrictModel):
    system_ref: OpaqueRef
    account_ref: OpaqueRef
    revocation_verification_ref: OpaqueRef
    claimed_provider_effect_receipt_digest: Sha256Digest
    revoked_at: str

    @field_validator("revoked_at")
    @classmethod
    def _revoked_time(cls, value: str) -> str:
        return _timestamp(value, field_name="revoked_at")


class PeopleOperationsSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.people_operations_snapshot.v1"] = Field(
        default=PEOPLE_OPERATIONS_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: PeopleOperationsScope
    scope_digest: Sha256Digest
    lifecycle_ref: OpaqueRef
    state: PeopleLifecycleState
    candidate_stage: CandidateStage
    position_authorization_ref: OpaqueRef
    worker_activation_ref: OpaqueRef | None = None
    employment_starts_at: str | None = None
    current_compensation_ref: OpaqueRef | None = None
    current_base_pay_rate: Decimal | None = None
    current_compensation_effective_at: str | None = None
    latest_shift_ref: OpaqueRef | None = None
    latest_shift_starts_at: str | None = None
    latest_shift_ends_at: str | None = None
    latest_scheduled_hours: Decimal | None = None
    latest_timecard_ref: OpaqueRef | None = None
    latest_timecard_shift_ref: OpaqueRef | None = None
    latest_timecard_shift_starts_at: str | None = None
    latest_timecard_shift_ends_at: str | None = None
    latest_timecard_pay_period: PeoplePayPeriod | None = None
    latest_regular_hours: Decimal | None = None
    latest_overtime_hours: Decimal | None = None
    latest_paid_leave_hours: Decimal | None = None
    latest_leave_ref: OpaqueRef | None = None
    latest_leave_pay_period: PeoplePayPeriod | None = None
    latest_leave_hours: Decimal | None = None
    latest_leave_paid: bool | None = None
    latest_leave_payroll_reconciled: bool | None = None
    latest_performance_review_ref: OpaqueRef | None = None
    certifications: tuple[CertificationProjection, ...] = Field(
        default=(),
        max_length=_MAX_CERTIFICATIONS,
    )
    latest_payroll_handoff_ref: OpaqueRef | None = None
    latest_payroll_timecard_ref: OpaqueRef | None = None
    latest_payroll_pay_period: PeoplePayPeriod | None = None
    latest_gross_pay_amount: Decimal | None = None
    latest_payroll_calculation_basis_digest: Sha256Digest | None = None
    latest_payroll_pay_periods_per_year: PayPeriodsPerYear | None = None
    latest_salary_period_basis: SalaryPeriodBasis | None = None
    offboarding_ref: OpaqueRef | None = None
    offboarding_initiated_at: str | None = None
    last_working_at: str | None = None
    final_payroll_handoff_ref: OpaqueRef | None = None
    expected_access_system_refs: tuple[OpaqueRef, ...] = ()
    access_revocations: tuple[AccessRevocationProjection, ...] = Field(
        default=(),
        max_length=_MAX_ACCESS_SYSTEMS,
    )
    offboarded_at: str | None = None
    revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    transition_history: tuple[PeopleTransitionCandidate, ...] = Field(
        min_length=1,
        max_length=_MAX_TRANSITIONS,
    )
    state_digest: Sha256Digest

    @field_validator(
        "employment_starts_at",
        "current_compensation_effective_at",
        "latest_shift_starts_at",
        "latest_shift_ends_at",
        "latest_timecard_shift_starts_at",
        "latest_timecard_shift_ends_at",
        "offboarding_initiated_at",
        "last_working_at",
        "offboarded_at",
    )
    @classmethod
    def _timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("current_base_pay_rate", "latest_gross_pay_amount", mode="before")
    @classmethod
    def _money_values(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)

    @field_validator(
        "latest_scheduled_hours",
        "latest_regular_hours",
        "latest_overtime_hours",
        "latest_paid_leave_hours",
        "latest_leave_hours",
        mode="before",
    )
    @classmethod
    def _hour_values(cls, value: Any) -> Decimal | None:
        return None if value is None else _hours(value)

    @field_validator(
        "certifications",
        "expected_access_system_refs",
        "access_revocations",
        "transition_history",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_replays_exactly(self) -> "PeopleOperationsSnapshot":
        projection, expected_digest = _derive_projection(
            self.scope,
            self.lifecycle_ref,
            self.transition_history,
        )
        expected_payload = _snapshot_payload(
            self.scope,
            self.lifecycle_ref,
            self.transition_history,
            projection,
        )
        actual_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"state_digest"},
        )
        if actual_payload != expected_payload:
            raise ValueError(
                "people snapshot does not match deterministic history replay"
            )
        if self.state_digest != expected_digest:
            raise ValueError(
                "people snapshot digest does not match exact replayed content"
            )
        return self


def people_snapshot_digest(
    value: PeopleOperationsSnapshot | Mapping[str, Any],
) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    payload.pop("state_digest", None)
    return _stable_digest(payload)


def _projection_value(projection: Any, field_name: str) -> Any:
    if isinstance(projection, Mapping):
        return projection.get(field_name)
    return getattr(projection, field_name, None)


def _payroll_calculation_basis_digest(
    scope: PeopleOperationsScope,
    projection: Any,
    command: PreparePayrollHandoffCommand,
) -> str:
    regular_hours = _projection_value(projection, "latest_regular_hours") or Decimal(
        "0.000"
    )
    overtime_hours = _projection_value(projection, "latest_overtime_hours") or Decimal(
        "0.000"
    )
    paid_leave_hours = _projection_value(
        projection, "latest_paid_leave_hours"
    ) or Decimal("0.000")
    material = {
        "schema": PEOPLE_PAYROLL_CALCULATION_BASIS_SCHEMA,
        "scope_digest": people_scope_digest(scope),
        "worker_ref": command.worker_ref,
        "candidate_ref": command.candidate_ref,
        "position_ref": command.position_ref,
        "jurisdiction": command.jurisdiction,
        "pay_period": command.pay_period.to_dict(),
        "shift_ref": _projection_value(projection, "latest_timecard_shift_ref"),
        "shift_starts_at": _projection_value(
            projection, "latest_timecard_shift_starts_at"
        ),
        "shift_ends_at": _projection_value(projection, "latest_timecard_shift_ends_at"),
        "timecard_ref": command.timecard_ref,
        "compensation_ref": command.compensation_ref,
        "compensation_effective_at": _projection_value(
            projection, "current_compensation_effective_at"
        ),
        "base_pay_rate": str(command.base_pay_rate),
        "regular_hours": str(regular_hours),
        "overtime_hours": str(overtime_hours),
        "paid_leave_hours": str(paid_leave_hours),
        "paid_leave_ref": (
            _projection_value(projection, "latest_leave_ref")
            if paid_leave_hours > 0
            else None
        ),
        "overtime_multiplier": str(command.overtime_multiplier),
        "gross_pay_amount": str(command.gross_pay_amount),
        "currency": command.currency,
        "pay_rate_uom": command.pay_rate_uom,
    }
    if command.pay_rate_uom == "year":
        material.update(
            {
                "pay_periods_per_year": command.pay_periods_per_year,
                "salary_period_basis": command.salary_period_basis,
            }
        )
    return _stable_digest(material)


def people_payroll_calculation_basis_digest(
    snapshot: PeopleOperationsSnapshot,
    command: PreparePayrollHandoffCommand | Mapping[str, Any],
) -> str:
    """Digest exact retained time/rate lineage without authorizing payroll."""

    parsed_snapshot = PeopleOperationsSnapshot.model_validate(snapshot)
    parsed = PreparePayrollHandoffCommand.model_validate(command)
    _validate_command_identity(parsed_snapshot.scope, parsed)
    return _payroll_calculation_basis_digest(
        parsed_snapshot.scope,
        parsed_snapshot,
        parsed,
    )


class PeopleTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.people_transition_request.v1"] = Field(
        default=PEOPLE_TRANSITION_REQUEST_SCHEMA,
        alias="schema",
    )
    scope: PeopleOperationsScope
    lifecycle_ref: OpaqueRef
    expected_revision: int = Field(ge=0, le=_MAX_TRANSITIONS)
    expected_state_digest: Sha256Digest
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    requested_by_ref: OpaqueRef
    proposed_at: str
    current_snapshot: PeopleOperationsSnapshot | None = None
    command: PeopleCommand
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=_MAX_EVIDENCE_PER_TRANSITION,
    )

    @field_validator("proposed_at")
    @classmethod
    def _proposed_time(cls, value: str) -> str:
        return _timestamp(value, field_name="proposed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _genesis_or_current_snapshot_is_exact(self) -> "PeopleTransitionRequest":
        if self.current_snapshot is None:
            if self.expected_revision != 0 or self.expected_state_digest != ZERO_DIGEST:
                raise ValueError(
                    "genesis request requires revision zero and zero digest"
                )
        elif (
            self.expected_revision != self.current_snapshot.revision
            or self.expected_state_digest != self.current_snapshot.state_digest
        ):
            raise ValueError("request fence must match exact current snapshot")
        refs = [item.evidence_ref for item in self.evidence_refs]
        digests = [item.sha256 for item in self.evidence_refs]
        if len(refs) != len(set(refs)) or len(digests) != len(set(digests)):
            raise ValueError("request evidence references and digests must be unique")
        if tuple(sorted(refs)) != tuple(refs):
            raise ValueError("request evidence must use canonical reference order")
        return self


def people_idempotency_digest(
    scope: PeopleOperationsScope | Mapping[str, Any],
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    return _stable_digest(
        {
            "schema": "lightbulb.people_idempotency.v1",
            "scope_digest": people_scope_digest(scope),
            "lifecycle_ref": lifecycle_ref,
            "idempotency_key": idempotency_key,
        }
    )


def people_transition_evidence_digest(
    value: PeopleTransitionRequest | Mapping[str, Any],
) -> str:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, BaseModel)
        else dict(value)
    )
    scope = payload["scope"]
    command = payload["command"]
    approval = (
        command.approval
        if isinstance(command, _PeopleCommand)
        else command.get("approval")
    )
    approval_digest = (
        approval.approval_digest
        if isinstance(approval, PeopleApprovalEvidence)
        else approval.get("approval_digest")
        if approval is not None
        else None
    )
    material = {
        "schema": PEOPLE_TRANSITION_EVIDENCE_COMMITMENT_SCHEMA,
        "scope_digest": people_scope_digest(scope),
        "lifecycle_ref": payload["lifecycle_ref"],
        "expected_revision": payload["expected_revision"],
        "expected_state_digest": payload["expected_state_digest"],
        "transition_ref": payload["transition_ref"],
        "idempotency_digest": people_idempotency_digest(
            scope,
            payload["lifecycle_ref"],
            payload["idempotency_key"],
        ),
        "requested_by_ref": payload["requested_by_ref"],
        "proposed_at": _timestamp(payload["proposed_at"], field_name="proposed_at"),
        "command_digest": people_command_digest(command),
        "approval_digest": approval_digest,
    }
    return _stable_digest(material)


def _access_revocation_evidence_digest(
    scope_digest: str,
    lifecycle_ref: str,
    transition_ref: str,
    parsed: VerifyAccessRevocationCommand,
) -> str:
    return _stable_digest(
        {
            "schema": PEOPLE_ACCESS_REVOCATION_EVIDENCE_SCHEMA,
            "scope_digest": scope_digest,
            "lifecycle_ref": lifecycle_ref,
            "transition_ref": transition_ref,
            "worker_ref": parsed.worker_ref,
            "candidate_ref": parsed.candidate_ref,
            "position_ref": parsed.position_ref,
            "jurisdiction": parsed.jurisdiction,
            "offboarding_ref": parsed.offboarding_ref,
            "system_ref": parsed.system_ref,
            "account_ref": parsed.account_ref,
            "revocation_verification_ref": parsed.revocation_verification_ref,
            "claimed_provider_effect_receipt_digest": (
                parsed.claimed_provider_effect_receipt_digest
            ),
            "revoked_at": parsed.revoked_at,
        }
    )


def people_access_revocation_evidence_digest(
    scope: PeopleOperationsScope | Mapping[str, Any],
    lifecycle_ref: str,
    transition_ref: str,
    command: VerifyAccessRevocationCommand | Mapping[str, Any],
) -> str:
    """Bind a portable revocation claim; this is not provider provenance."""

    parsed = (
        command
        if isinstance(command, VerifyAccessRevocationCommand)
        else VerifyAccessRevocationCommand.model_validate(command)
    )
    return _access_revocation_evidence_digest(
        people_scope_digest(scope), lifecycle_ref, transition_ref, parsed
    )


class PeopleTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.people_transition_proposal.v1"] = Field(
        default=PEOPLE_TRANSITION_PROPOSAL_SCHEMA,
        alias="schema",
    )
    scope: PeopleOperationsScope
    lifecycle_ref: OpaqueRef
    source_revision: int = Field(ge=0, le=_MAX_TRANSITIONS)
    source_state_digest: Sha256Digest
    target_revision: int = Field(ge=1, le=_MAX_TRANSITIONS)
    target_state: PeopleLifecycleState
    transition_ref: OpaqueRef
    transition_digest: Sha256Digest
    candidate_state_digest: Sha256Digest
    required_approver_role: ApprovalRole | None = None
    business_approval_evidence_present: bool
    spring_revalidation_required: Literal[True] = True
    authoritative_persistence_granted: Literal[False] = False
    employment_or_compensation_decision_executed: Literal[False] = False
    payroll_hcm_or_iam_write_executed: Literal[False] = False
    hosted_approval_task_created: Literal[False] = False
    spring_submission_executed: Literal[False] = False
    provider_receipt_verified_by_sdk: Literal[False] = False
    proposal_digest: Sha256Digest

    @model_validator(mode="after")
    def _proposal_is_exact(self) -> "PeopleTransitionProposal":
        if self.target_revision != self.source_revision + 1:
            raise ValueError("proposal must advance exactly one candidate revision")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("proposal_digest", None)
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("people proposal digest does not match exact content")
        return self


class PeopleTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.people_transition_result.v1"] = Field(
        default=PEOPLE_TRANSITION_RESULT_SCHEMA,
        alias="schema",
    )
    proposal: PeopleTransitionProposal
    candidate_snapshot: PeopleOperationsSnapshot
    candidate_validated: Literal[True] = True
    authoritative_state_changed: Literal[False] = False
    provider_effect_executed: Literal[False] = False
    hosted_approval_task_created: Literal[False] = False
    spring_submission_executed: Literal[False] = False
    provider_receipt_verified_by_sdk: Literal[False] = False

    @model_validator(mode="after")
    def _result_is_cross_bound(self) -> "PeopleTransitionResult":
        proposal = self.proposal
        snapshot = self.candidate_snapshot
        last = snapshot.transition_history[-1]
        if (
            proposal.scope != snapshot.scope
            or proposal.lifecycle_ref != snapshot.lifecycle_ref
            or proposal.source_revision != snapshot.revision - 1
            or proposal.source_state_digest != last.prior_state_digest
            or proposal.target_revision != snapshot.revision
            or proposal.target_state != snapshot.state
            or proposal.candidate_state_digest != snapshot.state_digest
            or proposal.transition_ref != last.transition_ref
            or proposal.transition_digest != last.transition_digest
            or proposal.required_approver_role != last.required_approver_role
            or proposal.business_approval_evidence_present
            != (last.command.approval is not None)
        ):
            raise ValueError(
                "people proposal result is not bound to exact candidate snapshot"
            )
        return self


class PeopleOperationsLifecycleError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _fault(code: str, message: str) -> None:
    raise PeopleOperationsLifecycleError(code, message)


def _required_approval_role(command: _PeopleCommand) -> ApprovalRole | None:
    if isinstance(command, CreateCandidateCommand):
        return "workforce_authorizer"
    if isinstance(command, AdvanceCandidateCommand):
        return (
            "recruiting_authorizer"
            if command.target_stage == "offer_approved"
            else None
        )
    if isinstance(command, ActivateWorkerCommand):
        return "people_operations_authorizer"
    if isinstance(command, ScheduleShiftCommand):
        return "workforce_scheduler"
    if isinstance(command, RecordApprovedTimecardCommand):
        return "time_authorizer"
    if isinstance(command, RecordApprovedLeaveCommand):
        return "leave_authorizer"
    if isinstance(command, RecordPerformanceCompensationCommand):
        return "compensation_authorizer"
    if isinstance(command, RecordCertificationCommand):
        return None
    if isinstance(command, PreparePayrollHandoffCommand):
        return "payroll_authorizer"
    if isinstance(command, InitiateOffboardingCommand):
        return "offboarding_authorizer"
    if isinstance(command, VerifyAccessRevocationCommand):
        return None
    if isinstance(command, CompleteOffboardingCommand):
        return "offboarding_authorizer"
    raise TypeError("unsupported people command")


def _transition_commitment_digest(
    *,
    scope_digest: str,
    lifecycle_ref: str,
    expected_revision: int,
    expected_state_digest: str,
    transition_ref: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
    command_digest: str,
    approval_digest: str | None,
) -> str:
    return _stable_digest(
        {
            "schema": PEOPLE_TRANSITION_EVIDENCE_COMMITMENT_SCHEMA,
            "scope_digest": scope_digest,
            "lifecycle_ref": lifecycle_ref,
            "expected_revision": expected_revision,
            "expected_state_digest": expected_state_digest,
            "transition_ref": transition_ref,
            "idempotency_digest": idempotency_digest,
            "requested_by_ref": requested_by_ref,
            "proposed_at": proposed_at,
            "command_digest": command_digest,
            "approval_digest": approval_digest,
        }
    )


def _validate_approval(
    scope: PeopleOperationsScope,
    lifecycle_ref: str,
    transition_ref: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
    command: _PeopleCommand,
) -> ApprovalRole | None:
    required = _required_approval_role(command)
    approval = command.approval
    if required is None:
        if approval is not None:
            _fault(
                "people_unexpected_approval",
                "This observational transition cannot consume approval evidence.",
            )
        return None
    if approval is None:
        _fault(
            "people_approval_required",
            f"The {command.kind} transition requires exact {required} evidence.",
        )
    assert approval is not None
    if (
        approval.approver_role != required
        or approval.scope_digest != people_scope_digest(scope)
        or approval.lifecycle_ref != lifecycle_ref
        or approval.transition_ref != transition_ref
        or approval.command_digest != people_command_digest(command)
        or approval.idempotency_digest != idempotency_digest
    ):
        _fault(
            "people_approval_binding_mismatch",
            "Approval evidence is not bound to the exact scope, transition, command, and idempotency identity.",
        )
    forbidden_approvers = {requested_by_ref, scope.worker_ref}
    if isinstance(command, RecordPerformanceCompensationCommand):
        forbidden_approvers.add(command.reviewer_ref)
    if approval.approved_by_ref in forbidden_approvers:
        _fault(
            "people_approval_separation_of_duties",
            "The approver must be independent of requester, worker, and applicable reviewer.",
        )
    proposed = _parsed_timestamp(proposed_at)
    if not (
        _parsed_timestamp(approval.approved_at)
        <= proposed
        <= _parsed_timestamp(approval.expires_at)
    ):
        _fault(
            "people_approval_expired",
            "Approval evidence is not effective at the proposed transition time.",
        )
    return required


def _validate_transition_evidence(
    *,
    scope_digest: str,
    lifecycle_ref: str,
    expected_revision: int,
    expected_state_digest: str,
    transition_ref: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
    command: _PeopleCommand,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    prior_evidence_refs: set[str],
    prior_evidence_digests: set[str],
) -> None:
    refs = [item.evidence_ref for item in evidence_refs]
    digests = [item.sha256 for item in evidence_refs]
    if len(refs) != len(set(refs)) or len(digests) != len(set(digests)):
        _fault(
            "people_duplicate_evidence",
            "Transition evidence references and content digests must be unique.",
        )
    if prior_evidence_refs.intersection(refs) or prior_evidence_digests.intersection(
        digests
    ):
        _fault(
            "people_replayed_evidence",
            "Transition evidence is single-use within one people lifecycle.",
        )
    approval = command.approval
    if approval is not None and (
        approval.evidence.evidence_ref in set(refs)
        or approval.evidence.sha256 in set(digests)
        or approval.evidence.evidence_ref in prior_evidence_refs
        or approval.evidence.sha256 in prior_evidence_digests
    ):
        _fault(
            "people_replayed_approval_evidence",
            "Approval evidence cannot be reused as transition or prior lifecycle evidence.",
        )
    expected_digest = _transition_commitment_digest(
        scope_digest=scope_digest,
        lifecycle_ref=lifecycle_ref,
        expected_revision=expected_revision,
        expected_state_digest=expected_state_digest,
        transition_ref=transition_ref,
        idempotency_digest=idempotency_digest,
        requested_by_ref=requested_by_ref,
        proposed_at=proposed_at,
        command_digest=people_command_digest(command),
        approval_digest=approval.approval_digest if approval is not None else None,
    )
    cutoff = _parsed_timestamp(proposed_at)
    minimum_grade = (
        PrimitiveEvidenceVerificationGrade.VERIFIED
        if isinstance(
            command, (RecordCertificationCommand, VerifyAccessRevocationCommand)
        )
        else PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    matching_commitment = False
    expected_revocation_digest = (
        _access_revocation_evidence_digest(
            scope_digest,
            lifecycle_ref,
            transition_ref,
            command,
        )
        if isinstance(command, VerifyAccessRevocationCommand)
        else None
    )
    matching_revocation_attestation = expected_revocation_digest is None
    for item in evidence_refs:
        observed = _parsed_timestamp(item.observed_at)
        if (
            item.issuer_ref != SPRING_PEOPLE_EVIDENCE_ISSUER
            or item.subject_ref != transition_ref
        ):
            _fault(
                "people_evidence_custody_mismatch",
                "Evidence must remain under exact Spring people-authority and transition custody.",
            )
        if observed > cutoff or cutoff - observed > _MAX_EVIDENCE_AGE:
            _fault(
                "people_evidence_stale_or_future",
                "Evidence is stale or was observed after the transition cutoff.",
            )
        if (
            isinstance(command, VerifyAccessRevocationCommand)
            and item.kind == "people_access_revocation_claim_attestation"
            and observed < _parsed_timestamp(command.revoked_at)
        ):
            _fault(
                "people_revocation_evidence_not_causal",
                "Access-revocation attestation cannot predate the claimed revocation time.",
            )
        if (
            item.effective_at is not None
            and _parsed_timestamp(item.effective_at) > cutoff
        ):
            _fault(
                "people_evidence_not_effective",
                "Evidence was not effective at the transition cutoff.",
            )
        if _GRADE_RANK[item.verification_grade] < _GRADE_RANK[minimum_grade]:
            _fault(
                "people_evidence_grade_insufficient",
                "Evidence verification grade is below the transition requirement.",
            )
        if (
            item.kind == "people_transition_commitment"
            and item.sha256 == expected_digest
        ):
            matching_commitment = True
        if (
            item.kind == "people_access_revocation_claim_attestation"
            and item.sha256 == expected_revocation_digest
        ):
            matching_revocation_attestation = True
    if not matching_commitment:
        _fault(
            "people_evidence_commitment_mismatch",
            "Evidence does not commit to the exact scope, fence, command, approval, and actor.",
        )
    if not matching_revocation_attestation:
        _fault(
            "people_revocation_attestation_mismatch",
            "Access-revocation evidence must bind the exact claimed provider receipt and account; Spring must still verify provenance.",
        )


def _validate_command_identity(
    scope: PeopleOperationsScope,
    command: _PeopleCommand,
) -> None:
    if (
        command.worker_ref != scope.worker_ref
        or command.candidate_ref != scope.candidate_ref
        or command.position_ref != scope.position_ref
        or command.jurisdiction != scope.jurisdiction
    ):
        _fault(
            "people_subject_scope_mismatch",
            "Command worker, candidate, position, and jurisdiction must match exact lifecycle scope.",
        )


def _pay_period_matches_scope(
    scope: PeopleOperationsScope,
    pay_period: PeoplePayPeriod,
) -> None:
    if (
        pay_period.jurisdiction != scope.jurisdiction
        or pay_period.currency != scope.payroll_currency
    ):
        _fault(
            "people_pay_period_scope_mismatch",
            "Pay period jurisdiction and currency must match exact lifecycle scope.",
        )


def _time_falls_in_period(timestamp: str, pay_period: PeoplePayPeriod) -> bool:
    day = _parsed_timestamp(timestamp).date()
    return (
        date.fromisoformat(pay_period.starts_on)
        <= day
        <= date.fromisoformat(pay_period.ends_on)
    )


def _base_projection(command: CreateCandidateCommand) -> dict[str, Any]:
    return {
        "state": "candidate_sourced",
        "candidate_stage": "sourced",
        "position_authorization_ref": command.position_authorization_ref,
        "certifications": (),
        "expected_access_system_refs": (),
        "access_revocations": (),
    }


def _apply_command(
    scope: PeopleOperationsScope,
    projection: Mapping[str, Any] | None,
    command: _PeopleCommand,
    *,
    proposed_at: str,
) -> dict[str, Any]:
    _validate_command_identity(scope, command)
    if isinstance(command, CreateCandidateCommand):
        if projection is not None:
            _fault(
                "people_candidate_already_exists",
                "Candidate creation is valid only as the genesis transition.",
            )
        return _base_projection(command)
    if projection is None:
        _fault(
            "people_candidate_required",
            "A candidate genesis transition is required before this command.",
        )
    current = dict(projection)
    state = current["state"]
    if isinstance(command, AdvanceCandidateCommand):
        expected = {
            "candidate_sourced": "screened",
            "candidate_screened": "interviewed",
            "candidate_interviewed": "offer_approved",
        }.get(state)
        if command.target_stage != expected:
            _fault(
                "people_candidate_stage_invalid",
                "Candidate stages must progress sourced, screened, interviewed, then offer approved.",
            )
        current["candidate_stage"] = command.target_stage
        current["state"] = {
            "screened": "candidate_screened",
            "interviewed": "candidate_interviewed",
            "offer_approved": "offer_approved",
        }[command.target_stage]
        return current
    if isinstance(command, ActivateWorkerCommand):
        if state != "offer_approved":
            _fault(
                "people_activation_state_invalid",
                "Worker activation requires an offer-approved candidate projection.",
            )
        if (
            command.currency != scope.payroll_currency
            or command.pay_rate_uom != scope.pay_rate_uom
        ):
            _fault(
                "people_compensation_scope_mismatch",
                "Activation compensation currency and UOM must match lifecycle scope.",
            )
        if _parsed_timestamp(command.employment_starts_at) < _parsed_timestamp(
            proposed_at
        ):
            _fault(
                "people_employment_start_in_past",
                "Employment start cannot precede the proposed activation time.",
            )
        current.update(
            {
                "state": "active",
                "candidate_stage": "hired",
                "worker_activation_ref": command.worker_activation_ref,
                "employment_starts_at": command.employment_starts_at,
                "current_compensation_ref": command.compensation_ref,
                "current_base_pay_rate": command.base_pay_rate,
                "current_compensation_effective_at": command.employment_starts_at,
            }
        )
        return current
    if isinstance(command, ScheduleShiftCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Shift scheduling requires an active worker.",
            )
        employment_start = current.get("employment_starts_at")
        if employment_start is None or _parsed_timestamp(
            command.starts_at
        ) < _parsed_timestamp(employment_start):
            _fault(
                "people_shift_before_employment",
                "A shift cannot begin before the exact employment start.",
            )
        if _parsed_timestamp(command.starts_at) < _parsed_timestamp(proposed_at):
            _fault(
                "people_shift_start_in_past",
                "A scheduled shift cannot begin before its proposal time.",
            )
        current.update(
            {
                "latest_shift_ref": command.shift_ref,
                "latest_shift_starts_at": command.starts_at,
                "latest_shift_ends_at": command.ends_at,
                "latest_scheduled_hours": command.scheduled_hours,
            }
        )
        return current
    if isinstance(command, RecordApprovedTimecardCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Timecard recording requires an active worker.",
            )
        _pay_period_matches_scope(scope, command.pay_period)
        if command.shift_ref != current.get("latest_shift_ref"):
            _fault(
                "people_timecard_shift_mismatch",
                "Approved timecard must reference the latest exact shift projection.",
            )
        shift_start = current.get("latest_shift_starts_at")
        shift_end = current.get("latest_shift_ends_at")
        if (
            shift_start is None
            or shift_end is None
            or not _time_falls_in_period(shift_start, command.pay_period)
            or not _time_falls_in_period(shift_end, command.pay_period)
        ):
            _fault(
                "people_timecard_pay_period_mismatch",
                "Timecard shift must fall within the exact pay period.",
            )
        if _parsed_timestamp(shift_end) > _parsed_timestamp(proposed_at):
            _fault(
                "people_timecard_shift_incomplete",
                "Approved worked time cannot be projected before the exact shift ends.",
            )
        current.update(
            {
                "latest_timecard_ref": command.timecard_ref,
                "latest_timecard_shift_ref": command.shift_ref,
                "latest_timecard_shift_starts_at": shift_start,
                "latest_timecard_shift_ends_at": shift_end,
                "latest_timecard_pay_period": command.pay_period,
                "latest_regular_hours": command.regular_hours,
                "latest_overtime_hours": command.overtime_hours,
                "latest_paid_leave_hours": command.paid_leave_hours,
            }
        )
        return current
    if isinstance(command, RecordApprovedLeaveCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Leave recording requires an active worker.",
            )
        _pay_period_matches_scope(scope, command.pay_period)
        if not _time_falls_in_period(
            command.starts_at,
            command.pay_period,
        ) or not _time_falls_in_period(command.ends_at, command.pay_period):
            _fault(
                "people_leave_pay_period_mismatch",
                "Approved leave must fall within the exact pay period.",
            )
        current.update(
            {
                "latest_leave_ref": command.leave_ref,
                "latest_leave_pay_period": command.pay_period,
                "latest_leave_hours": command.requested_hours,
                "latest_leave_paid": command.paid_leave,
                "latest_leave_payroll_reconciled": command.payroll_reconciled,
            }
        )
        return current
    if isinstance(command, RecordPerformanceCompensationCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Performance and compensation recording requires an active worker.",
            )
        if (
            command.currency != scope.payroll_currency
            or command.pay_rate_uom != scope.pay_rate_uom
            or command.old_base_pay_rate != current.get("current_base_pay_rate")
        ):
            _fault(
                "people_compensation_scope_mismatch",
                "Compensation currency, UOM, and prior rate must match exact current projection.",
            )
        if _parsed_timestamp(command.effective_at) > _parsed_timestamp(proposed_at):
            _fault(
                "people_compensation_not_effective",
                "Compensation change must be effective by its transition cutoff.",
            )
        current.update(
            {
                "latest_performance_review_ref": command.performance_review_ref,
                "current_compensation_ref": command.compensation_ref,
                "current_base_pay_rate": command.new_base_pay_rate,
                "current_compensation_effective_at": command.effective_at,
            }
        )
        return current
    if isinstance(command, RecordCertificationCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Certification recording requires an active worker.",
            )
        if (
            date.fromisoformat(command.issued_on)
            > _parsed_timestamp(proposed_at).date()
        ):
            _fault(
                "people_certification_not_issued",
                "A certification cannot be projected as current before its issue date.",
            )
        if (
            date.fromisoformat(command.expires_on)
            < _parsed_timestamp(proposed_at).date()
        ):
            _fault(
                "people_certification_expired",
                "An expired certification cannot be projected as current.",
            )
        certifications = tuple(current.get("certifications", ()))
        if len(certifications) >= _MAX_CERTIFICATIONS:
            _fault(
                "people_certification_limit_reached",
                "Portable certification history reached its bounded limit.",
            )
        if command.certification_ref in {
            item.certification_ref for item in certifications
        }:
            _fault(
                "people_duplicate_certification",
                "Certification identity was already retained by the lifecycle.",
            )
        current["certifications"] = (
            *certifications,
            CertificationProjection(
                certification_ref=command.certification_ref,
                learning_record_ref=command.learning_record_ref,
                credential_ref=command.credential_ref,
                issued_on=command.issued_on,
                expires_on=command.expires_on,
                required_for_position=command.required_for_position,
            ),
        )
        return current
    if isinstance(command, PreparePayrollHandoffCommand):
        if state != "active":
            _fault(
                "people_active_worker_required",
                "Payroll handoff requires an active worker.",
            )
        _pay_period_matches_scope(scope, command.pay_period)
        if command.timecard_ref != current.get(
            "latest_timecard_ref"
        ) or command.pay_period != current.get("latest_timecard_pay_period"):
            _fault(
                "people_payroll_timecard_mismatch",
                "Payroll handoff must reference the latest exact timecard and pay period.",
            )
        if command.timecard_ref == current.get(
            "latest_payroll_timecard_ref"
        ) and command.pay_period == current.get("latest_payroll_pay_period"):
            _fault(
                "people_duplicate_payroll_handoff",
                "The exact timecard and pay period already have a retained payroll-handoff candidate.",
            )
        if (
            command.compensation_ref != current.get("current_compensation_ref")
            or command.base_pay_rate != current.get("current_base_pay_rate")
            or command.currency != scope.payroll_currency
            or command.pay_rate_uom != scope.pay_rate_uom
        ):
            _fault(
                "people_payroll_compensation_mismatch",
                "Payroll handoff must use exact current compensation currency and UOM.",
            )
        compensation_effective_at = current.get("current_compensation_effective_at")
        shift_started_at = current.get("latest_timecard_shift_starts_at")
        if (
            compensation_effective_at is None
            or shift_started_at is None
            or _parsed_timestamp(compensation_effective_at)
            > _parsed_timestamp(shift_started_at)
        ):
            _fault(
                "people_payroll_compensation_period_mismatch",
                "Payroll rate must have been effective when the retained timecard shift began.",
            )
        regular = current.get("latest_regular_hours")
        overtime = current.get("latest_overtime_hours")
        paid_leave_hours = current.get("latest_paid_leave_hours")
        shift_ends_at = current.get("latest_timecard_shift_ends_at")
        if any(
            value is None
            for value in (
                regular,
                overtime,
                paid_leave_hours,
                shift_ends_at,
            )
        ):
            _fault(
                "people_payroll_lineage_incomplete",
                "Payroll handoff requires exact retained timecard, shift, and hours lineage.",
            )
        assert isinstance(regular, Decimal)
        assert isinstance(overtime, Decimal)
        assert isinstance(paid_leave_hours, Decimal)
        assert isinstance(shift_ends_at, str)
        if paid_leave_hours > 0:
            if (
                current.get("latest_leave_pay_period") != command.pay_period
                or not current.get("latest_leave_paid")
                or not current.get("latest_leave_payroll_reconciled")
                or current.get("latest_leave_hours") != paid_leave_hours
            ):
                _fault(
                    "people_payroll_leave_not_reconciled",
                    "Paid leave hours require an exact reconciled leave projection for the pay period.",
                )
        if scope.pay_rate_uom == "hour":
            expected_gross = (
                (regular + paid_leave_hours) * command.base_pay_rate
                + overtime * command.base_pay_rate * command.overtime_multiplier
            ).quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_EVEN)
            gross_mismatch_message = (
                "Hourly payroll gross does not reconcile exact time, leave, rate, "
                "and overtime multiplier."
            )
        else:
            if (
                scope.pay_periods_per_year is None
                or command.pay_periods_per_year != scope.pay_periods_per_year
                or command.salary_period_basis != "full_period_unprorated"
            ):
                _fault(
                    "people_payroll_salary_basis_mismatch",
                    "Annual salary handoff must match the exact scoped pay-period count and full unprorated basis.",
                )
            if overtime != Decimal("0.000"):
                _fault(
                    "people_payroll_salary_overtime_unsupported",
                    "Portable annual salary handoff does not calculate overtime.",
                )
            cutoff_date = _parsed_timestamp(proposed_at).date()
            period_start = date.fromisoformat(command.pay_period.starts_on)
            period_end = date.fromisoformat(command.pay_period.ends_on)
            employment_starts_at = current.get("employment_starts_at")
            if cutoff_date <= period_end:
                _fault(
                    "people_payroll_salary_period_incomplete",
                    "A full-period annual salary handoff cannot be proposed before the pay period has ended.",
                )
            if (
                employment_starts_at is None
                or _parsed_timestamp(employment_starts_at).date() >= period_start
                or _parsed_timestamp(compensation_effective_at).date() >= period_start
            ):
                _fault(
                    "people_payroll_salary_proration_unsupported",
                    "Full-period annual salary requires employment and the exact rate to predate the pay period; proration remains Spring-authoritative.",
                )
            expected_gross = _annual_salary_period_gross(
                command.base_pay_rate,
                scope.pay_periods_per_year,
            )
            gross_mismatch_message = (
                "Annual salary gross does not equal the exact annual rate divided "
                "by the scoped pay-period count at deterministic cents precision."
            )
        if command.gross_pay_amount != expected_gross:
            _fault(
                "people_payroll_gross_mismatch",
                gross_mismatch_message,
            )
        expected_basis_digest = _payroll_calculation_basis_digest(
            scope, current, command
        )
        if command.calculation_basis_digest != expected_basis_digest:
            _fault(
                "people_payroll_calculation_basis_mismatch",
                "Payroll calculation basis must bind exact scope, timecard, shift, leave, rate lineage, and gross amount.",
            )
        current.update(
            {
                "latest_payroll_handoff_ref": command.payroll_handoff_ref,
                "latest_payroll_timecard_ref": command.timecard_ref,
                "latest_payroll_pay_period": command.pay_period,
                "latest_gross_pay_amount": command.gross_pay_amount,
                "latest_payroll_calculation_basis_digest": (
                    command.calculation_basis_digest
                ),
                "latest_payroll_pay_periods_per_year": (command.pay_periods_per_year),
                "latest_salary_period_basis": command.salary_period_basis,
            }
        )
        return current
    if isinstance(command, InitiateOffboardingCommand):
        if state != "active":
            _fault(
                "people_offboarding_state_invalid",
                "Offboarding initiation requires an active worker.",
            )
        _pay_period_matches_scope(scope, command.final_pay_period)
        if command.final_payroll_handoff_ref != current.get(
            "latest_payroll_handoff_ref"
        ) or command.final_pay_period != current.get("latest_payroll_pay_period"):
            _fault(
                "people_final_payroll_mismatch",
                "Offboarding must bind the exact latest final-pay handoff and period.",
            )
        employment_start = current.get("employment_starts_at")
        if employment_start is None or _parsed_timestamp(
            command.last_working_at
        ) < _parsed_timestamp(employment_start):
            _fault(
                "people_last_working_time_invalid",
                "Last working time cannot precede employment start.",
            )
        current.update(
            {
                "state": "offboarding_pending",
                "offboarding_ref": command.offboarding_ref,
                "offboarding_initiated_at": proposed_at,
                "last_working_at": command.last_working_at,
                "final_payroll_handoff_ref": command.final_payroll_handoff_ref,
                "expected_access_system_refs": command.expected_access_system_refs,
                "access_revocations": (),
            }
        )
        return current
    if isinstance(command, VerifyAccessRevocationCommand):
        if state not in {"offboarding_pending", "revocation_verified"}:
            _fault(
                "people_revocation_state_invalid",
                "Access revocation verification requires pending offboarding.",
            )
        if command.offboarding_ref != current.get("offboarding_ref"):
            _fault(
                "people_offboarding_identity_mismatch",
                "Access revocation must reference the exact offboarding identity.",
            )
        expected_systems = tuple(current.get("expected_access_system_refs", ()))
        if command.system_ref not in expected_systems:
            _fault(
                "people_access_system_unplanned",
                "Access revocation system is outside the exact offboarding plan.",
            )
        revocations = tuple(current.get("access_revocations", ()))
        if command.system_ref in {item.system_ref for item in revocations}:
            _fault(
                "people_duplicate_access_revocation",
                "Access system already has a retained revocation verification.",
            )
        initiated_at = current.get("offboarding_initiated_at")
        if (
            initiated_at is None
            or _parsed_timestamp(command.revoked_at) < _parsed_timestamp(initiated_at)
            or _parsed_timestamp(command.revoked_at) > _parsed_timestamp(proposed_at)
        ):
            _fault(
                "people_revocation_time_invalid",
                "Revocation must follow offboarding initiation and precede its verification cutoff.",
            )
        revocations = (
            *revocations,
            AccessRevocationProjection(
                system_ref=command.system_ref,
                account_ref=command.account_ref,
                revocation_verification_ref=command.revocation_verification_ref,
                claimed_provider_effect_receipt_digest=(
                    command.claimed_provider_effect_receipt_digest
                ),
                revoked_at=command.revoked_at,
            ),
        )
        current["access_revocations"] = revocations
        if {item.system_ref for item in revocations} == set(expected_systems):
            current["state"] = "revocation_verified"
        return current
    if isinstance(command, CompleteOffboardingCommand):
        if state != "revocation_verified":
            _fault(
                "people_access_revocation_incomplete",
                "Offboarding completion requires verified revocation for every planned access system.",
            )
        if command.offboarding_ref != current.get(
            "offboarding_ref"
        ) or command.final_payroll_handoff_ref != current.get(
            "final_payroll_handoff_ref"
        ):
            _fault(
                "people_offboarding_identity_mismatch",
                "Completion must bind exact offboarding and final-pay identities.",
            )
        latest_required_time = max(
            [
                _parsed_timestamp(current["last_working_at"]),
                *[
                    _parsed_timestamp(item.revoked_at)
                    for item in current.get("access_revocations", ())
                ],
            ]
        )
        completed_at = _parsed_timestamp(command.completed_at)
        if completed_at < latest_required_time or completed_at > _parsed_timestamp(
            proposed_at
        ):
            _fault(
                "people_offboarding_completion_time_invalid",
                "Completion must follow last work and every revocation, without exceeding cutoff.",
            )
        current.update({"state": "offboarded", "offboarded_at": command.completed_at})
        return current
    raise TypeError("unsupported people command")


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def _snapshot_payload(
    scope: PeopleOperationsScope,
    lifecycle_ref: str,
    history: Sequence[PeopleTransitionCandidate],
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": PEOPLE_OPERATIONS_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "scope_digest": people_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        **{
            key: _json_value(value)
            for key, value in projection.items()
            if value is not None
        },
        "revision": len(history),
        "transition_history": [item.to_dict() for item in history],
    }


def _derive_projection(
    scope: PeopleOperationsScope,
    lifecycle_ref: str,
    history: Sequence[PeopleTransitionCandidate],
) -> tuple[dict[str, Any], str]:
    if not history or len(history) > _MAX_TRANSITIONS:
        raise ValueError("people lifecycle history must contain 1 to 32 transitions")
    scope_digest = people_scope_digest(scope)
    projection: dict[str, Any] | None = None
    prefix: list[PeopleTransitionCandidate] = []
    current_digest = ZERO_DIGEST
    seen_transition_refs: set[str] = set()
    seen_idempotency_digests: set[str] = set()
    seen_evidence_refs: set[str] = set()
    seen_evidence_digests: set[str] = set()
    seen_approval_refs: set[str] = set()
    seen_approval_receipts: set[str] = set()
    prior_proposed_at: datetime | None = None
    for expected_revision, candidate in enumerate(history, start=1):
        if (
            candidate.revision != expected_revision
            or candidate.scope_digest != scope_digest
            or candidate.lifecycle_ref != lifecycle_ref
            or candidate.prior_state_digest != current_digest
        ):
            raise ValueError(
                "transition history revision, scope, lifecycle, or prior digest is invalid"
            )
        if candidate.transition_ref in seen_transition_refs:
            raise ValueError("transition references must be single-use")
        if candidate.idempotency_digest in seen_idempotency_digests:
            raise ValueError("idempotency digests must be single-use")
        proposed_at = _parsed_timestamp(candidate.proposed_at)
        if prior_proposed_at is not None and proposed_at < prior_proposed_at:
            raise ValueError("transition history time must be monotonic")
        required = _validate_approval(
            scope,
            lifecycle_ref,
            candidate.transition_ref,
            candidate.idempotency_digest,
            candidate.requested_by_ref,
            candidate.proposed_at,
            candidate.command,
        )
        if candidate.required_approver_role != required:
            raise ValueError("candidate required approver role is invalid")
        _validate_transition_evidence(
            scope_digest=scope_digest,
            lifecycle_ref=lifecycle_ref,
            expected_revision=expected_revision - 1,
            expected_state_digest=current_digest,
            transition_ref=candidate.transition_ref,
            idempotency_digest=candidate.idempotency_digest,
            requested_by_ref=candidate.requested_by_ref,
            proposed_at=candidate.proposed_at,
            command=candidate.command,
            evidence_refs=candidate.evidence_refs,
            prior_evidence_refs=seen_evidence_refs,
            prior_evidence_digests=seen_evidence_digests,
        )
        approval = candidate.command.approval
        if approval is not None:
            if (
                approval.approval_ref in seen_approval_refs
                or approval.approval_receipt_digest in seen_approval_receipts
            ):
                raise ValueError("approval references and receipts must be single-use")
            seen_approval_refs.add(approval.approval_ref)
            seen_approval_receipts.add(approval.approval_receipt_digest)
            seen_evidence_refs.add(approval.evidence.evidence_ref)
            seen_evidence_digests.add(approval.evidence.sha256)
        for evidence in candidate.evidence_refs:
            seen_evidence_refs.add(evidence.evidence_ref)
            seen_evidence_digests.add(evidence.sha256)
        projection = _apply_command(
            scope,
            projection,
            candidate.command,
            proposed_at=candidate.proposed_at,
        )
        prefix.append(candidate)
        current_digest = _stable_digest(
            _snapshot_payload(scope, lifecycle_ref, prefix, projection)
        )
        seen_transition_refs.add(candidate.transition_ref)
        seen_idempotency_digests.add(candidate.idempotency_digest)
        prior_proposed_at = proposed_at
    assert projection is not None
    return projection, current_digest


def _history_evidence(
    history: Sequence[PeopleTransitionCandidate],
) -> tuple[set[str], set[str]]:
    refs: set[str] = set()
    digests: set[str] = set()
    for candidate in history:
        for evidence in candidate.evidence_refs:
            refs.add(evidence.evidence_ref)
            digests.add(evidence.sha256)
        if candidate.command.approval is not None:
            refs.add(candidate.command.approval.evidence.evidence_ref)
            digests.add(candidate.command.approval.evidence.sha256)
    return refs, digests


def propose_people_operations_transition(
    value: PeopleTransitionRequest | Mapping[str, Any],
) -> PeopleTransitionResult:
    request = PeopleTransitionRequest.model_validate(value)
    current = request.current_snapshot
    if current is None:
        history: tuple[PeopleTransitionCandidate, ...] = ()
        source_digest = ZERO_DIGEST
    else:
        if (
            current.scope != request.scope
            or current.lifecycle_ref != request.lifecycle_ref
        ):
            _fault(
                "people_snapshot_scope_mismatch",
                "Current snapshot must match exact lifecycle and organizational scope.",
            )
        history = current.transition_history
        source_digest = current.state_digest
    if len(history) >= _MAX_TRANSITIONS:
        _fault(
            "people_transition_limit_reached",
            "Portable people lifecycle reached its bounded transition limit.",
        )
    idempotency_digest = people_idempotency_digest(
        request.scope,
        request.lifecycle_ref,
        request.idempotency_key,
    )
    if request.transition_ref in {item.transition_ref for item in history}:
        _fault(
            "people_duplicate_transition",
            "Transition reference was already retained by this lifecycle.",
        )
    if idempotency_digest in {item.idempotency_digest for item in history}:
        _fault(
            "people_replayed_idempotency_key",
            "Idempotency key was already retained by this lifecycle.",
        )
    required_role = _validate_approval(
        request.scope,
        request.lifecycle_ref,
        request.transition_ref,
        idempotency_digest,
        request.requested_by_ref,
        request.proposed_at,
        request.command,
    )
    prior_evidence_refs, prior_evidence_digests = _history_evidence(history)
    _validate_transition_evidence(
        scope_digest=people_scope_digest(request.scope),
        lifecycle_ref=request.lifecycle_ref,
        expected_revision=request.expected_revision,
        expected_state_digest=request.expected_state_digest,
        transition_ref=request.transition_ref,
        idempotency_digest=idempotency_digest,
        requested_by_ref=request.requested_by_ref,
        proposed_at=request.proposed_at,
        command=request.command,
        evidence_refs=request.evidence_refs,
        prior_evidence_refs=prior_evidence_refs,
        prior_evidence_digests=prior_evidence_digests,
    )
    approval = request.command.approval
    if approval is not None:
        if approval.approval_ref in {
            item.approval_ref for item in history if item.approval_ref is not None
        } or approval.approval_receipt_digest in {
            item.approval_receipt_digest
            for item in history
            if item.approval_receipt_digest is not None
        }:
            _fault(
                "people_replayed_approval",
                "Approval reference and receipt are single-use within one lifecycle.",
            )
    candidate_payload: dict[str, Any] = {
        "lifecycle_ref": request.lifecycle_ref,
        "revision": len(history) + 1,
        "scope_digest": people_scope_digest(request.scope),
        "transition_ref": request.transition_ref,
        "prior_state_digest": source_digest,
        "command": request.command,
        "command_digest": people_command_digest(request.command),
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": request.requested_by_ref,
        "proposed_at": request.proposed_at,
        "evidence_refs": request.evidence_refs,
        "evidence_digest": _evidence_digest(request.evidence_refs),
        "required_approver_role": required_role,
        "approval_ref": approval.approval_ref if approval is not None else None,
        "approval_receipt_digest": (
            approval.approval_receipt_digest if approval is not None else None
        ),
    }
    provisional_candidate = PeopleTransitionCandidate.model_construct(
        **candidate_payload,
        transition_digest=ZERO_DIGEST,
    )
    normalized_candidate = provisional_candidate.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"transition_digest"},
    )
    normalized_candidate["transition_digest"] = _stable_digest(normalized_candidate)
    candidate = PeopleTransitionCandidate.model_validate(normalized_candidate)
    next_history = (*history, candidate)
    projection, snapshot_digest = _derive_projection(
        request.scope,
        request.lifecycle_ref,
        next_history,
    )
    snapshot_payload = _snapshot_payload(
        request.scope,
        request.lifecycle_ref,
        next_history,
        projection,
    )
    snapshot_payload["state_digest"] = snapshot_digest
    snapshot = PeopleOperationsSnapshot.model_validate(snapshot_payload)
    proposal_payload: dict[str, Any] = {
        "scope": request.scope,
        "lifecycle_ref": request.lifecycle_ref,
        "source_revision": request.expected_revision,
        "source_state_digest": request.expected_state_digest,
        "target_revision": snapshot.revision,
        "target_state": snapshot.state,
        "transition_ref": request.transition_ref,
        "transition_digest": candidate.transition_digest,
        "candidate_state_digest": snapshot.state_digest,
        "required_approver_role": required_role,
        "business_approval_evidence_present": approval is not None,
    }
    provisional_proposal = PeopleTransitionProposal.model_construct(
        **proposal_payload,
        proposal_digest=ZERO_DIGEST,
    )
    normalized_proposal = provisional_proposal.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"proposal_digest"},
    )
    normalized_proposal["proposal_digest"] = _stable_digest(normalized_proposal)
    proposal = PeopleTransitionProposal.model_validate(normalized_proposal)
    return PeopleTransitionResult(proposal=proposal, candidate_snapshot=snapshot)


PEOPLE_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="people.operations-transition-proposal",
    tool="people.prepare_operations_transition",
    effect=ConnectorEffect.DRAFT,
    approval_required=True,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _no_effect_recovery() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.NONE,
        disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
    )


def _receipt(
    *,
    status: PrimitiveOperationStatus,
    request_digest: str,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    external_refs: Mapping[str, str] | None = None,
    error: PrimitiveBlocker | None = None,
) -> PrimitiveOperationReceipt:
    return PrimitiveOperationReceipt(
        spec=PEOPLE_TRANSITION_OPERATION,
        status=status,
        request_digest=request_digest,
        external_refs=dict(external_refs or {}),
        evidence_refs=list(evidence_refs),
        replayed=False,
        recovery_disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
        recovery_plan=_no_effect_recovery(),
        error=error,
    )


def _request_matches_context(
    request: PeopleTransitionRequest,
    context: PrimitiveExecutionContext,
) -> bool:
    context_scope = context.scope
    return (
        request.scope.tenant_ref == context_scope.tenant_ref
        and request.scope.company_ref == context_scope.company_ref
        and request.scope.project_ref == context_scope.project_ref
        and context_scope.project_id is not None
        and request.scope.project_id == context_scope.project_id
        and context_scope.actor_ref is not None
        and request.requested_by_ref == context_scope.actor_ref
        and context.idempotency_key is not None
        and request.idempotency_key == context.idempotency_key
    )


def _example_evidence(
    evidence_ref: str,
    *,
    subject_ref: str,
    sha256: str,
    observed_at: str,
    kind: str,
    grade: Literal["attested", "verified"] = "attested",
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": SPRING_PEOPLE_EVIDENCE_ISSUER,
        "subject_ref": subject_ref,
        "sha256": sha256,
        "observed_at": observed_at,
        "verification_grade": grade,
        "classification": "restricted",
        "retention_policy": "people-seven-years",
        "jurisdiction": "US-NY",
    }


def _example_scope() -> dict[str, Any]:
    return {
        "schema": PEOPLE_OPERATIONS_SCOPE_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000761",
        "worker_ref": "worker-example",
        "candidate_ref": "candidate-example",
        "position_ref": "position-example",
        "jurisdiction": "US-NY",
        "payroll_currency": "USD",
        "pay_rate_uom": "hour",
    }


def _example_approval(
    *,
    scope: Mapping[str, Any],
    lifecycle_ref: str,
    transition_ref: str,
    idempotency_key: str,
    requested_by_ref: str,
    command: Mapping[str, Any],
    role: ApprovalRole,
    approved_by_ref: str,
    approved_at: str,
    expires_at: str,
) -> dict[str, Any]:
    approval_ref = f"approval-{transition_ref}"
    payload: dict[str, Any] = {
        "schema": PEOPLE_APPROVAL_EVIDENCE_SCHEMA,
        "approval_ref": approval_ref,
        "approval_receipt_digest": _stable_digest({"approval_receipt": approval_ref}),
        "scope_digest": people_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        "transition_ref": transition_ref,
        "command_digest": people_command_digest(command),
        "idempotency_digest": people_idempotency_digest(
            scope,
            lifecycle_ref,
            idempotency_key,
        ),
        "approved_by_ref": approved_by_ref,
        "approver_role": role,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "decision": "approved",
        "single_use": True,
        "sdk_execution_authority_granted": False,
    }
    digest = people_approval_digest(payload)
    payload["evidence"] = _example_evidence(
        f"evidence-{approval_ref}",
        subject_ref=approval_ref,
        sha256=digest,
        observed_at=approved_at,
        kind="people_approval_decision",
        grade="verified",
    )
    payload["approval_digest"] = digest
    return payload


def _example_inputs() -> dict[str, Any]:
    scope = _example_scope()
    lifecycle_ref = "people-lifecycle-example"
    transition_ref = "transition-create-candidate-example"
    idempotency_key = "idempotency-create-candidate-example"
    requested_by_ref = "recruiter-example"
    proposed_at = "2026-08-25T14:00:00Z"
    command: dict[str, Any] = {
        "schema": "lightbulb.people_create_candidate_command.v1",
        "kind": "create_candidate",
        "worker_ref": scope["worker_ref"],
        "candidate_ref": scope["candidate_ref"],
        "position_ref": scope["position_ref"],
        "jurisdiction": scope["jurisdiction"],
        "recruiting_source_ref": "ats-source-example",
        "headcount_plan_ref": "headcount-plan-example",
        "position_authorization_ref": "position-approval-example",
        "position_status": "approved_open",
    }
    command["approval"] = _example_approval(
        scope=scope,
        lifecycle_ref=lifecycle_ref,
        transition_ref=transition_ref,
        idempotency_key=idempotency_key,
        requested_by_ref=requested_by_ref,
        command=command,
        role="workforce_authorizer",
        approved_by_ref="workforce-authorizer-example",
        approved_at="2026-08-25T13:55:00Z",
        expires_at="2026-08-25T15:55:00Z",
    )
    payload: dict[str, Any] = {
        "schema": PEOPLE_TRANSITION_REQUEST_SCHEMA,
        "scope": scope,
        "lifecycle_ref": lifecycle_ref,
        "expected_revision": 0,
        "expected_state_digest": ZERO_DIGEST,
        "transition_ref": transition_ref,
        "idempotency_key": idempotency_key,
        "requested_by_ref": requested_by_ref,
        "proposed_at": proposed_at,
        "command": command,
    }
    evidence_digest = people_transition_evidence_digest(payload)
    payload["evidence_refs"] = [
        _example_evidence(
            "evidence-transition-create-candidate-example",
            subject_ref=transition_ref,
            sha256=evidence_digest,
            observed_at="2026-08-25T13:58:00Z",
            kind="people_transition_commitment",
        )
    ]
    return PeopleTransitionRequest.model_validate(payload).to_dict()


class ProposePeopleOperationsTransitionPrimitive(
    BusinessProcessPrimitive[PeopleTransitionRequest, PeopleTransitionResult]
):
    primitive_ref = "people.propose_operations_transition"
    version = "1.1.0"
    title = "Propose a governed people-operations lifecycle transition"
    description = (
        "Validate and project one evidence-bound people-operations transition "
        "without changing employment, payroll, HCM, scheduling, learning, or IAM state."
    )
    input_model = PeopleTransitionRequest
    output_model = PeopleTransitionResult
    connector_tools = ()
    risk_level = "high"
    approval_required = True
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "sdk_projection_or_proposal_only": True,
            "authoritative_state_changed": False,
            "employment_or_compensation_decision_executed": False,
            "payroll_hcm_or_iam_write_executed": False,
            "hosted_approval_task_created": False,
            "spring_submission_executed": False,
            "provider_receipt_verified_by_sdk": False,
            "connector_calls": False,
            "spring_identity_rbac_and_persistence_required": True,
            "spring_approval_revalidation_required": True,
            "spring_revocation_provenance_verification_required": True,
        }
        contract["portable_payroll_calculation"] = {
            "hourly_time_leave_and_overtime_reconciliation": True,
            "annual_salary_full_period_only": True,
            "annual_salary_period_count_scope_required": True,
            "annual_salary_rounding": "decimal_half_even_to_currency_cent",
            "salary_proration_supported": False,
            "salary_overtime_supported": False,
            "authoritative_payroll_submission": False,
        }
        contract["portable_approval_evidence_is_execution_authority"] = False
        contract["portable_revocation_evidence_is_provider_provenance"] = False
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PeopleTransitionRequest,
    ) -> PrimitiveExecutionResult[PeopleTransitionResult]:
        all_evidence = list(inputs.evidence_refs)
        if inputs.command.approval is not None:
            all_evidence.append(inputs.command.approval.evidence)
        if not _request_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="people_runtime_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, project-id, actor, and "
                    "idempotency scope are required and must match the exact people request."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="People transition rejected at the runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=all_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs),
                        evidence_refs=all_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        try:
            output = propose_people_operations_transition(inputs)
        except PeopleOperationsLifecycleError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="People transition failed deterministic lifecycle validation.",
                blockers=[blocker],
                evidence_refs=all_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=_stable_digest(inputs),
                        evidence_refs=all_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        status = PrimitiveExecutionStatus.PENDING_APPROVAL
        receipt_status = PrimitiveOperationStatus.PENDING_APPROVAL
        summary = (
            "People transition candidate validated locally; Spring submission, "
            "authorization, and persistence remain pending, no hosted approval "
            "task was created, and no live system changed."
        )
        if context.preview_only:
            status = PrimitiveExecutionStatus.PREVIEW
            receipt_status = PrimitiveOperationStatus.PREVIEW
            summary = (
                "People transition preview passed deterministic validation; no "
                "Spring submission or hosted approval task was created, and Spring "
                "authorization, persistence, and any live writes remain pending."
            )
        proposal = output.proposal
        return PrimitiveExecutionResult(
            status=status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=summary,
            output=output,
            events=[
                PrimitiveEvent(
                    type="people.operations_transition_candidate_validated",
                    payload={
                        "lifecycle_ref": proposal.lifecycle_ref,
                        "transition_ref": proposal.transition_ref,
                        "target_state": proposal.target_state,
                        "proposal_digest": proposal.proposal_digest,
                        "authoritative_state_changed": False,
                        "provider_effect_executed": False,
                        "hosted_approval_task_created": False,
                        "spring_submission_executed": False,
                        "provider_receipt_verified_by_sdk": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="people_operations_transition_proposal",
                    summary=(
                        "Content-bound SDK candidate; Spring retains employment, "
                        "payroll, HCM, IAM, approval, persistence, and audit authority."
                    ),
                    labels=[
                        inputs.command.kind,
                        proposal.target_state,
                        "no_live_effect",
                        "not_submitted_to_spring",
                    ],
                    refs={"proposal_digest": proposal.proposal_digest},
                )
            ],
            evidence_refs=all_evidence,
            operation_receipts=[
                _receipt(
                    status=receipt_status,
                    request_digest=proposal.proposal_digest,
                    evidence_refs=all_evidence,
                    external_refs={
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "transition_digest": proposal.transition_digest,
                    },
                )
            ],
            retryable=False,
        )


PEOPLE_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposePeopleOperationsTransitionPrimitive(),)


__all__ = [
    "PEOPLE_ACCESS_REVOCATION_EVIDENCE_SCHEMA",
    "PEOPLE_APPROVAL_EVIDENCE_SCHEMA",
    "PEOPLE_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "PEOPLE_OPERATIONS_SCOPE_SCHEMA",
    "PEOPLE_OPERATIONS_SNAPSHOT_SCHEMA",
    "PEOPLE_PAY_PERIOD_SCHEMA",
    "PEOPLE_PAYROLL_CALCULATION_BASIS_SCHEMA",
    "PEOPLE_TRANSITION_CANDIDATE_SCHEMA",
    "PEOPLE_TRANSITION_EVIDENCE_COMMITMENT_SCHEMA",
    "PEOPLE_TRANSITION_OPERATION",
    "PEOPLE_TRANSITION_PROPOSAL_SCHEMA",
    "PEOPLE_TRANSITION_REQUEST_SCHEMA",
    "PEOPLE_TRANSITION_RESULT_SCHEMA",
    "SPRING_PEOPLE_EVIDENCE_ISSUER",
    "ZERO_DIGEST",
    "AccessRevocationProjection",
    "ActivateWorkerCommand",
    "AdvanceCandidateCommand",
    "CertificationProjection",
    "CompleteOffboardingCommand",
    "CreateCandidateCommand",
    "InitiateOffboardingCommand",
    "PeopleApprovalEvidence",
    "PeopleOperationsLifecycleError",
    "PeopleOperationsScope",
    "PeopleOperationsSnapshot",
    "PeoplePayPeriod",
    "PeopleTransitionCandidate",
    "PeopleTransitionProposal",
    "PeopleTransitionRequest",
    "PeopleTransitionResult",
    "PreparePayrollHandoffCommand",
    "ProposePeopleOperationsTransitionPrimitive",
    "RecordApprovedLeaveCommand",
    "RecordApprovedTimecardCommand",
    "RecordCertificationCommand",
    "RecordPerformanceCompensationCommand",
    "ScheduleShiftCommand",
    "VerifyAccessRevocationCommand",
    "people_approval_digest",
    "people_access_revocation_evidence_digest",
    "people_command_digest",
    "people_idempotency_digest",
    "people_payroll_calculation_basis_digest",
    "people_scope_digest",
    "people_snapshot_digest",
    "people_transition_candidate_digest",
    "people_transition_evidence_digest",
    "propose_people_operations_transition",
]
