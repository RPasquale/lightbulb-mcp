"""Evidence-bound recruiting, payroll-readiness, and offboarding controls.

The SDK evaluates normalized people-operations evidence. It never hires or
terminates a worker, changes compensation or leave, exports payroll, schedules
a shift, provisions/revokes access, or asserts that a system-of-record changed.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
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
    revalidate_model_boundary,
)


PEOPLE_CONTROL_INPUT_SCHEMA = "lightbulb.people_control_input.v1"
PEOPLE_CONTROL_RESULT_SCHEMA = "lightbulb.people_control_result.v1"
WORKER_LIFECYCLE_SNAPSHOT_SCHEMA = "lightbulb.worker_lifecycle_snapshot.v1"

_QUANTITY_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.0001")
_ZERO_DIGEST = "0" * 64
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

PeopleTarget = Literal["hire", "payroll", "offboarding"]
GateName = Literal[
    "evidence",
    "workforce",
    "recruiting",
    "worker",
    "schedule_time",
    "leave",
    "performance_compensation",
    "learning",
    "payroll",
    "offboarding",
    "access",
]
GateStatus = Literal["pass", "review", "fail", "indeterminate"]
_GATE_ORDER: tuple[GateName, ...] = (
    "evidence",
    "workforce",
    "recruiting",
    "worker",
    "schedule_time",
    "leave",
    "performance_compensation",
    "learning",
    "payroll",
    "offboarding",
    "access",
)
Disposition = Literal[
    "ready_for_hire_approval",
    "ready_for_payroll_export",
    "ready_for_offboarding_completion",
    "manual_review_required",
    "blocked",
    "indeterminate",
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


def _as_tuple(value: Any) -> Any:
    return tuple(value) if isinstance(value, list) else value


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
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise ValueError(f"{field_name} must be YYYY-MM-DD") from exc


def _decimal(value: Any, *, quantum: Decimal) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal fields must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError("decimal fields must use bounded notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(quantum)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("decimal fields must be finite") from exc
    if not parsed.is_finite() or parsed != normalized or parsed < 0:
        raise ValueError("decimal field is negative or exceeds supported precision")
    return normalized


def _quantity(value: Any) -> Decimal:
    return _decimal(value, quantum=_QUANTITY_QUANTUM)


def _money(value: Any) -> Decimal:
    return _decimal(value, quantum=_MONEY_QUANTUM)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def people_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


class WorkerLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.worker_lifecycle_snapshot.v1"] = Field(
        default=WORKER_LIFECYCLE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    person_ref: OpaqueRef
    candidate_ref: OpaqueRef | None = None
    worker_ref: OpaqueRef | None = None
    position_ref: OpaqueRef
    manager_ref: OpaqueRef | None = None
    company_ref: OpaqueRef
    location_ref: OpaqueRef
    employment_type: Literal["employee", "contractor", "temporary", "intern"]
    stage: Literal[
        "candidate",
        "offer",
        "prehire",
        "active",
        "leave",
        "suspended",
        "terminated",
    ]
    identity_verification: Literal["verified", "pending", "failed", "unknown"]
    right_to_work: Literal["verified", "pending", "failed", "not_applicable", "unknown"]
    start_date: str | None = None
    end_date: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("start_date", "end_date")
    @classmethod
    def _valid_dates(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _date(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _employment_dates_are_chronological(self) -> "WorkerLifecycleSnapshot":
        if (
            self.start_date is not None
            and self.end_date is not None
            and date.fromisoformat(self.end_date) < date.fromisoformat(self.start_date)
        ):
            raise ValueError("worker end_date cannot precede start_date")
        return self


class WorkforcePlanSnapshot(_StrictModel):
    plan_ref: OpaqueRef
    position_ref: OpaqueRef
    position_status: Literal[
        "approved_open", "filled", "frozen", "cancelled", "unknown"
    ]
    headcount_available: bool | None
    budget_ref: OpaqueRef | None = None
    budget_approved: bool | None = None
    required_location_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class RecruitingSnapshot(_StrictModel):
    recruiting_ref: OpaqueRef
    candidate_ref: OpaqueRef
    stage: Literal[
        "application",
        "screen",
        "interview",
        "reference_check",
        "offer_pending",
        "offer_accepted",
        "rejected",
        "withdrawn",
    ]
    scorecard_complete: bool
    conflict_check: Literal["clear", "review", "blocked", "not_performed"]
    background_check: Literal["clear", "review", "failed", "not_required", "pending"]
    offer_ref: OpaqueRef | None = None
    offer_approval_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _accepted_offer_is_bound(self) -> "RecruitingSnapshot":
        if self.stage == "offer_accepted" and (
            self.offer_ref is None or self.offer_approval_ref is None
        ):
            raise ValueError("accepted offer requires offer_ref and offer_approval_ref")
        return self


class ScheduleTimeSnapshot(_StrictModel):
    timecard_ref: OpaqueRef
    worker_ref: OpaqueRef
    pay_period_ref: OpaqueRef
    pay_period_start: str
    pay_period_end: str
    scheduled_hours: Decimal = Field(ge=0)
    worked_hours: Decimal = Field(ge=0)
    overtime_hours: Decimal = Field(default=Decimal("0"), ge=0)
    status: Literal["draft", "submitted", "approved", "rejected"]
    approval_ref: OpaqueRef | None = None
    exception_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("pay_period_start", "pay_period_end")
    @classmethod
    def _valid_dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)

    @field_validator("scheduled_hours", "worked_hours", "overtime_hours", mode="before")
    @classmethod
    def _valid_hours(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("exception_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_period(self) -> "ScheduleTimeSnapshot":
        if self.pay_period_end < self.pay_period_start:
            raise ValueError("pay_period_end cannot precede pay_period_start")
        if self.status == "approved" and self.approval_ref is None:
            raise ValueError("approved timecard requires approval_ref")
        return self


class LeaveSnapshot(_StrictModel):
    leave_ref: OpaqueRef
    worker_ref: OpaqueRef
    leave_type_ref: OpaqueRef
    start_date: str
    end_date: str
    requested_hours: Decimal = Field(gt=0)
    available_hours: Decimal = Field(ge=0)
    status: Literal["requested", "approved", "denied", "in_progress", "completed"]
    approval_ref: OpaqueRef | None = None
    payroll_reconciled: bool | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("start_date", "end_date")
    @classmethod
    def _valid_dates(cls, value: str, info: Any) -> str:
        return _date(value, field_name=info.field_name)

    @field_validator("requested_hours", "available_hours", mode="before")
    @classmethod
    def _valid_hours(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _leave_dates_are_chronological(self) -> "LeaveSnapshot":
        if date.fromisoformat(self.end_date) < date.fromisoformat(self.start_date):
            raise ValueError("leave end_date cannot precede start_date")
        return self


class PerformanceCompensationSnapshot(_StrictModel):
    review_ref: OpaqueRef
    worker_ref: OpaqueRef
    review_status: Literal["not_due", "pending", "completed", "overdue"]
    compensation_change_amount: Decimal | None = Field(default=None, ge=0)
    currency: CurrencyCode | None = None
    compensation_approval_ref: OpaqueRef | None = None
    pay_equity_review: Literal["clear", "review", "blocked", "not_performed"]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("compensation_change_amount", mode="before")
    @classmethod
    def _valid_amount(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _compensation_fields_bound(self) -> "PerformanceCompensationSnapshot":
        if self.compensation_change_amount is not None and (
            self.currency is None or self.compensation_approval_ref is None
        ):
            raise ValueError("compensation change requires currency and approval_ref")
        if self.compensation_change_amount is None and (
            self.currency is not None or self.compensation_approval_ref is not None
        ):
            raise ValueError("compensation fields require a change amount")
        return self


class CertificationRequirement(_StrictModel):
    certification_ref: OpaqueRef
    status: Literal["current", "pending", "expired", "missing", "waived"]
    expires_at: str | None = None
    waiver_ref: OpaqueRef | None = None

    @field_validator("expires_at")
    @classmethod
    def _valid_expiry(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="expires_at")

    @model_validator(mode="after")
    def _waiver_bound(self) -> "CertificationRequirement":
        if self.status == "waived" and self.waiver_ref is None:
            raise ValueError("waived certification requires waiver_ref")
        return self


class LearningSnapshot(_StrictModel):
    learning_ref: OpaqueRef
    worker_or_candidate_ref: OpaqueRef
    requirements: tuple[CertificationRequirement, ...] = Field(
        default_factory=tuple,
        max_length=1_000,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("requirements", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _unique_requirements(self) -> "LearningSnapshot":
        refs = [item.certification_ref for item in self.requirements]
        if len(refs) != len(set(refs)):
            raise ValueError("certification requirements must be unique")
        return self


class PayrollIntegrationSnapshot(_StrictModel):
    payroll_ref: OpaqueRef
    worker_ref: OpaqueRef
    provider_worker_ref: OpaqueRef | None = None
    tax_profile: Literal["complete", "missing", "invalid", "unknown"]
    payment_method: Literal["verified", "missing", "invalid", "unknown"]
    compensation_ref: OpaqueRef | None = None
    pay_group_ref: OpaqueRef | None = None
    time_import: Literal["not_required", "ready", "blocked", "unknown"]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class OffboardingSnapshot(_StrictModel):
    offboarding_ref: OpaqueRef
    worker_ref: OpaqueRef
    termination_approval_ref: OpaqueRef | None = None
    last_working_date: str
    final_pay: Literal["unknown", "calculated", "approved", "paid"]
    final_pay_approval_ref: OpaqueRef | None = None
    assets: Literal["unknown", "pending", "returned", "waived"]
    asset_waiver_ref: OpaqueRef | None = None
    knowledge_transfer: Literal["not_required", "pending", "completed"]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("last_working_date")
    @classmethod
    def _valid_last_day(cls, value: str) -> str:
        return _date(value, field_name="last_working_date")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _waiver_bound(self) -> "OffboardingSnapshot":
        if self.assets == "waived" and self.asset_waiver_ref is None:
            raise ValueError("asset return waiver requires asset_waiver_ref")
        return self


class AccessAccountSnapshot(_StrictModel):
    system_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal["active", "disabled", "revoked", "unknown"]
    revocation_receipt_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _revocation_bound(self) -> "AccessAccountSnapshot":
        if self.status == "revoked" and self.revocation_receipt_ref is None:
            raise ValueError("revoked access requires revocation_receipt_ref")
        return self


class PeopleControlPolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=720, ge=1, le=8_760)
    require_current_certifications_for_hire: bool = True
    allow_certification_waiver_review: bool = True
    require_clear_pay_equity_review: bool = True
    require_timecard_without_exceptions: bool = True
    require_final_pay_approval: bool = True
    require_all_access_revoked: bool = True


class PeopleControlInput(_StrictModel):
    schema_id: Literal["lightbulb.people_control_input.v1"] = Field(
        default=PEOPLE_CONTROL_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: PeopleTarget
    analysis_as_of: str
    target_pay_period_ref: OpaqueRef | None = None
    target_pay_period_start: str | None = None
    target_pay_period_end: str | None = None
    worker: WorkerLifecycleSnapshot
    workforce_plan: WorkforcePlanSnapshot | None = None
    recruiting: RecruitingSnapshot | None = None
    schedule_time: ScheduleTimeSnapshot | None = None
    leave: LeaveSnapshot | None = None
    performance_compensation: PerformanceCompensationSnapshot | None = None
    learning: LearningSnapshot | None = None
    payroll: PayrollIntegrationSnapshot | None = None
    offboarding: OffboardingSnapshot | None = None
    access_accounts: tuple[AccessAccountSnapshot, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    policy: PeopleControlPolicy = Field(default_factory=PeopleControlPolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator("target_pay_period_start", "target_pay_period_end")
    @classmethod
    def _valid_target_pay_period_dates(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _date(value, field_name=info.field_name)

    @field_validator("access_accounts", mode="before")
    @classmethod
    def _access_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _input_scope_is_coherent(self) -> "PeopleControlInput":
        refs = [(item.system_ref, item.account_ref) for item in self.access_accounts]
        if len(refs) != len(set(refs)):
            raise ValueError("access system/account pairs must be unique")
        analysis_date = _parsed_timestamp(self.analysis_as_of).date()
        worker_start_date = (
            date.fromisoformat(self.worker.start_date)
            if self.worker.start_date is not None
            else None
        )
        if (
            self.worker.stage in {"active", "leave", "suspended", "terminated"}
            and worker_start_date is not None
            and worker_start_date > analysis_date
        ):
            raise ValueError("actual worker start_date cannot follow analysis_as_of")
        worker_end_date = (
            date.fromisoformat(self.worker.end_date)
            if self.worker.end_date is not None
            else None
        )
        if (
            self.worker.stage == "terminated"
            and worker_end_date is not None
            and worker_end_date > analysis_date
        ):
            raise ValueError("terminated worker end_date cannot follow analysis_as_of")

        if self.offboarding is not None:
            if (
                self.worker.end_date is None
                or self.offboarding.last_working_date != self.worker.end_date
            ):
                raise ValueError(
                    "offboarding last_working_date must exactly match worker end_date"
                )

        if self.leave is not None:
            leave_start_date = date.fromisoformat(self.leave.start_date)
            leave_end_date = date.fromisoformat(self.leave.end_date)
            if self.leave.status == "in_progress" and leave_start_date > analysis_date:
                raise ValueError(
                    "in-progress leave start_date cannot follow analysis_as_of"
                )
            if self.leave.status == "completed" and leave_end_date > analysis_date:
                raise ValueError(
                    "completed leave end_date cannot follow analysis_as_of"
                )
        target_period = (
            self.target_pay_period_ref,
            self.target_pay_period_start,
            self.target_pay_period_end,
        )
        if self.target == "payroll" and any(value is None for value in target_period):
            raise ValueError(
                "payroll evaluation requires target pay-period ref, start, and end"
            )
        if self.target != "payroll" and any(
            value is not None for value in target_period
        ):
            raise ValueError("target pay-period fields are valid only for payroll")
        if self.target == "payroll":
            period_start = date.fromisoformat(self.target_pay_period_start or "")
            period_end = date.fromisoformat(self.target_pay_period_end or "")
            if period_end < period_start:
                raise ValueError(
                    "target_pay_period_end cannot precede target_pay_period_start"
                )
            if period_end > analysis_date:
                raise ValueError(
                    "target pay period cannot end after the analysis cutoff"
                )
        return self


class PeopleFinding(_StrictModel):
    code: OpaqueRef
    gate: GateName
    status: Literal["review", "fail", "indeterminate"]
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    subject_ref: OpaqueRef | None = None


class PeopleGateResult(_StrictModel):
    gate: GateName
    status: GateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=1_000
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class PeopleEffectBoundary(_StrictModel):
    worker_hired_or_terminated: Literal[False] = False
    compensation_or_leave_changed: Literal[False] = False
    schedule_or_timecard_changed: Literal[False] = False
    payroll_exported_or_paid: Literal[False] = False
    learning_or_certification_changed: Literal[False] = False
    access_provisioned_or_revoked: Literal[False] = False
    trusted_host_authority_required: Literal[True] = True


PEOPLE_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="worker-lifecycle-controls.evaluate",
    tool="people.evaluate_worker_lifecycle_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class PeopleControlResult(_StrictModel):
    schema_id: Literal["lightbulb.people_control_result.v1"] = Field(
        default=PEOPLE_CONTROL_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: PeopleTarget
    analysis_as_of: str
    proposed_disposition: Disposition
    assurance_grade: PrimitiveEvidenceVerificationGrade
    gates: tuple[PeopleGateResult, ...]
    findings: tuple[PeopleFinding, ...]
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[OpaqueRef, ...]
    effect_boundary: PeopleEffectBoundary = Field(default_factory=PeopleEffectBoundary)
    result_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator("gates", "findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _result_is_coherent_and_content_bound(self) -> "PeopleControlResult":
        expected_findings = tuple(
            sorted(
                self.findings,
                key=lambda item: (
                    _GATE_ORDER.index(item.gate),
                    item.subject_ref or "",
                    item.code,
                ),
            )
        )
        if self.findings != expected_findings:
            raise ValueError("findings must be in canonical order")
        expected_gates = tuple(
            PeopleGateResult(
                gate=gate,
                status=_status([item for item in self.findings if item.gate == gate]),
                finding_codes=tuple(
                    item.code for item in self.findings if item.gate == gate
                ),
            )
            for gate in _GATE_ORDER
        )
        if self.gates != expected_gates:
            raise ValueError("gates must be the canonical projection of findings")
        statuses = {gate.status for gate in self.gates}
        expected_disposition: Disposition = (
            "blocked"
            if "fail" in statuses
            else "indeterminate"
            if "indeterminate" in statuses
            else "manual_review_required"
            if "review" in statuses
            else {
                "hire": "ready_for_hire_approval",
                "payroll": "ready_for_payroll_export",
                "offboarding": "ready_for_offboarding_completion",
            }[self.target]
        )
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match target and gate results")
        if set(self.source_snapshot_digests) != {
            "worker",
            "policy",
            "target_pay_period",
            "workforce_plan",
            "recruiting",
            "schedule_time",
            "leave",
            "performance_compensation",
            "learning",
            "payroll",
            "offboarding",
            "access_accounts",
        }:
            raise ValueError(
                "source_snapshot_digests must contain the exact source set"
            )
        if any(
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in self.source_snapshot_digests.values()
        ):
            raise ValueError("source snapshot digests must be lowercase SHA-256 values")
        if self.evidence_refs != tuple(sorted(set(self.evidence_refs))):
            raise ValueError("evidence_refs must be unique and in canonical order")
        expected_digest = _stable_digest(
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


def _all_snapshots(
    inputs: PeopleControlInput,
) -> dict[str, BaseModel | Mapping[str, Any] | None]:
    return {
        "worker": inputs.worker,
        "target_pay_period": (
            {
                "target_pay_period_ref": inputs.target_pay_period_ref,
                "target_pay_period_start": inputs.target_pay_period_start,
                "target_pay_period_end": inputs.target_pay_period_end,
            }
            if inputs.target == "payroll"
            else None
        ),
        "workforce_plan": inputs.workforce_plan,
        "recruiting": inputs.recruiting,
        "schedule_time": inputs.schedule_time,
        "leave": inputs.leave,
        "performance_compensation": inputs.performance_compensation,
        "learning": inputs.learning,
        "payroll": inputs.payroll,
        "offboarding": inputs.offboarding,
        "access_accounts": None,
    }


def _all_evidence(inputs: PeopleControlInput) -> tuple[PrimitiveEvidenceRef, ...]:
    evidence: list[PrimitiveEvidenceRef] = []
    for snapshot in _all_snapshots(inputs).values():
        if snapshot is not None:
            evidence.extend(getattr(snapshot, "evidence_refs", ()))
    for account in inputs.access_accounts:
        evidence.extend(account.evidence_refs)
    return tuple(evidence)


def _add(
    findings: list[PeopleFinding],
    *,
    code: str,
    gate: GateName,
    status: Literal["review", "fail", "indeterminate"],
    message: str,
    subject_ref: str | None = None,
) -> None:
    findings.append(
        PeopleFinding(
            code=code,
            gate=gate,
            status=status,
            message=message,
            subject_ref=subject_ref,
        )
    )


def _status(findings: Sequence[PeopleFinding]) -> GateStatus:
    values = {item.status for item in findings}
    if "fail" in values:
        return "fail"
    if "indeterminate" in values:
        return "indeterminate"
    if "review" in values:
        return "review"
    return "pass"


def evaluate_people_controls(
    value: PeopleControlInput | Mapping[str, Any],
) -> PeopleControlResult:
    """Evaluate one people-lifecycle gate without changing a host system."""

    inputs = revalidate_model_boundary(PeopleControlInput, value)
    findings: list[PeopleFinding] = []
    evidence = _all_evidence(inputs)
    evidence_names = [item.evidence_ref for item in evidence]
    if len(evidence_names) != len(set(evidence_names)):
        _add(
            findings,
            code="evidence_ref_reused",
            gate="evidence",
            status="indeterminate",
            message="Evidence references must identify unique retained artifacts.",
        )
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    for item in evidence:
        observed_at = _parsed_timestamp(item.observed_at)
        if observed_at > analysis_at:
            _add(
                findings,
                code=f"future_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence was observed after the analysis cutoff.",
                subject_ref=item.evidence_ref,
            )
        elif (
            analysis_at - observed_at
        ).total_seconds() > inputs.policy.max_evidence_age_hours * 3_600:
            _add(
                findings,
                code=f"stale_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence exceeds the configured freshness window.",
                subject_ref=item.evidence_ref,
            )
        if (
            _GRADE_RANK[item.verification_grade]
            < _GRADE_RANK[inputs.policy.minimum_evidence_grade]
        ):
            _add(
                findings,
                code=f"weak_evidence:{item.evidence_ref}",
                gate="evidence",
                status="indeterminate",
                message="Evidence verification grade is below policy.",
                subject_ref=item.evidence_ref,
            )

    worker = inputs.worker
    if worker.identity_verification in {"failed"}:
        _add(
            findings,
            code="identity_verification_failed",
            gate="worker",
            status="fail",
            message="Worker identity verification failed.",
            subject_ref=worker.person_ref,
        )
    elif worker.identity_verification in {"pending", "unknown"}:
        _add(
            findings,
            code="identity_verification_incomplete",
            gate="worker",
            status="indeterminate",
            message="Worker identity verification is incomplete.",
            subject_ref=worker.person_ref,
        )
    if worker.right_to_work == "failed":
        _add(
            findings,
            code="right_to_work_failed",
            gate="worker",
            status="fail",
            message="Right-to-work verification failed.",
            subject_ref=worker.person_ref,
        )
    elif worker.right_to_work in {"pending", "unknown"}:
        _add(
            findings,
            code="right_to_work_incomplete",
            gate="worker",
            status="indeterminate",
            message="Right-to-work verification is incomplete.",
            subject_ref=worker.person_ref,
        )

    if inputs.target == "hire":
        plan = inputs.workforce_plan
        if plan is None:
            _add(
                findings,
                code="workforce_plan_missing",
                gate="workforce",
                status="indeterminate",
                message="Hire readiness requires an approved workforce-plan position.",
                subject_ref=worker.position_ref,
            )
        elif plan.position_ref != worker.position_ref:
            _add(
                findings,
                code="workforce_position_mismatch",
                gate="workforce",
                status="fail",
                message="Worker and workforce plan position references differ.",
                subject_ref=worker.position_ref,
            )
        elif (
            plan.required_location_ref is not None
            and plan.required_location_ref != worker.location_ref
        ):
            _add(
                findings,
                code="workforce_location_mismatch",
                gate="workforce",
                status="fail",
                message=(
                    "Worker/candidate location does not match the workforce plan's "
                    "required location."
                ),
                subject_ref=plan.plan_ref,
            )
        elif (
            plan.position_status != "approved_open"
            or plan.headcount_available is not True
            or plan.budget_approved is not True
            or plan.budget_ref is None
        ):
            _add(
                findings,
                code="workforce_position_not_authorized",
                gate="workforce",
                status=(
                    "indeterminate"
                    if plan.headcount_available is None or plan.budget_approved is None
                    else "fail"
                ),
                message="Position, headcount, and budget are not all approved and available.",
                subject_ref=plan.plan_ref,
            )
        recruiting = inputs.recruiting
        if recruiting is None:
            _add(
                findings,
                code="recruiting_evidence_missing",
                gate="recruiting",
                status="indeterminate",
                message="Hire readiness requires candidate progression evidence.",
                subject_ref=worker.candidate_ref,
            )
        elif recruiting.candidate_ref != worker.candidate_ref:
            _add(
                findings,
                code="candidate_reference_mismatch",
                gate="recruiting",
                status="fail",
                message="Recruiting and worker candidate references differ.",
                subject_ref=recruiting.recruiting_ref,
            )
        else:
            if (
                recruiting.stage != "offer_accepted"
                or not recruiting.scorecard_complete
            ):
                _add(
                    findings,
                    code="candidate_progression_incomplete",
                    gate="recruiting",
                    status="fail",
                    message="Candidate scorecard and accepted offer are required.",
                    subject_ref=recruiting.recruiting_ref,
                )
            if (
                recruiting.conflict_check == "blocked"
                or recruiting.background_check == "failed"
            ):
                _add(
                    findings,
                    code="recruiting_screen_blocked",
                    gate="recruiting",
                    status="fail",
                    message="Conflict or background screening blocked the hire.",
                    subject_ref=recruiting.recruiting_ref,
                )
            elif recruiting.conflict_check in {
                "review",
                "not_performed",
            } or recruiting.background_check in {"review", "pending"}:
                _add(
                    findings,
                    code="recruiting_screen_review",
                    gate="recruiting",
                    status="review",
                    message="Conflict or background screening requires review.",
                    subject_ref=recruiting.recruiting_ref,
                )
        if (
            worker.stage not in {"offer", "prehire"}
            or worker.manager_ref is None
            or worker.start_date is None
        ):
            _add(
                findings,
                code="prehire_worker_context_incomplete",
                gate="worker",
                status="fail",
                message="Prehire stage, manager, and start date are required.",
                subject_ref=worker.person_ref,
            )

    if inputs.target == "payroll":
        if worker.stage not in {"active", "leave"} or worker.worker_ref is None:
            _add(
                findings,
                code="worker_not_payroll_eligible",
                gate="worker",
                status="fail",
                message="Payroll readiness requires an active or leave worker reference.",
                subject_ref=worker.person_ref,
            )
        timecard = inputs.schedule_time
        if timecard is None:
            _add(
                findings,
                code="timecard_missing",
                gate="schedule_time",
                status="indeterminate",
                message="Payroll readiness requires a normalized timecard.",
                subject_ref=worker.worker_ref,
            )
        elif timecard.worker_ref != worker.worker_ref or timecard.status != "approved":
            _add(
                findings,
                code="timecard_not_approved",
                gate="schedule_time",
                status="fail",
                message="Timecard is not approved for the exact worker.",
                subject_ref=timecard.timecard_ref,
            )
        elif (
            timecard.pay_period_ref != inputs.target_pay_period_ref
            or timecard.pay_period_start != inputs.target_pay_period_start
            or timecard.pay_period_end != inputs.target_pay_period_end
        ):
            _add(
                findings,
                code="timecard_pay_period_mismatch",
                gate="schedule_time",
                status="fail",
                message=(
                    "Approved timecard must exactly match the target pay-period "
                    "identity and date range."
                ),
                subject_ref=timecard.timecard_ref,
            )
        elif (
            inputs.policy.require_timecard_without_exceptions
            and timecard.exception_refs
        ):
            _add(
                findings,
                code="timecard_exceptions_open",
                gate="schedule_time",
                status="fail",
                message="Approved timecard still contains unresolved exceptions.",
                subject_ref=timecard.timecard_ref,
            )
        if inputs.leave is not None:
            leave = inputs.leave
            if leave.worker_ref != worker.worker_ref:
                _add(
                    findings,
                    code="leave_worker_mismatch",
                    gate="leave",
                    status="fail",
                    message="Leave and payroll worker references differ.",
                    subject_ref=leave.leave_ref,
                )
            elif leave.status in {"approved", "in_progress", "completed"} and (
                leave.approval_ref is None or leave.payroll_reconciled is not True
            ):
                _add(
                    findings,
                    code="leave_not_payroll_reconciled",
                    gate="leave",
                    status="fail",
                    message="Approved leave is not reconciled to payroll.",
                    subject_ref=leave.leave_ref,
                )
            if (
                leave.requested_hours > leave.available_hours
                and leave.status == "approved"
            ):
                _add(
                    findings,
                    code="leave_balance_exceeded",
                    gate="leave",
                    status="review",
                    message="Approved leave exceeds the supplied balance.",
                    subject_ref=leave.leave_ref,
                )
        payroll = inputs.payroll
        if payroll is None:
            _add(
                findings,
                code="payroll_integration_missing",
                gate="payroll",
                status="indeterminate",
                message="Payroll integration evidence is missing.",
                subject_ref=worker.worker_ref,
            )
        elif payroll.worker_ref != worker.worker_ref:
            _add(
                findings,
                code="payroll_worker_mismatch",
                gate="payroll",
                status="fail",
                message="Payroll integration belongs to a different worker.",
                subject_ref=payroll.payroll_ref,
            )
        elif (
            payroll.provider_worker_ref is None
            or payroll.compensation_ref is None
            or payroll.pay_group_ref is None
            or payroll.tax_profile != "complete"
            or payroll.payment_method != "verified"
            or payroll.time_import not in {"ready", "not_required"}
        ):
            unknown = (
                payroll.tax_profile == "unknown"
                or payroll.payment_method == "unknown"
                or payroll.time_import == "unknown"
            )
            _add(
                findings,
                code="payroll_integration_incomplete",
                gate="payroll",
                status="indeterminate" if unknown else "fail",
                message="Payroll worker, tax, payment, compensation, pay-group, or time import is incomplete.",
                subject_ref=payroll.payroll_ref,
            )

    compensation = inputs.performance_compensation
    if compensation is not None:
        if (
            worker.worker_ref is not None
            and compensation.worker_ref != worker.worker_ref
        ):
            _add(
                findings,
                code="performance_worker_mismatch",
                gate="performance_compensation",
                status="fail",
                message="Performance/compensation evidence belongs to another worker.",
                subject_ref=compensation.review_ref,
            )
        if compensation.review_status == "overdue":
            _add(
                findings,
                code="performance_review_overdue",
                gate="performance_compensation",
                status="review",
                message="A performance review is overdue.",
                subject_ref=compensation.review_ref,
            )
        if (
            inputs.policy.require_clear_pay_equity_review
            and compensation.pay_equity_review != "clear"
        ):
            _add(
                findings,
                code="pay_equity_review_not_clear",
                gate="performance_compensation",
                status=(
                    "fail" if compensation.pay_equity_review == "blocked" else "review"
                ),
                message="Pay-equity review is not clear.",
                subject_ref=compensation.review_ref,
            )

    if inputs.learning is not None:
        expected_learning_subject = (
            worker.candidate_ref if inputs.target == "hire" else worker.worker_ref
        )
        if (
            expected_learning_subject is None
            or inputs.learning.worker_or_candidate_ref != expected_learning_subject
        ):
            _add(
                findings,
                code="learning_subject_mismatch",
                gate="learning",
                status="fail",
                message=(
                    "Learning and certification evidence must belong to the exact "
                    "evaluated candidate or worker."
                ),
                subject_ref=inputs.learning.learning_ref,
            )
        for requirement in (
            inputs.learning.requirements
            if inputs.learning.worker_or_candidate_ref == expected_learning_subject
            else ()
        ):
            expired_by_date = (
                requirement.expires_at is not None
                and _parsed_timestamp(requirement.expires_at) < analysis_at
            )
            if requirement.status in {"expired", "missing"} or expired_by_date:
                _add(
                    findings,
                    code=f"certification_not_current:{requirement.certification_ref}",
                    gate="learning",
                    status="fail",
                    message="A required certification is missing or expired.",
                    subject_ref=requirement.certification_ref,
                )
            elif requirement.status == "pending":
                _add(
                    findings,
                    code=f"certification_pending:{requirement.certification_ref}",
                    gate="learning",
                    status="indeterminate",
                    message="A required certification is pending.",
                    subject_ref=requirement.certification_ref,
                )
            elif requirement.status == "waived":
                _add(
                    findings,
                    code=f"certification_waived:{requirement.certification_ref}",
                    gate="learning",
                    status=(
                        "review"
                        if inputs.policy.allow_certification_waiver_review
                        else "fail"
                    ),
                    message="A required certification was waived.",
                    subject_ref=requirement.certification_ref,
                )
    elif (
        inputs.target == "hire"
        and inputs.policy.require_current_certifications_for_hire
    ):
        _add(
            findings,
            code="learning_evidence_missing",
            gate="learning",
            status="indeterminate",
            message="Hire readiness requires learning/certification evidence.",
            subject_ref=worker.candidate_ref,
        )

    if inputs.target == "offboarding":
        if worker.stage not in {"suspended", "terminated"} or worker.worker_ref is None:
            _add(
                findings,
                code="worker_not_in_offboarding_state",
                gate="worker",
                status="fail",
                message="Offboarding requires a suspended/terminated worker reference.",
                subject_ref=worker.person_ref,
            )
        offboarding = inputs.offboarding
        if offboarding is None:
            _add(
                findings,
                code="offboarding_packet_missing",
                gate="offboarding",
                status="indeterminate",
                message="Offboarding packet is missing.",
                subject_ref=worker.worker_ref,
            )
        elif offboarding.worker_ref != worker.worker_ref:
            _add(
                findings,
                code="offboarding_worker_mismatch",
                gate="offboarding",
                status="fail",
                message="Offboarding packet belongs to another worker.",
                subject_ref=offboarding.offboarding_ref,
            )
        else:
            if offboarding.termination_approval_ref is None:
                _add(
                    findings,
                    code="termination_approval_missing",
                    gate="offboarding",
                    status="fail",
                    message="Termination approval reference is missing.",
                    subject_ref=offboarding.offboarding_ref,
                )
            if inputs.policy.require_final_pay_approval and (
                offboarding.final_pay not in {"approved", "paid"}
                or offboarding.final_pay_approval_ref is None
            ):
                _add(
                    findings,
                    code="final_pay_not_approved",
                    gate="offboarding",
                    status=(
                        "indeterminate"
                        if offboarding.final_pay == "unknown"
                        else "fail"
                    ),
                    message="Final pay is not approved or paid with evidence.",
                    subject_ref=offboarding.offboarding_ref,
                )
            if offboarding.assets not in {"returned", "waived"}:
                _add(
                    findings,
                    code="assets_not_resolved",
                    gate="offboarding",
                    status=(
                        "indeterminate" if offboarding.assets == "unknown" else "fail"
                    ),
                    message="Assigned assets are not returned or waived.",
                    subject_ref=offboarding.offboarding_ref,
                )
            if offboarding.knowledge_transfer == "pending":
                _add(
                    findings,
                    code="knowledge_transfer_pending",
                    gate="offboarding",
                    status="review",
                    message="Knowledge transfer remains pending.",
                    subject_ref=offboarding.offboarding_ref,
                )
        if inputs.policy.require_all_access_revoked and not inputs.access_accounts:
            _add(
                findings,
                code="access_inventory_missing",
                gate="access",
                status="indeterminate",
                message="No authoritative access-account inventory was supplied.",
                subject_ref=worker.worker_ref,
            )
        for account in inputs.access_accounts:
            if account.status == "active":
                _add(
                    findings,
                    code=f"access_still_active:{account.system_ref}",
                    gate="access",
                    status="fail",
                    message="A worker account remains active.",
                    subject_ref=account.account_ref,
                )
            elif account.status in {"disabled", "unknown"}:
                _add(
                    findings,
                    code=f"access_revocation_unverified:{account.system_ref}",
                    gate="access",
                    status="indeterminate",
                    message="Access revocation lacks a verified revocation receipt.",
                    subject_ref=account.account_ref,
                )

    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                _GATE_ORDER.index(item.gate),
                item.subject_ref or "",
                item.code,
            ),
        )
    )
    gates = tuple(
        PeopleGateResult(
            gate=gate,
            status=_status([item for item in ordered_findings if item.gate == gate]),
            finding_codes=tuple(
                item.code for item in ordered_findings if item.gate == gate
            ),
        )
        for gate in _GATE_ORDER
    )
    statuses = {gate.status for gate in gates}
    if "fail" in statuses:
        disposition: Disposition = "blocked"
    elif "indeterminate" in statuses:
        disposition = "indeterminate"
    elif "review" in statuses:
        disposition = "manual_review_required"
    else:
        disposition = {
            "hire": "ready_for_hire_approval",
            "payroll": "ready_for_payroll_export",
            "offboarding": "ready_for_offboarding_completion",
        }[inputs.target]

    assurance_grade = min(
        (item.verification_grade for item in evidence),
        key=lambda grade: _GRADE_RANK[grade],
    )
    snapshots = _all_snapshots(inputs)
    source_digests = {
        key: people_snapshot_digest(snapshot)
        if snapshot is not None
        else _stable_digest(None)
        for key, snapshot in snapshots.items()
    }
    source_digests["access_accounts"] = _stable_digest(
        [item.to_dict() for item in inputs.access_accounts]
    )
    source_digests["policy"] = people_snapshot_digest(inputs.policy)
    result = PeopleControlResult(
        evaluation_ref=inputs.evaluation_ref,
        target=inputs.target,
        analysis_as_of=inputs.analysis_as_of,
        proposed_disposition=disposition,
        assurance_grade=assurance_grade,
        gates=gates,
        findings=ordered_findings,
        source_snapshot_digests=source_digests,
        evidence_refs=tuple(sorted(evidence_names)),
    )
    return result


def _example_evidence(ref: str, character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": "normalized_people_snapshot",
        "issuer_ref": "spring-people-authority",
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "restricted",
        "retention_policy": "people-seven-years",
        "jurisdiction": "US",
    }


class EvaluateWorkerLifecycleControlsPrimitive(
    BusinessProcessPrimitive[PeopleControlInput, PeopleControlResult]
):
    primitive_ref = "people.evaluate_worker_lifecycle_controls"
    version = "1.0.0"
    title = "Evaluate worker lifecycle controls"
    description = (
        "Evaluate evidence-bound hiring, payroll-readiness, or offboarding controls "
        "without changing HR, payroll, scheduling, learning, or identity systems."
    )
    input_model = PeopleControlInput
    output_model = PeopleControlResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "evaluation_ref": "people-evaluation-1042",
        "target": "hire",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "worker": {
            "person_ref": "person-ada",
            "candidate_ref": "candidate-ada",
            "position_ref": "position-finance-analyst",
            "manager_ref": "manager-grace",
            "company_ref": "company-example",
            "location_ref": "location-new-york",
            "employment_type": "employee",
            "stage": "prehire",
            "identity_verification": "verified",
            "right_to_work": "verified",
            "start_date": "2026-09-01",
            "evidence_refs": [_example_evidence("worker-evidence", "a")],
        },
        "workforce_plan": {
            "plan_ref": "workforce-plan-2026",
            "position_ref": "position-finance-analyst",
            "position_status": "approved_open",
            "headcount_available": True,
            "budget_ref": "budget-people-2026",
            "budget_approved": True,
            "required_location_ref": "location-new-york",
            "evidence_refs": [_example_evidence("workforce-evidence", "b")],
        },
        "recruiting": {
            "recruiting_ref": "recruiting-ada",
            "candidate_ref": "candidate-ada",
            "stage": "offer_accepted",
            "scorecard_complete": True,
            "conflict_check": "clear",
            "background_check": "clear",
            "offer_ref": "offer-ada",
            "offer_approval_ref": "approval-offer-ada",
            "evidence_refs": [_example_evidence("recruiting-evidence", "c")],
        },
        "learning": {
            "learning_ref": "learning-ada",
            "worker_or_candidate_ref": "candidate-ada",
            "requirements": [],
            "evidence_refs": [_example_evidence("learning-evidence", "d")],
        },
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = PEOPLE_CONTROL_OPERATION.to_dict()
        contract["capability_hints"] = [
            "hris.read_worker",
            "ats.read_candidate",
            "timekeeping.read_timecard",
            "payroll.read_worker",
            "lms.read_certifications",
            "iam.read_access_inventory",
        ]
        contract["capability_hints_are_dispatch_authority"] = False
        contract["effect_boundary"] = PeopleEffectBoundary().to_dict()
        contract["system_of_record_authority"] = "trusted_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PeopleControlInput,
    ) -> PrimitiveExecutionResult[PeopleControlResult]:
        del context
        output = evaluate_people_controls(inputs)
        evidence_refs = sorted(
            _all_evidence(inputs), key=lambda item: item.evidence_ref
        )
        receipt = PrimitiveOperationReceipt(
            spec=PEOPLE_CONTROL_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=people_snapshot_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[PeopleControlResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "People controls evaluated; the result proposes "
                f"{output.proposed_disposition} and grants no execution authority."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="people.worker_lifecycle_controls_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "target": output.target,
                        "proposed_disposition": output.proposed_disposition,
                        "finding_count": len(output.findings),
                        "live_systems_changed": False,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="people_control_result",
                    summary=(
                        "The SDK evaluated normalized people evidence without changing "
                        "employment, payroll, leave, learning, scheduling, or access."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "PEOPLE_CONTROL_INPUT_SCHEMA",
    "PEOPLE_CONTROL_RESULT_SCHEMA",
    "PEOPLE_CONTROL_OPERATION",
    "WORKER_LIFECYCLE_SNAPSHOT_SCHEMA",
    "AccessAccountSnapshot",
    "CertificationRequirement",
    "EvaluateWorkerLifecycleControlsPrimitive",
    "LearningSnapshot",
    "LeaveSnapshot",
    "OffboardingSnapshot",
    "PayrollIntegrationSnapshot",
    "PeopleControlInput",
    "PeopleControlPolicy",
    "PeopleControlResult",
    "PeopleEffectBoundary",
    "PeopleFinding",
    "PeopleGateResult",
    "PerformanceCompensationSnapshot",
    "RecruitingSnapshot",
    "ScheduleTimeSnapshot",
    "WorkerLifecycleSnapshot",
    "WorkforcePlanSnapshot",
    "evaluate_people_controls",
    "people_snapshot_digest",
]
