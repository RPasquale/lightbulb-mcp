"""Bounded, immutable maintenance work-order transition proposals.

The models in this module validate evidence-bound maintenance facts and
materialize a deterministic candidate snapshot only.  They do not isolate an
asset, dispatch labor, reserve or move inventory, execute maintenance, return
an asset to service, close a work order, persist state, or call a provider.
Spring remains authoritative for authenticated scope, RBAC, approvals,
persistence, audit, and write admission; governed EAM/CMMS, inventory, labor,
and asset systems remain authoritative for live facts and effects.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
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
)


MAINTENANCE_SCOPE_SCHEMA = "lightbulb.maintenance_work_order_scope.v1"
MAINTENANCE_EVIDENCE_SCHEMA = "lightbulb.maintenance_work_order_evidence.v1"
MAINTENANCE_TRANSITION_SCHEMA = "lightbulb.maintenance_work_order_transition.v1"
MAINTENANCE_SNAPSHOT_SCHEMA = "lightbulb.maintenance_work_order_snapshot.v1"
MAINTENANCE_REQUEST_SCHEMA = "lightbulb.maintenance_work_order_request.v1"
MAINTENANCE_PROPOSAL_SCHEMA = "lightbulb.maintenance_work_order_proposal.v1"
MAINTENANCE_RESULT_SCHEMA = "lightbulb.maintenance_work_order_result.v1"
GENESIS_MAINTENANCE_DIGEST = "0" * 64
MAX_MAINTENANCE_TRANSITIONS = 7
MAX_EVIDENCE_PER_TRANSITION = 4
MAX_CHECKLIST_ITEMS = 100
MAX_RESOURCES = 100
MAX_METER = Decimal("1000000000000000")
MAX_QUANTITY = Decimal("1000000000")
MAX_MONEY = Decimal("1000000000000.00")
MAX_EVIDENCE_AGE = timedelta(days=7)
MIN_RETENTION_YEARS = 7


MaintenanceState = Literal[
    "request_diagnosed",
    "planned",
    "authorized_and_scheduled",
    "execution_recorded",
    "independently_inspected",
    "return_to_service_candidate",
    "close_candidate",
]
MaintenanceStrategy = Literal["preventive", "corrective", "predictive", "emergency"]
MaintenancePriority = Literal["p1", "p2", "p3", "p4", "p5"]


class MaintenanceWorkOrderError(ValueError):
    """Stable, fail-closed lifecycle error used by the primitive wrapper."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


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


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Decimal):
        return format(value, "f")
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
    target_year = observed.year + MIN_RETENTION_YEARS
    try:
        return observed.replace(year=target_year)
    except ValueError:
        # A leap-day observation remains retained through the following March 1,
        # avoiding a shorter-than-seven-calendar-year custody promise.
        return observed.replace(year=target_year, month=3, day=1)


def _decimal(
    value: Any,
    *,
    name: str,
    maximum: Decimal,
    scale: int,
    allow_zero: bool = True,
) -> Decimal:
    if isinstance(value, (float, bool)) or not isinstance(value, (str, int, Decimal)):
        raise ValueError(f"{name} must be a decimal string, integer, or Decimal")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 64:
        raise ValueError(f"{name} must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError(f"{name} must be a finite decimal")
    if parsed < 0 or (not allow_zero and parsed == 0):
        raise ValueError(
            f"{name} must be {'nonnegative' if allow_zero else 'positive'}"
        )
    if parsed > maximum:
        raise ValueError(f"{name} exceeds the supported bound")
    if max(0, -parsed.as_tuple().exponent) > scale:
        raise ValueError(f"{name} supports at most {scale} fractional digits")
    if parsed == 0:
        return Decimal("0")
    with localcontext() as context:
        context.prec = 64
        return parsed.normalize(context=context)


def _money(value: Any, *, name: str, allow_zero: bool = True) -> Decimal:
    return _decimal(
        value,
        name=name,
        maximum=MAX_MONEY,
        scale=2,
        allow_zero=allow_zero,
    )


def _quantity(value: Any, *, name: str, allow_zero: bool = False) -> Decimal:
    return _decimal(
        value,
        name=name,
        maximum=MAX_QUANTITY,
        scale=6,
        allow_zero=allow_zero,
    )


def _meter(value: Any, *, name: str) -> Decimal:
    return _decimal(value, name=name, maximum=MAX_METER, scale=6)


def _money_product(quantity: Decimal, unit_cost: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 64
        context.rounding = ROUND_HALF_EVEN
        return (quantity * unit_cost).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_EVEN
        )


def _labor_cost(minutes: int, hourly_rate: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = 64
        context.rounding = ROUND_HALF_EVEN
        return (Decimal(minutes) * hourly_rate / Decimal(60)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_EVEN
        )


def _money_sum(values: Sequence[Decimal]) -> Decimal:
    with localcontext() as context:
        context.prec = 64
        return sum(values, Decimal("0"))


def _interval_minutes(start: str, end: str) -> Decimal:
    delta = _dt(end) - _dt(start)
    microseconds = (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000 + delta.microseconds
    with localcontext() as context:
        context.prec = 64
        return Decimal(microseconds) / Decimal(60_000_000)


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must be unique")


def _as_tuple(value: Any, *, name: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    return tuple(value)


class MaintenanceWorkOrderScope(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_scope.v1"] = Field(
        default=MAINTENANCE_SCOPE_SCHEMA, alias="schema"
    )
    tenant_ref: str = Field(min_length=1, max_length=160)
    company_ref: str = Field(min_length=1, max_length=160)
    project_ref: str = Field(min_length=1, max_length=160)
    project_id: UUID
    site_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    work_order_ref: str = Field(min_length=1, max_length=160)
    asset_system_ref: str = Field(min_length=1, max_length=160)
    jurisdiction_ref: str = Field(min_length=1, max_length=80)
    retention_policy_ref: str = Field(min_length=1, max_length=160)
    evidence_custodian_ref: str = Field(min_length=1, max_length=160)
    spring_authority_ref: str = Field(min_length=1, max_length=160)

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
        "site_ref",
        "asset_ref",
        "work_order_ref",
        "asset_system_ref",
        "jurisdiction_ref",
        "retention_policy_ref",
        "evidence_custodian_ref",
        "spring_authority_ref",
    )
    @classmethod
    def _exact_refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)


def maintenance_scope_digest(
    scope: MaintenanceWorkOrderScope | Mapping[str, Any],
) -> str:
    parsed = MaintenanceWorkOrderScope.model_validate(_jsonable(scope))
    return _stable_digest(parsed)


class MaintenanceEvidence(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_evidence.v1"] = Field(
        default=MAINTENANCE_EVIDENCE_SCHEMA, alias="schema"
    )
    sequence: int = Field(
        ge=1, le=MAX_MAINTENANCE_TRANSITIONS * MAX_EVIDENCE_PER_TRANSITION
    )
    evidence_ref: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=80)
    issuer_ref: str = Field(min_length=1, max_length=200)
    custodian_ref: str = Field(min_length=1, max_length=200)
    subject_ref: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    effective_at: str
    verification_grade: PrimitiveEvidenceVerificationGrade
    classification: PrimitiveEvidenceClassification
    retention_policy: str = Field(min_length=1, max_length=160)
    jurisdiction: str = Field(min_length=1, max_length=80)
    retained_until: str
    single_use: Literal[True] = True
    causal_revision: int = Field(ge=0, le=MAX_MAINTENANCE_TRANSITIONS)
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
    def _exact_refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _canonical_times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("verification_grade", mode="before")
    @classmethod
    def _verification_grade(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
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
    def _chronology_and_lineage(self) -> "MaintenanceEvidence":
        if _dt(self.effective_at) > _dt(self.observed_at):
            raise ValueError("evidence effective_at cannot follow observed_at")
        if _dt(self.retained_until) < _retention_floor(self.observed_at):
            raise ValueError("evidence retention must cover at least seven years")
        if self.lineage_digest != maintenance_evidence_lineage_digest(self):
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


def maintenance_evidence_lineage_digest(
    evidence: MaintenanceEvidence | Mapping[str, Any],
) -> str:
    payload = _jsonable(evidence)
    if not isinstance(payload, Mapping):
        raise ValueError("evidence must be a mapping")
    content = dict(payload)
    content.pop("lineage_digest", None)
    return _stable_digest(content)


class MaintenanceChecklistItem(_StrictModel):
    sequence: int = Field(ge=1, le=MAX_CHECKLIST_ITEMS)
    task_ref: str = Field(min_length=1, max_length=160)
    instruction_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_competency_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    requires_shutdown: bool
    requires_loto: bool

    @field_validator("task_ref")
    @classmethod
    def _task_ref(cls, value: str) -> str:
        return _visible(value, name="task_ref")

    @field_validator("required_competency_refs", mode="before")
    @classmethod
    def _competencies(cls, value: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name="required_competency_refs")
        normalized = tuple(
            _visible(item, name="required_competency_ref") for item in value
        )
        _unique(normalized, label="checklist competency references")
        return normalized

    @model_validator(mode="after")
    def _loto_requires_shutdown(self) -> "MaintenanceChecklistItem":
        if self.requires_loto and not self.requires_shutdown:
            raise ValueError("a LOTO checklist task must require asset shutdown")
        return self


class PartReservation(_StrictModel):
    reservation_ref: str = Field(min_length=1, max_length=160)
    part_ref: str = Field(min_length=1, max_length=160)
    quantity: Decimal
    unit_of_measure: str = Field(min_length=1, max_length=32)
    unit_cost: Decimal
    extended_cost: Decimal
    lot_tracking_required: bool
    serial_tracking_required: bool
    authorized_lot_refs: tuple[str, ...] = Field(default=(), max_length=100)
    authorized_serial_refs: tuple[str, ...] = Field(default=(), max_length=100)
    custody_from_ref: str = Field(min_length=1, max_length=160)

    @field_validator(
        "reservation_ref", "part_ref", "unit_of_measure", "custody_from_ref"
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, name="part reservation quantity")

    @field_validator("unit_cost", "extended_cost", mode="before")
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator("authorized_lot_refs", "authorized_serial_refs", mode="before")
    @classmethod
    def _genealogy_arrays(cls, value: Any, info: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name=info.field_name)
        normalized = tuple(_visible(item, name=info.field_name) for item in value)
        _unique(normalized, label=info.field_name)
        return normalized

    @model_validator(mode="after")
    def _math_and_tracking(self) -> "PartReservation":
        if self.extended_cost != _money_product(self.quantity, self.unit_cost):
            raise ValueError("part reservation extended_cost does not match quantity")
        if (
            self.serial_tracking_required
            and self.quantity != self.quantity.to_integral()
        ):
            raise ValueError("serial-tracked reservation quantity must be an integer")
        if self.lot_tracking_required != bool(self.authorized_lot_refs):
            raise ValueError(
                "lot tracking requirement must match authorized lot genealogy"
            )
        if self.serial_tracking_required:
            if len(self.authorized_serial_refs) != int(self.quantity):
                raise ValueError(
                    "serial-tracked reservation requires one authorized serial per unit"
                )
        elif self.authorized_serial_refs:
            raise ValueError("untracked reservation cannot authorize serial genealogy")
        return self


class LaborReservation(_StrictModel):
    reservation_ref: str = Field(min_length=1, max_length=160)
    technician_ref: str = Field(min_length=1, max_length=160)
    competency_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    planned_minutes: int = Field(gt=0, le=100_000)
    hourly_rate: Decimal
    planned_cost: Decimal

    @field_validator("reservation_ref", "technician_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("competency_refs", mode="before")
    @classmethod
    def _competencies(cls, value: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name="competency_refs")
        normalized = tuple(_visible(item, name="competency_ref") for item in value)
        _unique(normalized, label="labor competency references")
        return normalized

    @field_validator("hourly_rate", "planned_cost", mode="before")
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @model_validator(mode="after")
    def _math(self) -> "LaborReservation":
        if self.planned_cost != _labor_cost(self.planned_minutes, self.hourly_rate):
            raise ValueError("labor reservation planned_cost does not match minutes")
        return self


class ToolReservation(_StrictModel):
    reservation_ref: str = Field(min_length=1, max_length=160)
    tool_ref: str = Field(min_length=1, max_length=160)
    calibration_due_at: str

    @field_validator("reservation_ref", "tool_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("calibration_due_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="calibration_due_at")


class ChecklistCompletion(_StrictModel):
    sequence: int = Field(ge=1, le=MAX_CHECKLIST_ITEMS)
    task_ref: str = Field(min_length=1, max_length=160)
    completed_by_ref: str = Field(min_length=1, max_length=160)
    completed_at: str
    actual_minutes: int = Field(gt=0, le=100_000)
    status: Literal["completed"] = "completed"

    @field_validator("task_ref", "completed_by_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("completed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="completed_at")


class LaborEntry(_StrictModel):
    technician_ref: str = Field(min_length=1, max_length=160)
    minutes: int = Field(gt=0, le=100_000)
    hourly_rate: Decimal
    labor_cost: Decimal

    @field_validator("technician_ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        return _visible(value, name="technician_ref")

    @field_validator("hourly_rate", "labor_cost", mode="before")
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @model_validator(mode="after")
    def _math(self) -> "LaborEntry":
        if self.labor_cost != _labor_cost(self.minutes, self.hourly_rate):
            raise ValueError("labor entry cost does not match minutes and rate")
        return self


class PartUsage(_StrictModel):
    reservation_ref: str = Field(min_length=1, max_length=160)
    part_ref: str = Field(min_length=1, max_length=160)
    quantity: Decimal
    unit_of_measure: str = Field(min_length=1, max_length=32)
    unit_cost: Decimal
    extended_cost: Decimal
    lot_ref: str | None = Field(default=None, min_length=1, max_length=160)
    serial_refs: tuple[str, ...] = Field(default=(), max_length=100)
    custody_from_ref: str = Field(min_length=1, max_length=160)
    custody_to_ref: str = Field(min_length=1, max_length=160)
    issued_at: str
    installed_at: str

    @field_validator(
        "reservation_ref",
        "part_ref",
        "unit_of_measure",
        "lot_ref",
        "custody_from_ref",
        "custody_to_ref",
    )
    @classmethod
    def _refs(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _visible(value, name=info.field_name)

    @field_validator("serial_refs", mode="before")
    @classmethod
    def _serials(cls, value: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name="serial_refs")
        normalized = tuple(_visible(item, name="serial_ref") for item in value)
        _unique(normalized, label="serial references")
        return normalized

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity(cls, value: Any) -> Decimal:
        return _quantity(value, name="part usage quantity")

    @field_validator("unit_cost", "extended_cost", mode="before")
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator("issued_at", "installed_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _math_and_custody(self) -> "PartUsage":
        if self.extended_cost != _money_product(self.quantity, self.unit_cost):
            raise ValueError("part usage extended_cost does not match quantity")
        if self.custody_from_ref == self.custody_to_ref:
            raise ValueError("part custody must identify a real transfer")
        if _dt(self.installed_at) < _dt(self.issued_at):
            raise ValueError("part installation cannot precede issue")
        return self


class InspectionTest(_StrictModel):
    test_ref: str = Field(min_length=1, max_length=160)
    method_ref: str = Field(min_length=1, max_length=160)
    measured_value: Decimal
    minimum_acceptable: Decimal
    maximum_acceptable: Decimal
    unit_of_measure: str = Field(min_length=1, max_length=32)
    passed: Literal[True] = True

    @field_validator("test_ref", "method_ref", "unit_of_measure")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator(
        "measured_value", "minimum_acceptable", "maximum_acceptable", mode="before"
    )
    @classmethod
    def _values(cls, value: Any, info: Any) -> Decimal:
        return _decimal(
            value,
            name=info.field_name,
            maximum=MAX_METER,
            scale=6,
        )

    @model_validator(mode="after")
    def _within_acceptance(self) -> "InspectionTest":
        if self.minimum_acceptable > self.maximum_acceptable:
            raise ValueError("inspection acceptance range is inverted")
        if (
            not self.minimum_acceptable
            <= self.measured_value
            <= self.maximum_acceptable
        ):
            raise ValueError("passed inspection value is outside its acceptance range")
        return self


class _Command(_StrictModel):
    kind: str

    @field_validator("kind")
    @classmethod
    def _kind(cls, value: str) -> str:
        return _visible(value, name="kind")


class RecordWorkRequestCommand(_Command):
    kind: Literal["record_request_and_diagnosis"] = "record_request_and_diagnosis"
    request_ref: str = Field(min_length=1, max_length=160)
    requested_by_ref: str = Field(min_length=1, max_length=160)
    diagnosed_by_ref: str = Field(min_length=1, max_length=160)
    requested_at: str
    diagnosed_at: str
    symptom_code: str = Field(min_length=1, max_length=80)
    failure_mode_ref: str = Field(min_length=1, max_length=160)
    affected_component_ref: str = Field(min_length=1, max_length=160)
    production_impact: Literal["none", "degraded", "stopped", "safety_critical"]
    failure_severity: int = Field(ge=1, le=5)
    meter_name: str = Field(min_length=1, max_length=80)
    meter_reading: Decimal
    meter_unit: str = Field(min_length=1, max_length=32)

    @field_validator(
        "request_ref",
        "requested_by_ref",
        "diagnosed_by_ref",
        "symptom_code",
        "failure_mode_ref",
        "affected_component_ref",
        "meter_name",
        "meter_unit",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("requested_at", "diagnosed_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("meter_reading", mode="before")
    @classmethod
    def _meter(cls, value: Any) -> Decimal:
        return _meter(value, name="meter_reading")

    @model_validator(mode="after")
    def _chronology(self) -> "RecordWorkRequestCommand":
        if _dt(self.diagnosed_at) < _dt(self.requested_at):
            raise ValueError("diagnosis cannot precede work request")
        return self


class PlanMaintenanceCommand(_Command):
    kind: Literal["plan_work"] = "plan_work"
    plan_ref: str = Field(min_length=1, max_length=160)
    planner_ref: str = Field(min_length=1, max_length=160)
    planned_at: str
    strategy: MaintenanceStrategy
    priority: MaintenancePriority
    risk_likelihood: int = Field(ge=1, le=5)
    risk_severity: int = Field(ge=1, le=5)
    risk_detectability: int = Field(ge=1, le=5)
    risk_score: int = Field(ge=1, le=125)
    hazard_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    loto_required: bool
    isolation_point_refs: tuple[str, ...] = Field(default=(), max_length=20)
    permit_required: bool
    required_permit_refs: tuple[str, ...] = Field(default=(), max_length=20)
    required_competency_refs: tuple[str, ...] = Field(min_length=1, max_length=20)
    checklist: tuple[MaintenanceChecklistItem, ...] = Field(
        min_length=1, max_length=MAX_CHECKLIST_ITEMS
    )
    planned_window_start: str
    planned_window_end: str

    @field_validator("plan_ref", "planner_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator(
        "hazard_refs",
        "isolation_point_refs",
        "required_permit_refs",
        "required_competency_refs",
        mode="before",
    )
    @classmethod
    def _ref_lists(cls, value: Any, info: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name=info.field_name)
        normalized = tuple(_visible(item, name=info.field_name) for item in value)
        _unique(normalized, label=info.field_name)
        return normalized

    @field_validator("planned_at", "planned_window_start", "planned_window_end")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("checklist", mode="before")
    @classmethod
    def _checklist_array(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="checklist")

    @model_validator(mode="after")
    def _plan_is_complete(self) -> "PlanMaintenanceCommand":
        if self.risk_score != (
            self.risk_likelihood * self.risk_severity * self.risk_detectability
        ):
            raise ValueError(
                "risk_score must equal likelihood * severity * detectability"
            )
        if self.strategy == "emergency" and self.priority != "p1":
            raise ValueError("emergency maintenance must use priority p1")
        if self.loto_required != bool(self.isolation_point_refs):
            raise ValueError("LOTO requirement must match declared isolation points")
        if self.permit_required != bool(self.required_permit_refs):
            raise ValueError("permit requirement must match required permits")
        if _dt(self.planned_window_end) <= _dt(self.planned_window_start):
            raise ValueError("planned maintenance window must have positive duration")
        sequences = [item.sequence for item in self.checklist]
        if sequences != list(range(1, len(self.checklist) + 1)):
            raise ValueError("maintenance checklist must be exact and contiguous")
        _unique([item.task_ref for item in self.checklist], label="checklist task refs")
        plan_competencies = set(self.required_competency_refs)
        if any(
            not set(item.required_competency_refs).issubset(plan_competencies)
            for item in self.checklist
        ):
            raise ValueError("checklist competency is missing from the safety plan")
        if (
            any(item.requires_loto for item in self.checklist)
            and not self.loto_required
        ):
            raise ValueError("a LOTO checklist task requires a LOTO plan")
        if self.loto_required and not any(
            item.requires_loto for item in self.checklist
        ):
            raise ValueError("a LOTO plan requires an explicit LOTO checklist task")
        return self


class AuthorizeAndScheduleCommand(_Command):
    kind: Literal["authorize_and_schedule"] = "authorize_and_schedule"
    authorization_ref: str = Field(min_length=1, max_length=160)
    safety_approver_ref: str = Field(min_length=1, max_length=160)
    authorized_at: str
    approved_plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    loto_plan_verified: Literal[True] = True
    permit_plan_verified: Literal[True] = True
    competency_requirements_verified: Literal[True] = True
    risk_controls_approved: Literal[True] = True
    schedule_start: str
    schedule_end: str
    part_reservations: tuple[PartReservation, ...] = Field(
        default=(), max_length=MAX_RESOURCES
    )
    labor_reservations: tuple[LaborReservation, ...] = Field(
        min_length=1, max_length=MAX_RESOURCES
    )
    tool_reservations: tuple[ToolReservation, ...] = Field(
        default=(), max_length=MAX_RESOURCES
    )
    estimated_parts_cost: Decimal
    estimated_labor_cost: Decimal
    estimated_total_cost: Decimal

    @field_validator("authorization_ref", "safety_approver_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("authorized_at", "schedule_start", "schedule_end")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator(
        "estimated_parts_cost",
        "estimated_labor_cost",
        "estimated_total_cost",
        mode="before",
    )
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator(
        "part_reservations",
        "labor_reservations",
        "tool_reservations",
        mode="before",
    )
    @classmethod
    def _resource_arrays(cls, value: Any, info: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name=info.field_name)

    @model_validator(mode="after")
    def _resources_and_math(self) -> "AuthorizeAndScheduleCommand":
        if _dt(self.schedule_end) <= _dt(self.schedule_start):
            raise ValueError("authorized schedule must have positive duration")
        part_cost = _money_sum([item.extended_cost for item in self.part_reservations])
        labor_cost = _money_sum([item.planned_cost for item in self.labor_reservations])
        if self.estimated_parts_cost != part_cost:
            raise ValueError("estimated_parts_cost does not match reservations")
        if self.estimated_labor_cost != labor_cost:
            raise ValueError("estimated_labor_cost does not match reservations")
        if self.estimated_total_cost != _money_sum([part_cost, labor_cost]):
            raise ValueError("estimated_total_cost does not match parts plus labor")
        refs = [
            *(item.reservation_ref for item in self.part_reservations),
            *(item.reservation_ref for item in self.labor_reservations),
            *(item.reservation_ref for item in self.tool_reservations),
        ]
        _unique(refs, label="resource reservation refs")
        _unique(
            [item.part_ref for item in self.part_reservations],
            label="reserved part refs",
        )
        _unique(
            [item.technician_ref for item in self.labor_reservations],
            label="reserved technician refs",
        )
        _unique(
            [item.tool_ref for item in self.tool_reservations],
            label="reserved tool refs",
        )
        schedule_minutes = _interval_minutes(self.schedule_start, self.schedule_end)
        if any(
            Decimal(item.planned_minutes) > schedule_minutes
            for item in self.labor_reservations
        ):
            raise ValueError(
                "labor reservation minutes exceed the authorized schedule capacity"
            )
        return self


class RecordMaintenanceExecutionCommand(_Command):
    kind: Literal["record_execution"] = "record_execution"
    execution_ref: str = Field(min_length=1, max_length=160)
    started_at: str
    completed_at: str
    checklist_results: tuple[ChecklistCompletion, ...] = Field(
        min_length=1, max_length=MAX_CHECKLIST_ITEMS
    )
    labor_entries: tuple[LaborEntry, ...] = Field(
        min_length=1, max_length=MAX_RESOURCES
    )
    parts_used: tuple[PartUsage, ...] = Field(default=(), max_length=MAX_RESOURCES)
    meter_name: str = Field(min_length=1, max_length=80)
    meter_unit: str = Field(min_length=1, max_length=32)
    meter_before: Decimal
    meter_after: Decimal
    meter_delta: Decimal
    actual_labor_cost: Decimal
    actual_parts_cost: Decimal
    actual_total_cost: Decimal

    @field_validator("execution_ref", "meter_name", "meter_unit")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("meter_before", "meter_after", "meter_delta", mode="before")
    @classmethod
    def _meters(cls, value: Any, info: Any) -> Decimal:
        return _meter(value, name=info.field_name)

    @field_validator(
        "actual_labor_cost", "actual_parts_cost", "actual_total_cost", mode="before"
    )
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator("checklist_results", "labor_entries", "parts_used", mode="before")
    @classmethod
    def _execution_arrays(cls, value: Any, info: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name=info.field_name)

    @model_validator(mode="after")
    def _execution_math(self) -> "RecordMaintenanceExecutionCommand":
        if _dt(self.completed_at) <= _dt(self.started_at):
            raise ValueError("maintenance execution must have positive duration")
        if self.meter_after < self.meter_before:
            raise ValueError("asset meter cannot move backwards")
        with localcontext() as context:
            context.prec = 64
            expected_meter_delta = self.meter_after - self.meter_before
        if self.meter_delta != expected_meter_delta:
            raise ValueError("meter_delta does not match before and after readings")
        labor_cost = _money_sum([entry.labor_cost for entry in self.labor_entries])
        part_cost = _money_sum([entry.extended_cost for entry in self.parts_used])
        if self.actual_labor_cost != labor_cost:
            raise ValueError("actual_labor_cost does not match labor entries")
        if self.actual_parts_cost != part_cost:
            raise ValueError("actual_parts_cost does not match parts used")
        if self.actual_total_cost != _money_sum([labor_cost, part_cost]):
            raise ValueError("actual_total_cost does not match parts plus labor")
        _unique(
            [entry.technician_ref for entry in self.labor_entries],
            label="labor technician refs",
        )
        serials = [serial for usage in self.parts_used for serial in usage.serial_refs]
        _unique(serials, label="consumed serial refs")
        return self


class RecordIndependentInspectionCommand(_Command):
    kind: Literal["record_independent_inspection"] = "record_independent_inspection"
    inspection_ref: str = Field(min_length=1, max_length=160)
    inspector_ref: str = Field(min_length=1, max_length=160)
    inspected_at: str
    execution_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    tests: tuple[InspectionTest, ...] = Field(min_length=1, max_length=50)
    checklist_complete_verified: Literal[True] = True
    no_unresolved_safety_condition: Literal[True] = True
    open_deficiency_refs: tuple[()] = ()

    @field_validator("inspection_ref", "inspector_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("inspected_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="inspected_at")

    @field_validator("tests", "open_deficiency_refs", mode="before")
    @classmethod
    def _inspection_arrays(cls, value: Any, info: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name=info.field_name)

    @model_validator(mode="after")
    def _tests_are_unique(self) -> "RecordIndependentInspectionCommand":
        _unique([item.test_ref for item in self.tests], label="inspection test refs")
        return self


class ProposeReturnToServiceCommand(_Command):
    kind: Literal["propose_return_to_service"] = "propose_return_to_service"
    authorization_ref: str = Field(min_length=1, max_length=160)
    authorized_by_ref: str = Field(min_length=1, max_length=160)
    authorized_at: str
    inspection_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    safe_to_return_to_service: Literal[True] = True
    loto_release_reviewed: Literal[True] = True
    permit_closeout_reviewed: Literal[True] = True
    open_deficiency_refs: tuple[()] = ()
    operating_condition_refs: tuple[str, ...] = Field(min_length=1, max_length=20)

    @field_validator("authorization_ref", "authorized_by_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("operating_condition_refs", mode="before")
    @classmethod
    def _conditions(cls, value: Any) -> tuple[str, ...]:
        value = _as_tuple(value, name="operating_condition_refs")
        normalized = tuple(
            _visible(item, name="operating_condition_ref") for item in value
        )
        _unique(normalized, label="operating condition refs")
        return normalized

    @field_validator("authorized_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _utc(value, name="authorized_at")

    @field_validator("open_deficiency_refs", mode="before")
    @classmethod
    def _open_deficiencies(cls, value: Any) -> tuple[Any, ...]:
        return _as_tuple(value, name="open_deficiency_refs")


class ProposeMaintenanceCloseCommand(_Command):
    kind: Literal["propose_close"] = "propose_close"
    close_ref: str = Field(min_length=1, max_length=160)
    closed_by_ref: str = Field(min_length=1, max_length=160)
    closed_at: str
    return_authorization_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_code: str = Field(min_length=1, max_length=80)
    root_cause_code: str = Field(min_length=1, max_length=80)
    actual_labor_cost: Decimal
    actual_parts_cost: Decimal
    actual_total_cost: Decimal
    effectiveness_status: Literal["verified", "review_scheduled"]
    effectiveness_at: str
    effectiveness_evidence_ref: str = Field(min_length=1, max_length=160)
    next_maintenance_due_at: str
    next_maintenance_meter: Decimal

    @field_validator(
        "close_ref",
        "closed_by_ref",
        "failure_code",
        "root_cause_code",
        "effectiveness_evidence_ref",
    )
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("closed_at", "effectiveness_at", "next_maintenance_due_at")
    @classmethod
    def _times(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator(
        "actual_labor_cost", "actual_parts_cost", "actual_total_cost", mode="before"
    )
    @classmethod
    def _costs(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator("next_maintenance_meter", mode="before")
    @classmethod
    def _meter(cls, value: Any) -> Decimal:
        return _meter(value, name="next_maintenance_meter")

    @model_validator(mode="after")
    def _close_math(self) -> "ProposeMaintenanceCloseCommand":
        if self.actual_total_cost != _money_sum(
            [self.actual_labor_cost, self.actual_parts_cost]
        ):
            raise ValueError("close cost does not match labor plus parts")
        if _dt(self.effectiveness_at) < _dt(self.closed_at):
            raise ValueError("effectiveness evidence cannot predate close")
        if _dt(self.next_maintenance_due_at) <= _dt(self.closed_at):
            raise ValueError("next maintenance must be scheduled after close")
        return self


MaintenanceCommand = Annotated[
    Union[
        RecordWorkRequestCommand,
        PlanMaintenanceCommand,
        AuthorizeAndScheduleCommand,
        RecordMaintenanceExecutionCommand,
        RecordIndependentInspectionCommand,
        ProposeReturnToServiceCommand,
        ProposeMaintenanceCloseCommand,
    ],
    Field(discriminator="kind"),
]
_COMMAND_ADAPTER = TypeAdapter(MaintenanceCommand)


def maintenance_command_digest(command: MaintenanceCommand | Mapping[str, Any]) -> str:
    parsed = _COMMAND_ADAPTER.validate_python(_jsonable(command), strict=True)
    return _stable_digest(parsed)


def _command_actor_refs(command: MaintenanceCommand) -> tuple[str, ...]:
    if isinstance(command, RecordWorkRequestCommand):
        return (command.requested_by_ref, command.diagnosed_by_ref)
    if isinstance(command, PlanMaintenanceCommand):
        return (command.planner_ref,)
    if isinstance(command, AuthorizeAndScheduleCommand):
        return (command.safety_approver_ref,)
    if isinstance(command, RecordMaintenanceExecutionCommand):
        return tuple(entry.technician_ref for entry in command.labor_entries)
    if isinstance(command, RecordIndependentInspectionCommand):
        return (command.inspector_ref,)
    if isinstance(command, ProposeReturnToServiceCommand):
        return (command.authorized_by_ref,)
    return (command.closed_by_ref,)


def _command_occurred_at(command: MaintenanceCommand) -> str:
    if isinstance(command, RecordWorkRequestCommand):
        return command.diagnosed_at
    if isinstance(command, PlanMaintenanceCommand):
        return command.planned_at
    if isinstance(command, AuthorizeAndScheduleCommand):
        return command.authorized_at
    if isinstance(command, RecordMaintenanceExecutionCommand):
        return command.completed_at
    if isinstance(command, RecordIndependentInspectionCommand):
        return command.inspected_at
    if isinstance(command, ProposeReturnToServiceCommand):
        return command.authorized_at
    return (
        command.effectiveness_at
        if command.effectiveness_status == "verified"
        else command.closed_at
    )


def _command_subject_ref(command: MaintenanceCommand) -> str:
    if isinstance(command, RecordWorkRequestCommand):
        return command.request_ref
    if isinstance(command, PlanMaintenanceCommand):
        return command.plan_ref
    if isinstance(command, AuthorizeAndScheduleCommand):
        return command.authorization_ref
    if isinstance(command, RecordMaintenanceExecutionCommand):
        return command.execution_ref
    if isinstance(command, RecordIndependentInspectionCommand):
        return command.inspection_ref
    if isinstance(command, ProposeReturnToServiceCommand):
        return command.authorization_ref
    return command.close_ref


_FACT_KIND: dict[str, str] = {
    "record_request_and_diagnosis": "maintenance_work_request_and_diagnosis",
    "plan_work": "maintenance_risk_and_work_plan",
    "authorize_and_schedule": "maintenance_safety_resource_authorization",
    "record_execution": "maintenance_execution_record",
    "record_independent_inspection": "maintenance_independent_inspection",
    "propose_return_to_service": "maintenance_return_to_service_authorization",
    "propose_close": "maintenance_close_effectiveness",
}


_STATE_FOR_KIND: dict[str, MaintenanceState] = {
    "record_request_and_diagnosis": "request_diagnosed",
    "plan_work": "planned",
    "authorize_and_schedule": "authorized_and_scheduled",
    "record_execution": "execution_recorded",
    "record_independent_inspection": "independently_inspected",
    "propose_return_to_service": "return_to_service_candidate",
    "propose_close": "close_candidate",
}


def _idempotency_digest_from_scope_digest(
    scope_digest: str,
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    return _stable_digest(
        {
            "scope_digest": scope_digest,
            "lifecycle_ref": lifecycle_ref,
            "idempotency_key": idempotency_key,
        }
    )


class MaintenanceTransitionRecord(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_transition.v1"] = Field(
        default=MAINTENANCE_TRANSITION_SCHEMA, alias="schema"
    )
    revision: int = Field(ge=1, le=MAX_MAINTENANCE_TRANSITIONS)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    prior_state: MaintenanceState | None = None
    prior_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: MaintenanceState
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: MaintenanceCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: tuple[MaintenanceEvidence, ...] = Field(
        min_length=2, max_length=MAX_EVIDENCE_PER_TRANSITION
    )
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative_scope_verified: Literal[False] = False
    authoritative_approval_recorded: Literal[False] = False
    work_order_persisted: Literal[False] = False
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
    def _record_is_content_bound(self) -> "MaintenanceTransitionRecord":
        if self.command_digest != maintenance_command_digest(self.command):
            raise ValueError("transition command_digest does not match command")
        if self.idempotency_digest != _idempotency_digest_from_scope_digest(
            self.scope_digest,
            self.lifecycle_ref,
            self.idempotency_key,
        ):
            raise ValueError(
                "transition idempotency_digest does not match its exact fence"
            )
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
            raise ValueError(
                "transition content_digest does not match transition content"
            )
        if self.state != _STATE_FOR_KIND[self.command.kind]:
            raise ValueError("transition state does not match command kind")
        if self.evidence_digest != _stable_digest(self.evidence):
            raise ValueError("transition evidence_digest does not match evidence")
        if self.evidence_lineage_digest != self.evidence[-1].lineage_digest:
            raise ValueError(
                "transition evidence lineage does not match final evidence"
            )
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
    scope: MaintenanceWorkOrderScope,
    lifecycle_ref: str,
    history: Sequence[MaintenanceTransitionRecord],
) -> dict[str, Any]:
    return {
        "schema": MAINTENANCE_SNAPSHOT_SCHEMA,
        "scope": scope,
        "scope_digest": maintenance_scope_digest(scope),
        "lifecycle_ref": lifecycle_ref,
        "revision": len(history),
        "state": history[-1].state,
        "history": tuple(history),
        "evidence_lineage_digest": history[-1].evidence_lineage_digest,
    }


def maintenance_snapshot_digest(
    snapshot: "MaintenanceWorkOrderSnapshot" | Mapping[str, Any],
) -> str:
    payload = _jsonable(snapshot)
    if not isinstance(payload, Mapping):
        raise ValueError("snapshot must be a mapping")
    content = dict(payload)
    content.pop("state_digest", None)
    return _stable_digest(content)


class MaintenanceWorkOrderSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_snapshot.v1"] = Field(
        default=MAINTENANCE_SNAPSHOT_SCHEMA, alias="schema"
    )
    scope: MaintenanceWorkOrderScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    revision: int = Field(ge=1, le=MAX_MAINTENANCE_TRANSITIONS)
    state: MaintenanceState
    history: tuple[MaintenanceTransitionRecord, ...] = Field(
        min_length=1, max_length=MAX_MAINTENANCE_TRANSITIONS
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
    def _snapshot_is_canonical(self) -> "MaintenanceWorkOrderSnapshot":
        if self.scope_digest != maintenance_scope_digest(self.scope):
            raise ValueError("snapshot scope_digest does not match exact scope")
        if self.revision != len(self.history):
            raise ValueError("snapshot revision must equal history length")
        transition_refs: list[str] = []
        idempotency_digests: list[str] = []
        evidence_refs: list[str] = []
        evidence_content_digests: list[str] = []
        evidence_lineage_digests: list[str] = []
        prior_state: MaintenanceState | None = None
        prior_state_digest = GENESIS_MAINTENANCE_DIGEST
        prior_lineage = GENESIS_MAINTENANCE_DIGEST
        for expected_revision, raw_record in enumerate(self.history, start=1):
            record = MaintenanceTransitionRecord.model_validate(
                raw_record.model_dump(mode="python", by_alias=True)
            )
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
            evidence_content_digests.extend(item.sha256 for item in record.evidence)
            evidence_lineage_digests.extend(
                item.lineage_digest for item in record.evidence
            )
            prefix = _snapshot_payload(
                scope=self.scope,
                lifecycle_ref=self.lifecycle_ref,
                history=self.history[:expected_revision],
            )
            prefix["state_digest"] = _stable_digest(prefix)
            prior_state = record.state
            prior_state_digest = prefix["state_digest"]
            prior_lineage = record.evidence_lineage_digest
        _unique(transition_refs, label="snapshot transition refs")
        _unique(idempotency_digests, label="snapshot idempotency digests")
        _unique(evidence_refs, label="snapshot evidence refs")
        _unique(evidence_content_digests, label="snapshot evidence content digests")
        _unique(evidence_lineage_digests, label="snapshot evidence lineage digests")
        if self.state != self.history[-1].state:
            raise ValueError("snapshot state does not match final transition")
        if self.evidence_lineage_digest != self.history[-1].evidence_lineage_digest:
            raise ValueError(
                "snapshot evidence lineage does not match final transition"
            )
        if self.state_digest != maintenance_snapshot_digest(self):
            raise ValueError("snapshot state_digest does not match snapshot content")
        _validate_history_semantics(self)
        return self


def maintenance_idempotency_digest(
    scope: MaintenanceWorkOrderScope | Mapping[str, Any],
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    return _idempotency_digest_from_scope_digest(
        maintenance_scope_digest(scope),
        _visible(lifecycle_ref, name="lifecycle_ref"),
        _visible(idempotency_key, name="idempotency_key"),
    )


def _transition_content_payload(
    *,
    scope_digest: str,
    lifecycle_ref: str,
    source_revision: int,
    source_state: MaintenanceState | None,
    source_state_digest: str,
    source_evidence_lineage_digest: str,
    transition_ref: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
    command_digest: str,
) -> dict[str, Any]:
    return {
        "schema": MAINTENANCE_REQUEST_SCHEMA,
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


class MaintenanceTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_request.v1"] = Field(
        default=MAINTENANCE_REQUEST_SCHEMA, alias="schema"
    )
    scope: MaintenanceWorkOrderScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    expected_revision: int = Field(ge=0, le=MAX_MAINTENANCE_TRANSITIONS)
    expected_state: MaintenanceState | None = None
    expected_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_snapshot: MaintenanceWorkOrderSnapshot | None = None
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: MaintenanceCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: tuple[MaintenanceEvidence, ...] = Field(
        min_length=2, max_length=MAX_EVIDENCE_PER_TRANSITION
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
    def _fences_and_digests(self) -> "MaintenanceTransitionRequest":
        if self.scope_digest != maintenance_scope_digest(self.scope):
            raise ValueError("request scope_digest does not match exact scope")
        if self.command_digest != maintenance_command_digest(self.command):
            raise ValueError("request command_digest does not match command")
        if self.idempotency_digest != maintenance_idempotency_digest(
            self.scope, self.lifecycle_ref, self.idempotency_key
        ):
            raise ValueError(
                "request idempotency_digest does not match its exact fence"
            )
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
                or self.expected_state_digest != GENESIS_MAINTENANCE_DIGEST
                or self.expected_evidence_lineage_digest != GENESIS_MAINTENANCE_DIGEST
            ):
                raise ValueError("revision zero must use the exact genesis fence")
        else:
            snapshot = self.expected_snapshot
            if snapshot is None:
                raise ValueError("nonzero revision requires the exact prior snapshot")
            if (
                snapshot.scope != self.scope
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


def maintenance_transition_content_digest(
    request: MaintenanceTransitionRequest | Mapping[str, Any],
) -> str:
    if isinstance(request, MaintenanceTransitionRequest):
        return _stable_digest(
            _transition_content_payload(
                scope_digest=request.scope_digest,
                lifecycle_ref=request.lifecycle_ref,
                source_revision=request.expected_revision,
                source_state=request.expected_state,
                source_state_digest=request.expected_state_digest,
                source_evidence_lineage_digest=request.expected_evidence_lineage_digest,
                transition_ref=request.transition_ref,
                idempotency_digest=request.idempotency_digest,
                requested_by_ref=request.requested_by_ref,
                proposed_at=request.proposed_at,
                command_digest=request.command_digest,
            )
        )
    payload = dict(request)
    scope = MaintenanceWorkOrderScope.model_validate(payload["scope"])
    lifecycle_ref = _visible(payload["lifecycle_ref"], name="lifecycle_ref")
    idempotency_digest = maintenance_idempotency_digest(
        scope,
        lifecycle_ref,
        _visible(payload["idempotency_key"], name="idempotency_key"),
    )
    return _stable_digest(
        _transition_content_payload(
            scope_digest=maintenance_scope_digest(scope),
            lifecycle_ref=lifecycle_ref,
            source_revision=payload["expected_revision"],
            source_state=payload.get("expected_state"),
            source_state_digest=payload["expected_state_digest"],
            source_evidence_lineage_digest=payload["expected_evidence_lineage_digest"],
            transition_ref=_visible(payload["transition_ref"], name="transition_ref"),
            idempotency_digest=idempotency_digest,
            requested_by_ref=_visible(
                payload["requested_by_ref"], name="requested_by_ref"
            ),
            proposed_at=_utc(payload["proposed_at"], name="proposed_at"),
            command_digest=maintenance_command_digest(payload["command"]),
        )
    )


def maintenance_fact_evidence_digest(
    scope: MaintenanceWorkOrderScope | Mapping[str, Any],
    lifecycle_ref: str,
    transition_ref: str,
    command: MaintenanceCommand | Mapping[str, Any],
) -> str:
    return _stable_digest(
        {
            "scope_digest": maintenance_scope_digest(scope),
            "lifecycle_ref": _visible(lifecycle_ref, name="lifecycle_ref"),
            "transition_ref": _visible(transition_ref, name="transition_ref"),
            "command_digest": maintenance_command_digest(command),
        }
    )


def maintenance_transition_commitment_digest(
    *, content_digest: str, fact_evidence_digest: str
) -> str:
    return _stable_digest(
        {
            "content_digest": content_digest,
            "fact_evidence_digest": fact_evidence_digest,
        }
    )


class MaintenanceEffectBoundary(_StrictModel):
    authoritative_scope_verified: Literal[False] = False
    rbac_authorized: Literal[False] = False
    authoritative_evidence_verified: Literal[False] = False
    authoritative_approval_recorded: Literal[False] = False
    work_order_persisted: Literal[False] = False
    asset_isolated: Literal[False] = False
    work_executed: Literal[False] = False
    labor_dispatched: Literal[False] = False
    inventory_reserved_or_moved: Literal[False] = False
    return_to_service_executed: Literal[False] = False
    work_order_closed: Literal[False] = False
    provider_write_executed: Literal[False] = False
    spring_submission_executed: Literal[False] = False


class MaintenanceTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_proposal.v1"] = Field(
        default=MAINTENANCE_PROPOSAL_SCHEMA, alias="schema"
    )
    scope: MaintenanceWorkOrderScope
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    source_revision: int = Field(ge=0, lt=MAX_MAINTENANCE_TRANSITIONS)
    source_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_revision: int = Field(ge=1, le=MAX_MAINTENANCE_TRANSITIONS)
    target_state: MaintenanceState
    transition_ref: str = Field(min_length=1, max_length=160)
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_evidence_lineage_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    effect_boundary: MaintenanceEffectBoundary = Field(
        default_factory=MaintenanceEffectBoundary
    )
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref", "transition_ref")
    @classmethod
    def _refs(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @model_validator(mode="after")
    def _proposal_is_bound(self) -> "MaintenanceTransitionProposal":
        if self.target_revision != self.source_revision + 1:
            raise ValueError("proposal must advance exactly one revision")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"proposal_digest"},
        )
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("proposal_digest does not match proposal")
        return self


class MaintenanceTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.maintenance_work_order_result.v1"] = Field(
        default=MAINTENANCE_RESULT_SCHEMA, alias="schema"
    )
    proposal: MaintenanceTransitionProposal
    candidate_snapshot: MaintenanceWorkOrderSnapshot
    authority_boundary: Literal[
        "sdk_candidate_only_spring_and_governed_systems_authoritative"
    ] = "sdk_candidate_only_spring_and_governed_systems_authoritative"
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _result_is_bound(self) -> "MaintenanceTransitionResult":
        last = self.candidate_snapshot.history[-1]
        if (
            self.proposal.scope != self.candidate_snapshot.scope
            or self.proposal.lifecycle_ref != self.candidate_snapshot.lifecycle_ref
            or self.proposal.source_revision != last.revision - 1
            or self.proposal.source_state_digest != last.prior_state_digest
            or self.proposal.target_revision != self.candidate_snapshot.revision
            or self.proposal.target_state != self.candidate_snapshot.state
            or self.proposal.transition_ref != last.transition_ref
            or self.proposal.command_digest != last.command_digest
            or self.proposal.content_digest != last.content_digest
            or self.proposal.idempotency_digest != last.idempotency_digest
            or self.proposal.transition_digest != last.transition_digest
            or self.proposal.candidate_state_digest
            != self.candidate_snapshot.state_digest
            or self.proposal.candidate_evidence_lineage_digest
            != self.candidate_snapshot.evidence_lineage_digest
        ):
            raise ValueError("result proposal does not bind the candidate snapshot")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"result_digest"},
        )
        if self.result_digest != _stable_digest(payload):
            raise ValueError("result_digest does not match result")
        return self


def _fail(code: str, message: str) -> None:
    raise MaintenanceWorkOrderError(code, message)


def _validate_evidence(
    *,
    scope: MaintenanceWorkOrderScope,
    lifecycle_ref: str,
    revision: int,
    prior_state_digest: str,
    prior_lineage_digest: str,
    prior_evidence_count: int,
    transition_ref: str,
    proposed_at: str,
    command: MaintenanceCommand,
    command_digest: str,
    content_digest: str,
    evidence: Sequence[MaintenanceEvidence],
) -> None:
    if len(evidence) != 2:
        _fail(
            "maintenance_evidence_set_incomplete",
            "each transition requires exactly one fact and one commitment evidence item",
        )
    fact, commitment = evidence
    expected_fact_kind = _FACT_KIND[command.kind]
    if (
        fact.kind != expected_fact_kind
        or commitment.kind != "maintenance_transition_commitment"
    ):
        _fail(
            "maintenance_evidence_kind_mismatch",
            "transition evidence kinds do not match the command",
        )
    expected_sequences = (prior_evidence_count + 1, prior_evidence_count + 2)
    if (fact.sequence, commitment.sequence) != expected_sequences:
        _fail(
            "maintenance_evidence_sequence_mismatch",
            "evidence sequence must be globally contiguous",
        )
    expected_fact_digest = maintenance_fact_evidence_digest(
        scope, lifecycle_ref, transition_ref, command
    )
    if (
        fact.subject_ref != _command_subject_ref(command)
        or fact.sha256 != expected_fact_digest
    ):
        _fail(
            "maintenance_fact_evidence_mismatch",
            "fact evidence is not bound to the exact command artifact",
        )
    expected_commitment = maintenance_transition_commitment_digest(
        content_digest=content_digest,
        fact_evidence_digest=expected_fact_digest,
    )
    if (
        commitment.subject_ref != transition_ref
        or commitment.sha256 != expected_commitment
    ):
        _fail(
            "maintenance_commitment_evidence_mismatch",
            "commitment evidence is not bound to the exact transition content",
        )
    if fact.predecessor_lineage_digest != prior_lineage_digest:
        _fail(
            "maintenance_evidence_lineage_mismatch",
            "fact evidence does not continue the prior evidence lineage",
        )
    if commitment.predecessor_lineage_digest != fact.lineage_digest:
        _fail(
            "maintenance_evidence_lineage_mismatch",
            "commitment evidence does not continue the fact evidence lineage",
        )
    previous_observed: datetime | None = None
    for item in evidence:
        if (
            item.issuer_ref != scope.spring_authority_ref
            or item.custodian_ref != scope.evidence_custodian_ref
            or item.retention_policy != scope.retention_policy_ref
            or item.jurisdiction != scope.jurisdiction_ref
            or item.classification != PrimitiveEvidenceClassification.RESTRICTED
            or item.causal_revision != revision - 1
            or item.causal_state_digest != prior_state_digest
        ):
            _fail(
                "maintenance_evidence_scope_mismatch",
                "evidence issuer, custody, retention, jurisdiction, classification, or causal fence is wrong",
            )
        observed_at = _dt(item.observed_at)
        if observed_at > _dt(proposed_at):
            _fail(
                "maintenance_future_evidence",
                "evidence cannot be observed after the proposal time",
            )
        if observed_at < _dt(proposed_at) - MAX_EVIDENCE_AGE:
            _fail(
                "maintenance_stale_evidence",
                "transition evidence is older than the supported freshness window",
            )
        if previous_observed is not None and observed_at < previous_observed:
            _fail(
                "maintenance_evidence_chronology_mismatch",
                "evidence observation order must follow evidence sequence",
            )
        previous_observed = observed_at
    if fact.effective_at != _command_occurred_at(command):
        _fail(
            "maintenance_fact_effective_time_mismatch",
            "fact evidence effective_at must equal the command fact time",
        )
    if commitment.effective_at != commitment.observed_at:
        _fail(
            "maintenance_commitment_time_mismatch",
            "commitment evidence must be effective when observed",
        )
    minimum_grade = (
        PrimitiveEvidenceVerificationGrade.VERIFIED
        if command.kind
        in {
            "authorize_and_schedule",
            "record_independent_inspection",
            "propose_return_to_service",
            "propose_close",
        }
        else PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    accepted_fact_grades = (
        {PrimitiveEvidenceVerificationGrade.VERIFIED}
        if minimum_grade == PrimitiveEvidenceVerificationGrade.VERIFIED
        else {
            PrimitiveEvidenceVerificationGrade.ATTESTED,
            PrimitiveEvidenceVerificationGrade.VERIFIED,
        }
    )
    if (
        fact.verification_grade not in accepted_fact_grades
        or commitment.verification_grade
        not in {
            PrimitiveEvidenceVerificationGrade.ATTESTED,
            PrimitiveEvidenceVerificationGrade.VERIFIED,
        }
    ):
        _fail(
            "maintenance_evidence_grade_insufficient",
            "evidence verification grade is insufficient for the transition",
        )


def _expected_command_kind(revision: int) -> str:
    return (
        "record_request_and_diagnosis",
        "plan_work",
        "authorize_and_schedule",
        "record_execution",
        "record_independent_inspection",
        "propose_return_to_service",
        "propose_close",
    )[revision - 1]


def _validate_semantic_transition(
    *,
    scope: MaintenanceWorkOrderScope,
    prior_records: Sequence[MaintenanceTransitionRecord],
    command: MaintenanceCommand,
    proposed_at: str,
) -> None:
    revision = len(prior_records) + 1
    expected_kind = _expected_command_kind(revision)
    if command.kind != expected_kind:
        _fail(
            "maintenance_transition_order_invalid",
            f"revision {revision} requires command {expected_kind}",
        )
    command_time = _dt(_command_occurred_at(command))
    proposal_time = _dt(proposed_at)
    if command_time > proposal_time:
        _fail(
            "maintenance_command_from_future",
            "command facts cannot occur after the proposal time",
        )
    if prior_records:
        prior = prior_records[-1]
        if proposal_time <= _dt(prior.proposed_at):
            _fail(
                "maintenance_non_monotonic_proposal_time",
                "proposal time must advance strictly across transitions",
            )
        if command_time < _dt(prior.proposed_at):
            _fail(
                "maintenance_non_causal_command_time",
                "a command fact cannot predate the preceding transition",
            )

    prior_commands = [record.command for record in prior_records]
    if isinstance(command, RecordWorkRequestCommand):
        if (
            command.production_impact == "safety_critical"
            and command.failure_severity < 4
        ):
            _fail(
                "maintenance_safety_risk_understated",
                "safety-critical impact requires failure severity four or five",
            )
        return

    request = prior_commands[0]
    assert isinstance(request, RecordWorkRequestCommand)
    if isinstance(command, PlanMaintenanceCommand):
        if _dt(command.planned_at) < _dt(request.diagnosed_at):
            _fail("maintenance_plan_predates_diagnosis", "work plan predates diagnosis")
        if _dt(command.planned_window_start) < _dt(command.planned_at):
            _fail(
                "maintenance_window_predates_plan",
                "planned work window cannot begin before the plan",
            )
        if request.production_impact == "safety_critical":
            if command.priority != "p1":
                _fail(
                    "maintenance_safety_priority_invalid",
                    "safety-critical work requires priority p1",
                )
            if not (command.loto_required or command.permit_required):
                _fail(
                    "maintenance_safety_controls_missing",
                    "safety-critical work requires a LOTO or permit control",
                )
        return

    plan = prior_commands[1]
    assert isinstance(plan, PlanMaintenanceCommand)
    if isinstance(command, AuthorizeAndScheduleCommand):
        if command.approved_plan_digest != prior_records[1].command_digest:
            _fail(
                "maintenance_approved_plan_digest_mismatch",
                "safety authorization does not bind the exact work plan",
            )
        reserved_technicians = {
            item.technician_ref for item in command.labor_reservations
        }
        if command.safety_approver_ref in {
            request.requested_by_ref,
            request.diagnosed_by_ref,
            plan.planner_ref,
            *reserved_technicians,
        }:
            _fail(
                "maintenance_safety_approval_sod_violation",
                "safety approver must be independent of requester, diagnostician, and planner",
            )
        if _dt(command.authorized_at) < _dt(plan.planned_at):
            _fail(
                "maintenance_authorization_predates_plan",
                "safety authorization cannot predate the work plan",
            )
        if (
            _dt(command.schedule_start) < _dt(plan.planned_window_start)
            or _dt(command.schedule_end) > _dt(plan.planned_window_end)
            or _dt(command.schedule_start) < _dt(command.authorized_at)
        ):
            _fail(
                "maintenance_schedule_outside_authorized_window",
                "authorized schedule must fit the planned window and follow approval",
            )
        available_competencies = {
            competency
            for labor in command.labor_reservations
            for competency in labor.competency_refs
        }
        if not set(plan.required_competency_refs).issubset(available_competencies):
            _fail(
                "maintenance_competency_reservation_incomplete",
                "reserved labor does not cover every required competency",
            )
        if any(
            _dt(tool.calibration_due_at) < _dt(command.schedule_end)
            for tool in command.tool_reservations
        ):
            _fail(
                "maintenance_tool_calibration_expired",
                "reserved tool calibration must cover the authorized schedule",
            )
        return

    authorization = prior_commands[2]
    assert isinstance(authorization, AuthorizeAndScheduleCommand)
    if isinstance(command, RecordMaintenanceExecutionCommand):
        if (
            _dt(command.started_at) < _dt(authorization.schedule_start)
            or _dt(command.started_at) >= _dt(authorization.schedule_end)
            or _dt(command.completed_at) > _dt(authorization.schedule_end)
        ):
            _fail(
                "maintenance_execution_outside_schedule",
                "execution must start and finish inside the independently authorized schedule",
            )
        expected_checklist = [(item.sequence, item.task_ref) for item in plan.checklist]
        actual_checklist = [
            (item.sequence, item.task_ref) for item in command.checklist_results
        ]
        if actual_checklist != expected_checklist:
            _fail(
                "maintenance_checklist_mismatch",
                "execution must complete the exact planned checklist in order",
            )
        labor_by_technician = {
            item.technician_ref: item for item in authorization.labor_reservations
        }
        actual_minutes: dict[str, int] = {}
        previous_completion_time: datetime | None = None
        for completion, planned_item in zip(
            command.checklist_results, plan.checklist, strict=True
        ):
            completion_time = _dt(completion.completed_at)
            if not (
                _dt(command.started_at) <= completion_time <= _dt(command.completed_at)
            ):
                _fail(
                    "maintenance_checklist_time_invalid",
                    "checklist completion time must fall inside execution",
                )
            if (
                previous_completion_time is not None
                and completion_time < previous_completion_time
            ):
                _fail(
                    "maintenance_checklist_chronology_mismatch",
                    "checklist completion times must follow exact checklist sequence",
                )
            previous_completion_time = completion_time
            reservation = labor_by_technician.get(completion.completed_by_ref)
            if reservation is None:
                _fail(
                    "maintenance_unreserved_executor",
                    "every checklist executor must have an authorized labor reservation",
                )
            if not set(planned_item.required_competency_refs).issubset(
                set(reservation.competency_refs)
            ):
                _fail(
                    "maintenance_executor_competency_missing",
                    "checklist executor lacks a required competency",
                )
            actual_minutes[completion.completed_by_ref] = (
                actual_minutes.get(completion.completed_by_ref, 0)
                + completion.actual_minutes
            )
        labor_entry_by_technician = {
            item.technician_ref: item for item in command.labor_entries
        }
        if set(labor_entry_by_technician) != set(actual_minutes):
            _fail(
                "maintenance_labor_genealogy_mismatch",
                "labor entries must exactly identify checklist executors",
            )
        for technician_ref, entry in labor_entry_by_technician.items():
            reservation = labor_by_technician.get(technician_ref)
            if (
                reservation is None
                or entry.hourly_rate != reservation.hourly_rate
                or entry.minutes != actual_minutes[technician_ref]
                or entry.minutes > reservation.planned_minutes
            ):
                _fail(
                    "maintenance_labor_reservation_mismatch",
                    "labor entry does not match authorized rate, work, and reservation",
                )
        execution_minutes = _interval_minutes(
            command.started_at,
            command.completed_at,
        )
        if any(
            Decimal(minutes) > execution_minutes for minutes in actual_minutes.values()
        ):
            _fail(
                "maintenance_labor_time_capacity_exceeded",
                "one technician's checklist minutes cannot exceed the execution interval",
            )
        part_by_reservation = {
            item.reservation_ref: item for item in authorization.part_reservations
        }
        _unique(
            [usage.reservation_ref for usage in command.parts_used],
            label="part usage reservation refs",
        )
        for usage in command.parts_used:
            reservation = part_by_reservation.get(usage.reservation_ref)
            if (
                reservation is None
                or usage.part_ref != reservation.part_ref
                or usage.unit_of_measure != reservation.unit_of_measure
                or usage.unit_cost != reservation.unit_cost
                or usage.quantity > reservation.quantity
            ):
                _fail(
                    "maintenance_part_reservation_mismatch",
                    "part usage does not match the authorized reservation",
                )
            if reservation.lot_tracking_required and usage.lot_ref is None:
                _fail(
                    "maintenance_part_lot_genealogy_missing",
                    "lot-tracked part usage requires its lot reference",
                )
            if reservation.lot_tracking_required:
                if usage.lot_ref not in set(reservation.authorized_lot_refs):
                    _fail(
                        "maintenance_part_lot_genealogy_mismatch",
                        "lot-tracked usage must continue authorized lot genealogy",
                    )
            elif usage.lot_ref is not None:
                _fail(
                    "maintenance_unexpected_lot_genealogy",
                    "untracked part usage must not invent lot genealogy",
                )
            if reservation.serial_tracking_required:
                if usage.quantity != usage.quantity.to_integral() or len(
                    usage.serial_refs
                ) != int(usage.quantity):
                    _fail(
                        "maintenance_part_serial_genealogy_mismatch",
                        "serial-tracked usage requires one unique serial per unit",
                    )
                if not set(usage.serial_refs).issubset(
                    set(reservation.authorized_serial_refs)
                ):
                    _fail(
                        "maintenance_part_serial_genealogy_mismatch",
                        "serial-tracked usage must continue authorized serial genealogy",
                    )
            elif usage.serial_refs:
                _fail(
                    "maintenance_unexpected_serial_genealogy",
                    "untracked part usage must not invent serial genealogy",
                )
            if (
                usage.custody_from_ref != reservation.custody_from_ref
                or usage.custody_to_ref != scope.asset_ref
            ):
                _fail(
                    "maintenance_part_custody_scope_mismatch",
                    "installed part custody must continue the authorized source and terminate at the exact asset",
                )
            if not (
                _dt(command.started_at)
                <= _dt(usage.issued_at)
                <= _dt(usage.installed_at)
                <= _dt(command.completed_at)
            ):
                _fail(
                    "maintenance_part_custody_time_invalid",
                    "part issue and installation must fall inside execution",
                )
        if (
            command.meter_name != request.meter_name
            or command.meter_unit != request.meter_unit
            or command.meter_before != request.meter_reading
        ):
            _fail(
                "maintenance_meter_fence_mismatch",
                "execution meter must continue the diagnosed asset meter",
            )
        return

    execution = prior_commands[3]
    assert isinstance(execution, RecordMaintenanceExecutionCommand)
    executors = {item.technician_ref for item in execution.labor_entries}
    if isinstance(command, RecordIndependentInspectionCommand):
        if command.execution_digest != prior_records[3].command_digest:
            _fail(
                "maintenance_inspection_execution_digest_mismatch",
                "inspection does not bind the exact execution record",
            )
        if _dt(command.inspected_at) < _dt(execution.completed_at):
            _fail(
                "maintenance_inspection_predates_execution",
                "independent inspection cannot predate execution completion",
            )
        if command.inspector_ref in {
            request.requested_by_ref,
            request.diagnosed_by_ref,
            *executors,
            authorization.safety_approver_ref,
            plan.planner_ref,
        }:
            _fail(
                "maintenance_inspection_sod_violation",
                "inspector must be independent of planning, approval, and execution",
            )
        return

    inspection = prior_commands[4]
    assert isinstance(inspection, RecordIndependentInspectionCommand)
    if isinstance(command, ProposeReturnToServiceCommand):
        if command.inspection_digest != prior_records[4].command_digest:
            _fail(
                "maintenance_return_inspection_digest_mismatch",
                "return authorization does not bind the exact independent inspection",
            )
        if _dt(command.authorized_at) < _dt(inspection.inspected_at):
            _fail(
                "maintenance_return_predates_inspection",
                "return-to-service candidate cannot predate inspection",
            )
        if command.authorized_by_ref in {
            request.requested_by_ref,
            request.diagnosed_by_ref,
            *executors,
            inspection.inspector_ref,
            authorization.safety_approver_ref,
            plan.planner_ref,
        }:
            _fail(
                "maintenance_return_authorization_sod_violation",
                "return authorizer must be independent of planning, approval, execution, and inspection",
            )
        return

    return_candidate = prior_commands[5]
    assert isinstance(return_candidate, ProposeReturnToServiceCommand)
    assert isinstance(command, ProposeMaintenanceCloseCommand)
    if command.return_authorization_digest != prior_records[5].command_digest:
        _fail(
            "maintenance_close_return_digest_mismatch",
            "close candidate does not bind the exact return authorization candidate",
        )
    if _dt(command.closed_at) < _dt(return_candidate.authorized_at):
        _fail(
            "maintenance_close_predates_return_authorization",
            "close candidate cannot predate return authorization",
        )
    if command.closed_by_ref in {
        request.requested_by_ref,
        request.diagnosed_by_ref,
        plan.planner_ref,
        authorization.safety_approver_ref,
        *executors,
        inspection.inspector_ref,
        return_candidate.authorized_by_ref,
    }:
        _fail(
            "maintenance_close_sod_violation",
            "close reviewer must be independent of execution and return authorization",
        )
    if (
        command.actual_labor_cost != execution.actual_labor_cost
        or command.actual_parts_cost != execution.actual_parts_cost
        or command.actual_total_cost != execution.actual_total_cost
    ):
        _fail(
            "maintenance_close_cost_mismatch",
            "close costs must match the exact execution record",
        )
    if command.next_maintenance_meter <= execution.meter_after:
        _fail(
            "maintenance_next_meter_invalid",
            "next maintenance meter must follow the execution reading",
        )
    if (
        command.effectiveness_status == "verified"
        and _dt(command.effectiveness_at) > proposal_time
    ):
        _fail(
            "maintenance_future_effectiveness_claim",
            "verified effectiveness evidence cannot be from the future",
        )
    if (
        command.effectiveness_status == "review_scheduled"
        and _dt(command.effectiveness_at) <= proposal_time
    ):
        _fail(
            "maintenance_effectiveness_schedule_invalid",
            "a scheduled effectiveness review must remain in the future at proposal time",
        )


def _validate_history_semantics(snapshot: MaintenanceWorkOrderSnapshot) -> None:
    prior: list[MaintenanceTransitionRecord] = []
    prior_evidence_count = 0
    for record in snapshot.history:
        expected_content = _stable_digest(
            _transition_content_payload(
                scope_digest=record.scope_digest,
                lifecycle_ref=record.lifecycle_ref,
                source_revision=record.revision - 1,
                source_state=record.prior_state,
                source_state_digest=record.prior_state_digest,
                source_evidence_lineage_digest=record.prior_evidence_lineage_digest,
                transition_ref=record.transition_ref,
                idempotency_digest=record.idempotency_digest,
                requested_by_ref=record.requested_by_ref,
                proposed_at=record.proposed_at,
                command_digest=record.command_digest,
            )
        )
        if record.content_digest != expected_content:
            _fail(
                "maintenance_history_content_digest_mismatch",
                "history contains a transition with an invalid content digest",
            )
        if record.idempotency_digest != maintenance_idempotency_digest(
            snapshot.scope, snapshot.lifecycle_ref, record.idempotency_key
        ):
            _fail(
                "maintenance_history_idempotency_digest_mismatch",
                "history contains an invalid idempotency fence",
            )
        _validate_semantic_transition(
            scope=snapshot.scope,
            prior_records=prior,
            command=record.command,
            proposed_at=record.proposed_at,
        )
        _validate_evidence(
            scope=snapshot.scope,
            lifecycle_ref=snapshot.lifecycle_ref,
            revision=record.revision,
            prior_state_digest=record.prior_state_digest,
            prior_lineage_digest=record.prior_evidence_lineage_digest,
            prior_evidence_count=prior_evidence_count,
            transition_ref=record.transition_ref,
            proposed_at=record.proposed_at,
            command=record.command,
            command_digest=record.command_digest,
            content_digest=record.content_digest,
            evidence=record.evidence,
        )
        prior.append(record)
        prior_evidence_count += len(record.evidence)


def propose_maintenance_work_order_transition(
    request: MaintenanceTransitionRequest | Mapping[str, Any],
) -> MaintenanceTransitionResult:
    """Validate one exact transition and return an immutable candidate snapshot."""

    try:
        parsed = MaintenanceTransitionRequest.model_validate(_jsonable(request))
    except (ValidationError, ValueError, TypeError, KeyError) as exc:
        raise MaintenanceWorkOrderError(
            "maintenance_request_invalid",
            "maintenance request failed strict schema or digest validation",
        ) from exc

    history: list[MaintenanceTransitionRecord] = []
    if parsed.expected_snapshot is not None:
        try:
            snapshot = MaintenanceWorkOrderSnapshot.model_validate(
                parsed.expected_snapshot.model_dump(mode="python", by_alias=True)
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise MaintenanceWorkOrderError(
                "maintenance_snapshot_invalid",
                "prior maintenance snapshot failed canonical validation",
            ) from exc
        _validate_history_semantics(snapshot)
        history = list(snapshot.history)
    if len(history) >= MAX_MAINTENANCE_TRANSITIONS:
        _fail(
            "maintenance_transition_limit_reached",
            "the bounded maintenance lifecycle is already complete",
        )

    by_transition_ref = next(
        (item for item in history if item.transition_ref == parsed.transition_ref), None
    )
    by_idempotency = next(
        (
            item
            for item in history
            if item.idempotency_digest == parsed.idempotency_digest
            or item.idempotency_key == parsed.idempotency_key
        ),
        None,
    )
    if by_transition_ref is not None or by_idempotency is not None:
        prior = by_transition_ref or by_idempotency
        assert prior is not None
        if (
            prior.transition_ref == parsed.transition_ref
            and prior.command_digest == parsed.command_digest
            and prior.requested_by_ref == parsed.requested_by_ref
        ):
            _fail(
                "maintenance_duplicate_transition",
                "transition was already represented in the supplied history; do not replay",
            )
        _fail(
            "maintenance_idempotency_conflict",
            "transition or idempotency identity conflicts with prior content",
        )
    prior_evidence_refs = {
        item.evidence_ref for record in history for item in record.evidence
    }
    prior_evidence_digests = {
        item.sha256 for record in history for item in record.evidence
    }
    current_evidence_refs = {item.evidence_ref for item in parsed.evidence}
    current_evidence_digests = {item.sha256 for item in parsed.evidence}
    if len(current_evidence_refs) != len(parsed.evidence) or len(
        current_evidence_digests
    ) != len(parsed.evidence):
        _fail(
            "maintenance_duplicate_current_evidence",
            "transition evidence references and content digests must be unique",
        )
    if (
        prior_evidence_refs & current_evidence_refs
        or prior_evidence_digests & current_evidence_digests
    ):
        _fail(
            "maintenance_evidence_reuse",
            "single-use evidence reference or content was already consumed by the lifecycle",
        )

    _validate_semantic_transition(
        scope=parsed.scope,
        prior_records=history,
        command=parsed.command,
        proposed_at=parsed.proposed_at,
    )
    prior_evidence_count = sum(len(item.evidence) for item in history)
    _validate_evidence(
        scope=parsed.scope,
        lifecycle_ref=parsed.lifecycle_ref,
        revision=parsed.expected_revision + 1,
        prior_state_digest=parsed.expected_state_digest,
        prior_lineage_digest=parsed.expected_evidence_lineage_digest,
        prior_evidence_count=prior_evidence_count,
        transition_ref=parsed.transition_ref,
        proposed_at=parsed.proposed_at,
        command=parsed.command,
        command_digest=parsed.command_digest,
        content_digest=parsed.content_digest,
        evidence=parsed.evidence,
    )

    record_payload: dict[str, Any] = {
        "schema": MAINTENANCE_TRANSITION_SCHEMA,
        "revision": parsed.expected_revision + 1,
        "scope_digest": parsed.scope_digest,
        "lifecycle_ref": parsed.lifecycle_ref,
        "prior_state": parsed.expected_state,
        "prior_state_digest": parsed.expected_state_digest,
        "prior_evidence_lineage_digest": parsed.expected_evidence_lineage_digest,
        "state": _STATE_FOR_KIND[parsed.command.kind],
        "transition_ref": parsed.transition_ref,
        "idempotency_key": parsed.idempotency_key,
        "idempotency_digest": parsed.idempotency_digest,
        "requested_by_ref": parsed.requested_by_ref,
        "proposed_at": parsed.proposed_at,
        "command": parsed.command,
        "command_digest": parsed.command_digest,
        "content_digest": parsed.content_digest,
        "evidence": parsed.evidence,
        "evidence_digest": _stable_digest(parsed.evidence),
        "evidence_lineage_digest": parsed.evidence[-1].lineage_digest,
        "authoritative_scope_verified": False,
        "authoritative_approval_recorded": False,
        "work_order_persisted": False,
        "live_effect_executed": False,
    }
    record_payload["transition_digest"] = _stable_digest(
        {key: value for key, value in record_payload.items() if value is not None}
    )
    record = MaintenanceTransitionRecord.model_validate(record_payload)
    next_history = [*history, record]
    snapshot_payload = _snapshot_payload(
        scope=parsed.scope,
        lifecycle_ref=parsed.lifecycle_ref,
        history=next_history,
    )
    snapshot_payload["state_digest"] = _stable_digest(snapshot_payload)
    snapshot = MaintenanceWorkOrderSnapshot.model_validate(snapshot_payload)
    _validate_history_semantics(snapshot)

    proposal_payload: dict[str, Any] = {
        "schema": MAINTENANCE_PROPOSAL_SCHEMA,
        "scope": parsed.scope,
        "lifecycle_ref": parsed.lifecycle_ref,
        "source_revision": parsed.expected_revision,
        "source_state_digest": parsed.expected_state_digest,
        "target_revision": snapshot.revision,
        "target_state": snapshot.state,
        "transition_ref": parsed.transition_ref,
        "command_digest": parsed.command_digest,
        "content_digest": parsed.content_digest,
        "idempotency_digest": parsed.idempotency_digest,
        "transition_digest": record.transition_digest,
        "candidate_state_digest": snapshot.state_digest,
        "candidate_evidence_lineage_digest": snapshot.evidence_lineage_digest,
        "effect_boundary": MaintenanceEffectBoundary(),
    }
    proposal_payload["proposal_digest"] = _stable_digest(proposal_payload)
    proposal = MaintenanceTransitionProposal.model_validate(proposal_payload)
    result_payload: dict[str, Any] = {
        "schema": MAINTENANCE_RESULT_SCHEMA,
        "proposal": proposal,
        "candidate_snapshot": snapshot,
        "authority_boundary": (
            "sdk_candidate_only_spring_and_governed_systems_authoritative"
        ),
    }
    result_payload["result_digest"] = _stable_digest(result_payload)
    return MaintenanceTransitionResult.model_validate(result_payload)


MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="maintenance-work-order.materialize-transition-candidate.v1",
    tool="sdk.maintenance.propose_work_order_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _scope_matches_context(
    request: MaintenanceTransitionRequest,
    context: PrimitiveExecutionContext,
) -> bool:
    return (
        request.scope.tenant_ref == context.scope.tenant_ref
        and request.scope.company_ref == context.scope.company_ref
        and request.scope.project_ref == context.scope.project_ref
        and context.scope.project_id is not None
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
        "schema": MAINTENANCE_EVIDENCE_SCHEMA,
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
    payload["lineage_digest"] = maintenance_evidence_lineage_digest(payload)
    return payload


def _example_inputs() -> dict[str, Any]:
    scope: dict[str, Any] = {
        "schema": MAINTENANCE_SCOPE_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000931",
        "site_ref": "site-example",
        "asset_ref": "asset-example",
        "work_order_ref": "work-order-example",
        "asset_system_ref": "eam-example",
        "jurisdiction_ref": "US-NY",
        "retention_policy_ref": "maintenance-seven-years",
        "evidence_custodian_ref": "spring-maintenance-evidence-vault",
        "spring_authority_ref": "spring-maintenance-authority",
    }
    command: dict[str, Any] = {
        "kind": "record_request_and_diagnosis",
        "request_ref": "request-example",
        "requested_by_ref": "requester-example",
        "diagnosed_by_ref": "diagnostician-example",
        "requested_at": "2026-08-25T12:00:00Z",
        "diagnosed_at": "2026-08-25T12:10:00Z",
        "symptom_code": "bearing-vibration",
        "failure_mode_ref": "failure-mode-bearing-wear",
        "affected_component_ref": "component-drive-bearing",
        "production_impact": "degraded",
        "failure_severity": 3,
        "meter_name": "operating-hours",
        "meter_reading": "1240",
        "meter_unit": "hours",
    }
    lifecycle_ref = "maintenance-lifecycle-example"
    transition_ref = "transition-request-example"
    idempotency_key = "maintenance-request-idem-example"
    proposed_at = "2026-08-25T12:15:00Z"
    scope_digest = maintenance_scope_digest(scope)
    command_digest = maintenance_command_digest(command)
    idempotency_digest = maintenance_idempotency_digest(
        scope, lifecycle_ref, idempotency_key
    )
    content_digest = _stable_digest(
        _transition_content_payload(
            scope_digest=scope_digest,
            lifecycle_ref=lifecycle_ref,
            source_revision=0,
            source_state=None,
            source_state_digest=GENESIS_MAINTENANCE_DIGEST,
            source_evidence_lineage_digest=GENESIS_MAINTENANCE_DIGEST,
            transition_ref=transition_ref,
            idempotency_digest=idempotency_digest,
            requested_by_ref="requester-example",
            proposed_at=proposed_at,
            command_digest=command_digest,
        )
    )
    fact_digest = maintenance_fact_evidence_digest(
        scope, lifecycle_ref, transition_ref, command
    )
    fact = _example_evidence_payload(
        scope=scope,
        sequence=1,
        evidence_ref="evidence-request-fact-example",
        kind="maintenance_work_request_and_diagnosis",
        subject_ref="request-example",
        sha256=fact_digest,
        observed_at="2026-08-25T12:11:00Z",
        effective_at="2026-08-25T12:10:00Z",
        grade="attested",
        causal_revision=0,
        causal_state_digest=GENESIS_MAINTENANCE_DIGEST,
        predecessor_lineage_digest=GENESIS_MAINTENANCE_DIGEST,
    )
    commitment = _example_evidence_payload(
        scope=scope,
        sequence=2,
        evidence_ref="evidence-request-commitment-example",
        kind="maintenance_transition_commitment",
        subject_ref=transition_ref,
        sha256=maintenance_transition_commitment_digest(
            content_digest=content_digest,
            fact_evidence_digest=fact_digest,
        ),
        observed_at="2026-08-25T12:14:00Z",
        effective_at="2026-08-25T12:14:00Z",
        grade="attested",
        causal_revision=0,
        causal_state_digest=GENESIS_MAINTENANCE_DIGEST,
        predecessor_lineage_digest=fact["lineage_digest"],
    )
    return MaintenanceTransitionRequest.model_validate(
        {
            "schema": MAINTENANCE_REQUEST_SCHEMA,
            "scope": scope,
            "scope_digest": scope_digest,
            "lifecycle_ref": lifecycle_ref,
            "expected_revision": 0,
            "expected_state": None,
            "expected_state_digest": GENESIS_MAINTENANCE_DIGEST,
            "expected_evidence_lineage_digest": GENESIS_MAINTENANCE_DIGEST,
            "transition_ref": transition_ref,
            "idempotency_key": idempotency_key,
            "idempotency_digest": idempotency_digest,
            "requested_by_ref": "requester-example",
            "proposed_at": proposed_at,
            "command": command,
            "command_digest": command_digest,
            "content_digest": content_digest,
            "evidence": [fact, commitment],
        }
    ).to_dict()


class ProposeMaintenanceWorkOrderTransitionPrimitive(
    BusinessProcessPrimitive[MaintenanceTransitionRequest, MaintenanceTransitionResult]
):
    primitive_ref = "maintenance.propose_work_order_transition"
    version = "1.1.0"
    title = "Propose a bounded maintenance work-order transition"
    description = (
        "Validate one exact-scope, evidence-bound maintenance candidate without "
        "isolating an asset, dispatching or executing work, moving inventory, "
        "returning an asset to service, closing a work order, persisting state, "
        "or calling a provider."
    )
    input_model = MaintenanceTransitionRequest
    output_model = MaintenanceTransitionResult
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
            MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION.to_dict()
        )
        contract["effect_boundary"] = MaintenanceEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "spring_control_plane": (
                "authenticated scope, RBAC, authoritative evidence and approvals, "
                "persistence, audit, idempotency, and write admission"
            ),
            "governed_operational_systems": (
                "asset isolation, dispatch, inventory custody and movement, work "
                "execution, return to service, and work-order close"
            ),
            "sdk": "strict deterministic preview-only candidate materialization",
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_MAINTENANCE_TRANSITIONS,
            "scope": "exact tenant/company/project/site/asset/work-order",
            "history": "immutable append-only state, command, and snapshot digests",
            "evidence": (
                "ordered causal lineage with exact kind, issuer, custodian, subject, "
                "grade, jurisdiction, retention, and revision fences"
            ),
            "segregation_of_duties": (
                "independent safety approval, inspection, return authorization, and close review"
            ),
            "live_effects": False,
        }
        contract["portable_evidence_is_execution_authority"] = False
        contract["non_preview_result_is_still_preview"] = True
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: MaintenanceTransitionRequest,
    ) -> PrimitiveExecutionResult[MaintenanceTransitionResult]:
        portable_evidence = [item.portable_ref() for item in inputs.evidence]
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="maintenance_runtime_scope_mismatch",
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
                summary="Maintenance candidate rejected at the runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.content_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        try:
            output = propose_maintenance_work_order_transition(inputs)
        except MaintenanceWorkOrderError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code, message=exc.message, retryable=False
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Maintenance candidate failed deterministic lifecycle validation."
                ),
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.content_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        proposal = output.proposal
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Maintenance candidate passed deterministic validation; no live "
                "asset, labor, inventory, work-order, Spring, or provider state changed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="maintenance.work_order_transition_candidate_validated",
                    payload={
                        "lifecycle_ref": proposal.lifecycle_ref,
                        "transition_ref": proposal.transition_ref,
                        "target_state": proposal.target_state,
                        "proposal_digest": proposal.proposal_digest,
                        "authoritative_scope_verified": False,
                        "authoritative_approval_recorded": False,
                        "asset_isolated": False,
                        "work_executed": False,
                        "inventory_moved": False,
                        "return_to_service_executed": False,
                        "work_order_closed": False,
                        "provider_write_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="maintenance_work_order_transition_candidate",
                    summary=(
                        "Content-bound SDK candidate; Spring and governed operational "
                        "systems retain scope, approval, persistence, fact, and effect authority."
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
                    },
                )
            ],
            evidence_refs=portable_evidence,
            operation_receipts=[
                PrimitiveOperationReceipt(
                    spec=MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION,
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.content_digest,
                    external_refs={
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "proposal_digest": proposal.proposal_digest,
                        "transition_digest": proposal.transition_digest,
                    },
                    evidence_refs=portable_evidence,
                    replayed=False,
                )
            ],
            retryable=False,
        )


MAINTENANCE_WORK_ORDER_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeMaintenanceWorkOrderTransitionPrimitive(),)


__all__ = [
    "GENESIS_MAINTENANCE_DIGEST",
    "MAINTENANCE_EVIDENCE_SCHEMA",
    "MAINTENANCE_PROPOSAL_SCHEMA",
    "MAINTENANCE_REQUEST_SCHEMA",
    "MAINTENANCE_RESULT_SCHEMA",
    "MAINTENANCE_SCOPE_SCHEMA",
    "MAINTENANCE_SNAPSHOT_SCHEMA",
    "MAINTENANCE_TRANSITION_SCHEMA",
    "MAINTENANCE_WORK_ORDER_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "MAINTENANCE_WORK_ORDER_TRANSITION_OPERATION",
    "MAX_MAINTENANCE_TRANSITIONS",
    "AuthorizeAndScheduleCommand",
    "ChecklistCompletion",
    "InspectionTest",
    "LaborEntry",
    "LaborReservation",
    "MaintenanceChecklistItem",
    "MaintenanceCommand",
    "MaintenanceEffectBoundary",
    "MaintenanceEvidence",
    "MaintenanceTransitionProposal",
    "MaintenanceTransitionRecord",
    "MaintenanceTransitionRequest",
    "MaintenanceTransitionResult",
    "MaintenanceWorkOrderError",
    "MaintenanceWorkOrderScope",
    "MaintenanceWorkOrderSnapshot",
    "PartReservation",
    "PartUsage",
    "PlanMaintenanceCommand",
    "ProposeMaintenanceCloseCommand",
    "ProposeMaintenanceWorkOrderTransitionPrimitive",
    "ProposeReturnToServiceCommand",
    "RecordIndependentInspectionCommand",
    "RecordMaintenanceExecutionCommand",
    "RecordWorkRequestCommand",
    "ToolReservation",
    "maintenance_command_digest",
    "maintenance_evidence_lineage_digest",
    "maintenance_fact_evidence_digest",
    "maintenance_idempotency_digest",
    "maintenance_scope_digest",
    "maintenance_snapshot_digest",
    "maintenance_transition_commitment_digest",
    "maintenance_transition_content_digest",
    "propose_maintenance_work_order_transition",
]
