"""Deterministic manufacturing execution lifecycle contracts.

This module materializes an immutable SDK projection from a released BOM and
routing through production-order scheduling, ordered shop-floor completion,
lot/serial genealogy, and independent quality disposition.  It performs no
ERP, MES, QMS, inventory, or connector write.  Spring remains authoritative
for authenticated scope, RBAC, durable state, approvals, audit, and any live
effect; a Connector Runtime may execute such an effect only after Spring has
authorized it.

Every candidate transition is version-, digest-, scope-, evidence-, and
idempotency-bound.  The projection rejects stale state, duplicate transition
references, idempotency conflicts, out-of-order work, impossible quantities,
untraceable material, and non-independent quality release.  Materialized
candidate transitions carry a portable projection receipt, but that receipt
proves only deterministic SDK materialization and never claims a provider or
system-of-record write.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Context, Decimal, InvalidOperation, localcontext
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
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


RELEASED_BOM_SCHEMA = "lightbulb.manufacturing_released_bom.v1"
RELEASED_ROUTING_SCHEMA = "lightbulb.manufacturing_released_routing.v1"
RELEASED_DEFINITION_SCHEMA = "lightbulb.manufacturing_released_definition.v1"
MANUFACTURING_LIFECYCLE_SNAPSHOT_SCHEMA = (
    "lightbulb.manufacturing_execution_lifecycle_snapshot.v2"
)
MANUFACTURING_LIFECYCLE_INPUT_SCHEMA = (
    "lightbulb.manufacturing_execution_lifecycle_input.v2"
)
MANUFACTURING_TRANSITION_RECEIPT_SCHEMA = (
    "lightbulb.manufacturing_execution_transition_receipt.v2"
)
MANUFACTURING_LIFECYCLE_RESULT_SCHEMA = (
    "lightbulb.manufacturing_execution_lifecycle_result.v2"
)

GENESIS_SNAPSHOT_DIGEST = "0" * 64
MAX_LIFECYCLE_TRANSITIONS = 512
MAX_ROUTING_OPERATIONS = 100
MAX_BOM_COMPONENTS = 500
MAX_TRACES_PER_OPERATION = 10_000
MAX_NONCONFORMANCES = 100
MAX_QUANTITY = Decimal("1000000000000000000")
MAX_QUANTITY_DECIMAL_PLACES = 9
_QUANTITY_ARITHMETIC_CONTEXT = Context(prec=64, Emin=-999999, Emax=999999)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_UNIT_PATTERN = r"^[A-Z][A-Z0-9._/-]{0,15}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError(
            "references must contain visible characters without whitespace"
        )
    return value


def _canonical_uuid_ref(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError("project_id must be a valid UUID") from exc


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
UuidRef = Annotated[str, AfterValidator(_canonical_uuid_ref)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
UnitCode = Annotated[str, StringConstraints(pattern=_UNIT_PATTERN)]
TraceKind = Literal["lot", "serial"]


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
    return tuple(value or ())


def _stable_digest(value: Any) -> str:
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
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _quantity(value: Any, *, allow_zero: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, Decimal)):
        raise ValueError("quantity must be supplied as a decimal string or Decimal")
    if isinstance(value, str) and (not value or value != value.strip()):
        raise ValueError("quantity must be a canonical visible decimal")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("quantity must be a finite decimal value") from exc
    if not parsed.is_finite() or parsed.copy_abs() > MAX_QUANTITY:
        raise ValueError("quantity must be finite and within the supported bound")
    if parsed.as_tuple().exponent < -MAX_QUANTITY_DECIMAL_PLACES:
        raise ValueError(
            f"quantity supports at most {MAX_QUANTITY_DECIMAL_PLACES} decimal places"
        )
    if parsed < 0 or (parsed == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"quantity must be {qualifier}")
    if parsed == 0:
        return Decimal(0)
    sign, digits, exponent = parsed.as_tuple()
    canonical_digits = list(digits)
    if exponent > 0:
        canonical_digits.extend([0] * exponent)
        exponent = 0
    while canonical_digits and canonical_digits[-1] == 0 and exponent < 0:
        canonical_digits.pop()
        exponent += 1
    return Decimal((sign, tuple(canonical_digits), exponent))


def _quantity_add(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_QUANTITY_ARITHMETIC_CONTEXT):
        return left + right


def _quantity_multiply(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_QUANTITY_ARITHMETIC_CONTEXT):
        return left * right


def _quantity_sum(values: Sequence[Decimal]) -> Decimal:
    with localcontext(_QUANTITY_ARITHMETIC_CONTEXT):
        return sum(values, Decimal(0))


def _unique_refs(values: Sequence[Any], *, field_name: str, label: str) -> None:
    refs = [getattr(value, field_name) for value in values]
    if len(refs) != len(set(refs)):
        raise ValueError(f"{label} references must be unique")


def released_bom_content_digest(value: BaseModel | Mapping[str, Any]) -> str:
    """Commit the exact released BOM content, excluding its evidence envelope."""

    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("evidence_refs", None)
        return _stable_digest(payload)
    raw = dict(value)
    scope_digest = raw.get("scope_digest")
    if (
        not isinstance(scope_digest, str)
        or len(scope_digest) != 64
        or any(character not in "0123456789abcdef" for character in scope_digest)
    ):
        raise ValueError("scope_digest is required for released BOM content")
    effective_from = raw.get("effective_from")
    if not isinstance(effective_from, str):
        raise ValueError("effective_from is required for released BOM content")
    payload: dict[str, Any] = {
        "schema": raw.get("schema", RELEASED_BOM_SCHEMA),
        "bom_ref": raw.get("bom_ref"),
        "scope_digest": scope_digest,
        "product_ref": raw.get("product_ref"),
        "revision": raw.get("revision"),
        "status": raw.get("status", "released"),
        "output_unit_of_measure": raw.get("output_unit_of_measure"),
        "effective_from": _timestamp(effective_from, field_name="effective_from"),
        "components": [
            ReleasedBomComponent.model_validate(item).to_dict()
            for item in raw.get("components", ())
        ],
    }
    if raw.get("effective_until") is not None:
        payload["effective_until"] = _timestamp(
            raw["effective_until"],
            field_name="effective_until",
        )
    return _stable_digest(payload)


def released_routing_content_digest(value: BaseModel | Mapping[str, Any]) -> str:
    """Commit the exact released routing content, excluding its evidence envelope."""

    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("evidence_refs", None)
        return _stable_digest(payload)
    raw = dict(value)
    scope_digest = raw.get("scope_digest")
    if (
        not isinstance(scope_digest, str)
        or len(scope_digest) != 64
        or any(character not in "0123456789abcdef" for character in scope_digest)
    ):
        raise ValueError("scope_digest is required for released routing content")
    return _stable_digest(
        {
            "schema": raw.get("schema", RELEASED_ROUTING_SCHEMA),
            "routing_ref": raw.get("routing_ref"),
            "scope_digest": scope_digest,
            "product_ref": raw.get("product_ref"),
            "revision": raw.get("revision"),
            "status": raw.get("status", "released"),
            "operations": [
                ReleasedRoutingOperation.model_validate(item).to_dict()
                for item in raw.get("operations", ())
            ],
        }
    )


_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}


def _require_evidence(
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    *,
    subject_ref: str,
    minimum_grade: PrimitiveEvidenceVerificationGrade,
    no_later_than: str | None = None,
) -> None:
    if not evidence_refs:
        raise ValueError("evidence is required")
    _unique_refs(evidence_refs, field_name="evidence_ref", label="evidence")
    for evidence in evidence_refs:
        if evidence.subject_ref != subject_ref:
            raise ValueError(f"evidence must be bound to {subject_ref}")
        if _GRADE_RANK[evidence.verification_grade] < _GRADE_RANK[minimum_grade]:
            raise ValueError(
                f"evidence for {subject_ref} must be at least {minimum_grade.value}"
            )
        if no_later_than is not None and _parsed_timestamp(
            evidence.observed_at
        ) > _parsed_timestamp(no_later_than):
            raise ValueError("evidence cannot be observed after the transition")


class ManufacturingLifecycleScope(_StrictModel):
    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UuidRef
    site_ref: OpaqueRef


def manufacturing_scope_digest(
    scope: ManufacturingLifecycleScope | Mapping[str, Any],
) -> str:
    """Commit exact tenant, company, project UUID, project ref, and site scope."""

    parsed = (
        scope
        if isinstance(scope, ManufacturingLifecycleScope)
        else ManufacturingLifecycleScope.model_validate(scope)
    )
    return _stable_digest(parsed.to_dict())


class ReleasedBomComponent(_StrictModel):
    component_ref: OpaqueRef
    item_ref: OpaqueRef
    quantity_per_unit: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    trace_kind: TraceKind

    @field_validator("quantity_per_unit", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @model_validator(mode="after")
    def _serial_quantity_is_integral(self) -> "ReleasedBomComponent":
        if self.trace_kind == "serial" and self.quantity_per_unit != int(
            self.quantity_per_unit
        ):
            raise ValueError("serial-controlled component quantity must be integral")
        return self


class ReleasedBomSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_released_bom.v1"] = Field(
        default=RELEASED_BOM_SCHEMA,
        alias="schema",
    )
    bom_ref: OpaqueRef
    scope_digest: Sha256Digest
    product_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: Literal["released"] = "released"
    output_unit_of_measure: UnitCode
    effective_from: str
    effective_until: str | None = None
    components: tuple[ReleasedBomComponent, ...] = Field(
        min_length=1,
        max_length=MAX_BOM_COMPONENTS,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("components", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("effective_from")
    @classmethod
    def _effective_from(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_from")

    @field_validator("effective_until")
    @classmethod
    def _effective_until(cls, value: str | None) -> str | None:
        return (
            None if value is None else _timestamp(value, field_name="effective_until")
        )

    @model_validator(mode="after")
    def _released_bom_is_exact(self) -> "ReleasedBomSnapshot":
        _unique_refs(self.components, field_name="component_ref", label="BOM component")
        if self.effective_until is not None and _parsed_timestamp(
            self.effective_until
        ) <= _parsed_timestamp(self.effective_from):
            raise ValueError("effective_until must be after effective_from")
        _require_evidence(
            self.evidence_refs,
            subject_ref=self.bom_ref,
            minimum_grade=PrimitiveEvidenceVerificationGrade.ATTESTED,
        )
        content_digest = released_bom_content_digest(self)
        if any(evidence.sha256 != content_digest for evidence in self.evidence_refs):
            raise ValueError("released BOM evidence must commit the exact BOM content")
        return self


class ReleasedRoutingOperation(_StrictModel):
    sequence: int = Field(ge=1)
    operation_ref: OpaqueRef
    work_center_ref: OpaqueRef
    work_instruction_ref: OpaqueRef
    work_instruction_revision: int = Field(ge=1)
    required_certification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )

    @field_validator("required_certification_refs", mode="before")
    @classmethod
    def _certifications_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _certifications_are_unique(self) -> "ReleasedRoutingOperation":
        if len(self.required_certification_refs) != len(
            set(self.required_certification_refs)
        ):
            raise ValueError("required certification references must be unique")
        return self


class ReleasedRoutingSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_released_routing.v1"] = Field(
        default=RELEASED_ROUTING_SCHEMA,
        alias="schema",
    )
    routing_ref: OpaqueRef
    scope_digest: Sha256Digest
    product_ref: OpaqueRef
    revision: int = Field(ge=1)
    status: Literal["released"] = "released"
    operations: tuple[ReleasedRoutingOperation, ...] = Field(
        min_length=1,
        max_length=MAX_ROUTING_OPERATIONS,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )

    @field_validator("operations", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _released_routing_is_exact(self) -> "ReleasedRoutingSnapshot":
        _unique_refs(
            self.operations, field_name="operation_ref", label="routing operation"
        )
        sequences = [operation.sequence for operation in self.operations]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("routing operations must have unique ascending sequences")
        _require_evidence(
            self.evidence_refs,
            subject_ref=self.routing_ref,
            minimum_grade=PrimitiveEvidenceVerificationGrade.ATTESTED,
        )
        content_digest = released_routing_content_digest(self)
        if any(evidence.sha256 != content_digest for evidence in self.evidence_refs):
            raise ValueError(
                "released routing evidence must commit the exact routing content"
            )
        return self


class ReleasedManufacturingDefinition(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_released_definition.v1"] = Field(
        default=RELEASED_DEFINITION_SCHEMA,
        alias="schema",
    )
    bill_of_material: ReleasedBomSnapshot
    routing: ReleasedRoutingSnapshot
    definition_digest: Sha256Digest

    @model_validator(mode="after")
    def _definition_is_content_bound(self) -> "ReleasedManufacturingDefinition":
        if self.bill_of_material.product_ref != self.routing.product_ref:
            raise ValueError("released BOM and routing must describe the same product")
        if self.bill_of_material.scope_digest != self.routing.scope_digest:
            raise ValueError(
                "released BOM and routing must bind the same exact lifecycle scope"
            )
        expected = _stable_digest(
            {
                "bill_of_material": self.bill_of_material.to_dict(),
                "routing": self.routing.to_dict(),
            }
        )
        if self.definition_digest != expected:
            raise ValueError(
                "definition_digest does not match released BOM and routing"
            )
        return self


def build_released_manufacturing_definition(
    bill_of_material: ReleasedBomSnapshot | Mapping[str, Any],
    routing: ReleasedRoutingSnapshot | Mapping[str, Any],
) -> ReleasedManufacturingDefinition:
    """Validate and content-bind one released BOM/routing pair."""

    bom = revalidate_model_boundary(ReleasedBomSnapshot, bill_of_material)
    route = revalidate_model_boundary(ReleasedRoutingSnapshot, routing)
    digest = _stable_digest(
        {"bill_of_material": bom.to_dict(), "routing": route.to_dict()}
    )
    return ReleasedManufacturingDefinition(
        bill_of_material=bom,
        routing=route,
        definition_digest=digest,
    )


class ProductionOrderPlan(_StrictModel):
    production_order_ref: OpaqueRef
    product_ref: OpaqueRef
    site_ref: OpaqueRef
    planned_quantity: Decimal = Field(gt=0)
    unit_of_measure: UnitCode
    output_trace_kind: TraceKind
    definition_digest: Sha256Digest
    scheduled_start: str
    scheduled_end: str

    @field_validator("planned_quantity", mode="before")
    @classmethod
    def _planned_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("scheduled_start", "scheduled_end")
    @classmethod
    def _timestamps(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _valid_schedule_and_serial_plan(self) -> "ProductionOrderPlan":
        if _parsed_timestamp(self.scheduled_end) <= _parsed_timestamp(
            self.scheduled_start
        ):
            raise ValueError("scheduled_end must be after scheduled_start")
        if self.output_trace_kind == "serial" and self.planned_quantity != int(
            self.planned_quantity
        ):
            raise ValueError("serial-controlled production quantity must be integral")
        return self


class MaterialInputTrace(_StrictModel):
    source_type: Literal["component", "prior_output"]
    source_ref: OpaqueRef
    item_ref: OpaqueRef
    unit_of_measure: UnitCode
    trace_kind: TraceKind
    trace_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)

    @field_validator("quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @model_validator(mode="after")
    def _serial_quantity_is_one(self) -> "MaterialInputTrace":
        if self.trace_kind == "serial" and self.quantity != 1:
            raise ValueError("each serial input trace must have quantity 1")
        return self


class ProducedTrace(_StrictModel):
    item_ref: OpaqueRef
    unit_of_measure: UnitCode
    trace_kind: TraceKind
    trace_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)

    @field_validator("quantity", mode="before")
    @classmethod
    def _positive_quantity(cls, value: Any) -> Decimal:
        return _quantity(value)

    @model_validator(mode="after")
    def _serial_quantity_is_one(self) -> "ProducedTrace":
        if self.trace_kind == "serial" and self.quantity != 1:
            raise ValueError("each serial output trace must have quantity 1")
        return self


class OperationCompletion(_StrictModel):
    operation_ref: OpaqueRef
    sequence: int = Field(ge=1)
    work_center_ref: OpaqueRef
    input_quantity: Decimal = Field(gt=0)
    quantity_completed: Decimal = Field(ge=0)
    quantity_scrapped: Decimal = Field(ge=0)
    operator_ref: OpaqueRef
    certification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    occurred_at: str
    input_traces: tuple[MaterialInputTrace, ...] = Field(
        min_length=1,
        max_length=MAX_TRACES_PER_OPERATION,
    )
    output_traces: tuple[ProducedTrace, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACES_PER_OPERATION,
    )
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )
    transition_request_digest: Sha256Digest

    @field_validator(
        "input_quantity", "quantity_completed", "quantity_scrapped", mode="before"
    )
    @classmethod
    def _quantities(cls, value: Any, info: Any) -> Decimal:
        return _quantity(
            value,
            allow_zero=info.field_name in {"quantity_completed", "quantity_scrapped"},
        )

    @field_validator(
        "certification_refs",
        "input_traces",
        "output_traces",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _completion_is_quantity_sound(self) -> "OperationCompletion":
        if (
            _quantity_add(self.quantity_completed, self.quantity_scrapped)
            != self.input_quantity
        ):
            raise ValueError(
                "completed plus scrapped quantity must equal input quantity"
            )
        if _quantity_sum(tuple(trace.quantity for trace in self.output_traces)) != (
            self.quantity_completed
        ):
            raise ValueError("output trace quantities must equal completed quantity")
        _unique_refs(self.input_traces, field_name="trace_ref", label="input trace")
        _unique_refs(self.output_traces, field_name="trace_ref", label="output trace")
        if len(self.certification_refs) != len(set(self.certification_refs)):
            raise ValueError("certification references must be unique")
        return self


class QualityHold(_StrictModel):
    hold_ref: OpaqueRef
    status: Literal["active", "released"]
    trace_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=MAX_TRACES_PER_OPERATION
    )
    reason_code: OpaqueRef
    held_by_ref: OpaqueRef
    held_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)
    hold_transition_request_digest: Sha256Digest
    released_by_ref: OpaqueRef | None = None
    released_at: str | None = None
    release_approval_ref: OpaqueRef | None = None
    release_approval_evidence_ref: OpaqueRef | None = None
    release_transition_request_digest: Sha256Digest | None = None
    release_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple,
        max_length=50,
    )

    @field_validator(
        "trace_refs", "evidence_refs", "release_evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("held_at")
    @classmethod
    def _held_at(cls, value: str) -> str:
        return _timestamp(value, field_name="held_at")

    @field_validator("released_at")
    @classmethod
    def _released_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="released_at")

    @model_validator(mode="after")
    def _hold_state_is_coherent(self) -> "QualityHold":
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("quality hold trace references must be unique")
        release_fields = (
            self.released_by_ref,
            self.released_at,
            self.release_approval_ref,
            self.release_approval_evidence_ref,
            self.release_transition_request_digest,
        )
        if self.status == "active" and (
            any(value is not None for value in release_fields)
            or self.release_evidence_refs
        ):
            raise ValueError("active quality hold cannot carry release evidence")
        if self.status == "released" and (
            any(value is None for value in release_fields)
            or not self.release_evidence_refs
        ):
            raise ValueError("released quality hold requires exact release evidence")
        if self.released_at is not None and _parsed_timestamp(
            self.released_at
        ) < _parsed_timestamp(self.held_at):
            raise ValueError("quality release cannot precede the hold")
        return self


class Nonconformance(_StrictModel):
    nonconformance_ref: OpaqueRef
    hold_ref: OpaqueRef
    trace_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=MAX_TRACES_PER_OPERATION
    )
    severity: Literal["minor", "major", "critical"]
    description_digest: Sha256Digest
    status: Literal["open", "closed"]
    opened_by_ref: OpaqueRef
    opened_at: str
    opening_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1,
        max_length=50,
    )
    opening_transition_request_digest: Sha256Digest
    closed_by_ref: OpaqueRef | None = None
    closed_at: str | None = None
    disposition: Literal["use_as_is", "scrap"] | None = None
    concession_ref: OpaqueRef | None = None
    concession_evidence_ref: OpaqueRef | None = None
    capa_ref: OpaqueRef | None = None
    capa_evidence_ref: OpaqueRef | None = None
    closure_evidence_ref: OpaqueRef | None = None
    closure_transition_request_digest: Sha256Digest | None = None
    closure_evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple,
        max_length=50,
    )

    @field_validator(
        "trace_refs", "opening_evidence_refs", "closure_evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("opened_at")
    @classmethod
    def _opened_at(cls, value: str) -> str:
        return _timestamp(value, field_name="opened_at")

    @field_validator("closed_at")
    @classmethod
    def _closed_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="closed_at")

    @model_validator(mode="after")
    def _nonconformance_state_is_coherent(self) -> "Nonconformance":
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("nonconformance trace references must be unique")
        closure_fields = (
            self.closed_by_ref,
            self.closed_at,
            self.disposition,
            self.closure_evidence_ref,
            self.closure_transition_request_digest,
        )
        if self.status == "open" and (
            any(value is not None for value in closure_fields)
            or self.concession_ref is not None
            or self.concession_evidence_ref is not None
            or self.capa_ref is not None
            or self.capa_evidence_ref is not None
            or self.closure_evidence_refs
        ):
            raise ValueError("open nonconformance cannot carry closure fields")
        if self.status == "closed" and (
            any(value is None for value in closure_fields)
            or not self.closure_evidence_refs
        ):
            raise ValueError("closed nonconformance requires complete closure evidence")
        if self.disposition != "use_as_is" and self.concession_ref is not None:
            raise ValueError("concession_ref is valid only for use_as_is")
        if (self.concession_ref is None) != (self.concession_evidence_ref is None):
            raise ValueError(
                "concession reference and evidence must be present together"
            )
        if (self.capa_ref is None) != (self.capa_evidence_ref is None):
            raise ValueError("CAPA reference and evidence must be present together")
        if self.disposition == "use_as_is" and self.severity in {"major", "critical"}:
            if self.concession_ref is None:
                raise ValueError("major or critical use_as_is requires a concession")
        if (
            self.severity == "critical"
            and self.status == "closed"
            and self.capa_ref is None
        ):
            raise ValueError("critical nonconformance closure requires CAPA evidence")
        if self.closed_at is not None and _parsed_timestamp(
            self.closed_at
        ) < _parsed_timestamp(self.opened_at):
            raise ValueError("nonconformance closure cannot precede opening")
        return self


class MaterializedCandidateManufacturingTransition(_StrictModel):
    transition_ref: OpaqueRef
    actor_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: Literal[
        "create_production_order",
        "complete_operation",
        "place_quality_hold",
        "open_nonconformance",
        "close_nonconformance",
        "release_quality_hold",
    ]
    occurred_at: str
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=1)
    expected_snapshot_digest: Sha256Digest
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)
    evidence_digest: Sha256Digest

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @model_validator(mode="after")
    def _version_advances_once(
        self,
    ) -> "MaterializedCandidateManufacturingTransition":
        if self.to_version != self.from_version + 1:
            raise ValueError("each manufacturing transition must advance one version")
        if self.from_version == 0 and (
            self.expected_snapshot_digest != GENESIS_SNAPSHOT_DIGEST
        ):
            raise ValueError(
                "the first transition must bind the genesis snapshot digest"
            )
        minimum_grade = (
            PrimitiveEvidenceVerificationGrade.VERIFIED
            if self.command_kind in {"close_nonconformance", "release_quality_hold"}
            else PrimitiveEvidenceVerificationGrade.ATTESTED
        )
        _require_evidence(
            self.evidence_refs,
            subject_ref=self.transition_ref,
            minimum_grade=minimum_grade,
            no_later_than=self.occurred_at,
        )
        if self.evidence_digest != _evidence_digest(self.evidence_refs):
            raise ValueError("transition evidence_digest does not match evidence")
        return self


OrderStatus = Literal[
    "released",
    "in_process",
    "awaiting_quality",
    "on_quality_hold",
    "completed",
    "scrapped",
]


class ManufacturingOrderState(_StrictModel):
    plan: ProductionOrderPlan
    status: OrderStatus
    operation_completions: tuple[OperationCompletion, ...] = Field(
        default_factory=tuple,
        max_length=MAX_ROUTING_OPERATIONS,
    )
    quality_hold: QualityHold | None = None
    nonconformances: tuple[Nonconformance, ...] = Field(
        default_factory=tuple,
        max_length=MAX_NONCONFORMANCES,
    )
    completed_quantity: Decimal = Field(ge=0)

    @field_validator("operation_completions", "nonconformances", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("completed_quantity", mode="before")
    @classmethod
    def _completed_quantity(cls, value: Any) -> Decimal:
        return _quantity(value, allow_zero=True)

    @model_validator(mode="after")
    def _order_state_is_coherent(self) -> "ManufacturingOrderState":
        _unique_refs(
            self.operation_completions,
            field_name="operation_ref",
            label="operation completion",
        )
        _unique_refs(
            self.nonconformances,
            field_name="nonconformance_ref",
            label="nonconformance",
        )
        if self.completed_quantity > self.plan.planned_quantity:
            raise ValueError("completed quantity cannot exceed planned quantity")
        if self.status == "on_quality_hold" and (
            self.quality_hold is None or self.quality_hold.status != "active"
        ):
            raise ValueError("on_quality_hold requires one active quality hold")
        if self.status == "completed" and (
            self.quality_hold is None or self.quality_hold.status != "released"
        ):
            raise ValueError("completed order requires an independently released hold")
        if (
            self.status not in {"on_quality_hold", "completed", "scrapped"}
            and self.quality_hold is not None
        ):
            raise ValueError("quality hold state does not match order status")
        if (
            self.status == "scrapped"
            and self.quality_hold is not None
            and self.quality_hold.status != "released"
        ):
            raise ValueError("quality-scrapped order requires a disposed quality hold")
        if self.status != "completed" and self.completed_quantity != 0:
            raise ValueError("only a completed order may report completed_quantity")
        return self


class ManufacturingExecutionLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_execution_lifecycle_snapshot.v2"] = (
        Field(default=MANUFACTURING_LIFECYCLE_SNAPSHOT_SCHEMA, alias="schema")
    )
    scope: ManufacturingLifecycleScope
    definition: ReleasedManufacturingDefinition
    order: ManufacturingOrderState
    version: int = Field(ge=1, le=MAX_LIFECYCLE_TRANSITIONS)
    transition_history: tuple[MaterializedCandidateManufacturingTransition, ...] = (
        Field(
            min_length=1,
            max_length=MAX_LIFECYCLE_TRANSITIONS,
        )
    )
    state_digest: Sha256Digest

    @field_validator("transition_history", mode="before")
    @classmethod
    def _history_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_is_exact_and_bounded(
        self,
    ) -> "ManufacturingExecutionLifecycleSnapshot":
        if self.version != len(self.transition_history):
            raise ValueError(
                "snapshot version must equal materialized candidate transition count"
            )
        if [item.to_version for item in self.transition_history] != list(
            range(1, self.version + 1)
        ):
            raise ValueError("transition history must be contiguous")
        if (
            len({item.transition_ref for item in self.transition_history})
            != self.version
        ):
            raise ValueError("transition references must be unique")
        if (
            len({item.idempotency_key for item in self.transition_history})
            != self.version
        ):
            raise ValueError("idempotency keys must be unique")
        if (
            len({item.request_digest for item in self.transition_history})
            != self.version
        ):
            raise ValueError("transition request digests must be unique")
        if self.transition_history[0].command_kind != "create_production_order" or any(
            item.command_kind == "create_production_order"
            for item in self.transition_history[1:]
        ):
            raise ValueError(
                "exactly the first transition must create the production order"
            )
        transition_times = [
            _parsed_timestamp(item.occurred_at) for item in self.transition_history
        ]
        if transition_times != sorted(transition_times):
            raise ValueError("transition history timestamps must be monotonic")
        if self.order.plan.site_ref != self.scope.site_ref:
            raise ValueError("production order site must match lifecycle scope")
        if self.order.plan.product_ref != self.definition.bill_of_material.product_ref:
            raise ValueError("production order product must match released definition")
        if (
            self.order.plan.unit_of_measure
            != self.definition.bill_of_material.output_unit_of_measure
        ):
            raise ValueError(
                "production order unit must match the released product unit"
            )
        if self.order.plan.definition_digest != self.definition.definition_digest:
            raise ValueError("production order must pin the released definition digest")
        routing = self.definition.routing.operations
        completions = self.order.operation_completions
        if [item.operation_ref for item in completions] != [
            item.operation_ref for item in routing[: len(completions)]
        ]:
            raise ValueError("operation completions must be an ordered routing prefix")
        transitions_by_request = {
            item.request_digest: item for item in self.transition_history
        }

        def command_base(
            transition: MaterializedCandidateManufacturingTransition,
        ) -> dict[str, Any]:
            return {
                "kind": transition.command_kind,
                "scope": self.scope.to_dict(),
                "transition_ref": transition.transition_ref,
                "actor_ref": transition.actor_ref,
                "idempotency_key": transition.idempotency_key,
                "expected_version": transition.from_version,
                "expected_snapshot_digest": transition.expected_snapshot_digest,
                "occurred_at": transition.occurred_at,
                "evidence_refs": [
                    item.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_none=True,
                    )
                    for item in transition.evidence_refs
                ],
            }

        creation = self.transition_history[0]
        creation_payload = command_base(creation)
        creation_payload.update(
            {
                "definition": self.definition.to_dict(),
                "order_plan": self.order.plan.to_dict(),
            }
        )
        if manufacturing_command_digest(creation_payload) != creation.request_digest:
            raise ValueError(
                "production order does not match its creation request digest"
            )
        known_trace_refs: set[str] = set()
        previous: OperationCompletion | None = None
        for completion, operation in zip(
            completions,
            routing[: len(completions)],
            strict=True,
        ):
            if (
                completion.sequence != operation.sequence
                or completion.work_center_ref != operation.work_center_ref
            ):
                raise ValueError(
                    "operation completion must match the released routing step"
                )
            if not set(operation.required_certification_refs).issubset(
                completion.certification_refs
            ):
                raise ValueError("operation completion lacks required certification")
            transition = transitions_by_request.get(
                completion.transition_request_digest
            )
            if (
                transition is None
                or transition.command_kind != "complete_operation"
                or transition.occurred_at != completion.occurred_at
                or transition.evidence_refs != completion.evidence_refs
            ):
                raise ValueError("operation completion lacks exact transition evidence")
            completion_payload = command_base(transition)
            completion_payload.update(
                {
                    "operation_ref": completion.operation_ref,
                    "work_center_ref": completion.work_center_ref,
                    "quantity_completed": completion.quantity_completed,
                    "quantity_scrapped": completion.quantity_scrapped,
                    "operator_ref": completion.operator_ref,
                    "certification_refs": list(completion.certification_refs),
                    "input_traces": [
                        item.to_dict() for item in completion.input_traces
                    ],
                    "output_traces": [
                        item.to_dict() for item in completion.output_traces
                    ],
                }
            )
            if (
                manufacturing_command_digest(completion_payload)
                != transition.request_digest
            ):
                raise ValueError(
                    "operation completion does not match its request digest"
                )
            input_quantity = (
                self.order.plan.planned_quantity
                if previous is None
                else previous.quantity_completed
            )
            if completion.input_quantity != input_quantity:
                raise ValueError("operation input quantity breaks routing continuity")
            if previous is None:
                components = {
                    item.component_ref: item
                    for item in self.definition.bill_of_material.components
                }
                grouped: dict[str, list[MaterialInputTrace]] = defaultdict(list)
                for trace in completion.input_traces:
                    if trace.source_type != "component":
                        raise ValueError("first operation must consume BOM components")
                    grouped[trace.source_ref].append(trace)
                if set(grouped) != set(components):
                    raise ValueError("first operation does not cover the released BOM")
                for component_ref, component in components.items():
                    traces = grouped[component_ref]
                    if any(
                        trace.item_ref != component.item_ref
                        or trace.unit_of_measure != component.unit_of_measure
                        or trace.trace_kind != component.trace_kind
                        for trace in traces
                    ):
                        raise ValueError("first-operation trace does not match the BOM")
                    expected_quantity = _quantity_multiply(
                        component.quantity_per_unit, input_quantity
                    )
                    if (
                        _quantity_sum(tuple(trace.quantity for trace in traces))
                        != expected_quantity
                    ):
                        raise ValueError(
                            "first-operation trace quantity does not match the BOM"
                        )
            else:
                if any(
                    trace.source_type != "prior_output"
                    or trace.source_ref != previous.operation_ref
                    for trace in completion.input_traces
                ):
                    raise ValueError("later operation must consume the prior operation")
                actual_inputs = sorted(
                    _trace_identity(trace) for trace in completion.input_traces
                )
                expected_inputs = sorted(
                    _trace_identity(trace) for trace in previous.output_traces
                )
                if actual_inputs != expected_inputs:
                    raise ValueError("operation genealogy is discontinuous")
            if any(
                trace.item_ref != self.order.plan.product_ref
                or trace.unit_of_measure != self.order.plan.unit_of_measure
                or trace.trace_kind != self.order.plan.output_trace_kind
                for trace in completion.output_traces
            ):
                raise ValueError("operation output traces do not match the order")
            output_refs_for_step = {
                trace.trace_ref for trace in completion.output_traces
            }
            input_refs_for_step = {trace.trace_ref for trace in completion.input_traces}
            if output_refs_for_step & (known_trace_refs | input_refs_for_step):
                raise ValueError("operation output trace reference was reused")
            known_trace_refs.update(input_refs_for_step)
            known_trace_refs.update(output_refs_for_step)
            previous = completion
        all_complete = len(completions) == len(routing)
        expected_kind_counts = {
            "create_production_order": 1,
            "complete_operation": len(completions),
            "place_quality_hold": 1 if self.order.quality_hold is not None else 0,
            "open_nonconformance": len(self.order.nonconformances),
            "close_nonconformance": sum(
                record.status == "closed" for record in self.order.nonconformances
            ),
            "release_quality_hold": (
                1
                if self.order.quality_hold is not None
                and self.order.quality_hold.status == "released"
                else 0
            ),
        }
        for kind, expected_count in expected_kind_counts.items():
            actual_count = sum(
                item.command_kind == kind for item in self.transition_history
            )
            if actual_count != expected_count:
                raise ValueError(f"transition history count does not match {kind}")
        if self.order.status == "released" and completions:
            raise ValueError("released order cannot contain operation completions")
        if self.order.status == "in_process" and (not completions or all_complete):
            raise ValueError("in_process order requires a strict routing prefix")
        if self.order.status == "scrapped":
            shop_floor_scrap = (
                bool(completions)
                and completions[-1].quantity_completed == 0
                and self.order.quality_hold is None
            )
            quality_scrap = (
                all_complete
                and self.order.quality_hold is not None
                and self.order.quality_hold.status == "released"
                and self.order.completed_quantity == 0
            )
            if not (shop_floor_scrap or quality_scrap):
                raise ValueError(
                    "scrapped order requires shop-floor or quality-disposition evidence"
                )
        if (
            self.order.status in {"awaiting_quality", "on_quality_hold", "completed"}
            and not all_complete
        ):
            raise ValueError(
                "quality disposition requires every routing operation complete"
            )
        output_refs = [
            trace.trace_ref
            for completion in completions
            for trace in completion.output_traces
        ]
        if len(output_refs) != len(set(output_refs)):
            raise ValueError("output trace references must be globally unique")
        if self.order.quality_hold is not None:
            hold = self.order.quality_hold
            final_refs = {trace.trace_ref for trace in completions[-1].output_traces}
            if set(hold.trace_refs) != final_refs:
                raise ValueError("quality hold must bind every final output trace")
            hold_transition = transitions_by_request.get(
                hold.hold_transition_request_digest
            )
            if (
                hold_transition is None
                or hold_transition.command_kind != "place_quality_hold"
                or hold_transition.occurred_at != hold.held_at
                or hold_transition.evidence_refs != hold.evidence_refs
            ):
                raise ValueError("quality hold lacks exact transition evidence")
            hold_payload = command_base(hold_transition)
            hold_payload.update(
                {
                    "hold_ref": hold.hold_ref,
                    "trace_refs": list(hold.trace_refs),
                    "reason_code": hold.reason_code,
                    "held_by_ref": hold.held_by_ref,
                }
            )
            if (
                manufacturing_command_digest(hold_payload)
                != hold_transition.request_digest
            ):
                raise ValueError("quality hold does not match its request digest")
            for record in self.order.nonconformances:
                if record.hold_ref != hold.hold_ref:
                    raise ValueError("nonconformance must bind the active order hold")
                if not set(record.trace_refs).issubset(final_refs):
                    raise ValueError("nonconformance references unknown final traces")
                opening = transitions_by_request.get(
                    record.opening_transition_request_digest
                )
                if (
                    opening is None
                    or opening.command_kind != "open_nonconformance"
                    or opening.occurred_at != record.opened_at
                    or opening.evidence_refs != record.opening_evidence_refs
                ):
                    raise ValueError("nonconformance lacks exact opening evidence")
                opening_payload = command_base(opening)
                opening_payload.update(
                    {
                        "nonconformance_ref": record.nonconformance_ref,
                        "hold_ref": record.hold_ref,
                        "trace_refs": list(record.trace_refs),
                        "severity": record.severity,
                        "description_digest": record.description_digest,
                        "opened_by_ref": record.opened_by_ref,
                    }
                )
                if (
                    manufacturing_command_digest(opening_payload)
                    != opening.request_digest
                ):
                    raise ValueError(
                        "nonconformance does not match its opening request"
                    )
                if record.status == "closed":
                    assert record.closure_transition_request_digest is not None
                    closure = transitions_by_request.get(
                        record.closure_transition_request_digest
                    )
                    if (
                        closure is None
                        or closure.command_kind != "close_nonconformance"
                        or closure.occurred_at != record.closed_at
                        or closure.evidence_refs != record.closure_evidence_refs
                    ):
                        raise ValueError("nonconformance lacks exact closure evidence")
                    closure_payload = command_base(closure)
                    closure_payload.update(
                        {
                            "nonconformance_ref": record.nonconformance_ref,
                            "closed_by_ref": record.closed_by_ref,
                            "disposition": record.disposition,
                            "closure_evidence_ref": record.closure_evidence_ref,
                        }
                    )
                    if record.concession_ref is not None:
                        closure_payload["concession_ref"] = record.concession_ref
                        closure_payload["concession_evidence_ref"] = (
                            record.concession_evidence_ref
                        )
                    if record.capa_ref is not None:
                        closure_payload["capa_ref"] = record.capa_ref
                        closure_payload["capa_evidence_ref"] = record.capa_evidence_ref
                    if (
                        manufacturing_command_digest(closure_payload)
                        != closure.request_digest
                    ):
                        raise ValueError(
                            "nonconformance does not match its closure request"
                        )
            if hold.status == "released":
                assert hold.release_transition_request_digest is not None
                release = transitions_by_request.get(
                    hold.release_transition_request_digest
                )
                if (
                    release is None
                    or release.command_kind != "release_quality_hold"
                    or release.occurred_at != hold.released_at
                    or release.evidence_refs != hold.release_evidence_refs
                ):
                    raise ValueError("quality release lacks exact transition evidence")
                release_payload = command_base(release)
                release_payload.update(
                    {
                        "hold_ref": hold.hold_ref,
                        "released_by_ref": hold.released_by_ref,
                        "approval_ref": hold.release_approval_ref,
                        "approval_evidence_ref": hold.release_approval_evidence_ref,
                    }
                )
                if (
                    manufacturing_command_digest(release_payload)
                    != release.request_digest
                ):
                    raise ValueError(
                        "quality release does not match its request digest"
                    )
                if any(
                    record.status != "closed" for record in self.order.nonconformances
                ):
                    raise ValueError(
                        "completed order cannot retain open nonconformance"
                    )
                prohibited_actors = {
                    hold.held_by_ref,
                    *(item.operator_ref for item in completions),
                    *(item.opened_by_ref for item in self.order.nonconformances),
                    *(
                        item.closed_by_ref
                        for item in self.order.nonconformances
                        if item.closed_by_ref is not None
                    ),
                }
                if hold.released_by_ref in prohibited_actors:
                    raise ValueError("quality release is not independent")
                trace_quantities = {
                    trace.trace_ref: trace.quantity
                    for trace in completions[-1].output_traces
                }
                scrapped_refs = {
                    trace_ref
                    for record in self.order.nonconformances
                    if record.disposition == "scrap"
                    for trace_ref in record.trace_refs
                }
                accepted_quantity = _quantity_sum(
                    tuple(
                        quantity
                        for trace_ref, quantity in trace_quantities.items()
                        if trace_ref not in scrapped_refs
                    )
                )
                if self.order.completed_quantity != accepted_quantity:
                    raise ValueError(
                        "completed quantity does not match quality disposition"
                    )
        expected = manufacturing_snapshot_digest(self, validate=False)
        if self.state_digest != expected:
            raise ValueError(
                "state_digest does not match manufacturing lifecycle state"
            )
        return self


def manufacturing_snapshot_digest(
    snapshot: ManufacturingExecutionLifecycleSnapshot | Mapping[str, Any],
    *,
    validate: bool = True,
) -> str:
    """Return the canonical digest excluding the snapshot's digest field."""

    if isinstance(snapshot, ManufacturingExecutionLifecycleSnapshot):
        payload = snapshot.model_dump(mode="json", by_alias=True, exclude_none=True)
    elif validate:
        parsed = ManufacturingExecutionLifecycleSnapshot.model_validate(snapshot)
        payload = parsed.model_dump(mode="json", by_alias=True, exclude_none=True)
    else:
        payload = dict(snapshot)
    payload.pop("state_digest", None)
    return _stable_digest(payload)


class _CommandBase(_StrictModel):
    scope: ManufacturingLifecycleScope
    transition_ref: OpaqueRef
    actor_ref: OpaqueRef
    idempotency_key: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_LIFECYCLE_TRANSITIONS)
    expected_snapshot_digest: Sha256Digest
    occurred_at: str
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)
    request_digest: Sha256Digest

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _request_is_content_bound(self, info: ValidationInfo) -> "_CommandBase":
        skip_digest = bool(
            info.context and info.context.get("skip_manufacturing_request_digest")
        )
        if not skip_digest and self.request_digest != manufacturing_command_digest(
            self
        ):
            raise ValueError("request_digest does not match the transition command")
        _require_evidence(
            self.evidence_refs,
            subject_ref=self.transition_ref,
            minimum_grade=self.minimum_evidence_grade(),
            no_later_than=self.occurred_at,
        )
        return self

    def minimum_evidence_grade(self) -> PrimitiveEvidenceVerificationGrade:
        return PrimitiveEvidenceVerificationGrade.ATTESTED


class CreateProductionOrderCommand(_CommandBase):
    kind: Literal["create_production_order"] = "create_production_order"
    definition: ReleasedManufacturingDefinition
    order_plan: ProductionOrderPlan

    @model_validator(mode="after")
    def _starts_at_genesis(self) -> "CreateProductionOrderCommand":
        if (
            self.expected_version != 0
            or self.expected_snapshot_digest != GENESIS_SNAPSHOT_DIGEST
        ):
            raise ValueError(
                "production-order creation must bind the genesis version and digest"
            )
        expected_scope_digest = manufacturing_scope_digest(self.scope)
        if (
            self.definition.bill_of_material.scope_digest != expected_scope_digest
            or self.definition.routing.scope_digest != expected_scope_digest
        ):
            raise ValueError(
                "released definition must bind the exact production-order scope"
            )
        return self


class CompleteOperationCommand(_CommandBase):
    kind: Literal["complete_operation"] = "complete_operation"
    operation_ref: OpaqueRef
    work_center_ref: OpaqueRef
    quantity_completed: Decimal = Field(ge=0)
    quantity_scrapped: Decimal = Field(ge=0)
    operator_ref: OpaqueRef
    certification_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    input_traces: tuple[MaterialInputTrace, ...] = Field(
        min_length=1,
        max_length=MAX_TRACES_PER_OPERATION,
    )
    output_traces: tuple[ProducedTrace, ...] = Field(
        default_factory=tuple,
        max_length=MAX_TRACES_PER_OPERATION,
    )

    @field_validator("quantity_completed", "quantity_scrapped", mode="before")
    @classmethod
    def _quantities(cls, value: Any, info: Any) -> Decimal:
        return _quantity(
            value,
            allow_zero=info.field_name in {"quantity_completed", "quantity_scrapped"},
        )

    @field_validator(
        "certification_refs", "input_traces", "output_traces", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _traces_are_unique(self) -> "CompleteOperationCommand":
        _unique_refs(self.input_traces, field_name="trace_ref", label="input trace")
        _unique_refs(self.output_traces, field_name="trace_ref", label="output trace")
        if len(self.certification_refs) != len(set(self.certification_refs)):
            raise ValueError("certification references must be unique")
        if self.actor_ref != self.operator_ref:
            raise ValueError("actor_ref must exactly match operator_ref")
        return self


class PlaceQualityHoldCommand(_CommandBase):
    kind: Literal["place_quality_hold"] = "place_quality_hold"
    hold_ref: OpaqueRef
    trace_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=MAX_TRACES_PER_OPERATION
    )
    reason_code: OpaqueRef
    held_by_ref: OpaqueRef

    @field_validator("trace_refs", mode="before")
    @classmethod
    def _traces_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _traces_are_unique(self) -> "PlaceQualityHoldCommand":
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("quality hold trace references must be unique")
        if self.actor_ref != self.held_by_ref:
            raise ValueError("actor_ref must exactly match held_by_ref")
        return self


class OpenNonconformanceCommand(_CommandBase):
    kind: Literal["open_nonconformance"] = "open_nonconformance"
    nonconformance_ref: OpaqueRef
    hold_ref: OpaqueRef
    trace_refs: tuple[OpaqueRef, ...] = Field(
        min_length=1, max_length=MAX_TRACES_PER_OPERATION
    )
    severity: Literal["minor", "major", "critical"]
    description_digest: Sha256Digest
    opened_by_ref: OpaqueRef

    @field_validator("trace_refs", mode="before")
    @classmethod
    def _traces_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _traces_are_unique(self) -> "OpenNonconformanceCommand":
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("nonconformance trace references must be unique")
        if self.actor_ref != self.opened_by_ref:
            raise ValueError("actor_ref must exactly match opened_by_ref")
        return self


class CloseNonconformanceCommand(_CommandBase):
    kind: Literal["close_nonconformance"] = "close_nonconformance"
    nonconformance_ref: OpaqueRef
    closed_by_ref: OpaqueRef
    disposition: Literal["use_as_is", "scrap"]
    closure_evidence_ref: OpaqueRef
    concession_ref: OpaqueRef | None = None
    concession_evidence_ref: OpaqueRef | None = None
    capa_ref: OpaqueRef | None = None
    capa_evidence_ref: OpaqueRef | None = None

    def minimum_evidence_grade(self) -> PrimitiveEvidenceVerificationGrade:
        return PrimitiveEvidenceVerificationGrade.VERIFIED

    @model_validator(mode="after")
    def _closure_evidence_is_exact(self) -> "CloseNonconformanceCommand":
        if self.actor_ref != self.closed_by_ref:
            raise ValueError("actor_ref must exactly match closed_by_ref")
        if not any(
            evidence.evidence_ref == self.closure_evidence_ref
            and evidence.kind == "nonconformance_closure"
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "closure_evidence_ref must select verified nonconformance_closure evidence"
            )
        if (self.concession_ref is None) != (self.concession_evidence_ref is None):
            raise ValueError(
                "concession reference and evidence must be present together"
            )
        if self.concession_evidence_ref is not None and not any(
            evidence.evidence_ref == self.concession_evidence_ref
            and evidence.kind == "quality_concession_approval"
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "concession_evidence_ref must select verified concession approval evidence"
            )
        if (self.capa_ref is None) != (self.capa_evidence_ref is None):
            raise ValueError("CAPA reference and evidence must be present together")
        if self.capa_evidence_ref is not None and not any(
            evidence.evidence_ref == self.capa_evidence_ref
            and evidence.kind == "capa_verification"
            for evidence in self.evidence_refs
        ):
            raise ValueError("capa_evidence_ref must select verified CAPA evidence")
        return self


class ReleaseQualityHoldCommand(_CommandBase):
    kind: Literal["release_quality_hold"] = "release_quality_hold"
    hold_ref: OpaqueRef
    released_by_ref: OpaqueRef
    approval_ref: OpaqueRef
    approval_evidence_ref: OpaqueRef

    def minimum_evidence_grade(self) -> PrimitiveEvidenceVerificationGrade:
        return PrimitiveEvidenceVerificationGrade.VERIFIED

    @model_validator(mode="after")
    def _approval_evidence_is_exact(self) -> "ReleaseQualityHoldCommand":
        if self.actor_ref != self.released_by_ref:
            raise ValueError("actor_ref must exactly match released_by_ref")
        if not any(
            evidence.evidence_ref == self.approval_evidence_ref
            and evidence.kind == "quality_release_approval"
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "approval_evidence_ref must select verified quality_release_approval evidence"
            )
        return self


ManufacturingLifecycleCommand = Annotated[
    CreateProductionOrderCommand
    | CompleteOperationCommand
    | PlaceQualityHoldCommand
    | OpenNonconformanceCommand
    | CloseNonconformanceCommand
    | ReleaseQualityHoldCommand,
    Field(discriminator="kind"),
]

_COMMAND_MODELS: dict[str, type[_CommandBase]] = {
    "create_production_order": CreateProductionOrderCommand,
    "complete_operation": CompleteOperationCommand,
    "place_quality_hold": PlaceQualityHoldCommand,
    "open_nonconformance": OpenNonconformanceCommand,
    "close_nonconformance": CloseNonconformanceCommand,
    "release_quality_hold": ReleaseQualityHoldCommand,
}


def manufacturing_command_digest(command: BaseModel | Mapping[str, Any]) -> str:
    """Digest all command fields except the self-describing request digest."""

    payload = (
        command.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(command, BaseModel)
        else dict(command)
    )
    payload.pop("request_digest", None)
    payload.pop("schema", None)
    return _stable_digest(payload)


def seal_manufacturing_command(command: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize, validate, and seal a command with its exact request digest."""

    payload = dict(command)
    kind = payload.get("kind")
    command_model = _COMMAND_MODELS.get(kind) if isinstance(kind, str) else None
    if command_model is None:
        raise ValueError("kind must identify a supported manufacturing command")
    payload["request_digest"] = GENESIS_SNAPSHOT_DIGEST
    parsed = command_model.model_validate(
        payload,
        context={"skip_manufacturing_request_digest": True},
    )
    canonical = parsed.model_dump(mode="json", by_alias=True, exclude_none=True)
    canonical.pop("request_digest", None)
    canonical["request_digest"] = manufacturing_command_digest(canonical)
    return canonical


class ManufacturingExecutionLifecycleInput(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_execution_lifecycle_input.v2"] = Field(
        default=MANUFACTURING_LIFECYCLE_INPUT_SCHEMA, alias="schema"
    )
    scope: ManufacturingLifecycleScope
    command: ManufacturingLifecycleCommand
    current_snapshot: ManufacturingExecutionLifecycleSnapshot | None = None

    @model_validator(mode="after")
    def _scope_and_genesis_are_exact(self) -> "ManufacturingExecutionLifecycleInput":
        creating = isinstance(self.command, CreateProductionOrderCommand)
        if not creating and self.current_snapshot is None:
            raise ValueError("every non-creation command requires a current snapshot")
        if (
            self.current_snapshot is not None
            and self.current_snapshot.scope != self.scope
        ):
            raise ValueError(
                "input scope must exactly match the current snapshot scope"
            )
        if self.command.scope != self.scope:
            raise ValueError(
                "command scope must exactly match the lifecycle input scope"
            )
        return self


RecoveryDisposition = Literal[
    "not_required",
    "refresh_snapshot",
    "do_not_replay",
    "correct_state",
]


class ManufacturingTransitionRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def _instructions_match_disposition(self) -> "ManufacturingTransitionRecovery":
        if (self.disposition == "not_required") != (self.instructions is None):
            raise ValueError(
                "only unresolved transition recovery requires instructions"
            )
        return self


class ManufacturingTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_execution_transition_receipt.v2"] = (
        Field(default=MANUFACTURING_TRANSITION_RECEIPT_SCHEMA, alias="schema")
    )
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: str = Field(min_length=1, max_length=80)
    status: Literal["candidate_materialized", "rejected"]
    from_version: int = Field(ge=0)
    to_version: int = Field(ge=0)
    from_snapshot_digest: Sha256Digest
    to_snapshot_digest: Sha256Digest
    evidence_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: ManufacturingTransitionRecovery
    replayed: Literal[False] = False
    live_systems_changed: Literal[False] = False
    authoritative_write_authorized: Literal[False] = False

    @model_validator(mode="after")
    def _receipt_is_truthful(self) -> "ManufacturingTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1:
                raise ValueError(
                    "materialized candidate transition must advance one version"
                )
            if self.from_snapshot_digest == self.to_snapshot_digest:
                raise ValueError(
                    "materialized candidate transition must change the snapshot digest"
                )
            if (
                self.rejection_code is not None
                or self.recovery.disposition != "not_required"
            ):
                raise ValueError(
                    "materialized candidate transition cannot carry rejection recovery"
                )
        else:
            if self.to_version != self.from_version:
                raise ValueError("rejected transition cannot advance a version")
            if self.to_snapshot_digest != self.from_snapshot_digest:
                raise ValueError("rejected transition cannot mutate the snapshot")
            if (
                self.rejection_code is None
                or self.recovery.disposition == "not_required"
            ):
                raise ValueError(
                    "rejected transition requires a code and recovery route"
                )
        return self


class ManufacturingExecutionLifecycleResult(_StrictModel):
    schema_id: Literal["lightbulb.manufacturing_execution_lifecycle_result.v2"] = Field(
        default=MANUFACTURING_LIFECYCLE_RESULT_SCHEMA, alias="schema"
    )
    candidate_materialized: bool
    snapshot: ManufacturingExecutionLifecycleSnapshot | None = None
    transition_receipt: ManufacturingTransitionReceipt
    live_systems_changed: Literal[False] = False
    authoritative_write_authorized: Literal[False] = False

    @model_validator(mode="after")
    def _materialization_matches_receipt(
        self,
    ) -> "ManufacturingExecutionLifecycleResult":
        if self.candidate_materialized != (
            self.transition_receipt.status == "candidate_materialized"
        ):
            raise ValueError("candidate_materialized must match the transition receipt")
        if self.candidate_materialized and (
            self.snapshot is None
            or self.snapshot.state_digest != self.transition_receipt.to_snapshot_digest
        ):
            raise ValueError(
                "materialized candidate transition must return its exact projection snapshot"
            )
        return self


MANUFACTURING_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="manufacturing-execution.materialize-candidate-projection",
    tool="manufacturing.materialize_execution_candidate_projection",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class _TransitionRejected(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        recovery_disposition: Literal[
            "refresh_snapshot",
            "do_not_replay",
            "correct_state",
        ],
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.recovery_disposition = recovery_disposition


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest(
        [
            evidence.to_dict()
            for evidence in sorted(evidence_refs, key=lambda item: item.evidence_ref)
        ]
    )


def _snapshot_data(
    *,
    scope: ManufacturingLifecycleScope,
    definition: ReleasedManufacturingDefinition,
    order: ManufacturingOrderState,
    version: int,
    history: Sequence[MaterializedCandidateManufacturingTransition],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": MANUFACTURING_LIFECYCLE_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "definition": definition.to_dict(),
        "order": order.to_dict(),
        "version": version,
        "transition_history": [item.to_dict() for item in history],
    }
    payload["state_digest"] = _stable_digest(payload)
    return payload


def _materialize_snapshot(
    *,
    scope: ManufacturingLifecycleScope,
    definition: ReleasedManufacturingDefinition,
    order: ManufacturingOrderState,
    version: int,
    history: Sequence[MaterializedCandidateManufacturingTransition],
) -> ManufacturingExecutionLifecycleSnapshot:
    return ManufacturingExecutionLifecycleSnapshot.model_validate(
        _snapshot_data(
            scope=scope,
            definition=definition,
            order=order,
            version=version,
            history=history,
        )
    )


def _replace_order(
    order: ManufacturingOrderState,
    **updates: Any,
) -> ManufacturingOrderState:
    payload = order.to_dict()
    payload.update(updates)
    return ManufacturingOrderState.model_validate(payload)


def _reject(
    inputs: ManufacturingExecutionLifecycleInput,
    error: _TransitionRejected,
) -> ManufacturingExecutionLifecycleResult:
    command = inputs.command
    snapshot = inputs.current_snapshot
    version = snapshot.version if snapshot is not None else 0
    digest = snapshot.state_digest if snapshot is not None else GENESIS_SNAPSHOT_DIGEST
    return ManufacturingExecutionLifecycleResult(
        candidate_materialized=False,
        snapshot=snapshot,
        transition_receipt=ManufacturingTransitionReceipt(
            transition_ref=command.transition_ref,
            idempotency_key=command.idempotency_key,
            request_digest=command.request_digest,
            command_kind=command.kind,
            status="rejected",
            from_version=version,
            to_version=version,
            from_snapshot_digest=digest,
            to_snapshot_digest=digest,
            evidence_digest=_evidence_digest(command.evidence_refs),
            rejection_code=error.code,
            recovery=ManufacturingTransitionRecovery(
                disposition=error.recovery_disposition,
                instructions=error.message,
            ),
        ),
    )


def _check_transition_header(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: _CommandBase,
) -> None:
    if snapshot.version >= MAX_LIFECYCLE_TRANSITIONS:
        raise _TransitionRejected(
            "TRANSITION_LIMIT_REACHED",
            "The bounded lifecycle transition limit has been reached.",
            "correct_state",
        )
    by_ref = next(
        (
            item
            for item in snapshot.transition_history
            if item.transition_ref == command.transition_ref
        ),
        None,
    )
    by_key = next(
        (
            item
            for item in snapshot.transition_history
            if item.idempotency_key == command.idempotency_key
        ),
        None,
    )
    existing = by_ref or by_key
    if existing is not None:
        same = (
            existing.transition_ref == command.transition_ref
            and existing.idempotency_key == command.idempotency_key
            and existing.request_digest == command.request_digest
        )
        raise _TransitionRejected(
            "DUPLICATE_TRANSITION" if same else "IDEMPOTENCY_CONFLICT",
            (
                "This exact candidate transition was already materialized and must "
                "not be replayed."
                if same
                else "The transition reference or idempotency key is bound to another request."
            ),
            "do_not_replay",
        )
    if command.expected_version != snapshot.version or (
        command.expected_snapshot_digest != snapshot.state_digest
    ):
        raise _TransitionRejected(
            "STALE_SNAPSHOT",
            "Refresh the current candidate projection and issue a new transition identity.",
            "refresh_snapshot",
        )
    if _parsed_timestamp(command.occurred_at) < _parsed_timestamp(
        snapshot.transition_history[-1].occurred_at
    ):
        raise _TransitionRejected(
            "NON_MONOTONIC_TRANSITION_TIME",
            "Transition time cannot precede the latest materialized candidate transition.",
            "correct_state",
        )


def _creation_order(
    scope: ManufacturingLifecycleScope,
    command: CreateProductionOrderCommand,
) -> ManufacturingOrderState:
    definition = command.definition
    plan = command.order_plan
    expected_scope_digest = manufacturing_scope_digest(scope)
    if (
        definition.bill_of_material.scope_digest != expected_scope_digest
        or definition.routing.scope_digest != expected_scope_digest
    ):
        raise _TransitionRejected(
            "RELEASE_SCOPE_MISMATCH",
            "Released BOM and routing must bind the exact lifecycle scope.",
            "correct_state",
        )
    if plan.product_ref != definition.bill_of_material.product_ref:
        raise _TransitionRejected(
            "PRODUCT_MISMATCH",
            "Production order product must match the released definition.",
            "correct_state",
        )
    if plan.unit_of_measure != definition.bill_of_material.output_unit_of_measure:
        raise _TransitionRejected(
            "PRODUCT_UNIT_MISMATCH",
            "Production order unit must match the released BOM product unit.",
            "correct_state",
        )
    if plan.site_ref != scope.site_ref:
        raise _TransitionRejected(
            "SITE_SCOPE_MISMATCH",
            "Production order site must match the exact lifecycle scope.",
            "correct_state",
        )
    if plan.definition_digest != definition.definition_digest:
        raise _TransitionRejected(
            "DEFINITION_DIGEST_MISMATCH",
            "Production order must pin the exact released definition digest.",
            "correct_state",
        )
    if any(
        _parsed_timestamp(evidence.observed_at) > _parsed_timestamp(command.occurred_at)
        for evidence in (
            *definition.bill_of_material.evidence_refs,
            *definition.routing.evidence_refs,
        )
    ):
        raise _TransitionRejected(
            "FUTURE_DEFINITION_EVIDENCE",
            "Released BOM and routing evidence must predate order creation.",
            "correct_state",
        )
    for component in definition.bill_of_material.components:
        required_quantity = _quantity_multiply(
            component.quantity_per_unit, plan.planned_quantity
        )
        if component.trace_kind == "serial" and required_quantity != int(
            required_quantity
        ):
            raise _TransitionRejected(
                "IMPOSSIBLE_SERIAL_REQUIREMENT",
                (
                    f"Serial-controlled component {component.component_ref} "
                    "requires a non-integral quantity for this order."
                ),
                "correct_state",
            )
    start = _parsed_timestamp(plan.scheduled_start)
    bom = definition.bill_of_material
    if start < _parsed_timestamp(bom.effective_from) or (
        bom.effective_until is not None
        and start >= _parsed_timestamp(bom.effective_until)
    ):
        raise _TransitionRejected(
            "BOM_NOT_EFFECTIVE_FOR_SCHEDULE",
            "Released BOM is not effective at the scheduled production start.",
            "correct_state",
        )
    if _parsed_timestamp(command.occurred_at) > start:
        raise _TransitionRejected(
            "ORDER_CREATED_AFTER_SCHEDULE_START",
            "Production order must be created no later than its scheduled start.",
            "correct_state",
        )
    return ManufacturingOrderState(
        plan=plan,
        status="released",
        completed_quantity=Decimal(0),
    )


def _trace_identity(trace: MaterialInputTrace | ProducedTrace) -> tuple[Any, ...]:
    return (
        trace.item_ref,
        trace.unit_of_measure,
        trace.trace_kind,
        trace.trace_ref,
        trace.quantity,
    )


def _validate_first_operation_inputs(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: CompleteOperationCommand,
    input_quantity: Decimal,
) -> None:
    components = {
        component.component_ref: component
        for component in snapshot.definition.bill_of_material.components
    }
    grouped: dict[str, list[MaterialInputTrace]] = defaultdict(list)
    for trace in command.input_traces:
        if trace.source_type != "component":
            raise _TransitionRejected(
                "INVALID_FIRST_OPERATION_SOURCE",
                "First operation inputs must bind released BOM components.",
                "correct_state",
            )
        grouped[trace.source_ref].append(trace)
    if set(grouped) != set(components):
        raise _TransitionRejected(
            "BOM_COMPONENT_COVERAGE_MISMATCH",
            "First operation inputs must cover every and only released BOM component.",
            "correct_state",
        )
    for component_ref, component in components.items():
        traces = grouped[component_ref]
        if any(
            trace.item_ref != component.item_ref
            or trace.unit_of_measure != component.unit_of_measure
            or trace.trace_kind != component.trace_kind
            for trace in traces
        ):
            raise _TransitionRejected(
                "BOM_TRACE_BINDING_MISMATCH",
                f"Input traces do not match released BOM component {component_ref}.",
                "correct_state",
            )
        expected = _quantity_multiply(component.quantity_per_unit, input_quantity)
        actual = _quantity_sum(tuple(trace.quantity for trace in traces))
        if actual != expected:
            raise _TransitionRejected(
                "BOM_QUANTITY_MISMATCH",
                f"Input quantity for component {component_ref} must equal {expected}.",
                "correct_state",
            )


def _validate_prior_operation_inputs(
    previous: OperationCompletion,
    command: CompleteOperationCommand,
) -> None:
    if any(
        trace.source_type != "prior_output"
        or trace.source_ref != previous.operation_ref
        for trace in command.input_traces
    ):
        raise _TransitionRejected(
            "INVALID_PRIOR_OUTPUT_SOURCE",
            "Later operation inputs must bind the immediately preceding operation.",
            "correct_state",
        )
    actual = sorted(_trace_identity(trace) for trace in command.input_traces)
    expected = sorted(_trace_identity(trace) for trace in previous.output_traces)
    if actual != expected:
        raise _TransitionRejected(
            "GENEALOGY_DISCONTINUITY",
            "Later operation inputs must exactly consume the preceding output traces.",
            "correct_state",
        )


def _complete_operation(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: CompleteOperationCommand,
) -> ManufacturingOrderState:
    order = snapshot.order
    if order.status not in {"released", "in_process"}:
        raise _TransitionRejected(
            "ORDER_NOT_EXECUTABLE",
            "Operations may complete only on released or in-process orders.",
            "correct_state",
        )
    if _parsed_timestamp(command.occurred_at) < _parsed_timestamp(
        order.plan.scheduled_start
    ):
        raise _TransitionRejected(
            "OPERATION_BEFORE_SCHEDULE_START",
            "Shop-floor completion cannot precede the scheduled production start.",
            "correct_state",
        )
    routing = snapshot.definition.routing.operations
    completion_index = len(order.operation_completions)
    if completion_index >= len(routing):
        raise _TransitionRejected(
            "ROUTING_ALREADY_COMPLETE",
            "Every released routing operation is already complete.",
            "do_not_replay",
        )
    operation = routing[completion_index]
    if command.operation_ref != operation.operation_ref:
        raise _TransitionRejected(
            "OUT_OF_SEQUENCE_OPERATION",
            f"Next operation must be {operation.operation_ref}.",
            "correct_state",
        )
    if command.work_center_ref != operation.work_center_ref:
        raise _TransitionRejected(
            "WORK_CENTER_MISMATCH",
            "Operation completion must bind the released work center.",
            "correct_state",
        )
    if not set(operation.required_certification_refs).issubset(
        command.certification_refs
    ):
        raise _TransitionRejected(
            "OPERATOR_CERTIFICATION_MISSING",
            "Operation completion lacks a released-routing certification.",
            "correct_state",
        )
    previous = order.operation_completions[-1] if order.operation_completions else None
    input_quantity = (
        order.plan.planned_quantity if previous is None else previous.quantity_completed
    )
    if (
        _quantity_add(command.quantity_completed, command.quantity_scrapped)
        != input_quantity
    ):
        raise _TransitionRejected(
            "IMPOSSIBLE_OPERATION_QUANTITY",
            "Completed plus scrapped quantity must exactly equal available input quantity.",
            "correct_state",
        )
    if previous is None:
        _validate_first_operation_inputs(snapshot, command, input_quantity)
    else:
        _validate_prior_operation_inputs(previous, command)
    output_total = _quantity_sum(
        tuple(trace.quantity for trace in command.output_traces)
    )
    if output_total != command.quantity_completed:
        raise _TransitionRejected(
            "OUTPUT_QUANTITY_MISMATCH",
            "Output trace quantities must equal completed quantity.",
            "correct_state",
        )
    if any(
        trace.item_ref != order.plan.product_ref
        or trace.unit_of_measure != order.plan.unit_of_measure
        or trace.trace_kind != order.plan.output_trace_kind
        for trace in command.output_traces
    ):
        raise _TransitionRejected(
            "OUTPUT_TRACE_BINDING_MISMATCH",
            "Output traces must bind the order product and configured trace kind.",
            "correct_state",
        )
    known_trace_refs = {
        trace.trace_ref
        for completion in order.operation_completions
        for trace in (*completion.input_traces, *completion.output_traces)
    }
    command_output_refs = {trace.trace_ref for trace in command.output_traces}
    command_input_refs = {trace.trace_ref for trace in command.input_traces}
    if len(command_output_refs) != len(command.output_traces) or (
        command_output_refs & (known_trace_refs | command_input_refs)
    ):
        raise _TransitionRejected(
            "OUTPUT_TRACE_REUSE",
            "Every operation must mint new output trace references.",
            "do_not_replay",
        )
    completion = OperationCompletion(
        operation_ref=operation.operation_ref,
        sequence=operation.sequence,
        work_center_ref=operation.work_center_ref,
        input_quantity=input_quantity,
        quantity_completed=command.quantity_completed,
        quantity_scrapped=command.quantity_scrapped,
        operator_ref=command.operator_ref,
        certification_refs=command.certification_refs,
        occurred_at=command.occurred_at,
        input_traces=command.input_traces,
        output_traces=command.output_traces,
        evidence_refs=command.evidence_refs,
        transition_request_digest=command.request_digest,
    )
    completions = (*order.operation_completions, completion)
    status: OrderStatus
    if command.quantity_completed == 0:
        status = "scrapped"
    else:
        status = (
            "awaiting_quality" if len(completions) == len(routing) else "in_process"
        )
    return _replace_order(
        order,
        status=status,
        operation_completions=[item.to_dict() for item in completions],
    )


def _place_quality_hold(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: PlaceQualityHoldCommand,
) -> ManufacturingOrderState:
    order = snapshot.order
    if order.status != "awaiting_quality" or order.quality_hold is not None:
        raise _TransitionRejected(
            "ORDER_NOT_AWAITING_QUALITY",
            "A quality hold may be placed once, after every routing operation completes.",
            "correct_state",
        )
    final_refs = {
        trace.trace_ref for trace in order.operation_completions[-1].output_traces
    }
    if set(command.trace_refs) != final_refs:
        raise _TransitionRejected(
            "QUALITY_HOLD_TRACE_COVERAGE_MISMATCH",
            "Quality hold must bind every and only final output trace.",
            "correct_state",
        )
    hold = QualityHold(
        hold_ref=command.hold_ref,
        status="active",
        trace_refs=command.trace_refs,
        reason_code=command.reason_code,
        held_by_ref=command.held_by_ref,
        held_at=command.occurred_at,
        evidence_refs=command.evidence_refs,
        hold_transition_request_digest=command.request_digest,
    )
    return _replace_order(order, status="on_quality_hold", quality_hold=hold.to_dict())


def _open_nonconformance(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: OpenNonconformanceCommand,
) -> ManufacturingOrderState:
    order = snapshot.order
    hold = order.quality_hold
    if order.status != "on_quality_hold" or hold is None or hold.status != "active":
        raise _TransitionRejected(
            "ACTIVE_QUALITY_HOLD_REQUIRED",
            "Nonconformance must bind an active quality hold.",
            "correct_state",
        )
    if command.hold_ref != hold.hold_ref:
        raise _TransitionRejected(
            "QUALITY_HOLD_MISMATCH",
            "Nonconformance must bind the exact active hold.",
            "correct_state",
        )
    if any(
        record.nonconformance_ref == command.nonconformance_ref
        for record in order.nonconformances
    ):
        raise _TransitionRejected(
            "DUPLICATE_NONCONFORMANCE",
            "Nonconformance reference already exists.",
            "do_not_replay",
        )
    if len(order.nonconformances) >= MAX_NONCONFORMANCES:
        raise _TransitionRejected(
            "NONCONFORMANCE_LIMIT_REACHED",
            "The bounded nonconformance limit has been reached.",
            "correct_state",
        )
    if not set(command.trace_refs).issubset(hold.trace_refs):
        raise _TransitionRejected(
            "UNKNOWN_NONCONFORMANCE_TRACE",
            "Nonconformance references a trace outside the active hold.",
            "correct_state",
        )
    existing_traces = {
        trace_ref for record in order.nonconformances for trace_ref in record.trace_refs
    }
    if set(command.trace_refs) & existing_traces:
        raise _TransitionRejected(
            "OVERLAPPING_NONCONFORMANCE_TRACE",
            "A final trace may belong to only one order nonconformance.",
            "correct_state",
        )
    record = Nonconformance(
        nonconformance_ref=command.nonconformance_ref,
        hold_ref=hold.hold_ref,
        trace_refs=command.trace_refs,
        severity=command.severity,
        description_digest=command.description_digest,
        status="open",
        opened_by_ref=command.opened_by_ref,
        opened_at=command.occurred_at,
        opening_evidence_refs=command.evidence_refs,
        opening_transition_request_digest=command.request_digest,
    )
    records = (*order.nonconformances, record)
    return _replace_order(
        order,
        nonconformances=[item.to_dict() for item in records],
    )


def _close_nonconformance(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: CloseNonconformanceCommand,
) -> ManufacturingOrderState:
    order = snapshot.order
    hold = order.quality_hold
    if order.status != "on_quality_hold" or hold is None or hold.status != "active":
        raise _TransitionRejected(
            "ACTIVE_QUALITY_HOLD_REQUIRED",
            "Nonconformance closure requires the exact active hold.",
            "correct_state",
        )
    index = next(
        (
            position
            for position, record in enumerate(order.nonconformances)
            if record.nonconformance_ref == command.nonconformance_ref
        ),
        None,
    )
    if index is None:
        raise _TransitionRejected(
            "NONCONFORMANCE_NOT_FOUND",
            "Nonconformance is not present in this scoped order.",
            "correct_state",
        )
    record = order.nonconformances[index]
    if record.status != "open":
        raise _TransitionRejected(
            "NONCONFORMANCE_ALREADY_CLOSED",
            "Closed nonconformance must not be replayed.",
            "do_not_replay",
        )
    if command.closed_by_ref == record.opened_by_ref:
        raise _TransitionRejected(
            "NONCONFORMANCE_CLOSURE_NOT_INDEPENDENT",
            "Nonconformance closer must differ from the opener.",
            "correct_state",
        )
    if command.disposition != "use_as_is" and command.concession_ref is not None:
        raise _TransitionRejected(
            "UNEXPECTED_CONCESSION",
            "Concession evidence is valid only for use_as_is.",
            "correct_state",
        )
    if command.disposition == "use_as_is" and record.severity in {"major", "critical"}:
        if command.concession_ref is None:
            raise _TransitionRejected(
                "CONCESSION_REQUIRED",
                "Major or critical use_as_is requires an exact concession reference.",
                "correct_state",
            )
    if record.severity == "critical" and command.capa_ref is None:
        raise _TransitionRejected(
            "CAPA_REQUIRED",
            "Critical nonconformance closure requires a CAPA reference.",
            "correct_state",
        )
    closed = record.to_dict()
    closed.update(
        {
            "status": "closed",
            "closed_by_ref": command.closed_by_ref,
            "closed_at": command.occurred_at,
            "disposition": command.disposition,
            "concession_ref": command.concession_ref,
            "concession_evidence_ref": command.concession_evidence_ref,
            "capa_ref": command.capa_ref,
            "capa_evidence_ref": command.capa_evidence_ref,
            "closure_evidence_ref": command.closure_evidence_ref,
            "closure_transition_request_digest": command.request_digest,
            "closure_evidence_refs": [item.to_dict() for item in command.evidence_refs],
        }
    )
    records = list(order.nonconformances)
    records[index] = Nonconformance.model_validate(closed)
    return _replace_order(
        order,
        nonconformances=[item.to_dict() for item in records],
    )


def _release_quality_hold(
    snapshot: ManufacturingExecutionLifecycleSnapshot,
    command: ReleaseQualityHoldCommand,
) -> ManufacturingOrderState:
    order = snapshot.order
    hold = order.quality_hold
    if order.status != "on_quality_hold" or hold is None or hold.status != "active":
        raise _TransitionRejected(
            "ACTIVE_QUALITY_HOLD_REQUIRED",
            "Quality release requires the exact active hold.",
            "correct_state",
        )
    if command.hold_ref != hold.hold_ref:
        raise _TransitionRejected(
            "QUALITY_HOLD_MISMATCH",
            "Quality release must bind the exact active hold.",
            "correct_state",
        )
    open_records = [
        record for record in order.nonconformances if record.status != "closed"
    ]
    if open_records:
        raise _TransitionRejected(
            "OPEN_NONCONFORMANCE",
            "Every nonconformance must be independently closed before quality release.",
            "correct_state",
        )
    prohibited_actors = {
        hold.held_by_ref,
        *(completion.operator_ref for completion in order.operation_completions),
        *(record.opened_by_ref for record in order.nonconformances),
        *(
            record.closed_by_ref
            for record in order.nonconformances
            if record.closed_by_ref is not None
        ),
    }
    if command.released_by_ref in prohibited_actors:
        raise _TransitionRejected(
            "QUALITY_RELEASE_NOT_INDEPENDENT",
            "Quality releaser must differ from operators, holder, and nonconformance actors.",
            "correct_state",
        )
    final_outputs = order.operation_completions[-1].output_traces
    trace_quantities = {trace.trace_ref: trace.quantity for trace in final_outputs}
    scrapped_refs = {
        trace_ref
        for record in order.nonconformances
        if record.disposition == "scrap"
        for trace_ref in record.trace_refs
    }
    accepted_quantity = _quantity_sum(
        tuple(
            quantity
            for trace_ref, quantity in trace_quantities.items()
            if trace_ref not in scrapped_refs
        )
    )
    if accepted_quantity < 0 or accepted_quantity > order.plan.planned_quantity:
        raise _TransitionRejected(
            "IMPOSSIBLE_RELEASE_QUANTITY",
            "Quality disposition quantity must remain within the production plan.",
            "correct_state",
        )
    released_hold = hold.to_dict()
    released_hold.update(
        {
            "status": "released",
            "released_by_ref": command.released_by_ref,
            "released_at": command.occurred_at,
            "release_approval_ref": command.approval_ref,
            "release_approval_evidence_ref": command.approval_evidence_ref,
            "release_transition_request_digest": command.request_digest,
            "release_evidence_refs": [item.to_dict() for item in command.evidence_refs],
        }
    )
    return _replace_order(
        order,
        status="scrapped" if accepted_quantity == 0 else "completed",
        completed_quantity=accepted_quantity,
        quality_hold=released_hold,
    )


def _materialize_candidate_transition(
    inputs: ManufacturingExecutionLifecycleInput,
) -> ManufacturingExecutionLifecycleSnapshot:
    command = inputs.command
    if isinstance(command, CreateProductionOrderCommand):
        if inputs.current_snapshot is not None:
            _check_transition_header(inputs.current_snapshot, command)
            raise _TransitionRejected(
                "CREATION_ALREADY_MATERIALIZED",
                "A lifecycle snapshot already exists for this production order.",
                "do_not_replay",
            )
        order = _creation_order(inputs.scope, command)
        version = 1
        history: tuple[MaterializedCandidateManufacturingTransition, ...] = ()
        definition = command.definition
    else:
        snapshot = inputs.current_snapshot
        assert snapshot is not None
        _check_transition_header(snapshot, command)
        if isinstance(command, CompleteOperationCommand):
            order = _complete_operation(snapshot, command)
        elif isinstance(command, PlaceQualityHoldCommand):
            order = _place_quality_hold(snapshot, command)
        elif isinstance(command, OpenNonconformanceCommand):
            order = _open_nonconformance(snapshot, command)
        elif isinstance(command, CloseNonconformanceCommand):
            order = _close_nonconformance(snapshot, command)
        else:
            order = _release_quality_hold(snapshot, command)
        version = snapshot.version + 1
        history = snapshot.transition_history
        definition = snapshot.definition
    materialized_candidate = MaterializedCandidateManufacturingTransition(
        transition_ref=command.transition_ref,
        actor_ref=command.actor_ref,
        idempotency_key=command.idempotency_key,
        request_digest=command.request_digest,
        command_kind=command.kind,
        occurred_at=command.occurred_at,
        from_version=version - 1,
        to_version=version,
        expected_snapshot_digest=command.expected_snapshot_digest,
        evidence_refs=command.evidence_refs,
        evidence_digest=_evidence_digest(command.evidence_refs),
    )
    return _materialize_snapshot(
        scope=inputs.scope,
        definition=definition,
        order=order,
        version=version,
        history=(*history, materialized_candidate),
    )


def advance_manufacturing_execution_lifecycle(
    inputs: ManufacturingExecutionLifecycleInput | Mapping[str, Any],
) -> ManufacturingExecutionLifecycleResult:
    """Materialize one bounded candidate projection without external mutation."""

    parsed = revalidate_model_boundary(ManufacturingExecutionLifecycleInput, inputs)
    command = parsed.command
    from_snapshot = parsed.current_snapshot
    from_version = from_snapshot.version if from_snapshot is not None else 0
    from_digest = (
        from_snapshot.state_digest
        if from_snapshot is not None
        else GENESIS_SNAPSHOT_DIGEST
    )
    try:
        snapshot = _materialize_candidate_transition(parsed)
    except _TransitionRejected as exc:
        return _reject(parsed, exc)
    receipt = ManufacturingTransitionReceipt(
        transition_ref=command.transition_ref,
        idempotency_key=command.idempotency_key,
        request_digest=command.request_digest,
        command_kind=command.kind,
        status="candidate_materialized",
        from_version=from_version,
        to_version=snapshot.version,
        from_snapshot_digest=from_digest,
        to_snapshot_digest=snapshot.state_digest,
        evidence_digest=_evidence_digest(command.evidence_refs),
        recovery=ManufacturingTransitionRecovery(disposition="not_required"),
    )
    return ManufacturingExecutionLifecycleResult(
        candidate_materialized=True,
        snapshot=snapshot,
        transition_receipt=receipt,
    )


def _scope_matches_context(
    inputs: ManufacturingExecutionLifecycleInput,
    context: PrimitiveExecutionContext,
) -> bool:
    scope = inputs.scope
    command = inputs.command
    return (
        scope.tenant_ref == context.scope.tenant_ref
        and scope.company_ref == context.scope.company_ref
        and scope.project_ref == context.scope.project_ref
        and context.scope.project_id is not None
        and scope.project_id == str(context.scope.project_id)
        and context.scope.actor_ref is not None
        and command.actor_ref == context.scope.actor_ref
        and context.idempotency_key is not None
        and command.idempotency_key == context.idempotency_key
    )


def _manufacturing_lifecycle_example_inputs() -> dict[str, Any]:
    scope = {
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "123e4567-e89b-42d3-a456-426614174401",
        "site_ref": "plant-example",
    }
    release_scope_digest = manufacturing_scope_digest(
        ManufacturingLifecycleScope.model_validate(scope)
    )
    bom: dict[str, Any] = {
        "schema": RELEASED_BOM_SCHEMA,
        "bom_ref": "bom-example",
        "scope_digest": release_scope_digest,
        "product_ref": "product-example",
        "revision": 1,
        "status": "released",
        "output_unit_of_measure": "EA",
        "effective_from": "2026-01-01T00:00:00Z",
        "components": [
            {
                "component_ref": "component-example",
                "item_ref": "material-example",
                "quantity_per_unit": "1",
                "unit_of_measure": "EA",
                "trace_kind": "lot",
            }
        ],
    }
    bom["evidence_refs"] = [
        {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": "evidence-bom-example",
            "kind": "released_bom_snapshot",
            "issuer_ref": "spring-manufacturing-authority",
            "subject_ref": "bom-example",
            "sha256": released_bom_content_digest(bom),
            "observed_at": "2026-08-24T08:00:00Z",
            "verification_grade": "attested",
            "classification": "confidential",
        }
    ]
    routing: dict[str, Any] = {
        "schema": RELEASED_ROUTING_SCHEMA,
        "routing_ref": "routing-example",
        "scope_digest": release_scope_digest,
        "product_ref": "product-example",
        "revision": 1,
        "status": "released",
        "operations": [
            {
                "sequence": 10,
                "operation_ref": "operation-example",
                "work_center_ref": "work-center-example",
                "work_instruction_ref": "work-instruction-example",
                "work_instruction_revision": 1,
                "required_certification_refs": [],
            }
        ],
    }
    routing["evidence_refs"] = [
        {
            "schema": "lightbulb.primitive_evidence_ref.v1",
            "evidence_ref": "evidence-routing-example",
            "kind": "released_routing_snapshot",
            "issuer_ref": "spring-manufacturing-authority",
            "subject_ref": "routing-example",
            "sha256": released_routing_content_digest(routing),
            "observed_at": "2026-08-24T08:05:00Z",
            "verification_grade": "attested",
            "classification": "confidential",
        }
    ]
    definition = build_released_manufacturing_definition(bom, routing)
    transition_ref = "transition-create-example"
    command = seal_manufacturing_command(
        {
            "kind": "create_production_order",
            "scope": scope,
            "transition_ref": transition_ref,
            "actor_ref": "manufacturing-planner-example",
            "idempotency_key": "idem-create-example",
            "expected_version": 0,
            "expected_snapshot_digest": GENESIS_SNAPSHOT_DIGEST,
            "occurred_at": "2026-08-25T09:00:00Z",
            "evidence_refs": [
                {
                    "schema": "lightbulb.primitive_evidence_ref.v1",
                    "evidence_ref": "evidence-create-example",
                    "kind": "production_order_creation",
                    "issuer_ref": "spring-manufacturing-authority",
                    "subject_ref": transition_ref,
                    "sha256": _stable_digest("production-order-example"),
                    "observed_at": "2026-08-25T09:00:00Z",
                    "verification_grade": "attested",
                    "classification": "confidential",
                }
            ],
            "definition": definition.to_dict(),
            "order_plan": {
                "production_order_ref": "production-order-example",
                "product_ref": "product-example",
                "site_ref": "plant-example",
                "planned_quantity": "1",
                "unit_of_measure": "EA",
                "output_trace_kind": "lot",
                "definition_digest": definition.definition_digest,
                "scheduled_start": "2026-08-25T10:00:00Z",
                "scheduled_end": "2026-08-25T12:00:00Z",
            },
        }
    )
    return {"scope": scope, "command": command}


class AdvanceManufacturingExecutionLifecyclePrimitive(
    BusinessProcessPrimitive[
        ManufacturingExecutionLifecycleInput,
        ManufacturingExecutionLifecycleResult,
    ]
):
    primitive_ref = "manufacturing.advance_execution_lifecycle"
    version = "2.0.0"
    title = "Advance a bounded manufacturing execution lifecycle"
    description = (
        "Materialize one scope-, version-, evidence-, and idempotency-bound SDK "
        "candidate projection without changing ERP, MES, QMS, inventory, or "
        "provider state."
    )
    input_model = ManufacturingExecutionLifecycleInput
    output_model = ManufacturingExecutionLifecycleResult
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _manufacturing_lifecycle_example_inputs()

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["effect_boundary"] = {
            "sdk_projection_only": True,
            "live_systems_changed": False,
            "authoritative_write_authorized": False,
            "spring_authority_required_for_live_effects": True,
            "connector_or_provider_claims": False,
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_LIFECYCLE_TRANSITIONS,
            "scope_binding": (
                "exact_tenant_company_project_ref_project_uuid_site_"
                "actor_and_idempotency"
            ),
            "stale_snapshot_policy": "reject",
            "duplicate_transition_policy": "reject_without_reapply",
            "ambiguous_external_outcomes": "not_applicable_no_external_dispatch",
            "quality_release_separation_of_duties": (
                "structural_proposal_only_spring_must_verify_actor_roles_and_approval"
            ),
            "genesis_idempotency_authority": "durable_spring_ledger_required",
            "lot_serial_genealogy_required": True,
            "quantity_contract": (
                "decimal_string_or_Decimal_only_max_1e18_max_9_places_"
                "fixed_64_digit_arithmetic_context"
            ),
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ManufacturingExecutionLifecycleInput,
    ) -> PrimitiveExecutionResult[ManufacturingExecutionLifecycleResult]:
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project ref/project UUID, actor, and "
                    "idempotency must exactly match the manufacturing lifecycle input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[ManufacturingExecutionLifecycleResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary=(
                    "Manufacturing lifecycle candidate rejected at the trusted "
                    "runtime boundary."
                ),
                blockers=[blocker],
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=MANUFACTURING_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.command.request_digest,
                        evidence_refs=list(inputs.command.evidence_refs),
                        error=blocker,
                    )
                ],
            )
        output = advance_manufacturing_execution_lifecycle(inputs)
        receipt_status = (
            PrimitiveOperationStatus.PREVIEW
            if output.candidate_materialized
            else PrimitiveOperationStatus.BLOCKED
        )
        blocker = None
        if not output.candidate_materialized:
            blocker = PrimitiveBlocker(
                code=output.transition_receipt.rejection_code or "TRANSITION_REJECTED",
                message=(
                    output.transition_receipt.recovery.instructions
                    or "Manufacturing lifecycle transition rejected."
                ),
                retryable=False,
            )
        operation_receipt = PrimitiveOperationReceipt(
            spec=MANUFACTURING_TRANSITION_OPERATION,
            status=receipt_status,
            request_digest=inputs.command.request_digest,
            evidence_refs=list(inputs.command.evidence_refs),
            external_refs=(
                {
                    "candidate_projection_digest": output.snapshot.state_digest,
                    "transition_ref": inputs.command.transition_ref,
                }
                if output.candidate_materialized and output.snapshot is not None
                else {}
            ),
            error=blocker,
        )
        events = []
        if output.candidate_materialized and output.snapshot is not None:
            events.append(
                PrimitiveEvent(
                    type=("manufacturing.execution_candidate_projection_materialized"),
                    payload={
                        "production_order_ref": output.snapshot.order.plan.production_order_ref,
                        "transition_ref": inputs.command.transition_ref,
                        "transition_kind": inputs.command.kind,
                        "candidate_materialized": True,
                        "candidate_projection_version": output.snapshot.version,
                        "candidate_projection_digest": output.snapshot.state_digest,
                        "candidate_order_status": output.snapshot.order.status,
                        "live_systems_changed": False,
                        "authoritative_write_authorized": False,
                    },
                )
            )
        return PrimitiveExecutionResult[ManufacturingExecutionLifecycleResult](
            status=(
                PrimitiveExecutionStatus.PREVIEW
                if output.candidate_materialized
                else PrimitiveExecutionStatus.BLOCKED
            ),
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Manufacturing lifecycle candidate projection materialized; no "
                "authoritative or live state changed."
                if output.candidate_materialized
                else (
                    "Manufacturing lifecycle candidate rejected without candidate "
                    "projection or live-state mutation."
                )
            ),
            output=output,
            events=events,
            evidence=[
                PrimitiveEvidence(
                    kind="manufacturing_execution_candidate_projection",
                    summary=(
                        "Content-bound SDK candidate projection receipt; Spring "
                        "remains the authority for any durable or external effect."
                    ),
                    refs={
                        "transition_ref": inputs.command.transition_ref,
                        "request_digest": inputs.command.request_digest,
                    },
                )
            ],
            evidence_refs=list(inputs.command.evidence_refs),
            operation_receipts=[operation_receipt],
            blockers=[] if blocker is None else [blocker],
            retryable=False,
        )


MANUFACTURING_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (AdvanceManufacturingExecutionLifecyclePrimitive(),)

# Deprecated compatibility name retained for the package facade during the v2
# migration. New callers should use the explicit candidate-projection type.
AppliedManufacturingTransition = MaterializedCandidateManufacturingTransition


__all__ = [
    "AdvanceManufacturingExecutionLifecyclePrimitive",
    "AppliedManufacturingTransition",
    "CloseNonconformanceCommand",
    "CompleteOperationCommand",
    "CreateProductionOrderCommand",
    "GENESIS_SNAPSHOT_DIGEST",
    "MANUFACTURING_EXECUTION_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "MANUFACTURING_LIFECYCLE_INPUT_SCHEMA",
    "MANUFACTURING_LIFECYCLE_RESULT_SCHEMA",
    "MANUFACTURING_LIFECYCLE_SNAPSHOT_SCHEMA",
    "MANUFACTURING_TRANSITION_RECEIPT_SCHEMA",
    "MANUFACTURING_TRANSITION_OPERATION",
    "ManufacturingExecutionLifecycleInput",
    "ManufacturingExecutionLifecycleResult",
    "ManufacturingExecutionLifecycleSnapshot",
    "ManufacturingLifecycleCommand",
    "ManufacturingLifecycleScope",
    "MaterializedCandidateManufacturingTransition",
    "ManufacturingOrderState",
    "ManufacturingTransitionReceipt",
    "ManufacturingTransitionRecovery",
    "MaterialInputTrace",
    "Nonconformance",
    "OpenNonconformanceCommand",
    "OperationCompletion",
    "PlaceQualityHoldCommand",
    "ProducedTrace",
    "ProductionOrderPlan",
    "QualityHold",
    "ReleaseQualityHoldCommand",
    "ReleasedBomComponent",
    "ReleasedBomSnapshot",
    "ReleasedManufacturingDefinition",
    "ReleasedRoutingOperation",
    "ReleasedRoutingSnapshot",
    "RELEASED_BOM_SCHEMA",
    "RELEASED_DEFINITION_SCHEMA",
    "RELEASED_ROUTING_SCHEMA",
    "advance_manufacturing_execution_lifecycle",
    "build_released_manufacturing_definition",
    "manufacturing_command_digest",
    "manufacturing_scope_digest",
    "manufacturing_snapshot_digest",
    "released_bom_content_digest",
    "released_routing_content_digest",
    "seal_manufacturing_command",
]
