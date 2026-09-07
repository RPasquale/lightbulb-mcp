"""EHS, recall, and field-quality control evaluation for physical operations.

The primitive evaluates normalized evidence only.  It never stops work, files
an incident, quarantines inventory, initiates a recall, notifies a regulator or
customer, closes CAPA, or mutates a manufacturing/quality system of record.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
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


FIELD_QUALITY_CONTROL_INPUT_SCHEMA = "lightbulb.field_quality_control_input.v1"
FIELD_QUALITY_CONTROL_RESULT_SCHEMA = "lightbulb.field_quality_control_result.v1"

OpaqueRef = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
    ),
]
FindingCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,119}$")]

FieldQualityGate = Literal["evidence", "ehs", "field_quality", "traceability", "recall"]
FieldQualityStatus = Literal["pass", "fail", "indeterminate"]
FieldQualityDisposition = Literal[
    "controls_satisfied", "manual_review_required", "blocked", "indeterminate"
]

_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}
_REQUIRED_EVIDENCE_KINDS = (
    "ehs_program",
    "field_quality_register",
    "product_traceability",
    "recall_readiness",
)
_ZERO_DIGEST = "0" * 64


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


class EhsIncident(_StrictModel):
    incident_ref: OpaqueRef
    severity: Literal["minor", "recordable", "serious", "fatal"]
    occurred_at: str
    reportable: bool
    regulator_reported: bool
    investigation_status: Literal["not_started", "in_progress", "complete"]
    corrective_action_status: Literal[
        "not_required", "open", "implemented", "effectiveness_verified"
    ]
    work_stop_required: bool
    work_stopped: bool
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("occurred_at")
    @classmethod
    def _incident_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="occurred_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class EhsProgramSnapshot(_StrictModel):
    company_ref: OpaqueRef
    site_ref: OpaqueRef
    workforce_count: int = Field(ge=1, le=10_000_000)
    required_training_count: int = Field(ge=0, le=100_000_000)
    completed_training_count: int = Field(ge=0, le=100_000_000)
    required_permit_count: int = Field(ge=0, le=1_000_000)
    current_permit_count: int = Field(ge=0, le=1_000_000)
    emergency_plan_current: bool
    last_emergency_drill_at: str
    incidents: tuple[EhsIncident, ...] = Field(default_factory=tuple, max_length=10_000)

    @field_validator("last_emergency_drill_at")
    @classmethod
    def _drill_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="last_emergency_drill_at")

    @field_validator("incidents", mode="before")
    @classmethod
    def _incident_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _program_counts_are_bounded(self) -> "EhsProgramSnapshot":
        if self.completed_training_count > self.required_training_count:
            raise ValueError("completed training cannot exceed required training")
        if self.current_permit_count > self.required_permit_count:
            raise ValueError("current permits cannot exceed required permits")
        refs = [item.incident_ref for item in self.incidents]
        if len(refs) != len(set(refs)):
            raise ValueError("incident references must be unique")
        return self


class FieldQualitySignal(_StrictModel):
    signal_ref: OpaqueRef
    product_ref: OpaqueRef
    kind: Literal["complaint", "warranty", "adverse_event", "field_defect"]
    severity: Literal["low", "medium", "high", "critical"]
    received_at: str
    trace_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=1_000)
    classified: bool
    investigation_status: Literal["not_started", "in_progress", "complete"]
    safety_related: bool
    reportable: bool
    regulator_reported: bool
    containment_status: Literal["not_required", "pending", "contained", "verified"]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=20)

    @field_validator("received_at")
    @classmethod
    def _received_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="received_at")

    @field_validator("trace_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _trace_refs_are_unique(self) -> "FieldQualitySignal":
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("field-quality trace references must be unique")
        return self


class ProductTraceabilitySnapshot(_StrictModel):
    company_ref: OpaqueRef
    product_ref: OpaqueRef
    snapshot_at: str
    shipped_unit_count: int = Field(ge=0, le=1_000_000_000)
    traceable_unit_count: int = Field(ge=0, le=1_000_000_000)
    destination_accounted_unit_count: int = Field(ge=0, le=1_000_000_000)
    trace_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100_000)
    forward_trace_test_passed: bool
    backward_trace_test_passed: bool

    @field_validator("snapshot_at")
    @classmethod
    def _snapshot_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="snapshot_at")

    @field_validator("trace_refs", mode="before")
    @classmethod
    def _trace_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _trace_counts_are_bounded(self) -> "ProductTraceabilitySnapshot":
        if self.traceable_unit_count > self.shipped_unit_count:
            raise ValueError("traceable units cannot exceed shipped units")
        if self.destination_accounted_unit_count > self.shipped_unit_count:
            raise ValueError("destination-accounted units cannot exceed shipped units")
        if len(self.trace_refs) != len(set(self.trace_refs)):
            raise ValueError("trace references must be unique")
        return self


class RecallReadinessSnapshot(_StrictModel):
    company_ref: OpaqueRef
    product_ref: OpaqueRef
    recall_ref: OpaqueRef
    status: Literal[
        "not_required", "assessment", "authorized", "in_progress", "complete"
    ]
    trigger_signal_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=10_000
    )
    affected_unit_count: int = Field(ge=0, le=1_000_000_000)
    located_unit_count: int = Field(ge=0, le=1_000_000_000)
    notified_unit_count: int = Field(ge=0, le=1_000_000_000)
    quarantined_or_recovered_unit_count: int = Field(ge=0, le=1_000_000_000)
    regulator_notification_required: bool
    regulator_notification_complete: bool
    customer_notification_complete: bool
    effectiveness_check_complete: bool
    quantity_reconciled: bool
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=30)

    @field_validator("trigger_signal_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _recall_counts_are_bounded(self) -> "RecallReadinessSnapshot":
        if any(
            value > self.affected_unit_count
            for value in (
                self.located_unit_count,
                self.notified_unit_count,
                self.quarantined_or_recovered_unit_count,
            )
        ):
            raise ValueError("recall progress counts cannot exceed affected units")
        if len(self.trigger_signal_refs) != len(set(self.trigger_signal_refs)):
            raise ValueError("recall trigger signal references must be unique")
        return self


class FieldQualityControlPolicy(_StrictModel):
    maximum_snapshot_age_hours: int = Field(default=168, ge=1, le=8_760)
    maximum_emergency_drill_age_hours: int = Field(default=4_380, ge=1, le=17_520)
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    required_evidence_kinds: tuple[str, ...] = Field(
        default=_REQUIRED_EVIDENCE_KINDS, min_length=1, max_length=20
    )

    @field_validator("required_evidence_kinds", mode="before")
    @classmethod
    def _kinds_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _kinds_are_unique(self) -> "FieldQualityControlPolicy":
        if len(self.required_evidence_kinds) != len(set(self.required_evidence_kinds)):
            raise ValueError("required evidence kinds must be unique")
        return self


class FieldQualityControlInput(_StrictModel):
    schema_id: Literal["lightbulb.field_quality_control_input.v1"] = Field(
        default=FIELD_QUALITY_CONTROL_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    company_ref: OpaqueRef
    product_ref: OpaqueRef
    analysis_as_of: str
    ehs: EhsProgramSnapshot
    field_signals: tuple[FieldQualitySignal, ...] = Field(
        default_factory=tuple, max_length=100_000
    )
    traceability: ProductTraceabilitySnapshot
    recall: RecallReadinessSnapshot
    policy: FieldQualityControlPolicy = Field(default_factory=FieldQualityControlPolicy)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        min_length=1, max_length=200
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _analysis_timestamp(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator("field_signals", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _scope_and_refs_are_exact(self) -> "FieldQualityControlInput":
        if any(
            value != self.company_ref
            for value in (
                self.ehs.company_ref,
                self.traceability.company_ref,
                self.recall.company_ref,
            )
        ):
            raise ValueError("all physical-operation snapshots must match company_ref")
        if any(
            value != self.product_ref
            for value in (self.traceability.product_ref, self.recall.product_ref)
        ) or any(item.product_ref != self.product_ref for item in self.field_signals):
            raise ValueError("all field-quality snapshots must match product_ref")
        for label, refs in (
            ("field signal", [item.signal_ref for item in self.field_signals]),
            ("evidence", [item.evidence_ref for item in self.evidence_refs]),
        ):
            if len(refs) != len(set(refs)):
                raise ValueError(f"{label} references must be unique")
        return self


class FieldQualityFinding(_StrictModel):
    gate: FieldQualityGate
    code: FindingCode
    status: FieldQualityStatus
    message: str = Field(min_length=1, max_length=500)
    affected_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("affected_refs", mode="before")
    @classmethod
    def _refs_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class FieldQualityControlResult(_StrictModel):
    schema_id: Literal["lightbulb.field_quality_control_result.v1"] = Field(
        default=FIELD_QUALITY_CONTROL_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    company_ref: OpaqueRef
    product_ref: OpaqueRef
    analysis_as_of: str
    disposition: FieldQualityDisposition
    findings: tuple[FieldQualityFinding, ...]
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    indeterminate_count: int = Field(ge=0)
    safety_or_recall_trigger_refs: tuple[OpaqueRef, ...]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...]
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )
    operation_spec: PrimitiveOperationSpec
    work_stoppage_authorized: Literal[False] = False
    regulator_report_filed: Literal[False] = False
    recall_initiated: Literal[False] = False
    customer_notification_sent: Literal[False] = False
    inventory_quarantined: Literal[False] = False
    capa_closed: Literal[False] = False

    @field_validator(
        "findings", "safety_or_recall_trigger_refs", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _counts_and_operation_are_exact(self) -> "FieldQualityControlResult":
        for evidence in self.evidence_refs:
            PrimitiveEvidenceRef.model_validate(
                evidence.model_dump(mode="python", by_alias=True)
            )
        PrimitiveOperationSpec.model_validate(
            self.operation_spec.model_dump(mode="python", by_alias=True)
        )
        actual = {
            status: sum(item.status == status for item in self.findings)
            for status in ("pass", "fail", "indeterminate")
        }
        if actual != {
            "pass": self.passed_count,
            "fail": self.failed_count,
            "indeterminate": self.indeterminate_count,
        }:
            raise ValueError("finding counts must match findings")
        expected_disposition: FieldQualityDisposition = (
            "blocked"
            if self.failed_count
            else "indeterminate"
            if self.indeterminate_count
            else "manual_review_required"
            if self.safety_or_recall_trigger_refs
            else "controls_satisfied"
        )
        if self.disposition != expected_disposition:
            raise ValueError("disposition must match findings and trigger references")
        if self.safety_or_recall_trigger_refs != tuple(
            sorted(set(self.safety_or_recall_trigger_refs))
        ):
            raise ValueError(
                "safety_or_recall_trigger_refs must be unique and in canonical order"
            )
        evidence_refs = tuple(item.evidence_ref for item in self.evidence_refs)
        if evidence_refs != tuple(sorted(set(evidence_refs))):
            raise ValueError("evidence_refs must be unique and in canonical order")
        expected_evidence_digest = _stable_digest(
            [item.to_dict() for item in self.evidence_refs]
        )
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match evidence_refs")
        if self.operation_spec != FIELD_QUALITY_CONTROL_OPERATION:
            raise ValueError("operation_spec must identify this evaluator")
        expected_evaluation_digest = _stable_digest(
            self.model_dump(
                mode="json",
                by_alias=True,
                exclude={"evaluation_digest"},
                exclude_none=True,
            )
        )
        if self.evaluation_digest not in {
            _ZERO_DIGEST,
            expected_evaluation_digest,
        }:
            raise ValueError("evaluation_digest does not match the evaluation")
        object.__setattr__(
            self,
            "evaluation_digest",
            expected_evaluation_digest,
        )
        return self


FIELD_QUALITY_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="ehs-recall-field-quality.evaluate",
    tool="manufacturing.evaluate_ehs_recall_field_quality_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _finding(
    findings: list[FieldQualityFinding],
    *,
    gate: FieldQualityGate,
    code: str,
    status: FieldQualityStatus,
    message: str,
    refs: tuple[str, ...] = (),
) -> None:
    findings.append(
        FieldQualityFinding(
            gate=gate,
            code=code,
            status=status,
            message=message,
            affected_refs=refs,
        )
    )


def _evidence_status(
    evidence_refs: tuple[PrimitiveEvidenceRef, ...],
    *,
    analysis_at: datetime,
    policy: FieldQualityControlPolicy,
) -> FieldQualityStatus:
    for evidence in evidence_refs:
        observed_at = _parsed_timestamp(evidence.observed_at)
        if observed_at > analysis_at:
            return "fail"
        if (
            analysis_at - observed_at
        ).total_seconds() / 3_600 > policy.maximum_snapshot_age_hours or _GRADE_RANK[
            evidence.verification_grade
        ] < _GRADE_RANK[policy.minimum_evidence_grade]:
            return "indeterminate"
    return "pass"


def _boolean_gate(
    findings: list[FieldQualityFinding],
    *,
    gate: FieldQualityGate,
    code: str,
    passed: bool,
    pass_message: str,
    fail_message: str,
    refs: tuple[str, ...] = (),
) -> None:
    _finding(
        findings,
        gate=gate,
        code=code,
        status="pass" if passed else "fail",
        message=pass_message if passed else fail_message,
        refs=refs,
    )


def evaluate_field_quality_controls(
    inputs: FieldQualityControlInput | dict[str, Any],
) -> FieldQualityControlResult:
    """Evaluate EHS, field-quality, traceability, and recall controls."""

    parsed = revalidate_model_boundary(FieldQualityControlInput, inputs)
    analysis_at = _parsed_timestamp(parsed.analysis_as_of)
    findings: list[FieldQualityFinding] = []

    evidence_by_kind: dict[str, list[PrimitiveEvidenceRef]] = {}
    for evidence in parsed.evidence_refs:
        evidence_by_kind.setdefault(evidence.kind, []).append(evidence)
    for kind in parsed.policy.required_evidence_kinds:
        candidates = tuple(evidence_by_kind.get(kind, ()))
        status: FieldQualityStatus = (
            "indeterminate"
            if not candidates
            else _evidence_status(
                candidates, analysis_at=analysis_at, policy=parsed.policy
            )
        )
        _finding(
            findings,
            gate="evidence",
            code=f"evidence.{kind}",
            status=status,
            message=f"Required {kind.replace('_', ' ')} evidence is {status}.",
        )

    ehs = parsed.ehs
    _boolean_gate(
        findings,
        gate="ehs",
        code="ehs.training_and_permits",
        passed=ehs.completed_training_count == ehs.required_training_count
        and ehs.current_permit_count == ehs.required_permit_count,
        pass_message="Required EHS training and permits are current.",
        fail_message="Required EHS training or permits are incomplete.",
    )
    drill_at = _parsed_timestamp(ehs.last_emergency_drill_at)
    drill_future = drill_at > analysis_at
    drill_stale = (
        not drill_future
        and (analysis_at - drill_at).total_seconds() / 3_600
        > parsed.policy.maximum_emergency_drill_age_hours
    )
    _finding(
        findings,
        gate="ehs",
        code="ehs.emergency_readiness",
        status=(
            "fail"
            if drill_future or not ehs.emergency_plan_current
            else "indeterminate"
            if drill_stale
            else "pass"
        ),
        message=(
            "Emergency plan or drill chronology is invalid."
            if drill_future or not ehs.emergency_plan_current
            else "Emergency drill evidence is stale."
            if drill_stale
            else "Emergency plan and drill are current."
        ),
    )
    incident_failures: list[str] = []
    incident_indeterminate: list[str] = []
    for incident in ehs.incidents:
        if _parsed_timestamp(incident.occurred_at) > analysis_at:
            incident_failures.append(incident.incident_ref)
            continue
        if incident.reportable and not incident.regulator_reported:
            incident_failures.append(incident.incident_ref)
        if incident.work_stop_required and not incident.work_stopped:
            incident_failures.append(incident.incident_ref)
        if (
            incident.investigation_status != "complete"
            or incident.corrective_action_status
            in {
                "open",
                "implemented",
            }
        ):
            incident_indeterminate.append(incident.incident_ref)
        evidence_status = _evidence_status(
            incident.evidence_refs,
            analysis_at=analysis_at,
            policy=parsed.policy,
        )
        if evidence_status == "fail":
            incident_failures.append(incident.incident_ref)
        elif evidence_status == "indeterminate":
            incident_indeterminate.append(incident.incident_ref)
    _finding(
        findings,
        gate="ehs",
        code="ehs.incident_controls",
        status=(
            "fail"
            if incident_failures
            else "indeterminate"
            if incident_indeterminate
            else "pass"
        ),
        message=(
            "One or more EHS incidents have unmet reporting or stop-work controls."
            if incident_failures
            else "One or more EHS investigations or corrective actions remain open."
            if incident_indeterminate
            else "EHS incidents are reported, investigated, and controlled."
        ),
        refs=tuple(dict.fromkeys(incident_failures + incident_indeterminate)),
    )

    signal_failures: list[str] = []
    signal_indeterminate: list[str] = []
    trigger_refs: list[str] = []
    for signal in parsed.field_signals:
        if _parsed_timestamp(signal.received_at) > analysis_at:
            signal_failures.append(signal.signal_ref)
            continue
        if not signal.classified:
            signal_indeterminate.append(signal.signal_ref)
        if not signal.trace_refs:
            signal_failures.append(signal.signal_ref)
        if signal.investigation_status != "complete":
            signal_indeterminate.append(signal.signal_ref)
        if signal.reportable and not signal.regulator_reported:
            signal_failures.append(signal.signal_ref)
        if signal.safety_related or signal.severity in {"high", "critical"}:
            trigger_refs.append(signal.signal_ref)
            if signal.containment_status not in {"contained", "verified"}:
                signal_failures.append(signal.signal_ref)
        evidence_status = _evidence_status(
            signal.evidence_refs,
            analysis_at=analysis_at,
            policy=parsed.policy,
        )
        if evidence_status == "fail":
            signal_failures.append(signal.signal_ref)
        elif evidence_status == "indeterminate":
            signal_indeterminate.append(signal.signal_ref)
    _finding(
        findings,
        gate="field_quality",
        code="field_quality.signal_controls",
        status=(
            "fail"
            if signal_failures
            else "indeterminate"
            if signal_indeterminate
            else "pass"
        ),
        message=(
            "Field-quality signals have missing trace, reporting, or containment controls."
            if signal_failures
            else "Field-quality classification or investigation remains incomplete."
            if signal_indeterminate
            else "Field-quality signals are traced, investigated, reported, and contained."
        ),
        refs=tuple(dict.fromkeys(signal_failures + signal_indeterminate)),
    )

    trace = parsed.traceability
    trace_at = _parsed_timestamp(trace.snapshot_at)
    trace_future = trace_at > analysis_at
    trace_stale = (
        not trace_future
        and (analysis_at - trace_at).total_seconds() / 3_600
        > parsed.policy.maximum_snapshot_age_hours
    )
    _finding(
        findings,
        gate="traceability",
        code="traceability.snapshot_freshness",
        status="fail" if trace_future else "indeterminate" if trace_stale else "pass",
        message=(
            "Traceability snapshot occurs after analysis time."
            if trace_future
            else "Traceability snapshot is stale."
            if trace_stale
            else "Traceability snapshot is current."
        ),
    )
    _boolean_gate(
        findings,
        gate="traceability",
        code="traceability.coverage_and_drill",
        passed=trace.traceable_unit_count == trace.shipped_unit_count
        and trace.destination_accounted_unit_count == trace.shipped_unit_count
        and trace.forward_trace_test_passed
        and trace.backward_trace_test_passed,
        pass_message="All shipped units and destinations are traceable in both directions.",
        fail_message="Product traceability coverage or trace drill is incomplete.",
    )

    recall = parsed.recall
    trigger_set = set(trigger_refs)
    declared_triggers = set(recall.trigger_signal_refs)
    missing_triggers = tuple(sorted(trigger_set - declared_triggers))
    recall_required = bool(trigger_set)
    recall_status_valid = (
        recall.status in {"assessment", "authorized", "in_progress", "complete"}
        if recall_required
        else recall.status == "not_required"
        or recall.status in {"assessment", "complete"}
    )
    _boolean_gate(
        findings,
        gate="recall",
        code="recall.trigger_assessment",
        passed=recall_status_valid and not missing_triggers,
        pass_message="Recall assessment status covers all safety and material field signals.",
        fail_message="Recall assessment is missing or does not cover all trigger signals.",
        refs=missing_triggers,
    )
    if recall.status in {"authorized", "in_progress", "complete"}:
        progress_complete = (
            recall.located_unit_count == recall.affected_unit_count
            and recall.notified_unit_count == recall.affected_unit_count
            and (
                not recall.regulator_notification_required
                or recall.regulator_notification_complete
            )
            and recall.customer_notification_complete
        )
        _boolean_gate(
            findings,
            gate="recall",
            code="recall.location_and_notification",
            passed=progress_complete,
            pass_message="Affected units are located and required notifications are complete.",
            fail_message="Affected-unit location or required notification is incomplete.",
        )
    else:
        _finding(
            findings,
            gate="recall",
            code="recall.location_and_notification",
            status="pass" if not recall_required else "indeterminate",
            message=(
                "No active recall requires location or notification."
                if not recall_required
                else "Recall location and notification await an authorized recall decision."
            ),
        )
    if recall.status == "complete":
        closure_ready = (
            recall.quarantined_or_recovered_unit_count == recall.affected_unit_count
            and recall.effectiveness_check_complete
            and recall.quantity_reconciled
        )
        _boolean_gate(
            findings,
            gate="recall",
            code="recall.effectiveness_and_reconciliation",
            passed=closure_ready,
            pass_message="Recall recovery, effectiveness, and quantity reconciliation are complete.",
            fail_message="Recall effectiveness or quantity reconciliation is incomplete.",
        )
    else:
        _finding(
            findings,
            gate="recall",
            code="recall.effectiveness_and_reconciliation",
            status="pass" if not recall_required else "indeterminate",
            message=(
                "No recall closure control is currently required."
                if not recall_required
                else "Recall effectiveness and reconciliation remain pending."
            ),
        )
    recall_evidence_status = _evidence_status(
        recall.evidence_refs,
        analysis_at=analysis_at,
        policy=parsed.policy,
    )
    _finding(
        findings,
        gate="recall",
        code="recall.evidence",
        status=recall_evidence_status,
        message=f"Recall decision and execution evidence is {recall_evidence_status}.",
    )

    passed_count = sum(item.status == "pass" for item in findings)
    failed_count = sum(item.status == "fail" for item in findings)
    indeterminate_count = sum(item.status == "indeterminate" for item in findings)
    disposition: FieldQualityDisposition = (
        "blocked"
        if failed_count
        else "indeterminate"
        if indeterminate_count
        else "manual_review_required"
        if trigger_refs
        else "controls_satisfied"
    )
    input_digest = _stable_digest(parsed.to_dict())
    evidence_digest = _stable_digest(
        [
            evidence.to_dict()
            for evidence in sorted(
                parsed.evidence_refs, key=lambda item: item.evidence_ref
            )
        ]
    )
    return FieldQualityControlResult(
        evaluation_ref=parsed.evaluation_ref,
        company_ref=parsed.company_ref,
        product_ref=parsed.product_ref,
        analysis_as_of=parsed.analysis_as_of,
        disposition=disposition,
        findings=tuple(findings),
        passed_count=passed_count,
        failed_count=failed_count,
        indeterminate_count=indeterminate_count,
        safety_or_recall_trigger_refs=tuple(sorted(set(trigger_refs))),
        evidence_refs=tuple(
            sorted(parsed.evidence_refs, key=lambda item: item.evidence_ref)
        ),
        input_digest=input_digest,
        evidence_digest=evidence_digest,
        operation_spec=FIELD_QUALITY_CONTROL_OPERATION,
    )


def _evidence(ref: str, kind: str, character: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": kind,
        "issuer_ref": "spring-quality-authority",
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "restricted",
        "retention_policy": "quality-ten-years",
    }


def _example_inputs() -> dict[str, Any]:
    return {
        "schema": FIELD_QUALITY_CONTROL_INPUT_SCHEMA,
        "evaluation_ref": "field-quality-2026-08-24",
        "company_ref": "company-401",
        "product_ref": "product-assembly-a",
        "analysis_as_of": "2026-08-24T13:00:00Z",
        "ehs": {
            "company_ref": "company-401",
            "site_ref": "site-plant-1",
            "workforce_count": 100,
            "required_training_count": 100,
            "completed_training_count": 100,
            "required_permit_count": 4,
            "current_permit_count": 4,
            "emergency_plan_current": True,
            "last_emergency_drill_at": "2026-08-01T00:00:00Z",
            "incidents": [],
        },
        "field_signals": [],
        "traceability": {
            "company_ref": "company-401",
            "product_ref": "product-assembly-a",
            "snapshot_at": "2026-08-24T12:00:00Z",
            "shipped_unit_count": 1000,
            "traceable_unit_count": 1000,
            "destination_accounted_unit_count": 1000,
            "trace_refs": ["lot-a", "lot-b"],
            "forward_trace_test_passed": True,
            "backward_trace_test_passed": True,
        },
        "recall": {
            "company_ref": "company-401",
            "product_ref": "product-assembly-a",
            "recall_ref": "recall-assessment-current",
            "status": "not_required",
            "trigger_signal_refs": [],
            "affected_unit_count": 0,
            "located_unit_count": 0,
            "notified_unit_count": 0,
            "quarantined_or_recovered_unit_count": 0,
            "regulator_notification_required": False,
            "regulator_notification_complete": False,
            "customer_notification_complete": False,
            "effectiveness_check_complete": False,
            "quantity_reconciled": False,
            "evidence_refs": [
                _evidence("evidence-recall-decision", "recall_decision", "e")
            ],
        },
        "evidence_refs": [
            _evidence("evidence-ehs", "ehs_program", "a"),
            _evidence("evidence-field", "field_quality_register", "b"),
            _evidence("evidence-trace", "product_traceability", "c"),
            _evidence("evidence-recall", "recall_readiness", "d"),
        ],
    }


class EvaluateFieldQualityControlsPrimitive(
    BusinessProcessPrimitive[FieldQualityControlInput, FieldQualityControlResult]
):
    primitive_ref = "manufacturing.evaluate_ehs_recall_field_quality_controls"
    version = "1.0.0"
    title = "Evaluate EHS, recall, and field-quality controls"
    description = (
        "Evaluate EHS readiness, incidents, field signals, product traceability, "
        "and recall controls without performing or authorizing physical actions."
    )
    input_model = FieldQualityControlInput
    output_model = FieldQualityControlResult
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
        contract["operation_contract"] = FIELD_QUALITY_CONTROL_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "connector_reads": 0,
            "connector_writes": 0,
            "work_stoppages": 0,
            "regulatory_filings": 0,
            "recalls_initiated": 0,
            "customer_notifications": 0,
            "inventory_movements": 0,
            "authorization_granted": False,
        }
        contract["system_of_record_authority"] = "spring_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: FieldQualityControlInput,
    ) -> PrimitiveExecutionResult[FieldQualityControlResult]:
        del context
        output = evaluate_field_quality_controls(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=FIELD_QUALITY_CONTROL_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.input_digest,
            external_refs={"evaluation_digest": output.evaluation_digest},
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult(
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=f"EHS and field-quality controls evaluated: {output.disposition}.",
            output=output,
            events=[
                PrimitiveEvent(
                    type="manufacturing.field_quality_controls_evaluated",
                    payload={
                        "disposition": output.disposition,
                        "trigger_count": len(output.safety_or_recall_trigger_refs),
                        "evaluation_digest": output.evaluation_digest,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="field_quality_control_evaluation",
                    summary="EHS and field-quality controls evaluated without a physical effect.",
                    labels=[
                        output.disposition,
                        "read_only",
                        "spring_authority_required",
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


FIELD_QUALITY_EXECUTABLE_PRIMITIVES: tuple[BusinessProcessPrimitive[Any, Any], ...] = (
    EvaluateFieldQualityControlsPrimitive(),
)


__all__ = [
    "EhsIncident",
    "EhsProgramSnapshot",
    "EvaluateFieldQualityControlsPrimitive",
    "FIELD_QUALITY_CONTROL_INPUT_SCHEMA",
    "FIELD_QUALITY_CONTROL_OPERATION",
    "FIELD_QUALITY_CONTROL_RESULT_SCHEMA",
    "FIELD_QUALITY_EXECUTABLE_PRIMITIVES",
    "FieldQualityControlInput",
    "FieldQualityControlPolicy",
    "FieldQualityControlResult",
    "FieldQualityDisposition",
    "FieldQualityFinding",
    "FieldQualityGate",
    "FieldQualitySignal",
    "FieldQualityStatus",
    "ProductTraceabilitySnapshot",
    "RecallReadinessSnapshot",
    "evaluate_field_quality_controls",
]
