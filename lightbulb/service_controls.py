"""Deterministic customer-service intake, SLA, and resolution controls.

The SDK evaluates normalized service evidence and proposes a disposition. It
does not close a case, issue money, approve a return, dispatch field service,
change an entitlement, or claim that a customer outcome was verified.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
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
    revalidate_model_boundary,
)


SERVICE_CASE_SNAPSHOT_SCHEMA = "lightbulb.service_case_snapshot.v1"
SERVICE_CONTROL_INPUT_SCHEMA = "lightbulb.service_control_input.v1"
SERVICE_CONTROL_RESULT_SCHEMA = "lightbulb.service_control_result.v1"

_MONEY_QUANTUM = Decimal("0.0001")
_RATIO_QUANTUM = Decimal("0.000001")
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
SummaryText = Annotated[str, StringConstraints(min_length=1, max_length=2_000)]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

ServiceTarget = Literal["triage", "resolution"]
GateName = Literal[
    "evidence",
    "intake",
    "sla",
    "entitlement",
    "remedy",
    "fulfillment",
    "resolution",
]
GateStatus = Literal["pass", "review", "fail", "indeterminate"]
_GATE_ORDER: tuple[GateName, ...] = (
    "evidence",
    "intake",
    "sla",
    "entitlement",
    "remedy",
    "fulfillment",
    "resolution",
)
Disposition = Literal[
    "ready_for_assignment",
    "ready_for_resolution_approval",
    "escalation_required",
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


def _decimal(value: Any, *, quantum: Decimal, upper: Decimal | None = None) -> Decimal:
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
    if upper is not None and parsed > upper:
        raise ValueError(f"decimal field must be at most {upper}")
    return normalized


def _money(value: Any) -> Decimal:
    return _decimal(value, quantum=_MONEY_QUANTUM)


def _ratio(value: Any) -> Decimal:
    return _decimal(value, quantum=_RATIO_QUANTUM, upper=Decimal("1"))


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def service_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


class ServiceCaseSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.service_case_snapshot.v1"] = Field(
        default=SERVICE_CASE_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    channel: Literal["email", "web", "chat", "sms", "voice", "whatsapp", "social"]
    opened_at: str
    status: Literal[
        "new",
        "classified",
        "assigned",
        "in_progress",
        "waiting_customer",
        "waiting_internal",
        "resolved",
        "closed",
        "reopened",
    ]
    category_ref: OpaqueRef | None = None
    classification_confidence: Decimal | None = Field(default=None, ge=0, le=1)
    priority: Literal["low", "normal", "high", "critical"]
    owner_ref: OpaqueRef | None = None
    summary: SummaryText
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("opened_at")
    @classmethod
    def _valid_opened_at(cls, value: str) -> str:
        return _timestamp(value, field_name="opened_at")

    @field_validator("classification_confidence", mode="before")
    @classmethod
    def _valid_confidence(cls, value: Any) -> Decimal | None:
        return None if value is None else _ratio(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ServiceSlaSnapshot(_StrictModel):
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    policy_ref: OpaqueRef
    first_response_due_at: str
    first_response_at: str | None = None
    resolution_due_at: str
    escalation_required: bool = False
    escalation_ref: OpaqueRef | None = None
    escalation_owner_ref: OpaqueRef | None = None
    escalation_started_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator(
        "first_response_due_at",
        "first_response_at",
        "resolution_due_at",
        "escalation_started_at",
    )
    @classmethod
    def _valid_timestamps(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_sla(self) -> "ServiceSlaSnapshot":
        if _parsed_timestamp(self.resolution_due_at) < _parsed_timestamp(
            self.first_response_due_at
        ):
            raise ValueError("resolution_due_at cannot precede first_response_due_at")
        escalation_fields = (
            self.escalation_ref,
            self.escalation_owner_ref,
            self.escalation_started_at,
        )
        if self.escalation_required and any(
            value is None for value in escalation_fields
        ):
            raise ValueError("required escalation needs ref, owner, and started_at")
        return self


class EntitlementSnapshot(_StrictModel):
    entitlement_ref: OpaqueRef
    customer_ref: OpaqueRef
    product_ref: OpaqueRef
    asset_ref: OpaqueRef | None = None
    serial_ref: OpaqueRef | None = None
    coverage: Literal["active", "expired", "not_found", "unknown"]
    coverage_ends_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("coverage_ends_at")
    @classmethod
    def _valid_coverage_end(cls, value: str | None) -> str | None:
        return (
            None if value is None else _timestamp(value, field_name="coverage_ends_at")
        )

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class RemedyRequest(_StrictModel):
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    remedy_ref: OpaqueRef
    kind: Literal["none", "refund", "credit", "warranty_repair", "rma", "field_service"]
    reason_ref: OpaqueRef | None = None
    amount: Decimal | None = Field(default=None, ge=0)
    currency: CurrencyCode | None = None
    original_transaction_ref: OpaqueRef | None = None
    approval_ref: OpaqueRef | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("amount", mode="before")
    @classmethod
    def _valid_amount(cls, value: Any) -> Decimal | None:
        return None if value is None else _money(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _valid_remedy(self) -> "RemedyRequest":
        if self.kind in {"refund", "credit"} and (
            self.amount is None
            or self.currency is None
            or self.original_transaction_ref is None
        ):
            raise ValueError(
                "refund and credit remedies require amount, currency, and transaction ref"
            )
        if self.kind not in {"refund", "credit"} and (
            self.amount is not None
            or self.currency is not None
            or self.original_transaction_ref is not None
        ):
            raise ValueError("financial fields are valid only for refunds and credits")
        return self


class ServiceFulfillmentSnapshot(_StrictModel):
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    fulfillment_ref: OpaqueRef
    kind: Literal["warranty_repair", "rma", "field_service"]
    status: Literal[
        "requested",
        "authorized",
        "in_transit",
        "received",
        "scheduled",
        "in_service",
        "completed",
        "cancelled",
    ]
    asset_ref: OpaqueRef | None = None
    serial_ref: OpaqueRef | None = None
    return_tracking_ref: OpaqueRef | None = None
    diagnostic_ref: OpaqueRef | None = None
    completion_receipt_ref: OpaqueRef | None = None
    completed_at: str | None = None
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("completed_at")
    @classmethod
    def _valid_completed_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="completed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _completed_has_receipt(self) -> "ServiceFulfillmentSnapshot":
        if self.status == "completed" and (
            self.completion_receipt_ref is None or self.completed_at is None
        ):
            raise ValueError("completed fulfillment needs receipt and completed_at")
        return self


class ResolutionSnapshot(_StrictModel):
    case_ref: OpaqueRef
    customer_ref: OpaqueRef
    resolution_ref: OpaqueRef
    root_cause_ref: OpaqueRef
    resolution_summary: SummaryText
    knowledge_article_ref: OpaqueRef | None = None
    knowledge_article_revision: int | None = Field(default=None, ge=1)
    customer_verification: Literal["pending", "confirmed", "rejected", "unreachable"]
    outcome_verified: bool
    reopened: bool = False
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(min_length=1, max_length=50)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _knowledge_revision_is_bound(self) -> "ResolutionSnapshot":
        if (self.knowledge_article_ref is None) != (
            self.knowledge_article_revision is None
        ):
            raise ValueError(
                "knowledge article ref and revision must be supplied together"
            )
        return self


class ServiceControlPolicy(_StrictModel):
    minimum_evidence_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    max_evidence_age_hours: int = Field(default=168, ge=1, le=8_760)
    minimum_classification_confidence: Decimal = Field(
        default=Decimal("0.800000"),
        ge=0,
        le=1,
    )
    require_owner_for_assignment: bool = True
    require_financial_remedy_approval: bool = True
    require_entitlement_for_service_remedy: bool = True
    require_customer_resolution_confirmation: bool = True
    allow_unreachable_customer_manual_review: bool = True

    @field_validator("minimum_classification_confidence", mode="before")
    @classmethod
    def _valid_confidence(cls, value: Any) -> Decimal:
        return _ratio(value)


class ServiceControlInput(_StrictModel):
    schema_id: Literal["lightbulb.service_control_input.v1"] = Field(
        default=SERVICE_CONTROL_INPUT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: ServiceTarget
    analysis_as_of: str
    case: ServiceCaseSnapshot
    sla: ServiceSlaSnapshot
    remedy: RemedyRequest | None = None
    entitlement: EntitlementSnapshot | None = None
    fulfillment: ServiceFulfillmentSnapshot | None = None
    resolution: ResolutionSnapshot | None = None
    policy: ServiceControlPolicy = Field(default_factory=ServiceControlPolicy)

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @model_validator(mode="after")
    def _remedy_matches_target(self) -> "ServiceControlInput":
        if self.target == "resolution" and self.remedy is None:
            raise ValueError("resolution evaluation requires a remedy request")
        if (
            self.target == "triage"
            and self.remedy is not None
            and self.remedy.kind != "none"
        ):
            raise ValueError("triage accepts only an optional kind=none remedy")
        return self

    @model_validator(mode="after")
    def _business_timeline_is_coherent(self) -> "ServiceControlInput":
        analysis_at = _parsed_timestamp(self.analysis_as_of)
        opened_at = _parsed_timestamp(self.case.opened_at)
        if opened_at > analysis_at:
            raise ValueError("case opened_at cannot follow analysis_as_of")

        first_response_due_at = _parsed_timestamp(self.sla.first_response_due_at)
        if first_response_due_at < opened_at:
            raise ValueError("first_response_due_at cannot precede case opened_at")

        first_response_at = (
            _parsed_timestamp(self.sla.first_response_at)
            if self.sla.first_response_at is not None
            else None
        )
        if first_response_at is not None:
            if first_response_at < opened_at:
                raise ValueError("first_response_at cannot precede case opened_at")
            if first_response_at > analysis_at:
                raise ValueError("first_response_at cannot follow analysis_as_of")

        escalation_started_at = (
            _parsed_timestamp(self.sla.escalation_started_at)
            if self.sla.escalation_started_at is not None
            else None
        )
        if escalation_started_at is not None:
            if escalation_started_at < opened_at:
                raise ValueError("escalation_started_at cannot precede case opened_at")
            if escalation_started_at > analysis_at:
                raise ValueError("escalation_started_at cannot follow analysis_as_of")

        completed_at = (
            _parsed_timestamp(self.fulfillment.completed_at)
            if self.fulfillment is not None
            and self.fulfillment.completed_at is not None
            else None
        )
        if completed_at is not None:
            if completed_at < opened_at:
                raise ValueError(
                    "fulfillment completed_at cannot precede case opened_at"
                )
            if first_response_at is not None and completed_at < first_response_at:
                raise ValueError(
                    "fulfillment completed_at cannot precede first_response_at"
                )
            if completed_at > analysis_at:
                raise ValueError(
                    "fulfillment completed_at cannot follow analysis_as_of"
                )
        return self


class ServiceFinding(_StrictModel):
    code: OpaqueRef
    gate: GateName
    status: Literal["review", "fail", "indeterminate"]
    message: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    subject_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ServiceGateResult(_StrictModel):
    gate: GateName
    status: GateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=1_000
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _finding_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class ServiceEffectBoundary(_StrictModel):
    case_assigned_or_closed: Literal[False] = False
    escalation_created_or_resolved: Literal[False] = False
    refund_or_credit_authorized: Literal[False] = False
    warranty_or_rma_authorized: Literal[False] = False
    field_service_dispatched: Literal[False] = False
    entitlement_changed: Literal[False] = False
    customer_outcome_claimed: Literal[False] = False
    trusted_host_authority_required: Literal[True] = True


SERVICE_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="customer-service-case-controls.evaluate",
    tool="service.evaluate_case_resolution_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class ServiceControlResult(_StrictModel):
    schema_id: Literal["lightbulb.service_control_result.v1"] = Field(
        default=SERVICE_CONTROL_RESULT_SCHEMA,
        alias="schema",
    )
    evaluation_ref: OpaqueRef
    target: ServiceTarget
    analysis_as_of: str
    proposed_disposition: Disposition
    assurance_grade: PrimitiveEvidenceVerificationGrade
    gates: tuple[ServiceGateResult, ...]
    findings: tuple[ServiceFinding, ...]
    source_snapshot_digests: dict[str, str]
    evidence_refs: tuple[OpaqueRef, ...]
    effect_boundary: ServiceEffectBoundary = Field(
        default_factory=ServiceEffectBoundary
    )
    result_digest: str = Field(
        default=_ZERO_DIGEST,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator("gates", "findings", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _result_is_coherent_and_content_bound(self) -> "ServiceControlResult":
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
            ServiceGateResult(
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
            "escalation_required"
            if "escalation_required" in {item.code for item in self.findings}
            else "blocked"
            if "fail" in statuses
            else "indeterminate"
            if "indeterminate" in statuses
            else "manual_review_required"
            if "review" in statuses
            else "ready_for_assignment"
            if self.target == "triage"
            else "ready_for_resolution_approval"
        )
        if self.proposed_disposition != expected_disposition:
            raise ValueError(
                "proposed_disposition must match findings and gate results"
            )
        if set(self.source_snapshot_digests) != {
            "case",
            "policy",
            "sla",
            "remedy",
            "entitlement",
            "fulfillment",
            "resolution",
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


def _active_evidence_groups(
    inputs: ServiceControlInput,
) -> tuple[tuple[str, tuple[PrimitiveEvidenceRef, ...]], ...]:
    groups = [
        (inputs.case.case_ref, inputs.case.evidence_refs),
        (inputs.case.case_ref, inputs.sla.evidence_refs),
    ]
    if inputs.target == "resolution":
        if inputs.remedy is not None:
            groups.append((inputs.case.case_ref, inputs.remedy.evidence_refs))
        if inputs.entitlement is not None:
            groups.append((inputs.case.customer_ref, inputs.entitlement.evidence_refs))
        for optional in (inputs.fulfillment, inputs.resolution):
            if optional is not None:
                groups.append((inputs.case.case_ref, optional.evidence_refs))
    return tuple(groups)


def _all_evidence(inputs: ServiceControlInput) -> tuple[PrimitiveEvidenceRef, ...]:
    return tuple(
        evidence for _, group in _active_evidence_groups(inputs) for evidence in group
    )


def _add(
    findings: list[ServiceFinding],
    *,
    code: str,
    gate: GateName,
    status: Literal["review", "fail", "indeterminate"],
    message: str,
    subject_ref: str | None = None,
    evidence_refs: Sequence[str] = (),
) -> None:
    findings.append(
        ServiceFinding(
            code=code,
            gate=gate,
            status=status,
            message=message,
            subject_ref=subject_ref,
            evidence_refs=tuple(evidence_refs),
        )
    )


def _status(findings: Sequence[ServiceFinding]) -> GateStatus:
    statuses = {item.status for item in findings}
    if "fail" in statuses:
        return "fail"
    if "indeterminate" in statuses:
        return "indeterminate"
    if "review" in statuses:
        return "review"
    return "pass"


def evaluate_service_case_controls(
    value: ServiceControlInput | Mapping[str, Any],
) -> ServiceControlResult:
    """Evaluate intake or resolution controls without exercising host authority."""

    inputs = revalidate_model_boundary(ServiceControlInput, value)
    findings: list[ServiceFinding] = []
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
    for expected_subject_ref, group in _active_evidence_groups(inputs):
        for item in group:
            if item.subject_ref != expected_subject_ref:
                _add(
                    findings,
                    code=f"evidence_subject_mismatch:{item.evidence_ref}",
                    gate="evidence",
                    status="fail",
                    message=(
                        "Evidence subject must exactly match the evaluated case or "
                        "customer."
                    ),
                    subject_ref=item.evidence_ref,
                    evidence_refs=(item.evidence_ref,),
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
                evidence_refs=(item.evidence_ref,),
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
                evidence_refs=(item.evidence_ref,),
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
                evidence_refs=(item.evidence_ref,),
            )

    case = inputs.case
    sla = inputs.sla
    if sla.case_ref != case.case_ref or sla.customer_ref != case.customer_ref:
        _add(
            findings,
            code="sla_case_customer_mismatch",
            gate="sla",
            status="fail",
            message="SLA snapshot must bind the exact evaluated case and customer.",
            subject_ref=sla.policy_ref,
        )
    if case.category_ref is None or case.classification_confidence is None:
        _add(
            findings,
            code="case_classification_missing",
            gate="intake",
            status="indeterminate",
            message="Case category and classification confidence are required.",
            subject_ref=case.case_ref,
        )
    elif (
        case.classification_confidence < inputs.policy.minimum_classification_confidence
    ):
        _add(
            findings,
            code="case_classification_low_confidence",
            gate="intake",
            status="review",
            message="Case classification confidence is below policy.",
            subject_ref=case.case_ref,
        )
    if inputs.policy.require_owner_for_assignment and case.owner_ref is None:
        _add(
            findings,
            code="case_owner_missing",
            gate="intake",
            status="indeterminate",
            message="A governed case owner is required before assignment.",
            subject_ref=case.case_ref,
        )

    first_response_due = _parsed_timestamp(sla.first_response_due_at)
    resolution_due = _parsed_timestamp(sla.resolution_due_at)
    if sla.first_response_at is None and analysis_at > first_response_due:
        _add(
            findings,
            code="first_response_sla_breached",
            gate="sla",
            status="fail",
            message="The first-response SLA is breached.",
            subject_ref=case.case_ref,
        )
    elif (
        sla.first_response_at is not None
        and _parsed_timestamp(sla.first_response_at) > first_response_due
    ):
        _add(
            findings,
            code="first_response_sla_missed",
            gate="sla",
            status="review",
            message="The recorded first response missed its SLA.",
            subject_ref=case.case_ref,
        )
    overdue = analysis_at > resolution_due and case.status not in {"resolved", "closed"}
    escalation_needed = case.priority == "critical" or overdue
    escalation_active = (
        sla.escalation_required
        and sla.escalation_ref is not None
        and sla.escalation_owner_ref is not None
        and sla.escalation_started_at is not None
    )
    if escalation_needed and not escalation_active:
        _add(
            findings,
            code="escalation_required",
            gate="sla",
            status="fail",
            message="Critical priority or SLA breach requires an active escalation.",
            subject_ref=case.case_ref,
        )
    elif overdue:
        _add(
            findings,
            code="resolution_sla_breached_escalated",
            gate="sla",
            status="review",
            message="Resolution SLA is breached, but an escalation is active.",
            subject_ref=case.case_ref,
        )

    remedy = inputs.remedy
    service_remedies = {"warranty_repair", "rma", "field_service"}
    if (
        inputs.target == "resolution"
        and remedy is not None
        and (
            remedy.case_ref != case.case_ref or remedy.customer_ref != case.customer_ref
        )
    ):
        _add(
            findings,
            code="remedy_case_customer_mismatch",
            gate="remedy",
            status="fail",
            message="Remedy request must bind the exact evaluated case and customer.",
            subject_ref=remedy.remedy_ref,
        )
    fulfillment = inputs.fulfillment
    if (
        inputs.target == "resolution"
        and fulfillment is not None
        and (
            fulfillment.case_ref != case.case_ref
            or fulfillment.customer_ref != case.customer_ref
        )
    ):
        _add(
            findings,
            code="fulfillment_case_customer_mismatch",
            gate="fulfillment",
            status="fail",
            message=(
                "Service fulfillment must bind the exact evaluated case and customer."
            ),
            subject_ref=fulfillment.fulfillment_ref,
        )
    if (
        inputs.target == "resolution"
        and remedy is not None
        and remedy.kind in {"refund", "credit"}
        and inputs.policy.require_financial_remedy_approval
    ):
        if remedy.approval_ref is None:
            _add(
                findings,
                code="financial_remedy_approval_missing",
                gate="remedy",
                status="fail",
                message="Refund or credit requires a host-verified approval reference.",
                subject_ref=remedy.remedy_ref,
            )
    if (
        inputs.target == "resolution"
        and remedy is not None
        and remedy.kind in service_remedies
        and inputs.policy.require_entitlement_for_service_remedy
    ):
        entitlement = inputs.entitlement
        if entitlement is None:
            _add(
                findings,
                code="service_entitlement_missing",
                gate="entitlement",
                status="indeterminate",
                message="Warranty/RMA/field-service remedy lacks entitlement evidence.",
                subject_ref=remedy.remedy_ref,
            )
        elif entitlement.customer_ref != case.customer_ref:
            _add(
                findings,
                code="entitlement_customer_mismatch",
                gate="entitlement",
                status="fail",
                message="Entitlement and case customer references do not match.",
                subject_ref=entitlement.entitlement_ref,
            )
        elif entitlement.coverage in {"expired", "not_found"}:
            _add(
                findings,
                code="service_entitlement_inactive",
                gate="entitlement",
                status="fail",
                message="Service entitlement is expired or not found.",
                subject_ref=entitlement.entitlement_ref,
            )
        elif entitlement.coverage == "unknown":
            _add(
                findings,
                code="service_entitlement_unknown",
                gate="entitlement",
                status="indeterminate",
                message="Service entitlement coverage is unknown.",
                subject_ref=entitlement.entitlement_ref,
            )
        elif (
            entitlement.coverage_ends_at is not None
            and _parsed_timestamp(entitlement.coverage_ends_at) < analysis_at
        ):
            _add(
                findings,
                code="service_entitlement_expired_at_cutoff",
                gate="entitlement",
                status="fail",
                message="Entitlement end date precedes the analysis cutoff.",
                subject_ref=entitlement.entitlement_ref,
            )

    if (
        inputs.target == "resolution"
        and remedy is not None
        and remedy.kind in service_remedies
    ):
        if fulfillment is None:
            _add(
                findings,
                code="service_fulfillment_missing",
                gate="fulfillment",
                status="indeterminate",
                message="Service remedy lacks fulfillment evidence.",
                subject_ref=remedy.remedy_ref,
            )
        elif fulfillment.kind != remedy.kind:
            _add(
                findings,
                code="service_fulfillment_kind_mismatch",
                gate="fulfillment",
                status="fail",
                message="Fulfillment kind does not match the approved remedy request.",
                subject_ref=fulfillment.fulfillment_ref,
            )
        elif (
            remedy.kind == "rma"
            and inputs.entitlement is not None
            and (
                inputs.entitlement.asset_ref is None
                or inputs.entitlement.serial_ref is None
                or fulfillment.asset_ref != inputs.entitlement.asset_ref
                or fulfillment.serial_ref != inputs.entitlement.serial_ref
            )
        ):
            _add(
                findings,
                code="rma_fulfillment_entitlement_identity_mismatch",
                gate="fulfillment",
                status="fail",
                message=(
                    "RMA fulfillment asset and serial must exactly match the "
                    "entitlement."
                ),
                subject_ref=fulfillment.fulfillment_ref,
            )
        elif fulfillment.status != "completed":
            _add(
                findings,
                code="service_fulfillment_incomplete",
                gate="fulfillment",
                status="fail",
                message="Service fulfillment is not completed.",
                subject_ref=fulfillment.fulfillment_ref,
            )
        elif (
            remedy.kind in {"warranty_repair", "rma"}
            and fulfillment.diagnostic_ref is None
        ):
            _add(
                findings,
                code="repair_diagnostic_missing",
                gate="fulfillment",
                status="indeterminate",
                message="Completed repair/RMA lacks diagnostic evidence.",
                subject_ref=fulfillment.fulfillment_ref,
            )

    if inputs.target == "resolution":
        resolution = inputs.resolution
        if resolution is None:
            _add(
                findings,
                code="resolution_evidence_missing",
                gate="resolution",
                status="indeterminate",
                message="Resolution verification evidence is missing.",
                subject_ref=case.case_ref,
            )
        else:
            if (
                resolution.case_ref != case.case_ref
                or resolution.customer_ref != case.customer_ref
            ):
                _add(
                    findings,
                    code="resolution_case_customer_mismatch",
                    gate="resolution",
                    status="fail",
                    message=(
                        "Resolution snapshot must bind the exact evaluated case and "
                        "customer."
                    ),
                    subject_ref=resolution.resolution_ref,
                )
            if resolution.reopened or resolution.customer_verification == "rejected":
                _add(
                    findings,
                    code="resolution_rejected_or_reopened",
                    gate="resolution",
                    status="fail",
                    message="The customer rejected the resolution or the case reopened.",
                    subject_ref=resolution.resolution_ref,
                )
            elif resolution.customer_verification == "pending":
                _add(
                    findings,
                    code="customer_resolution_confirmation_pending",
                    gate="resolution",
                    status="indeterminate",
                    message="Customer resolution confirmation is pending.",
                    subject_ref=resolution.resolution_ref,
                )
            elif resolution.customer_verification == "unreachable":
                _add(
                    findings,
                    code="customer_unreachable_for_confirmation",
                    gate="resolution",
                    status=(
                        "review"
                        if inputs.policy.allow_unreachable_customer_manual_review
                        else "fail"
                    ),
                    message="Customer could not be reached to verify resolution.",
                    subject_ref=resolution.resolution_ref,
                )
            if (
                inputs.policy.require_customer_resolution_confirmation
                and not resolution.outcome_verified
            ):
                _add(
                    findings,
                    code="resolution_outcome_unverified",
                    gate="resolution",
                    status="fail",
                    message="The claimed customer outcome is not verified.",
                    subject_ref=resolution.resolution_ref,
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
        ServiceGateResult(
            gate=gate,
            status=_status([item for item in ordered_findings if item.gate == gate]),
            finding_codes=tuple(
                item.code for item in ordered_findings if item.gate == gate
            ),
        )
        for gate in _GATE_ORDER
    )
    statuses = {gate.status for gate in gates}
    if "escalation_required" in {item.code for item in findings}:
        disposition: Disposition = "escalation_required"
    elif "fail" in statuses:
        disposition = "blocked"
    elif "indeterminate" in statuses:
        disposition = "indeterminate"
    elif "review" in statuses:
        disposition = "manual_review_required"
    elif inputs.target == "triage":
        disposition = "ready_for_assignment"
    else:
        disposition = "ready_for_resolution_approval"

    assurance_grade = min(
        (item.verification_grade for item in evidence),
        key=lambda grade: _GRADE_RANK[grade],
    )
    source_digests = {
        "case": service_snapshot_digest(case),
        "policy": service_snapshot_digest(inputs.policy),
        "sla": service_snapshot_digest(sla),
        "remedy": (
            service_snapshot_digest(remedy)
            if remedy is not None
            else _stable_digest(None)
        ),
        "entitlement": (
            service_snapshot_digest(inputs.entitlement)
            if inputs.entitlement is not None
            else _stable_digest(None)
        ),
        "fulfillment": (
            service_snapshot_digest(inputs.fulfillment)
            if inputs.fulfillment is not None
            else _stable_digest(None)
        ),
        "resolution": (
            service_snapshot_digest(inputs.resolution)
            if inputs.resolution is not None
            else _stable_digest(None)
        ),
    }
    result = ServiceControlResult(
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


def _example_evidence(ref: str, character: str, *, subject_ref: str) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": ref,
        "kind": "normalized_service_snapshot",
        "issuer_ref": "spring-service-authority",
        "subject_ref": subject_ref,
        "sha256": character * 64,
        "observed_at": "2026-08-24T12:00:00Z",
        "verification_grade": "attested",
        "classification": "confidential",
        "retention_policy": "service-seven-years",
        "jurisdiction": "US",
    }


class EvaluateCaseResolutionControlsPrimitive(
    BusinessProcessPrimitive[ServiceControlInput, ServiceControlResult]
):
    primitive_ref = "service.evaluate_case_resolution_controls"
    version = "1.0.0"
    title = "Evaluate customer-service case controls"
    description = (
        "Evaluate evidence-bound case intake, SLA, escalation, entitlement, remedy, "
        "fulfillment, and resolution controls without changing service systems."
    )
    input_model = ServiceControlInput
    output_model = ServiceControlResult
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "evaluation_ref": "service-evaluation-1042",
        "target": "triage",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "case": {
            "case_ref": "case-1042",
            "customer_ref": "customer-42",
            "channel": "email",
            "opened_at": "2026-08-24T10:00:00Z",
            "status": "assigned",
            "category_ref": "delivery-damage",
            "classification_confidence": "0.950000",
            "priority": "normal",
            "owner_ref": "agent-ada",
            "summary": "Customer reports transit damage.",
            "evidence_refs": [
                _example_evidence("case-evidence", "a", subject_ref="case-1042")
            ],
        },
        "sla": {
            "case_ref": "case-1042",
            "customer_ref": "customer-42",
            "policy_ref": "sla-standard",
            "first_response_due_at": "2026-08-24T11:00:00Z",
            "first_response_at": "2026-08-24T10:30:00Z",
            "resolution_due_at": "2026-08-26T10:00:00Z",
            "evidence_refs": [
                _example_evidence("sla-evidence", "b", subject_ref="case-1042")
            ],
        },
    }

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = SERVICE_CONTROL_OPERATION.to_dict()
        contract["capability_hints"] = [
            "crm.read_case",
            "support.read_sla",
            "billing.read_transaction",
            "field_service.read_work_order",
            "knowledge.read_article_revision",
        ]
        contract["capability_hints_are_dispatch_authority"] = False
        contract["effect_boundary"] = ServiceEffectBoundary().to_dict()
        contract["system_of_record_authority"] = "trusted_host_required"
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ServiceControlInput,
    ) -> PrimitiveExecutionResult[ServiceControlResult]:
        del context
        output = evaluate_service_case_controls(inputs)
        evidence_refs = sorted(
            _all_evidence(inputs), key=lambda item: item.evidence_ref
        )
        receipt = PrimitiveOperationReceipt(
            spec=SERVICE_CONTROL_OPERATION,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=service_snapshot_digest(inputs),
            external_refs={"result_digest": output.result_digest},
            evidence_refs=evidence_refs,
        )
        return PrimitiveExecutionResult[ServiceControlResult](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Service controls evaluated; the result proposes "
                f"{output.proposed_disposition} and grants no execution authority."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="service.case_controls_evaluated",
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
                    kind="service_control_result",
                    summary=(
                        "The SDK evaluated normalized service evidence without closing "
                        "a case, issuing money, authorizing service, or dispatching work."
                    ),
                    refs={"result_sha256": output.result_digest},
                )
            ],
            evidence_refs=evidence_refs,
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "SERVICE_CASE_SNAPSHOT_SCHEMA",
    "SERVICE_CONTROL_INPUT_SCHEMA",
    "SERVICE_CONTROL_RESULT_SCHEMA",
    "SERVICE_CONTROL_OPERATION",
    "EntitlementSnapshot",
    "EvaluateCaseResolutionControlsPrimitive",
    "RemedyRequest",
    "ResolutionSnapshot",
    "ServiceCaseSnapshot",
    "ServiceControlInput",
    "ServiceControlPolicy",
    "ServiceControlResult",
    "ServiceEffectBoundary",
    "ServiceFinding",
    "ServiceFulfillmentSnapshot",
    "ServiceGateResult",
    "ServiceSlaSnapshot",
    "evaluate_service_case_controls",
    "service_snapshot_digest",
]
