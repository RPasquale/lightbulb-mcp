"""Deterministic warranty, depot-repair, and field-service projections.

The SDK validates and materializes one immutable candidate transition.  It does
not authenticate the supplied Spring evidence, authorize a remedy, create an
RMA or work order, dispatch a technician, move inventory, ship an asset,
perform work, mutate a customer-service case, or close anything.  Spring owns
scope, RBAC, approval, persistence, idempotency, audit, and write admission;
the relevant service, field-service, depot, inventory, and logistics systems
remain authoritative for operational facts and effects.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Mapping, Sequence, Union
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
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


SERVICE_ASSET_REMEDY_SCOPE_SCHEMA = "lightbulb.service_asset_remedy_scope.v1"
SERVICE_ASSET_REMEDY_EVIDENCE_SCHEMA = "lightbulb.service_asset_remedy_evidence.v1"
SERVICE_ASSET_REMEDY_AUTHORIZATION_SCHEMA = (
    "lightbulb.service_asset_remedy_authorization_commitment.v1"
)
SERVICE_ASSET_REMEDY_TRANSITION_RECORD_SCHEMA = (
    "lightbulb.service_asset_remedy_transition_record.v1"
)
SERVICE_ASSET_REMEDY_SNAPSHOT_SCHEMA = "lightbulb.service_asset_remedy_snapshot.v1"
SERVICE_ASSET_REMEDY_REQUEST_SCHEMA = (
    "lightbulb.service_asset_remedy_transition_request.v1"
)
SERVICE_ASSET_REMEDY_PROPOSAL_SCHEMA = (
    "lightbulb.service_asset_remedy_transition_proposal.v1"
)
SERVICE_ASSET_REMEDY_RESULT_SCHEMA = (
    "lightbulb.service_asset_remedy_transition_result.v1"
)
SPRING_SERVICE_ASSET_EVIDENCE_ISSUER = "spring-service-authority"
SPRING_SERVICE_ASSET_EVIDENCE_CUSTODIAN = "spring:service-evidence-vault"
SERVICE_ASSET_REMEDY_ZERO_DIGEST = "0" * 64
MAX_SERVICE_ASSET_TRANSITIONS = 9
MAX_EVIDENCE_PER_TRANSITION = 8
MAX_PARTS_PER_REMEDY = 32
MAX_MONEY = Decimal("1000000000000.00")
MAX_EVIDENCE_AGE = timedelta(hours=72)
MIN_EVIDENCE_RETENTION = timedelta(days=365 * 7)
MAX_AUTHORIZATION_WINDOW = timedelta(hours=24)
MAX_LIFECYCLE_WINDOW = timedelta(days=90)


ServiceAssetRemedyBranch = Literal["depot_repair", "field_service"]
ServiceAssetRemedyState = Literal[
    "entitlement_validated",
    "depot_custody_recorded",
    "field_service_planned",
    "diagnosed",
    "work_prepared",
    "work_completed",
    "independently_verified",
    "returned_to_customer",
    "reinstalled_at_customer",
    "customer_resolution_verified",
    "closure_candidate",
]


class ServiceAssetRemedyError(ValueError):
    """Stable, fail-closed lifecycle error surfaced by the primitive wrapper."""

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
        str_strip_whitespace=False,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _stable_digest(value: Any) -> str:
    encoded = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: Any, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _visible(value: Any, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
    ):
        raise ValueError(
            f"{name} must contain visible ASCII characters without whitespace"
        )
    return value


def _quantity(value: Any) -> Decimal:
    if isinstance(value, float):
        raise ValueError("quantity must not be supplied as a binary float")
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError("quantity must be a decimal string, integer, or Decimal")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 32:
        raise ValueError("quantity must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("quantity must be a finite decimal") from exc
    if not parsed.is_finite() or parsed <= 0 or parsed > Decimal("1000000"):
        raise ValueError("quantity must be positive, finite, and bounded")
    if max(0, -parsed.as_tuple().exponent) > 6:
        raise ValueError("quantity supports at most six fractional digits")
    return parsed.normalize()


def _money(value: Any, *, name: str) -> Decimal:
    if isinstance(value, float):
        raise ValueError(f"{name} must not be supplied as a binary float")
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError(f"{name} must be a decimal string, integer, or Decimal")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 32:
        raise ValueError(f"{name} must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed > MAX_MONEY:
        raise ValueError(f"{name} must be non-negative, finite, and bounded")
    if max(0, -parsed.as_tuple().exponent) > 2:
        raise ValueError(f"{name} supports at most two fractional digits")
    return parsed.quantize(Decimal("0.01"))


def _money_product(quantity: Decimal, unit_cost: Decimal) -> Decimal:
    return (quantity * unit_cost).quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)


def _labor_cost(labor_minutes: int, hourly_rate: Decimal) -> Decimal:
    return (Decimal(labor_minutes) * hourly_rate / Decimal(60)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_EVEN
    )


class ServiceAssetRemedyScope(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_scope.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_SCOPE_SCHEMA,
        alias="schema",
    )
    tenant_ref: str = Field(min_length=1, max_length=160)
    company_ref: str = Field(min_length=1, max_length=160)
    project_ref: str = Field(min_length=1, max_length=160)
    project_id: UUID
    customer_ref: str = Field(min_length=1, max_length=160)
    case_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    product_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    remedy_ref: str = Field(min_length=1, max_length=160)
    branch: ServiceAssetRemedyBranch
    resolution_due_at: str

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
        "customer_ref",
        "case_ref",
        "asset_ref",
        "product_ref",
        "serial_ref",
        "remedy_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _visible(value, name=info.field_name)

    @field_validator("resolution_due_at")
    @classmethod
    def _deadline_is_utc(cls, value: str) -> str:
        return _utc(value, name="resolution_due_at")


def service_asset_remedy_scope_digest(
    scope: ServiceAssetRemedyScope | Mapping[str, Any],
) -> str:
    parsed = ServiceAssetRemedyScope.model_validate(_jsonable(scope))
    return _stable_digest(parsed)


class ServiceAssetRemedyEvidence(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_evidence.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_EVIDENCE_SCHEMA,
        alias="schema",
    )
    evidence_ref: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=96)
    issuer_ref: Literal["spring-service-authority"]
    custodian_ref: Literal["spring:service-evidence-vault"]
    subject_ref: str = Field(min_length=1, max_length=200)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    effective_at: str
    verification_grade: Literal["attested", "verified"]
    classification: Literal["restricted"]
    retention_policy: Literal["customer-service-seven-years"]
    retained_until: str
    single_use: Literal[True]
    causal_revision: int = Field(ge=0, le=MAX_SERVICE_ASSET_TRANSITIONS)
    causal_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_ref", "kind", "subject_ref")
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("observed_at", "effective_at", "retained_until")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _chronology_and_retention(self) -> "ServiceAssetRemedyEvidence":
        if _dt(self.effective_at) > _dt(self.observed_at):
            raise ValueError("evidence cannot be observed before it becomes effective")
        if _dt(self.retained_until) <= _dt(self.observed_at):
            raise ValueError("evidence retention must extend beyond observation")
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
            verification_grade=PrimitiveEvidenceVerificationGrade(
                self.verification_grade
            ),
            classification=PrimitiveEvidenceClassification(self.classification),
            retention_policy=self.retention_policy,
        )


class ServiceAssetRemedyAuthorizationCommitment(_StrictModel):
    """Spring-attested commitment to one existing case/RMA proposal and branch.

    The commitment proves only that the host recorded an authorization decision.
    Its explicit false flags prevent it from being treated as SDK execution or
    provider-write authority.
    """

    schema_id: Literal["lightbulb.service_asset_remedy_authorization_commitment.v1"] = (
        Field(default=SERVICE_ASSET_REMEDY_AUTHORIZATION_SCHEMA, alias="schema")
    )
    authorization_ref: str = Field(min_length=1, max_length=200)
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_case_snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_case_revision: int = Field(ge=1, le=128)
    remedy_proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    remedy_kind: Literal["rma", "field_service"]
    authorized_branch: ServiceAssetRemedyBranch
    authorized_by_ref: str = Field(min_length=1, max_length=160)
    authorized_role: Literal["returns_authorizer", "field_service_authorizer"]
    proposed_by_ref: str = Field(min_length=1, max_length=160)
    case_owner_ref: str = Field(min_length=1, max_length=160)
    case_resolver_ref: str | None = Field(default=None, min_length=1, max_length=160)
    decision: Literal["approved"]
    authorized_at: str
    expires_at: str
    single_use: Literal[True]
    sdk_execution_authority_granted: Literal[False]
    provider_write_authority_granted: Literal[False]
    authorization_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: ServiceAssetRemedyEvidence

    @field_validator(
        "authorization_ref",
        "lifecycle_ref",
        "authorized_by_ref",
        "proposed_by_ref",
        "case_owner_ref",
        "case_resolver_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _visible(value, name=info.field_name)

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _content_bound_and_independent(
        self,
    ) -> "ServiceAssetRemedyAuthorizationCommitment":
        expected_remedy_kind = (
            "rma" if self.authorized_branch == "depot_repair" else "field_service"
        )
        if self.remedy_kind != expected_remedy_kind:
            raise ValueError(
                "authorization remedy kind must exactly match the authorized branch"
            )
        expected_role = (
            "returns_authorizer"
            if self.authorized_branch == "depot_repair"
            else "field_service_authorizer"
        )
        if self.authorized_role != expected_role:
            raise ValueError(
                "authorization role must exactly match the authorized branch"
            )
        authorized_at = _dt(self.authorized_at)
        expires_at = _dt(self.expires_at)
        if (
            expires_at <= authorized_at
            or expires_at - authorized_at > MAX_AUTHORIZATION_WINDOW
        ):
            raise ValueError(
                "authorization validity must be positive and no longer than 24 hours"
            )
        if self.authorized_by_ref in {
            self.proposed_by_ref,
            self.case_owner_ref,
            self.case_resolver_ref,
        }:
            raise ValueError(
                "remedy authorizer must be independent of proposer, case owner, and resolver"
            )
        if self.authorization_digest != service_asset_remedy_authorization_digest(self):
            raise ValueError("authorization_digest does not match exact commitment")
        evidence = self.evidence
        if (
            evidence.kind != "service_asset_remedy_authorization"
            or evidence.subject_ref != self.authorization_ref
            or evidence.sha256 != self.authorization_digest
            or evidence.verification_grade != "verified"
            or evidence.observed_at != self.authorized_at
            or evidence.effective_at != self.authorized_at
            or evidence.causal_revision != 0
            or evidence.causal_state_digest != SERVICE_ASSET_REMEDY_ZERO_DIGEST
            or _dt(evidence.retained_until) < authorized_at + MIN_EVIDENCE_RETENTION
        ):
            raise ValueError(
                "authorization evidence must verify and retain the exact Spring commitment"
            )
        return self


def service_asset_remedy_authorization_digest(
    authorization: ServiceAssetRemedyAuthorizationCommitment | Mapping[str, Any],
) -> str:
    payload = _jsonable(authorization)
    payload.pop("authorization_digest", None)
    payload.pop("evidence", None)
    return _stable_digest(payload)


class ServicePartCustody(_StrictModel):
    part_ref: str = Field(min_length=1, max_length=160)
    lot_ref: str | None = Field(default=None, min_length=1, max_length=160)
    serial_ref: str | None = Field(default=None, min_length=1, max_length=160)
    quantity: Decimal
    currency_code: str = Field(pattern=r"^[A-Z]{3}$")
    unit_cost: Decimal
    extended_cost: Decimal
    source_inventory_ref: str = Field(min_length=1, max_length=160)
    custody_event_ref: str = Field(min_length=1, max_length=160)
    from_custodian_ref: str = Field(min_length=1, max_length=160)
    to_technician_ref: str = Field(min_length=1, max_length=160)
    transferred_at: str

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity_is_exact(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator("unit_cost", "extended_cost", mode="before")
    @classmethod
    def _cost_is_exact(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator(
        "part_ref",
        "lot_ref",
        "serial_ref",
        "source_inventory_ref",
        "custody_event_ref",
        "from_custodian_ref",
        "to_technician_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _visible(value, name=info.field_name)

    @field_validator("transferred_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="transferred_at")

    @model_validator(mode="after")
    def _traceability_is_present(self) -> "ServicePartCustody":
        if self.lot_ref is None and self.serial_ref is None:
            raise ValueError("each used part requires lot or serial traceability")
        if self.serial_ref is not None and self.quantity != Decimal(1):
            raise ValueError("serialized part quantity must be exactly one")
        if self.from_custodian_ref == self.to_technician_ref:
            raise ValueError("part custody must transfer between distinct custodians")
        if self.extended_cost != _money_product(self.quantity, self.unit_cost):
            raise ValueError(
                "part extended_cost must equal exact quantity multiplied by unit_cost"
            )
        return self


class ServicePartInstallation(_StrictModel):
    """Candidate custody continuation from one prepared part to the serviced asset."""

    part_ref: str = Field(min_length=1, max_length=160)
    lot_ref: str | None = Field(default=None, min_length=1, max_length=160)
    serial_ref: str | None = Field(default=None, min_length=1, max_length=160)
    quantity: Decimal
    source_custody_event_ref: str = Field(min_length=1, max_length=160)
    installation_event_ref: str = Field(min_length=1, max_length=160)
    from_technician_ref: str = Field(min_length=1, max_length=160)
    to_asset_ref: str = Field(min_length=1, max_length=160)
    installed_at: str

    @field_validator("quantity", mode="before")
    @classmethod
    def _quantity_is_exact(cls, value: Any) -> Decimal:
        return _quantity(value)

    @field_validator(
        "part_ref",
        "lot_ref",
        "serial_ref",
        "source_custody_event_ref",
        "installation_event_ref",
        "from_technician_ref",
        "to_asset_ref",
    )
    @classmethod
    def _refs_are_exact(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _visible(value, name=info.field_name)

    @field_validator("installed_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="installed_at")

    @model_validator(mode="after")
    def _traceability_is_exact(self) -> "ServicePartInstallation":
        if self.lot_ref is None and self.serial_ref is None:
            raise ValueError("each installed part requires lot or serial traceability")
        if self.serial_ref is not None and self.quantity != Decimal(1):
            raise ValueError("serialized installed part quantity must be exactly one")
        if self.source_custody_event_ref == self.installation_event_ref:
            raise ValueError(
                "part installation and source custody event identities must differ"
            )
        if self.from_technician_ref == self.to_asset_ref:
            raise ValueError(
                "part installation must transfer between technician and asset"
            )
        return self


class _Command(_StrictModel):
    @model_validator(mode="after")
    def _all_refs_are_exact(self) -> "_Command":
        for field_name in type(self).model_fields:
            value = getattr(self, field_name, None)
            if isinstance(value, str) and field_name.endswith("_ref"):
                _visible(value, name=field_name)
        return self


class ValidateWarrantyEntitlementCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_validate_warranty_entitlement_command.v1"
    ] = Field(
        default="lightbulb.service_asset_validate_warranty_entitlement_command.v1",
        alias="schema",
    )
    kind: Literal["validate_warranty_entitlement"]
    entitlement_ref: str = Field(min_length=1, max_length=160)
    warranty_policy_ref: str = Field(min_length=1, max_length=160)
    contract_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    product_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    customer_ref: str = Field(min_length=1, max_length=160)
    coverage_status: Literal["covered"]
    coverage_started_at: str
    coverage_expires_at: str
    validated_at: str
    validator_ref: str = Field(min_length=1, max_length=160)

    @field_validator("coverage_started_at", "coverage_expires_at", "validated_at")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _coverage_is_current(self) -> "ValidateWarrantyEntitlementCommand":
        validated_at = _dt(self.validated_at)
        if not (
            _dt(self.coverage_started_at)
            <= validated_at
            < _dt(self.coverage_expires_at)
        ):
            raise ValueError("warranty entitlement must be active at validation")
        return self


class RecordDepotReceiptCommand(_Command):
    schema_id: Literal["lightbulb.service_asset_record_depot_receipt_command.v1"] = (
        Field(
            default="lightbulb.service_asset_record_depot_receipt_command.v1",
            alias="schema",
        )
    )
    kind: Literal["record_depot_receipt"]
    rma_ref: str = Field(min_length=1, max_length=160)
    inbound_shipment_ref: str = Field(min_length=1, max_length=160)
    custody_event_ref: str = Field(min_length=1, max_length=160)
    carrier_ref: str = Field(min_length=1, max_length=160)
    depot_ref: str = Field(min_length=1, max_length=160)
    from_customer_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    product_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    received_at: str
    receiving_ref: str = Field(min_length=1, max_length=160)

    @field_validator("received_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="received_at")


class PlanFieldServiceCommand(_Command):
    schema_id: Literal["lightbulb.service_asset_plan_field_service_command.v1"] = Field(
        default="lightbulb.service_asset_plan_field_service_command.v1",
        alias="schema",
    )
    kind: Literal["plan_field_service"]
    work_order_ref: str = Field(min_length=1, max_length=160)
    service_location_ref: str = Field(min_length=1, max_length=160)
    dispatcher_ref: str = Field(min_length=1, max_length=160)
    technician_ref: str = Field(min_length=1, max_length=160)
    competency_ref: str = Field(min_length=1, max_length=160)
    safety_plan_ref: str = Field(min_length=1, max_length=160)
    scheduled_start_at: str
    scheduled_end_at: str
    planned_at: str

    @field_validator("scheduled_start_at", "scheduled_end_at", "planned_at")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @model_validator(mode="after")
    def _schedule_is_bounded(self) -> "PlanFieldServiceCommand":
        if not (
            _dt(self.planned_at)
            <= _dt(self.scheduled_start_at)
            < _dt(self.scheduled_end_at)
        ):
            raise ValueError("field-service schedule must follow planning time")
        if self.dispatcher_ref == self.technician_ref:
            raise ValueError("field dispatcher and technician must be independent")
        return self


class RecordDiagnosticCommand(_Command):
    schema_id: Literal["lightbulb.service_asset_record_diagnostic_command.v1"] = Field(
        default="lightbulb.service_asset_record_diagnostic_command.v1",
        alias="schema",
    )
    kind: Literal["record_diagnostic"]
    diagnostic_ref: str = Field(min_length=1, max_length=160)
    remedy_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    failure_code_ref: str = Field(min_length=1, max_length=160)
    diagnostic_protocol_ref: str = Field(min_length=1, max_length=160)
    diagnostician_ref: str = Field(min_length=1, max_length=160)
    diagnosed_at: str
    repairability: Literal["repairable", "replace_required"]

    @field_validator("diagnosed_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="diagnosed_at")


class PrepareServiceWorkCommand(_Command):
    schema_id: Literal["lightbulb.service_asset_prepare_work_command.v1"] = Field(
        default="lightbulb.service_asset_prepare_work_command.v1", alias="schema"
    )
    kind: Literal["prepare_service_work"]
    work_order_ref: str = Field(min_length=1, max_length=160)
    technician_ref: str = Field(min_length=1, max_length=160)
    competency_ref: str = Field(min_length=1, max_length=160)
    competency_valid_until: str
    safety_plan_ref: str = Field(min_length=1, max_length=160)
    safety_acknowledged_at: str
    prepared_at: str
    parts: tuple[ServicePartCustody, ...] = Field(
        min_length=1, max_length=MAX_PARTS_PER_REMEDY
    )

    @field_validator("competency_valid_until", "safety_acknowledged_at", "prepared_at")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("parts", mode="before")
    @classmethod
    def _parts_are_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _competency_safety_and_parts_are_exact(self) -> "PrepareServiceWorkCommand":
        prepared_at = _dt(self.prepared_at)
        if _dt(self.competency_valid_until) < prepared_at:
            raise ValueError("technician competency must remain valid at preparation")
        if _dt(self.safety_acknowledged_at) > prepared_at:
            raise ValueError("safety acknowledgement cannot follow preparation")
        if any(_dt(part.transferred_at) > prepared_at for part in self.parts):
            raise ValueError("parts custody must precede work preparation")
        custody_refs = [part.custody_event_ref for part in self.parts]
        serial_refs = [part.serial_ref for part in self.parts if part.serial_ref]
        if len(set(custody_refs)) != len(custody_refs) or len(set(serial_refs)) != len(
            serial_refs
        ):
            raise ValueError("parts custody events and serialized parts must be unique")
        if any(part.to_technician_ref != self.technician_ref for part in self.parts):
            raise ValueError(
                "every part custody transfer must bind the exact technician"
            )
        return self


class RecordServiceWorkCompletionCommand(_Command):
    schema_id: Literal["lightbulb.service_asset_record_work_completion_command.v1"] = (
        Field(
            default="lightbulb.service_asset_record_work_completion_command.v1",
            alias="schema",
        )
    )
    kind: Literal["record_service_work_completion"]
    completion_ref: str = Field(min_length=1, max_length=160)
    work_order_ref: str = Field(min_length=1, max_length=160)
    technician_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    outcome: Literal["repaired", "replaced"]
    replacement_asset_ref: str | None = Field(
        default=None, min_length=1, max_length=160
    )
    replacement_serial_ref: str | None = Field(
        default=None, min_length=1, max_length=160
    )
    removed_serial_ref: str | None = Field(default=None, min_length=1, max_length=160)
    parts: tuple[ServicePartCustody, ...] = Field(
        min_length=1, max_length=MAX_PARTS_PER_REMEDY
    )
    installations: tuple[ServicePartInstallation, ...] = Field(
        min_length=1, max_length=MAX_PARTS_PER_REMEDY
    )
    labor_minutes: int = Field(gt=0, le=129_600)
    currency_code: str = Field(pattern=r"^[A-Z]{3}$")
    labor_hourly_rate: Decimal
    labor_cost: Decimal
    parts_cost: Decimal
    total_cost: Decimal
    started_at: str
    completed_at: str

    @field_validator(
        "labor_hourly_rate", "labor_cost", "parts_cost", "total_cost", mode="before"
    )
    @classmethod
    def _cost_is_exact(cls, value: Any, info: Any) -> Decimal:
        return _money(value, name=info.field_name)

    @field_validator("started_at", "completed_at")
    @classmethod
    def _time_is_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("parts", "installations", mode="before")
    @classmethod
    def _parts_are_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _execution_and_replacement_are_exact(
        self,
    ) -> "RecordServiceWorkCompletionCommand":
        replacement_fields = (
            self.replacement_asset_ref,
            self.replacement_serial_ref,
            self.removed_serial_ref,
        )
        if self.outcome == "replaced" and any(
            value is None for value in replacement_fields
        ):
            raise ValueError("replacement requires new asset/serial and removed serial")
        if self.outcome == "repaired" and any(
            value is not None for value in replacement_fields
        ):
            raise ValueError("repair cannot fabricate replacement genealogy")
        started_at = _dt(self.started_at)
        completed_at = _dt(self.completed_at)
        if started_at >= completed_at:
            raise ValueError("work start must precede work completion")
        if self.labor_minutes * 60 > (completed_at - started_at).total_seconds():
            raise ValueError(
                "labor minutes cannot exceed the bounded work execution interval"
            )
        expected_labor_cost = _labor_cost(self.labor_minutes, self.labor_hourly_rate)
        if self.labor_cost != expected_labor_cost:
            raise ValueError(
                "labor_cost must equal exact labor minutes multiplied by hourly rate"
            )
        expected_parts_cost = sum(
            (part.extended_cost for part in self.parts), Decimal("0.00")
        )
        if any(part.currency_code != self.currency_code for part in self.parts):
            raise ValueError(
                "all prepared part costs must use the exact execution currency"
            )
        if self.parts_cost != expected_parts_cost:
            raise ValueError("parts_cost must equal exact prepared part costs")
        if self.total_cost != self.labor_cost + self.parts_cost:
            raise ValueError("total_cost must equal exact labor and parts costs")

        custody_by_ref = {part.custody_event_ref: part for part in self.parts}
        installation_refs = [
            installation.installation_event_ref for installation in self.installations
        ]
        source_refs = [
            installation.source_custody_event_ref for installation in self.installations
        ]
        installed_serials = [
            installation.serial_ref
            for installation in self.installations
            if installation.serial_ref is not None
        ]
        if (
            len(custody_by_ref) != len(self.parts)
            or len(set(installation_refs)) != len(installation_refs)
            or len(set(source_refs)) != len(source_refs)
            or len(set(installed_serials)) != len(installed_serials)
            or set(source_refs) != set(custody_by_ref)
        ):
            raise ValueError(
                "each prepared part requires one unique installation custody continuation"
            )
        target_asset_ref = (
            self.replacement_asset_ref if self.outcome == "replaced" else self.asset_ref
        )
        for installation in self.installations:
            source = custody_by_ref[installation.source_custody_event_ref]
            if (
                installation.part_ref != source.part_ref
                or installation.lot_ref != source.lot_ref
                or installation.serial_ref != source.serial_ref
                or installation.quantity != source.quantity
                or installation.from_technician_ref != self.technician_ref
                or installation.to_asset_ref != target_asset_ref
            ):
                raise ValueError(
                    "part installation must continue exact prepared custody genealogy"
                )
            if not (started_at <= _dt(installation.installed_at) <= completed_at):
                raise ValueError(
                    "part installation must occur within the work execution interval"
                )
            if _dt(source.transferred_at) > started_at:
                raise ValueError(
                    "prepared part custody must precede the work execution interval"
                )
        return self


class VerifyIndependentRepairCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_verify_independent_repair_command.v1"
    ] = Field(
        default="lightbulb.service_asset_verify_independent_repair_command.v1",
        alias="schema",
    )
    kind: Literal["verify_independent_repair"]
    inspection_ref: str = Field(min_length=1, max_length=160)
    completion_ref: str = Field(min_length=1, max_length=160)
    inspector_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    test_protocol_ref: str = Field(min_length=1, max_length=160)
    test_result: Literal["passed"]
    inspected_at: str

    @field_validator("inspected_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="inspected_at")


class RecordDepotReturnDeliveryCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_record_depot_return_delivery_command.v1"
    ] = Field(
        default="lightbulb.service_asset_record_depot_return_delivery_command.v1",
        alias="schema",
    )
    kind: Literal["record_depot_return_delivery"]
    outbound_shipment_ref: str = Field(min_length=1, max_length=160)
    delivery_ref: str = Field(min_length=1, max_length=160)
    inspection_ref: str = Field(min_length=1, max_length=160)
    custody_event_ref: str = Field(min_length=1, max_length=160)
    from_depot_ref: str = Field(min_length=1, max_length=160)
    to_customer_ref: str = Field(min_length=1, max_length=160)
    carrier_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    delivered_at: str
    delivery_confirmer_ref: str = Field(min_length=1, max_length=160)

    @field_validator("delivered_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="delivered_at")


class RecordFieldReinstallationCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_record_field_reinstallation_command.v1"
    ] = Field(
        default="lightbulb.service_asset_record_field_reinstallation_command.v1",
        alias="schema",
    )
    kind: Literal["record_field_reinstallation"]
    reinstallation_ref: str = Field(min_length=1, max_length=160)
    delivery_ref: str = Field(min_length=1, max_length=160)
    inspection_ref: str = Field(min_length=1, max_length=160)
    service_location_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    technician_ref: str = Field(min_length=1, max_length=160)
    reinstalled_at: str

    @field_validator("reinstalled_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="reinstalled_at")


class VerifyCustomerResolutionCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_verify_customer_resolution_command.v1"
    ] = Field(
        default="lightbulb.service_asset_verify_customer_resolution_command.v1",
        alias="schema",
    )
    kind: Literal["verify_customer_resolution"]
    verification_ref: str = Field(min_length=1, max_length=160)
    case_ref: str = Field(min_length=1, max_length=160)
    delivery_ref: str = Field(min_length=1, max_length=160)
    customer_ref: str = Field(min_length=1, max_length=160)
    asset_ref: str = Field(min_length=1, max_length=160)
    serial_ref: str = Field(min_length=1, max_length=160)
    resolution_outcome: Literal["confirmed"]
    verified_at: str
    verifier_ref: str = Field(min_length=1, max_length=160)

    @field_validator("verified_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="verified_at")


class ProposeServiceClosureCandidateCommand(_Command):
    schema_id: Literal[
        "lightbulb.service_asset_propose_closure_candidate_command.v1"
    ] = Field(
        default="lightbulb.service_asset_propose_closure_candidate_command.v1",
        alias="schema",
    )
    kind: Literal["propose_service_closure_candidate"]
    closure_candidate_ref: str = Field(min_length=1, max_length=160)
    case_ref: str = Field(min_length=1, max_length=160)
    resolution_verification_ref: str = Field(min_length=1, max_length=160)
    closer_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str

    @field_validator("proposed_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="proposed_at")


ServiceAssetRemedyCommand = Annotated[
    Union[
        ValidateWarrantyEntitlementCommand,
        RecordDepotReceiptCommand,
        PlanFieldServiceCommand,
        RecordDiagnosticCommand,
        PrepareServiceWorkCommand,
        RecordServiceWorkCompletionCommand,
        VerifyIndependentRepairCommand,
        RecordDepotReturnDeliveryCommand,
        RecordFieldReinstallationCommand,
        VerifyCustomerResolutionCommand,
        ProposeServiceClosureCandidateCommand,
    ],
    Field(discriminator="kind"),
]
_COMMAND_ADAPTER = TypeAdapter(ServiceAssetRemedyCommand)


def service_asset_remedy_command_digest(
    command: ServiceAssetRemedyCommand | Mapping[str, Any],
) -> str:
    parsed = _COMMAND_ADAPTER.validate_python(_jsonable(command), strict=True)
    return _stable_digest(parsed)


def service_asset_remedy_idempotency_digest(
    scope: ServiceAssetRemedyScope | Mapping[str, Any],
    lifecycle_ref: str,
    idempotency_key: str,
) -> str:
    parsed_scope = ServiceAssetRemedyScope.model_validate(_jsonable(scope))
    clean_lifecycle = _visible(lifecycle_ref, name="lifecycle_ref")
    clean_key = _visible(idempotency_key, name="idempotency_key")
    if len(clean_key) < 8 or len(clean_key) > 200:
        raise ValueError("idempotency_key must contain 8 to 200 characters")
    return _stable_digest(
        {
            "schema": "lightbulb.service_asset_remedy_idempotency.v1",
            "scope_digest": service_asset_remedy_scope_digest(parsed_scope),
            "lifecycle_ref": clean_lifecycle,
            "idempotency_key": clean_key,
        }
    )


def service_asset_remedy_root_commitment_digest(
    scope: ServiceAssetRemedyScope | Mapping[str, Any],
    authorization: ServiceAssetRemedyAuthorizationCommitment | Mapping[str, Any],
) -> str:
    parsed_scope = ServiceAssetRemedyScope.model_validate(_jsonable(scope))
    parsed_authorization = ServiceAssetRemedyAuthorizationCommitment.model_validate(
        _jsonable(authorization)
    )
    return _stable_digest(
        {
            "schema": "lightbulb.service_asset_remedy_root_commitment.v1",
            "scope_digest": service_asset_remedy_scope_digest(parsed_scope),
            "source_case_snapshot_digest": (
                parsed_authorization.source_case_snapshot_digest
            ),
            "source_case_revision": parsed_authorization.source_case_revision,
            "remedy_proposal_digest": parsed_authorization.remedy_proposal_digest,
            "authorization_digest": parsed_authorization.authorization_digest,
            "authorized_branch": parsed_authorization.authorized_branch,
        }
    )


def _target_state(
    branch: ServiceAssetRemedyBranch,
    prior_state: ServiceAssetRemedyState | None,
    command: ServiceAssetRemedyCommand,
) -> ServiceAssetRemedyState:
    kind = command.kind
    if prior_state is None and kind == "validate_warranty_entitlement":
        return "entitlement_validated"
    if prior_state == "entitlement_validated":
        if branch == "depot_repair" and kind == "record_depot_receipt":
            return "depot_custody_recorded"
        if branch == "field_service" and kind == "plan_field_service":
            return "field_service_planned"
    if prior_state in {"depot_custody_recorded", "field_service_planned"} and kind == (
        "record_diagnostic"
    ):
        return "diagnosed"
    if prior_state == "diagnosed" and kind == "prepare_service_work":
        return "work_prepared"
    if prior_state == "work_prepared" and kind == "record_service_work_completion":
        return "work_completed"
    if prior_state == "work_completed" and kind == "verify_independent_repair":
        return "independently_verified"
    if prior_state == "independently_verified":
        if branch == "depot_repair" and kind == "record_depot_return_delivery":
            return "returned_to_customer"
        if branch == "field_service" and kind == "record_field_reinstallation":
            return "reinstalled_at_customer"
    if (
        prior_state
        in {
            "returned_to_customer",
            "reinstalled_at_customer",
        }
        and kind == "verify_customer_resolution"
    ):
        return "customer_resolution_verified"
    if (
        prior_state == "customer_resolution_verified"
        and kind == "propose_service_closure_candidate"
    ):
        return "closure_candidate"
    raise ValueError(
        f"command {kind!r} is not valid after state {prior_state!r} for branch {branch!r}"
    )


def _actor_for(command: ServiceAssetRemedyCommand) -> str:
    if isinstance(command, ValidateWarrantyEntitlementCommand):
        return command.validator_ref
    if isinstance(command, RecordDepotReceiptCommand):
        return command.receiving_ref
    if isinstance(command, PlanFieldServiceCommand):
        return command.dispatcher_ref
    if isinstance(command, RecordDiagnosticCommand):
        return command.diagnostician_ref
    if isinstance(command, PrepareServiceWorkCommand):
        return command.technician_ref
    if isinstance(command, RecordServiceWorkCompletionCommand):
        return command.technician_ref
    if isinstance(command, VerifyIndependentRepairCommand):
        return command.inspector_ref
    if isinstance(command, RecordDepotReturnDeliveryCommand):
        return command.delivery_confirmer_ref
    if isinstance(command, RecordFieldReinstallationCommand):
        return command.technician_ref
    if isinstance(command, VerifyCustomerResolutionCommand):
        return command.verifier_ref
    return command.closer_ref


def _event_time(command: ServiceAssetRemedyCommand) -> str:
    if isinstance(command, ValidateWarrantyEntitlementCommand):
        return command.validated_at
    if isinstance(command, RecordDepotReceiptCommand):
        return command.received_at
    if isinstance(command, PlanFieldServiceCommand):
        return command.planned_at
    if isinstance(command, RecordDiagnosticCommand):
        return command.diagnosed_at
    if isinstance(command, PrepareServiceWorkCommand):
        return command.prepared_at
    if isinstance(command, RecordServiceWorkCompletionCommand):
        return command.completed_at
    if isinstance(command, VerifyIndependentRepairCommand):
        return command.inspected_at
    if isinstance(command, RecordDepotReturnDeliveryCommand):
        return command.delivered_at
    if isinstance(command, RecordFieldReinstallationCommand):
        return command.reinstalled_at
    if isinstance(command, VerifyCustomerResolutionCommand):
        return command.verified_at
    return command.proposed_at


def _fact_identity(command: ServiceAssetRemedyCommand) -> tuple[str, str]:
    if isinstance(command, ValidateWarrantyEntitlementCommand):
        return "warranty_entitlement_validation", command.entitlement_ref
    if isinstance(command, RecordDepotReceiptCommand):
        return "depot_asset_custody_receipt", command.custody_event_ref
    if isinstance(command, PlanFieldServiceCommand):
        return "governed_field_service_plan", command.work_order_ref
    if isinstance(command, RecordDiagnosticCommand):
        return "asset_diagnostic_failure_code", command.diagnostic_ref
    if isinstance(command, PrepareServiceWorkCommand):
        return "technician_parts_safety_custody", command.work_order_ref
    if isinstance(command, RecordServiceWorkCompletionCommand):
        return "service_work_execution", command.completion_ref
    if isinstance(command, VerifyIndependentRepairCommand):
        return "independent_repair_inspection_test", command.inspection_ref
    if isinstance(command, RecordDepotReturnDeliveryCommand):
        return "depot_return_delivery_custody", command.delivery_ref
    if isinstance(command, RecordFieldReinstallationCommand):
        return "field_reinstallation_delivery", command.reinstallation_ref
    if isinstance(command, VerifyCustomerResolutionCommand):
        return "customer_resolution_verification", command.verification_ref
    return "service_case_closure_candidate", command.closure_candidate_ref


def _transition_content_payload(
    *,
    scope_digest: str,
    root_commitment_digest: str,
    lifecycle_ref: str,
    target_revision: int,
    prior_state: ServiceAssetRemedyState | None,
    prior_state_digest: str,
    transition_ref: str,
    command_digest: str,
    idempotency_digest: str,
    requested_by_ref: str,
    proposed_at: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.service_asset_remedy_transition_content.v1",
        "scope_digest": scope_digest,
        "root_commitment_digest": root_commitment_digest,
        "lifecycle_ref": lifecycle_ref,
        "target_revision": target_revision,
        "prior_state": prior_state,
        "prior_state_digest": prior_state_digest,
        "transition_ref": transition_ref,
        "command_digest": command_digest,
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": requested_by_ref,
        "proposed_at": proposed_at,
    }


def service_asset_remedy_fact_evidence_digest(
    *,
    scope_digest: str,
    root_commitment_digest: str,
    lifecycle_ref: str,
    transition_ref: str,
    command_digest: str,
) -> str:
    return _stable_digest(
        {
            "schema": "lightbulb.service_asset_remedy_fact_evidence_commitment.v1",
            "scope_digest": scope_digest,
            "root_commitment_digest": root_commitment_digest,
            "lifecycle_ref": lifecycle_ref,
            "transition_ref": transition_ref,
            "command_digest": command_digest,
        }
    )


def service_asset_remedy_transition_evidence_digest(
    *, content_digest: str, fact_evidence_digest: str
) -> str:
    return _stable_digest(
        {
            "schema": "lightbulb.service_asset_remedy_transition_evidence_commitment.v1",
            "content_digest": content_digest,
            "fact_evidence_digest": fact_evidence_digest,
        }
    )


class ServiceAssetRemedyProjection(_StrictModel):
    entitlement_ref: str | None = None
    warranty_policy_ref: str | None = None
    entitlement_validated_at: str | None = None
    coverage_expires_at: str | None = None
    rma_ref: str | None = None
    depot_ref: str | None = None
    inbound_shipment_ref: str | None = None
    inbound_custody_event_ref: str | None = None
    depot_received_at: str | None = None
    field_work_order_ref: str | None = None
    service_location_ref: str | None = None
    dispatcher_ref: str | None = None
    scheduled_technician_ref: str | None = None
    scheduled_competency_ref: str | None = None
    scheduled_safety_plan_ref: str | None = None
    scheduled_start_at: str | None = None
    scheduled_end_at: str | None = None
    diagnostic_ref: str | None = None
    failure_code_ref: str | None = None
    diagnostician_ref: str | None = None
    diagnosed_at: str | None = None
    repairability: Literal["repairable", "replace_required"] | None = None
    work_order_ref: str | None = None
    technician_ref: str | None = None
    competency_ref: str | None = None
    competency_valid_until: str | None = None
    safety_plan_ref: str | None = None
    parts: tuple[ServicePartCustody, ...] = ()
    work_prepared_at: str | None = None
    completion_ref: str | None = None
    completion_outcome: Literal["repaired", "replaced"] | None = None
    serviced_asset_ref: str | None = None
    serviced_serial_ref: str | None = None
    part_installations: tuple[ServicePartInstallation, ...] = ()
    work_started_at: str | None = None
    work_completed_at: str | None = None
    labor_minutes: int | None = Field(default=None, gt=0, le=129_600)
    currency_code: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    labor_hourly_rate: Decimal | None = None
    labor_cost: Decimal | None = None
    parts_cost: Decimal | None = None
    total_cost: Decimal | None = None
    inspection_ref: str | None = None
    inspector_ref: str | None = None
    inspected_at: str | None = None
    delivery_ref: str | None = None
    delivery_confirmer_ref: str | None = None
    outbound_shipment_ref: str | None = None
    delivery_custody_event_ref: str | None = None
    delivered_at: str | None = None
    resolution_verification_ref: str | None = None
    resolution_verifier_ref: str | None = None
    customer_verified_at: str | None = None
    closure_candidate_ref: str | None = None
    closure_reviewer_ref: str | None = None
    closure_proposed_at: str | None = None

    @field_validator(
        "entitlement_validated_at",
        "coverage_expires_at",
        "depot_received_at",
        "scheduled_start_at",
        "scheduled_end_at",
        "diagnosed_at",
        "competency_valid_until",
        "work_prepared_at",
        "work_started_at",
        "work_completed_at",
        "inspected_at",
        "delivered_at",
        "customer_verified_at",
        "closure_proposed_at",
    )
    @classmethod
    def _times_are_utc(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _utc(value, name=info.field_name)

    @field_validator(
        "labor_hourly_rate", "labor_cost", "parts_cost", "total_cost", mode="before"
    )
    @classmethod
    def _cost_is_exact(cls, value: Any, info: Any) -> Decimal | None:
        return None if value is None else _money(value, name=info.field_name)

    @field_validator("parts", "part_installations", mode="before")
    @classmethod
    def _parts_are_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


def _empty_projection() -> ServiceAssetRemedyProjection:
    return ServiceAssetRemedyProjection()


def _apply_command(
    *,
    scope: ServiceAssetRemedyScope,
    authorization: ServiceAssetRemedyAuthorizationCommitment,
    prior_state: ServiceAssetRemedyState | None,
    projection: ServiceAssetRemedyProjection,
    command: ServiceAssetRemedyCommand,
    proposed_at: str,
    causal_not_before: str | None,
) -> ServiceAssetRemedyProjection:
    _target_state(scope.branch, prior_state, command)
    event_at = _dt(_event_time(command))
    if event_at > _dt(proposed_at):
        raise ServiceAssetRemedyError(
            "service_asset_future_command_fact",
            "command fact time cannot follow candidate proposal time",
        )
    if _dt(proposed_at) > _dt(scope.resolution_due_at):
        raise ServiceAssetRemedyError(
            "service_asset_resolution_deadline_elapsed",
            "candidate transition cannot be proposed after the bound resolution deadline",
        )
    forbidden_authority_actors = {
        authorization.authorized_by_ref,
        authorization.proposed_by_ref,
        authorization.case_owner_ref,
    }
    if authorization.case_resolver_ref is not None:
        forbidden_authority_actors.add(authorization.case_resolver_ref)

    if isinstance(command, ValidateWarrantyEntitlementCommand):
        if (
            command.asset_ref != scope.asset_ref
            or command.product_ref != scope.product_ref
            or command.serial_ref != scope.serial_ref
            or command.customer_ref != scope.customer_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_entitlement_scope_mismatch",
                "warranty entitlement must bind the exact customer, product, asset, and serial",
            )
        if command.validator_ref in forbidden_authority_actors:
            raise ServiceAssetRemedyError(
                "service_asset_entitlement_separation_of_duties",
                "entitlement validator must be independent of remedy authority actors",
            )
        if _dt(command.coverage_expires_at) <= _dt(proposed_at):
            raise ServiceAssetRemedyError(
                "service_asset_entitlement_expired",
                "warranty entitlement must remain active at candidate proposal time",
            )
        return projection.model_copy(
            update={
                "entitlement_ref": command.entitlement_ref,
                "warranty_policy_ref": command.warranty_policy_ref,
                "entitlement_validated_at": command.validated_at,
                "coverage_expires_at": command.coverage_expires_at,
            }
        )

    if isinstance(command, RecordDepotReceiptCommand):
        if scope.branch != "depot_repair":
            raise ServiceAssetRemedyError(
                "service_asset_wrong_branch_artifact",
                "depot custody evidence is invalid for a field-service lifecycle",
            )
        if (
            command.rma_ref != scope.remedy_ref
            or command.asset_ref != scope.asset_ref
            or command.product_ref != scope.product_ref
            or command.serial_ref != scope.serial_ref
            or command.from_customer_ref != scope.customer_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_depot_custody_scope_mismatch",
                "depot receipt must bind the exact scoped remedy, customer, product, asset, and serial",
            )
        if command.receiving_ref in forbidden_authority_actors:
            raise ServiceAssetRemedyError(
                "service_asset_depot_receipt_separation_of_duties",
                "depot receiver must be independent of remedy authority actors",
            )
        return projection.model_copy(
            update={
                "rma_ref": command.rma_ref,
                "depot_ref": command.depot_ref,
                "inbound_shipment_ref": command.inbound_shipment_ref,
                "inbound_custody_event_ref": command.custody_event_ref,
                "depot_received_at": command.received_at,
            }
        )

    if isinstance(command, PlanFieldServiceCommand):
        if scope.branch != "field_service":
            raise ServiceAssetRemedyError(
                "service_asset_wrong_branch_artifact",
                "field-service plan is invalid for a depot-repair lifecycle",
            )
        if command.dispatcher_ref in forbidden_authority_actors or (
            command.technician_ref in forbidden_authority_actors
        ):
            raise ServiceAssetRemedyError(
                "service_asset_field_plan_separation_of_duties",
                "dispatcher and technician must be independent of remedy authority actors",
            )
        if command.work_order_ref != scope.remedy_ref:
            raise ServiceAssetRemedyError(
                "service_asset_field_remedy_scope_mismatch",
                "field-service plan must bind the exact scoped remedy work order",
            )
        if _dt(command.scheduled_end_at) > _dt(scope.resolution_due_at):
            raise ServiceAssetRemedyError(
                "service_asset_field_schedule_after_deadline",
                "field-service schedule cannot exceed the exact resolution deadline",
            )
        return projection.model_copy(
            update={
                "field_work_order_ref": command.work_order_ref,
                "service_location_ref": command.service_location_ref,
                "dispatcher_ref": command.dispatcher_ref,
                "scheduled_technician_ref": command.technician_ref,
                "scheduled_competency_ref": command.competency_ref,
                "scheduled_safety_plan_ref": command.safety_plan_ref,
                "scheduled_start_at": command.scheduled_start_at,
                "scheduled_end_at": command.scheduled_end_at,
            }
        )

    if isinstance(command, RecordDiagnosticCommand):
        if (
            command.remedy_ref != scope.remedy_ref
            or command.asset_ref != scope.asset_ref
            or command.serial_ref != scope.serial_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_diagnostic_scope_mismatch",
                "diagnostic evidence must bind the exact remedy, asset, and serial",
            )
        if command.diagnostician_ref in forbidden_authority_actors:
            raise ServiceAssetRemedyError(
                "service_asset_diagnostic_separation_of_duties",
                "diagnostician must be independent of remedy authority actors",
            )
        if scope.branch == "field_service" and command.diagnostician_ref != (
            projection.scheduled_technician_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_unplanned_field_technician",
                "field diagnostic must use the exact planned technician",
            )
        if scope.branch == "field_service" and not (
            _dt(projection.scheduled_start_at or "")
            <= _dt(command.diagnosed_at)
            <= _dt(projection.scheduled_end_at or "")
        ):
            raise ServiceAssetRemedyError(
                "service_asset_field_diagnostic_outside_schedule",
                "field diagnostic must occur within the exact governed schedule",
            )
        return projection.model_copy(
            update={
                "diagnostic_ref": command.diagnostic_ref,
                "failure_code_ref": command.failure_code_ref,
                "diagnostician_ref": command.diagnostician_ref,
                "diagnosed_at": command.diagnosed_at,
                "repairability": command.repairability,
            }
        )

    if isinstance(command, PrepareServiceWorkCommand):
        if command.technician_ref in forbidden_authority_actors:
            raise ServiceAssetRemedyError(
                "service_asset_work_preparation_separation_of_duties",
                "technician must be independent of remedy authority actors",
            )
        if scope.branch == "field_service" and (
            command.work_order_ref != projection.field_work_order_ref
            or command.technician_ref != projection.scheduled_technician_ref
            or command.competency_ref != projection.scheduled_competency_ref
            or command.safety_plan_ref != projection.scheduled_safety_plan_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_field_plan_binding_mismatch",
                "field work must use the exact planned work order, technician, competency, and safety plan",
            )
        if (
            scope.branch == "depot_repair"
            and command.work_order_ref == projection.rma_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_work_order_identity_collision",
                "depot work order and RMA identities must differ",
            )
        if _dt(command.safety_acknowledged_at) < _dt(projection.diagnosed_at or ""):
            raise ServiceAssetRemedyError(
                "service_asset_stale_safety_acknowledgement",
                "safety acknowledgement must follow the exact diagnostic",
            )
        if any(
            _dt(part.transferred_at) <= _dt(projection.diagnosed_at or "")
            for part in command.parts
        ):
            raise ServiceAssetRemedyError(
                "service_asset_parts_custody_non_causal",
                "parts custody must follow the exact diagnostic",
            )
        if causal_not_before is not None and (
            _dt(command.safety_acknowledged_at) <= _dt(causal_not_before)
            or any(
                _dt(part.transferred_at) <= _dt(causal_not_before)
                for part in command.parts
            )
        ):
            raise ServiceAssetRemedyError(
                "service_asset_preparation_fact_non_causal",
                "safety acknowledgement and parts custody must follow the diagnostic transition",
            )
        if scope.branch == "field_service" and _dt(command.prepared_at) > _dt(
            projection.scheduled_end_at or ""
        ):
            raise ServiceAssetRemedyError(
                "service_asset_field_preparation_outside_schedule",
                "field work preparation must remain within the governed schedule",
            )
        return projection.model_copy(
            update={
                "work_order_ref": command.work_order_ref,
                "technician_ref": command.technician_ref,
                "competency_ref": command.competency_ref,
                "competency_valid_until": command.competency_valid_until,
                "safety_plan_ref": command.safety_plan_ref,
                "parts": command.parts,
                "work_prepared_at": command.prepared_at,
            }
        )

    if isinstance(command, RecordServiceWorkCompletionCommand):
        if (
            command.work_order_ref != projection.work_order_ref
            or command.technician_ref != projection.technician_ref
            or command.asset_ref != scope.asset_ref
            or command.serial_ref != scope.serial_ref
            or command.parts != projection.parts
        ):
            raise ServiceAssetRemedyError(
                "service_asset_work_genealogy_mismatch",
                "completion must bind the prepared work order, technician, asset, serial, and parts genealogy",
            )
        if command.outcome == "repaired" and projection.repairability != "repairable":
            raise ServiceAssetRemedyError(
                "service_asset_repairability_mismatch",
                "a repair outcome conflicts with replace-required diagnostic evidence",
            )
        if (
            command.outcome == "replaced"
            and projection.repairability != "replace_required"
        ):
            raise ServiceAssetRemedyError(
                "service_asset_repairability_mismatch",
                "a replacement outcome requires exact replace-required diagnostic evidence",
            )
        if _dt(command.started_at) < _dt(projection.work_prepared_at or ""):
            raise ServiceAssetRemedyError(
                "service_asset_work_started_before_preparation",
                "work execution must follow the exact prepared work candidate",
            )
        if causal_not_before is not None and (
            _dt(command.started_at) <= _dt(causal_not_before)
            or any(
                _dt(installation.installed_at) <= _dt(causal_not_before)
                for installation in command.installations
            )
        ):
            raise ServiceAssetRemedyError(
                "service_asset_execution_fact_non_causal",
                "work start and part installation must follow the preparation transition",
            )
        if _dt(command.completed_at) > _dt(projection.competency_valid_until or ""):
            raise ServiceAssetRemedyError(
                "service_asset_technician_competency_expired",
                "technician competency must remain valid through work completion",
            )
        if scope.branch == "field_service" and not (
            _dt(projection.scheduled_start_at or "")
            <= _dt(command.started_at)
            < _dt(command.completed_at)
            <= _dt(projection.scheduled_end_at or "")
        ):
            raise ServiceAssetRemedyError(
                "service_asset_field_completion_outside_schedule",
                "field work execution must remain within the governed schedule",
            )
        if command.outcome == "replaced" and (
            command.removed_serial_ref != scope.serial_ref
            or command.replacement_serial_ref == scope.serial_ref
            or command.replacement_asset_ref == scope.asset_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_replacement_genealogy_mismatch",
                "replacement must remove the authorized serial and introduce distinct asset and serial identities",
            )
        serviced_asset_ref = (
            command.replacement_asset_ref
            if command.outcome == "replaced"
            else scope.asset_ref
        )
        serviced_serial_ref = (
            command.replacement_serial_ref
            if command.outcome == "replaced"
            else scope.serial_ref
        )
        return projection.model_copy(
            update={
                "completion_ref": command.completion_ref,
                "completion_outcome": command.outcome,
                "serviced_asset_ref": serviced_asset_ref,
                "serviced_serial_ref": serviced_serial_ref,
                "part_installations": command.installations,
                "work_started_at": command.started_at,
                "work_completed_at": command.completed_at,
                "labor_minutes": command.labor_minutes,
                "currency_code": command.currency_code,
                "labor_hourly_rate": command.labor_hourly_rate,
                "labor_cost": command.labor_cost,
                "parts_cost": command.parts_cost,
                "total_cost": command.total_cost,
            }
        )

    if isinstance(command, VerifyIndependentRepairCommand):
        if (
            command.completion_ref != projection.completion_ref
            or command.asset_ref != projection.serviced_asset_ref
            or command.serial_ref != projection.serviced_serial_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_inspection_genealogy_mismatch",
                "inspection must bind the exact serviced asset and serial",
            )
        if command.inspector_ref in forbidden_authority_actors | {
            projection.technician_ref,
            projection.diagnostician_ref,
        }:
            raise ServiceAssetRemedyError(
                "service_asset_inspection_separation_of_duties",
                "independent inspection cannot be performed by an authority actor, diagnostician, or technician",
            )
        return projection.model_copy(
            update={
                "inspection_ref": command.inspection_ref,
                "inspector_ref": command.inspector_ref,
                "inspected_at": command.inspected_at,
            }
        )

    if isinstance(command, RecordDepotReturnDeliveryCommand):
        if scope.branch != "depot_repair":
            raise ServiceAssetRemedyError(
                "service_asset_wrong_branch_artifact",
                "depot return delivery is invalid for a field-service lifecycle",
            )
        if (
            command.from_depot_ref != projection.depot_ref
            or command.to_customer_ref != scope.customer_ref
            or command.inspection_ref != projection.inspection_ref
            or command.asset_ref != projection.serviced_asset_ref
            or command.serial_ref != projection.serviced_serial_ref
            or command.custody_event_ref == projection.inbound_custody_event_ref
            or command.outbound_shipment_ref == projection.inbound_shipment_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_return_genealogy_mismatch",
                "return delivery must continue the exact depot, customer, asset, serial, and custody genealogy",
            )
        if command.delivery_confirmer_ref in forbidden_authority_actors | {
            projection.technician_ref,
            projection.inspector_ref,
        }:
            raise ServiceAssetRemedyError(
                "service_asset_delivery_separation_of_duties",
                "delivery confirmation must be independent of repair and inspection",
            )
        return projection.model_copy(
            update={
                "delivery_ref": command.delivery_ref,
                "delivery_confirmer_ref": command.delivery_confirmer_ref,
                "outbound_shipment_ref": command.outbound_shipment_ref,
                "delivery_custody_event_ref": command.custody_event_ref,
                "delivered_at": command.delivered_at,
            }
        )

    if isinstance(command, RecordFieldReinstallationCommand):
        if scope.branch != "field_service":
            raise ServiceAssetRemedyError(
                "service_asset_wrong_branch_artifact",
                "field reinstallation is invalid for a depot-repair lifecycle",
            )
        if (
            command.service_location_ref != projection.service_location_ref
            or command.inspection_ref != projection.inspection_ref
            or command.asset_ref != projection.serviced_asset_ref
            or command.serial_ref != projection.serviced_serial_ref
            or command.technician_ref != projection.technician_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_reinstallation_genealogy_mismatch",
                "reinstallation must bind the planned location and exact serviced asset, serial, and technician",
            )
        if _dt(command.reinstalled_at) > _dt(projection.scheduled_end_at or ""):
            raise ServiceAssetRemedyError(
                "service_asset_field_reinstallation_outside_schedule",
                "field reinstallation must remain within the governed schedule",
            )
        if _dt(command.reinstalled_at) > _dt(projection.competency_valid_until or ""):
            raise ServiceAssetRemedyError(
                "service_asset_reinstallation_competency_expired",
                "technician competency must remain valid through field reinstallation",
            )
        return projection.model_copy(
            update={
                "delivery_ref": command.delivery_ref,
                "delivery_confirmer_ref": command.technician_ref,
                "delivered_at": command.reinstalled_at,
            }
        )

    if isinstance(command, VerifyCustomerResolutionCommand):
        if (
            command.case_ref != scope.case_ref
            or command.delivery_ref != projection.delivery_ref
            or command.customer_ref != scope.customer_ref
            or command.asset_ref != projection.serviced_asset_ref
            or command.serial_ref != projection.serviced_serial_ref
        ):
            raise ServiceAssetRemedyError(
                "service_asset_resolution_scope_mismatch",
                "resolution verification must bind the exact case, customer, serviced asset, and serial",
            )
        if command.verifier_ref in forbidden_authority_actors | {
            projection.technician_ref,
            projection.diagnostician_ref,
            projection.inspector_ref,
            projection.delivery_confirmer_ref,
        }:
            raise ServiceAssetRemedyError(
                "service_asset_resolution_separation_of_duties",
                "customer resolution verification must be independent of authority, repair, and inspection",
            )
        return projection.model_copy(
            update={
                "resolution_verification_ref": command.verification_ref,
                "resolution_verifier_ref": command.verifier_ref,
                "customer_verified_at": command.verified_at,
            }
        )

    if command.case_ref != scope.case_ref or command.resolution_verification_ref != (
        projection.resolution_verification_ref
    ):
        raise ServiceAssetRemedyError(
            "service_asset_closure_scope_mismatch",
            "closure candidate must bind the exact case and customer verification",
        )
    if command.closer_ref in forbidden_authority_actors | {
        projection.diagnostician_ref,
        projection.technician_ref,
        projection.inspector_ref,
        projection.delivery_confirmer_ref,
        projection.resolution_verifier_ref,
    }:
        raise ServiceAssetRemedyError(
            "service_asset_closure_separation_of_duties",
            "closure reviewer must be independent of authority, execution, inspection, and resolution verification",
        )
    return projection.model_copy(
        update={
            "closure_candidate_ref": command.closure_candidate_ref,
            "closure_reviewer_ref": command.closer_ref,
            "closure_proposed_at": command.proposed_at,
        }
    )


class ServiceAssetRemedyTransitionRecord(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_transition_record.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_TRANSITION_RECORD_SCHEMA, alias="schema"
    )
    revision: int = Field(ge=1, le=MAX_SERVICE_ASSET_TRANSITIONS)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_commitment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    transition_ref: str = Field(min_length=1, max_length=160)
    prior_state: ServiceAssetRemedyState | None = None
    target_state: ServiceAssetRemedyState
    prior_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    command: ServiceAssetRemedyCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    evidence_refs: tuple[ServiceAssetRemedyEvidence, ServiceAssetRemedyEvidence]
    evidence_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative_case_changed: Literal[False]
    rma_or_work_order_created: Literal[False]
    dispatch_or_shipping_executed: Literal[False]
    repair_or_inventory_write_executed: Literal[False]
    warranty_decision_executed: Literal[False]
    closure_executed: Literal[False]
    provider_write_executed: Literal[False]
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "lifecycle_ref", "transition_ref", "idempotency_key", "requested_by_ref"
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_is_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _digests_and_transition_are_exact(self) -> "ServiceAssetRemedyTransitionRecord":
        if self.command_digest != service_asset_remedy_command_digest(self.command):
            raise ValueError("record command_digest does not match command")
        if self.target_state != _target_state(
            # branch-specific legality is fully replayed by the snapshot/request;
            # the two branch-only commands identify their branch unambiguously.
            "field_service"
            if isinstance(
                self.command,
                (PlanFieldServiceCommand, RecordFieldReinstallationCommand),
            )
            else "depot_repair"
            if isinstance(
                self.command,
                (RecordDepotReceiptCommand, RecordDepotReturnDeliveryCommand),
            )
            else (
                "field_service"
                if self.prior_state
                in {"field_service_planned", "reinstalled_at_customer"}
                else "depot_repair"
            ),
            self.prior_state,
            self.command,
        ):
            raise ValueError("record target_state is invalid for its command")
        expected_content = _stable_digest(
            _transition_content_payload(
                scope_digest=self.scope_digest,
                root_commitment_digest=self.root_commitment_digest,
                lifecycle_ref=self.lifecycle_ref,
                target_revision=self.revision,
                prior_state=self.prior_state,
                prior_state_digest=self.prior_state_digest,
                transition_ref=self.transition_ref,
                command_digest=self.command_digest,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("record content_digest does not match transition content")
        if self.evidence_digest != _stable_digest(self.evidence_refs):
            raise ValueError("record evidence_digest does not match exact evidence")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("transition_digest", None)
        if self.transition_digest != _stable_digest(payload):
            raise ValueError("transition_digest does not match exact record")
        return self


def _validate_transition_evidence(
    *,
    evidence_refs: Sequence[ServiceAssetRemedyEvidence],
    scope_digest: str,
    root_commitment_digest: str,
    lifecycle_ref: str,
    transition_ref: str,
    content_digest: str,
    command: ServiceAssetRemedyCommand,
    command_digest: str,
    proposed_at: str,
    causal_revision: int,
    causal_state_digest: str,
    causal_not_before: str | None,
) -> None:
    if len(evidence_refs) != 2:
        raise ServiceAssetRemedyError(
            "service_asset_evidence_set_incomplete",
            "each transition requires exactly one content commitment and one stage fact",
        )
    evidence_ids = [item.evidence_ref for item in evidence_refs]
    evidence_digests = [item.sha256 for item in evidence_refs]
    if len(set(evidence_ids)) != len(evidence_ids) or len(set(evidence_digests)) != len(
        evidence_digests
    ):
        raise ServiceAssetRemedyError(
            "service_asset_evidence_collision",
            "transition evidence references and digests must be unique",
        )
    fact_kind, fact_subject = _fact_identity(command)
    fact_digest = service_asset_remedy_fact_evidence_digest(
        scope_digest=scope_digest,
        root_commitment_digest=root_commitment_digest,
        lifecycle_ref=lifecycle_ref,
        transition_ref=transition_ref,
        command_digest=command_digest,
    )
    commitment_digest = service_asset_remedy_transition_evidence_digest(
        content_digest=content_digest,
        fact_evidence_digest=fact_digest,
    )
    commitment = [
        item
        for item in evidence_refs
        if item.kind == "service_asset_remedy_transition_commitment"
    ]
    fact = [item for item in evidence_refs if item.kind == fact_kind]
    if len(commitment) != 1 or len(fact) != 1:
        raise ServiceAssetRemedyError(
            "service_asset_evidence_kind_mismatch",
            f"transition requires commitment evidence and exact fact kind {fact_kind!r}",
        )
    commitment_evidence = commitment[0]
    fact_evidence = fact[0]
    if (
        commitment_evidence.subject_ref != transition_ref
        or commitment_evidence.sha256 != commitment_digest
        or commitment_evidence.verification_grade != "attested"
    ):
        raise ServiceAssetRemedyError(
            "service_asset_transition_commitment_mismatch",
            "transition commitment evidence does not bind the exact candidate content",
        )
    if (
        fact_evidence.subject_ref != fact_subject
        or fact_evidence.sha256 != fact_digest
        or fact_evidence.verification_grade != "verified"
        or fact_evidence.effective_at != _event_time(command)
    ):
        raise ServiceAssetRemedyError(
            "service_asset_fact_evidence_mismatch",
            "stage fact evidence must verify the exact artifact, command, and fact time",
        )
    proposed = _dt(proposed_at)
    for evidence in evidence_refs:
        observed = _dt(evidence.observed_at)
        effective = _dt(evidence.effective_at)
        if (
            evidence.causal_revision != causal_revision
            or evidence.causal_state_digest != causal_state_digest
        ):
            raise ServiceAssetRemedyError(
                "service_asset_evidence_causality_mismatch",
                "transition evidence must bind the exact predecessor revision and digest",
            )
        if observed > proposed or proposed - observed > MAX_EVIDENCE_AGE:
            raise ServiceAssetRemedyError(
                "service_asset_evidence_stale_or_future",
                "transition evidence must be current and observed no later than proposal time",
            )
        if causal_not_before is not None and effective <= _dt(causal_not_before):
            raise ServiceAssetRemedyError(
                "service_asset_evidence_non_causal",
                "transition evidence must become effective after its exact predecessor",
            )
        if _dt(evidence.retained_until) < proposed + MIN_EVIDENCE_RETENTION:
            raise ServiceAssetRemedyError(
                "service_asset_evidence_retention_insufficient",
                "transition evidence must retain at least seven years beyond proposal",
            )


def _snapshot_payload(
    *,
    scope: ServiceAssetRemedyScope,
    authorization: ServiceAssetRemedyAuthorizationCommitment,
    root_commitment_digest: str,
    lifecycle_ref: str,
    history: Sequence[ServiceAssetRemedyTransitionRecord],
    projection: ServiceAssetRemedyProjection,
) -> dict[str, Any]:
    last = history[-1]
    return {
        "schema": SERVICE_ASSET_REMEDY_SNAPSHOT_SCHEMA,
        "scope": scope,
        "scope_digest": service_asset_remedy_scope_digest(scope),
        "authorization": authorization,
        "source_case_snapshot_digest": authorization.source_case_snapshot_digest,
        "source_case_revision": authorization.source_case_revision,
        "remedy_proposal_digest": authorization.remedy_proposal_digest,
        "authorization_digest": authorization.authorization_digest,
        "root_commitment_digest": root_commitment_digest,
        "lifecycle_ref": lifecycle_ref,
        "revision": last.revision,
        "state": last.target_state,
        "started_at": history[0].proposed_at,
        "updated_at": last.proposed_at,
        "history": tuple(history),
        "projection": projection,
        "customer_resolution_verified": last.target_state
        in {"customer_resolution_verified", "closure_candidate"},
        "closure_candidate_materialized": last.target_state == "closure_candidate",
        "authoritative_case_changed": False,
        "rma_or_work_order_created": False,
        "dispatch_or_shipping_executed": False,
        "repair_or_inventory_write_executed": False,
        "warranty_decision_executed": False,
        "closure_executed": False,
        "provider_write_executed": False,
    }


def _partial_snapshot_digest(
    *,
    scope: ServiceAssetRemedyScope,
    authorization: ServiceAssetRemedyAuthorizationCommitment,
    root_commitment_digest: str,
    lifecycle_ref: str,
    history: Sequence[ServiceAssetRemedyTransitionRecord],
    projection: ServiceAssetRemedyProjection,
) -> str:
    return _stable_digest(
        _snapshot_payload(
            scope=scope,
            authorization=authorization,
            root_commitment_digest=root_commitment_digest,
            lifecycle_ref=lifecycle_ref,
            history=history,
            projection=projection,
        )
    )


def _replay_history(
    *,
    scope: ServiceAssetRemedyScope,
    authorization: ServiceAssetRemedyAuthorizationCommitment,
    root_commitment_digest: str,
    lifecycle_ref: str,
    history: Sequence[ServiceAssetRemedyTransitionRecord],
) -> tuple[
    ServiceAssetRemedyState | None,
    str,
    ServiceAssetRemedyProjection,
]:
    scope_digest = service_asset_remedy_scope_digest(scope)
    state: ServiceAssetRemedyState | None = None
    state_digest = SERVICE_ASSET_REMEDY_ZERO_DIGEST
    projection = _empty_projection()
    accepted: list[ServiceAssetRemedyTransitionRecord] = []
    transition_refs: set[str] = set()
    idempotency_digests: set[str] = set()
    evidence_refs: set[str] = set()
    evidence_digests: set[str] = set()
    prior_proposed_at: str | None = None

    for expected_revision, raw_record in enumerate(history, start=1):
        try:
            record = ServiceAssetRemedyTransitionRecord.model_validate(
                _jsonable(raw_record)
            )
        except (TypeError, ValueError) as exc:
            raise ServiceAssetRemedyError(
                "service_asset_history_record_invalid",
                "prior history contains an invalid or forged transition record",
            ) from exc
        if (
            record.revision != expected_revision
            or record.scope_digest != scope_digest
            or record.root_commitment_digest != root_commitment_digest
            or record.lifecycle_ref != lifecycle_ref
            or record.prior_state != state
            or record.prior_state_digest != state_digest
        ):
            raise ServiceAssetRemedyError(
                "service_asset_history_chain_mismatch",
                "prior history must be a contiguous exact-scope state and digest chain",
            )
        if record.transition_ref in transition_refs:
            raise ServiceAssetRemedyError(
                "service_asset_transition_replay_conflict",
                "transition identity was already consumed in prior history",
            )
        if record.idempotency_digest in idempotency_digests:
            raise ServiceAssetRemedyError(
                "service_asset_idempotency_replay_conflict",
                "idempotency identity was already consumed in prior history",
            )
        expected_idempotency = service_asset_remedy_idempotency_digest(
            scope, lifecycle_ref, record.idempotency_key
        )
        if record.idempotency_digest != expected_idempotency:
            raise ServiceAssetRemedyError(
                "service_asset_idempotency_digest_mismatch",
                "prior history idempotency digest does not match its exact key and scope",
            )
        if record.requested_by_ref != _actor_for(record.command):
            raise ServiceAssetRemedyError(
                "service_asset_command_actor_mismatch",
                "prior transition requester must be the exact command actor",
            )
        if prior_proposed_at is not None and _dt(record.proposed_at) <= _dt(
            prior_proposed_at
        ):
            raise ServiceAssetRemedyError(
                "service_asset_non_monotonic_history",
                "transition proposals must be strictly chronological",
            )
        if expected_revision == 1 and not (
            _dt(authorization.authorized_at)
            <= _dt(record.proposed_at)
            <= _dt(authorization.expires_at)
        ):
            raise ServiceAssetRemedyError(
                "service_asset_authorization_not_current_at_start",
                "the first transition must occur within the exact authorization window",
            )
        if _dt(record.proposed_at) > _dt(scope.resolution_due_at):
            raise ServiceAssetRemedyError(
                "service_asset_resolution_deadline_elapsed",
                "prior transition exceeds the exact resolution deadline",
            )
        _validate_transition_evidence(
            evidence_refs=record.evidence_refs,
            scope_digest=scope_digest,
            root_commitment_digest=root_commitment_digest,
            lifecycle_ref=lifecycle_ref,
            transition_ref=record.transition_ref,
            content_digest=record.content_digest,
            command=record.command,
            command_digest=record.command_digest,
            proposed_at=record.proposed_at,
            causal_revision=expected_revision - 1,
            causal_state_digest=state_digest,
            causal_not_before=prior_proposed_at,
        )
        for evidence in record.evidence_refs:
            if (
                evidence.evidence_ref in evidence_refs
                or evidence.sha256 in evidence_digests
            ):
                raise ServiceAssetRemedyError(
                    "service_asset_global_evidence_replay",
                    "evidence references and commitments are single-use across the lifecycle",
                )
            evidence_refs.add(evidence.evidence_ref)
            evidence_digests.add(evidence.sha256)
        projection = _apply_command(
            scope=scope,
            authorization=authorization,
            prior_state=state,
            projection=projection,
            command=record.command,
            proposed_at=record.proposed_at,
            causal_not_before=prior_proposed_at,
        )
        state = _target_state(scope.branch, state, record.command)
        if state != record.target_state:
            raise ServiceAssetRemedyError(
                "service_asset_history_target_mismatch",
                "prior transition target does not match deterministic lifecycle replay",
            )
        accepted.append(record)
        state_digest = _partial_snapshot_digest(
            scope=scope,
            authorization=authorization,
            root_commitment_digest=root_commitment_digest,
            lifecycle_ref=lifecycle_ref,
            history=accepted,
            projection=projection,
        )
        transition_refs.add(record.transition_ref)
        idempotency_digests.add(record.idempotency_digest)
        prior_proposed_at = record.proposed_at
    return state, state_digest, projection


class ServiceAssetRemedySnapshot(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_snapshot.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    scope: ServiceAssetRemedyScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization: ServiceAssetRemedyAuthorizationCommitment
    source_case_snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_case_revision: int = Field(ge=1, le=128)
    remedy_proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_commitment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    revision: int = Field(ge=1, le=MAX_SERVICE_ASSET_TRANSITIONS)
    state: ServiceAssetRemedyState
    started_at: str
    updated_at: str
    history: tuple[ServiceAssetRemedyTransitionRecord, ...] = Field(
        min_length=1,
        max_length=MAX_SERVICE_ASSET_TRANSITIONS,
    )
    projection: ServiceAssetRemedyProjection
    customer_resolution_verified: bool
    closure_candidate_materialized: bool
    authoritative_case_changed: Literal[False]
    rma_or_work_order_created: Literal[False]
    dispatch_or_shipping_executed: Literal[False]
    repair_or_inventory_write_executed: Literal[False]
    warranty_decision_executed: Literal[False]
    closure_executed: Literal[False]
    provider_write_executed: Literal[False]
    state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("lifecycle_ref")
    @classmethod
    def _lifecycle_ref_is_exact(cls, value: str) -> str:
        return _visible(value, name="lifecycle_ref")

    @field_validator("started_at", "updated_at")
    @classmethod
    def _times_are_utc(cls, value: str, info: Any) -> str:
        return _utc(value, name=info.field_name)

    @field_validator("history", mode="before")
    @classmethod
    def _history_is_tuple(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _snapshot_is_content_bound(self) -> "ServiceAssetRemedySnapshot":
        if self.scope_digest != service_asset_remedy_scope_digest(self.scope):
            raise ValueError("snapshot scope_digest does not match exact scope")
        if self.revision != len(self.history):
            raise ValueError("snapshot revision must equal history length")
        if (
            self.source_case_snapshot_digest
            != self.authorization.source_case_snapshot_digest
            or self.source_case_revision != self.authorization.source_case_revision
            or self.remedy_proposal_digest != self.authorization.remedy_proposal_digest
            or self.authorization_digest != self.authorization.authorization_digest
            or self.root_commitment_digest
            != service_asset_remedy_root_commitment_digest(
                self.scope, self.authorization
            )
        ):
            raise ValueError("snapshot source authorization commitments do not match")
        if (
            self.history[-1].target_state != self.state
            or self.history[0].proposed_at != self.started_at
            or self.history[-1].proposed_at != self.updated_at
        ):
            raise ValueError("snapshot state and times must match exact history")
        if self.customer_resolution_verified != (
            self.state
            in {
                "customer_resolution_verified",
                "closure_candidate",
            }
        ):
            raise ValueError("snapshot resolution verification flag is inconsistent")
        if self.closure_candidate_materialized != (self.state == "closure_candidate"):
            raise ValueError("snapshot closure-candidate flag is inconsistent")
        try:
            replayed_state, replayed_digest, replayed_projection = _replay_history(
                scope=self.scope,
                authorization=self.authorization,
                root_commitment_digest=self.root_commitment_digest,
                lifecycle_ref=self.lifecycle_ref,
                history=self.history,
            )
        except ServiceAssetRemedyError as exc:
            raise ValueError("snapshot history failed deterministic replay") from exc
        if (
            replayed_state != self.state
            or replayed_digest != self.state_digest
            or replayed_projection != self.projection
        ):
            raise ValueError("snapshot projection does not match deterministic history")
        if self.state_digest != service_asset_remedy_snapshot_digest(self):
            raise ValueError("snapshot state_digest does not match exact content")
        return self


def service_asset_remedy_snapshot_digest(
    snapshot: ServiceAssetRemedySnapshot | Mapping[str, Any],
) -> str:
    payload = _jsonable(snapshot)
    payload.pop("state_digest", None)
    return _stable_digest(payload)


def _request_digest_from_candidate_snapshot(
    snapshot: ServiceAssetRemedySnapshot,
) -> str:
    latest = snapshot.history[-1]
    payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_REQUEST_SCHEMA,
        "scope": snapshot.scope,
        "scope_digest": snapshot.scope_digest,
        "authorization": snapshot.authorization,
        "root_commitment_digest": snapshot.root_commitment_digest,
        "lifecycle_ref": snapshot.lifecycle_ref,
        "expected_revision": latest.revision - 1,
        "expected_state_digest": latest.prior_state_digest,
        "prior_history": snapshot.history[:-1],
        "transition_ref": latest.transition_ref,
        "idempotency_key": latest.idempotency_key,
        "idempotency_digest": latest.idempotency_digest,
        "requested_by_ref": latest.requested_by_ref,
        "proposed_at": latest.proposed_at,
        "command": latest.command,
        "command_digest": latest.command_digest,
        "content_digest": latest.content_digest,
        "evidence_refs": latest.evidence_refs,
    }
    if latest.prior_state is not None:
        payload["expected_state"] = latest.prior_state
    return _stable_digest(payload)


class ServiceAssetRemedyTransitionRequest(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_transition_request.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_REQUEST_SCHEMA, alias="schema"
    )
    scope: ServiceAssetRemedyScope
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization: ServiceAssetRemedyAuthorizationCommitment
    root_commitment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    expected_revision: int = Field(ge=0, lt=MAX_SERVICE_ASSET_TRANSITIONS)
    expected_state: ServiceAssetRemedyState | None = None
    expected_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_history: tuple[ServiceAssetRemedyTransitionRecord, ...] = Field(
        max_length=MAX_SERVICE_ASSET_TRANSITIONS - 1
    )
    transition_ref: str = Field(min_length=1, max_length=160)
    idempotency_key: str = Field(min_length=8, max_length=200)
    idempotency_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_by_ref: str = Field(min_length=1, max_length=160)
    proposed_at: str
    command: ServiceAssetRemedyCommand
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_refs: tuple[ServiceAssetRemedyEvidence, ServiceAssetRemedyEvidence]
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "lifecycle_ref", "transition_ref", "idempotency_key", "requested_by_ref"
    )
    @classmethod
    def _refs_are_exact(cls, value: str, info: Any) -> str:
        return _visible(value, name=info.field_name)

    @field_validator("proposed_at")
    @classmethod
    def _time_is_utc(cls, value: str) -> str:
        return _utc(value, name="proposed_at")

    @field_validator("prior_history", "evidence_refs", mode="before")
    @classmethod
    def _sequences_are_tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _request_is_exact_and_content_bound(
        self,
    ) -> "ServiceAssetRemedyTransitionRequest":
        if self.scope_digest != service_asset_remedy_scope_digest(self.scope):
            raise ValueError("scope_digest does not match exact scope")
        authorization = self.authorization
        if (
            authorization.scope_digest != self.scope_digest
            or authorization.authorized_branch != self.scope.branch
            or authorization.lifecycle_ref != self.lifecycle_ref
        ):
            raise ValueError(
                "authorization does not bind the exact scope, branch, and lifecycle"
            )
        if (
            authorization.source_case_snapshot_digest
            == SERVICE_ASSET_REMEDY_ZERO_DIGEST
            or authorization.remedy_proposal_digest == SERVICE_ASSET_REMEDY_ZERO_DIGEST
        ):
            raise ValueError("source case and remedy commitments cannot be sentinels")
        expected_root = service_asset_remedy_root_commitment_digest(
            self.scope, authorization
        )
        if self.root_commitment_digest != expected_root:
            raise ValueError(
                "root_commitment_digest does not match exact authorization"
            )
        if _dt(self.scope.resolution_due_at) <= _dt(authorization.authorized_at) or (
            _dt(self.scope.resolution_due_at) - _dt(authorization.authorized_at)
            > MAX_LIFECYCLE_WINDOW
        ):
            raise ValueError("resolution deadline must be positive and within 90 days")
        if (self.expected_revision == 0) != (self.expected_state is None):
            raise ValueError("only revision zero may omit an expected state")
        if (self.expected_revision == 0) != (
            self.expected_state_digest == SERVICE_ASSET_REMEDY_ZERO_DIGEST
        ):
            raise ValueError("only revision zero may use the genesis state digest")
        if self.expected_revision != len(self.prior_history):
            raise ValueError("expected_revision must equal prior history length")
        if self.requested_by_ref != _actor_for(self.command):
            raise ValueError("requester must be the exact actor named by the command")
        if self.command_digest != service_asset_remedy_command_digest(self.command):
            raise ValueError("command_digest does not match exact command")
        expected_idempotency = service_asset_remedy_idempotency_digest(
            self.scope, self.lifecycle_ref, self.idempotency_key
        )
        if self.idempotency_digest != expected_idempotency:
            raise ValueError("idempotency_digest does not match exact key and scope")
        expected_content = _stable_digest(
            _transition_content_payload(
                scope_digest=self.scope_digest,
                root_commitment_digest=self.root_commitment_digest,
                lifecycle_ref=self.lifecycle_ref,
                target_revision=self.expected_revision + 1,
                prior_state=self.expected_state,
                prior_state_digest=self.expected_state_digest,
                transition_ref=self.transition_ref,
                command_digest=self.command_digest,
                idempotency_digest=self.idempotency_digest,
                requested_by_ref=self.requested_by_ref,
                proposed_at=self.proposed_at,
            )
        )
        if self.content_digest != expected_content:
            raise ValueError("content_digest does not match exact request content")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("request_digest", None)
        if self.request_digest != _stable_digest(payload):
            raise ValueError("request_digest does not match exact request")
        return self


class ServiceAssetRemedyTransitionProposal(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_transition_proposal.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_PROPOSAL_SCHEMA, alias="schema"
    )
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    root_commitment_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle_ref: str = Field(min_length=1, max_length=160)
    source_revision: int = Field(ge=0, lt=MAX_SERVICE_ASSET_TRANSITIONS)
    source_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_revision: int = Field(ge=1, le=MAX_SERVICE_ASSET_TRANSITIONS)
    target_state: ServiceAssetRemedyState
    transition_ref: str = Field(min_length=1, max_length=160)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    command_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transition_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_state_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_retry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_authorization_commitment_present: Literal[True]
    sdk_execution_authority_granted: Literal[False]
    authoritative_case_changed: Literal[False]
    rma_or_work_order_created: Literal[False]
    dispatch_or_shipping_executed: Literal[False]
    repair_or_inventory_write_executed: Literal[False]
    warranty_decision_executed: Literal[False]
    closure_executed: Literal[False]
    provider_write_executed: Literal[False]
    spring_submission_executed: Literal[False]
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _proposal_is_content_bound(self) -> "ServiceAssetRemedyTransitionProposal":
        if self.target_revision != self.source_revision + 1:
            raise ValueError("proposal target revision must advance exactly once")
        expected_retry = _stable_digest(
            {
                "schema": "lightbulb.service_asset_remedy_deterministic_retry.v1",
                "request_digest": self.request_digest,
                "candidate_state_digest": self.candidate_state_digest,
            }
        )
        if self.deterministic_retry_digest != expected_retry:
            raise ValueError("deterministic_retry_digest does not match exact result")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("proposal_digest", None)
        if self.proposal_digest != _stable_digest(payload):
            raise ValueError("proposal_digest does not match exact proposal")
        return self


class ServiceAssetRemedyTransitionResult(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_transition_result.v1"] = Field(
        default=SERVICE_ASSET_REMEDY_RESULT_SCHEMA, alias="schema"
    )
    proposal: ServiceAssetRemedyTransitionProposal
    candidate_snapshot: ServiceAssetRemedySnapshot
    sdk_execution_authority_granted: Literal[False]
    authoritative_case_changed: Literal[False]
    provider_write_executed: Literal[False]
    result_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _result_is_exact_and_content_bound(
        self,
    ) -> "ServiceAssetRemedyTransitionResult":
        proposal = self.proposal
        snapshot = self.candidate_snapshot
        latest = snapshot.history[-1]
        if (
            proposal.scope_digest != snapshot.scope_digest
            or proposal.root_commitment_digest != snapshot.root_commitment_digest
            or proposal.lifecycle_ref != snapshot.lifecycle_ref
            or proposal.source_revision != latest.revision - 1
            or proposal.source_state_digest != latest.prior_state_digest
            or proposal.target_revision != snapshot.revision
            or proposal.target_state != snapshot.state
            or proposal.transition_ref != latest.transition_ref
            or proposal.command_digest != latest.command_digest
            or proposal.transition_digest != snapshot.history[-1].transition_digest
            or proposal.candidate_state_digest != snapshot.state_digest
            or proposal.request_digest
            != _request_digest_from_candidate_snapshot(snapshot)
        ):
            raise ValueError("proposal does not bind the exact candidate snapshot")
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("result_digest", None)
        if self.result_digest != _stable_digest(payload):
            raise ValueError("result_digest does not match exact result")
        return self


def propose_service_asset_remedy_transition(
    request: ServiceAssetRemedyTransitionRequest | Mapping[str, Any],
) -> ServiceAssetRemedyTransitionResult:
    """Materialize one exact candidate after full immutable-history replay."""

    try:
        parsed = ServiceAssetRemedyTransitionRequest.model_validate(_jsonable(request))
    except (TypeError, ValueError) as exc:
        raise ServiceAssetRemedyError(
            "service_asset_request_invalid",
            "request is not a strict, content-bound service asset remedy transition",
        ) from exc

    state, state_digest, projection = _replay_history(
        scope=parsed.scope,
        authorization=parsed.authorization,
        root_commitment_digest=parsed.root_commitment_digest,
        lifecycle_ref=parsed.lifecycle_ref,
        history=parsed.prior_history,
    )
    if (
        parsed.expected_revision != len(parsed.prior_history)
        or parsed.expected_state != state
        or parsed.expected_state_digest != state_digest
    ):
        raise ServiceAssetRemedyError(
            "service_asset_optimistic_fence_mismatch",
            "expected revision, state, and digest must match deterministic history replay",
        )
    if parsed.transition_ref in {item.transition_ref for item in parsed.prior_history}:
        raise ServiceAssetRemedyError(
            "service_asset_transition_replay_conflict",
            "transition identity was already consumed by prior history",
        )
    if parsed.idempotency_digest in {
        item.idempotency_digest for item in parsed.prior_history
    }:
        raise ServiceAssetRemedyError(
            "service_asset_idempotency_replay_conflict",
            "idempotency identity was already consumed by prior history",
        )
    existing_evidence_refs = {
        evidence.evidence_ref
        for record in parsed.prior_history
        for evidence in record.evidence_refs
    }
    existing_evidence_digests = {
        evidence.sha256
        for record in parsed.prior_history
        for evidence in record.evidence_refs
    }
    if any(
        evidence.evidence_ref in existing_evidence_refs
        or evidence.sha256 in existing_evidence_digests
        for evidence in parsed.evidence_refs
    ):
        raise ServiceAssetRemedyError(
            "service_asset_global_evidence_replay",
            "new transition evidence must be globally single-use in this lifecycle",
        )
    prior_proposed_at = (
        parsed.prior_history[-1].proposed_at if parsed.prior_history else None
    )
    if prior_proposed_at is not None and _dt(parsed.proposed_at) <= _dt(
        prior_proposed_at
    ):
        raise ServiceAssetRemedyError(
            "service_asset_non_monotonic_transition",
            "new proposal time must strictly follow prior history",
        )
    if parsed.expected_revision == 0 and not (
        _dt(parsed.authorization.authorized_at)
        <= _dt(parsed.proposed_at)
        <= _dt(parsed.authorization.expires_at)
    ):
        raise ServiceAssetRemedyError(
            "service_asset_authorization_not_current_at_start",
            "first transition must occur within the exact authorization window",
        )
    try:
        target_state = _target_state(parsed.scope.branch, state, parsed.command)
    except ValueError as exc:
        raise ServiceAssetRemedyError(
            "service_asset_transition_invalid_for_state",
            str(exc),
        ) from exc
    _validate_transition_evidence(
        evidence_refs=parsed.evidence_refs,
        scope_digest=parsed.scope_digest,
        root_commitment_digest=parsed.root_commitment_digest,
        lifecycle_ref=parsed.lifecycle_ref,
        transition_ref=parsed.transition_ref,
        content_digest=parsed.content_digest,
        command=parsed.command,
        command_digest=parsed.command_digest,
        proposed_at=parsed.proposed_at,
        causal_revision=parsed.expected_revision,
        causal_state_digest=parsed.expected_state_digest,
        causal_not_before=prior_proposed_at,
    )
    next_projection = _apply_command(
        scope=parsed.scope,
        authorization=parsed.authorization,
        prior_state=state,
        projection=projection,
        command=parsed.command,
        proposed_at=parsed.proposed_at,
        causal_not_before=prior_proposed_at,
    )
    record_payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_TRANSITION_RECORD_SCHEMA,
        "revision": parsed.expected_revision + 1,
        "scope_digest": parsed.scope_digest,
        "root_commitment_digest": parsed.root_commitment_digest,
        "lifecycle_ref": parsed.lifecycle_ref,
        "transition_ref": parsed.transition_ref,
        "prior_state": parsed.expected_state,
        "target_state": target_state,
        "prior_state_digest": parsed.expected_state_digest,
        "command": parsed.command,
        "command_digest": parsed.command_digest,
        "content_digest": parsed.content_digest,
        "idempotency_key": parsed.idempotency_key,
        "idempotency_digest": parsed.idempotency_digest,
        "requested_by_ref": parsed.requested_by_ref,
        "proposed_at": parsed.proposed_at,
        "evidence_refs": parsed.evidence_refs,
        "evidence_digest": _stable_digest(parsed.evidence_refs),
        "authoritative_case_changed": False,
        "rma_or_work_order_created": False,
        "dispatch_or_shipping_executed": False,
        "repair_or_inventory_write_executed": False,
        "warranty_decision_executed": False,
        "closure_executed": False,
        "provider_write_executed": False,
    }
    record_payload["transition_digest"] = _stable_digest(
        {key: value for key, value in record_payload.items() if value is not None}
    )
    record = ServiceAssetRemedyTransitionRecord.model_validate(record_payload)
    history = (*parsed.prior_history, record)
    snapshot_payload = _snapshot_payload(
        scope=parsed.scope,
        authorization=parsed.authorization,
        root_commitment_digest=parsed.root_commitment_digest,
        lifecycle_ref=parsed.lifecycle_ref,
        history=history,
        projection=next_projection,
    )
    snapshot_payload["state_digest"] = _stable_digest(snapshot_payload)
    snapshot = ServiceAssetRemedySnapshot.model_validate(snapshot_payload)
    proposal_payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_PROPOSAL_SCHEMA,
        "scope_digest": parsed.scope_digest,
        "root_commitment_digest": parsed.root_commitment_digest,
        "lifecycle_ref": parsed.lifecycle_ref,
        "source_revision": parsed.expected_revision,
        "source_state_digest": parsed.expected_state_digest,
        "target_revision": snapshot.revision,
        "target_state": snapshot.state,
        "transition_ref": parsed.transition_ref,
        "request_digest": parsed.request_digest,
        "command_digest": parsed.command_digest,
        "transition_digest": record.transition_digest,
        "candidate_state_digest": snapshot.state_digest,
        "deterministic_retry_digest": _stable_digest(
            {
                "schema": "lightbulb.service_asset_remedy_deterministic_retry.v1",
                "request_digest": parsed.request_digest,
                "candidate_state_digest": snapshot.state_digest,
            }
        ),
        "source_authorization_commitment_present": True,
        "sdk_execution_authority_granted": False,
        "authoritative_case_changed": False,
        "rma_or_work_order_created": False,
        "dispatch_or_shipping_executed": False,
        "repair_or_inventory_write_executed": False,
        "warranty_decision_executed": False,
        "closure_executed": False,
        "provider_write_executed": False,
        "spring_submission_executed": False,
    }
    proposal_payload["proposal_digest"] = _stable_digest(proposal_payload)
    proposal = ServiceAssetRemedyTransitionProposal.model_validate(proposal_payload)
    result_payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_RESULT_SCHEMA,
        "proposal": proposal,
        "candidate_snapshot": snapshot,
        "sdk_execution_authority_granted": False,
        "authoritative_case_changed": False,
        "provider_write_executed": False,
    }
    result_payload["result_digest"] = _stable_digest(result_payload)
    return ServiceAssetRemedyTransitionResult.model_validate(result_payload)


class ServiceAssetRemedyEffectBoundary(_StrictModel):
    schema_id: Literal["lightbulb.service_asset_remedy_effect_boundary.v1"] = Field(
        default="lightbulb.service_asset_remedy_effect_boundary.v1",
        alias="schema",
    )
    sdk_projection_only: Literal[True] = True
    read_only_validation_completed: Literal[True] = True
    source_authorization_is_sdk_execution_authority: Literal[False] = False
    warranty_decision_executed: Literal[False] = False
    refund_or_credit_authorized_or_executed: Literal[False] = False
    rma_created_or_executed: Literal[False] = False
    shipping_or_dispatch_executed: Literal[False] = False
    repair_or_replacement_executed: Literal[False] = False
    parts_or_inventory_write_executed: Literal[False] = False
    work_order_created_or_changed: Literal[False] = False
    case_mutated_or_closed: Literal[False] = False
    provider_or_spring_write_executed: Literal[False] = False
    connector_calls: Literal[False] = False


SERVICE_ASSET_REMEDY_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="service-asset-remedy.validate-transition-candidate",
    tool="service.propose_asset_remedy_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


def _no_effect_recovery() -> PrimitiveRecoveryPlan:
    return PrimitiveRecoveryPlan(
        policy=PrimitiveOperationRecoveryPolicy.NONE,
        disposition=PrimitiveRecoveryDisposition.NOT_REQUIRED,
        instructions=(
            "No write or connector effect was attempted. Correct the exact inputs or "
            "obtain fresh Spring-custodied evidence before proposing a new candidate."
        ),
    )


def _receipt(
    *,
    status: PrimitiveOperationStatus,
    request_digest: str,
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    error: PrimitiveBlocker | None = None,
    external_refs: Mapping[str, str] | None = None,
) -> PrimitiveOperationReceipt:
    return PrimitiveOperationReceipt(
        spec=SERVICE_ASSET_REMEDY_TRANSITION_OPERATION,
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
    request: ServiceAssetRemedyTransitionRequest,
    context: PrimitiveExecutionContext,
) -> bool:
    scope = context.scope
    return (
        request.scope.tenant_ref == scope.tenant_ref
        and request.scope.company_ref == scope.company_ref
        and request.scope.project_ref == scope.project_ref
        and scope.project_id is not None
        and request.scope.project_id == scope.project_id
        and scope.actor_ref is not None
        and request.requested_by_ref == scope.actor_ref
        and context.idempotency_key is not None
        and request.idempotency_key == context.idempotency_key
    )


def _example_evidence(
    *,
    evidence_ref: str,
    kind: str,
    subject_ref: str,
    sha256: str,
    observed_at: str,
    effective_at: str,
    grade: Literal["attested", "verified"],
    causal_revision: int,
    causal_state_digest: str,
) -> dict[str, Any]:
    return {
        "schema": SERVICE_ASSET_REMEDY_EVIDENCE_SCHEMA,
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": SPRING_SERVICE_ASSET_EVIDENCE_ISSUER,
        "custodian_ref": SPRING_SERVICE_ASSET_EVIDENCE_CUSTODIAN,
        "subject_ref": subject_ref,
        "sha256": sha256,
        "observed_at": observed_at,
        "effective_at": effective_at,
        "verification_grade": grade,
        "classification": "restricted",
        "retention_policy": "customer-service-seven-years",
        "retained_until": "2034-09-01T00:00:00Z",
        "single_use": True,
        "causal_revision": causal_revision,
        "causal_state_digest": causal_state_digest,
    }


def _example_inputs() -> dict[str, Any]:
    scope: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_SCOPE_SCHEMA,
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "00000000-0000-0000-0000-000000000851",
        "customer_ref": "customer-example",
        "case_ref": "case-example",
        "asset_ref": "asset-example",
        "product_ref": "product-example",
        "serial_ref": "serial-example",
        "remedy_ref": "remedy-example",
        "branch": "depot_repair",
        "resolution_due_at": "2026-10-01T00:00:00Z",
    }
    scope_digest = service_asset_remedy_scope_digest(scope)
    authorization_payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_AUTHORIZATION_SCHEMA,
        "authorization_ref": "authorization-example",
        "lifecycle_ref": "service-asset-remedy-lifecycle-example",
        "scope_digest": scope_digest,
        "source_case_snapshot_digest": _stable_digest("case-snapshot-example"),
        "source_case_revision": 4,
        "remedy_proposal_digest": _stable_digest("remedy-proposal-example"),
        "remedy_kind": "rma",
        "authorized_branch": "depot_repair",
        "authorized_by_ref": "returns-authorizer-example",
        "authorized_role": "returns_authorizer",
        "proposed_by_ref": "case-proposer-example",
        "case_owner_ref": "case-owner-example",
        "decision": "approved",
        "authorized_at": "2026-08-25T12:00:00Z",
        "expires_at": "2026-08-26T12:00:00Z",
        "single_use": True,
        "sdk_execution_authority_granted": False,
        "provider_write_authority_granted": False,
    }
    authorization_digest = service_asset_remedy_authorization_digest(
        authorization_payload
    )
    authorization_payload["authorization_digest"] = authorization_digest
    authorization_payload["evidence"] = _example_evidence(
        evidence_ref="evidence-authorization-example",
        kind="service_asset_remedy_authorization",
        subject_ref="authorization-example",
        sha256=authorization_digest,
        observed_at="2026-08-25T12:00:00Z",
        effective_at="2026-08-25T12:00:00Z",
        grade="verified",
        causal_revision=0,
        causal_state_digest=SERVICE_ASSET_REMEDY_ZERO_DIGEST,
    )
    authorization = ServiceAssetRemedyAuthorizationCommitment.model_validate(
        authorization_payload
    )
    root_digest = service_asset_remedy_root_commitment_digest(scope, authorization)
    command: dict[str, Any] = {
        "schema": "lightbulb.service_asset_validate_warranty_entitlement_command.v1",
        "kind": "validate_warranty_entitlement",
        "entitlement_ref": "entitlement-example",
        "warranty_policy_ref": "warranty-policy-example",
        "contract_ref": "service-contract-example",
        "asset_ref": "asset-example",
        "product_ref": "product-example",
        "serial_ref": "serial-example",
        "customer_ref": "customer-example",
        "coverage_status": "covered",
        "coverage_started_at": "2026-01-01T00:00:00Z",
        "coverage_expires_at": "2027-01-01T00:00:00Z",
        "validated_at": "2026-08-25T12:30:00Z",
        "validator_ref": "warranty-validator-example",
    }
    lifecycle_ref = "service-asset-remedy-lifecycle-example"
    transition_ref = "transition-entitlement-example"
    idempotency_key = "idempotency-entitlement-example"
    proposed_at = "2026-08-25T13:00:00Z"
    command_digest = service_asset_remedy_command_digest(command)
    idempotency_digest = service_asset_remedy_idempotency_digest(
        scope, lifecycle_ref, idempotency_key
    )
    content_digest = _stable_digest(
        _transition_content_payload(
            scope_digest=scope_digest,
            root_commitment_digest=root_digest,
            lifecycle_ref=lifecycle_ref,
            target_revision=1,
            prior_state=None,
            prior_state_digest=SERVICE_ASSET_REMEDY_ZERO_DIGEST,
            transition_ref=transition_ref,
            command_digest=command_digest,
            idempotency_digest=idempotency_digest,
            requested_by_ref="warranty-validator-example",
            proposed_at=proposed_at,
        )
    )
    fact_digest = service_asset_remedy_fact_evidence_digest(
        scope_digest=scope_digest,
        root_commitment_digest=root_digest,
        lifecycle_ref=lifecycle_ref,
        transition_ref=transition_ref,
        command_digest=command_digest,
    )
    evidence = [
        _example_evidence(
            evidence_ref="evidence-transition-entitlement-example",
            kind="service_asset_remedy_transition_commitment",
            subject_ref=transition_ref,
            sha256=service_asset_remedy_transition_evidence_digest(
                content_digest=content_digest,
                fact_evidence_digest=fact_digest,
            ),
            observed_at="2026-08-25T12:59:00Z",
            effective_at="2026-08-25T12:59:00Z",
            grade="attested",
            causal_revision=0,
            causal_state_digest=SERVICE_ASSET_REMEDY_ZERO_DIGEST,
        ),
        _example_evidence(
            evidence_ref="evidence-entitlement-fact-example",
            kind="warranty_entitlement_validation",
            subject_ref="entitlement-example",
            sha256=fact_digest,
            observed_at="2026-08-25T12:55:00Z",
            effective_at="2026-08-25T12:30:00Z",
            grade="verified",
            causal_revision=0,
            causal_state_digest=SERVICE_ASSET_REMEDY_ZERO_DIGEST,
        ),
    ]
    request_payload: dict[str, Any] = {
        "schema": SERVICE_ASSET_REMEDY_REQUEST_SCHEMA,
        "scope": scope,
        "scope_digest": scope_digest,
        "authorization": authorization,
        "root_commitment_digest": root_digest,
        "lifecycle_ref": lifecycle_ref,
        "expected_revision": 0,
        "expected_state_digest": SERVICE_ASSET_REMEDY_ZERO_DIGEST,
        "prior_history": [],
        "transition_ref": transition_ref,
        "idempotency_key": idempotency_key,
        "idempotency_digest": idempotency_digest,
        "requested_by_ref": "warranty-validator-example",
        "proposed_at": proposed_at,
        "command": command,
        "command_digest": command_digest,
        "content_digest": content_digest,
        "evidence_refs": evidence,
    }
    request_payload["request_digest"] = _stable_digest(request_payload)
    return ServiceAssetRemedyTransitionRequest.model_validate(request_payload).to_dict()


class ProposeServiceAssetRemedyTransitionPrimitive(
    BusinessProcessPrimitive[
        ServiceAssetRemedyTransitionRequest,
        ServiceAssetRemedyTransitionResult,
    ]
):
    primitive_ref = "service.propose_asset_remedy_transition"
    version = "1.1.0"
    title = "Validate a governed warranty, repair, or field-service candidate"
    description = (
        "Replay and validate one exact-scope depot-repair or field-service candidate "
        "without authorizing or executing RMA, dispatch, shipping, work, inventory, "
        "case, closure, Spring, or provider changes."
    )
    input_model = ServiceAssetRemedyTransitionRequest
    output_model = ServiceAssetRemedyTransitionResult
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
            SERVICE_ASSET_REMEDY_TRANSITION_OPERATION.to_dict()
        )
        contract["effect_boundary"] = ServiceAssetRemedyEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "spring_control_plane": (
                "authenticated tenant/company/project/customer/case scope, RBAC, "
                "authorization authenticity, persistence, idempotency, audit, and writes"
            ),
            "operational_systems": (
                "warranty, RMA, depot, field-service, inventory, shipment, asset, "
                "case, and closure facts and effects"
            ),
            "sdk": "deterministic immutable read-only validation and candidate projection",
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_SERVICE_ASSET_TRANSITIONS,
            "branches": ["depot_repair", "field_service"],
            "history": "append-only exact-scope revision and state-digest replay",
            "evidence": (
                "exact kind, subject, content, grade, issuer, custodian, freshness, "
                "causal predecessor, single-use identity, and seven-year retention"
            ),
            "deterministic_retry": (
                "an identical immutable request produces the same result digest; "
                "consumed transition, idempotency, or evidence identity conflicts fail closed"
            ),
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ServiceAssetRemedyTransitionRequest,
    ) -> PrimitiveExecutionResult[ServiceAssetRemedyTransitionResult]:
        domain_evidence = [inputs.authorization.evidence, *inputs.evidence_refs]
        portable_evidence = [item.portable_ref() for item in domain_evidence]
        if not _request_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="service_asset_runtime_scope_mismatch",
                message=(
                    "Runtime tenant, company, project, project-id, actor, and "
                    "idempotency scope are required and must match the exact service request."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Service asset remedy candidate rejected at runtime scope boundary.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.request_digest,
                        evidence_refs=portable_evidence,
                        error=blocker,
                    )
                ],
                retryable=False,
            )
        try:
            output = propose_service_asset_remedy_transition(inputs)
        except ServiceAssetRemedyError as exc:
            blocker = PrimitiveBlocker(
                code=exc.code,
                message=exc.message,
                retryable=False,
            )
            return PrimitiveExecutionResult(
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Service asset remedy candidate failed deterministic validation.",
                blockers=[blocker],
                evidence_refs=portable_evidence,
                operation_receipts=[
                    _receipt(
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.request_digest,
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
                "Read-only service asset candidate validation completed. The candidate "
                "was not submitted, and no warranty, RMA, dispatch, shipment, work, "
                "parts, inventory, case, closure, Spring, or provider state changed."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="service.asset_remedy_transition_candidate_validated",
                    payload={
                        "lifecycle_ref": proposal.lifecycle_ref,
                        "transition_ref": proposal.transition_ref,
                        "target_state": proposal.target_state,
                        "proposal_digest": proposal.proposal_digest,
                        "result_digest": output.result_digest,
                        "authoritative_case_changed": False,
                        "provider_write_executed": False,
                        "spring_submission_executed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="service_asset_remedy_transition_proposal",
                    summary=(
                        "Content-bound SDK read-only candidate; Spring and operational "
                        "systems retain all fact, authority, persistence, and write custody."
                    ),
                    labels=[
                        inputs.scope.branch,
                        inputs.command.kind,
                        proposal.target_state,
                        "read_only",
                        "no_live_effect",
                    ],
                    refs={
                        "proposal_digest": proposal.proposal_digest,
                        "result_digest": output.result_digest,
                    },
                )
            ],
            evidence_refs=portable_evidence,
            operation_receipts=[
                _receipt(
                    status=PrimitiveOperationStatus.COMPLETED,
                    request_digest=inputs.request_digest,
                    evidence_refs=portable_evidence,
                    external_refs={
                        "candidate_state_digest": proposal.candidate_state_digest,
                        "proposal_digest": proposal.proposal_digest,
                        "result_digest": output.result_digest,
                        "transition_digest": proposal.transition_digest,
                    },
                )
            ],
            retryable=False,
        )


SERVICE_ASSET_REMEDY_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeServiceAssetRemedyTransitionPrimitive(),)


__all__ = [
    "MAX_SERVICE_ASSET_TRANSITIONS",
    "ProposeServiceAssetRemedyTransitionPrimitive",
    "ProposeServiceClosureCandidateCommand",
    "RecordDepotReceiptCommand",
    "RecordDepotReturnDeliveryCommand",
    "RecordDiagnosticCommand",
    "RecordFieldReinstallationCommand",
    "RecordServiceWorkCompletionCommand",
    "SERVICE_ASSET_REMEDY_AUTHORIZATION_SCHEMA",
    "SERVICE_ASSET_REMEDY_EVIDENCE_SCHEMA",
    "SERVICE_ASSET_REMEDY_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "SERVICE_ASSET_REMEDY_PROPOSAL_SCHEMA",
    "SERVICE_ASSET_REMEDY_REQUEST_SCHEMA",
    "SERVICE_ASSET_REMEDY_RESULT_SCHEMA",
    "SERVICE_ASSET_REMEDY_SCOPE_SCHEMA",
    "SERVICE_ASSET_REMEDY_SNAPSHOT_SCHEMA",
    "SERVICE_ASSET_REMEDY_TRANSITION_OPERATION",
    "SERVICE_ASSET_REMEDY_TRANSITION_RECORD_SCHEMA",
    "SERVICE_ASSET_REMEDY_ZERO_DIGEST",
    "SPRING_SERVICE_ASSET_EVIDENCE_CUSTODIAN",
    "SPRING_SERVICE_ASSET_EVIDENCE_ISSUER",
    "ServiceAssetRemedyAuthorizationCommitment",
    "ServiceAssetRemedyBranch",
    "ServiceAssetRemedyCommand",
    "ServiceAssetRemedyEffectBoundary",
    "ServiceAssetRemedyError",
    "ServiceAssetRemedyEvidence",
    "ServiceAssetRemedyProjection",
    "ServiceAssetRemedyScope",
    "ServiceAssetRemedySnapshot",
    "ServiceAssetRemedyState",
    "ServiceAssetRemedyTransitionProposal",
    "ServiceAssetRemedyTransitionRecord",
    "ServiceAssetRemedyTransitionRequest",
    "ServiceAssetRemedyTransitionResult",
    "ServicePartCustody",
    "ServicePartInstallation",
    "PlanFieldServiceCommand",
    "PrepareServiceWorkCommand",
    "ValidateWarrantyEntitlementCommand",
    "VerifyCustomerResolutionCommand",
    "VerifyIndependentRepairCommand",
    "propose_service_asset_remedy_transition",
    "service_asset_remedy_authorization_digest",
    "service_asset_remedy_command_digest",
    "service_asset_remedy_fact_evidence_digest",
    "service_asset_remedy_idempotency_digest",
    "service_asset_remedy_root_commitment_digest",
    "service_asset_remedy_scope_digest",
    "service_asset_remedy_snapshot_digest",
    "service_asset_remedy_transition_evidence_digest",
]
