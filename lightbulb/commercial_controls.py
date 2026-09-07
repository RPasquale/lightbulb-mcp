"""Deterministic commercial controls for quote-to-revenue workflows.

The SDK evaluates normalized, evidence-bound snapshots and proposes a bounded
disposition.  It never mutates or authorizes a quote, order, contract, bill,
entitlement, or commission.  Spring remains the authority for tenant/company
scope, RBAC, approvals, persistence, audit, and every consequential operation.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
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


COMMERCIAL_CONTROL_INPUT_SCHEMA = (
    "lightbulb.commercial_quote_order_contract_controls_input.v1"
)
COMMERCIAL_CONTROL_PROPOSAL_SCHEMA = (
    "lightbulb.commercial_quote_order_contract_controls_proposal.v1"
)
COMMERCIAL_CONFIGURATION_SCHEMA = "lightbulb.commercial_configuration_snapshot.v1"
COMMERCIAL_QUOTE_SCHEMA = "lightbulb.commercial_quote_snapshot.v1"
COMMERCIAL_ORDER_SCHEMA = "lightbulb.commercial_order_snapshot.v1"
COMMERCIAL_CONTRACT_SCHEMA = "lightbulb.commercial_contract_snapshot.v1"
COMMERCIAL_SUBSCRIPTION_SCHEMA = "lightbulb.commercial_subscription_snapshot.v1"
COMMERCIAL_USAGE_BILLING_SCHEMA = "lightbulb.commercial_usage_billing_snapshot.v1"
COMMERCIAL_RENEWAL_SCHEMA = "lightbulb.commercial_renewal_snapshot.v1"
COMMERCIAL_CHANNEL_SCHEMA = "lightbulb.commercial_channel_authorization_snapshot.v1"
COMMERCIAL_COMMISSION_SCHEMA = "lightbulb.commercial_commission_basis_snapshot.v1"
COMMERCIAL_REVENUE_OPS_SCHEMA = "lightbulb.commercial_revenue_ops_handoff_snapshot.v1"

_ZERO_DIGEST = "0" * 64
_OPAQUE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_DECIMAL = Decimal("1e24")
_DECIMAL_QUANTUM = Decimal("0.000001")
_REQUIRED_EVIDENCE_KINDS = (
    "cpq_configuration",
    "pricing",
    "quote_approval",
    "order_linkage",
    "contract_signature",
    "subscription_entitlement",
    "usage_billing",
    "renewal",
    "channel_partner",
    "commission_basis",
    "revenue_ops_handoff",
)
_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}

CommercialGateName = Literal[
    "evidence",
    "cpq_pricing",
    "quote_approval",
    "order_linkage",
    "contract_signature",
    "subscription_entitlement",
    "usage_billing",
    "renewal",
    "channel_partner",
    "commission_basis",
    "revenue_ops_handoff",
]
CommercialGateStatus = Literal["pass", "review", "fail", "indeterminate"]
CommercialFindingStatus = Literal["review", "fail", "indeterminate"]
CommercialDisposition = Literal[
    "ready", "manual_review_required", "blocked", "indeterminate"
]

_GATE_ORDER: tuple[CommercialGateName, ...] = (
    "evidence",
    "cpq_pricing",
    "quote_approval",
    "order_linkage",
    "contract_signature",
    "subscription_entitlement",
    "usage_billing",
    "renewal",
    "channel_partner",
    "commission_basis",
    "revenue_ops_handoff",
)


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("text must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("text contains an unsupported control character")
    return value


OpaqueRef = Annotated[str, StringConstraints(pattern=_OPAQUE_REF_PATTERN)]
ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=500),
    AfterValidator(_bounded_text),
]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


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


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError("decimal values must be strings or JSON numbers")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError("decimal values must use bounded notation")
    try:
        parsed = Decimal(lexical)
        normalized = parsed.quantize(_DECIMAL_QUANTUM)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(
            "decimal values must be finite and within supported precision"
        ) from exc
    if not parsed.is_finite() or abs(parsed) > _MAX_DECIMAL or parsed != normalized:
        raise ValueError(
            "decimal values support at most six places and bounded magnitude"
        )
    return normalized


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def commercial_snapshot_digest(snapshot: BaseModel | Mapping[str, Any]) -> str:
    """Return a stable digest for one normalized commercial snapshot."""

    if isinstance(snapshot, BaseModel):
        payload: Any = snapshot.model_dump(mode="json", by_alias=True)
    elif isinstance(snapshot, Mapping):
        payload = dict(snapshot)
    else:
        raise TypeError("snapshot must be a Pydantic model or mapping")
    return _stable_digest(payload)


def _require_unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} references must be unique")


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        strict=True,
    )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CommercialEvidencePolicy(_StrictModel):
    required_kinds: tuple[ShortText, ...] = Field(
        default=_REQUIRED_EVIDENCE_KINDS,
        max_length=40,
    )
    maximum_age_hours: int = Field(default=72, ge=1, le=8_760)
    minimum_verification_grade: PrimitiveEvidenceVerificationGrade = (
        PrimitiveEvidenceVerificationGrade.ATTESTED
    )
    require_effective_at: Literal[True] = True

    @field_validator("required_kinds", mode="before")
    @classmethod
    def _kinds_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @field_validator("minimum_verification_grade", mode="before")
    @classmethod
    def _grade_enum(cls, value: Any) -> PrimitiveEvidenceVerificationGrade:
        if isinstance(value, PrimitiveEvidenceVerificationGrade):
            return value
        return PrimitiveEvidenceVerificationGrade(str(value))

    @model_validator(mode="after")
    def _policy_cannot_weaken_baseline(self) -> "CommercialEvidencePolicy":
        _require_unique(self.required_kinds, label="required evidence kind")
        missing = set(_REQUIRED_EVIDENCE_KINDS) - set(self.required_kinds)
        if missing:
            raise ValueError("required_kinds cannot omit baseline commercial evidence")
        if (
            _GRADE_RANK[self.minimum_verification_grade]
            < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
        ):
            raise ValueError("minimum_verification_grade cannot be below attested")
        return self


class CommercialControlPolicy(_StrictModel):
    evidence: CommercialEvidencePolicy = Field(default_factory=CommercialEvidencePolicy)
    quote_approval_discount_threshold: Decimal = Field(
        default=Decimal("0.250000"), ge=0, le=1
    )
    amount_tolerance: Decimal = Field(default=Decimal("0.000000"), ge=0)
    renewal_horizon_days: int = Field(default=120, ge=1, le=730)
    require_partner_deal_registration: bool = True

    @field_validator(
        "quote_approval_discount_threshold", "amount_tolerance", mode="before"
    )
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class CommercialConfigurationLine(_StrictModel):
    configuration_line_ref: OpaqueRef
    product_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)
    list_unit_price: Decimal = Field(ge=0)
    configured_unit_price: Decimal = Field(ge=0)
    discount_ratio: Decimal = Field(ge=0, le=1)
    option_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=200)

    @field_validator(
        "quantity",
        "list_unit_price",
        "configured_unit_price",
        "discount_ratio",
        mode="before",
    )
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("option_refs", mode="before")
    @classmethod
    def _options_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _options_unique(self) -> "CommercialConfigurationLine":
        _require_unique(self.option_refs, label="configuration option")
        return self


class CommercialConfigurationSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_configuration_snapshot.v1"] = Field(
        default=COMMERCIAL_CONFIGURATION_SCHEMA, alias="schema"
    )
    configuration_ref: OpaqueRef
    revision: int = Field(ge=1)
    account_ref: OpaqueRef
    status: Literal["validated", "pending_review", "invalid", "retired"]
    price_book_ref: OpaqueRef
    currency: CurrencyCode
    effective_at: str
    expires_at: str | None = None
    lines: tuple[CommercialConfigurationLine, ...] = Field(
        min_length=1, max_length=5_000
    )
    manual_override_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("effective_at")
    @classmethod
    def _valid_effective_at(cls, value: str) -> str:
        return _timestamp(value, field_name="effective_at")

    @field_validator("expires_at")
    @classmethod
    def _valid_expires_at(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, field_name="expires_at")

    @field_validator("lines", "manual_override_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _configuration_refs_unique(self) -> "CommercialConfigurationSnapshot":
        _require_unique(
            [item.configuration_line_ref for item in self.lines],
            label="configuration line",
        )
        _require_unique(self.manual_override_refs, label="manual override")
        _require_unique(self.evidence_refs, label="configuration evidence")
        if self.expires_at is not None and _parsed_timestamp(
            self.expires_at
        ) <= _parsed_timestamp(self.effective_at):
            raise ValueError("expires_at must follow effective_at")
        return self


class CommercialQuoteLine(_StrictModel):
    quote_line_ref: OpaqueRef
    configuration_line_ref: OpaqueRef
    product_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)
    unit_price: Decimal = Field(ge=0)
    line_total: Decimal = Field(ge=0)

    @field_validator("quantity", "unit_price", "line_total", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class CommercialQuoteSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_quote_snapshot.v1"] = Field(
        default=COMMERCIAL_QUOTE_SCHEMA, alias="schema"
    )
    quote_ref: OpaqueRef
    revision: int = Field(ge=1)
    configuration_ref: OpaqueRef
    account_ref: OpaqueRef
    partner_ref: OpaqueRef | None = None
    status: Literal[
        "draft",
        "pending_approval",
        "approved",
        "accepted",
        "rejected",
        "expired",
        "cancelled",
    ]
    currency: CurrencyCode
    valid_until: str
    subtotal: Decimal = Field(ge=0)
    tax_total: Decimal = Field(ge=0)
    total: Decimal = Field(ge=0)
    approval_required: bool
    approval_status: Literal[
        "not_required", "pending", "approved", "rejected", "unknown"
    ]
    prepared_by_ref: OpaqueRef
    approved_by_ref: OpaqueRef | None = None
    lines: tuple[CommercialQuoteLine, ...] = Field(min_length=1, max_length=5_000)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("valid_until")
    @classmethod
    def _valid_until(cls, value: str) -> str:
        return _timestamp(value, field_name="valid_until")

    @field_validator("subtotal", "tax_total", "total", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _quote_refs_unique(self) -> "CommercialQuoteSnapshot":
        _require_unique(
            [item.quote_line_ref for item in self.lines], label="quote line"
        )
        _require_unique(self.evidence_refs, label="quote evidence")
        return self


class CommercialOrderLine(_StrictModel):
    order_line_ref: OpaqueRef
    quote_line_ref: OpaqueRef
    product_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)
    unit_price: Decimal = Field(ge=0)
    line_total: Decimal = Field(ge=0)

    @field_validator("quantity", "unit_price", "line_total", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class CommercialOrderSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_order_snapshot.v1"] = Field(
        default=COMMERCIAL_ORDER_SCHEMA, alias="schema"
    )
    order_ref: OpaqueRef
    revision: int = Field(ge=1)
    quote_ref: OpaqueRef
    contract_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal[
        "draft", "pending", "confirmed", "fulfilled", "on_hold", "rejected", "cancelled"
    ]
    currency: CurrencyCode
    total: Decimal = Field(ge=0)
    lines: tuple[CommercialOrderLine, ...] = Field(min_length=1, max_length=5_000)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("total", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _order_refs_unique(self) -> "CommercialOrderSnapshot":
        _require_unique(
            [item.order_line_ref for item in self.lines], label="order line"
        )
        _require_unique(self.evidence_refs, label="order evidence")
        return self


class CommercialContractSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_contract_snapshot.v1"] = Field(
        default=COMMERCIAL_CONTRACT_SCHEMA, alias="schema"
    )
    contract_ref: OpaqueRef
    revision: int = Field(ge=1)
    quote_ref: OpaqueRef
    order_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal[
        "draft",
        "pending_signature",
        "executed",
        "active",
        "expired",
        "terminated",
        "cancelled",
    ]
    currency: CurrencyCode
    contract_value: Decimal = Field(ge=0)
    effective_at: str
    expires_at: str
    signature_status: Literal[
        "not_required", "pending", "completed", "declined", "unknown"
    ]
    required_signer_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    completed_signer_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=100
    )
    amendment_pending: bool = False
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("contract_value", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("effective_at", "expires_at")
    @classmethod
    def _valid_timestamp(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "required_signer_refs", "completed_signer_refs", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _contract_refs_unique(self) -> "CommercialContractSnapshot":
        _require_unique(self.required_signer_refs, label="required signer")
        _require_unique(self.completed_signer_refs, label="completed signer")
        _require_unique(self.evidence_refs, label="contract evidence")
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.effective_at):
            raise ValueError("expires_at must follow effective_at")
        return self


class CommercialEntitlement(_StrictModel):
    entitlement_ref: OpaqueRef
    product_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)
    status: Literal["pending", "active", "suspended", "revoked", "expired"]
    effective_at: str
    expires_at: str

    @field_validator("quantity", mode="before")
    @classmethod
    def _valid_quantity(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("effective_at", "expires_at")
    @classmethod
    def _valid_timestamp(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _window_is_ordered(self) -> "CommercialEntitlement":
        if _parsed_timestamp(self.expires_at) <= _parsed_timestamp(self.effective_at):
            raise ValueError("expires_at must follow effective_at")
        return self


class CommercialSubscriptionSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_subscription_snapshot.v1"] = Field(
        default=COMMERCIAL_SUBSCRIPTION_SCHEMA, alias="schema"
    )
    subscription_ref: OpaqueRef
    order_ref: OpaqueRef
    contract_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal[
        "pending", "provisioning", "active", "suspended", "cancelled", "expired"
    ]
    billing_model: Literal["flat", "seat", "usage", "hybrid"]
    current_term_start: str
    current_term_end: str
    entitlements: tuple[CommercialEntitlement, ...] = Field(
        default_factory=tuple, max_length=5_000
    )
    authorized_meter_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=1_000
    )
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("current_term_start", "current_term_end")
    @classmethod
    def _valid_timestamp(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator(
        "entitlements", "authorized_meter_refs", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _subscription_refs_unique(self) -> "CommercialSubscriptionSnapshot":
        _require_unique(
            [item.entitlement_ref for item in self.entitlements],
            label="entitlement",
        )
        _require_unique(self.authorized_meter_refs, label="authorized meter")
        _require_unique(self.evidence_refs, label="subscription evidence")
        if _parsed_timestamp(self.current_term_end) <= _parsed_timestamp(
            self.current_term_start
        ):
            raise ValueError("current_term_end must follow current_term_start")
        return self


class CommercialUsageMeasurement(_StrictModel):
    measurement_ref: OpaqueRef
    meter_ref: OpaqueRef
    quantity: Decimal = Field(ge=0)
    unit_rate: Decimal = Field(ge=0)
    amount: Decimal = Field(ge=0)

    @field_validator("quantity", "unit_rate", "amount", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class CommercialUsageBillingSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_usage_billing_snapshot.v1"] = Field(
        default=COMMERCIAL_USAGE_BILLING_SCHEMA, alias="schema"
    )
    billing_ref: OpaqueRef
    subscription_ref: OpaqueRef
    account_ref: OpaqueRef
    period_start: str
    period_end: str
    status: Literal["not_applicable", "pending", "validated", "invoiced", "disputed"]
    currency: CurrencyCode
    aggregation_complete: bool
    deduplication_status: Literal["clear", "duplicates_found", "unknown"]
    measurements: tuple[CommercialUsageMeasurement, ...] = Field(
        default_factory=tuple, max_length=20_000
    )
    total: Decimal = Field(ge=0)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("period_start", "period_end")
    @classmethod
    def _valid_timestamp(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("total", mode="before")
    @classmethod
    def _valid_total(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("measurements", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _usage_refs_unique(self) -> "CommercialUsageBillingSnapshot":
        _require_unique(
            [item.measurement_ref for item in self.measurements],
            label="usage measurement",
        )
        _require_unique(self.evidence_refs, label="usage billing evidence")
        if _parsed_timestamp(self.period_end) <= _parsed_timestamp(self.period_start):
            raise ValueError("period_end must follow period_start")
        return self


class CommercialRenewalSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_renewal_snapshot.v1"] = Field(
        default=COMMERCIAL_RENEWAL_SCHEMA, alias="schema"
    )
    renewal_ref: OpaqueRef
    subscription_ref: OpaqueRef
    contract_ref: OpaqueRef
    status: Literal[
        "not_due", "planned", "pending_review", "approved", "renewed", "declined"
    ]
    renewal_at: str
    notice_deadline: str
    owner_ref: OpaqueRef | None = None
    renewal_quote_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("renewal_at", "notice_deadline")
    @classmethod
    def _valid_timestamp(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _renewal_window_and_refs(self) -> "CommercialRenewalSnapshot":
        _require_unique(self.evidence_refs, label="renewal evidence")
        if _parsed_timestamp(self.notice_deadline) > _parsed_timestamp(self.renewal_at):
            raise ValueError("notice_deadline cannot follow renewal_at")
        return self


class CommercialChannelAuthorizationSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_channel_authorization_snapshot.v1"] = (
        Field(default=COMMERCIAL_CHANNEL_SCHEMA, alias="schema")
    )
    route: Literal["direct", "partner"]
    account_ref: OpaqueRef
    partner_ref: OpaqueRef | None = None
    authorization_status: Literal[
        "not_applicable",
        "authorized",
        "conditional",
        "unauthorized",
        "suspended",
        "expired",
        "unknown",
    ]
    authorized_product_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=5_000
    )
    valid_from: str | None = None
    valid_until: str | None = None
    deal_registration_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _valid_timestamp(cls, value: str | None, info: Any) -> str | None:
        return None if value is None else _timestamp(value, field_name=info.field_name)

    @field_validator("authorized_product_refs", "evidence_refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _channel_refs_unique(self) -> "CommercialChannelAuthorizationSnapshot":
        _require_unique(self.authorized_product_refs, label="authorized product")
        _require_unique(self.evidence_refs, label="channel evidence")
        if (
            self.valid_from is not None
            and self.valid_until is not None
            and _parsed_timestamp(self.valid_until)
            <= _parsed_timestamp(self.valid_from)
        ):
            raise ValueError("valid_until must follow valid_from")
        return self


class CommercialCommissionBasisSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_commission_basis_snapshot.v1"] = Field(
        default=COMMERCIAL_COMMISSION_SCHEMA, alias="schema"
    )
    commission_ref: OpaqueRef
    order_ref: OpaqueRef
    contract_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal["draft", "validated", "approved", "paid", "disputed", "void"]
    plan_ref: OpaqueRef
    payee_ref: OpaqueRef
    currency: CurrencyCode
    gross_basis: Decimal = Field(ge=0)
    excluded_amount: Decimal = Field(ge=0)
    eligible_basis: Decimal = Field(ge=0)
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("gross_basis", "excluded_amount", "eligible_basis", mode="before")
    @classmethod
    def _valid_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _commission_evidence_unique(self) -> "CommercialCommissionBasisSnapshot":
        _require_unique(self.evidence_refs, label="commission evidence")
        return self


class CommercialRevenueOpsHandoffSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_revenue_ops_handoff_snapshot.v1"] = Field(
        default=COMMERCIAL_REVENUE_OPS_SCHEMA, alias="schema"
    )
    handoff_ref: OpaqueRef
    quote_ref: OpaqueRef
    order_ref: OpaqueRef
    contract_ref: OpaqueRef
    subscription_ref: OpaqueRef
    account_ref: OpaqueRef
    status: Literal["pending", "review_required", "complete", "rejected"]
    owner_ref: OpaqueRef | None = None
    required_artifact_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=500
    )
    received_artifact_refs: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=500
    )
    acknowledged_at: str | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=50)

    @field_validator("acknowledged_at")
    @classmethod
    def _valid_acknowledged_at(cls, value: str | None) -> str | None:
        return (
            None if value is None else _timestamp(value, field_name="acknowledged_at")
        )

    @field_validator(
        "required_artifact_refs",
        "received_artifact_refs",
        "evidence_refs",
        mode="before",
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _handoff_refs_unique(self) -> "CommercialRevenueOpsHandoffSnapshot":
        _require_unique(self.required_artifact_refs, label="required handoff artifact")
        _require_unique(self.received_artifact_refs, label="received handoff artifact")
        _require_unique(self.evidence_refs, label="revenue operations evidence")
        return self


class QuoteOrderContractControlsInput(_StrictModel):
    schema_id: Literal[
        "lightbulb.commercial_quote_order_contract_controls_input.v1"
    ] = Field(default=COMMERCIAL_CONTROL_INPUT_SCHEMA, alias="schema")
    evaluation_ref: OpaqueRef
    analysis_as_of: str
    account_ref: OpaqueRef
    configuration: CommercialConfigurationSnapshot
    quote: CommercialQuoteSnapshot
    order: CommercialOrderSnapshot
    contract: CommercialContractSnapshot
    subscription: CommercialSubscriptionSnapshot
    usage_billing: CommercialUsageBillingSnapshot
    renewal: CommercialRenewalSnapshot
    channel_authorization: CommercialChannelAuthorizationSnapshot
    commission_basis: CommercialCommissionBasisSnapshot
    revenue_ops_handoff: CommercialRevenueOpsHandoffSnapshot
    policy: CommercialControlPolicy = Field(default_factory=CommercialControlPolicy)
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(
        default_factory=tuple, max_length=500
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_as_of(cls, value: str) -> str:
        return _timestamp(value, field_name="analysis_as_of")

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _evidence_refs_unique(self) -> "QuoteOrderContractControlsInput":
        _require_unique(
            [item.evidence_ref for item in self.evidence_refs],
            label="retained evidence",
        )
        return self


class CommercialControlFinding(_StrictModel):
    code: OpaqueRef
    gate: CommercialGateName
    status: CommercialFindingStatus
    severity: Literal["review", "blocking"]
    message: ShortText
    subject_ref: OpaqueRef | None = None
    evidence_refs: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _evidence_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _severity_matches_status(self) -> "CommercialControlFinding":
        expected = "blocking" if self.status == "fail" else "review"
        if self.severity != expected:
            raise ValueError("finding severity must match finding status")
        return self


class CommercialGateResult(_StrictModel):
    gate: CommercialGateName
    status: CommercialGateStatus
    finding_codes: tuple[OpaqueRef, ...] = Field(
        default_factory=tuple, max_length=5_000
    )

    @field_validator("finding_codes", mode="before")
    @classmethod
    def _codes_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)


class CommercialEffectBoundary(_StrictModel):
    connector_reads: Literal[0] = 0
    connector_writes: Literal[0] = 0
    approvals_consumed: Literal[0] = 0
    quote_mutated: Literal[False] = False
    order_mutated: Literal[False] = False
    contract_mutated: Literal[False] = False
    billing_mutated: Literal[False] = False
    entitlement_mutated: Literal[False] = False
    commission_mutated: Literal[False] = False
    renewal_mutated: Literal[False] = False
    partner_authorization_mutated: Literal[False] = False
    revenue_ops_handoff_mutated: Literal[False] = False
    quote_authorized: Literal[False] = False
    order_authorized: Literal[False] = False
    contract_authorized: Literal[False] = False
    billing_authorized: Literal[False] = False
    entitlement_authorized: Literal[False] = False
    commission_authorized: Literal[False] = False
    external_systems_changed: Literal[False] = False
    spring_system_of_record_authority_required: Literal[True] = True
    spring_rbac_approval_audit_required: Literal[True] = True


COMMERCIAL_CONTROL_OPERATION = PrimitiveOperationSpec(
    operation_ref="quote-order-contract-controls.evaluate",
    tool="commercial.evaluate_quote_order_contract_controls",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.SAFE,
    freshness_class=PrimitiveOperationFreshnessClass.BOUNDED,
    recovery_policy=PrimitiveOperationRecoveryPolicy.NONE,
)


class QuoteOrderContractControlsProposal(_StrictModel):
    schema_id: Literal[
        "lightbulb.commercial_quote_order_contract_controls_proposal.v1"
    ] = Field(default=COMMERCIAL_CONTROL_PROPOSAL_SCHEMA, alias="schema")
    evaluation_ref: OpaqueRef
    account_ref: OpaqueRef
    evaluated_at: str
    proposed_disposition: CommercialDisposition
    gates: tuple[CommercialGateResult, ...]
    findings: tuple[CommercialControlFinding, ...] = Field(max_length=5_000)
    pass_gate_count: int = Field(ge=0, le=len(_GATE_ORDER))
    review_gate_count: int = Field(ge=0, le=len(_GATE_ORDER))
    fail_gate_count: int = Field(ge=0, le=len(_GATE_ORDER))
    indeterminate_gate_count: int = Field(ge=0, le=len(_GATE_ORDER))
    next_actions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    source_snapshot_digests: dict[str, Sha256Digest]
    evidence_refs: tuple[PrimitiveEvidenceRef, ...] = Field(max_length=500)
    operation_spec: PrimitiveOperationSpec
    operation_digest: Sha256Digest
    evidence_digest: Sha256Digest
    quote_mutated: Literal[False] = False
    order_mutated: Literal[False] = False
    contract_mutated: Literal[False] = False
    billing_mutated: Literal[False] = False
    entitlement_mutated: Literal[False] = False
    commission_mutated: Literal[False] = False
    quote_authorized: Literal[False] = False
    order_authorized: Literal[False] = False
    contract_authorized: Literal[False] = False
    billing_authorized: Literal[False] = False
    entitlement_authorized: Literal[False] = False
    commission_authorized: Literal[False] = False
    effect_boundary: CommercialEffectBoundary = Field(
        default_factory=CommercialEffectBoundary
    )
    proposal_digest: Sha256Digest = _ZERO_DIGEST

    @field_validator("evaluated_at")
    @classmethod
    def _valid_evaluated_at(cls, value: str) -> str:
        return _timestamp(value, field_name="evaluated_at")

    @field_validator(
        "gates", "findings", "next_actions", "evidence_refs", mode="before"
    )
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _proposal_is_coherent_and_content_bound(
        self,
    ) -> "QuoteOrderContractControlsProposal":
        if tuple(item.gate for item in self.gates) != _GATE_ORDER:
            raise ValueError("gates must be complete and in canonical order")
        counts = {
            status: sum(item.status == status for item in self.gates)
            for status in ("pass", "review", "fail", "indeterminate")
        }
        if (
            self.pass_gate_count != counts["pass"]
            or self.review_gate_count != counts["review"]
            or self.fail_gate_count != counts["fail"]
            or self.indeterminate_gate_count != counts["indeterminate"]
        ):
            raise ValueError("gate counts must match gates")
        expected_disposition: CommercialDisposition = (
            "blocked"
            if counts["fail"]
            else "indeterminate"
            if counts["indeterminate"]
            else "manual_review_required"
            if counts["review"]
            else "ready"
        )
        if self.proposed_disposition != expected_disposition:
            raise ValueError("proposed_disposition must match gate results")
        if self.proposed_disposition == "ready" and self.next_actions:
            raise ValueError("ready proposals cannot contain next_actions")
        if self.proposed_disposition != "ready" and not self.next_actions:
            raise ValueError("non-ready proposals require bounded next_actions")
        if self.operation_spec != COMMERCIAL_CONTROL_OPERATION:
            raise ValueError(
                "operation_spec must identify the read-only commercial evaluator"
            )
        expected_evidence_digest = _evidence_digest(self.evidence_refs)
        if self.evidence_digest != expected_evidence_digest:
            raise ValueError("evidence_digest does not match evidence_refs")
        digest_payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_digest"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(digest_payload)
        if self.proposal_digest not in {_ZERO_DIGEST, expected_digest}:
            raise ValueError("proposal_digest does not match proposal")
        object.__setattr__(self, "proposal_digest", expected_digest)
        return self


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest(
        [
            item.to_dict()
            for item in sorted(
                evidence_refs, key=lambda evidence: evidence.evidence_ref
            )
        ]
    )


def _add_finding(
    findings: list[CommercialControlFinding],
    *,
    code: str,
    gate: CommercialGateName,
    status: CommercialFindingStatus,
    message: str,
    subject_ref: str | None = None,
    evidence_refs: Sequence[str] = (),
) -> None:
    findings.append(
        CommercialControlFinding(
            code=code,
            gate=gate,
            status=status,
            severity="blocking" if status == "fail" else "review",
            message=message,
            subject_ref=subject_ref,
            evidence_refs=tuple(sorted(evidence_refs)),
        )
    )


def _within_tolerance(left: Decimal, right: Decimal, tolerance: Decimal) -> bool:
    return abs(left - right) <= tolerance


def _term_contains(
    outer_start: str,
    outer_end: str,
    inner_start: str,
    inner_end: str,
) -> bool:
    return _parsed_timestamp(outer_start) <= _parsed_timestamp(
        inner_start
    ) and _parsed_timestamp(inner_end) <= _parsed_timestamp(outer_end)


def _gate_status(findings: Sequence[CommercialControlFinding]) -> CommercialGateStatus:
    statuses = {item.status for item in findings}
    if "fail" in statuses:
        return "fail"
    if "indeterminate" in statuses:
        return "indeterminate"
    if "review" in statuses:
        return "review"
    return "pass"


def _referenced_evidence_by_gate(
    inputs: QuoteOrderContractControlsInput,
) -> dict[CommercialGateName, tuple[tuple[str, ...], tuple[str, ...]]]:
    return {
        "cpq_pricing": (
            inputs.configuration.evidence_refs,
            ("cpq_configuration", "pricing"),
        ),
        "quote_approval": (inputs.quote.evidence_refs, ("quote_approval",)),
        "order_linkage": (inputs.order.evidence_refs, ("order_linkage",)),
        "contract_signature": (
            inputs.contract.evidence_refs,
            ("contract_signature",),
        ),
        "subscription_entitlement": (
            inputs.subscription.evidence_refs,
            ("subscription_entitlement",),
        ),
        "usage_billing": (inputs.usage_billing.evidence_refs, ("usage_billing",)),
        "renewal": (inputs.renewal.evidence_refs, ("renewal",)),
        "channel_partner": (
            inputs.channel_authorization.evidence_refs,
            ("channel_partner",),
        ),
        "commission_basis": (
            inputs.commission_basis.evidence_refs,
            ("commission_basis",),
        ),
        "revenue_ops_handoff": (
            inputs.revenue_ops_handoff.evidence_refs,
            ("revenue_ops_handoff",),
        ),
    }


def _assess_evidence(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    policy = inputs.policy.evidence
    evidence_by_ref = {item.evidence_ref: item for item in inputs.evidence_refs}
    minimum_rank = _GRADE_RANK[policy.minimum_verification_grade]
    usable_refs: set[str] = set()

    for item in sorted(
        inputs.evidence_refs, key=lambda evidence: evidence.evidence_ref
    ):
        observed_at = _parsed_timestamp(item.observed_at)
        problems: list[tuple[str, str]] = []
        if item.subject_ref != inputs.account_ref:
            problems.append(
                ("scope", "Evidence is not scoped to the evaluated account.")
            )
        if observed_at > analysis_at:
            problems.append(
                ("future", "Evidence was observed after the analysis cutoff.")
            )
        elif analysis_at - observed_at > timedelta(hours=policy.maximum_age_hours):
            problems.append(
                ("stale", "Evidence exceeds the configured freshness window.")
            )
        if _GRADE_RANK[item.verification_grade] < minimum_rank:
            problems.append(("grade", "Evidence verification grade is below policy."))
        if item.effective_at is None:
            problems.append(
                ("effective_at", "Evidence lacks the required effective timestamp.")
            )
        elif _parsed_timestamp(item.effective_at) > analysis_at:
            problems.append(
                ("future_effective", "Evidence is not yet effective at the cutoff.")
            )
        if not problems:
            usable_refs.add(item.evidence_ref)
        for suffix, message in problems:
            _add_finding(
                findings,
                code=f"evidence.{suffix}",
                gate="evidence",
                status="indeterminate",
                message=message,
                subject_ref=item.evidence_ref,
                evidence_refs=(item.evidence_ref,),
            )

    kinds = {
        item.kind for item in inputs.evidence_refs if item.evidence_ref in usable_refs
    }
    for kind in sorted(set(policy.required_kinds) - kinds):
        _add_finding(
            findings,
            code="evidence.required_kind_missing",
            gate="evidence",
            status="indeterminate",
            message=f"No usable retained evidence was supplied for required kind {kind!r}.",
        )

    for gate, (references, required_kinds) in _referenced_evidence_by_gate(
        inputs
    ).items():
        for reference in sorted(references):
            if reference not in evidence_by_ref:
                _add_finding(
                    findings,
                    code="evidence.reference_missing",
                    gate=gate,
                    status="indeterminate",
                    message="A snapshot references evidence absent from the retained packet.",
                    subject_ref=reference,
                )
        for kind in required_kinds:
            supported = any(
                reference in usable_refs and evidence_by_ref[reference].kind == kind
                for reference in references
                if reference in evidence_by_ref
            )
            if not supported:
                _add_finding(
                    findings,
                    code="evidence.gate_support_missing",
                    gate=gate,
                    status="indeterminate",
                    message=f"The gate lacks usable referenced evidence of kind {kind!r}.",
                )


def _assess_cpq_pricing(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    configuration = inputs.configuration
    quote = inputs.quote
    tolerance = inputs.policy.amount_tolerance
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)

    if configuration.account_ref != inputs.account_ref:
        _add_finding(
            findings,
            code="cpq.account_scope_mismatch",
            gate="cpq_pricing",
            status="fail",
            message="The configuration is outside the evaluated account scope.",
            subject_ref=configuration.configuration_ref,
        )
    if configuration.status in {"invalid", "retired"}:
        _add_finding(
            findings,
            code="cpq.configuration_invalid",
            gate="cpq_pricing",
            status="fail",
            message="The selected configuration is invalid or retired.",
            subject_ref=configuration.configuration_ref,
        )
    elif configuration.status == "pending_review":
        _add_finding(
            findings,
            code="cpq.configuration_pending",
            gate="cpq_pricing",
            status="indeterminate",
            message="Configuration review has not reached a conclusive state.",
            subject_ref=configuration.configuration_ref,
        )
    if _parsed_timestamp(configuration.effective_at) > analysis_at:
        _add_finding(
            findings,
            code="cpq.configuration_not_effective",
            gate="cpq_pricing",
            status="indeterminate",
            message="The configuration is not effective at the analysis cutoff.",
            subject_ref=configuration.configuration_ref,
        )
    if (
        configuration.expires_at is not None
        and _parsed_timestamp(configuration.expires_at) <= analysis_at
    ):
        _add_finding(
            findings,
            code="cpq.configuration_expired",
            gate="cpq_pricing",
            status="fail",
            message="The configuration expired before the analysis cutoff.",
            subject_ref=configuration.configuration_ref,
        )
    if configuration.manual_override_refs:
        _add_finding(
            findings,
            code="cpq.manual_override",
            gate="cpq_pricing",
            status="review",
            message="Manual CPQ or pricing overrides require host-governed review.",
            subject_ref=configuration.configuration_ref,
        )

    configuration_lines = {
        item.configuration_line_ref: item for item in configuration.lines
    }
    for line in configuration.lines:
        expected_price = line.list_unit_price * (Decimal("1") - line.discount_ratio)
        if not _within_tolerance(line.configured_unit_price, expected_price, tolerance):
            _add_finding(
                findings,
                code="cpq.configured_price_mismatch",
                gate="cpq_pricing",
                status="fail",
                message="Configured unit price does not reconcile to list price and discount.",
                subject_ref=line.configuration_line_ref,
            )

    for mismatch, message in (
        (
            quote.configuration_ref != configuration.configuration_ref,
            "Quote is not linked to the supplied configuration revision.",
        ),
        (
            quote.account_ref != inputs.account_ref,
            "Quote is outside the evaluated account scope.",
        ),
        (
            quote.currency != configuration.currency,
            "Quote currency differs from the configured price-book currency.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="cpq.quote_linkage_mismatch",
                gate="cpq_pricing",
                status="fail",
                message=message,
                subject_ref=quote.quote_ref,
            )

    quoted_configuration_refs: set[str] = set()
    for line in quote.lines:
        configured = configuration_lines.get(line.configuration_line_ref)
        if configured is None:
            _add_finding(
                findings,
                code="cpq.quote_line_unconfigured",
                gate="cpq_pricing",
                status="fail",
                message="A quote line lacks a matching configured line.",
                subject_ref=line.quote_line_ref,
            )
            continue
        quoted_configuration_refs.add(line.configuration_line_ref)
        if (
            line.product_ref != configured.product_ref
            or line.quantity != configured.quantity
            or not _within_tolerance(
                line.unit_price, configured.configured_unit_price, tolerance
            )
        ):
            _add_finding(
                findings,
                code="cpq.quote_line_drift",
                gate="cpq_pricing",
                status="fail",
                message="Quote line product, quantity, or price drifted from configuration.",
                subject_ref=line.quote_line_ref,
            )
        if not _within_tolerance(
            line.line_total, line.quantity * line.unit_price, tolerance
        ):
            _add_finding(
                findings,
                code="cpq.quote_line_total_mismatch",
                gate="cpq_pricing",
                status="fail",
                message="Quote line total does not reconcile to quantity and unit price.",
                subject_ref=line.quote_line_ref,
            )
    for missing_ref in sorted(set(configuration_lines) - quoted_configuration_refs):
        _add_finding(
            findings,
            code="cpq.configured_line_missing_from_quote",
            gate="cpq_pricing",
            status="fail",
            message="A configured line is absent from the quote.",
            subject_ref=missing_ref,
        )

    expected_subtotal = sum(
        (item.line_total for item in quote.lines), start=Decimal("0")
    )
    if not _within_tolerance(quote.subtotal, expected_subtotal, tolerance):
        _add_finding(
            findings,
            code="cpq.quote_subtotal_mismatch",
            gate="cpq_pricing",
            status="fail",
            message="Quote subtotal does not reconcile to quote lines.",
            subject_ref=quote.quote_ref,
        )
    if not _within_tolerance(quote.total, quote.subtotal + quote.tax_total, tolerance):
        _add_finding(
            findings,
            code="cpq.quote_total_mismatch",
            gate="cpq_pricing",
            status="fail",
            message="Quote total does not reconcile to subtotal and tax.",
            subject_ref=quote.quote_ref,
        )


def _assess_quote_approval(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    quote = inputs.quote
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    if quote.status in {"rejected", "expired", "cancelled"}:
        _add_finding(
            findings,
            code="quote.state_ineligible",
            gate="quote_approval",
            status="fail",
            message="Quote state is rejected, expired, or cancelled.",
            subject_ref=quote.quote_ref,
        )
    elif quote.status in {"draft", "pending_approval"}:
        _add_finding(
            findings,
            code="quote.state_pending",
            gate="quote_approval",
            status="indeterminate",
            message="Quote has not reached an approved or accepted state.",
            subject_ref=quote.quote_ref,
        )
    if _parsed_timestamp(quote.valid_until) <= analysis_at:
        _add_finding(
            findings,
            code="quote.validity_expired",
            gate="quote_approval",
            status="fail",
            message="Quote validity ended before the analysis cutoff.",
            subject_ref=quote.quote_ref,
        )

    threshold_exceeded = any(
        item.discount_ratio > inputs.policy.quote_approval_discount_threshold
        for item in inputs.configuration.lines
    )
    if threshold_exceeded and not quote.approval_required:
        _add_finding(
            findings,
            code="quote.discount_approval_not_required",
            gate="quote_approval",
            status="fail",
            message="Discount exceeds policy while the quote is marked as not requiring approval.",
            subject_ref=quote.quote_ref,
        )
    if quote.approval_required:
        if quote.approval_status == "rejected":
            _add_finding(
                findings,
                code="quote.approval_rejected",
                gate="quote_approval",
                status="fail",
                message="The host-supplied quote approval is rejected.",
                subject_ref=quote.quote_ref,
            )
        elif quote.approval_status in {"pending", "unknown", "not_required"}:
            _add_finding(
                findings,
                code="quote.approval_unresolved",
                gate="quote_approval",
                status="indeterminate",
                message="Required quote approval is unresolved or unsupported.",
                subject_ref=quote.quote_ref,
            )
        elif quote.approved_by_ref is None:
            _add_finding(
                findings,
                code="quote.approver_missing",
                gate="quote_approval",
                status="indeterminate",
                message="Approved quote lacks a retained approver reference.",
                subject_ref=quote.quote_ref,
            )
        elif quote.approved_by_ref == quote.prepared_by_ref:
            _add_finding(
                findings,
                code="quote.segregation_of_duties",
                gate="quote_approval",
                status="fail",
                message="Quote preparer and approver must be different actors.",
                subject_ref=quote.quote_ref,
            )
    elif quote.approval_status not in {"not_required", "approved"}:
        _add_finding(
            findings,
            code="quote.approval_state_inconsistent",
            gate="quote_approval",
            status="indeterminate",
            message="Quote approval state is inconsistent with approval_required.",
            subject_ref=quote.quote_ref,
        )


def _assess_order_linkage(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    order = inputs.order
    quote = inputs.quote
    tolerance = inputs.policy.amount_tolerance
    if order.status in {"on_hold", "rejected", "cancelled"}:
        _add_finding(
            findings,
            code="order.state_ineligible",
            gate="order_linkage",
            status="fail",
            message="Order is on hold, rejected, or cancelled.",
            subject_ref=order.order_ref,
        )
    elif order.status in {"draft", "pending"}:
        _add_finding(
            findings,
            code="order.state_pending",
            gate="order_linkage",
            status="indeterminate",
            message="Order has not reached a confirmed state.",
            subject_ref=order.order_ref,
        )
    for mismatch, message in (
        (
            order.quote_ref != quote.quote_ref,
            "Order is not linked to the supplied quote.",
        ),
        (
            order.account_ref != inputs.account_ref,
            "Order is outside the evaluated account scope.",
        ),
        (order.currency != quote.currency, "Order and quote currencies differ."),
        (
            order.contract_ref != inputs.contract.contract_ref,
            "Order is not linked to the supplied contract.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="order.linkage_mismatch",
                gate="order_linkage",
                status="fail",
                message=message,
                subject_ref=order.order_ref,
            )

    quote_lines = {item.quote_line_ref: item for item in quote.lines}
    linked_quote_lines: set[str] = set()
    for line in order.lines:
        quoted = quote_lines.get(line.quote_line_ref)
        if quoted is None:
            _add_finding(
                findings,
                code="order.line_unlinked",
                gate="order_linkage",
                status="fail",
                message="An order line lacks a matching quote line.",
                subject_ref=line.order_line_ref,
            )
            continue
        linked_quote_lines.add(line.quote_line_ref)
        if (
            line.product_ref != quoted.product_ref
            or line.quantity != quoted.quantity
            or not _within_tolerance(line.unit_price, quoted.unit_price, tolerance)
            or not _within_tolerance(line.line_total, quoted.line_total, tolerance)
        ):
            _add_finding(
                findings,
                code="order.line_drift",
                gate="order_linkage",
                status="fail",
                message="Order line product, quantity, price, or total drifted from quote.",
                subject_ref=line.order_line_ref,
            )
        if not _within_tolerance(
            line.line_total, line.quantity * line.unit_price, tolerance
        ):
            _add_finding(
                findings,
                code="order.line_total_mismatch",
                gate="order_linkage",
                status="fail",
                message="Order line total does not reconcile to quantity and unit price.",
                subject_ref=line.order_line_ref,
            )
    for missing_ref in sorted(set(quote_lines) - linked_quote_lines):
        _add_finding(
            findings,
            code="order.quote_line_missing",
            gate="order_linkage",
            status="fail",
            message="A quote line is absent from the linked order.",
            subject_ref=missing_ref,
        )
    expected_total = sum((item.line_total for item in order.lines), Decimal("0"))
    if not _within_tolerance(
        order.total, expected_total, tolerance
    ) or not _within_tolerance(order.total, quote.total, tolerance):
        _add_finding(
            findings,
            code="order.total_mismatch",
            gate="order_linkage",
            status="fail",
            message="Order total does not reconcile to order lines and quote total.",
            subject_ref=order.order_ref,
        )


def _assess_contract_signature(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    contract = inputs.contract
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    tolerance = inputs.policy.amount_tolerance
    for mismatch, message in (
        (
            contract.quote_ref != inputs.quote.quote_ref,
            "Contract is not linked to the supplied quote.",
        ),
        (
            contract.order_ref != inputs.order.order_ref,
            "Contract is not linked to the supplied order.",
        ),
        (
            contract.account_ref != inputs.account_ref,
            "Contract is outside the evaluated account scope.",
        ),
        (
            contract.currency != inputs.order.currency,
            "Contract and order currencies differ.",
        ),
        (
            not _within_tolerance(
                contract.contract_value, inputs.order.total, tolerance
            ),
            "Contract value does not reconcile to order total.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="contract.linkage_mismatch",
                gate="contract_signature",
                status="fail",
                message=message,
                subject_ref=contract.contract_ref,
            )
    if contract.status in {"expired", "terminated", "cancelled"}:
        _add_finding(
            findings,
            code="contract.state_ineligible",
            gate="contract_signature",
            status="fail",
            message="Contract is expired, terminated, or cancelled.",
            subject_ref=contract.contract_ref,
        )
    elif contract.status in {"draft", "pending_signature"}:
        _add_finding(
            findings,
            code="contract.state_pending",
            gate="contract_signature",
            status="indeterminate",
            message="Contract has not reached an executed state.",
            subject_ref=contract.contract_ref,
        )
    if _parsed_timestamp(contract.effective_at) > analysis_at:
        _add_finding(
            findings,
            code="contract.not_effective",
            gate="contract_signature",
            status="indeterminate",
            message="Contract is not effective at the analysis cutoff.",
            subject_ref=contract.contract_ref,
        )
    if _parsed_timestamp(contract.expires_at) <= analysis_at:
        _add_finding(
            findings,
            code="contract.expired",
            gate="contract_signature",
            status="fail",
            message="Contract term ended before the analysis cutoff.",
            subject_ref=contract.contract_ref,
        )
    if contract.signature_status == "declined":
        _add_finding(
            findings,
            code="contract.signature_declined",
            gate="contract_signature",
            status="fail",
            message="A required contract signature was declined.",
            subject_ref=contract.contract_ref,
        )
    elif contract.signature_status in {"pending", "unknown"}:
        _add_finding(
            findings,
            code="contract.signature_unresolved",
            gate="contract_signature",
            status="indeterminate",
            message="Contract signature completion is unresolved.",
            subject_ref=contract.contract_ref,
        )
    elif contract.required_signer_refs and contract.signature_status != "completed":
        _add_finding(
            findings,
            code="contract.signature_state_inconsistent",
            gate="contract_signature",
            status="indeterminate",
            message="Required signers exist but signature status is not completed.",
            subject_ref=contract.contract_ref,
        )
    missing_signers = set(contract.required_signer_refs) - set(
        contract.completed_signer_refs
    )
    if missing_signers:
        _add_finding(
            findings,
            code="contract.signer_missing",
            gate="contract_signature",
            status="indeterminate",
            message="One or more required signer completions are absent.",
            subject_ref=contract.contract_ref,
        )
    if contract.amendment_pending:
        _add_finding(
            findings,
            code="contract.amendment_pending",
            gate="contract_signature",
            status="review",
            message="A pending contract amendment requires host-governed review.",
            subject_ref=contract.contract_ref,
        )


def _assess_subscription_entitlement(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    subscription = inputs.subscription
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    for mismatch, message in (
        (
            subscription.order_ref != inputs.order.order_ref,
            "Subscription is not linked to the supplied order.",
        ),
        (
            subscription.contract_ref != inputs.contract.contract_ref,
            "Subscription is not linked to the supplied contract.",
        ),
        (
            subscription.account_ref != inputs.account_ref,
            "Subscription is outside the evaluated account scope.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="entitlement.subscription_linkage_mismatch",
                gate="subscription_entitlement",
                status="fail",
                message=message,
                subject_ref=subscription.subscription_ref,
            )
    if subscription.status in {"suspended", "cancelled", "expired"}:
        _add_finding(
            findings,
            code="entitlement.subscription_ineligible",
            gate="subscription_entitlement",
            status="fail",
            message="Subscription is suspended, cancelled, or expired.",
            subject_ref=subscription.subscription_ref,
        )
    elif subscription.status in {"pending", "provisioning"}:
        _add_finding(
            findings,
            code="entitlement.subscription_pending",
            gate="subscription_entitlement",
            status="indeterminate",
            message="Subscription provisioning has not reached an active state.",
            subject_ref=subscription.subscription_ref,
        )
    if not (
        _parsed_timestamp(subscription.current_term_start)
        <= analysis_at
        < _parsed_timestamp(subscription.current_term_end)
    ):
        _add_finding(
            findings,
            code="entitlement.term_inactive",
            gate="subscription_entitlement",
            status="fail",
            message="Subscription term is not active at the analysis cutoff.",
            subject_ref=subscription.subscription_ref,
        )

    if not _term_contains(
        inputs.contract.effective_at,
        inputs.contract.expires_at,
        subscription.current_term_start,
        subscription.current_term_end,
    ):
        _add_finding(
            findings,
            code="entitlement.term_outside_contract",
            gate="subscription_entitlement",
            status="fail",
            message="Subscription term is not fully contained by the linked contract term.",
            subject_ref=subscription.subscription_ref,
        )

    required_by_product: dict[str, Decimal] = {}
    for line in inputs.order.lines:
        required_by_product[line.product_ref] = (
            required_by_product.get(line.product_ref, Decimal("0")) + line.quantity
        )
    active_by_product: dict[str, Decimal] = {}
    for entitlement in subscription.entitlements:
        if entitlement.status == "active" and not _term_contains(
            subscription.current_term_start,
            subscription.current_term_end,
            entitlement.effective_at,
            entitlement.expires_at,
        ):
            _add_finding(
                findings,
                code="entitlement.window_outside_subscription",
                gate="subscription_entitlement",
                status="fail",
                message=(
                    "Active entitlement window is not fully contained by the "
                    "subscription term."
                ),
                subject_ref=entitlement.entitlement_ref,
            )
        if entitlement.status == "active" and (
            _parsed_timestamp(entitlement.effective_at)
            <= analysis_at
            < _parsed_timestamp(entitlement.expires_at)
        ):
            active_by_product[entitlement.product_ref] = (
                active_by_product.get(entitlement.product_ref, Decimal("0"))
                + entitlement.quantity
            )
        elif entitlement.product_ref in required_by_product:
            status: CommercialFindingStatus = (
                "indeterminate" if entitlement.status == "pending" else "fail"
            )
            _add_finding(
                findings,
                code="entitlement.product_inactive",
                gate="subscription_entitlement",
                status=status,
                message="A required product entitlement is not active for the evaluated term.",
                subject_ref=entitlement.entitlement_ref,
            )
    for product_ref, required_quantity in sorted(required_by_product.items()):
        entitled_quantity = active_by_product.get(product_ref, Decimal("0"))
        if entitled_quantity < required_quantity:
            _add_finding(
                findings,
                code="entitlement.coverage_short",
                gate="subscription_entitlement",
                status="fail",
                message="Active entitlement quantity does not cover the ordered product quantity.",
                subject_ref=product_ref,
            )
    if (
        subscription.billing_model in {"usage", "hybrid"}
        and not subscription.authorized_meter_refs
    ):
        _add_finding(
            findings,
            code="entitlement.meter_authorization_missing",
            gate="subscription_entitlement",
            status="indeterminate",
            message="Usage-based subscription lacks an authorized meter set.",
            subject_ref=subscription.subscription_ref,
        )


def _assess_usage_billing(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    billing = inputs.usage_billing
    subscription = inputs.subscription
    tolerance = inputs.policy.amount_tolerance
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    for mismatch, message in (
        (
            billing.subscription_ref != subscription.subscription_ref,
            "Usage packet is not linked to the supplied subscription.",
        ),
        (
            billing.account_ref != inputs.account_ref,
            "Usage packet is outside the evaluated account scope.",
        ),
        (
            billing.currency != inputs.order.currency,
            "Usage packet and order currencies differ.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="billing.linkage_mismatch",
                gate="usage_billing",
                status="fail",
                message=message,
                subject_ref=billing.billing_ref,
            )

    usage_based = subscription.billing_model in {"usage", "hybrid"}
    if not usage_based:
        if (
            billing.status != "not_applicable"
            or billing.measurements
            or billing.total != 0
        ):
            _add_finding(
                findings,
                code="billing.unexpected_usage_basis",
                gate="usage_billing",
                status="fail",
                message="Non-usage subscription contains an active usage-billing basis.",
                subject_ref=billing.billing_ref,
            )
        return

    period_start = billing.period_start
    period_end = billing.period_end
    if not _term_contains(
        inputs.contract.effective_at,
        inputs.contract.expires_at,
        period_start,
        period_end,
    ):
        _add_finding(
            findings,
            code="billing.period_outside_contract",
            gate="usage_billing",
            status="fail",
            message="Usage service period falls outside the linked contract term.",
            subject_ref=billing.billing_ref,
        )
    if not _term_contains(
        subscription.current_term_start,
        subscription.current_term_end,
        period_start,
        period_end,
    ):
        _add_finding(
            findings,
            code="billing.period_outside_subscription",
            gate="usage_billing",
            status="fail",
            message="Usage service period falls outside the subscription term.",
            subject_ref=billing.billing_ref,
        )
    required_products = {line.product_ref for line in inputs.order.lines}
    covered_products = {
        entitlement.product_ref
        for entitlement in subscription.entitlements
        if entitlement.status == "active"
        and _term_contains(
            entitlement.effective_at,
            entitlement.expires_at,
            period_start,
            period_end,
        )
    }
    for product_ref in sorted(required_products - covered_products):
        _add_finding(
            findings,
            code="billing.period_outside_entitlement",
            gate="usage_billing",
            status="fail",
            message="Usage service period lacks exact active entitlement coverage.",
            subject_ref=product_ref,
        )

    if billing.status == "disputed":
        _add_finding(
            findings,
            code="billing.usage_disputed",
            gate="usage_billing",
            status="fail",
            message="Usage-billing evidence is disputed.",
            subject_ref=billing.billing_ref,
        )
    elif billing.status in {"pending", "not_applicable"}:
        _add_finding(
            findings,
            code="billing.usage_unvalidated",
            gate="usage_billing",
            status="indeterminate",
            message="Usage-billing evidence has not reached a validated state.",
            subject_ref=billing.billing_ref,
        )
    if _parsed_timestamp(billing.period_end) > analysis_at:
        _add_finding(
            findings,
            code="billing.period_open",
            gate="usage_billing",
            status="indeterminate",
            message="Usage period ends after the analysis cutoff.",
            subject_ref=billing.billing_ref,
        )
    if not billing.aggregation_complete:
        _add_finding(
            findings,
            code="billing.aggregation_incomplete",
            gate="usage_billing",
            status="indeterminate",
            message="Usage aggregation is not complete.",
            subject_ref=billing.billing_ref,
        )
    if billing.deduplication_status == "duplicates_found":
        _add_finding(
            findings,
            code="billing.duplicates_found",
            gate="usage_billing",
            status="fail",
            message="Duplicate usage measurements were detected.",
            subject_ref=billing.billing_ref,
        )
    elif billing.deduplication_status == "unknown":
        _add_finding(
            findings,
            code="billing.deduplication_unknown",
            gate="usage_billing",
            status="indeterminate",
            message="Usage deduplication status is unknown.",
            subject_ref=billing.billing_ref,
        )
    authorized_meters = set(subscription.authorized_meter_refs)
    for measurement in billing.measurements:
        if measurement.meter_ref not in authorized_meters:
            _add_finding(
                findings,
                code="billing.meter_unauthorized",
                gate="usage_billing",
                status="fail",
                message="A usage measurement references an unauthorized meter.",
                subject_ref=measurement.measurement_ref,
            )
        if not _within_tolerance(
            measurement.amount,
            measurement.quantity * measurement.unit_rate,
            tolerance,
        ):
            _add_finding(
                findings,
                code="billing.measurement_amount_mismatch",
                gate="usage_billing",
                status="fail",
                message="Usage amount does not reconcile to quantity and unit rate.",
                subject_ref=measurement.measurement_ref,
            )
    expected_total = sum(
        (item.amount for item in billing.measurements), start=Decimal("0")
    )
    if not _within_tolerance(billing.total, expected_total, tolerance):
        _add_finding(
            findings,
            code="billing.total_mismatch",
            gate="usage_billing",
            status="fail",
            message="Usage-billing total does not reconcile to measurements.",
            subject_ref=billing.billing_ref,
        )


def _assess_renewal(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    renewal = inputs.renewal
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    for mismatch, message in (
        (
            renewal.subscription_ref != inputs.subscription.subscription_ref,
            "Renewal is not linked to the supplied subscription.",
        ),
        (
            renewal.contract_ref != inputs.contract.contract_ref,
            "Renewal is not linked to the supplied contract.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="renewal.linkage_mismatch",
                gate="renewal",
                status="fail",
                message=message,
                subject_ref=renewal.renewal_ref,
            )
    renewal_at = _parsed_timestamp(renewal.renewal_at)
    notice_deadline = _parsed_timestamp(renewal.notice_deadline)
    contract_expires_at = _parsed_timestamp(inputs.contract.expires_at)
    subscription_expires_at = _parsed_timestamp(inputs.subscription.current_term_end)
    if contract_expires_at != subscription_expires_at:
        _add_finding(
            findings,
            code="renewal.expiry_mismatch",
            gate="renewal",
            status="fail",
            message=(
                "Current contract and subscription expiries do not share one renewal "
                "boundary."
            ),
            subject_ref=renewal.renewal_ref,
        )
    if renewal_at < subscription_expires_at:
        _add_finding(
            findings,
            code="renewal.term_overlap",
            gate="renewal",
            status="fail",
            message="Renewal timing overlaps the active subscription term.",
            subject_ref=renewal.renewal_ref,
        )
    elif renewal_at > subscription_expires_at:
        _add_finding(
            findings,
            code="renewal.term_gap",
            gate="renewal",
            status="fail",
            message="Renewal timing leaves a gap after the active subscription term.",
            subject_ref=renewal.renewal_ref,
        )
    active_term_start = max(
        _parsed_timestamp(inputs.contract.effective_at),
        _parsed_timestamp(inputs.subscription.current_term_start),
    )
    if notice_deadline < active_term_start:
        _add_finding(
            findings,
            code="renewal.notice_before_current_term",
            gate="renewal",
            status="fail",
            message="Renewal notice deadline predates the active commercial term.",
            subject_ref=renewal.renewal_ref,
        )
    within_horizon = renewal_at <= analysis_at + timedelta(
        days=inputs.policy.renewal_horizon_days
    )
    if renewal.status == "declined":
        _add_finding(
            findings,
            code="renewal.declined",
            gate="renewal",
            status="fail",
            message="Renewal was declined.",
            subject_ref=renewal.renewal_ref,
        )
    elif renewal.status == "pending_review":
        _add_finding(
            findings,
            code="renewal.review_pending",
            gate="renewal",
            status="review",
            message="Renewal terms require host-governed commercial review.",
            subject_ref=renewal.renewal_ref,
        )
    if renewal_at < analysis_at and renewal.status != "renewed":
        _add_finding(
            findings,
            code="renewal.overdue",
            gate="renewal",
            status="fail",
            message="Renewal date passed without a renewed state.",
            subject_ref=renewal.renewal_ref,
        )
    if notice_deadline < analysis_at and renewal.status in {
        "not_due",
        "planned",
        "pending_review",
    }:
        _add_finding(
            findings,
            code="renewal.notice_deadline_missed",
            gate="renewal",
            status="fail",
            message="Renewal notice deadline passed without an approved outcome.",
            subject_ref=renewal.renewal_ref,
        )
    if within_horizon and renewal.status == "not_due":
        _add_finding(
            findings,
            code="renewal.plan_missing",
            gate="renewal",
            status="indeterminate",
            message="Renewal is within policy horizon but remains marked not due.",
            subject_ref=renewal.renewal_ref,
        )
    if within_horizon and renewal.status not in {"declined", "renewed"}:
        if renewal.owner_ref is None:
            _add_finding(
                findings,
                code="renewal.owner_missing",
                gate="renewal",
                status="indeterminate",
                message="In-horizon renewal lacks an accountable owner.",
                subject_ref=renewal.renewal_ref,
            )
        if (
            renewal.status in {"planned", "approved"}
            and renewal.renewal_quote_ref is None
        ):
            _add_finding(
                findings,
                code="renewal.quote_missing",
                gate="renewal",
                status="indeterminate",
                message="Planned or approved renewal lacks a linked renewal quote.",
                subject_ref=renewal.renewal_ref,
            )


def _assess_channel_partner(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    channel = inputs.channel_authorization
    quote = inputs.quote
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    if channel.account_ref != inputs.account_ref:
        _add_finding(
            findings,
            code="channel.account_scope_mismatch",
            gate="channel_partner",
            status="fail",
            message="Channel authorization is outside the evaluated account scope.",
        )
    if channel.route == "direct":
        if (
            quote.partner_ref is not None
            or channel.partner_ref is not None
            or channel.authorization_status != "not_applicable"
        ):
            _add_finding(
                findings,
                code="channel.direct_route_inconsistent",
                gate="channel_partner",
                status="fail",
                message="Direct route contains partner identity or authorization state.",
                subject_ref=quote.quote_ref,
            )
        return
    if channel.partner_ref is None or quote.partner_ref != channel.partner_ref:
        _add_finding(
            findings,
            code="channel.partner_linkage_mismatch",
            gate="channel_partner",
            status="fail",
            message="Partner route lacks a matching quote and authorization partner.",
            subject_ref=quote.quote_ref,
        )
    if channel.authorization_status in {
        "unauthorized",
        "suspended",
        "expired",
        "not_applicable",
    }:
        _add_finding(
            findings,
            code="channel.partner_unauthorized",
            gate="channel_partner",
            status="fail",
            message="Partner is not currently authorized for this transaction.",
            subject_ref=channel.partner_ref,
        )
    elif channel.authorization_status == "unknown":
        _add_finding(
            findings,
            code="channel.partner_unknown",
            gate="channel_partner",
            status="indeterminate",
            message="Partner authorization status is unknown.",
            subject_ref=channel.partner_ref,
        )
    elif channel.authorization_status == "conditional":
        _add_finding(
            findings,
            code="channel.partner_conditional",
            gate="channel_partner",
            status="review",
            message="Conditional partner authorization requires host-governed review.",
            subject_ref=channel.partner_ref,
        )
    if channel.valid_from is None or channel.valid_until is None:
        _add_finding(
            findings,
            code="channel.authorization_window_missing",
            gate="channel_partner",
            status="indeterminate",
            message="Partner authorization lacks a complete validity window.",
            subject_ref=channel.partner_ref,
        )
    elif not (
        _parsed_timestamp(channel.valid_from)
        <= analysis_at
        < _parsed_timestamp(channel.valid_until)
    ):
        _add_finding(
            findings,
            code="channel.authorization_window_invalid",
            gate="channel_partner",
            status="fail",
            message="Partner authorization is not valid at the analysis cutoff.",
            subject_ref=channel.partner_ref,
        )
    quoted_products = {item.product_ref for item in quote.lines}
    missing_products = quoted_products - set(channel.authorized_product_refs)
    if missing_products:
        _add_finding(
            findings,
            code="channel.product_unauthorized",
            gate="channel_partner",
            status="fail",
            message="Partner is not authorized for every quoted product.",
            subject_ref=channel.partner_ref,
        )
    if (
        inputs.policy.require_partner_deal_registration
        and channel.deal_registration_ref is None
    ):
        _add_finding(
            findings,
            code="channel.deal_registration_missing",
            gate="channel_partner",
            status="indeterminate",
            message="Required partner deal registration evidence is missing.",
            subject_ref=channel.partner_ref,
        )


def _assess_commission_basis(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    commission = inputs.commission_basis
    tolerance = inputs.policy.amount_tolerance
    for mismatch, message in (
        (
            commission.order_ref != inputs.order.order_ref,
            "Commission basis is not linked to the supplied order.",
        ),
        (
            commission.contract_ref != inputs.contract.contract_ref,
            "Commission basis is not linked to the supplied contract.",
        ),
        (
            commission.account_ref != inputs.account_ref,
            "Commission basis is outside the evaluated account scope.",
        ),
        (
            commission.currency != inputs.order.currency,
            "Commission basis and order currencies differ.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="commission.linkage_mismatch",
                gate="commission_basis",
                status="fail",
                message=message,
                subject_ref=commission.commission_ref,
            )
    if commission.status == "void":
        _add_finding(
            findings,
            code="commission.basis_void",
            gate="commission_basis",
            status="fail",
            message="Commission basis is void.",
            subject_ref=commission.commission_ref,
        )
    elif commission.status == "draft":
        _add_finding(
            findings,
            code="commission.basis_draft",
            gate="commission_basis",
            status="indeterminate",
            message="Commission basis has not been validated.",
            subject_ref=commission.commission_ref,
        )
    elif commission.status == "disputed":
        _add_finding(
            findings,
            code="commission.basis_disputed",
            gate="commission_basis",
            status="review",
            message="Disputed commission basis requires host-governed review.",
            subject_ref=commission.commission_ref,
        )
    expected_basis = commission.gross_basis - commission.excluded_amount
    if commission.excluded_amount > commission.gross_basis or not _within_tolerance(
        commission.eligible_basis, expected_basis, tolerance
    ):
        _add_finding(
            findings,
            code="commission.basis_mismatch",
            gate="commission_basis",
            status="fail",
            message="Eligible commission basis does not reconcile to gross less exclusions.",
            subject_ref=commission.commission_ref,
        )
    if commission.eligible_basis > inputs.order.total + tolerance:
        _add_finding(
            findings,
            code="commission.basis_exceeds_order",
            gate="commission_basis",
            status="fail",
            message="Eligible commission basis exceeds the linked order value.",
            subject_ref=commission.commission_ref,
        )


def _assess_revenue_ops_handoff(
    inputs: QuoteOrderContractControlsInput,
    findings: list[CommercialControlFinding],
) -> None:
    handoff = inputs.revenue_ops_handoff
    analysis_at = _parsed_timestamp(inputs.analysis_as_of)
    for mismatch, message in (
        (
            handoff.quote_ref != inputs.quote.quote_ref,
            "Revenue-operations handoff is not linked to the supplied quote.",
        ),
        (
            handoff.order_ref != inputs.order.order_ref,
            "Revenue-operations handoff is not linked to the supplied order.",
        ),
        (
            handoff.contract_ref != inputs.contract.contract_ref,
            "Revenue-operations handoff is not linked to the supplied contract.",
        ),
        (
            handoff.subscription_ref != inputs.subscription.subscription_ref,
            "Revenue-operations handoff is not linked to the supplied subscription.",
        ),
        (
            handoff.account_ref != inputs.account_ref,
            "Revenue-operations handoff is outside the evaluated account scope.",
        ),
    ):
        if mismatch:
            _add_finding(
                findings,
                code="revenue_ops.linkage_mismatch",
                gate="revenue_ops_handoff",
                status="fail",
                message=message,
                subject_ref=handoff.handoff_ref,
            )
    if handoff.status == "rejected":
        _add_finding(
            findings,
            code="revenue_ops.handoff_rejected",
            gate="revenue_ops_handoff",
            status="fail",
            message="Revenue-operations handoff was rejected.",
            subject_ref=handoff.handoff_ref,
        )
    elif handoff.status == "pending":
        _add_finding(
            findings,
            code="revenue_ops.handoff_pending",
            gate="revenue_ops_handoff",
            status="indeterminate",
            message="Revenue-operations handoff is incomplete.",
            subject_ref=handoff.handoff_ref,
        )
    elif handoff.status == "review_required":
        _add_finding(
            findings,
            code="revenue_ops.handoff_review",
            gate="revenue_ops_handoff",
            status="review",
            message="Revenue-operations handoff requires host-governed review.",
            subject_ref=handoff.handoff_ref,
        )
    missing_artifacts = set(handoff.required_artifact_refs) - set(
        handoff.received_artifact_refs
    )
    if missing_artifacts:
        _add_finding(
            findings,
            code="revenue_ops.artifact_missing",
            gate="revenue_ops_handoff",
            status="indeterminate",
            message="One or more required revenue-operations artifacts are missing.",
            subject_ref=handoff.handoff_ref,
        )
    if handoff.owner_ref is None:
        _add_finding(
            findings,
            code="revenue_ops.owner_missing",
            gate="revenue_ops_handoff",
            status="indeterminate",
            message="Revenue-operations handoff lacks an accountable owner.",
            subject_ref=handoff.handoff_ref,
        )
    if handoff.status == "complete":
        if handoff.acknowledged_at is None:
            _add_finding(
                findings,
                code="revenue_ops.acknowledgement_missing",
                gate="revenue_ops_handoff",
                status="indeterminate",
                message="Completed handoff lacks an acknowledgement timestamp.",
                subject_ref=handoff.handoff_ref,
            )
        elif _parsed_timestamp(handoff.acknowledged_at) > analysis_at:
            _add_finding(
                findings,
                code="revenue_ops.acknowledgement_future",
                gate="revenue_ops_handoff",
                status="indeterminate",
                message="Handoff acknowledgement is after the analysis cutoff.",
                subject_ref=handoff.handoff_ref,
            )


def _source_snapshot_digests(
    inputs: QuoteOrderContractControlsInput,
) -> dict[str, str]:
    return {
        "configuration": commercial_snapshot_digest(inputs.configuration),
        "quote": commercial_snapshot_digest(inputs.quote),
        "order": commercial_snapshot_digest(inputs.order),
        "contract": commercial_snapshot_digest(inputs.contract),
        "subscription": commercial_snapshot_digest(inputs.subscription),
        "usage_billing": commercial_snapshot_digest(inputs.usage_billing),
        "renewal": commercial_snapshot_digest(inputs.renewal),
        "channel_authorization": commercial_snapshot_digest(
            inputs.channel_authorization
        ),
        "commission_basis": commercial_snapshot_digest(inputs.commission_basis),
        "revenue_ops_handoff": commercial_snapshot_digest(inputs.revenue_ops_handoff),
    }


def evaluate_quote_order_contract_controls(
    value: QuoteOrderContractControlsInput | Mapping[str, Any],
) -> QuoteOrderContractControlsProposal:
    """Evaluate quote-to-revenue controls without mutation or authorization."""

    inputs = revalidate_model_boundary(QuoteOrderContractControlsInput, value)
    findings: list[CommercialControlFinding] = []
    _assess_evidence(inputs, findings)
    _assess_cpq_pricing(inputs, findings)
    _assess_quote_approval(inputs, findings)
    _assess_order_linkage(inputs, findings)
    _assess_contract_signature(inputs, findings)
    _assess_subscription_entitlement(inputs, findings)
    _assess_usage_billing(inputs, findings)
    _assess_renewal(inputs, findings)
    _assess_channel_partner(inputs, findings)
    _assess_commission_basis(inputs, findings)
    _assess_revenue_ops_handoff(inputs, findings)

    ordered_findings = tuple(
        sorted(
            findings,
            key=lambda item: (
                _GATE_ORDER.index(item.gate),
                item.subject_ref or "",
                item.code,
                item.message,
            ),
        )
    )
    gates = tuple(
        CommercialGateResult(
            gate=gate,
            status=_gate_status(
                [item for item in ordered_findings if item.gate == gate]
            ),
            finding_codes=tuple(
                item.code for item in ordered_findings if item.gate == gate
            ),
        )
        for gate in _GATE_ORDER
    )
    status_counts = {
        status: sum(item.status == status for item in gates)
        for status in ("pass", "review", "fail", "indeterminate")
    }
    disposition: CommercialDisposition = (
        "blocked"
        if status_counts["fail"]
        else "indeterminate"
        if status_counts["indeterminate"]
        else "manual_review_required"
        if status_counts["review"]
        else "ready"
    )
    next_actions = tuple(
        dict.fromkeys(
            f"Resolve {item.code}: {item.message}"[:500].rstrip()
            for item in ordered_findings
        )
    )[:50]
    evidence_refs = tuple(
        sorted(inputs.evidence_refs, key=lambda item: item.evidence_ref)
    )
    evidence_digest = _evidence_digest(evidence_refs)
    operation_input = inputs.to_dict()
    operation_input["evidence_refs"] = [item.to_dict() for item in evidence_refs]
    operation_digest = _stable_digest(
        {
            "operation_spec": COMMERCIAL_CONTROL_OPERATION.to_dict(),
            "input": operation_input,
            "evidence_digest": evidence_digest,
        }
    )
    return QuoteOrderContractControlsProposal(
        evaluation_ref=inputs.evaluation_ref,
        account_ref=inputs.account_ref,
        evaluated_at=inputs.analysis_as_of,
        proposed_disposition=disposition,
        gates=gates,
        findings=ordered_findings,
        pass_gate_count=status_counts["pass"],
        review_gate_count=status_counts["review"],
        fail_gate_count=status_counts["fail"],
        indeterminate_gate_count=status_counts["indeterminate"],
        next_actions=next_actions,
        source_snapshot_digests=_source_snapshot_digests(inputs),
        evidence_refs=evidence_refs,
        operation_spec=COMMERCIAL_CONTROL_OPERATION,
        operation_digest=operation_digest,
        evidence_digest=evidence_digest,
    )


def _example_evidence(
    evidence_ref: str,
    kind: str,
    digest_character: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": "spring-commercial-authority",
        "subject_ref": "account-example",
        "sha256": digest_character * 64,
        "observed_at": "2026-08-24T11:00:00Z",
        "effective_at": "2026-08-24T10:00:00Z",
        "verification_grade": "verified",
        "classification": "confidential",
        "retention_policy": "commercial-controls-seven-years",
        "jurisdiction": "US",
    }


def _example_inputs() -> dict[str, Any]:
    evidence_specs = (
        ("evidence-configuration", "cpq_configuration", "a"),
        ("evidence-pricing", "pricing", "b"),
        ("evidence-quote-approval", "quote_approval", "c"),
        ("evidence-order", "order_linkage", "d"),
        ("evidence-contract", "contract_signature", "e"),
        ("evidence-entitlement", "subscription_entitlement", "f"),
        ("evidence-usage", "usage_billing", "1"),
        ("evidence-renewal", "renewal", "2"),
        ("evidence-channel", "channel_partner", "3"),
        ("evidence-commission", "commission_basis", "4"),
        ("evidence-handoff", "revenue_ops_handoff", "5"),
    )
    return {
        "schema": COMMERCIAL_CONTROL_INPUT_SCHEMA,
        "evaluation_ref": "commercial-evaluation-example",
        "analysis_as_of": "2026-08-24T12:00:00Z",
        "account_ref": "account-example",
        "configuration": {
            "schema": COMMERCIAL_CONFIGURATION_SCHEMA,
            "configuration_ref": "configuration-example",
            "revision": 3,
            "account_ref": "account-example",
            "status": "validated",
            "price_book_ref": "price-book-usd-2026",
            "currency": "USD",
            "effective_at": "2026-08-01T00:00:00Z",
            "expires_at": "2027-08-01T00:00:00Z",
            "lines": [
                {
                    "configuration_line_ref": "configuration-line-platform",
                    "product_ref": "product-platform",
                    "quantity": "2.000000",
                    "list_unit_price": "100.000000",
                    "configured_unit_price": "90.000000",
                    "discount_ratio": "0.100000",
                    "option_refs": ["option-enterprise-support"],
                }
            ],
            "manual_override_refs": [],
            "evidence_refs": ["evidence-configuration", "evidence-pricing"],
        },
        "quote": {
            "schema": COMMERCIAL_QUOTE_SCHEMA,
            "quote_ref": "quote-example",
            "revision": 2,
            "configuration_ref": "configuration-example",
            "account_ref": "account-example",
            "partner_ref": "partner-example",
            "status": "accepted",
            "currency": "USD",
            "valid_until": "2026-09-30T23:59:59Z",
            "subtotal": "180.000000",
            "tax_total": "0.000000",
            "total": "180.000000",
            "approval_required": True,
            "approval_status": "approved",
            "prepared_by_ref": "actor-sales-rep",
            "approved_by_ref": "actor-sales-manager",
            "lines": [
                {
                    "quote_line_ref": "quote-line-platform",
                    "configuration_line_ref": "configuration-line-platform",
                    "product_ref": "product-platform",
                    "quantity": "2.000000",
                    "unit_price": "90.000000",
                    "line_total": "180.000000",
                }
            ],
            "evidence_refs": ["evidence-quote-approval"],
        },
        "order": {
            "schema": COMMERCIAL_ORDER_SCHEMA,
            "order_ref": "order-example",
            "revision": 1,
            "quote_ref": "quote-example",
            "contract_ref": "contract-example",
            "account_ref": "account-example",
            "status": "confirmed",
            "currency": "USD",
            "total": "180.000000",
            "lines": [
                {
                    "order_line_ref": "order-line-platform",
                    "quote_line_ref": "quote-line-platform",
                    "product_ref": "product-platform",
                    "quantity": "2.000000",
                    "unit_price": "90.000000",
                    "line_total": "180.000000",
                }
            ],
            "evidence_refs": ["evidence-order"],
        },
        "contract": {
            "schema": COMMERCIAL_CONTRACT_SCHEMA,
            "contract_ref": "contract-example",
            "revision": 4,
            "quote_ref": "quote-example",
            "order_ref": "order-example",
            "account_ref": "account-example",
            "status": "active",
            "currency": "USD",
            "contract_value": "180.000000",
            "effective_at": "2026-08-01T00:00:00Z",
            "expires_at": "2027-02-24T00:00:00Z",
            "signature_status": "completed",
            "required_signer_refs": ["signer-customer", "signer-company"],
            "completed_signer_refs": ["signer-customer", "signer-company"],
            "amendment_pending": False,
            "evidence_refs": ["evidence-contract"],
        },
        "subscription": {
            "schema": COMMERCIAL_SUBSCRIPTION_SCHEMA,
            "subscription_ref": "subscription-example",
            "order_ref": "order-example",
            "contract_ref": "contract-example",
            "account_ref": "account-example",
            "status": "active",
            "billing_model": "usage",
            "current_term_start": "2026-08-01T00:00:00Z",
            "current_term_end": "2027-02-24T00:00:00Z",
            "entitlements": [
                {
                    "entitlement_ref": "entitlement-platform",
                    "product_ref": "product-platform",
                    "quantity": "2.000000",
                    "status": "active",
                    "effective_at": "2026-08-01T00:00:00Z",
                    "expires_at": "2027-02-24T00:00:00Z",
                }
            ],
            "authorized_meter_refs": ["meter-api-requests"],
            "evidence_refs": ["evidence-entitlement"],
        },
        "usage_billing": {
            "schema": COMMERCIAL_USAGE_BILLING_SCHEMA,
            "billing_ref": "usage-billing-example",
            "subscription_ref": "subscription-example",
            "account_ref": "account-example",
            "period_start": "2026-08-01T00:00:00Z",
            "period_end": "2026-08-24T10:00:00Z",
            "status": "validated",
            "currency": "USD",
            "aggregation_complete": True,
            "deduplication_status": "clear",
            "measurements": [
                {
                    "measurement_ref": "usage-measurement-example",
                    "meter_ref": "meter-api-requests",
                    "quantity": "10.000000",
                    "unit_rate": "2.000000",
                    "amount": "20.000000",
                }
            ],
            "total": "20.000000",
            "evidence_refs": ["evidence-usage"],
        },
        "renewal": {
            "schema": COMMERCIAL_RENEWAL_SCHEMA,
            "renewal_ref": "renewal-example",
            "subscription_ref": "subscription-example",
            "contract_ref": "contract-example",
            "status": "not_due",
            "renewal_at": "2027-02-24T00:00:00Z",
            "notice_deadline": "2026-12-24T00:00:00Z",
            "evidence_refs": ["evidence-renewal"],
        },
        "channel_authorization": {
            "schema": COMMERCIAL_CHANNEL_SCHEMA,
            "route": "partner",
            "account_ref": "account-example",
            "partner_ref": "partner-example",
            "authorization_status": "authorized",
            "authorized_product_refs": ["product-platform"],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "deal_registration_ref": "deal-registration-example",
            "evidence_refs": ["evidence-channel"],
        },
        "commission_basis": {
            "schema": COMMERCIAL_COMMISSION_SCHEMA,
            "commission_ref": "commission-example",
            "order_ref": "order-example",
            "contract_ref": "contract-example",
            "account_ref": "account-example",
            "status": "validated",
            "plan_ref": "commission-plan-example",
            "payee_ref": "actor-sales-rep",
            "currency": "USD",
            "gross_basis": "180.000000",
            "excluded_amount": "18.000000",
            "eligible_basis": "162.000000",
            "evidence_refs": ["evidence-commission"],
        },
        "revenue_ops_handoff": {
            "schema": COMMERCIAL_REVENUE_OPS_SCHEMA,
            "handoff_ref": "revenue-ops-handoff-example",
            "quote_ref": "quote-example",
            "order_ref": "order-example",
            "contract_ref": "contract-example",
            "subscription_ref": "subscription-example",
            "account_ref": "account-example",
            "status": "complete",
            "owner_ref": "actor-revenue-operations",
            "required_artifact_refs": ["artifact-order-form", "artifact-billing-plan"],
            "received_artifact_refs": ["artifact-order-form", "artifact-billing-plan"],
            "acknowledged_at": "2026-08-24T11:00:00Z",
            "evidence_refs": ["evidence-handoff"],
        },
        "evidence_refs": [
            _example_evidence(ref, kind, character)
            for ref, kind, character in evidence_specs
        ],
    }


class EvaluateQuoteOrderContractControlsPrimitive(
    BusinessProcessPrimitive[
        QuoteOrderContractControlsInput,
        QuoteOrderContractControlsProposal,
    ]
):
    primitive_ref = "commercial.evaluate_quote_order_contract_controls"
    version = "1.0.0"
    title = "Evaluate quote, order, and contract controls"
    description = (
        "Evaluate evidence-bound quote-to-revenue controls without mutating or "
        "authorizing commercial records."
    )
    input_model = QuoteOrderContractControlsInput
    output_model = QuoteOrderContractControlsProposal
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
        contract["operation_contract"] = COMMERCIAL_CONTROL_OPERATION.to_dict()
        contract["effect_boundary"] = CommercialEffectBoundary().to_dict()
        contract["authority_boundary"] = {
            "sdk": "deterministic_read_only_proposal",
            "system_of_record": "spring_host",
            "tenant_company_scope": "spring_host",
            "rbac": "spring_host",
            "approvals": "spring_host",
            "audit": "spring_host",
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: QuoteOrderContractControlsInput,
    ) -> PrimitiveExecutionResult[QuoteOrderContractControlsProposal]:
        del context
        output = evaluate_quote_order_contract_controls(inputs)
        receipt = PrimitiveOperationReceipt(
            spec=output.operation_spec,
            status=PrimitiveOperationStatus.COMPLETED,
            request_digest=output.operation_digest,
            evidence_refs=list(output.evidence_refs),
        )
        return PrimitiveExecutionResult[QuoteOrderContractControlsProposal](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Commercial controls evaluated; proposed disposition is "
                f"{output.proposed_disposition}, with no mutation or authorization."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="commercial.quote_order_contract_controls_evaluated",
                    payload={
                        "evaluation_ref": output.evaluation_ref,
                        "proposed_disposition": output.proposed_disposition,
                        "operation_digest": output.operation_digest,
                        "evidence_digest": output.evidence_digest,
                        "proposal_digest": output.proposal_digest,
                        "external_systems_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="commercial_control_proposal",
                    summary=(
                        "Deterministic quote-to-revenue controls evaluated without "
                        "connector calls, mutation, or authorization."
                    ),
                    labels=[
                        output.proposed_disposition,
                        "read_only",
                        "spring_authority_required",
                    ],
                    refs={
                        "operation_digest": output.operation_digest,
                        "evidence_digest": output.evidence_digest,
                        "proposal_digest": output.proposal_digest,
                    },
                )
            ],
            evidence_refs=list(output.evidence_refs),
            operation_receipts=[receipt],
            retryable=False,
        )


__all__ = [
    "COMMERCIAL_CHANNEL_SCHEMA",
    "COMMERCIAL_COMMISSION_SCHEMA",
    "COMMERCIAL_CONFIGURATION_SCHEMA",
    "COMMERCIAL_CONTRACT_SCHEMA",
    "COMMERCIAL_CONTROL_INPUT_SCHEMA",
    "COMMERCIAL_CONTROL_OPERATION",
    "COMMERCIAL_CONTROL_PROPOSAL_SCHEMA",
    "COMMERCIAL_ORDER_SCHEMA",
    "COMMERCIAL_QUOTE_SCHEMA",
    "COMMERCIAL_RENEWAL_SCHEMA",
    "COMMERCIAL_REVENUE_OPS_SCHEMA",
    "COMMERCIAL_SUBSCRIPTION_SCHEMA",
    "COMMERCIAL_USAGE_BILLING_SCHEMA",
    "CommercialChannelAuthorizationSnapshot",
    "CommercialCommissionBasisSnapshot",
    "CommercialConfigurationLine",
    "CommercialConfigurationSnapshot",
    "CommercialContractSnapshot",
    "CommercialControlFinding",
    "CommercialControlPolicy",
    "CommercialEffectBoundary",
    "CommercialEntitlement",
    "CommercialEvidencePolicy",
    "CommercialGateResult",
    "CommercialOrderLine",
    "CommercialOrderSnapshot",
    "CommercialQuoteLine",
    "CommercialQuoteSnapshot",
    "CommercialRenewalSnapshot",
    "CommercialRevenueOpsHandoffSnapshot",
    "CommercialSubscriptionSnapshot",
    "CommercialUsageBillingSnapshot",
    "CommercialUsageMeasurement",
    "EvaluateQuoteOrderContractControlsPrimitive",
    "QuoteOrderContractControlsInput",
    "QuoteOrderContractControlsProposal",
    "commercial_snapshot_digest",
    "evaluate_quote_order_contract_controls",
]
