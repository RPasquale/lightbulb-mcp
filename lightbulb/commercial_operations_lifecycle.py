"""Deterministic commercial-operations lifecycle materialization.

The SDK retains an immutable, evidence-bound projection from CPQ and quote
proposal through reviewed order and contract, active subscription and
entitlements, billing-model-specific proposal, reviewed renewal, channel
attribution, and a commission/Revenue Operations handoff proposal.  It does
not price, book, sign, provision, invoice, pay commission, persist an approval,
or dispatch to an external system.

Spring remains authoritative for authenticated tenant/company scope, customer
and product ownership, RBAC, pricing and booking decisions, contracts, billing,
commission writes, durable idempotency, approvals, audit, and external
dispatch.  Structural actor separation in this module is a proposal-time
guard; Spring must authenticate the actors and verify their roles.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Context, Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
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

from lightbulb.commercial_controls import (
    CommercialChannelAuthorizationSnapshot,
    CommercialCommissionBasisSnapshot,
    CommercialConfigurationSnapshot,
    CommercialContractSnapshot,
    CommercialOrderSnapshot,
    CommercialQuoteSnapshot,
    CommercialRenewalSnapshot,
    CommercialRevenueOpsHandoffSnapshot,
    CommercialSubscriptionSnapshot,
    CommercialUsageBillingSnapshot,
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


COMMERCIAL_LIFECYCLE_SNAPSHOT_SCHEMA = (
    "lightbulb.commercial_operations_lifecycle_snapshot.v2"
)
COMMERCIAL_LIFECYCLE_INPUT_SCHEMA = "lightbulb.commercial_operations_lifecycle_input.v2"
COMMERCIAL_TRANSITION_RECEIPT_SCHEMA = (
    "lightbulb.commercial_operations_transition_receipt.v2"
)
COMMERCIAL_LIFECYCLE_RESULT_SCHEMA = (
    "lightbulb.commercial_operations_lifecycle_result.v2"
)

GENESIS_SNAPSHOT_DIGEST = "0" * 64
MAX_COMMERCIAL_TRANSITIONS = 7
_MONEY_QUANTUM = Decimal("0.000001")
_MAX_DECIMAL = Decimal("1e24")
_DECIMAL_CONTEXT = Context(prec=80, rounding=ROUND_HALF_UP)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"


def _visible_ref(value: str) -> str:
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ValueError(
            "references must contain visible characters without whitespace"
        )
    return value


OpaqueRef = Annotated[
    str,
    StringConstraints(pattern=_REF_PATTERN),
    AfterValidator(_visible_ref),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


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


def _controlled_evidence_ref(value: Any) -> PrimitiveEvidenceRef:
    """Detach and revalidate evidence instances at every commercial boundary."""

    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, PrimitiveEvidenceRef)
        else value
    )
    return PrimitiveEvidenceRef.model_validate(payload)


_ControlledEvidenceRef = Annotated[
    PrimitiveEvidenceRef,
    BeforeValidator(_controlled_evidence_ref),
]


def _controlled_domain_contract(
    value: Any,
    model: type[BaseModel],
) -> BaseModel:
    """Validate reused commercial controls under this module's fixed context."""

    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, model)
        else value
    )
    with localcontext(_DECIMAL_CONTEXT):
        return model.model_validate(payload)


def _controlled_configuration(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialConfigurationSnapshot)


def _controlled_quote(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialQuoteSnapshot)


def _controlled_order(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialOrderSnapshot)


def _controlled_contract(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialContractSnapshot)


def _controlled_subscription(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialSubscriptionSnapshot)


def _controlled_usage(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialUsageBillingSnapshot)


def _controlled_renewal(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialRenewalSnapshot)


def _controlled_channel(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialChannelAuthorizationSnapshot)


def _controlled_commission(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialCommissionBasisSnapshot)


def _controlled_handoff(value: Any) -> BaseModel:
    return _controlled_domain_contract(value, CommercialRevenueOpsHandoffSnapshot)


_ControlledConfiguration = Annotated[
    CommercialConfigurationSnapshot,
    BeforeValidator(_controlled_configuration),
]
_ControlledQuote = Annotated[
    CommercialQuoteSnapshot,
    BeforeValidator(_controlled_quote),
]
_ControlledOrder = Annotated[
    CommercialOrderSnapshot,
    BeforeValidator(_controlled_order),
]
_ControlledContract = Annotated[
    CommercialContractSnapshot,
    BeforeValidator(_controlled_contract),
]
_ControlledSubscription = Annotated[
    CommercialSubscriptionSnapshot,
    BeforeValidator(_controlled_subscription),
]
_ControlledUsage = Annotated[
    CommercialUsageBillingSnapshot,
    BeforeValidator(_controlled_usage),
]
_ControlledRenewal = Annotated[
    CommercialRenewalSnapshot,
    BeforeValidator(_controlled_renewal),
]
_ControlledChannel = Annotated[
    CommercialChannelAuthorizationSnapshot,
    BeforeValidator(_controlled_channel),
]
_ControlledCommission = Annotated[
    CommercialCommissionBasisSnapshot,
    BeforeValidator(_controlled_commission),
]
_ControlledHandoff = Annotated[
    CommercialRevenueOpsHandoffSnapshot,
    BeforeValidator(_controlled_handoff),
]


def _as_tuple(value: Any) -> Any:
    return tuple(value or ())


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


def _decimal(value: Any, *, field_name: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError(f"{field_name} must be a string, integer, or Decimal")
    lexical = str(value)
    if lexical != lexical.strip() or len(lexical) > 80:
        raise ValueError(f"{field_name} must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
        with localcontext(_DECIMAL_CONTEXT):
            normalized = parsed.quantize(_MONEY_QUANTUM)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a finite decimal") from exc
    if (
        not parsed.is_finite()
        or parsed.copy_abs() > _MAX_DECIMAL
        or parsed != normalized
    ):
        raise ValueError(
            f"{field_name} supports at most six places and bounded magnitude"
        )
    return normalized


def _money_product(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_DECIMAL_CONTEXT):
        return (left * right).quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _exact_sum(values: Sequence[Decimal]) -> Decimal:
    with localcontext(_DECIMAL_CONTEXT):
        return sum(values, Decimal(0)).quantize(
            _MONEY_QUANTUM,
            rounding=ROUND_HALF_UP,
        )


def _exact_difference(left: Decimal, right: Decimal) -> Decimal:
    with localcontext(_DECIMAL_CONTEXT):
        return (left - right).quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


_UNORDERED_COLLECTION_KEYS = {
    "authorized_meter_refs",
    "authorized_product_refs",
    "completed_signer_refs",
    "entitlements",
    "evidence_refs",
    "lines",
    "manual_override_refs",
    "measurements",
    "option_refs",
    "received_artifact_refs",
    "required_artifact_refs",
    "required_signer_refs",
    "source_event_bindings",
}


def _normalize_unordered_collections(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {
            key: _normalize_unordered_collections(item, parent_key=str(key))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        normalized = [
            _normalize_unordered_collections(item, parent_key=parent_key)
            for item in value
        ]
        if parent_key in _UNORDERED_COLLECTION_KEYS:
            return sorted(
                normalized,
                key=lambda item: json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    default=str,
                ),
            )
        return normalized
    return value


def _unique(values: Sequence[str], *, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} references must be unique")


_GRADE_RANK = {
    PrimitiveEvidenceVerificationGrade.UNVERIFIED: 0,
    PrimitiveEvidenceVerificationGrade.ASSERTED: 1,
    PrimitiveEvidenceVerificationGrade.ATTESTED: 2,
    PrimitiveEvidenceVerificationGrade.VERIFIED: 3,
}


class CommercialLifecycleScope(_StrictModel):
    """Exact portable identity fence; Spring authenticates every value."""

    tenant_ref: OpaqueRef
    company_ref: OpaqueRef
    project_ref: OpaqueRef
    project_id: UUID
    customer_ref: OpaqueRef
    product_ref: OpaqueRef
    currency: CurrencyCode

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


def commercial_scope_digest(scope: CommercialLifecycleScope) -> str:
    return _stable_digest(scope.to_dict())


def _artifact_refs_are_unique(values: Sequence[str], *, label: str) -> None:
    _unique(tuple(values), label=label)


def _require_selected_evidence(
    evidence_refs: Sequence[PrimitiveEvidenceRef],
    *,
    evidence_ref: str,
    kind: str,
    minimum_grade: PrimitiveEvidenceVerificationGrade,
) -> None:
    selected = [item for item in evidence_refs if item.evidence_ref == evidence_ref]
    if len(selected) != 1 or selected[0].kind != kind:
        raise ValueError(
            f"{evidence_ref} must select exactly one {kind} evidence reference"
        )
    if _GRADE_RANK[selected[0].verification_grade] < _GRADE_RANK[minimum_grade]:
        raise ValueError(f"{kind} evidence must be at least {minimum_grade.value}")


def _require_exact_evidence_set(
    evidence_refs: Sequence[PrimitiveEvidenceRef] | Sequence[str],
    *,
    expected_refs: set[str],
    label: str,
) -> None:
    actual_refs = {
        item.evidence_ref if isinstance(item, PrimitiveEvidenceRef) else item
        for item in evidence_refs
    }
    if actual_refs != expected_refs or len(evidence_refs) != len(expected_refs):
        raise ValueError(f"{label} must retain exactly the selected evidence")


def _configuration_is_exact(
    scope: CommercialLifecycleScope,
    configuration: CommercialConfigurationSnapshot,
) -> None:
    if configuration.account_ref != scope.customer_ref:
        raise ValueError("configuration customer must match lifecycle scope")
    if configuration.currency != scope.currency:
        raise ValueError("configuration currency must match lifecycle scope")
    if configuration.status != "validated":
        raise ValueError("configuration must be validated")
    for line in configuration.lines:
        if line.product_ref != scope.product_ref:
            raise ValueError("every configuration line must match the scoped product")
        expected_price = _money_product(
            line.list_unit_price,
            _exact_difference(Decimal(1), line.discount_ratio),
        )
        if line.configured_unit_price != expected_price:
            raise ValueError(
                "configured unit price must exactly equal list price after discount"
            )


def _quote_is_exact(
    scope: CommercialLifecycleScope,
    configuration: CommercialConfigurationSnapshot,
    quote: CommercialQuoteSnapshot,
) -> None:
    if quote.configuration_ref != configuration.configuration_ref:
        raise ValueError("quote must pin the exact configuration reference")
    if quote.account_ref != scope.customer_ref or quote.currency != scope.currency:
        raise ValueError("quote customer and currency must match lifecycle scope")
    if quote.tax_total != 0:
        raise ValueError(
            "this SDK projection accepts no caller-authored tax amount; Spring must tax"
        )
    configuration_by_ref = {
        item.configuration_line_ref: item for item in configuration.lines
    }
    quoted_configuration_refs = {item.configuration_line_ref for item in quote.lines}
    if quoted_configuration_refs != set(configuration_by_ref) or len(
        quote.lines
    ) != len(configuration_by_ref):
        raise ValueError(
            "quote lines must exactly and one-to-one cover configuration lines"
        )
    line_totals: list[Decimal] = []
    for line in quote.lines:
        configured = configuration_by_ref[line.configuration_line_ref]
        if line.product_ref != scope.product_ref:
            raise ValueError("every quote line must match the scoped product")
        if (
            line.quantity != configured.quantity
            or line.unit_price != configured.configured_unit_price
        ):
            raise ValueError("quote quantity and price must match the configuration")
        expected_line_total = _money_product(line.quantity, line.unit_price)
        if line.line_total != expected_line_total:
            raise ValueError("quote line total must be deterministically rated")
        line_totals.append(line.line_total)
    subtotal = _exact_sum(line_totals)
    if quote.subtotal != subtotal or quote.total != subtotal:
        raise ValueError("quote totals must exactly equal deterministic line totals")


def _quote_economic_digest(quote: CommercialQuoteSnapshot) -> str:
    payload = quote.to_dict()
    for field_name in (
        "revision",
        "status",
        "approval_status",
        "approved_by_ref",
        "evidence_refs",
    ):
        payload.pop(field_name, None)
    return _stable_digest(_normalize_unordered_collections(payload))


class _CommandBase(_StrictModel):
    scope: CommercialLifecycleScope
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    requested_by_ref: OpaqueRef
    expected_version: int = Field(ge=0, le=MAX_COMMERCIAL_TRANSITIONS)
    expected_snapshot_digest: Sha256Digest
    occurred_at: str
    host_outcome_report: Literal["reported_certain", "reported_in_doubt"] = (
        "reported_certain"
    )
    evidence_refs: tuple[_ControlledEvidenceRef, ...] = Field(
        min_length=1,
        max_length=20,
    )
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
    def _base_fences_are_exact(self, info: ValidationInfo) -> "_CommandBase":
        _unique(
            [item.evidence_ref for item in self.evidence_refs],
            label="command evidence",
        )
        for evidence in self.evidence_refs:
            if evidence.subject_ref != self.transition_ref:
                raise ValueError(
                    "command evidence must be bound to the exact transition reference"
                )
            if (
                _GRADE_RANK[evidence.verification_grade]
                < _GRADE_RANK[PrimitiveEvidenceVerificationGrade.ATTESTED]
            ):
                raise ValueError("command evidence must be at least attested")
            if _parsed_timestamp(evidence.observed_at) > _parsed_timestamp(
                self.occurred_at
            ):
                raise ValueError("evidence cannot be observed after the transition")
            if evidence.effective_at is not None and _parsed_timestamp(
                evidence.effective_at
            ) > _parsed_timestamp(self.occurred_at):
                raise ValueError(
                    "evidence cannot become effective after the transition"
                )
        context = info.context or {}
        if not context.get("skip_commercial_evidence_digest"):
            evidence_digest = commercial_command_evidence_digest(self)
            if any(item.sha256 != evidence_digest for item in self.evidence_refs):
                raise ValueError(
                    "every command evidence reference must commit the exact command content"
                )
        if not context.get("skip_commercial_request_digest"):
            if self.request_digest != commercial_command_digest(self):
                raise ValueError(
                    "request_digest must commit the exact normalized command"
                )
        return self


class ProposeQuoteCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_propose_quote_command.v1"] = Field(
        default="lightbulb.commercial_propose_quote_command.v1",
        alias="schema",
    )
    kind: Literal["propose_quote"] = "propose_quote"
    configuration: _ControlledConfiguration
    quote: _ControlledQuote
    configured_by_ref: OpaqueRef
    configuration_evidence_ref: OpaqueRef
    pricing_evidence_ref: OpaqueRef

    @model_validator(mode="after")
    def _proposal_is_exact(self) -> "ProposeQuoteCommand":
        _configuration_is_exact(self.scope, self.configuration)
        _quote_is_exact(self.scope, self.configuration, self.quote)
        if self.configuration.revision != 1 or self.quote.revision != 1:
            raise ValueError(
                "initial configuration and quote revisions must both be one"
            )
        if self.configuration.configuration_ref == self.quote.quote_ref:
            raise ValueError(
                "configuration and quote require distinct primary artifact references"
            )
        if self.quote.status != "pending_approval":
            raise ValueError("proposed quote must be pending approval")
        if (
            not self.quote.approval_required
            or self.quote.approval_status != "pending"
            or self.quote.approved_by_ref is not None
        ):
            raise ValueError("proposed quote must retain an unapproved review gate")
        if self.configured_by_ref != self.quote.prepared_by_ref:
            raise ValueError("configured_by_ref must match the quote preparer")
        if _parsed_timestamp(self.quote.valid_until) <= _parsed_timestamp(
            self.occurred_at
        ):
            raise ValueError("quote validity must extend beyond proposal time")
        if _parsed_timestamp(self.configuration.effective_at) > _parsed_timestamp(
            self.occurred_at
        ):
            raise ValueError("configuration cannot become effective after proposal")
        if self.configuration.expires_at is not None and (
            _parsed_timestamp(self.configuration.expires_at)
            <= _parsed_timestamp(self.occurred_at)
            or _parsed_timestamp(self.quote.valid_until)
            > _parsed_timestamp(self.configuration.expires_at)
        ):
            raise ValueError(
                "configuration must remain effective through quote validity"
            )
        _require_selected_evidence(
            self.evidence_refs,
            evidence_ref=self.configuration_evidence_ref,
            kind="cpq_configuration",
            minimum_grade=PrimitiveEvidenceVerificationGrade.ATTESTED,
        )
        _require_selected_evidence(
            self.evidence_refs,
            evidence_ref=self.pricing_evidence_ref,
            kind="pricing",
            minimum_grade=PrimitiveEvidenceVerificationGrade.ATTESTED,
        )
        configuration_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.configuration_evidence_ref
        )
        pricing_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.pricing_evidence_ref
        )
        if _parsed_timestamp(pricing_evidence.observed_at) < _parsed_timestamp(
            configuration_evidence.observed_at
        ):
            raise ValueError("pricing evidence cannot predate configuration evidence")
        retained = set(self.configuration.evidence_refs) | set(self.quote.evidence_refs)
        if not {
            self.configuration_evidence_ref,
            self.pricing_evidence_ref,
        }.issubset(retained):
            raise ValueError("configuration and quote must retain selected evidence")
        expected_evidence = {
            self.configuration_evidence_ref,
            self.pricing_evidence_ref,
        }
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs=expected_evidence,
            label="quote proposal command",
        )
        _require_exact_evidence_set(
            self.configuration.evidence_refs,
            expected_refs=expected_evidence,
            label="configuration",
        )
        _require_exact_evidence_set(
            self.quote.evidence_refs,
            expected_refs={self.pricing_evidence_ref},
            label="proposed quote",
        )
        configuration_effective_at = _parsed_timestamp(self.configuration.effective_at)
        if any(
            _parsed_timestamp(evidence.observed_at) < configuration_effective_at
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "configuration and pricing evidence cannot predate effectiveness"
            )
        return self


class ReviewContractOrderCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_review_contract_order_command.v1"] = Field(
        default="lightbulb.commercial_review_contract_order_command.v1",
        alias="schema",
    )
    kind: Literal["review_contract_order"] = "review_contract_order"
    reviewed_quote: _ControlledQuote
    order: _ControlledOrder
    contract: _ControlledContract
    quote_approved_by_ref: OpaqueRef
    order_reviewed_by_ref: OpaqueRef
    contract_reviewed_by_ref: OpaqueRef
    quote_approval_evidence_ref: OpaqueRef
    order_review_evidence_ref: OpaqueRef
    contract_signature_evidence_ref: OpaqueRef

    @model_validator(mode="after")
    def _review_evidence_and_actors_are_independent(
        self,
    ) -> "ReviewContractOrderCommand":
        actors = (
            self.quote_approved_by_ref,
            self.order_reviewed_by_ref,
            self.contract_reviewed_by_ref,
        )
        if len(set(actors)) != len(actors):
            raise ValueError("quote, order, and contract reviewers must be distinct")
        for evidence_ref, kind in (
            (self.quote_approval_evidence_ref, "quote_approval"),
            (self.order_review_evidence_ref, "order_linkage"),
            (self.contract_signature_evidence_ref, "contract_signature"),
        ):
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=evidence_ref,
                kind=kind,
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
        quote_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.quote_approval_evidence_ref
        )
        order_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.order_review_evidence_ref
        )
        contract_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.contract_signature_evidence_ref
        )
        if _parsed_timestamp(order_evidence.observed_at) < _parsed_timestamp(
            quote_evidence.observed_at
        ):
            raise ValueError("order review evidence cannot predate quote approval")
        if _parsed_timestamp(contract_evidence.observed_at) < _parsed_timestamp(
            order_evidence.observed_at
        ):
            raise ValueError("contract signature evidence cannot predate order review")
        expected_evidence = {
            self.quote_approval_evidence_ref,
            self.order_review_evidence_ref,
            self.contract_signature_evidence_ref,
        }
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs=expected_evidence,
            label="contract and order review command",
        )
        _require_exact_evidence_set(
            self.reviewed_quote.evidence_refs,
            expected_refs={self.quote_approval_evidence_ref},
            label="reviewed quote",
        )
        _require_exact_evidence_set(
            self.order.evidence_refs,
            expected_refs={self.order_review_evidence_ref},
            label="reviewed order",
        )
        _require_exact_evidence_set(
            self.contract.evidence_refs,
            expected_refs={self.contract_signature_evidence_ref},
            label="reviewed contract",
        )
        return self


class ActivateSubscriptionCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_activate_subscription_command.v2"] = Field(
        default="lightbulb.commercial_activate_subscription_command.v2",
        alias="schema",
    )
    kind: Literal["activate_subscription"] = "activate_subscription"
    subscription_revision: int = Field(ge=1)
    subscription: _ControlledSubscription
    hybrid_recurring_basis: Literal["flat", "seat"] | None = None
    activated_by_ref: OpaqueRef
    entitlement_reviewed_by_ref: OpaqueRef
    entitlement_evidence_ref: OpaqueRef

    @model_validator(mode="after")
    def _activation_gate_is_independent(self) -> "ActivateSubscriptionCommand":
        if (self.subscription.billing_model == "hybrid") != (
            self.hybrid_recurring_basis is not None
        ):
            raise ValueError(
                "hybrid subscriptions require an activation-time recurring basis; "
                "other billing models forbid it"
            )
        if self.activated_by_ref == self.entitlement_reviewed_by_ref:
            raise ValueError(
                "subscription activation and entitlement review must differ"
            )
        _require_selected_evidence(
            self.evidence_refs,
            evidence_ref=self.entitlement_evidence_ref,
            kind="subscription_entitlement",
            minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
        )
        if self.entitlement_evidence_ref not in self.subscription.evidence_refs:
            raise ValueError("subscription must retain entitlement evidence")
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs={self.entitlement_evidence_ref},
            label="subscription activation command",
        )
        _require_exact_evidence_set(
            self.subscription.evidence_refs,
            expected_refs={self.entitlement_evidence_ref},
            label="subscription",
        )
        return self


class CommercialRecurringBillingLine(_StrictModel):
    """One deterministic fixed or seat component linked to an order line."""

    billing_line_ref: OpaqueRef
    order_line_ref: OpaqueRef
    quantity: Decimal = Field(gt=0)
    unit_rate: Decimal = Field(ge=0)
    amount: Decimal = Field(ge=0)

    @field_validator("quantity", "unit_rate", "amount", mode="before")
    @classmethod
    def _billing_decimal(cls, value: Any, info: Any) -> Decimal:
        return _decimal(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _amount_is_exact(self) -> "CommercialRecurringBillingLine":
        if self.amount != _money_product(self.quantity, self.unit_rate):
            raise ValueError(
                "recurring line amount must equal quantity times unit rate"
            )
        return self


class CommercialRecurringBillingProposal(_StrictModel):
    """Closed-period recurring proposal; never an invoice or authoritative write."""

    schema_id: Literal["lightbulb.commercial_recurring_billing_proposal.v1"] = Field(
        default="lightbulb.commercial_recurring_billing_proposal.v1",
        alias="schema",
    )
    billing_ref: OpaqueRef
    subscription_ref: OpaqueRef
    order_ref: OpaqueRef
    account_ref: OpaqueRef
    billing_basis: Literal["flat", "seat"]
    period_start: str
    period_end: str
    status: Literal["validated"]
    currency: CurrencyCode
    lines: tuple[CommercialRecurringBillingLine, ...] = Field(
        min_length=1,
        max_length=5_000,
    )
    total: Decimal = Field(ge=0)
    evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=2, max_length=20)

    @field_validator("period_start", "period_end")
    @classmethod
    def _billing_period(cls, value: str, info: Any) -> str:
        return _timestamp(value, field_name=info.field_name)

    @field_validator("total", mode="before")
    @classmethod
    def _billing_total(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="total")

    @field_validator("lines", "evidence_refs", mode="before")
    @classmethod
    def _billing_tuples(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _proposal_is_exact(self) -> "CommercialRecurringBillingProposal":
        if _parsed_timestamp(self.period_end) <= _parsed_timestamp(self.period_start):
            raise ValueError("recurring billing period_end must follow period_start")
        _unique(
            [line.billing_line_ref for line in self.lines],
            label="recurring billing line",
        )
        _unique(
            [line.order_line_ref for line in self.lines],
            label="recurring order line",
        )
        _unique(self.evidence_refs, label="recurring billing evidence")
        if self.billing_basis == "flat" and any(
            line.quantity != Decimal("1.000000") for line in self.lines
        ):
            raise ValueError("every flat billing line must have quantity one")
        if self.total != _exact_sum([line.amount for line in self.lines]):
            raise ValueError("recurring billing total must equal its exact line sum")
        return self


def _controlled_recurring_billing(value: Any) -> BaseModel:
    payload = (
        value.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, CommercialRecurringBillingProposal)
        else value
    )
    with localcontext(_DECIMAL_CONTEXT):
        return CommercialRecurringBillingProposal.model_validate(payload)


_ControlledRecurringBilling = Annotated[
    CommercialRecurringBillingProposal,
    BeforeValidator(_controlled_recurring_billing),
]


class UsageSourceBinding(_StrictModel):
    measurement_ref: OpaqueRef
    source_event_ref: OpaqueRef
    source_event_revision: int = Field(ge=1)
    source_event_digest: Sha256Digest
    meter_ref: OpaqueRef
    source_event_occurred_at: str

    @field_validator("source_event_occurred_at")
    @classmethod
    def _source_event_occurred_at(cls, value: str) -> str:
        return _timestamp(value, field_name="source_event_occurred_at")


class ProposeUsageBillingCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_propose_usage_billing_command.v2"] = Field(
        default="lightbulb.commercial_propose_usage_billing_command.v2",
        alias="schema",
    )
    kind: Literal["propose_usage_billing"] = "propose_usage_billing"
    usage_batch_revision: int = Field(ge=1)
    usage_billing: _ControlledUsage
    recurring_billing_revision: int | None = Field(default=None, ge=1)
    recurring_billing: _ControlledRecurringBilling | None = None
    source_event_bindings: tuple[UsageSourceBinding, ...] = Field(
        min_length=1,
        max_length=20_000,
    )
    usage_recorded_by_ref: OpaqueRef
    rated_by_ref: OpaqueRef
    billing_reviewed_by_ref: OpaqueRef
    recurring_priced_by_ref: OpaqueRef | None = None
    usage_source_evidence_ref: OpaqueRef
    rating_evidence_ref: OpaqueRef
    recurring_pricing_evidence_ref: OpaqueRef | None = None

    @field_validator("source_event_bindings", mode="before")
    @classmethod
    def _source_bindings_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _rating_gate_is_independent(self) -> "ProposeUsageBillingCommand":
        actors: tuple[str, ...] = (
            self.usage_recorded_by_ref,
            self.rated_by_ref,
            self.billing_reviewed_by_ref,
        )
        recurring_fields = (
            self.recurring_billing_revision,
            self.recurring_priced_by_ref,
            self.recurring_pricing_evidence_ref,
        )
        if self.recurring_billing is None:
            if any(value is not None for value in recurring_fields):
                raise ValueError(
                    "recurring billing metadata requires a recurring component"
                )
        else:
            if any(value is None for value in recurring_fields):
                raise ValueError(
                    "hybrid billing requires revision, pricing actor, and evidence"
                )
            recurring_priced_by_ref = self.recurring_priced_by_ref
            recurring_pricing_evidence_ref = self.recurring_pricing_evidence_ref
            if (
                recurring_priced_by_ref is None
                or recurring_pricing_evidence_ref is None
            ):
                raise ValueError("hybrid recurring metadata is incomplete")
            actors = (*actors, recurring_priced_by_ref)
        if len(set(actors)) != len(actors):
            raise ValueError(
                "usage recording, rating, recurring pricing, and billing review "
                "must differ"
            )
        for evidence_ref, kind in (
            (self.usage_source_evidence_ref, "usage_source_events"),
            (self.rating_evidence_ref, "usage_billing"),
        ):
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=evidence_ref,
                kind=kind,
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
        if self.recurring_billing is not None:
            recurring_pricing_evidence_ref = self.recurring_pricing_evidence_ref
            if recurring_pricing_evidence_ref is None:
                raise ValueError("hybrid recurring pricing evidence is required")
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=recurring_pricing_evidence_ref,
                kind="recurring_pricing",
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
            recurring = self.recurring_billing
            usage = self.usage_billing
            if (
                recurring.subscription_ref != usage.subscription_ref
                or recurring.account_ref != usage.account_ref
                or recurring.currency != usage.currency
                or recurring.period_start != usage.period_start
                or recurring.period_end != usage.period_end
                or recurring.billing_ref == usage.billing_ref
            ):
                raise ValueError(
                    "hybrid recurring and usage components must share exact scope and "
                    "period while retaining distinct references"
                )
            _require_exact_evidence_set(
                recurring.evidence_refs,
                expected_refs={
                    recurring_pricing_evidence_ref,
                    self.rating_evidence_ref,
                },
                label="hybrid recurring billing proposal",
            )
        measurement_refs = {
            measurement.measurement_ref
            for measurement in self.usage_billing.measurements
        }
        binding_measurement_refs = {
            binding.measurement_ref for binding in self.source_event_bindings
        }
        if binding_measurement_refs != measurement_refs or len(
            self.source_event_bindings
        ) != len(measurement_refs):
            raise ValueError(
                "source-event bindings must exactly cover usage measurements"
            )
        measurements_by_ref = {
            measurement.measurement_ref: measurement
            for measurement in self.usage_billing.measurements
        }
        if any(
            binding.meter_ref != measurements_by_ref[binding.measurement_ref].meter_ref
            for binding in self.source_event_bindings
        ):
            raise ValueError("every source event must bind the exact measurement meter")
        _unique(
            [binding.source_event_ref for binding in self.source_event_bindings],
            label="usage source event",
        )
        _unique(
            [binding.source_event_digest for binding in self.source_event_bindings],
            label="usage source event digest",
        )
        source_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.usage_source_evidence_ref
        )
        rating_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.rating_evidence_ref
        )
        latest_source_event_at = max(
            _parsed_timestamp(binding.source_event_occurred_at)
            for binding in self.source_event_bindings
        )
        if _parsed_timestamp(source_evidence.observed_at) < latest_source_event_at:
            raise ValueError(
                "usage source evidence cannot predate its latest source event"
            )
        if _parsed_timestamp(rating_evidence.observed_at) < _parsed_timestamp(
            source_evidence.observed_at
        ):
            raise ValueError("rating evidence cannot predate usage source evidence")
        if _parsed_timestamp(rating_evidence.observed_at) < _parsed_timestamp(
            self.usage_billing.period_end
        ):
            raise ValueError("rating evidence cannot predate the rated period end")
        if self.recurring_pricing_evidence_ref is not None:
            recurring_pricing_evidence = next(
                evidence
                for evidence in self.evidence_refs
                if evidence.evidence_ref == self.recurring_pricing_evidence_ref
            )
            if _parsed_timestamp(rating_evidence.observed_at) < _parsed_timestamp(
                recurring_pricing_evidence.observed_at
            ):
                raise ValueError(
                    "hybrid billing review cannot predate recurring pricing evidence"
                )
        usage_evidence = {
            self.usage_source_evidence_ref,
            self.rating_evidence_ref,
        }
        expected_evidence = set(usage_evidence)
        if self.recurring_pricing_evidence_ref is not None:
            expected_evidence.add(self.recurring_pricing_evidence_ref)
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs=expected_evidence,
            label="usage billing command",
        )
        _require_exact_evidence_set(
            self.usage_billing.evidence_refs,
            expected_refs=usage_evidence,
            label="usage billing proposal",
        )
        return self


class ProposeRecurringBillingCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_propose_recurring_billing_command.v1"] = (
        Field(
            default="lightbulb.commercial_propose_recurring_billing_command.v1",
            alias="schema",
        )
    )
    kind: Literal["propose_recurring_billing"] = "propose_recurring_billing"
    billing_revision: int = Field(ge=1)
    recurring_billing: _ControlledRecurringBilling
    priced_by_ref: OpaqueRef
    billing_reviewed_by_ref: OpaqueRef
    pricing_evidence_ref: OpaqueRef
    billing_evidence_ref: OpaqueRef

    @model_validator(mode="after")
    def _recurring_gate_is_independent(self) -> "ProposeRecurringBillingCommand":
        if self.priced_by_ref == self.billing_reviewed_by_ref:
            raise ValueError("recurring pricing and billing review must differ")
        for evidence_ref, kind in (
            (self.pricing_evidence_ref, "recurring_pricing"),
            (self.billing_evidence_ref, "recurring_billing"),
        ):
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=evidence_ref,
                kind=kind,
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
        pricing_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.pricing_evidence_ref
        )
        billing_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.billing_evidence_ref
        )
        if _parsed_timestamp(billing_evidence.observed_at) < _parsed_timestamp(
            self.recurring_billing.period_end
        ):
            raise ValueError("recurring billing evidence cannot predate period close")
        if _parsed_timestamp(billing_evidence.observed_at) < _parsed_timestamp(
            pricing_evidence.observed_at
        ):
            raise ValueError("billing review cannot predate recurring pricing evidence")
        expected_evidence = {
            self.pricing_evidence_ref,
            self.billing_evidence_ref,
        }
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs=expected_evidence,
            label="recurring billing command",
        )
        _require_exact_evidence_set(
            self.recurring_billing.evidence_refs,
            expected_refs=expected_evidence,
            label="recurring billing proposal",
        )
        return self


class PrepareRenewalCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_prepare_renewal_command.v1"] = Field(
        default="lightbulb.commercial_prepare_renewal_command.v1",
        alias="schema",
    )
    kind: Literal["prepare_renewal"] = "prepare_renewal"
    renewal_revision: int = Field(ge=1)
    renewal: _ControlledRenewal
    renewal_configuration: _ControlledConfiguration
    renewal_quote: _ControlledQuote
    proposed_renewal_total: Decimal = Field(ge=0)
    currency: CurrencyCode
    prepared_by_ref: OpaqueRef
    reviewed_by_ref: OpaqueRef
    renewal_pricing_evidence_ref: OpaqueRef
    renewal_review_evidence_ref: OpaqueRef

    @field_validator("proposed_renewal_total", mode="before")
    @classmethod
    def _renewal_total(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="proposed_renewal_total")

    @model_validator(mode="after")
    def _renewal_gate_is_independent(self) -> "PrepareRenewalCommand":
        if self.prepared_by_ref == self.reviewed_by_ref:
            raise ValueError("renewal preparation and review must be independent")
        if self.currency != self.scope.currency:
            raise ValueError("renewal currency must match lifecycle scope")
        if self.renewal.renewal_quote_ref is None:
            raise ValueError("reviewed renewal requires a renewal quote reference")
        _configuration_is_exact(self.scope, self.renewal_configuration)
        _quote_is_exact(
            self.scope,
            self.renewal_configuration,
            self.renewal_quote,
        )
        if self.renewal.renewal_quote_ref != self.renewal_quote.quote_ref:
            raise ValueError("renewal must pin the exact renewal quote")
        if (
            self.renewal_quote.status != "accepted"
            or self.renewal_quote.approval_status != "approved"
            or self.renewal_quote.prepared_by_ref != self.prepared_by_ref
            or self.renewal_quote.approved_by_ref != self.reviewed_by_ref
        ):
            raise ValueError(
                "renewal quote must retain its independent preparation and review"
            )
        if self.proposed_renewal_total != self.renewal_quote.total:
            raise ValueError(
                "proposed renewal total must equal the exact renewal quote total"
            )
        if _parsed_timestamp(
            self.renewal_configuration.effective_at
        ) > _parsed_timestamp(self.occurred_at) or _parsed_timestamp(
            self.renewal_quote.valid_until
        ) <= _parsed_timestamp(self.occurred_at):
            raise ValueError(
                "renewal configuration and quote must cover preparation time"
            )
        if self.renewal_configuration.expires_at is not None and (
            _parsed_timestamp(self.renewal_configuration.expires_at)
            <= _parsed_timestamp(self.occurred_at)
            or _parsed_timestamp(self.renewal_quote.valid_until)
            > _parsed_timestamp(self.renewal_configuration.expires_at)
        ):
            raise ValueError(
                "renewal configuration must remain effective through quote validity"
            )
        for evidence_ref, kind in (
            (self.renewal_pricing_evidence_ref, "renewal_pricing"),
            (self.renewal_review_evidence_ref, "renewal"),
        ):
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=evidence_ref,
                kind=kind,
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
        pricing_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.renewal_pricing_evidence_ref
        )
        review_evidence = next(
            evidence
            for evidence in self.evidence_refs
            if evidence.evidence_ref == self.renewal_review_evidence_ref
        )
        if _parsed_timestamp(review_evidence.observed_at) < _parsed_timestamp(
            pricing_evidence.observed_at
        ):
            raise ValueError("renewal review evidence cannot predate renewal pricing")
        if not {
            self.renewal_pricing_evidence_ref,
            self.renewal_review_evidence_ref,
        }.issubset(set(self.renewal.evidence_refs)):
            raise ValueError("renewal must retain pricing and review evidence")
        expected_evidence = {
            self.renewal_pricing_evidence_ref,
            self.renewal_review_evidence_ref,
        }
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs=expected_evidence,
            label="renewal command",
        )
        _require_exact_evidence_set(
            self.renewal.evidence_refs,
            expected_refs=expected_evidence,
            label="renewal",
        )
        _require_exact_evidence_set(
            self.renewal_configuration.evidence_refs,
            expected_refs=expected_evidence,
            label="renewal configuration",
        )
        _require_exact_evidence_set(
            self.renewal_quote.evidence_refs,
            expected_refs=expected_evidence,
            label="renewal quote",
        )
        renewal_effective_at = _parsed_timestamp(
            self.renewal_configuration.effective_at
        )
        if any(
            _parsed_timestamp(evidence.observed_at) < renewal_effective_at
            for evidence in self.evidence_refs
        ):
            raise ValueError(
                "renewal pricing and review evidence cannot predate effectiveness"
            )
        return self


class AttributeChannelCommand(_CommandBase):
    schema_id: Literal["lightbulb.commercial_attribute_channel_command.v1"] = Field(
        default="lightbulb.commercial_attribute_channel_command.v1",
        alias="schema",
    )
    kind: Literal["attribute_channel"] = "attribute_channel"
    attribution_revision: int = Field(ge=1)
    channel_authorization: _ControlledChannel
    attribution_ratio: Decimal = Field(gt=0, le=1)
    attributed_by_ref: OpaqueRef
    authorized_by_ref: OpaqueRef
    channel_evidence_ref: OpaqueRef

    @field_validator("attribution_ratio", mode="before")
    @classmethod
    def _attribution_ratio(cls, value: Any) -> Decimal:
        return _decimal(value, field_name="attribution_ratio")

    @model_validator(mode="after")
    def _channel_gate_is_independent(self) -> "AttributeChannelCommand":
        if self.attributed_by_ref == self.authorized_by_ref:
            raise ValueError("channel attribution and authorization must differ")
        _require_selected_evidence(
            self.evidence_refs,
            evidence_ref=self.channel_evidence_ref,
            kind="channel_partner",
            minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
        )
        if self.channel_evidence_ref not in self.channel_authorization.evidence_refs:
            raise ValueError("channel authorization must retain selected evidence")
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs={self.channel_evidence_ref},
            label="channel attribution command",
        )
        _require_exact_evidence_set(
            self.channel_authorization.evidence_refs,
            expected_refs={self.channel_evidence_ref},
            label="channel authorization",
        )
        return self


class PrepareCommissionRevOpsHandoffCommand(_CommandBase):
    schema_id: Literal[
        "lightbulb.commercial_prepare_commission_revops_handoff_command.v1"
    ] = Field(
        default=("lightbulb.commercial_prepare_commission_revops_handoff_command.v1"),
        alias="schema",
    )
    kind: Literal["prepare_commission_revops_handoff"] = (
        "prepare_commission_revops_handoff"
    )
    commission_revision: int = Field(ge=1)
    handoff_revision: int = Field(ge=1)
    commission_basis: _ControlledCommission
    commission_rate: Decimal = Field(ge=0, le=1)
    proposed_commission_amount: Decimal = Field(ge=0)
    revenue_ops_handoff: _ControlledHandoff
    commission_prepared_by_ref: OpaqueRef
    commission_approved_by_ref: OpaqueRef
    commission_plan_evidence_ref: OpaqueRef
    commission_evidence_ref: OpaqueRef
    handoff_evidence_ref: OpaqueRef

    @field_validator("commission_rate", "proposed_commission_amount", mode="before")
    @classmethod
    def _commission_decimal(cls, value: Any, info: Any) -> Decimal:
        return _decimal(value, field_name=info.field_name)

    @model_validator(mode="after")
    def _commission_gate_is_independent(
        self,
    ) -> "PrepareCommissionRevOpsHandoffCommand":
        owner_ref = self.revenue_ops_handoff.owner_ref
        if owner_ref is None:
            raise ValueError("Revenue Operations handoff requires an owner")
        actors = {
            self.commission_prepared_by_ref,
            self.commission_approved_by_ref,
            owner_ref,
        }
        if len(actors) != 3:
            raise ValueError(
                "commission preparation, approval, and RevOps ownership must differ"
            )
        if self.commission_approved_by_ref == self.commission_basis.payee_ref:
            raise ValueError("commission payee cannot approve their commission")
        if self.commission_prepared_by_ref == self.commission_basis.payee_ref:
            raise ValueError("commission payee cannot prepare their commission")
        if owner_ref == self.commission_basis.payee_ref:
            raise ValueError("commission payee cannot own their RevOps handoff")
        expected = _money_product(
            self.commission_basis.eligible_basis,
            self.commission_rate,
        )
        if self.proposed_commission_amount != expected:
            raise ValueError("proposed commission must equal eligible basis times rate")
        for evidence_ref, kind in (
            (self.commission_plan_evidence_ref, "commission_plan"),
            (self.commission_evidence_ref, "commission_basis"),
            (self.handoff_evidence_ref, "revenue_ops_handoff"),
        ):
            _require_selected_evidence(
                self.evidence_refs,
                evidence_ref=evidence_ref,
                kind=kind,
                minimum_grade=PrimitiveEvidenceVerificationGrade.VERIFIED,
            )
        evidence_by_ref = {
            evidence.evidence_ref: evidence for evidence in self.evidence_refs
        }
        plan_evidence = evidence_by_ref[self.commission_plan_evidence_ref]
        commission_evidence = evidence_by_ref[self.commission_evidence_ref]
        handoff_evidence = evidence_by_ref[self.handoff_evidence_ref]
        if _parsed_timestamp(commission_evidence.observed_at) < _parsed_timestamp(
            plan_evidence.observed_at
        ):
            raise ValueError("commission basis evidence cannot predate its plan")
        if _parsed_timestamp(handoff_evidence.observed_at) < _parsed_timestamp(
            commission_evidence.observed_at
        ):
            raise ValueError("RevOps handoff evidence cannot predate commission basis")
        if self.commission_evidence_ref not in self.commission_basis.evidence_refs:
            raise ValueError("commission basis must retain commission evidence")
        if self.handoff_evidence_ref not in self.revenue_ops_handoff.evidence_refs:
            raise ValueError("RevOps handoff must retain handoff evidence")
        _require_exact_evidence_set(
            self.evidence_refs,
            expected_refs={
                self.commission_plan_evidence_ref,
                self.commission_evidence_ref,
                self.handoff_evidence_ref,
            },
            label="commission and RevOps handoff command",
        )
        _require_exact_evidence_set(
            self.commission_basis.evidence_refs,
            expected_refs={
                self.commission_plan_evidence_ref,
                self.commission_evidence_ref,
            },
            label="commission basis",
        )
        _require_exact_evidence_set(
            self.revenue_ops_handoff.evidence_refs,
            expected_refs={self.handoff_evidence_ref},
            label="Revenue Operations handoff",
        )
        return self


CommercialLifecycleCommand = Annotated[
    ProposeQuoteCommand
    | ReviewContractOrderCommand
    | ActivateSubscriptionCommand
    | ProposeUsageBillingCommand
    | ProposeRecurringBillingCommand
    | PrepareRenewalCommand
    | AttributeChannelCommand
    | PrepareCommissionRevOpsHandoffCommand,
    Field(discriminator="kind"),
]


_COMMAND_MODELS: dict[str, type[_CommandBase]] = {
    "propose_quote": ProposeQuoteCommand,
    "review_contract_order": ReviewContractOrderCommand,
    "activate_subscription": ActivateSubscriptionCommand,
    "propose_usage_billing": ProposeUsageBillingCommand,
    "propose_recurring_billing": ProposeRecurringBillingCommand,
    "prepare_renewal": PrepareRenewalCommand,
    "attribute_channel": AttributeChannelCommand,
    "prepare_commission_revops_handoff": PrepareCommissionRevOpsHandoffCommand,
}

_COMMAND_STAGE_KINDS: tuple[frozenset[str], ...] = (
    frozenset({"propose_quote"}),
    frozenset({"review_contract_order"}),
    frozenset({"activate_subscription"}),
    frozenset({"propose_usage_billing", "propose_recurring_billing"}),
    frozenset({"prepare_renewal"}),
    frozenset({"attribute_channel"}),
    frozenset({"prepare_commission_revops_handoff"}),
)
_STATUS_ORDER = (
    "quote_proposed",
    "contract_order_reviewed",
    "subscription_active",
    "billing_proposed",
    "renewal_reviewed",
    "channel_attributed",
    "revops_handoff_ready",
)
CommercialLifecycleStatus = Literal[
    "quote_proposed",
    "contract_order_reviewed",
    "subscription_active",
    "billing_proposed",
    "renewal_reviewed",
    "channel_attributed",
    "revops_handoff_ready",
]


def _command_payload(command: BaseModel | Mapping[str, Any]) -> dict[str, Any]:
    payload = (
        command.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(command, BaseModel)
        else dict(command)
    )
    return _normalize_unordered_collections(payload)


def commercial_command_evidence_digest(
    command: BaseModel | Mapping[str, Any],
) -> str:
    """Digest normalized command content without its circular evidence envelope."""

    if isinstance(command, BaseModel):
        payload = _command_payload(command)
    else:
        raw = _normalize_unordered_collections(dict(command))
        kind = raw.get("kind")
        model = _COMMAND_MODELS.get(kind) if isinstance(kind, str) else None
        if model is None:
            raise ValueError("kind must identify a supported commercial command")
        raw["request_digest"] = GENESIS_SNAPSHOT_DIGEST
        with localcontext(_DECIMAL_CONTEXT):
            parsed = model.model_validate(
                raw,
                context={
                    "skip_commercial_evidence_digest": True,
                    "skip_commercial_request_digest": True,
                },
            )
        payload = _command_payload(parsed)
    payload.pop("request_digest", None)
    payload.pop("evidence_refs", None)
    return _stable_digest(payload)


def commercial_command_digest(command: BaseModel | Mapping[str, Any]) -> str:
    """Digest every normalized command field except its self-describing digest."""

    if isinstance(command, BaseModel):
        payload = _command_payload(command)
    else:
        raw = _normalize_unordered_collections(dict(command))
        kind = raw.get("kind")
        model = _COMMAND_MODELS.get(kind) if isinstance(kind, str) else None
        if model is None:
            raise ValueError("kind must identify a supported commercial command")
        raw["request_digest"] = GENESIS_SNAPSHOT_DIGEST
        with localcontext(_DECIMAL_CONTEXT):
            parsed = model.model_validate(
                raw,
                context={"skip_commercial_request_digest": True},
            )
        payload = _command_payload(parsed)
    payload.pop("request_digest", None)
    return _stable_digest(payload)


def seal_commercial_command(command: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and validate a command, then seal its exact request digest."""

    payload = _normalize_unordered_collections(dict(command))
    kind = payload.get("kind")
    command_model = _COMMAND_MODELS.get(kind) if isinstance(kind, str) else None
    if command_model is None:
        raise ValueError("kind must identify a supported commercial command")
    payload["request_digest"] = GENESIS_SNAPSHOT_DIGEST
    with localcontext(_DECIMAL_CONTEXT):
        parsed = command_model.model_validate(
            payload,
            context={"skip_commercial_request_digest": True},
        )
    canonical = _command_payload(parsed)
    canonical.pop("request_digest", None)
    canonical["request_digest"] = commercial_command_digest(canonical)
    return canonical


def _evidence_digest(evidence_refs: Sequence[PrimitiveEvidenceRef]) -> str:
    return _stable_digest(
        [
            item.to_dict()
            for item in sorted(evidence_refs, key=lambda item: item.evidence_ref)
        ]
    )


class CommercialTransitionCandidate(_StrictModel):
    schema_id: Literal["lightbulb.commercial_transition_candidate.v2"] = Field(
        default="lightbulb.commercial_transition_candidate.v2",
        alias="schema",
    )
    to_version: int = Field(ge=1, le=MAX_COMMERCIAL_TRANSITIONS)
    scope_digest: Sha256Digest
    command_content_digest: Sha256Digest
    evidence_digest: Sha256Digest
    command: CommercialLifecycleCommand

    @model_validator(mode="after")
    def _transition_is_self_proving(self) -> "CommercialTransitionCandidate":
        if self.to_version != self.command.expected_version + 1:
            raise ValueError(
                "candidate version must exactly follow the command's expected version"
            )
        if self.scope_digest != commercial_scope_digest(self.command.scope):
            raise ValueError("candidate transition scope digest is invalid")
        if self.command_content_digest != commercial_command_evidence_digest(
            self.command
        ):
            raise ValueError("candidate transition content digest is invalid")
        if self.evidence_digest != _evidence_digest(self.command.evidence_refs):
            raise ValueError("candidate transition evidence digest is invalid")
        return self


def _derived_artifacts(
    history: Sequence[CommercialTransitionCandidate],
) -> dict[str, Any]:
    artifacts: dict[str, Any] = {
        "configuration": None,
        "quote": None,
        "order": None,
        "contract": None,
        "subscription": None,
        "recurring_billing_proposal": None,
        "usage_billing_proposal": None,
        "renewal": None,
        "renewal_configuration": None,
        "renewal_quote": None,
        "channel_attribution": None,
        "commission_basis_proposal": None,
        "revenue_ops_handoff_proposal": None,
    }
    for candidate in history:
        command = candidate.command
        if isinstance(command, ProposeQuoteCommand):
            artifacts["configuration"] = command.configuration
            artifacts["quote"] = command.quote
        elif isinstance(command, ReviewContractOrderCommand):
            artifacts["quote"] = command.reviewed_quote
            artifacts["order"] = command.order
            artifacts["contract"] = command.contract
        elif isinstance(command, ActivateSubscriptionCommand):
            artifacts["subscription"] = command.subscription
        elif isinstance(command, ProposeUsageBillingCommand):
            artifacts["usage_billing_proposal"] = command.usage_billing
            artifacts["recurring_billing_proposal"] = command.recurring_billing
        elif isinstance(command, ProposeRecurringBillingCommand):
            artifacts["recurring_billing_proposal"] = command.recurring_billing
        elif isinstance(command, PrepareRenewalCommand):
            artifacts["renewal"] = command.renewal
            artifacts["renewal_configuration"] = command.renewal_configuration
            artifacts["renewal_quote"] = command.renewal_quote
        elif isinstance(command, AttributeChannelCommand):
            artifacts["channel_attribution"] = command.channel_authorization
        elif isinstance(command, PrepareCommissionRevOpsHandoffCommand):
            artifacts["commission_basis_proposal"] = command.commission_basis
            artifacts["revenue_ops_handoff_proposal"] = command.revenue_ops_handoff
    return artifacts


def _snapshot_payload(
    scope: CommercialLifecycleScope,
    history: Sequence[CommercialTransitionCandidate],
) -> dict[str, Any]:
    artifacts = _derived_artifacts(history)
    payload = {
        "schema": COMMERCIAL_LIFECYCLE_SNAPSHOT_SCHEMA,
        "scope": scope.to_dict(),
        "status": _STATUS_ORDER[len(history) - 1],
        "version": len(history),
        "transition_history": [item.to_dict() for item in history],
        **{
            key: value.to_dict() if isinstance(value, BaseModel) else value
            for key, value in artifacts.items()
        },
    }
    return _normalize_unordered_collections(payload)


def _snapshot_digest(
    scope: CommercialLifecycleScope,
    history: Sequence[CommercialTransitionCandidate],
) -> str:
    return _stable_digest(_snapshot_payload(scope, history))


class CommercialOperationsLifecycleSnapshot(_StrictModel):
    schema_id: Literal["lightbulb.commercial_operations_lifecycle_snapshot.v2"] = Field(
        default=COMMERCIAL_LIFECYCLE_SNAPSHOT_SCHEMA, alias="schema"
    )
    scope: CommercialLifecycleScope
    status: CommercialLifecycleStatus
    version: int = Field(ge=1, le=MAX_COMMERCIAL_TRANSITIONS)
    transition_history: tuple[CommercialTransitionCandidate, ...] = Field(
        min_length=1,
        max_length=MAX_COMMERCIAL_TRANSITIONS,
    )
    configuration: _ControlledConfiguration
    quote: _ControlledQuote
    order: _ControlledOrder | None = None
    contract: _ControlledContract | None = None
    subscription: _ControlledSubscription | None = None
    recurring_billing_proposal: _ControlledRecurringBilling | None = None
    usage_billing_proposal: _ControlledUsage | None = None
    renewal: _ControlledRenewal | None = None
    renewal_configuration: _ControlledConfiguration | None = None
    renewal_quote: _ControlledQuote | None = None
    channel_attribution: _ControlledChannel | None = None
    commission_basis_proposal: _ControlledCommission | None = None
    revenue_ops_handoff_proposal: _ControlledHandoff | None = None
    state_digest: Sha256Digest

    @field_validator("transition_history", mode="before")
    @classmethod
    def _history_tuple(cls, value: Any) -> Any:
        return _as_tuple(value)

    @model_validator(mode="after")
    def _snapshot_is_exact(self) -> "CommercialOperationsLifecycleSnapshot":
        if self.version != len(self.transition_history):
            raise ValueError("snapshot version must equal transition count")
        if self.status != _STATUS_ORDER[self.version - 1]:
            raise ValueError("snapshot status must match its bounded lifecycle stage")
        kinds = [item.command.kind for item in self.transition_history]
        if any(
            kind not in _COMMAND_STAGE_KINDS[index] for index, kind in enumerate(kinds)
        ):
            raise ValueError(
                "commercial transitions must be one ordered bounded prefix"
            )
        if [item.to_version for item in self.transition_history] != list(
            range(1, self.version + 1)
        ):
            raise ValueError("commercial transition versions must be contiguous")
        commands = [item.command for item in self.transition_history]
        for field_name in ("transition_ref", "idempotency_key", "request_digest"):
            _unique(
                [getattr(item, field_name) for item in commands],
                label=field_name,
            )
        evidence_refs = [
            evidence.evidence_ref
            for command in commands
            for evidence in command.evidence_refs
        ]
        _unique(evidence_refs, label="historical evidence")
        times = [_parsed_timestamp(item.occurred_at) for item in commands]
        if times != sorted(times):
            raise ValueError("commercial transition timestamps must be monotonic")
        for index, candidate in enumerate(self.transition_history):
            command = candidate.command
            if command.scope != self.scope:
                raise ValueError("every historical command must match exact scope")
            if candidate.scope_digest != commercial_scope_digest(self.scope):
                raise ValueError(
                    "every historical command must retain exact scope digest"
                )
            if command.expected_version != index:
                raise ValueError("historical expected versions must be contiguous")
            expected_digest = (
                GENESIS_SNAPSHOT_DIGEST
                if index == 0
                else _snapshot_digest(self.scope, self.transition_history[:index])
            )
            if command.expected_snapshot_digest != expected_digest:
                raise ValueError("historical snapshot digest fence is invalid")
        derived = _derived_artifacts(self.transition_history)
        for name, expected in derived.items():
            if getattr(self, name) != expected:
                raise ValueError(f"{name} must equal the artifact retained in history")
        _replay_historical_transition_semantics(
            self.scope,
            self.transition_history,
        )
        primary_artifact_refs = [
            self.configuration.configuration_ref,
            self.quote.quote_ref,
        ]
        for artifact, field_name in (
            (self.order, "order_ref"),
            (self.contract, "contract_ref"),
            (self.subscription, "subscription_ref"),
            (self.recurring_billing_proposal, "billing_ref"),
            (self.usage_billing_proposal, "billing_ref"),
            (self.renewal, "renewal_ref"),
            (self.renewal_configuration, "configuration_ref"),
            (self.renewal_quote, "quote_ref"),
            (self.commission_basis_proposal, "commission_ref"),
            (self.revenue_ops_handoff_proposal, "handoff_ref"),
        ):
            if artifact is not None:
                primary_artifact_refs.append(getattr(artifact, field_name))
        if (
            self.channel_attribution is not None
            and self.channel_attribution.deal_registration_ref is not None
        ):
            primary_artifact_refs.append(self.channel_attribution.deal_registration_ref)
        _artifact_refs_are_unique(
            primary_artifact_refs,
            label="primary commercial artifact",
        )
        if self.state_digest != _snapshot_digest(
            self.scope,
            self.transition_history,
        ):
            raise ValueError("state_digest must commit the exact lifecycle snapshot")
        return self


class CommercialOperationsLifecycleInput(_StrictModel):
    schema_id: Literal["lightbulb.commercial_operations_lifecycle_input.v2"] = Field(
        default=COMMERCIAL_LIFECYCLE_INPUT_SCHEMA, alias="schema"
    )
    scope: CommercialLifecycleScope
    command: CommercialLifecycleCommand
    current_snapshot: CommercialOperationsLifecycleSnapshot | None = None

    @model_validator(mode="after")
    def _input_scope_is_exact(self) -> "CommercialOperationsLifecycleInput":
        if self.command.scope != self.scope:
            raise ValueError("command scope must exactly match lifecycle input scope")
        if (
            self.current_snapshot is not None
            and self.current_snapshot.scope != self.scope
        ):
            raise ValueError("current snapshot scope must exactly match input scope")
        if (
            not isinstance(self.command, ProposeQuoteCommand)
            and self.current_snapshot is None
        ):
            raise ValueError("non-genesis commands require a current snapshot")
        return self


RecoveryDisposition = Literal[
    "not_required",
    "do_not_replay",
    "refresh_snapshot",
    "correct_input",
    "manual_reconciliation",
]


class CommercialTransitionRecovery(_StrictModel):
    disposition: RecoveryDisposition
    automatic_retry_allowed: Literal[False] = False
    instructions: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def _instructions_match_disposition(self) -> "CommercialTransitionRecovery":
        if self.disposition == "not_required" and self.instructions is not None:
            raise ValueError(
                "successful materialization needs no recovery instructions"
            )
        if self.disposition != "not_required" and self.instructions is None:
            raise ValueError("rejected materialization requires recovery instructions")
        return self


class CommercialTransitionReceipt(_StrictModel):
    schema_id: Literal["lightbulb.commercial_operations_transition_receipt.v2"] = Field(
        default=COMMERCIAL_TRANSITION_RECEIPT_SCHEMA, alias="schema"
    )
    transition_ref: OpaqueRef
    idempotency_key: OpaqueRef
    request_digest: Sha256Digest
    command_kind: str
    status: Literal["candidate_materialized", "rejected", "in_doubt"]
    from_version: int = Field(ge=0, le=MAX_COMMERCIAL_TRANSITIONS)
    to_version: int = Field(ge=0, le=MAX_COMMERCIAL_TRANSITIONS)
    from_snapshot_digest: Sha256Digest
    to_snapshot_digest: Sha256Digest
    evidence_digest: Sha256Digest
    rejection_code: str | None = Field(default=None, min_length=1, max_length=120)
    recovery: CommercialTransitionRecovery
    live_systems_changed: Literal[False] = False
    authoritative_write_authorized: Literal[False] = False
    pricing_or_booking_written: Literal[False] = False
    contract_or_billing_written: Literal[False] = False
    commission_written: Literal[False] = False

    @model_validator(mode="after")
    def _receipt_is_coherent(self) -> "CommercialTransitionReceipt":
        if self.status == "candidate_materialized":
            if self.to_version != self.from_version + 1:
                raise ValueError(
                    "materialized candidate must advance exactly one SDK version"
                )
            if self.rejection_code is not None:
                raise ValueError("materialized candidate cannot have a rejection code")
            if self.recovery.disposition != "not_required":
                raise ValueError("materialized candidate cannot require recovery")
        else:
            if self.to_version != self.from_version:
                raise ValueError("rejected transition cannot advance the version")
            if self.to_snapshot_digest != self.from_snapshot_digest:
                raise ValueError(
                    "rejected transition cannot change the snapshot digest"
                )
            if self.rejection_code is None:
                raise ValueError("rejected transition requires a rejection code")
            if self.recovery.disposition == "not_required":
                raise ValueError("rejected transition requires bounded recovery")
        if (
            self.status == "in_doubt"
            and self.recovery.disposition != "manual_reconciliation"
        ):
            raise ValueError("in-doubt outcome requires manual reconciliation")
        return self


class CommercialOperationsLifecycleResult(_StrictModel):
    schema_id: Literal["lightbulb.commercial_operations_lifecycle_result.v2"] = Field(
        default=COMMERCIAL_LIFECYCLE_RESULT_SCHEMA, alias="schema"
    )
    candidate_validated: bool
    evaluated_command: CommercialLifecycleCommand
    snapshot: CommercialOperationsLifecycleSnapshot | None = None
    transition_receipt: CommercialTransitionReceipt

    @model_validator(mode="after")
    def _result_is_coherent(self) -> "CommercialOperationsLifecycleResult":
        command = self.evaluated_command
        receipt = self.transition_receipt
        if (
            receipt.transition_ref != command.transition_ref
            or receipt.idempotency_key != command.idempotency_key
            or receipt.request_digest != command.request_digest
            or receipt.command_kind != command.kind
            or receipt.evidence_digest != _evidence_digest(command.evidence_refs)
        ):
            raise ValueError(
                "transition receipt must exactly identify the evaluated command"
            )
        if self.candidate_validated != (receipt.status == "candidate_materialized"):
            raise ValueError(
                "candidate_validated must match the transition receipt status"
            )
        if self.candidate_validated and self.snapshot is None:
            raise ValueError("validated candidate requires a resulting snapshot")
        if self.snapshot is not None and (
            self.snapshot.version != receipt.to_version
            or self.snapshot.state_digest != receipt.to_snapshot_digest
        ):
            raise ValueError("result snapshot must match the transition receipt")
        if self.candidate_validated:
            snapshot = self.snapshot
            if snapshot is None:
                raise ValueError("validated candidate requires a resulting snapshot")
            retained_command = snapshot.transition_history[-1].command
            if (
                retained_command != command
                or receipt.from_version != snapshot.version - 1
            ):
                raise ValueError(
                    "candidate receipt must exactly identify the retained command"
                )
            expected_from_digest = (
                GENESIS_SNAPSHOT_DIGEST
                if snapshot.version == 1
                else _snapshot_digest(
                    snapshot.scope,
                    snapshot.transition_history[:-1],
                )
            )
            if receipt.from_snapshot_digest != expected_from_digest:
                raise ValueError(
                    "candidate receipt must retain the exact prior snapshot digest"
                )
        else:
            current_version = self.snapshot.version if self.snapshot is not None else 0
            current_digest = (
                self.snapshot.state_digest
                if self.snapshot is not None
                else GENESIS_SNAPSHOT_DIGEST
            )
            if (
                receipt.from_version != current_version
                or receipt.to_version != current_version
                or receipt.from_snapshot_digest != current_digest
                or receipt.to_snapshot_digest != current_digest
            ):
                raise ValueError(
                    "rejected receipt must retain the exact evaluated current state"
                )
            replay_input = CommercialOperationsLifecycleInput(
                scope=command.scope,
                command=command,
                current_snapshot=self.snapshot,
            )
            try:
                _materialize_candidate_transition(replay_input)
            except _TransitionRejected as exc:
                expected_status = "in_doubt" if exc.in_doubt else "rejected"
                if (
                    receipt.status != expected_status
                    or receipt.rejection_code != exc.code
                    or receipt.recovery.disposition != exc.recovery
                    or receipt.recovery.instructions != exc.instructions
                ):
                    raise ValueError(
                        "rejected receipt must retain the deterministic rejection"
                    ) from exc
            else:
                raise ValueError(
                    "a command that materializes successfully cannot have a rejection receipt"
                )
        return self


class _TransitionRejected(Exception):
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


def _check_header(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: _CommandBase,
) -> None:
    historical = [item.command for item in snapshot.transition_history]
    transition_matches = [
        item for item in historical if item.transition_ref == command.transition_ref
    ]
    if transition_matches:
        code = (
            "DUPLICATE_TRANSITION"
            if transition_matches[0].request_digest == command.request_digest
            else "TRANSITION_REFERENCE_CONFLICT"
        )
        raise _TransitionRejected(
            code,
            "Do not replay; inspect the durable Spring transition ledger.",
            "do_not_replay",
        )
    idempotency_matches = [
        item for item in historical if item.idempotency_key == command.idempotency_key
    ]
    if idempotency_matches:
        code = (
            "DUPLICATE_IDEMPOTENCY_KEY"
            if idempotency_matches[0].request_digest == command.request_digest
            else "IDEMPOTENCY_KEY_CONFLICT"
        )
        raise _TransitionRejected(
            code,
            "Do not replay; reconcile the idempotency key in Spring's durable ledger.",
            "do_not_replay",
        )
    if any(item.request_digest == command.request_digest for item in historical):
        raise _TransitionRejected(
            "REQUEST_REPLAY",
            "The exact command was already retained; do not replay it.",
            "do_not_replay",
        )
    retained_evidence_refs = {
        evidence.evidence_ref
        for historical_command in historical
        for evidence in historical_command.evidence_refs
    }
    if retained_evidence_refs.intersection(
        evidence.evidence_ref for evidence in command.evidence_refs
    ):
        raise _TransitionRejected(
            "EVIDENCE_REFERENCE_REUSE",
            "Use new content-bound evidence references for each transition.",
            "correct_input",
        )
    if command.expected_version != snapshot.version:
        raise _TransitionRejected(
            "STALE_VERSION",
            "Refresh the authoritative snapshot before preparing another command.",
            "refresh_snapshot",
        )
    if command.expected_snapshot_digest != snapshot.state_digest:
        raise _TransitionRejected(
            "STALE_SNAPSHOT_DIGEST",
            "Refresh the authoritative snapshot; its content digest has changed.",
            "refresh_snapshot",
        )
    latest_transition_at = snapshot.transition_history[-1].command.occurred_at
    if _parsed_timestamp(command.occurred_at) < _parsed_timestamp(latest_transition_at):
        raise _TransitionRejected(
            "NON_MONOTONIC_TRANSITION_TIME",
            "Transition time cannot precede the latest retained transition.",
            "correct_input",
        )
    if any(
        _parsed_timestamp(evidence.observed_at)
        < _parsed_timestamp(latest_transition_at)
        for evidence in command.evidence_refs
    ):
        raise _TransitionRejected(
            "STALE_TRANSITION_EVIDENCE",
            "Consequential evidence cannot predate the prior lifecycle stage.",
            "correct_input",
        )


def _known_primary_artifact_refs(
    snapshot: CommercialOperationsLifecycleSnapshot,
) -> set[str]:
    refs = {
        snapshot.configuration.configuration_ref,
        snapshot.quote.quote_ref,
    }
    for artifact, field_name in (
        (snapshot.order, "order_ref"),
        (snapshot.contract, "contract_ref"),
        (snapshot.subscription, "subscription_ref"),
        (snapshot.recurring_billing_proposal, "billing_ref"),
        (snapshot.usage_billing_proposal, "billing_ref"),
        (snapshot.renewal, "renewal_ref"),
        (snapshot.renewal_configuration, "configuration_ref"),
        (snapshot.renewal_quote, "quote_ref"),
        (snapshot.commission_basis_proposal, "commission_ref"),
        (snapshot.revenue_ops_handoff_proposal, "handoff_ref"),
    ):
        if artifact is not None:
            refs.add(getattr(artifact, field_name))
    if (
        snapshot.channel_attribution is not None
        and snapshot.channel_attribution.deal_registration_ref is not None
    ):
        refs.add(snapshot.channel_attribution.deal_registration_ref)
    return refs


def _reject_artifact_ref_collision(
    snapshot: CommercialOperationsLifecycleSnapshot,
    *new_refs: str,
) -> None:
    retained = _known_primary_artifact_refs(snapshot)
    if len(set(new_refs)) != len(new_refs) or retained.intersection(new_refs):
        raise _TransitionRejected(
            "ARTIFACT_REFERENCE_COLLISION",
            "Every primary commercial artifact requires a new unambiguous reference.",
            "correct_input",
        )


def _validate_review_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: ReviewContractOrderCommand,
) -> None:
    proposed = snapshot.quote
    reviewed = command.reviewed_quote
    if (
        reviewed.quote_ref != proposed.quote_ref
        or reviewed.revision != proposed.revision + 1
    ):
        raise _TransitionRejected(
            "QUOTE_REVISION_MISMATCH",
            "Review must advance the exact proposed quote by one revision.",
            "correct_input",
        )
    if _quote_economic_digest(reviewed) != _quote_economic_digest(proposed):
        raise _TransitionRejected(
            "QUOTE_ECONOMICS_CHANGED",
            "Create a new scoped quote proposal before reviewing changed economics.",
            "correct_input",
        )
    if (
        reviewed.status != "accepted"
        or reviewed.approval_status != "approved"
        or reviewed.approved_by_ref != command.quote_approved_by_ref
    ):
        raise _TransitionRejected(
            "QUOTE_NOT_INDEPENDENTLY_APPROVED",
            "Provide an accepted quote with the selected independent approver.",
            "correct_input",
        )
    if proposed.prepared_by_ref in {
        command.quote_approved_by_ref,
        command.order_reviewed_by_ref,
        command.contract_reviewed_by_ref,
    }:
        raise _TransitionRejected(
            "QUOTE_APPROVAL_SOD_VIOLATION",
            "Quote preparer and every consequential reviewer must be distinct.",
            "correct_input",
        )
    _quote_is_exact(snapshot.scope, snapshot.configuration, reviewed)
    order = command.order
    contract = command.contract
    _reject_artifact_ref_collision(
        snapshot,
        order.order_ref,
        contract.contract_ref,
    )
    if order.revision != 1 or contract.revision != 1:
        raise _TransitionRejected(
            "INITIAL_REVIEW_ARTIFACT_REVISION_MISMATCH",
            "The first retained order and contract revisions must both be one.",
            "correct_input",
        )
    if (
        order.account_ref != snapshot.scope.customer_ref
        or order.currency != snapshot.scope.currency
        or order.quote_ref != reviewed.quote_ref
        or order.contract_ref != contract.contract_ref
        or order.status != "confirmed"
        or order.total != reviewed.total
    ):
        raise _TransitionRejected(
            "ORDER_LINKAGE_INVALID",
            "Order must be a confirmed, exact-scope projection of the reviewed quote.",
            "correct_input",
        )
    quote_lines = {item.quote_line_ref: item for item in reviewed.lines}
    if {item.quote_line_ref for item in order.lines} != set(quote_lines) or len(
        order.lines
    ) != len(quote_lines):
        raise _TransitionRejected(
            "ORDER_LINES_MISMATCH",
            "Order lines must exactly and one-to-one cover reviewed quote lines.",
            "correct_input",
        )
    for line in order.lines:
        quoted = quote_lines[line.quote_line_ref]
        if (
            line.product_ref != snapshot.scope.product_ref
            or line.quantity != quoted.quantity
            or line.unit_price != quoted.unit_price
            or line.line_total != quoted.line_total
        ):
            raise _TransitionRejected(
                "ORDER_LINE_ECONOMICS_MISMATCH",
                "Order line economics must exactly match the reviewed quote.",
                "correct_input",
            )
    if _exact_sum([line.line_total for line in order.lines]) != order.total:
        raise _TransitionRejected(
            "ORDER_TOTAL_MISMATCH",
            "Order total must exactly equal its retained line totals.",
            "correct_input",
        )
    if (
        contract.account_ref != snapshot.scope.customer_ref
        or contract.currency != snapshot.scope.currency
        or contract.quote_ref != reviewed.quote_ref
        or contract.order_ref != order.order_ref
        or contract.status != "active"
        or contract.signature_status != "completed"
        or contract.contract_value != order.total
        or contract.amendment_pending
        or set(contract.completed_signer_refs) != set(contract.required_signer_refs)
        or not contract.required_signer_refs
    ):
        raise _TransitionRejected(
            "CONTRACT_REVIEW_INVALID",
            "Contract must be fully signed, active, exact-scope, and value-linked.",
            "correct_input",
        )
    if not (
        _parsed_timestamp(contract.effective_at)
        <= _parsed_timestamp(command.occurred_at)
        < _parsed_timestamp(contract.expires_at)
    ):
        raise _TransitionRejected(
            "CONTRACT_EFFECTIVITY_INVALID",
            "An active contract must cover the exact review time.",
            "correct_input",
        )
    if _parsed_timestamp(reviewed.valid_until) <= _parsed_timestamp(
        command.occurred_at
    ):
        raise _TransitionRejected(
            "QUOTE_EXPIRED",
            "Review cannot use an expired quote.",
            "correct_input",
        )
    if not {
        command.quote_approval_evidence_ref,
        command.order_review_evidence_ref,
    }.issubset(set(reviewed.evidence_refs) | set(order.evidence_refs)):
        raise _TransitionRejected(
            "REVIEW_EVIDENCE_NOT_RETAINED",
            "Reviewed quote and order must retain the selected evidence.",
            "correct_input",
        )
    if command.contract_signature_evidence_ref not in contract.evidence_refs:
        raise _TransitionRejected(
            "CONTRACT_EVIDENCE_NOT_RETAINED",
            "Contract must retain the selected signature evidence.",
            "correct_input",
        )


def _validate_subscription_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: ActivateSubscriptionCommand,
) -> None:
    order = snapshot.order
    contract = snapshot.contract
    if order is None or contract is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Subscription activation requires reviewed order and contract candidates.",
            "correct_input",
        )
    subscription = command.subscription
    _reject_artifact_ref_collision(snapshot, subscription.subscription_ref)
    if command.subscription_revision != 1:
        raise _TransitionRejected(
            "SUBSCRIPTION_REVISION_MISMATCH",
            "The first retained subscription revision must be one.",
            "correct_input",
        )
    if (
        subscription.order_ref != order.order_ref
        or subscription.contract_ref != contract.contract_ref
        or subscription.account_ref != snapshot.scope.customer_ref
        or subscription.status != "active"
        or subscription.current_term_start != contract.effective_at
        or subscription.current_term_end != contract.expires_at
        or not subscription.entitlements
    ):
        raise _TransitionRejected(
            "SUBSCRIPTION_LINKAGE_INVALID",
            "Active subscription must exactly link the reviewed order and term.",
            "correct_input",
        )
    usage_metered = subscription.billing_model in {"usage", "hybrid"}
    if usage_metered != bool(subscription.authorized_meter_refs):
        raise _TransitionRejected(
            "BILLING_MODEL_CONFIGURATION_INVALID",
            "Usage and hybrid subscriptions require meters; flat and seat "
            "subscriptions must not fabricate them.",
            "correct_input",
        )
    if not (
        _parsed_timestamp(subscription.current_term_start)
        <= _parsed_timestamp(command.occurred_at)
        < _parsed_timestamp(subscription.current_term_end)
    ):
        raise _TransitionRejected(
            "SUBSCRIPTION_EFFECTIVITY_INVALID",
            "An active subscription must cover the exact activation time.",
            "correct_input",
        )
    for entitlement in subscription.entitlements:
        if (
            entitlement.product_ref != snapshot.scope.product_ref
            or entitlement.status != "active"
            or entitlement.effective_at != subscription.current_term_start
            or entitlement.expires_at != subscription.current_term_end
        ):
            raise _TransitionRejected(
                "ENTITLEMENT_SCOPE_INVALID",
                "Every active entitlement must match the scoped product and term.",
                "correct_input",
            )
    ordered_quantity = _exact_sum([line.quantity for line in order.lines])
    entitled_quantity = _exact_sum(
        [entitlement.quantity for entitlement in subscription.entitlements]
    )
    if entitled_quantity != ordered_quantity:
        raise _TransitionRejected(
            "ENTITLEMENT_QUANTITY_MISMATCH",
            "Active entitlement quantity must exactly equal ordered product quantity.",
            "correct_input",
        )


def _validate_recurring_billing_component(
    snapshot: CommercialOperationsLifecycleSnapshot,
    recurring: CommercialRecurringBillingProposal,
    *,
    occurred_at: str,
) -> None:
    subscription = snapshot.subscription
    order = snapshot.order
    if subscription is None or order is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Recurring billing requires active subscription and order candidates.",
            "correct_input",
        )
    if (
        recurring.subscription_ref != subscription.subscription_ref
        or recurring.order_ref != order.order_ref
        or recurring.account_ref != snapshot.scope.customer_ref
        or recurring.currency != snapshot.scope.currency
        or recurring.status != "validated"
    ):
        raise _TransitionRejected(
            "RECURRING_BILLING_LINKAGE_INVALID",
            "Recurring billing must retain exact subscription, order, and scope.",
            "correct_input",
        )
    if (
        recurring.period_start != subscription.current_term_start
        or _parsed_timestamp(recurring.period_end)
        > _parsed_timestamp(subscription.current_term_end)
        or _parsed_timestamp(recurring.period_end) > _parsed_timestamp(occurred_at)
    ):
        raise _TransitionRejected(
            "RECURRING_BILLING_PERIOD_INVALID",
            "The first recurring period must start with the term, be closed, and "
            "remain inside it.",
            "correct_input",
        )
    order_lines = {line.order_line_ref: line for line in order.lines}
    recurring_lines = {line.order_line_ref: line for line in recurring.lines}
    if set(recurring_lines) != set(order_lines):
        raise _TransitionRejected(
            "RECURRING_BILLING_LINES_MISMATCH",
            "Recurring billing lines must exactly cover retained order lines.",
            "correct_input",
        )
    for order_line_ref, recurring_line in recurring_lines.items():
        order_line = order_lines[order_line_ref]
        if recurring.billing_basis == "flat":
            exact = (
                recurring_line.quantity == Decimal("1.000000")
                and recurring_line.unit_rate == order_line.line_total
                and recurring_line.amount == order_line.line_total
            )
        else:
            exact = (
                recurring_line.quantity == order_line.quantity
                and recurring_line.unit_rate == order_line.unit_price
                and recurring_line.amount == order_line.line_total
            )
        if not exact:
            raise _TransitionRejected(
                "RECURRING_BILLING_ECONOMICS_MISMATCH",
                "Flat or seat quantity, rate, and amount must exactly match the order.",
                "correct_input",
            )
    if recurring.total != order.total:
        raise _TransitionRejected(
            "RECURRING_BILLING_TOTAL_MISMATCH",
            "Recurring billing total must exactly equal the retained order total.",
            "correct_input",
        )
    if recurring.billing_basis == "seat":
        billed_quantity = _exact_sum([line.quantity for line in recurring.lines])
        entitled_quantity = _exact_sum(
            [entitlement.quantity for entitlement in subscription.entitlements]
        )
        if billed_quantity != entitled_quantity:
            raise _TransitionRejected(
                "SEAT_BILLING_ENTITLEMENT_MISMATCH",
                "Seat quantity must exactly equal active entitlement quantity.",
                "correct_input",
            )


def _validate_recurring_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: ProposeRecurringBillingCommand,
) -> None:
    subscription = snapshot.subscription
    if subscription is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Recurring billing requires an active subscription candidate.",
            "correct_input",
        )
    recurring = command.recurring_billing
    _reject_artifact_ref_collision(snapshot, recurring.billing_ref)
    if command.billing_revision != 1:
        raise _TransitionRejected(
            "BILLING_REVISION_MISMATCH",
            "The first retained recurring billing revision must be one.",
            "correct_input",
        )
    if (
        subscription.billing_model not in {"flat", "seat"}
        or recurring.billing_basis != subscription.billing_model
    ):
        raise _TransitionRejected(
            "BILLING_MODEL_BRANCH_MISMATCH",
            "Flat and seat subscriptions require their exact recurring branch.",
            "correct_input",
        )
    _validate_recurring_billing_component(
        snapshot,
        recurring,
        occurred_at=command.occurred_at,
    )


def _validate_usage_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: ProposeUsageBillingCommand,
) -> None:
    subscription = snapshot.subscription
    if subscription is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Usage rating requires an active subscription candidate.",
            "correct_input",
        )
    usage = command.usage_billing
    recurring = command.recurring_billing
    if subscription.billing_model not in {"usage", "hybrid"}:
        raise _TransitionRejected(
            "BILLING_MODEL_BRANCH_MISMATCH",
            "Flat and seat subscriptions cannot fabricate usage billing.",
            "correct_input",
        )
    if (subscription.billing_model == "hybrid") != (recurring is not None):
        raise _TransitionRejected(
            "BILLING_MODEL_BRANCH_MISMATCH",
            "Usage subscriptions require usage only; hybrid subscriptions require "
            "exact recurring and usage components.",
            "correct_input",
        )
    if subscription.billing_model == "hybrid":
        activation_command = snapshot.transition_history[2].command
        if (
            not isinstance(activation_command, ActivateSubscriptionCommand)
            or recurring is None
            or activation_command.hybrid_recurring_basis != recurring.billing_basis
        ):
            raise _TransitionRejected(
                "HYBRID_RECURRING_BASIS_MISMATCH",
                "Hybrid billing must retain the recurring basis selected at activation.",
                "correct_input",
            )
    new_refs = (
        (usage.billing_ref, recurring.billing_ref)
        if recurring is not None
        else (usage.billing_ref,)
    )
    _reject_artifact_ref_collision(snapshot, *new_refs)
    if command.usage_batch_revision != 1:
        raise _TransitionRejected(
            "USAGE_REVISION_MISMATCH",
            "The first retained usage batch revision must be one.",
            "correct_input",
        )
    if recurring is not None:
        if command.recurring_billing_revision != 1:
            raise _TransitionRejected(
                "BILLING_REVISION_MISMATCH",
                "The first retained hybrid recurring revision must be one.",
                "correct_input",
            )
        _validate_recurring_billing_component(
            snapshot,
            recurring,
            occurred_at=command.occurred_at,
        )
    if (
        usage.subscription_ref != subscription.subscription_ref
        or usage.account_ref != snapshot.scope.customer_ref
        or usage.currency != snapshot.scope.currency
        or usage.status != "validated"
        or not usage.aggregation_complete
        or usage.deduplication_status != "clear"
        or not usage.measurements
    ):
        raise _TransitionRejected(
            "USAGE_PROPOSAL_INVALID",
            "Usage proposal must be complete, deduplicated, and exact-scope.",
            "correct_input",
        )
    if (
        _parsed_timestamp(usage.period_start)
        < _parsed_timestamp(subscription.current_term_start)
        or _parsed_timestamp(usage.period_end)
        > _parsed_timestamp(subscription.current_term_end)
        or _parsed_timestamp(usage.period_end) > _parsed_timestamp(command.occurred_at)
    ):
        raise _TransitionRejected(
            "USAGE_PERIOD_INVALID",
            "Usage period must be closed, observed, and within the subscription term.",
            "correct_input",
        )
    meters = set(subscription.authorized_meter_refs)
    if any(
        not (
            _parsed_timestamp(usage.period_start)
            <= _parsed_timestamp(binding.source_event_occurred_at)
            < _parsed_timestamp(usage.period_end)
        )
        for binding in command.source_event_bindings
    ):
        raise _TransitionRejected(
            "USAGE_SOURCE_EVENT_OUTSIDE_PERIOD",
            "Every immutable source event must occur inside the rated usage period.",
            "correct_input",
        )
    rated_amounts: list[Decimal] = []
    for measurement in usage.measurements:
        if measurement.meter_ref not in meters:
            raise _TransitionRejected(
                "UNAUTHORIZED_USAGE_METER",
                "Every measurement must use an authorized subscription meter.",
                "correct_input",
            )
        expected = _money_product(measurement.quantity, measurement.unit_rate)
        if measurement.amount != expected:
            raise _TransitionRejected(
                "USAGE_RATING_MISMATCH",
                "Measurement amount must equal quantity times unit rate.",
                "correct_input",
            )
        rated_amounts.append(measurement.amount)
    if usage.total != _exact_sum(rated_amounts):
        raise _TransitionRejected(
            "USAGE_TOTAL_MISMATCH",
            "Usage total must equal the deterministically rated measurements.",
            "correct_input",
        )


def _validate_renewal_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: PrepareRenewalCommand,
) -> None:
    subscription = snapshot.subscription
    contract = snapshot.contract
    if subscription is None or contract is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Renewal preparation requires contract and subscription candidates.",
            "correct_input",
        )
    renewal = command.renewal
    if renewal.renewal_quote_ref is None:
        raise _TransitionRejected(
            "RENEWAL_QUOTE_MISSING",
            "Renewal preparation requires an exact renewal quote reference.",
            "correct_input",
        )
    _reject_artifact_ref_collision(
        snapshot,
        renewal.renewal_ref,
        command.renewal_configuration.configuration_ref,
        renewal.renewal_quote_ref,
    )
    if (
        command.renewal_configuration.revision != 1
        or command.renewal_quote.revision != 1
    ):
        raise _TransitionRejected(
            "INITIAL_RENEWAL_ARTIFACT_REVISION_MISMATCH",
            "The first renewal configuration and quote revisions must both be one.",
            "correct_input",
        )
    if command.renewal_revision != 1:
        raise _TransitionRejected(
            "RENEWAL_REVISION_MISMATCH",
            "The first retained renewal revision must be one.",
            "correct_input",
        )
    if (
        renewal.subscription_ref != subscription.subscription_ref
        or renewal.contract_ref != contract.contract_ref
        or renewal.status != "approved"
        or renewal.renewal_at != subscription.current_term_end
        or renewal.owner_ref != command.prepared_by_ref
        or _parsed_timestamp(renewal.notice_deadline)
        < _parsed_timestamp(command.occurred_at)
    ):
        raise _TransitionRejected(
            "RENEWAL_LINKAGE_INVALID",
            "Renewal must be reviewed, term-linked, owned, and before its notice deadline.",
            "correct_input",
        )


def _validate_channel_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: AttributeChannelCommand,
) -> None:
    if snapshot.contract is None:
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Channel attribution requires a reviewed contract candidate.",
            "correct_input",
        )
    channel = command.channel_authorization
    if command.attribution_revision != 1:
        raise _TransitionRejected(
            "CHANNEL_REVISION_MISMATCH",
            "The first retained channel attribution revision must be one.",
            "correct_input",
        )
    if channel.account_ref != snapshot.scope.customer_ref:
        raise _TransitionRejected(
            "CHANNEL_CUSTOMER_MISMATCH",
            "Channel customer must match lifecycle scope.",
            "correct_input",
        )
    if snapshot.scope.product_ref not in channel.authorized_product_refs:
        raise _TransitionRejected(
            "CHANNEL_PRODUCT_UNAUTHORIZED",
            "Channel authorization must include the scoped product.",
            "correct_input",
        )
    if command.attribution_ratio != 1:
        raise _TransitionRejected(
            "INCOMPLETE_CHANNEL_ATTRIBUTION",
            "This single-route lifecycle requires complete channel attribution.",
            "correct_input",
        )
    quote_partner = snapshot.quote.partner_ref
    if channel.route == "partner":
        if (
            channel.authorization_status != "authorized"
            or channel.partner_ref is None
            or channel.deal_registration_ref is None
            or quote_partner != channel.partner_ref
        ):
            raise _TransitionRejected(
                "PARTNER_ATTRIBUTION_INVALID",
                "Partner route requires matching authorization and deal registration.",
                "correct_input",
            )
        _reject_artifact_ref_collision(
            snapshot,
            channel.deal_registration_ref,
        )
        if (
            channel.valid_from is None
            or channel.valid_until is None
            or not (
                _parsed_timestamp(channel.valid_from)
                <= _parsed_timestamp(command.occurred_at)
                < _parsed_timestamp(channel.valid_until)
            )
        ):
            raise _TransitionRejected(
                "PARTNER_AUTHORIZATION_EXPIRED",
                "Partner authorization must cover the attribution time.",
                "correct_input",
            )
    elif (
        quote_partner is not None
        or channel.partner_ref is not None
        or channel.deal_registration_ref is not None
        or channel.valid_from is not None
        or channel.valid_until is not None
        or channel.authorization_status != "not_applicable"
        or command.attribution_ratio != 1
    ):
        raise _TransitionRejected(
            "DIRECT_ATTRIBUTION_INVALID",
            "Direct route cannot retain partner identity or authorization windows and "
            "must attribute fully.",
            "correct_input",
        )


def _validate_handoff_transition(
    snapshot: CommercialOperationsLifecycleSnapshot,
    command: PrepareCommissionRevOpsHandoffCommand,
) -> None:
    order = snapshot.order
    contract = snapshot.contract
    subscription = snapshot.subscription
    recurring = snapshot.recurring_billing_proposal
    usage = snapshot.usage_billing_proposal
    renewal = snapshot.renewal
    renewal_configuration = snapshot.renewal_configuration
    renewal_quote = snapshot.renewal_quote
    channel = snapshot.channel_attribution
    if any(
        artifact is None
        for artifact in (
            order,
            contract,
            subscription,
            renewal,
            renewal_configuration,
            renewal_quote,
            channel,
        )
    ):
        raise _TransitionRejected(
            "INCOMPLETE_PRIOR_STAGE",
            "Commission and RevOps handoff requires every prior candidate artifact.",
            "correct_input",
        )
    if not (
        isinstance(order, CommercialOrderSnapshot)
        and isinstance(contract, CommercialContractSnapshot)
        and isinstance(subscription, CommercialSubscriptionSnapshot)
        and isinstance(renewal, CommercialRenewalSnapshot)
        and isinstance(renewal_configuration, CommercialConfigurationSnapshot)
        and isinstance(renewal_quote, CommercialQuoteSnapshot)
        and isinstance(channel, CommercialChannelAuthorizationSnapshot)
    ):
        raise _TransitionRejected(
            "INVALID_PRIOR_STAGE",
            "Prior commercial candidate artifacts have invalid contract types.",
            "correct_input",
        )
    expects_recurring = subscription.billing_model in {"flat", "seat", "hybrid"}
    expects_usage = subscription.billing_model in {"usage", "hybrid"}
    if (
        expects_recurring != (recurring is not None)
        or expects_usage != (usage is not None)
        or (
            recurring is not None
            and not isinstance(recurring, CommercialRecurringBillingProposal)
        )
        or (usage is not None and not isinstance(usage, CommercialUsageBillingSnapshot))
    ):
        raise _TransitionRejected(
            "INCOMPLETE_BILLING_STAGE",
            "Commission and RevOps require the exact retained billing-model branch.",
            "correct_input",
        )
    commission = command.commission_basis
    handoff = command.revenue_ops_handoff
    _reject_artifact_ref_collision(
        snapshot,
        commission.commission_ref,
        handoff.handoff_ref,
    )
    if command.commission_revision != 1 or command.handoff_revision != 1:
        raise _TransitionRejected(
            "HANDOFF_REVISION_MISMATCH",
            "Initial commission and handoff revisions must both be one.",
            "correct_input",
        )
    if subscription.billing_model == "usage":
        if usage is None:
            raise _TransitionRejected(
                "INCOMPLETE_BILLING_STAGE",
                "Usage billing proposal is required for commission preparation.",
                "correct_input",
            )
        gross_basis = usage.total
    elif subscription.billing_model == "hybrid":
        if recurring is None or usage is None:
            raise _TransitionRejected(
                "INCOMPLETE_BILLING_STAGE",
                "Hybrid commission requires recurring and usage proposals.",
                "correct_input",
            )
        gross_basis = _exact_sum([recurring.total, usage.total])
    else:
        if recurring is None:
            raise _TransitionRejected(
                "INCOMPLETE_BILLING_STAGE",
                "Recurring billing proposal is required for commission preparation.",
                "correct_input",
            )
        gross_basis = recurring.total
    eligible_payees = {snapshot.quote.prepared_by_ref}
    if channel.partner_ref is not None:
        eligible_payees.add(channel.partner_ref)
    if commission.payee_ref not in eligible_payees:
        raise _TransitionRejected(
            "COMMISSION_PAYEE_NOT_DEAL_PARTICIPANT",
            "Commission payee must be a retained seller or attributed partner.",
            "correct_input",
        )
    if (
        commission.order_ref != order.order_ref
        or commission.contract_ref != contract.contract_ref
        or commission.account_ref != snapshot.scope.customer_ref
        or commission.currency != snapshot.scope.currency
        or commission.status != "validated"
        or commission.gross_basis != gross_basis
        or commission.excluded_amount > commission.gross_basis
        or commission.eligible_basis
        != _exact_difference(
            commission.gross_basis,
            commission.excluded_amount,
        )
    ):
        raise _TransitionRejected(
            "COMMISSION_BASIS_INVALID",
            "Commission basis must be non-negative and exactly billing-model linked.",
            "correct_input",
        )
    if (
        handoff.quote_ref != snapshot.quote.quote_ref
        or handoff.order_ref != order.order_ref
        or handoff.contract_ref != contract.contract_ref
        or handoff.subscription_ref != subscription.subscription_ref
        or handoff.account_ref != snapshot.scope.customer_ref
        or handoff.status != "pending"
        or handoff.acknowledged_at is not None
        or set(handoff.required_artifact_refs) != set(handoff.received_artifact_refs)
    ):
        raise _TransitionRejected(
            "REVOPS_HANDOFF_INVALID",
            "RevOps proposal must be exact-linked, complete, pending, and unacknowledged.",
            "correct_input",
        )
    required_refs = {
        snapshot.configuration.configuration_ref,
        snapshot.quote.quote_ref,
        order.order_ref,
        contract.contract_ref,
        subscription.subscription_ref,
        renewal.renewal_ref,
        renewal_configuration.configuration_ref,
        renewal_quote.quote_ref,
        commission.commission_ref,
    }
    if recurring is not None:
        required_refs.add(recurring.billing_ref)
    if usage is not None:
        required_refs.add(usage.billing_ref)
    if channel.deal_registration_ref is not None:
        required_refs.add(channel.deal_registration_ref)
    retained_handoff_refs = set(handoff.required_artifact_refs)
    if not required_refs.issubset(retained_handoff_refs):
        raise _TransitionRejected(
            "REVOPS_ARTIFACTS_INCOMPLETE",
            "RevOps handoff must retain every commercial lifecycle artifact reference.",
            "correct_input",
        )
    if retained_handoff_refs != required_refs:
        raise _TransitionRejected(
            "REVOPS_ARTIFACTS_UNRECOGNIZED",
            "RevOps handoff cannot introduce unretained commercial artifacts.",
            "correct_input",
        )


def _trusted_prefix_snapshot(
    scope: CommercialLifecycleScope,
    history: tuple[CommercialTransitionCandidate, ...],
) -> CommercialOperationsLifecycleSnapshot:
    """Build an internal prefix view after its retained commands were validated."""

    artifacts = _derived_artifacts(history)
    return CommercialOperationsLifecycleSnapshot.model_construct(
        schema_id=COMMERCIAL_LIFECYCLE_SNAPSHOT_SCHEMA,
        scope=scope,
        status=_STATUS_ORDER[len(history) - 1],
        version=len(history),
        transition_history=history,
        state_digest=_snapshot_digest(scope, history),
        **artifacts,
    )


def _replay_historical_transition_semantics(
    scope: CommercialLifecycleScope,
    history: tuple[CommercialTransitionCandidate, ...],
) -> None:
    """Re-evaluate every retained transition against its exact prior prefix."""

    for index, candidate in enumerate(history):
        command = candidate.command
        if command.host_outcome_report != "reported_certain":
            raise ValueError(
                "an in-doubt host report cannot appear in candidate history"
            )
        if index == 0:
            continue
        prefix = _trusted_prefix_snapshot(scope, history[:index])
        try:
            _check_header(prefix, command)
            if isinstance(command, ReviewContractOrderCommand):
                _validate_review_transition(prefix, command)
            elif isinstance(command, ActivateSubscriptionCommand):
                _validate_subscription_transition(prefix, command)
            elif isinstance(command, ProposeUsageBillingCommand):
                _validate_usage_transition(prefix, command)
            elif isinstance(command, ProposeRecurringBillingCommand):
                _validate_recurring_transition(prefix, command)
            elif isinstance(command, PrepareRenewalCommand):
                _validate_renewal_transition(prefix, command)
            elif isinstance(command, AttributeChannelCommand):
                _validate_channel_transition(prefix, command)
            elif isinstance(command, PrepareCommissionRevOpsHandoffCommand):
                _validate_handoff_transition(prefix, command)
            else:
                raise ValueError("unsupported command retained in candidate history")
        except _TransitionRejected as exc:
            raise ValueError(
                f"historical transition {index + 1} is invalid: {exc.code}"
            ) from exc


def _materialize_snapshot(
    scope: CommercialLifecycleScope,
    history: tuple[CommercialTransitionCandidate, ...],
) -> CommercialOperationsLifecycleSnapshot:
    payload = _snapshot_payload(scope, history)
    payload["state_digest"] = _snapshot_digest(scope, history)
    with localcontext(_DECIMAL_CONTEXT):
        return CommercialOperationsLifecycleSnapshot.model_validate(payload)


def _materialize_candidate_transition(
    inputs: CommercialOperationsLifecycleInput,
) -> CommercialOperationsLifecycleSnapshot:
    command = inputs.command
    snapshot = inputs.current_snapshot
    if command.host_outcome_report == "reported_in_doubt":
        raise _TransitionRejected(
            "AMBIGUOUS_HOST_OUTCOME",
            "Do not retry automatically; Spring must reconcile its durable ledger.",
            "manual_reconciliation",
            in_doubt=True,
        )
    if snapshot is not None:
        _check_header(snapshot, command)
    elif not isinstance(command, ProposeQuoteCommand):
        raise _TransitionRejected(
            "MISSING_SNAPSHOT",
            "Refresh the authoritative commercial lifecycle snapshot.",
            "refresh_snapshot",
        )
    if isinstance(command, ProposeQuoteCommand):
        if snapshot is not None:
            raise _TransitionRejected(
                "GENESIS_ALREADY_MATERIALIZED",
                "Do not replay genesis; use Spring's durable transition ledger.",
                "do_not_replay",
            )
        if (
            command.expected_version != 0
            or command.expected_snapshot_digest != GENESIS_SNAPSHOT_DIGEST
        ):
            raise _TransitionRejected(
                "INVALID_GENESIS_FENCE",
                "Genesis requires version zero and the documented genesis digest.",
                "correct_input",
            )
        history: tuple[CommercialTransitionCandidate, ...] = ()
    else:
        if snapshot is None:
            raise _TransitionRejected(
                "MISSING_SNAPSHOT",
                "Refresh the authoritative commercial lifecycle snapshot.",
                "refresh_snapshot",
            )
        expected_kinds = (
            _COMMAND_STAGE_KINDS[snapshot.version]
            if snapshot.version < MAX_COMMERCIAL_TRANSITIONS
            else frozenset()
        )
        if command.kind not in expected_kinds:
            raise _TransitionRejected(
                "OUT_OF_ORDER_TRANSITION",
                "Apply exactly the next bounded commercial lifecycle transition.",
                "correct_input",
            )
        if isinstance(command, ReviewContractOrderCommand):
            _validate_review_transition(snapshot, command)
        elif isinstance(command, ActivateSubscriptionCommand):
            _validate_subscription_transition(snapshot, command)
        elif isinstance(command, ProposeUsageBillingCommand):
            _validate_usage_transition(snapshot, command)
        elif isinstance(command, ProposeRecurringBillingCommand):
            _validate_recurring_transition(snapshot, command)
        elif isinstance(command, PrepareRenewalCommand):
            _validate_renewal_transition(snapshot, command)
        elif isinstance(command, AttributeChannelCommand):
            _validate_channel_transition(snapshot, command)
        elif isinstance(command, PrepareCommissionRevOpsHandoffCommand):
            _validate_handoff_transition(snapshot, command)
        else:
            raise _TransitionRejected(
                "UNSUPPORTED_TRANSITION",
                "Use one documented commercial transition command.",
                "correct_input",
            )
        history = snapshot.transition_history
    candidate = CommercialTransitionCandidate(
        to_version=len(history) + 1,
        scope_digest=commercial_scope_digest(inputs.scope),
        command_content_digest=commercial_command_evidence_digest(command),
        evidence_digest=_evidence_digest(command.evidence_refs),
        command=command,
    )
    return _materialize_snapshot(inputs.scope, (*history, candidate))


def _rejected_result(
    inputs: CommercialOperationsLifecycleInput,
    exc: _TransitionRejected,
) -> CommercialOperationsLifecycleResult:
    snapshot = inputs.current_snapshot
    version = snapshot.version if snapshot is not None else 0
    digest = snapshot.state_digest if snapshot is not None else GENESIS_SNAPSHOT_DIGEST
    return CommercialOperationsLifecycleResult(
        candidate_validated=False,
        evaluated_command=inputs.command,
        snapshot=snapshot,
        transition_receipt=CommercialTransitionReceipt(
            transition_ref=inputs.command.transition_ref,
            idempotency_key=inputs.command.idempotency_key,
            request_digest=inputs.command.request_digest,
            command_kind=inputs.command.kind,
            status="in_doubt" if exc.in_doubt else "rejected",
            from_version=version,
            to_version=version,
            from_snapshot_digest=digest,
            to_snapshot_digest=digest,
            evidence_digest=_evidence_digest(inputs.command.evidence_refs),
            rejection_code=exc.code,
            recovery=CommercialTransitionRecovery(
                disposition=exc.recovery,
                instructions=exc.instructions,
            ),
        ),
    )


def materialize_commercial_operations_candidate(
    inputs: CommercialOperationsLifecycleInput | Mapping[str, Any],
) -> CommercialOperationsLifecycleResult:
    """Materialize exactly one bounded SDK-only commercial transition."""

    payload = (
        inputs.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(inputs, CommercialOperationsLifecycleInput)
        else inputs
    )
    payload = _normalize_unordered_collections(payload)
    # Pydantic's ``model_copy(update=...)`` intentionally skips validation.  Public
    # entry points therefore re-validate model instances as serialized contracts so
    # a forged copied snapshot cannot bypass history, digest, or cross-stage checks.
    with localcontext(_DECIMAL_CONTEXT):
        parsed = CommercialOperationsLifecycleInput.model_validate(payload)
    snapshot = parsed.current_snapshot
    from_version = snapshot.version if snapshot is not None else 0
    from_digest = (
        snapshot.state_digest if snapshot is not None else GENESIS_SNAPSHOT_DIGEST
    )
    try:
        resulting_snapshot = _materialize_candidate_transition(parsed)
    except _TransitionRejected as exc:
        return _rejected_result(parsed, exc)
    receipt = CommercialTransitionReceipt(
        transition_ref=parsed.command.transition_ref,
        idempotency_key=parsed.command.idempotency_key,
        request_digest=parsed.command.request_digest,
        command_kind=parsed.command.kind,
        status="candidate_materialized",
        from_version=from_version,
        to_version=resulting_snapshot.version,
        from_snapshot_digest=from_digest,
        to_snapshot_digest=resulting_snapshot.state_digest,
        evidence_digest=_evidence_digest(parsed.command.evidence_refs),
        recovery=CommercialTransitionRecovery(disposition="not_required"),
    )
    return CommercialOperationsLifecycleResult(
        candidate_validated=True,
        evaluated_command=parsed.command,
        snapshot=resulting_snapshot,
        transition_receipt=receipt,
    )


COMMERCIAL_TRANSITION_OPERATION = PrimitiveOperationSpec(
    operation_ref="commercial_operations_materialize_transition",
    tool="sdk.commercial.materialize_transition",
    effect=ConnectorEffect.READ,
    approval_required=False,
    replay_class=PrimitiveOperationReplayClass.NEVER,
    freshness_class=PrimitiveOperationFreshnessClass.CURRENT,
    recovery_policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
)


def _scope_matches_context(
    inputs: CommercialOperationsLifecycleInput,
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
    evidence_ref: str,
    kind: str,
    transition_ref: str,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "schema": "lightbulb.primitive_evidence_ref.v1",
        "evidence_ref": evidence_ref,
        "kind": kind,
        "issuer_ref": "authoritative-host-example",
        "subject_ref": transition_ref,
        "sha256": GENESIS_SNAPSHOT_DIGEST,
        "observed_at": observed_at,
        "verification_grade": "attested",
        "classification": "confidential",
    }


def _seal_example_command(command: dict[str, Any]) -> dict[str, Any]:
    digest = commercial_command_evidence_digest(command)
    for evidence in command["evidence_refs"]:
        evidence["sha256"] = digest
    return seal_commercial_command(command)


def _commercial_lifecycle_example_inputs() -> dict[str, Any]:
    scope = {
        "tenant_ref": "authenticated",
        "company_ref": "selected",
        "project_ref": "workflow-improvement",
        "project_id": "40100000-0000-4000-8000-000000000001",
        "customer_ref": "customer-example",
        "product_ref": "product-platform",
        "currency": "USD",
    }
    transition_ref = "transition-quote-example"
    evidence_refs = [
        _example_evidence(
            evidence_ref="evidence-cpq-example",
            kind="cpq_configuration",
            transition_ref=transition_ref,
            observed_at="2026-08-25T08:00:00Z",
        ),
        _example_evidence(
            evidence_ref="evidence-pricing-example",
            kind="pricing",
            transition_ref=transition_ref,
            observed_at="2026-08-25T08:01:00Z",
        ),
    ]
    command = _seal_example_command(
        {
            "kind": "propose_quote",
            "scope": scope,
            "transition_ref": transition_ref,
            "idempotency_key": "idem-quote-example",
            "requested_by_ref": "actor-requester-example",
            "expected_version": 0,
            "expected_snapshot_digest": GENESIS_SNAPSHOT_DIGEST,
            "occurred_at": "2026-08-25T09:00:00Z",
            "evidence_refs": evidence_refs,
            "configuration": {
                "schema": "lightbulb.commercial_configuration_snapshot.v1",
                "configuration_ref": "configuration-example",
                "revision": 1,
                "account_ref": "customer-example",
                "status": "validated",
                "price_book_ref": "price-book-example",
                "currency": "USD",
                "effective_at": "2026-08-25T00:00:00Z",
                "expires_at": "2027-08-25T00:00:00Z",
                "lines": [
                    {
                        "configuration_line_ref": "configuration-line-example",
                        "product_ref": "product-platform",
                        "quantity": "2.000000",
                        "list_unit_price": "100.000000",
                        "configured_unit_price": "90.000000",
                        "discount_ratio": "0.100000",
                        "option_refs": ["option-support"],
                    }
                ],
                "evidence_refs": [
                    "evidence-cpq-example",
                    "evidence-pricing-example",
                ],
            },
            "quote": {
                "schema": "lightbulb.commercial_quote_snapshot.v1",
                "quote_ref": "quote-example",
                "revision": 1,
                "configuration_ref": "configuration-example",
                "account_ref": "customer-example",
                "status": "pending_approval",
                "currency": "USD",
                "valid_until": "2026-09-25T00:00:00Z",
                "subtotal": "180.000000",
                "tax_total": "0.000000",
                "total": "180.000000",
                "approval_required": True,
                "approval_status": "pending",
                "prepared_by_ref": "actor-sales-example",
                "lines": [
                    {
                        "quote_line_ref": "quote-line-example",
                        "configuration_line_ref": "configuration-line-example",
                        "product_ref": "product-platform",
                        "quantity": "2.000000",
                        "unit_price": "90.000000",
                        "line_total": "180.000000",
                    }
                ],
                "evidence_refs": ["evidence-pricing-example"],
            },
            "configured_by_ref": "actor-sales-example",
            "configuration_evidence_ref": "evidence-cpq-example",
            "pricing_evidence_ref": "evidence-pricing-example",
        }
    )
    return {"scope": scope, "command": command}


class ProposeCommercialOperationsTransitionPrimitive(
    BusinessProcessPrimitive[
        CommercialOperationsLifecycleInput,
        CommercialOperationsLifecycleResult,
    ]
):
    primitive_ref = "commercial.propose_operations_transition"
    version = "2.0.0"
    title = "Propose a bounded commercial operations transition"
    description = (
        "Materialize one scope-, version-, evidence-, and idempotency-bound "
        "commercial SDK projection without a pricing, contract, subscription, "
        "entitlement, billing, renewal, channel, commission, connector, or "
        "system-of-record write."
    )
    input_model = CommercialOperationsLifecycleInput
    output_model = CommercialOperationsLifecycleResult
    connector_tools = ()
    risk_level = "medium"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = False
    mcp_open_world = False
    example_inputs: Mapping[str, Any] = _commercial_lifecycle_example_inputs()

    def execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CommercialOperationsLifecycleInput | Mapping[str, Any],
    ) -> PrimitiveExecutionResult[CommercialOperationsLifecycleResult]:
        """Keep canonical nested Decimal validation independent of host context."""

        with localcontext(_DECIMAL_CONTEXT):
            return super().execute(context, inputs)

    def implementation_contract(self) -> dict[str, Any]:
        contract = super().implementation_contract()
        contract["operation_contract"] = COMMERCIAL_TRANSITION_OPERATION.to_dict()
        contract["effect_boundary"] = {
            "sdk_projection_only": True,
            "live_systems_changed": False,
            "authoritative_write_authorized": False,
            "connector_or_provider_claims": False,
            "candidate_result_semantics": (
                "structural SDK validation only; execution always returns PREVIEW "
                "and never proves host acceptance"
            ),
        }
        contract["authority_boundary"] = {
            "spring": (
                "authenticated scope, RBAC, pricing, booking, contract, subscription, "
                "entitlement, billing, renewal, channel, commission, persistence, "
                "approvals, audit, and external dispatch"
            ),
            "sdk": "deterministic portable proposal materialization only",
            "actor_separation": (
                "structural proposal only; Spring verifies identities, roles, and approvals"
            ),
        }
        contract["lifecycle_guarantees"] = {
            "maximum_transitions": MAX_COMMERCIAL_TRANSITIONS,
            "scope_binding": (
                "exact tenant, company, project reference and UUID, customer, product, "
                "and currency"
            ),
            "runtime_attribution": (
                "runtime project UUID, authenticated actor, and idempotency key must be "
                "present and exactly match the validated transition command"
            ),
            "revision_and_snapshot_fencing": "reject stale or out-of-order commands",
            "duplicate_policy": "reject without reapplication",
            "genesis_replay": "durable Spring idempotency ledger required",
            "ambiguous_outcome": (
                "never auto-retry; manually reconcile Spring's durable ledger"
            ),
        }
        return contract

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: CommercialOperationsLifecycleInput,
    ) -> PrimitiveExecutionResult[CommercialOperationsLifecycleResult]:
        if not _scope_matches_context(inputs, context):
            blocker = PrimitiveBlocker(
                code="SCOPE_MISMATCH",
                message=(
                    "Runtime tenant/company/project UUID, actor, and idempotency key must "
                    "be present and exactly match the commercial lifecycle input."
                ),
                field="scope",
                retryable=False,
            )
            return PrimitiveExecutionResult[CommercialOperationsLifecycleResult](
                status=PrimitiveExecutionStatus.BLOCKED,
                primitive_ref=self.primitive_ref,
                primitive_version=self.version,
                summary="Commercial lifecycle transition rejected at scope boundary.",
                blockers=[blocker],
                operation_receipts=[
                    PrimitiveOperationReceipt(
                        spec=COMMERCIAL_TRANSITION_OPERATION,
                        status=PrimitiveOperationStatus.BLOCKED,
                        request_digest=inputs.command.request_digest,
                        evidence_refs=list(inputs.command.evidence_refs),
                        error=blocker,
                    )
                ],
            )
        output = materialize_commercial_operations_candidate(inputs)
        if output.candidate_validated:
            receipt_status = PrimitiveOperationStatus.PREVIEW
            execution_status = PrimitiveExecutionStatus.PREVIEW
            recovery_plan = None
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            blocker = None
        elif output.transition_receipt.status == "in_doubt":
            receipt_status = PrimitiveOperationStatus.IN_DOUBT
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_plan = PrimitiveRecoveryPlan(
                policy=PrimitiveOperationRecoveryPolicy.MANUAL_RECONCILIATION,
                disposition=(
                    PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
                ),
                instructions=output.transition_receipt.recovery.instructions,
            )
            recovery_disposition = (
                PrimitiveRecoveryDisposition.MANUAL_RECONCILIATION_REQUIRED
            )
            blocker = PrimitiveBlocker(
                code=output.transition_receipt.rejection_code or "OUTCOME_IN_DOUBT",
                message=output.transition_receipt.recovery.instructions
                or "Manual reconciliation required.",
                retryable=False,
            )
        else:
            receipt_status = PrimitiveOperationStatus.BLOCKED
            execution_status = PrimitiveExecutionStatus.BLOCKED
            recovery_plan = None
            recovery_disposition = PrimitiveRecoveryDisposition.NOT_REQUIRED
            blocker = PrimitiveBlocker(
                code=output.transition_receipt.rejection_code or "TRANSITION_REJECTED",
                message=output.transition_receipt.recovery.instructions
                or "Commercial lifecycle transition rejected.",
                retryable=False,
            )
        operation_receipt = PrimitiveOperationReceipt(
            spec=COMMERCIAL_TRANSITION_OPERATION,
            status=receipt_status,
            request_digest=inputs.command.request_digest,
            evidence_refs=list(inputs.command.evidence_refs),
            external_refs=(
                {
                    "snapshot_digest": output.snapshot.state_digest,
                    "transition_ref": inputs.command.transition_ref,
                }
                if output.candidate_validated and output.snapshot is not None
                else {}
            ),
            recovery_disposition=recovery_disposition,
            recovery_plan=recovery_plan,
            error=blocker,
        )
        return PrimitiveExecutionResult[CommercialOperationsLifecycleResult](
            status=execution_status,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                "Commercial transition candidate validated with no live write."
                if output.candidate_validated
                else "Commercial candidate rejected without changing live state."
            ),
            output=output,
            events=[
                PrimitiveEvent(
                    type="commercial.operations_lifecycle_candidate_evaluated",
                    payload={
                        "transition_ref": inputs.command.transition_ref,
                        "command_kind": inputs.command.kind,
                        "candidate_validated": output.candidate_validated,
                        "request_digest": inputs.command.request_digest,
                        "live_systems_changed": False,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="commercial_lifecycle_candidate_receipt",
                    summary=(
                        "Portable SDK candidate receipt; no authoritative commercial "
                        "approval, write, or provider result is claimed."
                    ),
                    refs={
                        "transition_ref": inputs.command.transition_ref,
                        "request_digest": inputs.command.request_digest,
                    },
                )
            ],
            evidence_refs=list(inputs.command.evidence_refs),
            operation_receipts=[operation_receipt],
            recovery_plan=recovery_plan,
            blockers=[blocker] if blocker is not None else [],
            retryable=False,
        )


COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES: tuple[
    BusinessProcessPrimitive[Any, Any], ...
] = (ProposeCommercialOperationsTransitionPrimitive(),)


__all__ = [
    "ActivateSubscriptionCommand",
    "ProposeCommercialOperationsTransitionPrimitive",
    "CommercialTransitionCandidate",
    "AttributeChannelCommand",
    "COMMERCIAL_LIFECYCLE_INPUT_SCHEMA",
    "COMMERCIAL_LIFECYCLE_RESULT_SCHEMA",
    "COMMERCIAL_LIFECYCLE_SNAPSHOT_SCHEMA",
    "COMMERCIAL_OPERATIONS_LIFECYCLE_EXECUTABLE_PRIMITIVES",
    "COMMERCIAL_TRANSITION_OPERATION",
    "COMMERCIAL_TRANSITION_RECEIPT_SCHEMA",
    "CommercialLifecycleCommand",
    "CommercialLifecycleScope",
    "CommercialOperationsLifecycleInput",
    "CommercialOperationsLifecycleResult",
    "CommercialOperationsLifecycleSnapshot",
    "CommercialRecurringBillingLine",
    "CommercialRecurringBillingProposal",
    "CommercialTransitionReceipt",
    "CommercialTransitionRecovery",
    "GENESIS_SNAPSHOT_DIGEST",
    "MAX_COMMERCIAL_TRANSITIONS",
    "PrepareCommissionRevOpsHandoffCommand",
    "PrepareRenewalCommand",
    "ProposeQuoteCommand",
    "ProposeRecurringBillingCommand",
    "ProposeUsageBillingCommand",
    "ReviewContractOrderCommand",
    "materialize_commercial_operations_candidate",
    "commercial_command_digest",
    "commercial_command_evidence_digest",
    "commercial_scope_digest",
    "seal_commercial_command",
]
