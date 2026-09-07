"""Profit engine: the money model of the Lightbulb Growth Engine.

The funnel (slice 1) knows how demand moves; this module knows what that
demand is *worth*. It turns per-connector contribution-ledger observations
(Shopify, Stripe, Xero, QuickBooks) into one sealed unit-economics snapshot,
translates funnel-rate shortfalls into contribution-profit deltas, plans
margin-guarded price moves that ship as preregistered experiments, and
extracts price-elasticity estimates from causal readouts so pricing becomes
a learned lever instead of a guess.

Design rules enforced here:

- **Evidence is sealed.** Unit economics are computed from
  :class:`ProfitContributionEvidence` envelopes minted by a trusted host;
  verification recomputes the keyed HMAC, so copying a visible scope digest
  onto fabricated ledger numbers is insufficient.
- **Unknown is not zero.** A cost component with no admissible evidence is
  reported ``unknown``; derived components name every missing input and carry
  an explicit ``complete`` flag. Nothing is imputed.
- **Currencies and bases never silently mix.** Every envelope declares an
  ISO-4217 currency and maps to one measurement basis (commerce-recorded vs
  finance-recorded); off-currency evidence is *excluded with a reason* and
  cross-basis derivations are labeled.
- **The margin floor is law.** :func:`plan_price_move` structurally refuses
  any price decrease whose constant-volume projection breaches the caller's
  minimum contribution margin, and the refusal names the exact bound.
- **Causal claims need causal inputs.** :func:`estimate_price_elasticity`
  only accepts a sealed price plan whose embedded preregistration matches the
  sealed design field-for-field, plus that design's causal readout. There is
  no code path from hunch to elasticity.

Naming note: ``lightbulb/growth_primitives.py`` predates the Growth Engine
and holds generic catalog-promoted primitives unrelated to growth analytics;
the Growth Engine lives in the ``growth_funnel`` / ``growth_experiments`` /
``growth_learnings`` / ``growth_profit`` module family.

Rail alignment: ledger field names (``gross_sales``, ``discounts``,
``refunds``, ``cogs``, ``fulfillment_cost``, ``payment_fees``,
``acquisition_cost``, ``service_cost``) and the attestation trio mirror the
execution rail's profit-contribution contract at the dict boundary only — no
imports. Price plans carry rail-style content-bound approval units and are
structurally ``dispatchable_by_planner=False``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .dynamic_workflows import DynamicWorkflowScope
from .growth_experiments import (
    AssignmentUnit,
    DesignGrowthExperimentInput,
    GrowthExperimentDesign,
    GrowthExperimentReadout,
    required_sample_per_arm_continuous,
    verify_growth_experiment_design,
    verify_growth_experiment_readout,
)
from .growth_funnel import GrowthFunnelSnapshot, verify_growth_funnel_snapshot
from .growth_learnings import GrowthLearningEntry, verify_growth_learning_entry
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_PROFIT_EVIDENCE_SCHEMA = "lightbulb.growth_profit_evidence.v1"
GROWTH_UNIT_ECONOMICS_SCHEMA = "lightbulb.growth_unit_economics.v1"
GROWTH_PRICE_PLAN_SCHEMA = "lightbulb.growth_price_plan.v1"
GROWTH_PROFIT_REVIEW_SCHEMA = "lightbulb.growth_profit_review.v1"
GROWTH_PRICE_ELASTICITY_SCHEMA = "lightbulb.growth_price_elasticity.v1"

_PROFIT_EVIDENCE_HMAC_DOMAIN = GROWTH_PROFIT_EVIDENCE_SCHEMA
_UNIT_ECONOMICS_HMAC_DOMAIN = GROWTH_UNIT_ECONOMICS_SCHEMA
_PRICE_PLAN_HMAC_DOMAIN = GROWTH_PRICE_PLAN_SCHEMA

_MAX_PROFIT_EVIDENCE = 100
_MAX_REVIEW_LEARNINGS = 20
_MAX_REVIEW_OPPORTUNITIES = 50

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")
_RATIO_STEP = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

ProfitProvider = Literal["shopify", "stripe", "xero", "quickbooks"]

_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "shopify": frozenset({"shopify.analytics_query"}),
    "stripe": frozenset({"stripe.financial_report"}),
    "xero": frozenset({"xero.profit_and_loss_report"}),
    "quickbooks": frozenset({"quickbooks.profit_and_loss_report"}),
}

ProfitBasis = Literal["commerce_recorded", "finance_recorded"]

_PROVIDER_BASIS: dict[str, ProfitBasis] = {
    "shopify": "commerce_recorded",
    "stripe": "finance_recorded",
    "xero": "finance_recorded",
    "quickbooks": "finance_recorded",
}

LedgerMetricName = Literal[
    "gross_sales",
    "discounts",
    "refunds",
    "cogs",
    "fulfillment_cost",
    "payment_fees",
    "service_cost",
    "acquisition_cost",
    "orders",
    "units",
    "new_customers",
]

_LEDGER_METRICS: tuple[LedgerMetricName, ...] = (
    "gross_sales",
    "discounts",
    "refunds",
    "cogs",
    "fulfillment_cost",
    "payment_fees",
    "service_cost",
    "acquisition_cost",
    "orders",
    "units",
    "new_customers",
)

_MONEY_METRICS = frozenset(
    {
        "gross_sales",
        "discounts",
        "refunds",
        "cogs",
        "fulfillment_cost",
        "payment_fees",
        "service_cost",
        "acquisition_cost",
    }
)

# Which measurement basis is the book of record for each metric. Commerce
# systems (Shopify) know sales, discounts, and unit costs; finance systems
# (Stripe, Xero, QuickBooks) know fees, refunds, and spend as actually booked.
_DEFAULT_BASIS_PRIORITY: tuple[ProfitBasis, ...] = (
    "commerce_recorded",
    "finance_recorded",
)
_METRIC_BASIS_PRIORITY: dict[str, tuple[ProfitBasis, ...]] = {
    "refunds": ("finance_recorded", "commerce_recorded"),
    "payment_fees": ("finance_recorded", "commerce_recorded"),
    "acquisition_cost": ("finance_recorded", "commerce_recorded"),
    "service_cost": ("finance_recorded", "commerce_recorded"),
}

EconomicsComponentName = Literal[
    "net_revenue",
    "variable_cost_total",
    "contribution_profit",
    "contribution_margin",
    "average_order_value",
    "contribution_per_order",
    "customer_acquisition_cost",
    "breakeven_roas",
    "cac_payback_orders",
]

_COMPONENT_ORDER: tuple[EconomicsComponentName, ...] = (
    "net_revenue",
    "variable_cost_total",
    "contribution_profit",
    "contribution_margin",
    "average_order_value",
    "contribution_per_order",
    "customer_acquisition_cost",
    "breakeven_roas",
    "cac_payback_orders",
)

ProfitExclusionReason = Literal[
    "currency_mismatch",
    "future_observation",
    "stale_observation",
    "unverified_evidence",
]

EvidenceScopeStatus = Literal[
    "caller_supplied_unverified",
    "host_hmac_verified",
]

PriceObjective = Literal["protect_margin", "test_elasticity", "grow_contribution"]
PriceDirection = Literal["increase", "decrease"]
PriceReferenceQuality = Literal["experimental_estimate", "default_heuristic"]

MoneyOpportunityKind = Literal[
    "plan_price_move",
    "run_experiment",
    "reduce_cost_leak",
    "collect_evidence",
]

# Cost-leak screening references. These are conservative operating heuristics,
# never presented as industry benchmarks: each emitted leak opportunity is
# labeled ``default_heuristic`` and carries its reference value.
_LEAK_REFERENCES: tuple[tuple[str, str, Decimal], ...] = (
    ("refunds", "refund_ratio", Decimal("0.050000")),
    ("discounts", "discount_ratio", Decimal("0.150000")),
    ("payment_fees", "payment_fee_ratio", Decimal("0.040000")),
)


class GrowthProfitValidationError(ValueError):
    """Profit evidence, economics, or price-plan content violates the contract."""


def _stable_digest(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bounded_text(value: str) -> str:
    if value != value.strip():
        raise ValueError("content must not contain surrounding whitespace")
    if any(ord(character) < 32 for character in value):
        raise ValueError("content contains an unsupported control character")
    return value


ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=300),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def _parse_timestamp(value: str) -> datetime:
    clean = value.strip()
    try:
        parsed = datetime.fromisoformat(clean.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalized_timestamp(value: str) -> str:
    return _parse_timestamp(value).isoformat().replace("+00:00", "Z")


def _decimal(value: Any, *, quantum: Decimal | None = None) -> Decimal:
    if not isinstance(value, (str, Decimal, int, float)) or isinstance(value, bool):
        raise ValueError("decimal values must be supplied as strings or JSON numbers")
    lexical = str(value)
    if len(lexical) > 48 or lexical != lexical.strip():
        raise ValueError("value must use bounded decimal notation")
    try:
        parsed = Decimal(lexical)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("value must be a finite decimal") from exc
    if not parsed.is_finite():
        raise ValueError("value must be a finite decimal")
    if quantum is not None:
        try:
            normalized = parsed.quantize(quantum)
        except InvalidOperation as exc:
            raise ValueError(
                "value cannot be represented at the required precision"
            ) from exc
        if parsed != normalized:
            raise ValueError(
                f"value supports at most {-quantum.as_tuple().exponent} decimal places"
            )
        return normalized
    return parsed


def _immutable_sequence(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(value)
    return value


def _quantized_money(value: Decimal) -> Decimal:
    return value.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _quantized_ratio(value: Decimal) -> Decimal:
    return value.quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=False,
        serialize_by_alias=True,
        strict=True,
    )


class ExactScopeDigestProvider(Protocol):
    """Host-held keyed scope digester; raw authority never enters artifacts."""

    active_key_id: str

    def exact_scope_digest(
        self,
        *,
        key_id: str,
        scope: DynamicWorkflowScope,
    ) -> str: ...

    def sign(self, key_id: str, domain: str, payload: Any) -> bytes: ...


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthProfitValidationError:
        raise
    except Exception as exc:
        raise GrowthProfitValidationError(
            "the profit signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthProfitValidationError:
        raise
    except Exception as exc:
        raise GrowthProfitValidationError(
            "the profit signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Contribution evidence
# ---------------------------------------------------------------------------


class ContributionMetrics(_StrictModel):
    """Normalized per-observation contribution-ledger values.

    Money field names mirror the execution rail's profit-contribution ledger
    verbatim (dict-boundary compatibility). Every field is optional because
    unknown is not zero: a source that cannot see a cost must not claim it.
    """

    gross_sales: Decimal | None = Field(default=None, ge=0)
    discounts: Decimal | None = Field(default=None, ge=0)
    refunds: Decimal | None = Field(default=None, ge=0)
    cogs: Decimal | None = Field(default=None, ge=0)
    fulfillment_cost: Decimal | None = Field(default=None, ge=0)
    payment_fees: Decimal | None = Field(default=None, ge=0)
    service_cost: Decimal | None = Field(default=None, ge=0)
    acquisition_cost: Decimal | None = Field(default=None, ge=0)
    orders: int | None = Field(default=None, ge=0, le=10_000_000_000)
    units: int | None = Field(default=None, ge=0, le=10_000_000_000)
    new_customers: int | None = Field(default=None, ge=0, le=10_000_000_000)

    @field_validator(
        "gross_sales",
        "discounts",
        "refunds",
        "cogs",
        "fulfillment_cost",
        "payment_fees",
        "service_cost",
        "acquisition_cost",
        mode="before",
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _at_least_one_metric(self) -> "ContributionMetrics":
        if all(value is None for value in self.model_dump(mode="python").values()):
            raise ValueError("at least one contribution metric is required")
        return self


class ProfitContributionEvidence(_StrictModel):
    """One sealed connector ledger observation admissible into unit economics."""

    observation_ref: PortableRef
    connector_account_ref: OperationRef
    provider: ProfitProvider
    source_capability: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$",
    )
    currency: CurrencyCode
    observed_at: str
    window_start: str
    window_end: str
    metrics: ContributionMetrics
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    evidence_hmac: Sha256Digest | None = None

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _valid_source_and_window(self) -> "ProfitContributionEvidence":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("evidence window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede the measured window")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.evidence_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "profit evidence attestation fields must be supplied together"
            )
        return self

    @property
    def basis(self) -> ProfitBasis:
        return _PROVIDER_BASIS[self.provider]

    @property
    def is_attested(self) -> bool:
        return self.evidence_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        """Return the complete canonical observation covered by host HMAC."""

        return self.model_dump(
            mode="json",
            exclude={"evidence_hmac"},
            exclude_none=True,
        )


def mint_profit_contribution_evidence(
    value: ProfitContributionEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> ProfitContributionEvidence:
    """Seal one host-verified ledger observation for unit-economics use."""

    evidence = (
        value
        if isinstance(value, ProfitContributionEvidence)
        else ProfitContributionEvidence.model_validate(value)
    )
    if evidence.is_attested or evidence.receipt_key_id is not None:
        raise GrowthProfitValidationError("profit evidence is already attested")
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=key_id,
        scope=workflow_scope,
    )
    payload = evidence.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "evidence_hmac": "0" * 64,
        }
    )
    draft = ProfitContributionEvidence.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_PROFIT_EVIDENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["evidence_hmac"] = signature
    return ProfitContributionEvidence.model_validate(sealed)


def _evidence_attestation_matches(
    evidence: ProfitContributionEvidence,
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
) -> bool:
    if (
        evidence.receipt_key_id is None
        or evidence.exact_scope_digest is None
        or evidence.evidence_hmac is None
    ):
        return False
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        scope=scope,
    )
    if not hmac.compare_digest(evidence.exact_scope_digest, expected_scope_digest):
        return False
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        domain=_PROFIT_EVIDENCE_HMAC_DOMAIN,
        payload=evidence.hmac_payload(),
    )
    return hmac.compare_digest(evidence.evidence_hmac, expected_hmac)


def verify_profit_contribution_evidence(
    value: ProfitContributionEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ProfitContributionEvidence:
    """Re-validate and verify one sealed evidence envelope; raise on failure."""

    evidence = ProfitContributionEvidence.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, ProfitContributionEvidence)
        else value
    )
    if not evidence.is_attested:
        raise GrowthProfitValidationError("profit evidence carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    if not _evidence_attestation_matches(
        evidence,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    ):
        raise GrowthProfitValidationError(
            "profit evidence attestation failed verification"
        )
    return evidence


# ---------------------------------------------------------------------------
# Unit economics snapshot
# ---------------------------------------------------------------------------


class ProfitStalenessPolicy(_StrictModel):
    """Admission budget for evidence age and verification requirements."""

    max_evidence_age_hours: int = Field(default=720, ge=1, le=8_760)
    require_verified_evidence: bool = False


class BuildUnitEconomicsInput(_StrictModel):
    analysis_as_of: str
    economics_ref: PortableRef
    currency: CurrencyCode
    evidence: tuple[ProfitContributionEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_PROFIT_EVIDENCE,
    )
    staleness_policy: ProfitStalenessPolicy = Field(
        default_factory=ProfitStalenessPolicy
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("evidence", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_members(self) -> "BuildUnitEconomicsInput":
        refs = [item.observation_ref for item in self.evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence observation_refs must be unique")
        digests = [item.evidence_digest for item in self.evidence]
        if len(digests) != len(set(digests)):
            raise ValueError("evidence digests must be unique")
        return self


class LedgerMetricTotal(_StrictModel):
    metric: LedgerMetricName
    basis: ProfitBasis
    unit: Literal["count", "money"]
    value: Decimal = Field(ge=0)
    evidence_count: int = Field(ge=1)
    account_count: int = Field(ge=1)

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _quantized_by_unit(self) -> "LedgerMetricTotal":
        expected_unit = "money" if self.metric in _MONEY_METRICS else "count"
        if self.unit != expected_unit:
            raise ValueError("ledger total unit does not match the metric")
        quantum = _MONEY_QUANTUM if self.unit == "money" else Decimal("1")
        if self.value != self.value.quantize(quantum):
            raise ValueError("ledger totals must be quantized to the metric unit")
        return self


class LedgerMetricPresence(_StrictModel):
    metric: LedgerMetricName
    status: Literal["present", "unknown"]


class EconomicsComponent(_StrictModel):
    """One derived money fact with explicit completeness and provenance."""

    name: EconomicsComponentName
    unit: Literal["money", "ratio", "multiple"]
    value: Decimal
    complete: bool
    missing_inputs: tuple[LedgerMetricName, ...] = Field(default_factory=tuple)
    cross_basis: bool
    formula: ShortText

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @field_validator("missing_inputs", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _quantized_and_consistent(self) -> "EconomicsComponent":
        quantum = _RATE_QUANTUM if self.unit == "ratio" else _MONEY_QUANTUM
        if self.value != self.value.quantize(quantum):
            raise ValueError("component values must be quantized to their unit")
        if self.complete and self.missing_inputs:
            raise ValueError("complete components cannot list missing inputs")
        if not self.complete and not self.missing_inputs:
            raise ValueError("incomplete components must name their missing inputs")
        return self


class AdmittedProfitEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    provider: ProfitProvider
    basis: ProfitBasis
    connector_account_ref: OperationRef
    window_start: str
    window_end: str
    verified: bool

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class ExcludedProfitEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    reason: ProfitExclusionReason


class UnitEconomicsSnapshot(_StrictModel):
    """Sealed unit-economics state derived from admissible ledger evidence."""

    schema_id: Literal["lightbulb.growth_unit_economics.v1"] = Field(
        default=GROWTH_UNIT_ECONOMICS_SCHEMA,
        alias="schema",
    )
    economics_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode
    evidence_scope_status: EvidenceScopeStatus
    staleness_policy: ProfitStalenessPolicy
    metric_presence: tuple[LedgerMetricPresence, ...]
    ledger_totals: tuple[LedgerMetricTotal, ...] = Field(default_factory=tuple)
    components: tuple[EconomicsComponent, ...] = Field(default_factory=tuple)
    data_quality_notes: tuple[ShortText, ...] = Field(default_factory=tuple)
    admitted_evidence: tuple[AdmittedProfitEvidence, ...] = Field(default_factory=tuple)
    excluded_evidence: tuple[ExcludedProfitEvidence, ...] = Field(default_factory=tuple)
    economics_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    economics_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "metric_presence",
        "ledger_totals",
        "components",
        "data_quality_notes",
        "admitted_evidence",
        "excluded_evidence",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "UnitEconomicsSnapshot":
        if tuple(item.metric for item in self.metric_presence) != _LEDGER_METRICS:
            raise ValueError(
                "unit economics must report presence for every ledger metric "
                "in canonical order"
            )
        component_names = [component.name for component in self.components]
        if len(component_names) != len(set(component_names)):
            raise ValueError("components must be unique per name")
        canonical = [name for name in _COMPONENT_ORDER if name in set(component_names)]
        if component_names != canonical:
            raise ValueError("components must use canonical ordering")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.economics_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "unit economics attestation fields must be supplied together"
            )
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.economics_hmac is None
        ):
            raise ValueError(
                "verified unit economics require a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"economics_digest", "economics_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.economics_digest != "0" * 64 and self.economics_digest != expected:
            raise ValueError("economics_digest does not match the canonical payload")
        object.__setattr__(self, "economics_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"economics_hmac", "economics_digest"},
            exclude_none=True,
        )

    def component(self, name: EconomicsComponentName) -> EconomicsComponent | None:
        for component in self.components:
            if component.name == name:
                return component
        return None

    def total(self, metric: LedgerMetricName) -> LedgerMetricTotal | None:
        """The priority-picked total for one metric, or None if unknown."""

        priority = _METRIC_BASIS_PRIORITY.get(metric, _DEFAULT_BASIS_PRIORITY)
        by_basis = {(total.metric, total.basis): total for total in self.ledger_totals}
        for basis in priority:
            found = by_basis.get((metric, basis))
            if found is not None:
                return found
        return None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _classify_profit_evidence(
    evidence: ProfitContributionEvidence,
    *,
    analysis_at: datetime,
    currency: str,
    policy: ProfitStalenessPolicy,
    scope: DynamicWorkflowScope | None,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[bool, ProfitExclusionReason | None]:
    """Return (verified, exclusion_reason) for one envelope.

    Attested evidence that fails verification raises: tampering is an error,
    never a silent exclusion. Exclusion precedence is currency, then future,
    then stale, then unverified — the first structural defect wins
    deterministically.
    """

    verified = False
    if evidence.is_attested and scope_keyring is not None and scope is not None:
        if not _evidence_attestation_matches(
            evidence,
            scope=scope,
            scope_keyring=scope_keyring,
        ):
            raise GrowthProfitValidationError(
                "profit evidence attestation failed verification"
            )
        verified = True
    if evidence.currency != currency:
        return verified, "currency_mismatch"
    observed_at = _parse_timestamp(evidence.observed_at)
    window_end = _parse_timestamp(evidence.window_end)
    if observed_at > analysis_at or window_end > analysis_at:
        return verified, "future_observation"
    age_hours = (analysis_at - window_end).total_seconds() / 3_600
    if age_hours > policy.max_evidence_age_hours:
        return verified, "stale_observation"
    if policy.require_verified_evidence and not verified:
        return verified, "unverified_evidence"
    return verified, None


def _reject_window_overlaps(admitted: list[ProfitContributionEvidence]) -> None:
    by_source: dict[tuple[str, str], list[ProfitContributionEvidence]] = {}
    for evidence in admitted:
        key = (evidence.connector_account_ref, evidence.source_capability)
        by_source.setdefault(key, []).append(evidence)
    for group in by_source.values():
        ordered = sorted(
            group,
            key=lambda item: (
                _parse_timestamp(item.window_start),
                _parse_timestamp(item.window_end),
            ),
        )
        for earlier, later in zip(ordered, ordered[1:]):
            earlier_start = _parse_timestamp(earlier.window_start)
            earlier_end = _parse_timestamp(earlier.window_end)
            later_start = _parse_timestamp(later.window_start)
            # Windows are half-open [start, end); see growth_funnel for the
            # zero-width reasoning this mirrors.
            if later_start < earlier_end or (
                earlier_start == earlier_end and earlier_start == later_start
            ):
                raise GrowthProfitValidationError(
                    "admitted evidence windows overlap for one account and "
                    "capability; aggregate windows upstream to avoid double "
                    "counting"
                )


def _pick_total(
    metric: str,
    totals: Mapping[tuple[str, str], Decimal],
) -> tuple[ProfitBasis, Decimal] | None:
    priority = _METRIC_BASIS_PRIORITY.get(metric, _DEFAULT_BASIS_PRIORITY)
    for basis in priority:
        value = totals.get((metric, basis))
        if value is not None:
            return basis, value
    return None


def _derive_components(
    totals: Mapping[tuple[str, str], Decimal],
) -> tuple[list[EconomicsComponent], list[str]]:
    """Deterministically derive money facts from picked ledger totals."""

    picks: dict[str, tuple[ProfitBasis, Decimal]] = {}
    for metric in _LEDGER_METRICS:
        picked = _pick_total(metric, totals)
        if picked is not None:
            picks[metric] = picked

    components: list[EconomicsComponent] = []
    notes: list[str] = []

    def _bases(*metrics: str) -> set[str]:
        return {picks[m][0] for m in metrics if m in picks}

    def _value(metric: str) -> Decimal | None:
        picked = picks.get(metric)
        return picked[1] if picked is not None else None

    gross = _value("gross_sales")
    net_revenue: EconomicsComponent | None = None
    if gross is not None:
        missing = tuple(m for m in ("discounts", "refunds") if m not in picks)
        value = gross
        for metric in ("discounts", "refunds"):
            deduction = _value(metric)
            if deduction is not None:
                value -= deduction
        net_revenue = EconomicsComponent(
            name="net_revenue",
            unit="money",
            value=_quantized_money(value),
            complete=not missing,
            missing_inputs=missing,
            cross_basis=len(_bases("gross_sales", "discounts", "refunds")) > 1,
            formula="gross_sales - discounts - refunds",
        )
        components.append(net_revenue)

    cost_inputs = ("cogs", "fulfillment_cost", "payment_fees", "service_cost")
    known_costs = [m for m in cost_inputs if m in picks]
    variable_costs: EconomicsComponent | None = None
    if known_costs:
        missing = tuple(m for m in cost_inputs if m not in picks)
        value = sum((picks[m][1] for m in known_costs), Decimal("0"))
        variable_costs = EconomicsComponent(
            name="variable_cost_total",
            unit="money",
            value=_quantized_money(value),
            complete=not missing,
            missing_inputs=missing,
            cross_basis=len(_bases(*cost_inputs)) > 1,
            formula="cogs + fulfillment_cost + payment_fees + service_cost",
        )
        components.append(variable_costs)

    contribution: EconomicsComponent | None = None
    if net_revenue is not None and variable_costs is not None:
        missing = tuple(
            dict.fromkeys((*net_revenue.missing_inputs, *variable_costs.missing_inputs))
        )
        contribution = EconomicsComponent(
            name="contribution_profit",
            unit="money",
            value=_quantized_money(net_revenue.value - variable_costs.value),
            complete=net_revenue.complete and variable_costs.complete,
            missing_inputs=missing,
            cross_basis=net_revenue.cross_basis or variable_costs.cross_basis,
            formula="net_revenue - variable_cost_total (acquisition_cost excluded)",
        )
        components.append(contribution)

    margin: EconomicsComponent | None = None
    if contribution is not None and net_revenue is not None and (net_revenue.value > 0):
        margin = EconomicsComponent(
            name="contribution_margin",
            unit="ratio",
            value=_quantized_ratio(contribution.value / net_revenue.value),
            complete=contribution.complete,
            missing_inputs=contribution.missing_inputs,
            cross_basis=contribution.cross_basis,
            formula="contribution_profit / net_revenue",
        )
        components.append(margin)

    orders = _value("orders")
    if gross is not None and orders is not None and orders > 0:
        components.append(
            EconomicsComponent(
                name="average_order_value",
                unit="money",
                value=_quantized_money(gross / orders),
                complete=True,
                missing_inputs=(),
                cross_basis=len(_bases("gross_sales", "orders")) > 1,
                formula="gross_sales / orders",
            )
        )

    per_order: EconomicsComponent | None = None
    if contribution is not None and orders is not None and orders > 0:
        per_order = EconomicsComponent(
            name="contribution_per_order",
            unit="money",
            value=_quantized_money(contribution.value / orders),
            complete=contribution.complete,
            missing_inputs=contribution.missing_inputs,
            cross_basis=contribution.cross_basis or len(_bases("orders")) > 1,
            formula="contribution_profit / orders",
        )
        components.append(per_order)

    acquisition = _value("acquisition_cost")
    new_customers = _value("new_customers")
    cac: EconomicsComponent | None = None
    if acquisition is not None and new_customers is not None and new_customers > 0:
        cac = EconomicsComponent(
            name="customer_acquisition_cost",
            unit="money",
            value=_quantized_money(acquisition / new_customers),
            complete=True,
            missing_inputs=(),
            cross_basis=len(_bases("acquisition_cost", "new_customers")) > 1,
            formula="acquisition_cost / new_customers",
        )
        components.append(cac)

    if margin is not None and margin.value > 0:
        components.append(
            EconomicsComponent(
                name="breakeven_roas",
                unit="multiple",
                value=_quantized_money(Decimal("1") / margin.value),
                complete=margin.complete,
                missing_inputs=margin.missing_inputs,
                cross_basis=margin.cross_basis,
                formula="1 / contribution_margin",
            )
        )

    if cac is not None and per_order is not None and per_order.value > 0:
        components.append(
            EconomicsComponent(
                name="cac_payback_orders",
                unit="multiple",
                value=_quantized_money(cac.value / per_order.value),
                complete=cac.complete and per_order.complete,
                missing_inputs=per_order.missing_inputs,
                cross_basis=cac.cross_basis or per_order.cross_basis,
                formula="customer_acquisition_cost / contribution_per_order",
            )
        )

    for component in components:
        if component.cross_basis:
            notes.append(
                f"component {component.name} mixes measurement bases; treat "
                "small differences with caution"
            )
        if not component.complete:
            notes.append(
                f"component {component.name} is incomplete; unknown inputs: "
                + ", ".join(component.missing_inputs)
            )
    return components, notes


def build_unit_economics(
    inputs: BuildUnitEconomicsInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> UnitEconomicsSnapshot:
    """Compute one sealed unit-economics snapshot from admissible evidence.

    With ``scope`` and ``scope_keyring`` the snapshot verifies every attested
    envelope, reports ``host_hmac_verified`` only when all admitted evidence
    verified, and seals the snapshot itself. Without them it is
    honest-but-unverified.
    """

    parsed = (
        inputs
        if isinstance(inputs, BuildUnitEconomicsInput)
        else BuildUnitEconomicsInput.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise GrowthProfitValidationError(
            "verified snapshots require both scope and scope_keyring"
        )
    workflow_scope: DynamicWorkflowScope | None = None
    if scope is not None:
        workflow_scope = _workflow_scope(scope)
    analysis_at = _parse_timestamp(parsed.analysis_as_of)

    admitted: list[ProfitContributionEvidence] = []
    admitted_verified: dict[str, bool] = {}
    excluded: list[ExcludedProfitEvidence] = []
    for evidence in parsed.evidence:
        verified, reason = _classify_profit_evidence(
            evidence,
            analysis_at=analysis_at,
            currency=parsed.currency,
            policy=parsed.staleness_policy,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if reason is not None:
            excluded.append(
                ExcludedProfitEvidence(
                    observation_ref=evidence.observation_ref,
                    evidence_digest=evidence.evidence_digest,
                    reason=reason,
                )
            )
            continue
        admitted.append(evidence)
        admitted_verified[evidence.observation_ref] = verified
    _reject_window_overlaps(admitted)

    totals: dict[tuple[str, str], Decimal] = {}
    accounts: dict[tuple[str, str], set[str]] = {}
    counts: dict[tuple[str, str], int] = {}
    for evidence in admitted:
        basis = evidence.basis
        for metric, value in evidence.metrics.model_dump(mode="python").items():
            if value is None:
                continue
            amount = value if isinstance(value, Decimal) else Decimal(int(value))
            key = (metric, basis)
            totals[key] = totals.get(key, Decimal("0")) + amount
            accounts.setdefault(key, set()).add(evidence.connector_account_ref)
            counts[key] = counts.get(key, 0) + 1

    ledger_totals = tuple(
        LedgerMetricTotal(
            metric=metric,
            basis=basis,
            unit="money" if metric in _MONEY_METRICS else "count",
            value=(
                value.quantize(_MONEY_QUANTUM)
                if metric in _MONEY_METRICS
                else value.quantize(Decimal("1"))
            ),
            evidence_count=counts[(metric, basis)],
            account_count=len(accounts[(metric, basis)]),
        )
        for (metric, basis), value in sorted(totals.items())
    )
    present_metrics = {metric for (metric, _) in totals}
    metric_presence = tuple(
        LedgerMetricPresence(
            metric=metric,
            status="present" if metric in present_metrics else "unknown",
        )
        for metric in _LEDGER_METRICS
    )

    components, notes = _derive_components(totals)

    all_verified = bool(admitted) and all(
        admitted_verified[evidence.observation_ref] for evidence in admitted
    )
    evidence_scope_status: EvidenceScopeStatus = (
        "host_hmac_verified"
        if scope_keyring is not None and all_verified
        else "caller_supplied_unverified"
    )

    snapshot_kwargs: dict[str, Any] = {
        "economics_ref": parsed.economics_ref,
        "analysis_as_of": parsed.analysis_as_of,
        "currency": parsed.currency,
        "evidence_scope_status": evidence_scope_status,
        "staleness_policy": parsed.staleness_policy,
        "metric_presence": metric_presence,
        "ledger_totals": ledger_totals,
        "components": tuple(components),
        "data_quality_notes": tuple(notes),
        "admitted_evidence": tuple(
            AdmittedProfitEvidence(
                observation_ref=evidence.observation_ref,
                evidence_digest=evidence.evidence_digest,
                provider=evidence.provider,
                basis=evidence.basis,
                connector_account_ref=evidence.connector_account_ref,
                window_start=evidence.window_start,
                window_end=evidence.window_end,
                verified=admitted_verified[evidence.observation_ref],
            )
            for evidence in sorted(admitted, key=lambda item: item.observation_ref)
        ),
        "excluded_evidence": tuple(
            sorted(excluded, key=lambda item: item.observation_ref)
        ),
    }

    if scope_keyring is None or workflow_scope is None:
        return UnitEconomicsSnapshot(**snapshot_kwargs)

    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=key_id,
        scope=workflow_scope,
    )
    draft = UnitEconomicsSnapshot(
        **snapshot_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        economics_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_UNIT_ECONOMICS_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"economics_digest"},
        exclude_none=True,
    )
    sealed["economics_hmac"] = signature
    return UnitEconomicsSnapshot.model_validate(sealed)


def verify_unit_economics_snapshot(
    value: UnitEconomicsSnapshot | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> UnitEconomicsSnapshot:
    """Re-validate and verify one sealed economics snapshot; raise on failure."""

    snapshot = UnitEconomicsSnapshot.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, UnitEconomicsSnapshot)
        else value
    )
    if (
        snapshot.receipt_key_id is None
        or snapshot.exact_scope_digest is None
        or snapshot.economics_hmac is None
    ):
        raise GrowthProfitValidationError("unit economics carry no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(snapshot.exact_scope_digest, expected_scope_digest):
        raise GrowthProfitValidationError(
            "unit economics attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        domain=_UNIT_ECONOMICS_HMAC_DOMAIN,
        payload=snapshot.hmac_payload(),
    )
    if not hmac.compare_digest(snapshot.economics_hmac, expected_hmac):
        raise GrowthProfitValidationError(
            "unit economics attestation failed verification"
        )
    return snapshot


# ---------------------------------------------------------------------------
# Price elasticity (from causal readouts only)
# ---------------------------------------------------------------------------


class PriceElasticityEstimate(_StrictModel):
    """Arc elasticity derived from a sealed price plan and its causal readout.

    Re-derivable digest-pinned advice, not a sealed artifact: every number
    here recomputes from the sealed plan, design, and readout it names.
    """

    schema_id: Literal["lightbulb.growth_price_elasticity.v1"] = Field(
        default=GROWTH_PRICE_ELASTICITY_SCHEMA,
        alias="schema",
    )
    estimate_ref: PortableRef
    method: Literal["arc_midpoint_revenue_per_session"]
    price_change_ratio: Decimal = Field(
        gt=Decimal("-1"), lt=Decimal("1"), multiple_of=_RATE_QUANTUM
    )
    control_revenue_per_session: Decimal = Field(gt=0, multiple_of=_RATE_QUANTUM)
    treatment_revenue_per_session: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    elasticity: Decimal = Field(multiple_of=_RATE_QUANTUM)
    ci_low: Decimal = Field(multiple_of=_RATE_QUANTUM)
    ci_high: Decimal = Field(multiple_of=_RATE_QUANTUM)
    readout_verdict: ShortText
    plan_digest: Sha256Digest
    design_digest: Sha256Digest
    readout_digest: Sha256Digest
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    estimate_digest: Sha256Digest = "0" * 64

    @field_validator(
        "price_change_ratio",
        "control_revenue_per_session",
        "treatment_revenue_per_session",
        "elasticity",
        "ci_low",
        "ci_high",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "PriceElasticityEstimate":
        if self.price_change_ratio == 0:
            raise ValueError("elasticity requires a nonzero price change")
        if not (self.ci_low <= self.elasticity <= self.ci_high):
            raise ValueError("elasticity must fall inside its interval")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"estimate_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.estimate_digest != "0" * 64 and self.estimate_digest != expected:
            raise ValueError("estimate_digest does not match the canonical payload")
        object.__setattr__(self, "estimate_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _arc_elasticity(
    control_rps: Decimal,
    treatment_rps: Decimal,
    price_change_ratio: Decimal,
) -> Decimal:
    """Midpoint arc elasticity from revenue-per-session under a price change.

    Quantity is proxied by revenue at constant catalog mix: q ∝ rps / price,
    so the treatment quantity index is rps_t / (1 + x) against a control
    index of rps_c.
    """

    quantity_control = control_rps
    quantity_treatment = treatment_rps / (Decimal("1") + price_change_ratio)
    quantity_sum = quantity_control + quantity_treatment
    if quantity_sum <= 0:
        raise GrowthProfitValidationError(
            "arc elasticity requires positive combined quantity"
        )
    numerator = (quantity_treatment - quantity_control) * (
        Decimal("2") + price_change_ratio
    )
    denominator = quantity_sum * price_change_ratio
    return _quantized_ratio(numerator / denominator)


def estimate_price_elasticity(
    plan: "PricePlan | Mapping[str, Any]",
    design: GrowthExperimentDesign | Mapping[str, Any],
    readout: GrowthExperimentReadout | Mapping[str, Any],
    *,
    estimate_ref: str,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> PriceElasticityEstimate:
    """Derive the price elasticity a causal price experiment actually proved.

    Hard failures: unsealed or tampered plan, design, or readout; a readout
    bound to a different design; a design that does not match the plan's
    embedded preregistration field-for-field; a non-causal readout; or a
    readout without effect statistics.
    """

    verified_plan = verify_price_plan(plan, scope=scope, scope_keyring=scope_keyring)
    verified_design = verify_growth_experiment_design(
        design, scope=scope, scope_keyring=scope_keyring
    )
    verified_readout = verify_growth_experiment_readout(
        readout, scope=scope, scope_keyring=scope_keyring
    )
    if verified_readout.design_digest != verified_design.design_digest:
        raise GrowthProfitValidationError("the readout is bound to a different design")
    brief_payload = verified_plan.operation.experiment_input.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    design_payload = verified_design.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    mismatched = [
        field
        for field, value in brief_payload.items()
        if design_payload.get(field) != value
    ]
    if mismatched:
        raise GrowthProfitValidationError(
            "the design does not match the plan's embedded preregistration; "
            "mismatched fields: " + ", ".join(sorted(mismatched))
        )
    if not verified_readout.causal:
        raise GrowthProfitValidationError(
            "elasticity requires a causal readout; this readout's verdict is "
            f"{verified_readout.verdict}"
        )
    if verified_readout.metric_name != "revenue_per_session":
        raise GrowthProfitValidationError(
            "elasticity is derived from revenue_per_session readouts only"
        )
    control_arm = next(arm for arm in verified_readout.arms if arm.is_control)
    treatment_arm = next(arm for arm in verified_readout.arms if not arm.is_control)
    if (
        control_arm.sample_mean is None
        or treatment_arm.sample_mean is None
        or verified_readout.ci_low is None
        or verified_readout.ci_high is None
    ):
        raise GrowthProfitValidationError(
            "the readout carries no effect statistics to derive elasticity from"
        )
    control_rps = control_arm.sample_mean
    if control_rps <= 0:
        raise GrowthProfitValidationError(
            "elasticity requires a positive control revenue per session"
        )
    ratio = verified_plan.operation.price_change_ratio
    treatment_rps = treatment_arm.sample_mean
    point = _arc_elasticity(control_rps, treatment_rps, ratio)
    bound_a = _arc_elasticity(
        control_rps,
        max(control_rps + verified_readout.ci_low, Decimal("0")),
        ratio,
    )
    bound_b = _arc_elasticity(
        control_rps,
        max(control_rps + verified_readout.ci_high, Decimal("0")),
        ratio,
    )
    ci_low, ci_high = sorted((bound_a, bound_b))
    ci_low = min(ci_low, point)
    ci_high = max(ci_high, point)
    notes = [
        "interval propagated from the readout's effect CI with the control "
        "mean treated as fixed",
        "quantity proxied by revenue_per_session / price at constant catalog mix",
    ]
    if verified_readout.verdict == "inconclusive":
        notes.append(
            "readout was inconclusive: the interval includes elasticities "
            "consistent with no revenue change"
        )
    return PriceElasticityEstimate(
        estimate_ref=estimate_ref,
        method="arc_midpoint_revenue_per_session",
        price_change_ratio=ratio,
        control_revenue_per_session=_quantized_ratio(control_rps),
        treatment_revenue_per_session=_quantized_ratio(treatment_rps),
        elasticity=point,
        ci_low=ci_low,
        ci_high=ci_high,
        readout_verdict=verified_readout.verdict,
        plan_digest=verified_plan.plan_digest,
        design_digest=verified_design.design_digest,
        readout_digest=verified_readout.readout_digest,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Price move planning
# ---------------------------------------------------------------------------


class PriceGuardrailPolicy(_StrictModel):
    """The caller-owned commercial constraints every price move must honor."""

    minimum_contribution_margin: Decimal = Field(ge=0, lt=1, multiple_of=_RATE_QUANTUM)
    max_price_increase_ratio: Decimal = Field(
        default=Decimal("0.100000"), gt=0, le=Decimal("0.5"), multiple_of=_RATE_QUANTUM
    )
    max_price_decrease_ratio: Decimal = Field(
        default=Decimal("0.100000"), gt=0, le=Decimal("0.5"), multiple_of=_RATE_QUANTUM
    )
    probe_ratio: Decimal = Field(
        default=Decimal("0.050000"),
        gt=0,
        le=Decimal("0.25"),
        multiple_of=_RATE_QUANTUM,
    )

    @field_validator(
        "minimum_contribution_margin",
        "max_price_increase_ratio",
        "max_price_decrease_ratio",
        "probe_ratio",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _probe_inside_bounds(self) -> "PriceGuardrailPolicy":
        if self.probe_ratio > self.max_price_increase_ratio or (
            self.probe_ratio > self.max_price_decrease_ratio
        ):
            raise ValueError("probe_ratio must fall inside both price-change bounds")
        return self


class PriceExperimentSettings(_StrictModel):
    """Preregistration parameters for the price test a plan ships with."""

    design_ref: PortableRef
    assignment_unit: AssignmentUnit
    baseline_value: Decimal | None = Field(
        default=None, gt=0, multiple_of=_RATE_QUANTUM
    )
    baseline_standard_deviation: Decimal = Field(gt=0, multiple_of=_RATE_QUANTUM)
    minimum_detectable_effect: Decimal = Field(gt=0, multiple_of=_RATE_QUANTUM)
    alpha: Decimal = Field(
        default=Decimal("0.050000"),
        ge=Decimal("0.001"),
        le=Decimal("0.2"),
        multiple_of=_RATE_QUANTUM,
    )
    power: Decimal = Field(
        default=Decimal("0.800000"),
        ge=Decimal("0.5"),
        le=Decimal("0.99"),
        multiple_of=_RATE_QUANTUM,
    )
    exposure_start: str
    readout_horizon: str

    @field_validator(
        "baseline_value",
        "baseline_standard_deviation",
        "minimum_detectable_effect",
        "alpha",
        "power",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("exposure_start", "readout_horizon")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class PricePlanBrief(_StrictModel):
    plan_ref: PortableRef
    planned_at: str
    objective: PriceObjective
    direction: PriceDirection | None = None
    unit_economics: UnitEconomicsSnapshot
    policy: PriceGuardrailPolicy
    experiment: PriceExperimentSettings
    funnel_snapshot: GrowthFunnelSnapshot | None = None
    elasticity: PriceElasticityEstimate | None = None
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_REVIEW_LEARNINGS
    )

    @field_validator("planned_at")
    @classmethod
    def _valid_planned_at(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("learnings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _objective_shape(self) -> "PricePlanBrief":
        if self.objective == "test_elasticity" and self.direction is None:
            raise ValueError(
                "test_elasticity requires an explicit direction for the probe"
            )
        if self.objective != "test_elasticity" and self.direction is not None:
            raise ValueError(
                "direction is derived from economics for this objective; omit it"
            )
        if self.objective == "grow_contribution" and self.elasticity is None:
            raise ValueError(
                "grow_contribution requires a price elasticity estimate; run "
                "test_elasticity first and derive one with "
                "estimate_price_elasticity"
            )
        if self.funnel_snapshot is not None and (
            self.experiment.baseline_value is not None
        ):
            raise ValueError(
                "provide either funnel_snapshot or experiment.baseline_value, not both"
            )
        if self.funnel_snapshot is None and self.experiment.baseline_value is None:
            raise ValueError(
                "the price test baseline needs a funnel_snapshot with "
                "revenue_per_session or an explicit experiment.baseline_value"
            )
        return self


class PriceMoveOperation(_StrictModel):
    """The executable content of a price move, bound to its approval unit."""

    operation_ref: PortableRef
    currency: CurrencyCode
    direction: PriceDirection
    price_change_ratio: Decimal = Field(
        gt=Decimal("-1"), lt=Decimal("1"), multiple_of=_RATE_QUANTUM
    )
    economics_digest: Sha256Digest
    experiment_input: DesignGrowthExperimentInput
    operation_digest: Sha256Digest = "0" * 64
    approval_unit: str = Field(min_length=1, max_length=200)

    @field_validator("price_change_ratio", mode="before")
    @classmethod
    def _ratio_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _content_bound_approval(self) -> "PriceMoveOperation":
        if self.price_change_ratio == 0:
            raise ValueError("a price move requires a nonzero change ratio")
        if (self.price_change_ratio > 0) != (self.direction == "increase"):
            raise ValueError("direction does not match the price change sign")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"operation_digest", "approval_unit"},
            exclude_none=True,
        )
        expected_digest = _stable_digest(payload)
        if self.operation_digest != "0" * 64 and (
            self.operation_digest != expected_digest
        ):
            raise ValueError("operation_digest does not match the canonical payload")
        object.__setattr__(self, "operation_digest", expected_digest)
        expected_unit = f"approval_price_move_{self.operation_ref}_{expected_digest}"
        sentinel_unit = f"approval_price_move_{self.operation_ref}_{'0' * 64}"
        if self.approval_unit == sentinel_unit:
            object.__setattr__(self, "approval_unit", expected_unit)
        elif self.approval_unit != expected_unit:
            raise ValueError(
                "approval_unit must bind the operation ref to its content digest"
            )
        return self


class PriceProjection(_StrictModel):
    """One labeled projection; the assumption is part of the artifact."""

    name: Literal[
        "constant_volume_margin",
        "constant_volume_contribution_delta",
        "constant_elasticity_contribution_delta",
        "constant_elasticity_contribution_delta_low",
        "constant_elasticity_contribution_delta_high",
        "required_sample_per_arm",
    ]
    unit: Literal["money", "ratio", "count"]
    value: Decimal
    assumption: ShortText

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _quantized_by_unit(self) -> "PriceProjection":
        quantum = {
            "money": _MONEY_QUANTUM,
            "ratio": _RATE_QUANTUM,
            "count": Decimal("1"),
        }[self.unit]
        if self.value != self.value.quantize(quantum):
            raise ValueError("projection values must be quantized to their unit")
        return self


class ProfitInformedBy(_StrictModel):
    economics_digest: Sha256Digest
    funnel_digest: Sha256Digest | None = None
    elasticity_estimate_digest: Sha256Digest | None = None
    elasticity_readout_digest: Sha256Digest | None = None
    learning_digests: tuple[Sha256Digest, ...] = Field(
        default_factory=tuple, max_length=_MAX_REVIEW_LEARNINGS
    )

    @field_validator("learning_digests", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class PricePlan(_StrictModel):
    """A margin-guarded, approval-ready price move that ships as an experiment."""

    schema_id: Literal["lightbulb.growth_price_plan.v1"] = Field(
        default=GROWTH_PRICE_PLAN_SCHEMA,
        alias="schema",
    )
    plan_ref: PortableRef
    planned_at: str
    objective: PriceObjective
    currency: CurrencyCode
    evidence_scope_status: EvidenceScopeStatus
    reference_quality: PriceReferenceQuality
    operation: PriceMoveOperation
    projections: tuple[PriceProjection, ...] = Field(default_factory=tuple)
    informed_by: ProfitInformedBy
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    dispatchable_by_planner: Literal[False] = False
    plan_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    plan_hmac: Sha256Digest | None = None

    @field_validator("planned_at")
    @classmethod
    def _valid_planned_at(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("projections", "notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "PricePlan":
        if self.operation.currency != self.currency:
            raise ValueError("the operation currency must match the plan currency")
        if self.operation.economics_digest != self.informed_by.economics_digest:
            raise ValueError(
                "the operation must bind the economics the plan was informed by"
            )
        projection_names = [projection.name for projection in self.projections]
        if len(projection_names) != len(set(projection_names)):
            raise ValueError("projections must be unique per name")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.plan_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError("price plan attestation fields must be supplied together")
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.plan_hmac is None
        ):
            raise ValueError("verified price plans require a complete host attestation")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_digest", "plan_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.plan_digest != "0" * 64 and self.plan_digest != expected:
            raise ValueError("plan_digest does not match the canonical payload")
        object.__setattr__(self, "plan_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_hmac", "plan_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _required_component(
    economics: UnitEconomicsSnapshot,
    name: EconomicsComponentName,
    *,
    require_complete: bool,
) -> EconomicsComponent:
    component = economics.component(name)
    if component is None:
        raise GrowthProfitValidationError(
            f"the price planner needs the {name} component; supply ledger "
            "evidence covering gross_sales, discounts, refunds, and the "
            "variable cost metrics, then rebuild unit economics"
        )
    if require_complete and not component.complete:
        raise GrowthProfitValidationError(
            f"the {name} component is incomplete (unknown inputs: "
            + ", ".join(component.missing_inputs)
            + "); collect the missing ledger metrics before planning this move"
        )
    return component


def _constant_volume_margin(
    net_revenue: Decimal,
    variable_costs: Decimal,
    ratio: Decimal,
) -> Decimal:
    projected_revenue = net_revenue * (Decimal("1") + ratio)
    if projected_revenue <= 0:
        raise GrowthProfitValidationError(
            "the projected net revenue is not positive at this price change"
        )
    return _quantized_ratio((projected_revenue - variable_costs) / projected_revenue)


def _minimum_ratio_for_floor(
    net_revenue: Decimal,
    variable_costs: Decimal,
    floor: Decimal,
) -> Decimal:
    """The smallest price-change ratio whose constant-volume margin meets floor."""

    denominator = net_revenue * (Decimal("1") - floor)
    if denominator <= 0:
        raise GrowthProfitValidationError(
            "the margin floor is unreachable at any price with these economics"
        )
    needed = variable_costs / denominator - Decimal("1")
    return needed.quantize(_RATE_QUANTUM, rounding=ROUND_CEILING)


def _elasticity_contribution_delta(
    net_revenue: Decimal,
    variable_costs: Decimal,
    ratio: Decimal,
    elasticity: Decimal,
) -> Decimal:
    """Contribution delta under constant elasticity; costs scale with volume."""

    quantity_ratio = Decimal(str(float(Decimal("1") + ratio) ** float(elasticity)))
    projected = (
        net_revenue * (Decimal("1") + ratio) * quantity_ratio
        - variable_costs * quantity_ratio
    )
    return _quantized_money(projected - (net_revenue - variable_costs))


def _resolve_price_baseline(
    brief: PricePlanBrief,
    verified_funnel: GrowthFunnelSnapshot | None,
) -> tuple[str, Decimal, str | None]:
    """Return (baseline_source, baseline_value, baseline_evidence_digest)."""

    snapshot = (
        verified_funnel if verified_funnel is not None else (brief.funnel_snapshot)
    )
    if snapshot is not None:
        for derived in snapshot.derived_values:
            if derived.name == "revenue_per_session":
                return (
                    "funnel_snapshot",
                    _quantized_ratio(derived.value),
                    snapshot.funnel_digest,
                )
        raise GrowthProfitValidationError(
            "the funnel snapshot carries no revenue_per_session derived value; "
            "admit revenue and sessions evidence or supply "
            "experiment.baseline_value instead"
        )
    assert brief.experiment.baseline_value is not None  # validated on the brief
    return "manual_estimate", brief.experiment.baseline_value, None


def _decide_price_move(
    brief: PricePlanBrief,
    margin: EconomicsComponent,
    net_revenue: EconomicsComponent,
    variable_costs: EconomicsComponent,
) -> tuple[PriceDirection, Decimal, PriceReferenceQuality, list[str]]:
    """Deterministically pick (direction, ratio, reference_quality, notes)."""

    policy = brief.policy
    floor = policy.minimum_contribution_margin
    notes: list[str] = []

    if brief.objective == "protect_margin":
        if margin.value >= floor:
            raise GrowthProfitValidationError(
                "contribution margin already meets the floor; use "
                "test_elasticity or grow_contribution instead"
            )
        needed = _minimum_ratio_for_floor(
            net_revenue.value, variable_costs.value, floor
        )
        if needed > policy.max_price_increase_ratio:
            raise GrowthProfitValidationError(
                f"reaching the margin floor needs a {needed} price increase, "
                f"above the {policy.max_price_increase_ratio} cap; price alone "
                "cannot close this gap — reduce variable costs or raise the cap"
            )
        notes.append(
            "increase sized to exactly reach the margin floor at constant volume"
        )
        return "increase", needed, "default_heuristic", notes

    if brief.objective == "test_elasticity":
        assert brief.direction is not None  # validated on the brief
        ratio = (
            policy.probe_ratio if brief.direction == "increase" else -policy.probe_ratio
        )
        notes.append(
            "probe sized by policy.probe_ratio; the goal is an elasticity "
            "estimate, not immediate contribution"
        )
        return brief.direction, ratio, "default_heuristic", notes

    # grow_contribution: grid search under the elasticity estimate.
    assert brief.elasticity is not None  # validated on the brief
    elasticity = brief.elasticity.elasticity
    best: tuple[Decimal, Decimal] | None = None
    step = _RATIO_STEP
    candidate = -policy.max_price_decrease_ratio
    while candidate <= policy.max_price_increase_ratio:
        ratio = candidate.quantize(_RATE_QUANTUM)
        candidate += step
        if ratio == 0:
            continue
        if ratio < 0:
            projected_margin = _constant_volume_margin(
                net_revenue.value, variable_costs.value, ratio
            )
            if projected_margin < floor:
                continue
        delta = _elasticity_contribution_delta(
            net_revenue.value, variable_costs.value, ratio, elasticity
        )
        if (
            best is None
            or delta > best[1]
            or (delta == best[1] and (abs(ratio), -ratio) < (abs(best[0]), -best[0]))
        ):
            best = (ratio, delta)
    if best is None or best[1] <= 0:
        raise GrowthProfitValidationError(
            "no price move inside the policy bounds improves contribution "
            f"under elasticity {elasticity}; widen the bounds or improve the "
            "cost structure instead"
        )
    ratio = best[0]
    notes.append(
        "move chosen by grid search under the supplied elasticity estimate; "
        "variable costs assumed to scale with volume"
    )
    return (
        ("increase" if ratio > 0 else "decrease"),
        ratio,
        ("experimental_estimate"),
        notes,
    )


def plan_price_move(
    inputs: PricePlanBrief | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> PricePlan:
    """Plan one margin-guarded price move that ships as a preregistered test.

    Planning only: the plan is structurally ``dispatchable_by_planner=False``
    and every executable byte is bound into a content-digest approval unit.
    The margin floor is enforced here, not advised: a decrease whose
    constant-volume projection breaches ``minimum_contribution_margin`` is
    refused with the exact feasible bound.
    """

    brief = (
        inputs
        if isinstance(inputs, PricePlanBrief)
        else PricePlanBrief.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise GrowthProfitValidationError(
            "verified planning requires both scope and scope_keyring"
        )
    workflow_scope: DynamicWorkflowScope | None = None
    verified_funnel: GrowthFunnelSnapshot | None = None
    if scope_keyring is not None and scope is not None:
        workflow_scope = _workflow_scope(scope)
        economics = verify_unit_economics_snapshot(
            brief.unit_economics, scope=workflow_scope, scope_keyring=scope_keyring
        )
        if brief.funnel_snapshot is not None:
            verified_funnel = verify_growth_funnel_snapshot(
                brief.funnel_snapshot,
                scope=workflow_scope,
                scope_keyring=scope_keyring,
            )
        for entry in brief.learnings:
            verify_growth_learning_entry(
                entry, scope=workflow_scope, scope_keyring=scope_keyring
            )
        status: EvidenceScopeStatus = economics.evidence_scope_status
    else:
        economics = brief.unit_economics
        status = "caller_supplied_unverified"

    if economics.currency != economics.currency.upper():
        raise GrowthProfitValidationError("economics currency must be ISO-4217")
    funnel_for_currency = verified_funnel or brief.funnel_snapshot
    if (
        funnel_for_currency is not None
        and funnel_for_currency.currency is not None
        and funnel_for_currency.currency != economics.currency
    ):
        raise GrowthProfitValidationError(
            "the funnel and unit economics currencies differ; a price plan "
            "cannot combine them without governed FX evidence"
        )

    margin = _required_component(
        economics, "contribution_margin", require_complete=True
    )
    net_revenue = _required_component(economics, "net_revenue", require_complete=True)
    variable_costs = _required_component(
        economics, "variable_cost_total", require_complete=True
    )

    direction, ratio, reference_quality, notes = _decide_price_move(
        brief, margin, net_revenue, variable_costs
    )

    # The margin floor is law for every decrease, whatever objective chose it.
    if ratio < 0:
        projected_margin = _constant_volume_margin(
            net_revenue.value, variable_costs.value, ratio
        )
        if projected_margin < brief.policy.minimum_contribution_margin:
            feasible = _minimum_ratio_for_floor(
                net_revenue.value,
                variable_costs.value,
                brief.policy.minimum_contribution_margin,
            )
            raise GrowthProfitValidationError(
                f"a {ratio} price change projects margin {projected_margin}, "
                f"below the {brief.policy.minimum_contribution_margin} floor; "
                f"the deepest feasible decrease is {feasible}"
            )

    baseline_source, baseline_value, baseline_digest = _resolve_price_baseline(
        brief, verified_funnel
    )

    percent = _quantized_ratio(ratio * 100)
    hypothesis_direction = "increase" if ratio > 0 else "decrease"
    experiment_body: dict[str, Any] = {
        "design_ref": brief.experiment.design_ref,
        "hypothesis": {
            "metric_name": "revenue_per_session",
            "direction": hypothesis_direction,
            "rationale": (
                f"A {percent}% price change should move revenue per session "
                f"{hypothesis_direction} if demand tolerates the new price; "
                "the readout feeds estimate_price_elasticity."
            ),
        },
        "variants": (
            {
                "variant_ref": "price-control",
                "description": "Current price",
                "allocation": Decimal("0.500000"),
                "is_control": True,
            },
            {
                "variant_ref": "price-treatment",
                "description": f"Price changed by {percent}%",
                "allocation": Decimal("0.500000"),
                "is_control": False,
            },
        ),
        "assignment_unit": brief.experiment.assignment_unit,
        "baseline_source": baseline_source,
        "baseline_value": baseline_value,
        "baseline_standard_deviation": brief.experiment.baseline_standard_deviation,
        "minimum_detectable_effect": brief.experiment.minimum_detectable_effect,
        "alpha": brief.experiment.alpha,
        "power": brief.experiment.power,
        "designed_at": brief.planned_at,
        "exposure_start": brief.experiment.exposure_start,
        "readout_horizon": brief.experiment.readout_horizon,
    }
    if baseline_digest is not None:
        experiment_body["baseline_evidence_digest"] = baseline_digest
    experiment_input = DesignGrowthExperimentInput.model_validate(experiment_body)

    required_n = required_sample_per_arm_continuous(
        float(brief.experiment.baseline_standard_deviation),
        float(brief.experiment.minimum_detectable_effect),
        alpha=float(brief.experiment.alpha),
        power=float(brief.experiment.power),
    )

    projections: list[PriceProjection] = [
        PriceProjection(
            name="constant_volume_margin",
            unit="ratio",
            value=_constant_volume_margin(
                net_revenue.value, variable_costs.value, ratio
            ),
            assumption="volume held constant; variable costs unchanged",
        ),
        PriceProjection(
            name="constant_volume_contribution_delta",
            unit="money",
            value=_quantized_money(net_revenue.value * ratio),
            assumption="volume held constant; the whole price change is margin",
        ),
        PriceProjection(
            name="required_sample_per_arm",
            unit="count",
            value=Decimal(required_n),
            assumption="preregistered power computation for the embedded test",
        ),
    ]
    informed_kwargs: dict[str, Any] = {
        "economics_digest": economics.economics_digest,
        "learning_digests": tuple(entry.entry_digest for entry in brief.learnings),
    }
    funnel_for_digest = verified_funnel or brief.funnel_snapshot
    if funnel_for_digest is not None:
        informed_kwargs["funnel_digest"] = funnel_for_digest.funnel_digest
    if brief.elasticity is not None:
        informed_kwargs["elasticity_estimate_digest"] = brief.elasticity.estimate_digest
        informed_kwargs["elasticity_readout_digest"] = brief.elasticity.readout_digest
        estimate = brief.elasticity
        point_delta = _elasticity_contribution_delta(
            net_revenue.value, variable_costs.value, ratio, estimate.elasticity
        )
        bound_deltas = sorted(
            (
                _elasticity_contribution_delta(
                    net_revenue.value, variable_costs.value, ratio, estimate.ci_low
                ),
                _elasticity_contribution_delta(
                    net_revenue.value, variable_costs.value, ratio, estimate.ci_high
                ),
            )
        )
        projections.extend(
            (
                PriceProjection(
                    name="constant_elasticity_contribution_delta",
                    unit="money",
                    value=point_delta,
                    assumption=(
                        "constant-elasticity demand; variable costs scale with volume"
                    ),
                ),
                PriceProjection(
                    name="constant_elasticity_contribution_delta_low",
                    unit="money",
                    value=bound_deltas[0],
                    assumption="delta at the elasticity interval bound",
                ),
                PriceProjection(
                    name="constant_elasticity_contribution_delta_high",
                    unit="money",
                    value=bound_deltas[1],
                    assumption="delta at the elasticity interval bound",
                ),
            )
        )
        notes.append(
            "elasticity provenance digests are echoed, not re-verified here; "
            "verify the named readout before dispatch"
        )
    notes.append(f"the embedded price test needs at least {required_n} units per arm")

    operation = PriceMoveOperation.model_validate(
        {
            "operation_ref": f"{brief.plan_ref}-move",
            "currency": economics.currency,
            "direction": direction,
            "price_change_ratio": ratio,
            "economics_digest": economics.economics_digest,
            "experiment_input": experiment_input,
            "approval_unit": (f"approval_price_move_{brief.plan_ref}-move_{'0' * 64}"),
        }
    )

    plan_kwargs: dict[str, Any] = {
        "plan_ref": brief.plan_ref,
        "planned_at": brief.planned_at,
        "objective": brief.objective,
        "currency": economics.currency,
        "evidence_scope_status": status,
        "reference_quality": reference_quality,
        "operation": operation,
        "projections": tuple(projections),
        "informed_by": ProfitInformedBy.model_validate(informed_kwargs),
        "notes": tuple(notes),
    }
    if scope_keyring is None or workflow_scope is None:
        return PricePlan(**plan_kwargs)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = PricePlan(
        **plan_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        plan_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_PRICE_PLAN_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"plan_digest"},
        exclude_none=True,
    )
    sealed["plan_hmac"] = signature
    return PricePlan.model_validate(sealed)


def verify_price_plan(
    value: PricePlan | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> PricePlan:
    """Re-validate and verify one sealed price plan; raise on failure."""

    plan = PricePlan.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, PricePlan)
        else value
    )
    if (
        plan.receipt_key_id is None
        or plan.exact_scope_digest is None
        or plan.plan_hmac is None
    ):
        raise GrowthProfitValidationError("the price plan carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=plan.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(plan.exact_scope_digest, expected_scope_digest):
        raise GrowthProfitValidationError("price plan attestation failed verification")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=plan.receipt_key_id,
        domain=_PRICE_PLAN_HMAC_DOMAIN,
        payload=plan.hmac_payload(),
    )
    if not hmac.compare_digest(plan.plan_hmac, expected_hmac):
        raise GrowthProfitValidationError("price plan attestation failed verification")
    return plan


# ---------------------------------------------------------------------------
# Profit review (the money cockpit)
# ---------------------------------------------------------------------------


class ReviewProfitInput(_StrictModel):
    as_of: str
    unit_economics: UnitEconomicsSnapshot
    funnel_snapshot: GrowthFunnelSnapshot | None = None
    policy: PriceGuardrailPolicy | None = None
    learnings: tuple[GrowthLearningEntry, ...] = Field(
        default_factory=tuple, max_length=_MAX_REVIEW_LEARNINGS
    )

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("learnings", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


class MoneyOpportunity(_StrictModel):
    """One action ranked by what it is worth in contribution profit."""

    rank: int = Field(ge=1, le=_MAX_REVIEW_OPPORTUNITIES)
    kind: MoneyOpportunityKind
    title: ShortText
    mechanism: ShortText
    expected_contribution_delta: Decimal | None = None
    delta_low: Decimal | None = None
    delta_high: Decimal | None = None
    interval_kind: Literal["scenario_half_to_full_close"] | None = None
    assumptions: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=5)
    next_primitive_ref: ShortText | None = None
    argument_hints: dict[str, str] = Field(default_factory=dict)

    @field_validator(
        "expected_contribution_delta", "delta_low", "delta_high", mode="before"
    )
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator("assumptions", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @field_validator("argument_hints", mode="before")
    @classmethod
    def _string_hints(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            return {str(key): str(item) for key, item in value.items()}
        return value

    @model_validator(mode="after")
    def _delta_shape(self) -> "MoneyOpportunity":
        delta_fields = (
            self.expected_contribution_delta,
            self.delta_low,
            self.delta_high,
            self.interval_kind,
        )
        if any(value is not None for value in delta_fields) and not all(
            value is not None for value in delta_fields
        ):
            raise ValueError(
                "money deltas, their interval, and its kind appear together"
            )
        if self.delta_low is not None and not (
            self.delta_low <= self.expected_contribution_delta <= self.delta_high
        ):
            raise ValueError("the expected delta must fall inside its interval")
        return self


class PricingLearningEcho(_StrictModel):
    entry_digest: Sha256Digest
    grade: Literal["experimental", "observational", "heuristic"]
    claim: ShortText


class ProfitReview(_StrictModel):
    """One deterministic answer to "where is the money, and what is it worth"."""

    schema_id: Literal["lightbulb.growth_profit_review.v1"] = Field(
        default=GROWTH_PROFIT_REVIEW_SCHEMA,
        alias="schema",
    )
    as_of: str
    economics_digest: Sha256Digest
    funnel_digest: Sha256Digest | None = None
    currency: CurrencyCode
    evidence_scope_status: EvidenceScopeStatus
    components: tuple[EconomicsComponent, ...] = Field(default_factory=tuple)
    opportunities: tuple[MoneyOpportunity, ...] = Field(default_factory=tuple)
    pricing_learnings: tuple[PricingLearningEcho, ...] = Field(default_factory=tuple)
    data_quality_notes: tuple[ShortText, ...] = Field(default_factory=tuple)
    review_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "components",
        "opportunities",
        "pricing_learnings",
        "data_quality_notes",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "ProfitReview":
        ranks = [item.rank for item in self.opportunities]
        if ranks != sorted(ranks) or len(ranks) != len(set(ranks)):
            raise ValueError("opportunities must carry unique ascending ranks")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"review_digest"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.review_digest != "0" * 64 and self.review_digest != expected:
            raise ValueError("review_digest does not match the canonical payload")
        object.__setattr__(self, "review_digest", expected)
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _scenario_delta(full_close: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    """(low, expected, high) for a close-the-gap scenario interval."""

    high = _quantized_money(full_close)
    low = _quantized_money(full_close / 2)
    expected = _quantized_money(full_close * Decimal("0.75"))
    return low, expected, high


# Funnel rates with a defensible path from rate improvement to money, given
# unit economics: rate -> (unit description, money-per-unit component source).
_MONEY_MAPPABLE_RATES = ("reach_to_visit", "visit_to_purchase", "purchase_to_repeat")


def _funnel_money_opportunities(
    snapshot: GrowthFunnelSnapshot,
    economics: UnitEconomicsSnapshot,
    notes: list[str],
) -> list[dict[str, Any]]:
    margin = economics.component("contribution_margin")
    per_order = economics.component("contribution_per_order")
    references = {item.rate_name: item for item in snapshot.reference_rates}
    revenue_per_session: Decimal | None = None
    for derived in snapshot.derived_values:
        if derived.name == "revenue_per_session":
            revenue_per_session = derived.value
    candidates: list[dict[str, Any]] = []
    for rate in snapshot.rates:
        if rate.anomalous:
            continue
        reference = references.get(rate.rate_name)
        if reference is None or rate.value >= reference.value:
            continue
        gap = reference.value - rate.value
        if rate.rate_name not in _MONEY_MAPPABLE_RATES:
            notes.append(
                f"rate {rate.rate_name} is below its reference but has no "
                "defensible money mapping; it is diagnosed by growth.diagnose"
            )
            continue
        assumptions: list[str] = [
            f"closing to the {reference.quality} reference of {reference.value}"
        ]
        if rate.rate_name == "reach_to_visit":
            if margin is None or revenue_per_session is None:
                continue
            unit_gain = revenue_per_session * margin.value
            assumptions.append(
                "new sessions valued at revenue_per_session x contribution_margin"
            )
            if not margin.complete:
                assumptions.append(
                    "margin excludes unknown costs: " + ", ".join(margin.missing_inputs)
                )
        else:
            if per_order is None:
                continue
            unit_gain = per_order.value
            assumptions.append(
                "new orders valued at contribution_per_order from the ledger"
            )
            if not per_order.complete:
                assumptions.append(
                    "contribution_per_order excludes unknown costs: "
                    + ", ".join(per_order.missing_inputs)
                )
        full_close = rate.denominator.value * gap * unit_gain
        if full_close <= 0:
            continue
        low, expected, high = _scenario_delta(full_close)
        candidates.append(
            {
                "kind": "run_experiment",
                "title": f"Close the {rate.rate_name} gap",
                "mechanism": (
                    f"{rate.rate_name} is {rate.value} against a "
                    f"{reference.quality} reference of {reference.value}"
                ),
                "expected_contribution_delta": expected,
                "delta_low": low,
                "delta_high": high,
                "interval_kind": "scenario_half_to_full_close",
                "assumptions": tuple(assumptions[:5]),
                "next_primitive_ref": "design_growth_experiment",
                "argument_hints": {
                    "metric_name": rate.rate_name,
                    "baseline_source": "funnel_snapshot",
                    "baseline_value": str(rate.value),
                    "baseline_evidence_digest": snapshot.funnel_digest,
                    "direction": "increase",
                },
            }
        )
    return candidates


def _leak_opportunities(
    economics: UnitEconomicsSnapshot,
) -> list[dict[str, Any]]:
    gross = economics.total("gross_sales")
    if gross is None or gross.value <= 0:
        return []
    candidates: list[dict[str, Any]] = []
    for metric, ratio_name, reference in _LEAK_REFERENCES:
        total = economics.total(metric)
        if total is None:
            continue
        observed = _quantized_ratio(total.value / gross.value)
        if observed <= reference:
            continue
        full_close = (observed - reference) * gross.value
        low, expected, high = _scenario_delta(full_close)
        candidates.append(
            {
                "kind": "reduce_cost_leak",
                "title": f"Reduce the {metric} leak",
                "mechanism": (
                    f"{ratio_name} is {observed} of gross sales against a "
                    f"default_heuristic reference of {reference}"
                ),
                "expected_contribution_delta": expected,
                "delta_low": low,
                "delta_high": high,
                "interval_kind": "scenario_half_to_full_close",
                "assumptions": (
                    "every recovered unit of this cost flows to contribution",
                    "the reference is an operating heuristic, not a benchmark",
                ),
                "next_primitive_ref": None,
                "argument_hints": {},
            }
        )
    return candidates


def review_profit(
    inputs: ReviewProfitInput | Mapping[str, Any],
) -> ProfitReview:
    """Deterministically rank where the money is from economics + funnel state.

    The review echoes the economics snapshot's own trust label; it never
    upgrades trust, never invents costs for unknown metrics, and labels every
    projection with the scenario or heuristic that produced it. Verification
    of inputs is the caller's job (via the verify_* functions) — advice is
    re-derivable and carries a content digest, not a seal.
    """

    parsed = (
        inputs
        if isinstance(inputs, ReviewProfitInput)
        else ReviewProfitInput.model_validate(inputs)
    )
    economics = parsed.unit_economics
    as_of_at = _parse_timestamp(parsed.as_of)
    if _parse_timestamp(economics.analysis_as_of) > as_of_at:
        raise GrowthProfitValidationError(
            "the unit economics are from the future of the review as_of"
        )
    if parsed.funnel_snapshot is not None and (
        _parse_timestamp(parsed.funnel_snapshot.analysis_as_of) > as_of_at
    ):
        raise GrowthProfitValidationError(
            "the funnel snapshot is from the future of the review as_of"
        )
    if (
        parsed.funnel_snapshot is not None
        and parsed.funnel_snapshot.currency is not None
        and parsed.funnel_snapshot.currency != economics.currency
    ):
        raise GrowthProfitValidationError(
            "the funnel and unit economics currencies differ; profit review "
            "cannot translate funnel movement into money"
        )

    notes: list[str] = list(economics.data_quality_notes)
    candidates: list[dict[str, Any]] = []

    margin = economics.component("contribution_margin")
    net_revenue = economics.component("net_revenue")
    policy = parsed.policy

    pricing_entries = [
        entry
        for entry in parsed.learnings
        if entry.lever == "pricing"
        and (
            entry.valid_until is None or _parse_timestamp(entry.valid_until) > as_of_at
        )
    ]
    has_experimental_pricing = any(
        entry.grade == "experimental" for entry in pricing_entries
    )

    if policy is not None and margin is not None and net_revenue is not None:
        floor = policy.minimum_contribution_margin
        if margin.complete and margin.value < floor:
            variable_costs = economics.component("variable_cost_total")
            if variable_costs is not None:
                needed = _minimum_ratio_for_floor(
                    net_revenue.value, variable_costs.value, floor
                )
                full_close = net_revenue.value * needed
                low, expected, high = _scenario_delta(full_close)
                candidates.append(
                    {
                        "kind": "plan_price_move",
                        "title": "Restore the contribution margin floor",
                        "mechanism": (
                            f"contribution_margin is {margin.value} against "
                            f"the policy floor of {floor}"
                        ),
                        "expected_contribution_delta": expected,
                        "delta_low": low,
                        "delta_high": high,
                        "interval_kind": "scenario_half_to_full_close",
                        "assumptions": ("volume held constant at the corrected price",),
                        "next_primitive_ref": "growth.plan_price_move",
                        "argument_hints": {
                            "objective": "protect_margin",
                            "economics_digest": economics.economics_digest,
                        },
                    }
                )
        elif margin.complete and not has_experimental_pricing:
            candidates.append(
                {
                    "kind": "plan_price_move",
                    "title": "Run a price elasticity probe",
                    "mechanism": (
                        "price is an untested lever for this scope; no "
                        "experimental pricing learning exists yet"
                    ),
                    "expected_contribution_delta": None,
                    "delta_low": None,
                    "delta_high": None,
                    "interval_kind": None,
                    "assumptions": (
                        "the probe buys an elasticity estimate, not "
                        "immediate contribution",
                    ),
                    "next_primitive_ref": "growth.plan_price_move",
                    "argument_hints": {
                        "objective": "test_elasticity",
                        "economics_digest": economics.economics_digest,
                    },
                }
            )

    if parsed.funnel_snapshot is not None:
        candidates.extend(
            _funnel_money_opportunities(parsed.funnel_snapshot, economics, notes)
        )
    candidates.extend(_leak_opportunities(economics))

    blocked_components = [
        component for component in economics.components if not component.complete
    ]
    missing_metrics = sorted(
        {
            metric
            for component in blocked_components
            for metric in component.missing_inputs
        }
    )
    if margin is None or missing_metrics:
        if margin is None:
            mechanism = (
                "contribution margin cannot be computed; money-ranking is "
                "blind until the ledger is measured"
            )
        else:
            mechanism = (
                "derived components are incomplete; unknown ledger metrics: "
                + ", ".join(missing_metrics)
            )
        candidates.append(
            {
                "kind": "collect_evidence",
                "title": "Collect contribution ledger evidence",
                "mechanism": mechanism[:300],
                "expected_contribution_delta": None,
                "delta_low": None,
                "delta_high": None,
                "interval_kind": None,
                "assumptions": ("no revenue impact is claimed for measurement itself",),
                "next_primitive_ref": "growth.build_unit_economics",
                "argument_hints": {
                    "suggested_sources": ", ".join(
                        sorted(
                            capability
                            for capabilities in _SOURCE_CAPABILITIES.values()
                            for capability in capabilities
                        )
                    ),
                },
            }
        )

    with_delta = [
        item for item in candidates if item["expected_contribution_delta"] is not None
    ]
    without_delta = [
        item for item in candidates if item["expected_contribution_delta"] is None
    ]
    with_delta.sort(
        key=lambda item: (-item["expected_contribution_delta"], item["title"])
    )
    without_delta.sort(key=lambda item: (item["kind"], item["title"]))
    opportunities = tuple(
        MoneyOpportunity(rank=rank, **body)
        for rank, body in enumerate(
            (*with_delta, *without_delta)[:_MAX_REVIEW_OPPORTUNITIES], start=1
        )
    )

    if economics.evidence_scope_status == "host_hmac_verified":
        notes.append(
            "trust label echoed from the economics snapshot without "
            "verification here; verify the seal "
            "(verify_unit_economics_snapshot) before acting on it"
        )

    grade_rank = {"experimental": 0, "observational": 1, "heuristic": 2}
    pricing_echo = [
        PricingLearningEcho(
            entry_digest=entry.entry_digest,
            grade=entry.grade,
            claim=(
                entry.claim if len(entry.claim) <= 300 else entry.claim[:297] + "..."
            ),
        )
        for entry in pricing_entries
    ]
    pricing_echo.sort(key=lambda item: (grade_rank[item.grade], item.entry_digest))

    return ProfitReview(
        as_of=parsed.as_of,
        economics_digest=economics.economics_digest,
        funnel_digest=(
            parsed.funnel_snapshot.funnel_digest
            if parsed.funnel_snapshot is not None
            else None
        ),
        currency=economics.currency,
        evidence_scope_status=economics.evidence_scope_status,
        components=economics.components,
        opportunities=opportunities,
        pricing_learnings=tuple(pricing_echo),
        data_quality_notes=tuple(notes[:20]),
    )


# ---------------------------------------------------------------------------
# Executable primitives (read-only planners; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_PROFIT_EVIDENCE: dict[str, Any] = {
    "observation_ref": "shopify-ledger-example",
    "connector_account_ref": "acct.shopify.example",
    "provider": "shopify",
    "source_capability": "shopify.analytics_query",
    "currency": "USD",
    "observed_at": "2026-08-18T00:00:00Z",
    "window_start": "2026-08-01T00:00:00Z",
    "window_end": "2026-08-15T00:00:00Z",
    "metrics": {
        "gross_sales": "12000.00",
        "discounts": "600.00",
        "refunds": "350.00",
        "cogs": "4800.00",
        "fulfillment_cost": "900.00",
        "payment_fees": "360.00",
        "service_cost": "240.00",
        "acquisition_cost": "1500.00",
        "orders": 300,
        "units": 420,
        "new_customers": 120,
    },
    "evidence_digest": "6" * 64,
}

_EXAMPLE_ECONOMICS: dict[str, Any] = build_unit_economics(
    {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "economics_ref": "econ-example",
        "currency": "USD",
        "evidence": (_EXAMPLE_PROFIT_EVIDENCE,),
    }
).to_dict()


def _planner_failure(
    primitive_ref: str,
    version: str,
    exc: ValueError,
) -> PrimitiveExecutionResult[Any]:
    return PrimitiveExecutionResult(
        status=PrimitiveExecutionStatus.FAILED,
        primitive_ref=primitive_ref,
        primitive_version=version,
        summary="The profit planner rejected the brief.",
        blockers=[
            PrimitiveBlocker(
                code="growth_profit_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class BuildUnitEconomicsPrimitive(
    BusinessProcessPrimitive[BuildUnitEconomicsInput, UnitEconomicsSnapshot]
):
    """Compile a unit-economics snapshot from supplied ledger envelopes."""

    primitive_ref = "growth.build_unit_economics"
    version = "1.0.0"
    title = "Build unit economics"
    description = (
        "Aggregate sealed or caller-supplied contribution-ledger envelopes "
        "(gross sales, discounts, refunds, COGS, fulfillment, fees, spend) "
        "into one unit-economics snapshot: net revenue, contribution profit "
        "and margin, AOV, CAC, breakeven ROAS — with honest per-metric "
        "completeness, currency and basis separation, and visible exclusions. "
        "Runs without connector calls; host sealing happens server-side."
    )
    input_model = BuildUnitEconomicsInput
    output_model = UnitEconomicsSnapshot
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "economics_ref": "econ-example",
        "currency": "USD",
        "evidence": [_EXAMPLE_PROFIT_EVIDENCE],
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BuildUnitEconomicsInput,
    ) -> PrimitiveExecutionResult[UnitEconomicsSnapshot]:
        try:
            snapshot = build_unit_economics(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        margin = snapshot.component("contribution_margin")
        return PrimitiveExecutionResult[UnitEconomicsSnapshot](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Unit economics built: {len(snapshot.admitted_evidence)} "
                f"envelopes admitted, {len(snapshot.excluded_evidence)} "
                "excluded; contribution margin "
                f"{margin.value if margin is not None else 'unknown'}."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="growth.unit_economics_built",
                    payload={
                        "economics_ref": snapshot.economics_ref,
                        "admitted": len(snapshot.admitted_evidence),
                        "excluded": len(snapshot.excluded_evidence),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Economics digest "
                    + snapshot.economics_digest[:16]
                    + "… derived from admitted ledger evidence only.",
                )
            ],
        )


class ReviewProfitPrimitive(BusinessProcessPrimitive[ReviewProfitInput, ProfitReview]):
    """Rank the next best money actions from unit economics and funnel state."""

    primitive_ref = "growth.review_profit"
    version = "2.0.0"
    title = "Review profit"
    description = (
        "Turn a unit-economics snapshot (plus optional funnel snapshot, price "
        "policy, and learnings) into money-ranked opportunities: funnel gaps "
        "priced in contribution profit with scenario intervals, cost leaks "
        "against labeled heuristics, margin-floor breaches, and the exact "
        "next primitive to call. Every projection names its assumptions."
    )
    input_model = ReviewProfitInput
    output_model = ProfitReview
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-08-19T00:00:00Z",
        "unit_economics": _EXAMPLE_ECONOMICS,
        "policy": {"minimum_contribution_margin": "0.250000"},
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReviewProfitInput,
    ) -> PrimitiveExecutionResult[ProfitReview]:
        try:
            review = review_profit(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[ProfitReview](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Profit review ready: {len(review.opportunities)} "
                f"opportunities in {review.currency}."
            ),
            output=review,
            events=[
                PrimitiveEvent(
                    type="growth.profit_review_ready",
                    payload={
                        "opportunities": len(review.opportunities),
                        "currency": review.currency,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Review derived from economics digest "
                    + review.economics_digest[:16]
                    + "…",
                )
            ],
        )


class PlanPriceMovePrimitive(BusinessProcessPrimitive[PricePlanBrief, PricePlan]):
    """Plan a margin-guarded price move that ships as a preregistered test."""

    primitive_ref = "growth.plan_price_move"
    version = "2.0.0"
    title = "Plan price move"
    description = (
        "Deterministically plan one bounded price change from sealed unit "
        "economics: protect a breached margin floor, probe elasticity, or "
        "grow contribution under a measured elasticity estimate. The margin "
        "floor is structurally enforced, the move is bound to a "
        "content-digest approval unit, and the plan embeds the exact "
        "preregistered experiment to run. Planning only — execution requires "
        "governed approvals."
    )
    input_model = PricePlanBrief
    output_model = PricePlan
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "plan_ref": "price-example",
        "planned_at": "2026-08-19T00:00:00Z",
        "objective": "test_elasticity",
        "direction": "increase",
        "unit_economics": _EXAMPLE_ECONOMICS,
        "policy": {"minimum_contribution_margin": "0.250000"},
        "experiment": {
            "design_ref": "price-test-example",
            "assignment_unit": "visitor",
            "baseline_value": "2.100000",
            "baseline_standard_deviation": "3.500000",
            "minimum_detectable_effect": "0.200000",
            "exposure_start": "2026-08-24T00:00:00Z",
            "readout_horizon": "2026-09-14T00:00:00Z",
        },
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: PricePlanBrief,
    ) -> PrimitiveExecutionResult[PricePlan]:
        try:
            plan = plan_price_move(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[PricePlan](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Price move planned: {plan.operation.direction} of "
                f"{plan.operation.price_change_ratio} ({plan.objective}), "
                f"status {plan.evidence_scope_status}."
            ),
            output=plan,
            events=[
                PrimitiveEvent(
                    type="growth.price_move_planned",
                    payload={
                        "plan_ref": plan.plan_ref,
                        "objective": plan.objective,
                        "direction": plan.operation.direction,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Plan digest "
                    + plan.plan_digest[:16]
                    + "…; the move carries a content-bound approval unit.",
                )
            ],
        )


__all__ = [
    "GROWTH_PRICE_ELASTICITY_SCHEMA",
    "GROWTH_PRICE_PLAN_SCHEMA",
    "GROWTH_PROFIT_EVIDENCE_SCHEMA",
    "GROWTH_PROFIT_REVIEW_SCHEMA",
    "GROWTH_UNIT_ECONOMICS_SCHEMA",
    "AdmittedProfitEvidence",
    "BuildUnitEconomicsInput",
    "BuildUnitEconomicsPrimitive",
    "ContributionMetrics",
    "EconomicsComponent",
    "ExcludedProfitEvidence",
    "GrowthProfitValidationError",
    "LedgerMetricPresence",
    "LedgerMetricTotal",
    "MoneyOpportunity",
    "PlanPriceMovePrimitive",
    "PriceElasticityEstimate",
    "PriceExperimentSettings",
    "PriceGuardrailPolicy",
    "PriceMoveOperation",
    "PricePlan",
    "PricePlanBrief",
    "PriceProjection",
    "PricingLearningEcho",
    "ProfitContributionEvidence",
    "ProfitInformedBy",
    "ProfitReview",
    "ProfitStalenessPolicy",
    "ReviewProfitInput",
    "ReviewProfitPrimitive",
    "UnitEconomicsSnapshot",
    "build_unit_economics",
    "estimate_price_elasticity",
    "mint_profit_contribution_evidence",
    "plan_price_move",
    "review_profit",
    "verify_price_plan",
    "verify_profit_contribution_evidence",
    "verify_unit_economics_snapshot",
]
