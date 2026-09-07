"""Customer value engine: what a customer is worth beyond the first order.

Every acquisition-facing number the Growth Engine emits elsewhere is
first-order: ``breakeven_roas = 1/contribution_margin``, CAC payback in
orders, and a purchase priced at exactly one order's contribution. For any
repeat-purchase business the spend ceiling is therefore wrong by the repeat
multiple — in either direction. This module measures what repeat behavior a
scope's cohorts have actually exhibited and turns it into the two numbers an
acquisition decision needs: horizon-bounded observed customer value and the
CAC ceiling it supports.

Design rules enforced here:

- **Observed, never extrapolated.** Value components are named
  ``*_h<days>`` and derive only from cohorts old enough to have lived the
  whole horizon. The **right-censoring law is structural**: a cohort whose
  youngest member has not aged past a horizon is excluded from that
  horizon's component with reason ``cohort_too_young`` — never averaged in,
  never projected forward. Beyond the oldest observed horizon, customer
  value is unknown, not zero.
- **Buckets tile or the cohort is out.** A horizon component admits a
  cohort only if its age buckets exactly tile ``[0, horizon)`` days;
  gapped or overlapping coverage is excluded with reason ``bucket_gap``
  rather than silently summed short.
- **Cross-artifact margin is labeled.** Contribution LTV multiplies
  observed net revenue by the contribution margin of a caller-supplied
  :class:`~lightbulb.growth_profit.UnitEconomicsSnapshot`; the component is
  flagged ``cross_artifact`` and pins ``economics_digest``, and margin
  incompleteness propagates.
- **The CAC ceiling is a policy, not a truth.** ``cac_ceiling_h<days>``
  equals contribution LTV at that horizon — "spend up to h-day payback" —
  and every artifact says the horizon choice is a finance-policy heuristic.
- **Evidence is sealed.** Cohort envelopes are minted by a trusted host and
  verification recomputes the keyed HMAC; tampering is an error, never an
  exclusion.

Naming note: ``lightbulb/growth_primitives.py`` predates the Growth Engine
and holds unrelated catalog primitives; the Growth Engine lives in the
``growth_funnel`` / ``growth_experiments`` / ``growth_learnings`` /
``growth_profit`` / ``growth_operating`` / ``growth_customers`` family.

Producer contract: the cohort envelope is a dict-boundary shape the
ingestion/rail lane can produce from a cohort-grouped
``shopify.analytics_query`` (or Stripe financial report). The exact field
contract is documented in ``docs/growth-engine-design.md`` (slice 8) so the
producer lands against a frozen shape.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
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
from .growth_profit import (
    UnitEconomicsSnapshot,
    verify_unit_economics_snapshot,
)
from .primitive_runtime import (
    BusinessProcessPrimitive,
    PrimitiveBlocker,
    PrimitiveEvent,
    PrimitiveEvidence,
    PrimitiveExecutionContext,
    PrimitiveExecutionResult,
    PrimitiveExecutionStatus,
)

GROWTH_CUSTOMER_COHORT_EVIDENCE_SCHEMA = (
    "lightbulb.growth_customer_cohort_evidence.v1"
)
GROWTH_CUSTOMER_VALUE_SCHEMA = "lightbulb.growth_customer_value.v1"
GROWTH_CUSTOMER_VALUE_REVIEW_SCHEMA = "lightbulb.growth_customer_value_review.v1"

_COHORT_EVIDENCE_HMAC_DOMAIN = GROWTH_CUSTOMER_COHORT_EVIDENCE_SCHEMA
_CUSTOMER_VALUE_HMAC_DOMAIN = GROWTH_CUSTOMER_VALUE_SCHEMA

_MAX_COHORTS = 24
_MAX_AGE_BUCKETS = 12
_MAX_REVIEW_OPPORTUNITIES = 20

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

CohortProvider = Literal["shopify", "stripe"]

_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "shopify": frozenset({"shopify.analytics_query"}),
    "stripe": frozenset({"stripe.financial_report"}),
}

# The observed-value horizons this engine reports, in days. Fixed and
# canonical so components are comparable across scopes and time.
VALUE_HORIZONS_DAYS: tuple[int, ...] = (30, 90, 180, 360)

CohortExclusionReason = Literal[
    "cohort_too_young",
    "bucket_gap",
    "currency_mismatch",
    "future_observation",
]


class GrowthCustomersValidationError(ValueError):
    """Cohort evidence or customer-value content violates the contract."""


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
    except GrowthCustomersValidationError:
        raise
    except Exception as exc:
        raise GrowthCustomersValidationError(
            "the customer-value signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthCustomersValidationError:
        raise
    except Exception as exc:
        raise GrowthCustomersValidationError(
            "the customer-value signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Cohort evidence
# ---------------------------------------------------------------------------


class CohortAgeBucket(_StrictModel):
    """Observed behavior of one cohort inside one age interval, in days.

    Ages are measured from each customer's acquisition. Buckets are
    half-open ``[age_days_start, age_days_end)``. A bucket that was not
    observed is simply absent — absence is unknown, never zero.
    """

    age_days_start: int = Field(ge=0, le=3_650)
    age_days_end: int = Field(ge=1, le=3_650)
    orders: int = Field(ge=0, le=10_000_000_000)
    # Money is bounded so pooled sums stay far inside the default 28-digit
    # Decimal context: 24 cohorts x 12 buckets x 1e12 cannot silently round.
    gross_sales: Decimal = Field(ge=0, le=Decimal("1000000000000"))
    discounts: Decimal = Field(ge=0, le=Decimal("1000000000000"))
    refunds: Decimal = Field(ge=0, le=Decimal("1000000000000"))

    @field_validator("gross_sales", "discounts", "refunds", mode="before")
    @classmethod
    def _money_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @model_validator(mode="after")
    def _ordered_interval(self) -> "CohortAgeBucket":
        if self.age_days_end <= self.age_days_start:
            raise ValueError("age buckets must span a positive interval")
        return self


class CustomerCohortEvidence(_StrictModel):
    """A sealed acquisition count; repeat behavior stays unknown until age buckets are observed."""

    cohort_ref: PortableRef
    connector_account_ref: OperationRef
    provider: CohortProvider
    source_capability: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$",
    )
    currency: CurrencyCode
    acquisition_window_start: str
    acquisition_window_end: str
    observed_at: str
    cohort_size: int = Field(ge=0, le=10_000_000_000)
    age_buckets: tuple[CohortAgeBucket, ...] = Field(
        min_length=0, max_length=_MAX_AGE_BUCKETS
    )
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    cohort_hmac: Sha256Digest | None = None

    @field_validator(
        "acquisition_window_start", "acquisition_window_end", "observed_at"
    )
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("age_buckets", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _valid_source_windows_and_buckets(self) -> "CustomerCohortEvidence":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.acquisition_window_end) <= _parse_timestamp(
            self.acquisition_window_start
        ):
            raise ValueError(
                "acquisition_window_end must follow acquisition_window_start"
            )
        if _parse_timestamp(self.observed_at) < _parse_timestamp(
            self.acquisition_window_end
        ):
            raise ValueError("observed_at must not precede the acquisition window")
        ordered = sorted(
            self.age_buckets, key=lambda bucket: bucket.age_days_start
        )
        if list(self.age_buckets) != ordered:
            raise ValueError("age buckets must be sorted by age_days_start")
        for earlier, later in zip(ordered, ordered[1:]):
            if later.age_days_start < earlier.age_days_end:
                raise ValueError("age buckets must not overlap")
        # No bucket may claim ages the cohort's youngest member has not
        # lived: observed behavior cannot come from the future.
        observed_age_days = self.observed_age_days
        if self.cohort_size == 0 and ordered:
            raise ValueError("zero-customer cohorts cannot carry observed order/value buckets")
        if ordered and ordered[-1].age_days_end > observed_age_days:
            raise ValueError(
                "age buckets claim behavior beyond the cohort's observed age "
                f"({observed_age_days} days for its youngest member)"
            )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.cohort_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "cohort evidence attestation fields must be supplied together"
            )
        return self

    @property
    def observed_age_days(self) -> int:
        """Whole days the cohort's YOUNGEST member has been observed."""

        elapsed = _parse_timestamp(self.observed_at) - _parse_timestamp(
            self.acquisition_window_end
        )
        return int(elapsed.total_seconds() // 86_400)

    @property
    def is_attested(self) -> bool:
        return self.cohort_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"cohort_hmac"},
            exclude_none=True,
        )


def mint_customer_cohort_evidence(
    value: CustomerCohortEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> CustomerCohortEvidence:
    """Seal one host-verified acquisition cohort for customer-value use."""

    evidence = (
        value
        if isinstance(value, CustomerCohortEvidence)
        else CustomerCohortEvidence.model_validate(value)
    )
    if evidence.is_attested or evidence.receipt_key_id is not None:
        raise GrowthCustomersValidationError("cohort evidence is already attested")
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    payload = evidence.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "cohort_hmac": "0" * 64,
        }
    )
    draft = CustomerCohortEvidence.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_COHORT_EVIDENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["cohort_hmac"] = signature
    return CustomerCohortEvidence.model_validate(sealed)


def _cohort_attestation_matches(
    evidence: CustomerCohortEvidence,
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
) -> bool:
    if (
        evidence.receipt_key_id is None
        or evidence.exact_scope_digest is None
        or evidence.cohort_hmac is None
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
        domain=_COHORT_EVIDENCE_HMAC_DOMAIN,
        payload=evidence.hmac_payload(),
    )
    return hmac.compare_digest(evidence.cohort_hmac, expected_hmac)


def verify_customer_cohort_evidence(
    value: CustomerCohortEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> CustomerCohortEvidence:
    """Re-validate and verify one sealed cohort envelope; raise on failure."""

    evidence = CustomerCohortEvidence.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, CustomerCohortEvidence)
        else value
    )
    if not evidence.is_attested:
        raise GrowthCustomersValidationError(
            "cohort evidence carries no host attestation"
        )
    workflow_scope = _workflow_scope(scope)
    if not _cohort_attestation_matches(
        evidence, scope=workflow_scope, scope_keyring=scope_keyring
    ):
        raise GrowthCustomersValidationError(
            "cohort evidence attestation failed verification"
        )
    return evidence


# ---------------------------------------------------------------------------
# Customer value snapshot
# ---------------------------------------------------------------------------


class BuildCustomerValueInput(_StrictModel):
    analysis_as_of: str
    value_ref: PortableRef
    currency: CurrencyCode
    cohorts: tuple[CustomerCohortEvidence, ...] = Field(
        min_length=1, max_length=_MAX_COHORTS
    )
    unit_economics: UnitEconomicsSnapshot | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("cohorts", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_members(self) -> "BuildCustomerValueInput":
        refs = [cohort.cohort_ref for cohort in self.cohorts]
        if len(refs) != len(set(refs)):
            raise ValueError("cohort refs must be unique")
        digests = [cohort.evidence_digest for cohort in self.cohorts]
        if len(digests) != len(set(digests)):
            raise ValueError("cohort evidence digests must be unique")
        return self


class HorizonComponent(_StrictModel):
    """Observed customer value at one horizon, from fully-aged cohorts only."""

    horizon_days: int = Field(ge=1, le=3_650)
    admitted_cohorts: int = Field(ge=1)
    customers: int = Field(ge=1)
    orders_per_customer: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    net_revenue_per_customer: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    contribution_ltv: Decimal | None = Field(
        default=None, multiple_of=_MONEY_QUANTUM
    )
    cac_ceiling: Decimal | None = Field(default=None, multiple_of=_MONEY_QUANTUM)
    cross_artifact: bool
    complete: bool
    missing_inputs: tuple[ShortText, ...] = Field(default_factory=tuple)
    formula: ShortText

    @field_validator(
        "orders_per_customer",
        "net_revenue_per_customer",
        "contribution_ltv",
        "cac_ceiling",
        mode="before",
    )
    @classmethod
    def _value_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return value
        return Decimal(str(value))

    @field_validator("missing_inputs", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _consistent_shape(self) -> "HorizonComponent":
        if (self.contribution_ltv is None) != (self.cac_ceiling is None):
            raise ValueError(
                "contribution_ltv and cac_ceiling appear together — the "
                "ceiling IS the horizon LTV"
            )
        if self.contribution_ltv is not None and (
            self.cac_ceiling != self.contribution_ltv
        ):
            raise ValueError("cac_ceiling must equal contribution_ltv")
        if self.contribution_ltv is not None and not self.cross_artifact:
            raise ValueError(
                "contribution values are cross-artifact by construction"
            )
        if self.complete and self.missing_inputs:
            raise ValueError("complete components cannot list missing inputs")
        if not self.complete and not self.missing_inputs:
            raise ValueError("incomplete components must name their missing inputs")
        return self


class ReorderCurvePoint(_StrictModel):
    """Pooled orders per customer inside one age interval."""

    age_days_start: int = Field(ge=0, le=3_650)
    age_days_end: int = Field(ge=1, le=3_650)
    customers: int = Field(ge=1)
    orders_per_customer: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)

    @field_validator("orders_per_customer", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        if isinstance(value, Decimal):
            return value
        return Decimal(str(value))


class ExcludedCohort(_StrictModel):
    cohort_ref: PortableRef
    evidence_digest: Sha256Digest
    horizon_days: int | None = Field(default=None, ge=1, le=3_650)
    reason: CohortExclusionReason


class CustomerValueSnapshot(_StrictModel):
    """Sealed, horizon-bounded observed customer value for one scope."""

    schema_id: Literal["lightbulb.growth_customer_value.v1"] = Field(
        default=GROWTH_CUSTOMER_VALUE_SCHEMA,
        alias="schema",
    )
    value_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode
    evidence_scope_status: Literal[
        "caller_supplied_unverified", "host_hmac_verified"
    ]
    horizons: tuple[HorizonComponent, ...] = Field(default_factory=tuple)
    reorder_curve: tuple[ReorderCurvePoint, ...] = Field(
        default_factory=tuple, max_length=24
    )
    economics_digest: Sha256Digest | None = None
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=20
    )
    admitted_cohort_refs: tuple[PortableRef, ...] = Field(default_factory=tuple)
    excluded_cohorts: tuple[ExcludedCohort, ...] = Field(default_factory=tuple)
    value_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    value_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "horizons",
        "reorder_curve",
        "data_quality_notes",
        "admitted_cohort_refs",
        "excluded_cohorts",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "CustomerValueSnapshot":
        horizon_days = [component.horizon_days for component in self.horizons]
        if horizon_days != sorted(horizon_days) or len(horizon_days) != len(
            set(horizon_days)
        ):
            raise ValueError("horizon components must be unique and ascending")
        for component in self.horizons:
            if component.horizon_days not in VALUE_HORIZONS_DAYS:
                raise ValueError(
                    "horizon components must use the canonical horizons"
                )
            if component.contribution_ltv is not None and (
                self.economics_digest is None
            ):
                raise ValueError(
                    "contribution components require the economics digest "
                    "they derive from"
                )
        curve = sorted(self.reorder_curve, key=lambda point: point.age_days_start)
        if list(self.reorder_curve) != curve:
            raise ValueError("the reorder curve must be sorted by age")
        for earlier, later in zip(curve, curve[1:]):
            if later.age_days_start < earlier.age_days_end:
                raise ValueError("reorder curve points must not overlap")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.value_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "customer value attestation fields must be supplied together"
            )
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.value_hmac is None
        ):
            raise ValueError(
                "verified customer value requires a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"value_digest", "value_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.value_digest != "0" * 64 and self.value_digest != expected:
            raise ValueError("value_digest does not match the canonical payload")
        object.__setattr__(self, "value_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"value_hmac", "value_digest"},
            exclude_none=True,
        )

    def horizon(self, horizon_days: int) -> HorizonComponent | None:
        for component in self.horizons:
            if component.horizon_days == horizon_days:
                return component
        return None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _buckets_tile(
    cohort: CustomerCohortEvidence, horizon_days: int
) -> bool:
    """True when the cohort's buckets exactly tile [0, horizon_days)."""

    covered = 0
    for bucket in cohort.age_buckets:
        if bucket.age_days_start > covered:
            return False
        if bucket.age_days_start < covered:
            # Overlap with covered ground is structurally impossible (the
            # envelope validator forbids overlaps), so this is a bucket that
            # started before our cursor only if it started before 0 — also
            # impossible. Defensive: treat as non-tiling.
            return False
        covered = bucket.age_days_end
        if covered >= horizon_days:
            return covered == horizon_days or _bucket_boundary_at(
                cohort, horizon_days
            )
    return covered >= horizon_days


def _bucket_boundary_at(
    cohort: CustomerCohortEvidence, horizon_days: int
) -> bool:
    """A horizon is only honest if a bucket boundary lands exactly on it."""

    boundaries = {0}
    for bucket in cohort.age_buckets:
        boundaries.add(bucket.age_days_end)
    return horizon_days in boundaries


def build_customer_value_snapshot(
    inputs: BuildCustomerValueInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> CustomerValueSnapshot:
    """Compute sealed, horizon-bounded observed customer value.

    The right-censoring law is enforced here: a horizon component pools only
    cohorts whose youngest member has lived the whole horizon AND whose
    buckets exactly tile it; everything else is excluded with a reason.
    With ``scope`` and ``scope_keyring`` every attested cohort is verified
    and the snapshot itself is sealed; supplied unit economics are verified
    too and their contribution margin converts revenue to contribution LTV,
    labeled cross-artifact.
    """

    parsed = (
        inputs
        if isinstance(inputs, BuildCustomerValueInput)
        else BuildCustomerValueInput.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise GrowthCustomersValidationError(
            "verified snapshots require both scope and scope_keyring"
        )
    workflow_scope: DynamicWorkflowScope | None = None
    economics = parsed.unit_economics
    if economics is not None and economics.currency != parsed.currency:
        raise GrowthCustomersValidationError(
            "the unit economics carry a different currency than the cohort "
            "snapshot; a margin cannot cross currencies — rebuild one of them"
        )
    if scope is not None and scope_keyring is not None:
        workflow_scope = _workflow_scope(scope)
        if economics is not None:
            economics = verify_unit_economics_snapshot(
                economics, scope=workflow_scope, scope_keyring=scope_keyring
            )
    analysis_at = _parse_timestamp(parsed.analysis_as_of)

    admitted: list[CustomerCohortEvidence] = []
    admitted_verified: dict[str, bool] = {}
    excluded: list[ExcludedCohort] = []
    for cohort in parsed.cohorts:
        verified = False
        if cohort.is_attested and scope_keyring is not None and (
            workflow_scope is not None
        ):
            if not _cohort_attestation_matches(
                cohort, scope=workflow_scope, scope_keyring=scope_keyring
            ):
                raise GrowthCustomersValidationError(
                    "cohort evidence attestation failed verification"
                )
            verified = True
        if cohort.currency != parsed.currency:
            excluded.append(
                ExcludedCohort(
                    cohort_ref=cohort.cohort_ref,
                    evidence_digest=cohort.evidence_digest,
                    reason="currency_mismatch",
                )
            )
            continue
        if _parse_timestamp(cohort.observed_at) > analysis_at:
            excluded.append(
                ExcludedCohort(
                    cohort_ref=cohort.cohort_ref,
                    evidence_digest=cohort.evidence_digest,
                    reason="future_observation",
                )
            )
            continue
        admitted.append(cohort)
        admitted_verified[cohort.cohort_ref] = verified

    # Overlapping acquisition windows from one account would count the same
    # customers into two cohorts; like the funnel's evidence-window law this
    # is a hard error, never a silent double count.
    by_account: dict[tuple[str, str], list[CustomerCohortEvidence]] = {}
    for member in admitted:
        key = (member.connector_account_ref, member.provider)
        by_account.setdefault(key, []).append(member)
    for group in by_account.values():
        ordered = sorted(
            group,
            key=lambda item: (
                _parse_timestamp(item.acquisition_window_start),
                _parse_timestamp(item.acquisition_window_end),
            ),
        )
        for earlier, later in zip(ordered, ordered[1:]):
            if _parse_timestamp(later.acquisition_window_start) < _parse_timestamp(
                earlier.acquisition_window_end
            ):
                raise GrowthCustomersValidationError(
                    "admitted cohorts overlap in acquisition window for one "
                    "account; the same customers would be counted twice — "
                    "split cohorts on disjoint windows upstream"
                )

    margin = economics.component("contribution_margin") if economics else None
    notes: list[str] = []

    horizons: list[HorizonComponent] = []
    for horizon_days in VALUE_HORIZONS_DAYS:
        pool: list[CustomerCohortEvidence] = []
        for cohort in admitted:
            if cohort.observed_age_days < horizon_days:
                excluded.append(
                    ExcludedCohort(
                        cohort_ref=cohort.cohort_ref,
                        evidence_digest=cohort.evidence_digest,
                        horizon_days=horizon_days,
                        reason="cohort_too_young",
                    )
                )
                continue
            if not _buckets_tile(cohort, horizon_days):
                excluded.append(
                    ExcludedCohort(
                        cohort_ref=cohort.cohort_ref,
                        evidence_digest=cohort.evidence_digest,
                        horizon_days=horizon_days,
                        reason="bucket_gap",
                    )
                )
                continue
            pool.append(cohort)
        if not pool:
            continue
        customers = sum(cohort.cohort_size for cohort in pool)
        orders = 0
        net_revenue = Decimal("0")
        for cohort in pool:
            for bucket in cohort.age_buckets:
                if bucket.age_days_end > horizon_days:
                    continue
                orders += bucket.orders
                net_revenue += (
                    bucket.gross_sales - bucket.discounts - bucket.refunds
                )
        net_per_customer = _quantized_money(net_revenue / customers)
        if net_per_customer < 0:
            net_per_customer = Decimal("0.00")
            notes.append(
                f"h{horizon_days}: pooled net revenue was negative (refunds "
                "exceeded sales); reported as zero with this note"
            )
        component_kwargs: dict[str, Any] = {
            "horizon_days": horizon_days,
            "admitted_cohorts": len(pool),
            "customers": customers,
            "orders_per_customer": _quantized_ratio(
                Decimal(orders) / customers
            ),
            "net_revenue_per_customer": net_per_customer,
            "formula": "sum(gross-discounts-refunds in [0,h)) / cohort customers",
        }
        if margin is not None and economics is not None:
            ltv = _quantized_money(net_per_customer * margin.value)
            component_kwargs.update(
                {
                    "contribution_ltv": ltv,
                    "cac_ceiling": ltv,
                    "cross_artifact": True,
                    "complete": margin.complete,
                    "missing_inputs": tuple(
                        f"economics:{name}" for name in margin.missing_inputs
                    ),
                    "formula": (
                        "sum(gross-discounts-refunds in [0,h)) / customers "
                        "x contribution_margin (cross-artifact economics)"
                    ),
                }
            )
        else:
            component_kwargs.update(
                {
                    "cross_artifact": False,
                    "complete": False,
                    "missing_inputs": ("unit_economics.contribution_margin",),
                }
            )
        horizons.append(HorizonComponent(**component_kwargs))

    curve_totals: dict[tuple[int, int], tuple[int, int]] = {}
    for cohort in admitted:
        for bucket in cohort.age_buckets:
            key = (bucket.age_days_start, bucket.age_days_end)
            customers_seen, orders_seen = curve_totals.get(key, (0, 0))
            curve_totals[key] = (
                customers_seen + cohort.cohort_size,
                orders_seen + bucket.orders,
            )
    curve_points: list[ReorderCurvePoint] = []
    last_end = 0
    skipped_grid_keys = 0
    for (start, end), (customers_seen, orders_seen) in sorted(
        curve_totals.items()
    ):
        if start < last_end:
            # Cohorts bucketed on different grids cannot pool into one honest
            # curve; report the finer-grained truth via a note instead.
            skipped_grid_keys += 1
            continue
        curve_points.append(
            ReorderCurvePoint(
                age_days_start=start,
                age_days_end=end,
                customers=customers_seen,
                orders_per_customer=_quantized_ratio(
                    Decimal(orders_seen) / customers_seen
                ),
            )
        )
        last_end = end
    if skipped_grid_keys:
        notes.append(
            f"cohorts use mismatched age-bucket grids; {skipped_grid_keys} "
            "bucket interval(s) were left out of the reorder curve"
        )
    if len(curve_points) > 24:
        notes.append(
            f"reorder curve truncated to its first 24 of {len(curve_points)} "
            "points"
        )

    # Mandatory honesty labels FIRST: they are part of the artifact's
    # contract and must survive the 20-note cap whatever else accumulated.
    mandatory: list[str] = [
        "cac_ceiling means: spending this much per customer breaks even on "
        "contribution within the named horizon; the horizon choice is a "
        "finance-policy heuristic"
    ]
    observed_horizons = {component.horizon_days for component in horizons}
    unobserved = [
        str(horizon)
        for horizon in VALUE_HORIZONS_DAYS
        if horizon not in observed_horizons
    ]
    if unobserved:
        mandatory.append(
            "no fully-aged cohort exists for the "
            + "/".join(unobserved)
            + "-day horizon(s); customer value there is unknown, not zero"
        )

    all_verified = bool(admitted) and all(
        admitted_verified[cohort.cohort_ref] for cohort in admitted
    )
    status = (
        "host_hmac_verified"
        if scope_keyring is not None and all_verified
        else "caller_supplied_unverified"
    )
    # Never upgrade: contribution components inherit the economics snapshot's
    # own trust label. Caller-typed margin numbers must not surface under
    # the engine's highest label just because the cohorts verified.
    if (
        status == "host_hmac_verified"
        and margin is not None
        and economics is not None
        and horizons
        and economics.evidence_scope_status != "host_hmac_verified"
    ):
        status = "caller_supplied_unverified"
        mandatory.append(
            "the unit economics behind the contribution margin are "
            "caller_supplied_unverified; the snapshot label echoes that "
            "lowest input"
        )
    notes = list(dict.fromkeys([*mandatory, *notes]))
    snapshot_kwargs: dict[str, Any] = {
        "value_ref": parsed.value_ref,
        "analysis_as_of": parsed.analysis_as_of,
        "currency": parsed.currency,
        "evidence_scope_status": status,
        "horizons": tuple(horizons),
        "reorder_curve": tuple(curve_points[:24]),
        "data_quality_notes": tuple(notes[:20]),
        "admitted_cohort_refs": tuple(
            sorted(cohort.cohort_ref for cohort in admitted)
        ),
        "excluded_cohorts": tuple(
            sorted(
                excluded,
                key=lambda item: (
                    item.cohort_ref,
                    item.horizon_days or 0,
                    item.reason,
                ),
            )
        ),
    }
    if margin is not None and economics is not None and horizons:
        snapshot_kwargs["economics_digest"] = economics.economics_digest

    if scope_keyring is None or workflow_scope is None:
        return CustomerValueSnapshot(**snapshot_kwargs)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = CustomerValueSnapshot(
        **snapshot_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        value_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_CUSTOMER_VALUE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"value_digest"},
        exclude_none=True,
    )
    sealed["value_hmac"] = signature
    return CustomerValueSnapshot.model_validate(sealed)


def verify_customer_value_snapshot(
    value: CustomerValueSnapshot | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> CustomerValueSnapshot:
    """Re-validate and verify one sealed value snapshot; raise on failure."""

    snapshot = CustomerValueSnapshot.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, CustomerValueSnapshot)
        else value
    )
    if (
        snapshot.receipt_key_id is None
        or snapshot.exact_scope_digest is None
        or snapshot.value_hmac is None
    ):
        raise GrowthCustomersValidationError(
            "customer value carries no host attestation"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(snapshot.exact_scope_digest, expected_scope_digest):
        raise GrowthCustomersValidationError(
            "customer value attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        domain=_CUSTOMER_VALUE_HMAC_DOMAIN,
        payload=snapshot.hmac_payload(),
    )
    if not hmac.compare_digest(snapshot.value_hmac, expected_hmac):
        raise GrowthCustomersValidationError(
            "customer value attestation failed verification"
        )
    return snapshot


# ---------------------------------------------------------------------------
# Customer value review (advisory)
# ---------------------------------------------------------------------------


class ReviewCustomerValueInput(_StrictModel):
    as_of: str
    customer_value: CustomerValueSnapshot
    unit_economics: UnitEconomicsSnapshot | None = None
    payback_horizon_days: int = Field(default=180, ge=1, le=3_650)

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _canonical_horizon(self) -> "ReviewCustomerValueInput":
        if self.payback_horizon_days not in VALUE_HORIZONS_DAYS:
            raise ValueError(
                "payback_horizon_days must be one of the canonical horizons "
                f"{VALUE_HORIZONS_DAYS}"
            )
        return self


class CustomerValueOpportunity(_StrictModel):
    rank: int = Field(ge=1, le=_MAX_REVIEW_OPPORTUNITIES)
    kind: Literal[
        "raise_acquisition_ceiling",
        "cut_acquisition_spend",
        "run_experiment",
        "collect_evidence",
    ]
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
    def _delta_shape(self) -> "CustomerValueOpportunity":
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
            self.delta_low
            <= self.expected_contribution_delta
            <= self.delta_high
        ):
            raise ValueError("the expected delta must fall inside its interval")
        return self


class CustomerValueReview(_StrictModel):
    """One deterministic answer to "what is a customer worth, and so what"."""

    schema_id: Literal["lightbulb.growth_customer_value_review.v1"] = Field(
        default=GROWTH_CUSTOMER_VALUE_REVIEW_SCHEMA,
        alias="schema",
    )
    as_of: str
    value_digest: Sha256Digest
    economics_digest: Sha256Digest | None = None
    currency: CurrencyCode
    evidence_scope_status: Literal[
        "caller_supplied_unverified", "host_hmac_verified"
    ]
    payback_horizon_days: int = Field(ge=1, le=3_650)
    opportunities: tuple[CustomerValueOpportunity, ...] = Field(
        default_factory=tuple, max_length=_MAX_REVIEW_OPPORTUNITIES
    )
    data_quality_notes: tuple[ShortText, ...] = Field(
        default_factory=tuple, max_length=20
    )
    review_digest: Sha256Digest = "0" * 64

    @field_validator("as_of")
    @classmethod
    def _valid_as_of(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("opportunities", "data_quality_notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _pinned_digest(self) -> "CustomerValueReview":
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


def _scenario(full_close: Decimal) -> tuple[Decimal, Decimal, Decimal]:
    high = _quantized_money(full_close)
    low = _quantized_money(full_close / 2)
    expected = _quantized_money(full_close * Decimal("0.75"))
    return low, expected, high


def review_customer_value(
    inputs: ReviewCustomerValueInput | Mapping[str, Any],
) -> CustomerValueReview:
    """Compare what a customer is worth with what acquisition pays for one.

    Deterministic advice, digest-pinned: it echoes the snapshot's trust
    label (never upgrades), prices ceiling headroom in contribution dollars
    with explicit scenario intervals and named assumptions, and demands the
    evidence it lacks rather than guessing.
    """

    parsed = (
        inputs
        if isinstance(inputs, ReviewCustomerValueInput)
        else ReviewCustomerValueInput.model_validate(inputs)
    )
    snapshot = parsed.customer_value
    as_of_at = _parse_timestamp(parsed.as_of)
    if _parse_timestamp(snapshot.analysis_as_of) > as_of_at:
        raise GrowthCustomersValidationError(
            "the customer value snapshot is from the future of the review as_of"
        )
    economics = parsed.unit_economics
    if economics is not None and economics.currency != snapshot.currency:
        raise GrowthCustomersValidationError(
            "the unit economics and customer value carry different currencies"
        )
    if (
        economics is not None
        and snapshot.economics_digest is not None
        and economics.economics_digest != snapshot.economics_digest
    ):
        raise GrowthCustomersValidationError(
            "the supplied unit economics differ from the ones the customer "
            "value snapshot derived its margin from; rebuild one of them"
        )

    # Review-generated notes come FIRST so inherited snapshot notes can
    # never evict them at the 20-note cap; the inherited tail is appended
    # after and the whole list deduplicated.
    notes: list[str] = []
    candidates: list[dict[str, Any]] = []

    component = snapshot.horizon(parsed.payback_horizon_days)
    cac = (
        economics.component("customer_acquisition_cost")
        if economics is not None
        else None
    )
    new_customers_total = (
        economics.total("new_customers") if economics is not None else None
    )

    if component is None or component.cac_ceiling is None or cac is None:
        missing: list[str] = []
        if component is None:
            missing.append(
                f"a fully-aged cohort for the {parsed.payback_horizon_days}-day "
                "horizon"
            )
        elif component.cac_ceiling is None:
            missing.append(
                "unit economics with a contribution margin sealed INTO the "
                "customer value snapshot (rebuild it supplying unit_economics)"
            )
        if cac is None:
            missing.append(
                "acquisition_cost and new_customers in the contribution ledger"
            )
        # Point at the primitive that fills the FIRST missing piece: the
        # ledger gap needs unit economics, everything else needs a rebuild
        # of the customer value snapshot.
        next_ref = (
            "growth.build_unit_economics"
            if component is not None
            and component.cac_ceiling is not None
            and cac is None
            else "growth.build_customer_value"
        )
        candidates.append(
            {
                "kind": "collect_evidence",
                "title": "Collect the evidence an acquisition ceiling needs",
                "mechanism": (
                    "the ceiling comparison is blind without: "
                    + "; ".join(missing)
                )[:300],
                "expected_contribution_delta": None,
                "delta_low": None,
                "delta_high": None,
                "interval_kind": None,
                "assumptions": (
                    "no revenue impact is claimed for measurement itself",
                ),
                "next_primitive_ref": next_ref,
                "argument_hints": {},
            }
        )
        if (
            component is not None
            and component.cac_ceiling is None
            and economics is not None
        ):
            notes.append(
                "unit economics were supplied to the review but the customer "
                "value snapshot was built without them; the margin cannot be "
                "applied after sealing — rebuild the snapshot"
            )
    else:
        headroom = _quantized_money(component.cac_ceiling - cac.value)
        assumptions = [
            f"{parsed.payback_horizon_days}-day payback tolerance is a "
            "finance-policy heuristic",
            "recent acquisition volume held constant",
        ]
        if not component.complete:
            assumptions.append(
                "the ceiling excludes unknown costs: "
                + ", ".join(component.missing_inputs)
            )
        volume = (
            int(new_customers_total.value)
            if new_customers_total is not None
            else None
        )
        if headroom > 0:
            mechanism = (
                f"observed {parsed.payback_horizon_days}-day contribution LTV "
                f"is {component.cac_ceiling} against CAC {cac.value}; "
                f"first-order math under-prices a customer by {headroom}"
            )
            if volume:
                full = headroom * volume
                low, expected, high = _scenario(full)
                candidates.append(
                    {
                        "kind": "raise_acquisition_ceiling",
                        "title": "Raise the acquisition ceiling",
                        "mechanism": mechanism[:300],
                        "expected_contribution_delta": expected,
                        "delta_low": low,
                        "delta_high": high,
                        "interval_kind": "scenario_half_to_full_close",
                        "assumptions": tuple(assumptions[:5]),
                        "next_primitive_ref": None,
                        "argument_hints": {
                            "cac_ceiling": str(component.cac_ceiling),
                            "current_cac": str(cac.value),
                            "horizon_days": str(parsed.payback_horizon_days),
                        },
                    }
                )
            else:
                candidates.append(
                    {
                        "kind": "raise_acquisition_ceiling",
                        "title": "Raise the acquisition ceiling",
                        "mechanism": mechanism[:300],
                        "expected_contribution_delta": None,
                        "delta_low": None,
                        "delta_high": None,
                        "interval_kind": None,
                        "assumptions": tuple(assumptions[:5]),
                        "next_primitive_ref": None,
                        "argument_hints": {
                            "cac_ceiling": str(component.cac_ceiling),
                            "current_cac": str(cac.value),
                            "horizon_days": str(parsed.payback_horizon_days),
                        },
                    }
                )
        elif headroom < 0:
            overspend = -headroom
            mechanism = (
                f"CAC {cac.value} exceeds the observed "
                f"{parsed.payback_horizon_days}-day contribution LTV of "
                f"{component.cac_ceiling}; every acquired customer is "
                f"{overspend} under water at this payback tolerance"
            )
            body: dict[str, Any] = {
                "kind": "cut_acquisition_spend",
                "title": "Cut acquisition spend or lengthen payback",
                "mechanism": mechanism[:300],
                "expected_contribution_delta": None,
                "delta_low": None,
                "delta_high": None,
                "interval_kind": None,
                "assumptions": tuple(assumptions[:5]),
                "next_primitive_ref": None,
                "argument_hints": {
                    "cac_ceiling": str(component.cac_ceiling),
                    "current_cac": str(cac.value),
                    "horizon_days": str(parsed.payback_horizon_days),
                },
            }
            if volume:
                full = overspend * volume
                low, expected, high = _scenario(full)
                body.update(
                    {
                        "expected_contribution_delta": expected,
                        "delta_low": low,
                        "delta_high": high,
                        "interval_kind": "scenario_half_to_full_close",
                    }
                )
            candidates.append(body)
        else:
            notes.append(
                "CAC sits exactly at the observed ceiling; the acquisition "
                "price is fair at this payback tolerance"
            )

    # The reorder curve names WHEN repeat behavior fades — the honest hook
    # for a preregistered retention experiment, run through the machinery
    # that already exists.
    if len(snapshot.reorder_curve) >= 2:
        peak = max(
            snapshot.reorder_curve, key=lambda point: point.orders_per_customer
        )
        tail = snapshot.reorder_curve[-1]
        if tail.orders_per_customer < peak.orders_per_customer / 2 and (
            tail is not peak
        ):
            candidates.append(
                {
                    "kind": "run_experiment",
                    "title": "Test a retention nudge where reordering fades",
                    "mechanism": (
                        "orders per customer fall from "
                        f"{peak.orders_per_customer} in days "
                        f"[{peak.age_days_start},{peak.age_days_end}) to "
                        f"{tail.orders_per_customer} in days "
                        f"[{tail.age_days_start},{tail.age_days_end}); the "
                        "fade window is where a preregistered "
                        "purchase_to_repeat experiment earns its keep"
                    )[:300],
                    "expected_contribution_delta": None,
                    "delta_low": None,
                    "delta_high": None,
                    "interval_kind": None,
                    "assumptions": (
                        "timing observed from the pooled reorder curve; "
                        "the effect size is unknown until tested",
                    ),
                    "next_primitive_ref": "design_growth_experiment",
                    "argument_hints": {
                        "metric_name": "purchase_to_repeat",
                        "direction": "increase",
                        "trigger_after_days": str(tail.age_days_start),
                        "baseline_source": "funnel_snapshot",
                        "baseline_hint": (
                            "take purchase_to_repeat and its funnel_digest "
                            "from your latest funnel snapshot"
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
        CustomerValueOpportunity(rank=rank, **body)
        for rank, body in enumerate(
            (*with_delta, *without_delta)[:_MAX_REVIEW_OPPORTUNITIES], start=1
        )
    )

    if snapshot.evidence_scope_status == "host_hmac_verified":
        notes.append(
            "trust label echoed from the customer value snapshot without "
            "verification here; verify the seal "
            "(verify_customer_value_snapshot) before acting on it"
        )
    notes = list(dict.fromkeys([*notes, *snapshot.data_quality_notes]))

    return CustomerValueReview(
        as_of=parsed.as_of,
        value_digest=snapshot.value_digest,
        economics_digest=(
            economics.economics_digest if economics is not None else None
        ),
        currency=snapshot.currency,
        evidence_scope_status=snapshot.evidence_scope_status,
        payback_horizon_days=parsed.payback_horizon_days,
        opportunities=opportunities,
        data_quality_notes=tuple(notes[:20]),
    )


# ---------------------------------------------------------------------------
# Executable primitives (read-only; unverified path by design)
# ---------------------------------------------------------------------------

_EXAMPLE_COHORT: dict[str, Any] = {
    "cohort_ref": "cohort-2026-01",
    "connector_account_ref": "acct.shopify.example",
    "provider": "shopify",
    "source_capability": "shopify.analytics_query",
    "currency": "USD",
    "acquisition_window_start": "2026-01-01T00:00:00Z",
    "acquisition_window_end": "2026-02-01T00:00:00Z",
    "observed_at": "2026-08-15T00:00:00Z",
    "cohort_size": 400,
    "age_buckets": [
        {
            "age_days_start": 0,
            "age_days_end": 30,
            "orders": 430,
            "gross_sales": "17200.00",
            "discounts": "860.00",
            "refunds": "500.00",
        },
        {
            "age_days_start": 30,
            "age_days_end": 90,
            "orders": 180,
            "gross_sales": "7400.00",
            "discounts": "360.00",
            "refunds": "220.00",
        },
        {
            "age_days_start": 90,
            "age_days_end": 180,
            "orders": 120,
            "gross_sales": "5000.00",
            "discounts": "240.00",
            "refunds": "150.00",
        },
    ],
    "evidence_digest": "d" * 64,
}

_EXAMPLE_CUSTOMER_VALUE: dict[str, Any] = build_customer_value_snapshot(
    {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "value_ref": "value-example",
        "currency": "USD",
        "cohorts": (_EXAMPLE_COHORT,),
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
        summary="The customer value engine rejected the inputs.",
        blockers=[
            PrimitiveBlocker(
                code="growth_customers_invalid",
                message=str(exc)[:500],
            )
        ],
        retryable=False,
    )


class BuildCustomerValuePrimitive(
    BusinessProcessPrimitive[BuildCustomerValueInput, CustomerValueSnapshot]
):
    """Compile horizon-bounded observed customer value from cohort evidence."""

    primitive_ref = "growth.build_customer_value"
    version = "1.0.0"
    title = "Build customer value"
    description = (
        "Pool sealed or caller-supplied acquisition-cohort envelopes into "
        "horizon-bounded observed customer value: net revenue and orders per "
        "customer at 30/90/180/360 days, contribution LTV and the CAC "
        "ceiling it supports (when unit economics supply a margin), and the "
        "pooled reorder-timing curve. Right-censoring is structural: cohorts "
        "too young for a horizon are excluded with a reason, never averaged "
        "in, and value beyond the observed horizons stays unknown. Runs "
        "without connector calls; host sealing happens server-side."
    )
    input_model = BuildCustomerValueInput
    output_model = CustomerValueSnapshot
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "analysis_as_of": "2026-08-19T00:00:00Z",
        "value_ref": "value-example",
        "currency": "USD",
        "cohorts": [_EXAMPLE_COHORT],
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: BuildCustomerValueInput,
    ) -> PrimitiveExecutionResult[CustomerValueSnapshot]:
        try:
            snapshot = build_customer_value_snapshot(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[CustomerValueSnapshot](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Customer value built: {len(snapshot.horizons)} horizon "
                f"components from {len(snapshot.admitted_cohort_refs)} "
                f"cohorts; {len(snapshot.excluded_cohorts)} exclusions "
                "reported."
            ),
            output=snapshot,
            events=[
                PrimitiveEvent(
                    type="growth.customer_value_built",
                    payload={
                        "value_ref": snapshot.value_ref,
                        "horizons": len(snapshot.horizons),
                        "cohorts": len(snapshot.admitted_cohort_refs),
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Value digest "
                    + snapshot.value_digest[:16]
                    + "… derived from admitted cohorts only.",
                )
            ],
        )


class ReviewCustomerValuePrimitive(
    BusinessProcessPrimitive[ReviewCustomerValueInput, CustomerValueReview]
):
    """Compare observed customer value with the acquisition price paid."""

    primitive_ref = "growth.review_customer_value"
    version = "1.0.0"
    title = "Review customer value"
    description = (
        "Turn a customer value snapshot (plus optional unit economics) into "
        "money-ranked acquisition advice: raise or cut the CAC ceiling with "
        "contribution-dollar scenario intervals against the chosen payback "
        "horizon, a retention-experiment hook where the reorder curve fades, "
        "and collect_evidence demands for whatever the comparison lacks. "
        "The payback horizon is labeled a finance-policy heuristic."
    )
    input_model = ReviewCustomerValueInput
    output_model = CustomerValueReview
    connector_tools = ()
    risk_level = "low"
    approval_required = False
    mcp_read_only = True
    mcp_destructive = False
    mcp_idempotent = True
    mcp_open_world = False
    example_inputs = {
        "as_of": "2026-08-19T01:00:00Z",
        "customer_value": _EXAMPLE_CUSTOMER_VALUE,
    }

    def _execute(
        self,
        context: PrimitiveExecutionContext,
        inputs: ReviewCustomerValueInput,
    ) -> PrimitiveExecutionResult[CustomerValueReview]:
        try:
            review = review_customer_value(inputs)
        except ValueError as exc:
            return _planner_failure(self.primitive_ref, self.version, exc)
        return PrimitiveExecutionResult[CustomerValueReview](
            status=PrimitiveExecutionStatus.COMPLETED,
            primitive_ref=self.primitive_ref,
            primitive_version=self.version,
            summary=(
                f"Customer value review ready: {len(review.opportunities)} "
                f"opportunities at the {review.payback_horizon_days}-day "
                "payback horizon."
            ),
            output=review,
            events=[
                PrimitiveEvent(
                    type="growth.customer_value_reviewed",
                    payload={
                        "opportunities": len(review.opportunities),
                        "horizon_days": review.payback_horizon_days,
                    },
                )
            ],
            evidence=[
                PrimitiveEvidence(
                    kind="deterministic_plan",
                    summary="Review derived from value digest "
                    + review.value_digest[:16]
                    + "…",
                )
            ],
        )


__all__ = [
    "GROWTH_CUSTOMER_COHORT_EVIDENCE_SCHEMA",
    "GROWTH_CUSTOMER_VALUE_REVIEW_SCHEMA",
    "GROWTH_CUSTOMER_VALUE_SCHEMA",
    "VALUE_HORIZONS_DAYS",
    "BuildCustomerValueInput",
    "BuildCustomerValuePrimitive",
    "CohortAgeBucket",
    "CustomerCohortEvidence",
    "CustomerValueOpportunity",
    "CustomerValueReview",
    "CustomerValueSnapshot",
    "ExcludedCohort",
    "GrowthCustomersValidationError",
    "HorizonComponent",
    "ReorderCurvePoint",
    "ReviewCustomerValueInput",
    "ReviewCustomerValuePrimitive",
    "build_customer_value_snapshot",
    "mint_customer_cohort_evidence",
    "review_customer_value",
    "verify_customer_cohort_evidence",
    "verify_customer_value_snapshot",
]
