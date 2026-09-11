"""Preregistered growth experiments with honest, sealed readouts.

Slice 2 of the Lightbulb Growth Engine. The contract this module enforces:

- **The seal is the preregistration.** A design becomes an experiment only
  when :func:`design_growth_experiment` seals it (HMAC over the canonical
  payload, bound to the exact workflow scope). Readouts exist only for sealed
  designs; there is no code path that emits a causal verdict without one.
- **No peeking.** Designs fix a readout horizon. :func:`read_out_growth_experiment`
  raises before the horizon; v1 offers fixed-horizon analysis only rather than
  pretending to alpha-spend.
- **Assignment is keyed and reproducible.** Units are bucketed by host HMAC
  over (design digest, unit id); raw unit identifiers never persist — only a
  keyed unit digest travels in artifacts.
- **Readouts bind to evidence.** Arm observations are sealed envelopes; a
  failing sample-ratio-mismatch check yields ``invalid_assignment``, tiny
  cells yield ``insufficient_data``, and tampering is always an error.

Statistics are implemented with the standard library only (the SDK's
dependency policy): normal CDF via ``math.erf``, normal quantile via Acklam's
rational approximation refined with one Newton step, Student's t via the
regularized incomplete beta continued fraction, and the chi-square survival
function via the regularized incomplete gamma. Internal math uses floats;
sealed artifacts carry Decimals quantized to fixed precision (p-values below
1e-6 round to 0).

See ``docs/growth-engine-design.md``; sealing idioms follow
``docs/growth-engine-build-contract-map.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation
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

GROWTH_EXPERIMENT_DESIGN_SCHEMA = "lightbulb.growth_experiment_design.v1"
GROWTH_EXPERIMENT_ARM_EVIDENCE_SCHEMA = "lightbulb.growth_experiment_arm_evidence.v1"
GROWTH_EXPERIMENT_READOUT_SCHEMA = "lightbulb.growth_experiment_readout.v1"
GROWTH_EXPERIMENT_ASSIGNMENT_SCHEMA = "lightbulb.growth_experiment_assignment.v1"

_DESIGN_HMAC_DOMAIN = GROWTH_EXPERIMENT_DESIGN_SCHEMA
_ARM_EVIDENCE_HMAC_DOMAIN = GROWTH_EXPERIMENT_ARM_EVIDENCE_SCHEMA
_READOUT_HMAC_DOMAIN = GROWTH_EXPERIMENT_READOUT_SCHEMA
_ASSIGNMENT_HMAC_DOMAIN = GROWTH_EXPERIMENT_ASSIGNMENT_SCHEMA
_ASSIGNMENT_BUCKET_DOMAIN = "lightbulb.growth_experiment_assignment_bucket.v1"
_UNIT_DIGEST_DOMAIN = "lightbulb.growth_experiment_unit_digest.v1"

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"

_MAX_GUARDRAILS = 5
_MIN_CELL_COUNT = 10
_SRM_ALPHA = Decimal("0.001000")

AnalyticsProvider = Literal[
    "lightbulb_lifecycle",
    "shopify",
    "hubspot",
    "salesforce",
    "facebook",
    "instagram",
    "linkedin",
    "google_analytics",
]

_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "lightbulb_lifecycle": frozenset({"lightbulb.lifecycle_cohort_outcomes"}),
    "shopify": frozenset({"shopify.analytics_query"}),
    "hubspot": frozenset({"crm.search_deals"}),
    "salesforce": frozenset({"salesforce.pipeline_report"}),
    "facebook": frozenset({"facebook.fetch_metrics"}),
    "instagram": frozenset({"instagram.fetch_metrics"}),
    "linkedin": frozenset({"linkedin.fetch_metrics"}),
    "google_analytics": frozenset({"google_analytics.fetch_metrics"}),
}

MetricKind = Literal["proportion", "continuous"]
ExperimentMetricName = Literal[
    "customer_activation",
    "customer_expansion",
    "reach_to_visit",
    "visit_to_engage",
    "visit_to_purchase",
    "lead_capture",
    "purchase_to_repeat",
    "revenue_per_session",
    "average_order_value",
]
_METRIC_KINDS: dict[str, MetricKind] = {
    "customer_activation": "proportion",
    "customer_expansion": "proportion",
    "reach_to_visit": "proportion",
    "visit_to_engage": "proportion",
    "visit_to_purchase": "proportion",
    "lead_capture": "proportion",
    "purchase_to_repeat": "proportion",
    "revenue_per_session": "continuous",
    "average_order_value": "continuous",
}

HypothesisDirection = Literal["increase", "decrease"]
AssignmentUnit = Literal["visitor", "customer", "session", "store", "campaign"]
BaselineSource = Literal["funnel_snapshot", "manual_estimate"]
ReadoutVerdict = Literal[
    "win",
    "loss",
    "inconclusive",
    "insufficient_data",
    "invalid_assignment",
]


class GrowthExperimentValidationError(ValueError):
    """Experiment content violates the preregistration contract."""


# ---------------------------------------------------------------------------
# Statistics (stdlib only; floats internally, Decimals in sealed artifacts)
# ---------------------------------------------------------------------------


def normal_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


_PPF_A = (
    -3.969683028665376e01,
    2.209460984245205e02,
    -2.759285104469687e02,
    1.383577518672690e02,
    -3.066479806614716e01,
    2.506628277459239e00,
)
_PPF_B = (
    -5.447609879822406e01,
    1.615858368580409e02,
    -1.556989798598866e02,
    6.680131188771972e01,
    -1.328068155288572e01,
)
_PPF_C = (
    -7.784894002430293e-03,
    -3.223964580411365e-01,
    -2.400758277161838e00,
    -2.549732539343734e00,
    4.374664141464968e00,
    2.938163982698783e00,
)
_PPF_D = (
    7.784695709041462e-03,
    3.224671290700398e-01,
    2.445134137142996e00,
    3.754408661907416e00,
)


def normal_ppf(p: float) -> float:
    """Inverse standard normal CDF (Acklam approximation + Newton step)."""

    if not 0.0 < p < 1.0:
        raise GrowthExperimentValidationError(
            "normal quantiles are defined only on (0, 1)"
        )
    p_low = 0.02425
    if p < p_low:
        q = math.sqrt(-2.0 * math.log(p))
        x = (
            (
                (((_PPF_C[0] * q + _PPF_C[1]) * q + _PPF_C[2]) * q + _PPF_C[3]) * q
                + _PPF_C[4]
            )
            * q
            + _PPF_C[5]
        ) / ((((_PPF_D[0] * q + _PPF_D[1]) * q + _PPF_D[2]) * q + _PPF_D[3]) * q + 1.0)
    elif p <= 1.0 - p_low:
        q = p - 0.5
        r = q * q
        x = (
            (
                (
                    (((_PPF_A[0] * r + _PPF_A[1]) * r + _PPF_A[2]) * r + _PPF_A[3]) * r
                    + _PPF_A[4]
                )
                * r
                + _PPF_A[5]
            )
            * q
            / (
                (
                    (((_PPF_B[0] * r + _PPF_B[1]) * r + _PPF_B[2]) * r + _PPF_B[3]) * r
                    + _PPF_B[4]
                )
                * r
                + 1.0
            )
        )
    else:
        q = math.sqrt(-2.0 * math.log(1.0 - p))
        x = -(
            (
                (((_PPF_C[0] * q + _PPF_C[1]) * q + _PPF_C[2]) * q + _PPF_C[3]) * q
                + _PPF_C[4]
            )
            * q
            + _PPF_C[5]
        ) / ((((_PPF_D[0] * q + _PPF_D[1]) * q + _PPF_D[2]) * q + _PPF_D[3]) * q + 1.0)
    # One Newton refinement against the erf-based CDF. Skip it where erf
    # saturates (deep tails): a step computed from a hard 0.0/1.0 CDF value
    # would corrupt the raw Acklam estimate, which is already accurate there.
    cdf = normal_cdf(x)
    if 0.0 < cdf < 1.0:
        density = math.exp(-0.5 * x * x) / math.sqrt(2.0 * math.pi)
        if density > 0.0:
            x -= (cdf - p) / density
    return x


def _betacf(a: float, b: float, x: float) -> float:
    max_iterations = 300
    epsilon = 3.0e-12
    tiny = 1.0e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, max_iterations + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < epsilon:
            return h
    raise GrowthExperimentValidationError(
        "incomplete beta continued fraction failed to converge"
    )


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    if a <= 0.0 or b <= 0.0:
        raise GrowthExperimentValidationError(
            "incomplete beta requires positive shape parameters"
        )
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_bt = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log(1.0 - x)
    )
    bt = math.exp(log_bt)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def student_t_two_sided_p(t_statistic: float, degrees_of_freedom: float) -> float:
    if degrees_of_freedom <= 0.0:
        raise GrowthExperimentValidationError(
            "student t requires positive degrees of freedom"
        )
    x = degrees_of_freedom / (degrees_of_freedom + t_statistic * t_statistic)
    return regularized_incomplete_beta(degrees_of_freedom / 2.0, 0.5, x)


def student_t_two_sided_quantile(alpha: float, degrees_of_freedom: float) -> float:
    """Positive t whose two-sided tail probability equals ``alpha`` (bisection)."""

    if not 0.0 < alpha < 1.0:
        raise GrowthExperimentValidationError(
            "t quantiles are defined only for alpha in (0, 1)"
        )
    if degrees_of_freedom <= 0.0:
        raise GrowthExperimentValidationError(
            "student t requires positive degrees of freedom"
        )
    low, high = 0.0, 1_000.0
    for _ in range(200):
        mid = (low + high) / 2.0
        if student_t_two_sided_p(mid, degrees_of_freedom) > alpha:
            low = mid
        else:
            high = mid
        if high - low < 1e-12:
            break
    return (low + high) / 2.0


def _lower_incomplete_gamma_regularized(a: float, x: float) -> float:
    if x < 0.0 or a <= 0.0:
        raise GrowthExperimentValidationError(
            "incomplete gamma requires positive arguments"
        )
    if x == 0.0:
        return 0.0
    if x < a + 1.0:
        # Series representation.
        term = 1.0 / a
        total = term
        n = a
        for _ in range(500):
            n += 1.0
            term *= x / n
            total += term
            if abs(term) < abs(total) * 3.0e-12:
                break
        else:
            raise GrowthExperimentValidationError(
                "incomplete gamma series failed to converge"
            )
        return total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # Continued fraction for the upper tail.
    tiny = 1.0e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3.0e-12:
            break
    else:
        raise GrowthExperimentValidationError(
            "incomplete gamma continued fraction failed to converge"
        )
    upper = math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    return 1.0 - upper


def chi_square_survival(statistic: float, degrees_of_freedom: int) -> float:
    if degrees_of_freedom < 1:
        raise GrowthExperimentValidationError(
            "chi-square requires at least one degree of freedom"
        )
    if statistic < 0.0:
        raise GrowthExperimentValidationError(
            "chi-square statistics cannot be negative"
        )
    return 1.0 - _lower_incomplete_gamma_regularized(
        degrees_of_freedom / 2.0, statistic / 2.0
    )


def required_sample_per_arm_proportion(
    baseline: float,
    minimum_detectable_effect: float,
    *,
    alpha: float,
    power: float,
    direction: HypothesisDirection,
) -> int:
    """Per-arm n for a two-sided two-proportion test (unpooled variance)."""

    if not 0.0 < baseline < 1.0:
        raise GrowthExperimentValidationError(
            "proportion baselines must fall inside (0, 1)"
        )
    treated = (
        baseline + minimum_detectable_effect
        if direction == "increase"
        else baseline - minimum_detectable_effect
    )
    if not 0.0 < treated < 1.0:
        raise GrowthExperimentValidationError(
            "baseline and minimum detectable effect leave (0, 1)"
        )
    z_alpha = normal_ppf(1.0 - alpha / 2.0)
    z_power = normal_ppf(power)
    variance = baseline * (1.0 - baseline) + treated * (1.0 - treated)
    n = (z_alpha + z_power) ** 2 * variance / (minimum_detectable_effect**2)
    return max(int(math.ceil(n)), 2)


def required_sample_per_arm_continuous(
    standard_deviation: float,
    minimum_detectable_effect: float,
    *,
    alpha: float,
    power: float,
) -> int:
    if standard_deviation <= 0.0:
        raise GrowthExperimentValidationError(
            "continuous designs require a positive baseline standard deviation"
        )
    z_alpha = normal_ppf(1.0 - alpha / 2.0)
    z_power = normal_ppf(power)
    n = (
        2.0
        * (standard_deviation**2)
        * (z_alpha + z_power) ** 2
        / (minimum_detectable_effect**2)
    )
    return max(int(math.ceil(n)), 2)


# ---------------------------------------------------------------------------
# Shared validation helpers (module-local per repo convention)
# ---------------------------------------------------------------------------


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
LongText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=10_000),
    AfterValidator(_bounded_text),
]
PortableRef = Annotated[str, StringConstraints(pattern=_PORTABLE_REF_PATTERN)]
OperationRef = Annotated[str, StringConstraints(pattern=_OPERATION_REF_PATTERN)]
Sha256Digest = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]


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


def _quantized_rate(value: float | Decimal) -> Decimal:
    return Decimal(str(value)).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


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
    except GrowthExperimentValidationError:
        raise
    except Exception as exc:
        raise GrowthExperimentValidationError(
            "the experiment signing key is unavailable"
        ) from exc


def _keyring_signature_bytes(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> bytes:
    try:
        return scope_keyring.sign(key_id, domain, payload)
    except GrowthExperimentValidationError:
        raise
    except Exception as exc:
        raise GrowthExperimentValidationError(
            "the experiment signing key is unavailable"
        ) from exc


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthExperimentValidationError:
        raise
    except Exception as exc:
        raise GrowthExperimentValidationError(
            "the experiment signing key is unavailable"
        ) from exc


def _workflow_scope(
    scope: DynamicWorkflowScope | Mapping[str, Any],
) -> DynamicWorkflowScope:
    if isinstance(scope, DynamicWorkflowScope):
        return scope
    return DynamicWorkflowScope.model_validate(scope)


# ---------------------------------------------------------------------------
# Design artifacts
# ---------------------------------------------------------------------------


class ExperimentHypothesis(_StrictModel):
    metric_name: ExperimentMetricName
    direction: HypothesisDirection
    rationale: LongText

    @property
    def metric_kind(self) -> MetricKind:
        return _METRIC_KINDS[self.metric_name]


class ExperimentVariant(_StrictModel):
    variant_ref: PortableRef
    description: ShortText
    allocation: Decimal = Field(gt=0, lt=1, multiple_of=_RATE_QUANTUM)
    is_control: bool

    @field_validator("allocation", mode="before")
    @classmethod
    def _allocation_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class ExperimentGuardrail(_StrictModel):
    """A preregistered protective intent.

    Sealed into the design so the intent cannot be rewritten, but NOT
    evaluated by the v1 readout (arm evidence carries the primary metric
    only); readouts over guarded designs say so in their notes.
    """

    metric_name: ExperimentMetricName
    max_absolute_degradation: Decimal = Field(gt=0, le=1, multiple_of=_RATE_QUANTUM)

    @field_validator("max_absolute_degradation", mode="before")
    @classmethod
    def _degradation_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class GrowthExperimentDesign(_StrictModel):
    """A sealed preregistration. The HMAC is what makes it an experiment."""

    schema_id: Literal["lightbulb.growth_experiment_design.v1"] = Field(
        default=GROWTH_EXPERIMENT_DESIGN_SCHEMA,
        alias="schema",
    )
    design_ref: PortableRef
    hypothesis: ExperimentHypothesis
    variants: tuple[ExperimentVariant, ...] = Field(min_length=2, max_length=2)
    assignment_unit: AssignmentUnit
    baseline_source: BaselineSource
    baseline_value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    baseline_evidence_digest: Sha256Digest | None = None
    baseline_standard_deviation: Decimal | None = Field(
        default=None, gt=0, multiple_of=_RATE_QUANTUM
    )
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
    required_sample_per_arm: int = Field(ge=2, le=1_000_000_000)
    designed_at: str
    exposure_start: str
    readout_horizon: str
    guardrails: tuple[ExperimentGuardrail, ...] = Field(
        default_factory=tuple, max_length=_MAX_GUARDRAILS
    )
    design_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    design_hmac: Sha256Digest | None = None

    @field_validator(
        "baseline_value",
        "minimum_detectable_effect",
        "alpha",
        "power",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("baseline_standard_deviation", mode="before")
    @classmethod
    def _deviation_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("designed_at", "exposure_start", "readout_horizon")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("variants", "guardrails", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _preregistration_shape(self) -> "GrowthExperimentDesign":
        controls = [variant for variant in self.variants if variant.is_control]
        if len(controls) != 1:
            raise ValueError("designs require exactly one control variant")
        refs = [variant.variant_ref for variant in self.variants]
        if len(refs) != len(set(refs)):
            raise ValueError("variant refs must be unique")
        total_allocation = sum(variant.allocation for variant in self.variants)
        if total_allocation != Decimal("1.000000"):
            raise ValueError("variant allocations must sum to exactly 1")
        kind = self.hypothesis.metric_kind
        if kind == "proportion":
            if self.baseline_value >= 1:
                raise ValueError("proportion baselines must fall inside (0, 1)")
            if self.baseline_value <= 0:
                raise ValueError("proportion baselines must fall inside (0, 1)")
            if self.baseline_standard_deviation is not None:
                raise ValueError(
                    "proportion designs must not carry a baseline deviation"
                )
            treated = (
                self.baseline_value + self.minimum_detectable_effect
                if self.hypothesis.direction == "increase"
                else self.baseline_value - self.minimum_detectable_effect
            )
            if treated <= 0 or treated >= 1:
                raise ValueError("baseline and minimum detectable effect leave (0, 1)")
        else:
            if self.baseline_standard_deviation is None:
                raise ValueError(
                    "continuous designs require a baseline standard deviation"
                )
        if self.baseline_source == "funnel_snapshot":
            if self.baseline_evidence_digest is None:
                raise ValueError("funnel-sourced baselines require the snapshot digest")
        elif self.baseline_evidence_digest is not None:
            raise ValueError("manual estimates must not claim evidence digests")
        guardrail_names = [item.metric_name for item in self.guardrails]
        if len(guardrail_names) != len(set(guardrail_names)):
            raise ValueError("guardrail metrics must be unique")
        if self.hypothesis.metric_name in guardrail_names:
            raise ValueError("the primary metric cannot also be a guardrail")
        designed = _parse_timestamp(self.designed_at)
        exposure = _parse_timestamp(self.exposure_start)
        horizon = _parse_timestamp(self.readout_horizon)
        if exposure < designed:
            raise ValueError("exposure cannot begin before the design exists")
        if horizon <= exposure:
            raise ValueError("the readout horizon must follow exposure start")
        expected_n = _expected_required_sample(self)
        if self.required_sample_per_arm != expected_n:
            raise ValueError(
                "required_sample_per_arm does not match the preregistered "
                "power computation"
            )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.design_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "experiment design attestation fields must be supplied together"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"design_digest", "design_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.design_digest != "0" * 64 and self.design_digest != expected:
            raise ValueError("design_digest does not match the canonical payload")
        object.__setattr__(self, "design_digest", expected)
        return self

    @property
    def is_sealed(self) -> bool:
        return self.design_hmac is not None

    @property
    def control_variant(self) -> ExperimentVariant:
        return next(variant for variant in self.variants if variant.is_control)

    @property
    def treatment_variant(self) -> ExperimentVariant:
        return next(variant for variant in self.variants if not variant.is_control)

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"design_hmac", "design_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _expected_required_sample(design: "GrowthExperimentDesign") -> int:
    if design.hypothesis.metric_kind == "proportion":
        return required_sample_per_arm_proportion(
            float(design.baseline_value),
            float(design.minimum_detectable_effect),
            alpha=float(design.alpha),
            power=float(design.power),
            direction=design.hypothesis.direction,
        )
    return required_sample_per_arm_continuous(
        float(design.baseline_standard_deviation),
        float(design.minimum_detectable_effect),
        alpha=float(design.alpha),
        power=float(design.power),
    )


class DesignGrowthExperimentInput(_StrictModel):
    design_ref: PortableRef
    hypothesis: ExperimentHypothesis
    variants: tuple[ExperimentVariant, ...] = Field(min_length=2, max_length=2)
    assignment_unit: AssignmentUnit
    baseline_source: BaselineSource
    baseline_value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    baseline_evidence_digest: Sha256Digest | None = None
    baseline_standard_deviation: Decimal | None = Field(
        default=None, gt=0, multiple_of=_RATE_QUANTUM
    )
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
    designed_at: str
    exposure_start: str
    readout_horizon: str
    guardrails: tuple[ExperimentGuardrail, ...] = Field(
        default_factory=tuple, max_length=_MAX_GUARDRAILS
    )

    @field_validator(
        "baseline_value",
        "minimum_detectable_effect",
        "alpha",
        "power",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("baseline_standard_deviation", mode="before")
    @classmethod
    def _deviation_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("designed_at", "exposure_start", "readout_horizon")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("variants", "guardrails", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)


def design_growth_experiment(
    inputs: DesignGrowthExperimentInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthExperimentDesign:
    """Compute the power analysis and seal the preregistration."""

    parsed = (
        inputs
        if isinstance(inputs, DesignGrowthExperimentInput)
        else DesignGrowthExperimentInput.model_validate(inputs)
    )
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    body = parsed.model_dump(mode="python", exclude_none=True)
    probe = GrowthExperimentDesign.model_validate(
        {
            **body,
            "required_sample_per_arm": _required_sample_for_input(parsed),
        }
    )
    draft = GrowthExperimentDesign.model_validate(
        {
            **probe.model_dump(
                mode="python",
                by_alias=True,
                exclude={"design_digest"},
                exclude_none=True,
            ),
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "design_hmac": "0" * 64,
        }
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_DESIGN_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"design_digest"},
        exclude_none=True,
    )
    sealed["design_hmac"] = signature
    return GrowthExperimentDesign.model_validate(sealed)


def _required_sample_for_input(parsed: DesignGrowthExperimentInput) -> int:
    if _METRIC_KINDS[parsed.hypothesis.metric_name] == "proportion":
        return required_sample_per_arm_proportion(
            float(parsed.baseline_value),
            float(parsed.minimum_detectable_effect),
            alpha=float(parsed.alpha),
            power=float(parsed.power),
            direction=parsed.hypothesis.direction,
        )
    if parsed.baseline_standard_deviation is None:
        raise GrowthExperimentValidationError(
            "continuous designs require a baseline standard deviation"
        )
    return required_sample_per_arm_continuous(
        float(parsed.baseline_standard_deviation),
        float(parsed.minimum_detectable_effect),
        alpha=float(parsed.alpha),
        power=float(parsed.power),
    )


def verify_growth_experiment_design(
    value: GrowthExperimentDesign | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthExperimentDesign:
    design = GrowthExperimentDesign.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthExperimentDesign)
        else value
    )
    if (
        design.receipt_key_id is None
        or design.exact_scope_digest is None
        or design.design_hmac is None
    ):
        raise GrowthExperimentValidationError(
            "the experiment design carries no preregistration seal"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=design.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(design.exact_scope_digest, expected_scope_digest):
        raise GrowthExperimentValidationError(
            "experiment design attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=design.receipt_key_id,
        domain=_DESIGN_HMAC_DOMAIN,
        payload=design.hmac_payload(),
    )
    if not hmac.compare_digest(design.design_hmac, expected_hmac):
        raise GrowthExperimentValidationError(
            "experiment design attestation failed verification"
        )
    return design


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------


class ExperimentAssignment(_StrictModel):
    schema_id: Literal["lightbulb.growth_experiment_assignment.v1"] = Field(
        default=GROWTH_EXPERIMENT_ASSIGNMENT_SCHEMA,
        alias="schema",
    )
    design_digest: Sha256Digest
    unit_digest: Sha256Digest
    variant_ref: PortableRef
    bucket: Decimal = Field(ge=0, lt=1, multiple_of=_RATE_QUANTUM)
    receipt_key_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest
    assignment_hmac: Sha256Digest

    @field_validator("bucket", mode="before")
    @classmethod
    def _bucket_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"assignment_hmac"},
            exclude_none=True,
        )


def assign_experiment_unit(
    design: GrowthExperimentDesign | Mapping[str, Any],
    unit_id: str,
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ExperimentAssignment:
    """Deterministically assign one unit; the raw unit id never persists."""

    verified = verify_growth_experiment_design(
        design, scope=scope, scope_keyring=scope_keyring
    )
    clean_unit = unit_id.strip()
    if not clean_unit or len(clean_unit) > 300:
        raise GrowthExperimentValidationError(
            "assignment unit ids must contain 1-300 characters"
        )
    key_id = verified.receipt_key_id
    assert key_id is not None  # verified above
    raw = _keyring_signature_bytes(
        scope_keyring,
        key_id=key_id,
        domain=_ASSIGNMENT_BUCKET_DOMAIN,
        payload={"design_digest": verified.design_digest, "unit_id": clean_unit},
    )
    bucket_value = int.from_bytes(raw[:8], "big") / float(2**64)
    cumulative = 0.0
    chosen = verified.variants[-1].variant_ref
    for variant in verified.variants:
        cumulative += float(variant.allocation)
        if bucket_value < cumulative:
            chosen = variant.variant_ref
            break
    unit_digest = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_UNIT_DIGEST_DOMAIN,
        payload={"design_digest": verified.design_digest, "unit_id": clean_unit},
    )
    body = {
        "design_digest": verified.design_digest,
        "unit_digest": unit_digest,
        "variant_ref": chosen,
        # Floor keeps the stored 6dp bucket strictly below 1 and never on the
        # wrong side of a variant boundary relative to the full-precision draw.
        "bucket": Decimal(str(bucket_value)).quantize(
            _RATE_QUANTUM, rounding=ROUND_FLOOR
        ),
        "receipt_key_id": key_id,
        "exact_scope_digest": verified.exact_scope_digest,
        "assignment_hmac": "0" * 64,
    }
    draft = ExperimentAssignment.model_validate(body)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_ASSIGNMENT_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", by_alias=True, exclude_none=True)
    sealed["assignment_hmac"] = signature
    return ExperimentAssignment.model_validate(sealed)


def verify_experiment_assignment(
    value: ExperimentAssignment | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ExperimentAssignment:
    """Re-validate and verify one sealed assignment record; raise on failure."""

    assignment = ExperimentAssignment.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, ExperimentAssignment)
        else value
    )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=assignment.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(assignment.exact_scope_digest, expected_scope_digest):
        raise GrowthExperimentValidationError(
            "assignment attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=assignment.receipt_key_id,
        domain=_ASSIGNMENT_HMAC_DOMAIN,
        payload=assignment.hmac_payload(),
    )
    if not hmac.compare_digest(assignment.assignment_hmac, expected_hmac):
        raise GrowthExperimentValidationError(
            "assignment attestation failed verification"
        )
    return assignment


# ---------------------------------------------------------------------------
# Arm evidence
# ---------------------------------------------------------------------------


class ExperimentArmEvidence(_StrictModel):
    """Sealed per-arm outcome totals gathered after exposure."""

    schema_id: Literal["lightbulb.growth_experiment_arm_evidence.v1"] = Field(
        default=GROWTH_EXPERIMENT_ARM_EVIDENCE_SCHEMA,
        alias="schema",
    )
    observation_ref: PortableRef
    design_digest: Sha256Digest
    variant_ref: PortableRef
    metric_kind: MetricKind
    connector_account_ref: OperationRef
    provider: AnalyticsProvider
    source_capability: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.[a-z][a-z0-9_.-]{0,127}$",
    )
    observed_at: str
    window_start: str
    window_end: str
    successes: int | None = Field(default=None, ge=0, le=10_000_000_000)
    trials: int | None = Field(default=None, ge=0, le=10_000_000_000)
    sample_count: int | None = Field(default=None, ge=0, le=10_000_000_000)
    sample_mean: Decimal | None = Field(default=None, ge=0)
    sample_variance: Decimal | None = Field(default=None, ge=0)
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    arm_hmac: Sha256Digest | None = None

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("sample_mean", "sample_variance", mode="before")
    @classmethod
    def _sample_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _kind_consistency(self) -> "ExperimentArmEvidence":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("evidence window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede the measured window")
        proportion_fields = (self.successes, self.trials)
        continuous_fields = (
            self.sample_count,
            self.sample_mean,
            self.sample_variance,
        )
        if self.metric_kind == "proportion":
            if any(value is None for value in proportion_fields) or any(
                value is not None for value in continuous_fields
            ):
                raise ValueError(
                    "proportion arm evidence carries successes and trials only"
                )
            if self.successes > self.trials:
                raise ValueError("successes cannot exceed trials")
        else:
            if any(value is None for value in continuous_fields) or any(
                value is not None for value in proportion_fields
            ):
                raise ValueError(
                    "continuous arm evidence carries count, mean, and variance"
                )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.arm_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "arm evidence attestation fields must be supplied together"
            )
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"arm_hmac"},
            exclude_none=True,
        )


def mint_experiment_arm_evidence(
    value: ExperimentArmEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> ExperimentArmEvidence:
    evidence = (
        value
        if isinstance(value, ExperimentArmEvidence)
        else ExperimentArmEvidence.model_validate(value)
    )
    if evidence.arm_hmac is not None or evidence.receipt_key_id is not None:
        raise GrowthExperimentValidationError("arm evidence is already attested")
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    payload = evidence.model_dump(mode="python", by_alias=True, exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "arm_hmac": "0" * 64,
        }
    )
    draft = ExperimentArmEvidence.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_ARM_EVIDENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", by_alias=True, exclude_none=True)
    sealed["arm_hmac"] = signature
    return ExperimentArmEvidence.model_validate(sealed)


def verify_experiment_arm_evidence(
    value: ExperimentArmEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> ExperimentArmEvidence:
    evidence = ExperimentArmEvidence.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, ExperimentArmEvidence)
        else value
    )
    if (
        evidence.receipt_key_id is None
        or evidence.exact_scope_digest is None
        or evidence.arm_hmac is None
    ):
        raise GrowthExperimentValidationError(
            "arm evidence carries no host attestation"
        )
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(evidence.exact_scope_digest, expected_scope_digest):
        raise GrowthExperimentValidationError(
            "arm evidence attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        domain=_ARM_EVIDENCE_HMAC_DOMAIN,
        payload=evidence.hmac_payload(),
    )
    if not hmac.compare_digest(evidence.arm_hmac, expected_hmac):
        raise GrowthExperimentValidationError(
            "arm evidence attestation failed verification"
        )
    return evidence


# ---------------------------------------------------------------------------
# Readout
# ---------------------------------------------------------------------------


class ReadoutArm(_StrictModel):
    variant_ref: PortableRef
    is_control: bool
    trials: int | None = Field(default=None, ge=0)
    successes: int | None = Field(default=None, ge=0)
    sample_count: int | None = Field(default=None, ge=0)
    sample_mean: Decimal | None = Field(default=None, ge=0)
    sample_variance: Decimal | None = Field(default=None, ge=0)
    evidence_digest: Sha256Digest

    @field_validator("sample_mean", "sample_variance", mode="before")
    @classmethod
    def _sample_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)


class SampleRatioCheck(_StrictModel):
    expected_control_share: Decimal = Field(gt=0, lt=1, multiple_of=_RATE_QUANTUM)
    observed_control: int = Field(ge=0)
    observed_treatment: int = Field(ge=0)
    p_value: Decimal = Field(ge=0, le=1, multiple_of=_RATE_QUANTUM)
    passed: bool

    @field_validator("expected_control_share", "p_value", mode="before")
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class GuardrailBreach(_StrictModel):
    metric_name: ExperimentMetricName
    control_value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    treatment_value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    max_absolute_degradation: Decimal = Field(gt=0, le=1, multiple_of=_RATE_QUANTUM)

    @field_validator(
        "control_value",
        "treatment_value",
        "max_absolute_degradation",
        mode="before",
    )
    @classmethod
    def _rate_decimals(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class GrowthExperimentReadout(_StrictModel):
    """A sealed verdict bound to its preregistered design by digest."""

    schema_id: Literal["lightbulb.growth_experiment_readout.v1"] = Field(
        default=GROWTH_EXPERIMENT_READOUT_SCHEMA,
        alias="schema",
    )
    readout_ref: PortableRef
    design_digest: Sha256Digest
    metric_name: ExperimentMetricName
    metric_kind: MetricKind
    direction: HypothesisDirection
    analysis_as_of: str
    arms: tuple[ReadoutArm, ...] = Field(min_length=2, max_length=2)
    sample_ratio_check: SampleRatioCheck
    test_used: Literal["two_proportion_z", "welch_t", "none"]
    effect_estimate: Decimal | None = None
    ci_low: Decimal | None = None
    ci_high: Decimal | None = None
    p_value: Decimal | None = Field(default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM)
    verdict: ReadoutVerdict
    causal: bool
    underpowered: bool
    guardrail_breaches: tuple[GuardrailBreach, ...] = Field(default_factory=tuple)
    notes: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=10)
    readout_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    readout_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator("effect_estimate", "ci_low", "ci_high", mode="before")
    @classmethod
    def _effect_decimals(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("p_value", mode="before")
    @classmethod
    def _p_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @field_validator("arms", "guardrail_breaches", "notes", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _verdict_shape(self) -> "GrowthExperimentReadout":
        controls = [arm for arm in self.arms if arm.is_control]
        if len(controls) != 1:
            raise ValueError("readouts require exactly one control arm")
        statistical = self.verdict in {"win", "loss", "inconclusive"}
        has_stats = (
            self.effect_estimate is not None
            and self.ci_low is not None
            and self.ci_high is not None
            and self.p_value is not None
            and self.test_used != "none"
        )
        if statistical != has_stats:
            raise ValueError(
                "statistical verdicts and effect statistics must appear together"
            )
        if self.verdict == "invalid_assignment" and self.sample_ratio_check.passed:
            raise ValueError("invalid_assignment requires a failing sample ratio check")
        if self.verdict == "win" and self.guardrail_breaches:
            raise ValueError("a win cannot coexist with guardrail breaches")
        if self.causal and self.verdict not in {"win", "loss", "inconclusive"}:
            raise ValueError("causal readouts require a statistical verdict")
        if self.causal and not self.sample_ratio_check.passed:
            raise ValueError("causal readouts require a passing sample ratio check")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.readout_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError("readout attestation fields must be supplied together")
        if self.causal and self.readout_hmac is None:
            raise ValueError("causal readouts must be host sealed")
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"readout_digest", "readout_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.readout_digest != "0" * 64 and self.readout_digest != expected:
            raise ValueError("readout_digest does not match the canonical payload")
        object.__setattr__(self, "readout_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"readout_hmac", "readout_digest"},
            exclude_none=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _clamped_p_value(p: float) -> Decimal:
    return _quantized_rate(min(max(p, 0.0), 1.0))


def read_out_growth_experiment(
    design: GrowthExperimentDesign | Mapping[str, Any],
    arm_evidence: tuple[ExperimentArmEvidence | Mapping[str, Any], ...]
    | list[ExperimentArmEvidence | Mapping[str, Any]],
    *,
    readout_ref: str,
    analysis_as_of: str,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthExperimentReadout:
    """Produce the sealed fixed-horizon readout for a preregistered design.

    Hard failures (exceptions): unsealed or tampered design, tampered or
    missing arm evidence, evidence outside the design's measurement window,
    or a readout attempted before the preregistered horizon. Everything else
    is an honest verdict on the sealed artifact.
    """

    verified_design = verify_growth_experiment_design(
        design, scope=scope, scope_keyring=scope_keyring
    )
    analysis_at = _parse_timestamp(_normalized_timestamp(analysis_as_of))
    horizon = _parse_timestamp(verified_design.readout_horizon)
    if analysis_at < horizon:
        raise GrowthExperimentValidationError(
            "readout requested before the preregistered horizon; fixed-horizon "
            "designs do not support interim analyses"
        )
    evidence_list = [
        verify_experiment_arm_evidence(item, scope=scope, scope_keyring=scope_keyring)
        for item in arm_evidence
    ]
    if len(evidence_list) != 2:
        raise GrowthExperimentValidationError(
            "readouts require exactly one sealed evidence envelope per arm"
        )
    by_variant: dict[str, ExperimentArmEvidence] = {}
    for item in evidence_list:
        if item.design_digest != verified_design.design_digest:
            raise GrowthExperimentValidationError(
                "arm evidence is bound to a different design"
            )
        if item.metric_kind != verified_design.hypothesis.metric_kind:
            raise GrowthExperimentValidationError(
                "arm evidence metric kind does not match the design"
            )
        if item.variant_ref in by_variant:
            raise GrowthExperimentValidationError(
                "duplicate arm evidence for one variant"
            )
        exposure = _parse_timestamp(verified_design.exposure_start)
        # Both arms must cover exactly the preregistered measurement window:
        # allowing shorter or shifted windows lets a caller compare disjoint
        # periods (seasonal confounds) or truncate the moment a difference
        # looks significant, defeating the fixed-horizon guarantee.
        if _parse_timestamp(item.window_start) != exposure or (
            _parse_timestamp(item.window_end) != horizon
        ):
            raise GrowthExperimentValidationError(
                "arm evidence must cover exactly the preregistered measurement "
                "window from exposure start to the readout horizon"
            )
        by_variant[item.variant_ref] = item
    expected_variants = {variant.variant_ref for variant in verified_design.variants}
    if set(by_variant) != expected_variants:
        raise GrowthExperimentValidationError(
            "arm evidence must cover exactly the design variants"
        )

    control = by_variant[verified_design.control_variant.variant_ref]
    treatment = by_variant[verified_design.treatment_variant.variant_ref]
    kind = verified_design.hypothesis.metric_kind

    if kind == "proportion":
        control_n = control.trials or 0
        treatment_n = treatment.trials or 0
    else:
        control_n = control.sample_count or 0
        treatment_n = treatment.sample_count or 0

    # Sample ratio mismatch: chi-square against preregistered allocations.
    expected_control_share = float(verified_design.control_variant.allocation)
    total = control_n + treatment_n
    if total > 0:
        expected_control = total * expected_control_share
        expected_treatment = total * (1.0 - expected_control_share)
        statistic = 0.0
        if expected_control > 0:
            statistic += (control_n - expected_control) ** 2 / expected_control
        if expected_treatment > 0:
            statistic += (treatment_n - expected_treatment) ** 2 / expected_treatment
        srm_p = chi_square_survival(statistic, 1)
    else:
        srm_p = 1.0
    sealed_srm_p = _clamped_p_value(srm_p)
    # Decide on the sealed 6dp value so the artifact cannot contradict itself.
    srm_passed = sealed_srm_p >= _SRM_ALPHA
    srm = SampleRatioCheck(
        expected_control_share=_quantized_rate(expected_control_share),
        observed_control=control_n,
        observed_treatment=treatment_n,
        p_value=sealed_srm_p,
        passed=srm_passed,
    )

    arms = tuple(
        ReadoutArm(
            variant_ref=item.variant_ref,
            is_control=item.variant_ref == verified_design.control_variant.variant_ref,
            trials=item.trials,
            successes=item.successes,
            sample_count=item.sample_count,
            sample_mean=item.sample_mean,
            sample_variance=item.sample_variance,
            evidence_digest=item.evidence_digest,
        )
        for item in (control, treatment)
    )

    notes: list[str] = []
    underpowered = min(control_n, treatment_n) < verified_design.required_sample_per_arm
    if underpowered:
        notes.append(
            "underpowered: at least one arm is below the preregistered "
            "required sample size"
        )

    base_kwargs: dict[str, Any] = {
        "readout_ref": readout_ref,
        "design_digest": verified_design.design_digest,
        "metric_name": verified_design.hypothesis.metric_name,
        "metric_kind": kind,
        "direction": verified_design.hypothesis.direction,
        "analysis_as_of": _normalized_timestamp(analysis_as_of),
        "arms": arms,
        "sample_ratio_check": srm,
        "underpowered": underpowered,
    }

    if not srm_passed:
        notes.append("sample ratio mismatch: assignment integrity is suspect")
        return _seal_readout(
            {
                **base_kwargs,
                "test_used": "none",
                "verdict": "invalid_assignment",
                "causal": False,
                "notes": tuple(notes),
            },
            scope=scope,
            scope_keyring=scope_keyring,
            scope_key_id=scope_key_id,
        )

    if kind == "proportion":
        insufficient = (
            min(
                control.successes or 0,
                (control.trials or 0) - (control.successes or 0),
                treatment.successes or 0,
                (treatment.trials or 0) - (treatment.successes or 0),
            )
            < _MIN_CELL_COUNT
        )
    else:
        insufficient = min(control_n, treatment_n) < 2
    if insufficient:
        notes.append(
            "insufficient data: cells are too small for the preregistered test"
        )
        return _seal_readout(
            {
                **base_kwargs,
                "test_used": "none",
                "verdict": "insufficient_data",
                "causal": False,
                "notes": tuple(notes),
            },
            scope=scope,
            scope_keyring=scope_keyring,
            scope_key_id=scope_key_id,
        )

    alpha = float(verified_design.alpha)
    if kind == "proportion":
        p_control = (control.successes or 0) / control_n
        p_treatment = (treatment.successes or 0) / treatment_n
        effect = p_treatment - p_control
        pooled = ((control.successes or 0) + (treatment.successes or 0)) / total
        pooled_se = math.sqrt(
            pooled * (1.0 - pooled) * (1.0 / control_n + 1.0 / treatment_n)
        )
        if pooled_se == 0.0:
            z = 0.0
            p_value = 1.0
        else:
            z = effect / pooled_se
            p_value = 2.0 * (1.0 - normal_cdf(abs(z)))
        unpooled_se = math.sqrt(
            p_control * (1.0 - p_control) / control_n
            + p_treatment * (1.0 - p_treatment) / treatment_n
        )
        margin = normal_ppf(1.0 - alpha / 2.0) * unpooled_se
        ci_low = effect - margin
        ci_high = effect + margin
        test_used = "two_proportion_z"
    else:
        mean_control = float(control.sample_mean or 0)
        mean_treatment = float(treatment.sample_mean or 0)
        var_control = float(control.sample_variance or 0)
        var_treatment = float(treatment.sample_variance or 0)
        effect = mean_treatment - mean_control
        se_sq = var_control / control_n + var_treatment / treatment_n
        if se_sq <= 0.0:
            if effect != 0.0:
                # Zero reported variance cannot support inference about a
                # nonzero difference; refusing beats sealing a contradictory
                # p-value and interval.
                notes.append(
                    "insufficient data: zero-variance arms cannot support "
                    "inference about a nonzero difference"
                )
                return _seal_readout(
                    {
                        **base_kwargs,
                        "test_used": "none",
                        "verdict": "insufficient_data",
                        "causal": False,
                        "notes": tuple(notes),
                    },
                    scope=scope,
                    scope_keyring=scope_keyring,
                    scope_key_id=scope_key_id,
                )
            t_stat = 0.0
            p_value = 1.0
            df = float(control_n + treatment_n - 2)
        else:
            se = math.sqrt(se_sq)
            t_stat = effect / se
            df_numerator = se_sq**2
            df_denominator = (var_control / control_n) ** 2 / (control_n - 1) + (
                var_treatment / treatment_n
            ) ** 2 / (treatment_n - 1)
            df = (
                df_numerator / df_denominator
                if df_denominator > 0
                else float(control_n + treatment_n - 2)
            )
            p_value = student_t_two_sided_p(t_stat, df)
        # The CI must match the test that produced the p-value: Welch's t
        # quantile, not the normal quantile, or small-n intervals undercover.
        margin = student_t_two_sided_quantile(alpha, df) * math.sqrt(max(se_sq, 0.0))
        ci_low = effect - margin
        ci_high = effect + margin
        test_used = "welch_t"

    sealed_p_value = _clamped_p_value(p_value)
    # Decide significance on the sealed 6dp values so the sealed verdict and
    # the sealed p-value cannot disagree at the alpha boundary.
    significant = sealed_p_value < verified_design.alpha
    direction = verified_design.hypothesis.direction
    beneficial = effect > 0 if direction == "increase" else effect < 0
    if significant and beneficial:
        verdict: ReadoutVerdict = "win"
    elif significant:
        verdict = "loss"
    else:
        verdict = "inconclusive"

    # Guardrails are preregistered intent only in this readout version: arm
    # evidence carries the primary metric alone, so breaches cannot be
    # evaluated here. Say so in the sealed artifact rather than letting an
    # empty tuple read as an affirmative clean bill.
    if verified_design.guardrails:
        notes.append(
            "guardrails were preregistered but are not evaluated by this "
            "readout version; the verdict reflects the primary metric only"
        )

    return _seal_readout(
        {
            **base_kwargs,
            "test_used": test_used,
            "effect_estimate": _quantized_rate(effect),
            "ci_low": _quantized_rate(ci_low),
            "ci_high": _quantized_rate(ci_high),
            "p_value": sealed_p_value,
            "verdict": verdict,
            "causal": True,
            "guardrail_breaches": (),
            "notes": tuple(notes),
        },
        scope=scope,
        scope_keyring=scope_keyring,
        scope_key_id=scope_key_id,
    )


def _seal_readout(
    body: dict[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None,
) -> GrowthExperimentReadout:
    workflow_scope = _workflow_scope(scope)
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring, key_id=key_id, scope=workflow_scope
    )
    draft = GrowthExperimentReadout.model_validate(
        {
            **body,
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "readout_hmac": "0" * 64,
        }
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_READOUT_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"readout_digest"},
        exclude_none=True,
    )
    sealed["readout_hmac"] = signature
    return GrowthExperimentReadout.model_validate(sealed)


def verify_growth_experiment_readout(
    value: GrowthExperimentReadout | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthExperimentReadout:
    readout = GrowthExperimentReadout.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthExperimentReadout)
        else value
    )
    if (
        readout.receipt_key_id is None
        or readout.exact_scope_digest is None
        or readout.readout_hmac is None
    ):
        raise GrowthExperimentValidationError("the readout carries no host attestation")
    workflow_scope = _workflow_scope(scope)
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=readout.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(readout.exact_scope_digest, expected_scope_digest):
        raise GrowthExperimentValidationError("readout attestation failed verification")
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=readout.receipt_key_id,
        domain=_READOUT_HMAC_DOMAIN,
        payload=readout.hmac_payload(),
    )
    if not hmac.compare_digest(readout.readout_hmac, expected_hmac):
        raise GrowthExperimentValidationError("readout attestation failed verification")
    return readout


__all__ = [
    "GROWTH_EXPERIMENT_ARM_EVIDENCE_SCHEMA",
    "GROWTH_EXPERIMENT_ASSIGNMENT_SCHEMA",
    "GROWTH_EXPERIMENT_DESIGN_SCHEMA",
    "GROWTH_EXPERIMENT_READOUT_SCHEMA",
    "DesignGrowthExperimentInput",
    "ExperimentArmEvidence",
    "ExperimentAssignment",
    "ExperimentGuardrail",
    "ExperimentHypothesis",
    "ExperimentVariant",
    "GrowthExperimentDesign",
    "GrowthExperimentReadout",
    "GrowthExperimentValidationError",
    "GuardrailBreach",
    "ReadoutArm",
    "SampleRatioCheck",
    "assign_experiment_unit",
    "chi_square_survival",
    "design_growth_experiment",
    "mint_experiment_arm_evidence",
    "normal_cdf",
    "normal_ppf",
    "read_out_growth_experiment",
    "regularized_incomplete_beta",
    "required_sample_per_arm_continuous",
    "required_sample_per_arm_proportion",
    "student_t_two_sided_p",
    "student_t_two_sided_quantile",
    "verify_experiment_arm_evidence",
    "verify_experiment_assignment",
    "verify_growth_experiment_design",
    "verify_growth_experiment_readout",
]
