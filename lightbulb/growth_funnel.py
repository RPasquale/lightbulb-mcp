"""Cross-connector growth funnel model with sealed analytics evidence.

This module is slice 1 of the Lightbulb Growth Engine: it turns per-connector
analytics observations (Shopify, HubSpot, Salesforce, Meta, LinkedIn, Google
Analytics) into one canonical six-stage growth funnel snapshot that downstream
planners, experiment designs, and the agent cockpit can trust.

Design rules enforced here:

- **Evidence is sealed.** Funnel snapshots are computed from
  :class:`GrowthFunnelEvidence` envelopes. A trusted host seals envelopes with
  :func:`mint_growth_funnel_evidence`; verification recomputes the keyed HMAC,
  so copying a visible scope digest onto fabricated metrics is insufficient.
- **Unknown is not zero.** A stage with no admissible evidence reports
  ``completeness="unknown"``; nothing is imputed.
- **Bases never silently mix.** Every provider maps to one measurement basis
  (platform-reported, site-measured, commerce-recorded, CRM-recorded); totals
  aggregate within a basis and cross-basis rates are explicitly labeled.
- **Exclusions are visible.** Evidence rejected for staleness, future
  observation, or missing verification is reported with its reason, never
  silently dropped. Attested evidence that fails verification is an error.
- **References are honest.** Bottleneck detection names the reference it used;
  static defaults are labeled ``default_heuristic``, never presented as
  benchmarks.

Naming note: ``lightbulb/growth_primitives.py`` predates this module and holds
generic catalog-promoted primitives unrelated to growth analytics; the Growth
Engine lives in the ``growth_funnel`` / ``growth_experiments`` /
``growth_learnings`` module family.

Rail alignment: the evidence envelope mirrors the execution rail's analytics
snapshot contract (field names, attestation trio, window laws) at the dict
boundary only — no imports. :func:`verify_growth_funnel_evidence` also accepts
envelopes sealed under the rail's analytics HMAC domain so host-verified rail
observations can feed the funnel without re-minting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
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

GROWTH_FUNNEL_EVIDENCE_SCHEMA = "lightbulb.growth_funnel_evidence.v2"
GROWTH_FUNNEL_SNAPSHOT_SCHEMA = "lightbulb.growth_funnel_snapshot.v2"

_GROWTH_FUNNEL_EVIDENCE_HMAC_DOMAIN = GROWTH_FUNNEL_EVIDENCE_SCHEMA
_GROWTH_FUNNEL_SNAPSHOT_HMAC_DOMAIN = GROWTH_FUNNEL_SNAPSHOT_SCHEMA
_LEGACY_GROWTH_FUNNEL_EVIDENCE_SCHEMA = "lightbulb.growth_funnel_evidence.v1"
# The execution rail's analytics domain, duplicated at the dict boundary so
# host-sealed rail observations can be admitted without importing rail code.
_RAIL_ANALYTICS_HMAC_DOMAIN = "lightbulb.product_launch_analytics_snapshot.v1"

_MAX_FUNNEL_EVIDENCE = 200
_MAX_REFERENCE_RATES = 10
_MAX_EXPECTED_CONTRIBUTIONS = 100

_RATE_QUANTUM = Decimal("0.000001")
_MONEY_QUANTUM = Decimal("0.01")
_COUNT_QUANTUM = Decimal("1")

_PORTABLE_REF_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
_OPERATION_REF_PATTERN = r"^[a-z][a-z0-9_.:-]{0,159}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)
_CURRENCY_PATTERN = r"^[A-Z]{3}$"

CurrencyCode = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]

AnalyticsProvider = Literal[
    "shopify",
    "hubspot",
    "salesforce",
    "facebook",
    "instagram",
    "linkedin",
    "google_analytics",
]

_SOURCE_CAPABILITIES: dict[str, frozenset[str]] = {
    "shopify": frozenset({"shopify.analytics_query"}),
    "hubspot": frozenset({"crm.search_deals"}),
    "salesforce": frozenset({"salesforce.pipeline_report"}),
    "facebook": frozenset({"facebook.fetch_metrics"}),
    "instagram": frozenset({"instagram.fetch_metrics"}),
    "linkedin": frozenset({"linkedin.fetch_metrics"}),
    "google_analytics": frozenset({"google_analytics.fetch_metrics"}),
}

FunnelBasis = Literal[
    "platform_reported",
    "site_measured",
    "commerce_recorded",
    "crm_recorded",
]

_PROVIDER_BASIS: dict[str, FunnelBasis] = {
    "shopify": "commerce_recorded",
    "google_analytics": "site_measured",
    "hubspot": "crm_recorded",
    "salesforce": "crm_recorded",
    "facebook": "platform_reported",
    "instagram": "platform_reported",
    "linkedin": "platform_reported",
}

FunnelStage = Literal[
    "audience",
    "traffic",
    "engagement",
    "conversion",
    "revenue",
    "retention",
]

_FUNNEL_STAGES: tuple[FunnelStage, ...] = (
    "audience",
    "traffic",
    "engagement",
    "conversion",
    "revenue",
    "retention",
)

MetricName = Literal[
    "impressions",
    "followers",
    "list_size",
    "sessions",
    "clicks",
    "unique_visitors",
    "engagements",
    "leads",
    "opportunities",
    "checkouts_started",
    "conversions",
    "orders",
    "won_deals",
    "revenue",
    "repeat_orders",
    "repeat_customers",
    "churn_events",
]

_METRIC_STAGE: dict[str, FunnelStage] = {
    "impressions": "audience",
    "followers": "audience",
    "list_size": "audience",
    "sessions": "traffic",
    "clicks": "traffic",
    "unique_visitors": "traffic",
    "engagements": "engagement",
    "leads": "conversion",
    "opportunities": "conversion",
    "checkouts_started": "conversion",
    "conversions": "conversion",
    "orders": "conversion",
    "won_deals": "conversion",
    "revenue": "revenue",
    "repeat_orders": "retention",
    "repeat_customers": "retention",
    "churn_events": "retention",
}

# Provider-precomputed ratio metrics carried by the rail contract; ratios can
# never be summed across envelopes, so they are excluded from stage totals.
_PRECOMPUTED_RATE_METRICS = frozenset(
    {
        "conversion_rate",
        "click_through_rate",
        "engagement_rate",
        "pipeline_win_rate",
    }
)

_DEFAULT_BASIS_PRIORITY: tuple[FunnelBasis, ...] = (
    "commerce_recorded",
    "site_measured",
    "crm_recorded",
    "platform_reported",
)
_METRIC_BASIS_PRIORITY: dict[str, tuple[FunnelBasis, ...]] = {
    "impressions": (
        "platform_reported",
        "site_measured",
        "commerce_recorded",
        "crm_recorded",
    ),
    "clicks": (
        "platform_reported",
        "site_measured",
        "commerce_recorded",
        "crm_recorded",
    ),
    "sessions": (
        "site_measured",
        "commerce_recorded",
        "platform_reported",
        "crm_recorded",
    ),
    "unique_visitors": (
        "site_measured",
        "commerce_recorded",
        "platform_reported",
        "crm_recorded",
    ),
}

RateName = Literal[
    "reach_to_visit",
    "visit_to_engage",
    "visit_to_purchase",
    "lead_capture",
    "purchase_to_repeat",
]

_RATE_DEFINITIONS: tuple[tuple[str, str, str], ...] = (
    ("reach_to_visit", "sessions", "impressions"),
    ("visit_to_engage", "engagements", "sessions"),
    ("visit_to_purchase", "orders", "sessions"),
    ("lead_capture", "leads", "sessions"),
    ("purchase_to_repeat", "repeat_orders", "orders"),
)
_RATE_ORDER: tuple[str, ...] = tuple(name for name, _, _ in _RATE_DEFINITIONS)

DerivedValueName = Literal["revenue_per_session", "average_order_value"]

ReferenceQuality = Literal[
    "scope_history",
    "portfolio_sibling",
    "default_heuristic",
]

ExclusionReason = Literal[
    "future_observation",
    "stale_observation",
    "unverified_evidence",
]

EvidenceScopeStatus = Literal[
    "caller_supplied_unverified",
    "host_hmac_verified",
]


class GrowthFunnelValidationError(ValueError):
    """Funnel evidence or snapshot content violates the sealed contract."""


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
PortableRef = Annotated[
    str,
    StringConstraints(pattern=_PORTABLE_REF_PATTERN),
]
OperationRef = Annotated[
    str,
    StringConstraints(pattern=_OPERATION_REF_PATTERN),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=_SHA256_PATTERN),
]


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
    """Normalize JSON arrays to tuples so frozen models are deeply immutable."""

    if isinstance(value, list):
        return tuple(value)
    return value


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


class GrowthMetrics(_StrictModel):
    """Normalized per-observation metrics.

    The first thirteen fields mirror the execution rail's normalized metrics
    contract verbatim so rail observations validate here at the dict boundary.
    The remaining fields extend coverage to audience and retention stages the
    rail does not model; envelopes carrying them are Growth-Engine-only.
    """

    impressions: int | None = Field(default=None, ge=0)
    clicks: int | None = Field(default=None, ge=0)
    engagements: int | None = Field(default=None, ge=0)
    conversions: int | None = Field(default=None, ge=0)
    sessions: int | None = Field(default=None, ge=0)
    orders: int | None = Field(default=None, ge=0)
    leads: int | None = Field(default=None, ge=0)
    opportunities: int | None = Field(default=None, ge=0)
    won_deals: int | None = Field(default=None, ge=0)
    revenue: Decimal | None = Field(default=None, ge=0, multiple_of=_MONEY_QUANTUM)
    conversion_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    click_through_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    engagement_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    pipeline_win_rate: Decimal | None = Field(
        default=None, ge=0, le=1, multiple_of=_RATE_QUANTUM
    )
    followers: int | None = Field(default=None, ge=0)
    list_size: int | None = Field(default=None, ge=0)
    unique_visitors: int | None = Field(default=None, ge=0)
    checkouts_started: int | None = Field(default=None, ge=0)
    repeat_orders: int | None = Field(default=None, ge=0)
    repeat_customers: int | None = Field(default=None, ge=0)
    churn_events: int | None = Field(default=None, ge=0)

    @field_validator("revenue", mode="before")
    @classmethod
    def _revenue_decimal(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_MONEY_QUANTUM)

    @field_validator(
        "conversion_rate",
        "click_through_rate",
        "engagement_rate",
        "pipeline_win_rate",
        mode="before",
    )
    @classmethod
    def _decimal_metrics(cls, value: Any) -> Decimal | None:
        if value is None:
            return None
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _at_least_one_metric(self) -> "GrowthMetrics":
        if all(value is None for value in self.model_dump(mode="python").values()):
            raise ValueError("at least one normalized metric is required")
        return self


class GrowthFunnelEvidence(_StrictModel):
    """One sealed connector observation admissible into funnel snapshots.

    Field names, window laws, and the attestation trio mirror the execution
    rail's analytics snapshot contract exactly (dict-boundary compatibility);
    ``metrics`` is a strict superset of the rail's normalized metrics.
    """

    schema_id: Literal[
        "lightbulb.growth_funnel_evidence.v1",
        "lightbulb.growth_funnel_evidence.v2",
    ] = Field(default=GROWTH_FUNNEL_EVIDENCE_SCHEMA, alias="schema")
    observation_ref: PortableRef
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
    sample_size: int = Field(ge=0, le=10_000_000_000)
    metrics: GrowthMetrics
    currency: CurrencyCode | None = None
    evidence_digest: Sha256Digest
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    snapshot_hmac: Sha256Digest | None = None

    @model_validator(mode="before")
    @classmethod
    def _recognize_legacy_attested_shape(cls, value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        if "schema" in value or "schema_id" in value:
            return value
        if any(
            value.get(field) is not None
            for field in ("receipt_key_id", "exact_scope_digest", "snapshot_hmac")
        ):
            return {"schema": _LEGACY_GROWTH_FUNNEL_EVIDENCE_SCHEMA, **value}
        return value

    @field_validator("observed_at", "window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @model_validator(mode="after")
    def _valid_source_and_window(self) -> "GrowthFunnelEvidence":
        if self.source_capability not in _SOURCE_CAPABILITIES[self.provider]:
            raise ValueError(
                "source_capability is not an allowed evidence source for provider"
            )
        if _parse_timestamp(self.window_end) < _parse_timestamp(self.window_start):
            raise ValueError("evidence window_end must not precede window_start")
        if _parse_timestamp(self.observed_at) < _parse_timestamp(self.window_end):
            raise ValueError("observed_at must not precede the measured window")
        if self.metrics.revenue is not None and self.currency is None:
            raise ValueError("revenue evidence requires an ISO-4217 currency")
        if (
            self.schema_id == _LEGACY_GROWTH_FUNNEL_EVIDENCE_SCHEMA
            and self.metrics.revenue is not None
        ):
            raise ValueError(
                "legacy v1 revenue evidence must be re-ingested with currency"
            )
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.snapshot_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "funnel evidence attestation fields must be supplied together"
            )
        return self

    @property
    def basis(self) -> FunnelBasis:
        return _PROVIDER_BASIS[self.provider]

    @property
    def is_attested(self) -> bool:
        return self.snapshot_hmac is not None

    def hmac_payload(self) -> dict[str, Any]:
        """Return the complete canonical observation covered by host HMAC."""

        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"snapshot_hmac"},
            exclude_none=True,
        )

    def legacy_hmac_payload(self) -> dict[str, Any]:
        """Return the pre-v2 count-only envelope covered by legacy HMACs."""

        return self.model_dump(
            mode="json",
            exclude={"schema_id", "currency", "snapshot_hmac"},
            exclude_none=True,
        )


def mint_growth_funnel_evidence(
    value: GrowthFunnelEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
    scope_key_id: str | None = None,
) -> GrowthFunnelEvidence:
    """Seal one host-verified connector observation for funnel use.

    The trusted host should call this only after verifying the underlying
    connector receipt identified by ``evidence_digest``. The HMAC covers the
    provider, connector account, time window, metrics, evidence digest, and
    exact workflow scope.
    """

    evidence = (
        value
        if isinstance(value, GrowthFunnelEvidence)
        else GrowthFunnelEvidence.model_validate(value)
    )
    if evidence.is_attested or evidence.receipt_key_id is not None:
        raise GrowthFunnelValidationError("funnel evidence is already attested")
    if evidence.schema_id != GROWTH_FUNNEL_EVIDENCE_SCHEMA:
        raise GrowthFunnelValidationError("new funnel evidence must use schema v2")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = scope_keyring.exact_scope_digest(
        key_id=key_id,
        scope=workflow_scope,
    )
    payload = evidence.model_dump(mode="python", exclude_none=True)
    payload.update(
        {
            "receipt_key_id": key_id,
            "exact_scope_digest": exact_scope_digest,
            "snapshot_hmac": "0" * 64,
        }
    )
    draft = GrowthFunnelEvidence.model_validate(payload)
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_GROWTH_FUNNEL_EVIDENCE_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(mode="python", exclude_none=True)
    sealed["snapshot_hmac"] = signature
    return GrowthFunnelEvidence.model_validate(sealed)


def _keyring_signature(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    domain: str,
    payload: Any,
) -> str:
    try:
        return scope_keyring.sign(key_id, domain, payload).hex()
    except GrowthFunnelValidationError:
        raise
    except Exception as exc:
        raise GrowthFunnelValidationError(
            "the funnel signing key is unavailable"
        ) from exc


def _evidence_attestation_matches(
    evidence: GrowthFunnelEvidence,
    *,
    scope: DynamicWorkflowScope,
    scope_keyring: ExactScopeDigestProvider,
) -> bool:
    if (
        evidence.receipt_key_id is None
        or evidence.exact_scope_digest is None
        or evidence.snapshot_hmac is None
    ):
        return False
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=evidence.receipt_key_id,
        scope=scope,
    )
    if not hmac.compare_digest(evidence.exact_scope_digest, expected_scope_digest):
        return False
    if evidence.schema_id == GROWTH_FUNNEL_EVIDENCE_SCHEMA:
        candidates = ((_GROWTH_FUNNEL_EVIDENCE_HMAC_DOMAIN, evidence.hmac_payload()),)
    else:
        if evidence.metrics.revenue is not None:
            return False
        candidates = (
            (_LEGACY_GROWTH_FUNNEL_EVIDENCE_SCHEMA, evidence.legacy_hmac_payload()),
            (_RAIL_ANALYTICS_HMAC_DOMAIN, evidence.legacy_hmac_payload()),
        )
    for domain, payload in candidates:
        expected_hmac = _keyring_signature(
            scope_keyring,
            key_id=evidence.receipt_key_id,
            domain=domain,
            payload=payload,
        )
        if hmac.compare_digest(evidence.snapshot_hmac, expected_hmac):
            return True
    return False


def _keyring_scope_digest(
    scope_keyring: ExactScopeDigestProvider,
    *,
    key_id: str,
    scope: DynamicWorkflowScope,
) -> str:
    try:
        return scope_keyring.exact_scope_digest(key_id=key_id, scope=scope)
    except GrowthFunnelValidationError:
        raise
    except Exception as exc:
        raise GrowthFunnelValidationError(
            "the funnel signing key is unavailable"
        ) from exc


def verify_growth_funnel_evidence(
    value: GrowthFunnelEvidence | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthFunnelEvidence:
    """Re-validate and verify one sealed evidence envelope; raise on failure."""

    evidence = GrowthFunnelEvidence.model_validate(
        value.model_dump(mode="python")
        if isinstance(value, GrowthFunnelEvidence)
        else value
    )
    if not evidence.is_attested:
        raise GrowthFunnelValidationError("funnel evidence carries no host attestation")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    if not _evidence_attestation_matches(
        evidence,
        scope=workflow_scope,
        scope_keyring=scope_keyring,
    ):
        raise GrowthFunnelValidationError(
            "funnel evidence attestation failed verification"
        )
    return evidence


class FunnelReferenceRate(_StrictModel):
    """A comparison rate with explicit provenance quality."""

    rate_name: RateName
    value: Decimal = Field(gt=0, le=1, multiple_of=_RATE_QUANTUM)
    quality: ReferenceQuality
    source_digest: Sha256Digest | None = None

    @field_validator("value", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _heuristics_carry_no_source(self) -> "FunnelReferenceRate":
        if self.quality == "default_heuristic" and self.source_digest is not None:
            raise ValueError("default heuristics must not claim a source digest")
        if self.quality != "default_heuristic" and self.source_digest is None:
            raise ValueError("history and sibling references require a source digest")
        return self


DEFAULT_FUNNEL_REFERENCE_RATES: tuple[FunnelReferenceRate, ...] = (
    FunnelReferenceRate(
        rate_name="reach_to_visit",
        value=Decimal("0.005000"),
        quality="default_heuristic",
    ),
    FunnelReferenceRate(
        rate_name="visit_to_engage",
        value=Decimal("0.300000"),
        quality="default_heuristic",
    ),
    FunnelReferenceRate(
        rate_name="visit_to_purchase",
        value=Decimal("0.020000"),
        quality="default_heuristic",
    ),
    FunnelReferenceRate(
        rate_name="lead_capture",
        value=Decimal("0.030000"),
        quality="default_heuristic",
    ),
    FunnelReferenceRate(
        rate_name="purchase_to_repeat",
        value=Decimal("0.200000"),
        quality="default_heuristic",
    ),
)


class FunnelStalenessPolicy(_StrictModel):
    """Admission budget for evidence age and verification requirements."""

    max_evidence_age_hours: int = Field(default=720, ge=1, le=8_760)
    require_verified_evidence: bool = False


class ExpectedFunnelContribution(_StrictModel):
    """Declares that a stage expects evidence from a specific account."""

    stage: FunnelStage
    connector_account_ref: OperationRef


class BuildGrowthFunnelSnapshotInput(_StrictModel):
    analysis_as_of: str
    snapshot_ref: PortableRef
    evidence: tuple[GrowthFunnelEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_FUNNEL_EVIDENCE,
    )
    staleness_policy: FunnelStalenessPolicy = Field(
        default_factory=FunnelStalenessPolicy
    )
    reference_rates: tuple[FunnelReferenceRate, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_REFERENCE_RATES,
    )
    expected_contributions: tuple[ExpectedFunnelContribution, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_EXPECTED_CONTRIBUTIONS,
    )

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "evidence",
        "reference_rates",
        "expected_contributions",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _unique_members(self) -> "BuildGrowthFunnelSnapshotInput":
        refs = [item.observation_ref for item in self.evidence]
        if len(refs) != len(set(refs)):
            raise ValueError("evidence observation_refs must be unique")
        digests = [item.evidence_digest for item in self.evidence]
        if len(digests) != len(set(digests)):
            raise ValueError("evidence digests must be unique")
        rate_names = [item.rate_name for item in self.reference_rates]
        if len(rate_names) != len(set(rate_names)):
            raise ValueError("reference rates must be unique per rate name")
        expectations = [
            (item.stage, item.connector_account_ref)
            for item in self.expected_contributions
        ]
        if len(expectations) != len(set(expectations)):
            raise ValueError("expected contributions must be unique")
        return self


class StageMetricTotal(_StrictModel):
    metric: MetricName
    basis: FunnelBasis
    unit: Literal["count", "money"]
    value: Decimal = Field(ge=0)
    evidence_count: int = Field(ge=1)
    account_count: int = Field(ge=1)

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)

    @model_validator(mode="after")
    def _quantized_by_unit(self) -> "StageMetricTotal":
        quantum = _MONEY_QUANTUM if self.unit == "money" else _COUNT_QUANTUM
        if self.value != self.value.quantize(quantum):
            raise ValueError("stage totals must be quantized to the metric unit")
        expected_unit = "money" if self.metric == "revenue" else "count"
        if self.unit != expected_unit:
            raise ValueError("stage total unit does not match the metric")
        return self


class StageAggregate(_StrictModel):
    stage: FunnelStage
    completeness: Literal["present", "partial", "unknown"]
    totals: tuple[StageMetricTotal, ...] = Field(default_factory=tuple)
    missing_expected_accounts: tuple[OperationRef, ...] = Field(default_factory=tuple)

    @field_validator("totals", "missing_expected_accounts", mode="before")
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _consistent_completeness(self) -> "StageAggregate":
        if not self.totals:
            if self.completeness != "unknown":
                raise ValueError("a stage without totals must be unknown")
            return self
        for total in self.totals:
            if _METRIC_STAGE[total.metric] != self.stage:
                raise ValueError("stage totals contain a foreign metric")
        expected = "partial" if self.missing_expected_accounts else "present"
        if self.completeness != expected:
            raise ValueError(
                "stage completeness does not match its missing expected accounts"
            )
        return self


class FunnelRateSide(_StrictModel):
    metric: MetricName
    stage: FunnelStage
    basis: FunnelBasis
    value: Decimal = Field(ge=0)

    @field_validator("value", mode="before")
    @classmethod
    def _value_decimal(cls, value: Any) -> Decimal:
        return _decimal(value)


class FunnelRate(_StrictModel):
    rate_name: RateName
    value: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    numerator: FunnelRateSide
    denominator: FunnelRateSide
    cross_basis: bool
    anomalous: bool

    @field_validator("value", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)

    @model_validator(mode="after")
    def _consistent_flags(self) -> "FunnelRate":
        if self.denominator.value <= 0:
            raise ValueError("funnel rates require a positive denominator")
        if self.cross_basis != (self.numerator.basis != self.denominator.basis):
            raise ValueError("cross_basis flag does not match the rate sides")
        if self.anomalous != (self.value > 1):
            raise ValueError("anomalous flag does not match the rate value")
        return self


class DerivedFunnelValue(_StrictModel):
    name: DerivedValueName
    value: Decimal = Field(ge=0, multiple_of=_MONEY_QUANTUM)
    numerator: FunnelRateSide
    denominator: FunnelRateSide

    @field_validator("value", mode="before")
    @classmethod
    def _money_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_MONEY_QUANTUM)


class FunnelBottleneck(_StrictModel):
    rate_name: RateName
    observed: Decimal = Field(ge=0, multiple_of=_RATE_QUANTUM)
    reference: FunnelReferenceRate
    shortfall: Decimal = Field(ge=0, lt=1, multiple_of=_RATE_QUANTUM)

    @field_validator("observed", "shortfall", mode="before")
    @classmethod
    def _rate_decimal(cls, value: Any) -> Decimal:
        return _decimal(value, quantum=_RATE_QUANTUM)


class AdmittedFunnelEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    provider: AnalyticsProvider
    basis: FunnelBasis
    connector_account_ref: OperationRef
    window_start: str
    window_end: str
    verified: bool

    @field_validator("window_start", "window_end")
    @classmethod
    def _valid_timestamp(cls, value: str) -> str:
        return _normalized_timestamp(value)


class ExcludedFunnelEvidence(_StrictModel):
    observation_ref: PortableRef
    evidence_digest: Sha256Digest
    reason: ExclusionReason


class GrowthFunnelSnapshot(_StrictModel):
    """Sealed six-stage funnel state derived from admissible evidence only."""

    schema_id: Literal["lightbulb.growth_funnel_snapshot.v2"] = Field(
        default=GROWTH_FUNNEL_SNAPSHOT_SCHEMA,
        alias="schema",
    )
    snapshot_ref: PortableRef
    analysis_as_of: str
    currency: CurrencyCode | None = None
    evidence_scope_status: EvidenceScopeStatus
    staleness_policy: FunnelStalenessPolicy
    stages: tuple[StageAggregate, ...]
    rates: tuple[FunnelRate, ...] = Field(default_factory=tuple)
    derived_values: tuple[DerivedFunnelValue, ...] = Field(default_factory=tuple)
    bottleneck: FunnelBottleneck | None = None
    bottleneck_reason: ShortText | None = None
    reference_rates: tuple[FunnelReferenceRate, ...] = Field(default_factory=tuple)
    admitted_evidence: tuple[AdmittedFunnelEvidence, ...] = Field(default_factory=tuple)
    excluded_evidence: tuple[ExcludedFunnelEvidence, ...] = Field(default_factory=tuple)
    funnel_digest: Sha256Digest = "0" * 64
    receipt_key_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,79}$",
    )
    exact_scope_digest: Sha256Digest | None = None
    funnel_hmac: Sha256Digest | None = None

    @field_validator("analysis_as_of")
    @classmethod
    def _valid_analysis_time(cls, value: str) -> str:
        return _normalized_timestamp(value)

    @field_validator(
        "stages",
        "rates",
        "derived_values",
        "reference_rates",
        "admitted_evidence",
        "excluded_evidence",
        mode="before",
    )
    @classmethod
    def _immutable_collections(cls, value: Any) -> Any:
        return _immutable_sequence(value)

    @model_validator(mode="after")
    def _sealed_shape(self) -> "GrowthFunnelSnapshot":
        if tuple(stage.stage for stage in self.stages) != _FUNNEL_STAGES:
            raise ValueError(
                "funnel snapshots must report all six stages in canonical order"
            )
        rate_names = [rate.rate_name for rate in self.rates]
        if len(rate_names) != len(set(rate_names)):
            raise ValueError("funnel rates must be unique per rate name")
        if rate_names != sorted(rate_names, key=_RATE_ORDER.index):
            raise ValueError("funnel rates must use canonical ordering")
        if (self.bottleneck is None) == (self.bottleneck_reason is None):
            raise ValueError(
                "exactly one of bottleneck and bottleneck_reason is required"
            )
        has_money = any(
            total.unit == "money" for stage in self.stages for total in stage.totals
        ) or bool(self.derived_values)
        if has_money and self.currency is None:
            raise ValueError("monetary funnel snapshots require a currency")
        if not has_money and self.currency is not None:
            raise ValueError("count-only funnel snapshots must not carry a currency")
        binding_fields = (
            self.receipt_key_id,
            self.exact_scope_digest,
            self.funnel_hmac,
        )
        if any(value is not None for value in binding_fields) and not all(
            value is not None for value in binding_fields
        ):
            raise ValueError(
                "funnel snapshot attestation fields must be supplied together"
            )
        if self.evidence_scope_status == "host_hmac_verified" and (
            self.funnel_hmac is None
        ):
            raise ValueError(
                "verified funnel snapshots require a complete host attestation"
            )
        payload = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"funnel_digest", "funnel_hmac"},
            exclude_none=True,
        )
        expected = _stable_digest(payload)
        if self.funnel_digest != "0" * 64 and self.funnel_digest != expected:
            raise ValueError("funnel_digest does not match the canonical payload")
        object.__setattr__(self, "funnel_digest", expected)
        return self

    def hmac_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"funnel_hmac", "funnel_digest"},
            exclude_none=True,
        )

    def stage(self, stage: FunnelStage) -> StageAggregate:
        for aggregate in self.stages:
            if aggregate.stage == stage:
                return aggregate
        raise KeyError(stage)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


def _classify_evidence(
    evidence: GrowthFunnelEvidence,
    *,
    analysis_at: datetime,
    policy: FunnelStalenessPolicy,
    scope: DynamicWorkflowScope | None,
    scope_keyring: ExactScopeDigestProvider | None,
) -> tuple[bool, ExclusionReason | None]:
    """Return (verified, exclusion_reason) for one envelope.

    Attested evidence that fails verification raises: tampering is an error,
    never a silent exclusion. Exclusion precedence is future, then stale,
    then unverified — the first structural defect wins deterministically.
    """

    verified = False
    if evidence.is_attested and scope_keyring is not None and scope is not None:
        if not _evidence_attestation_matches(
            evidence,
            scope=scope,
            scope_keyring=scope_keyring,
        ):
            raise GrowthFunnelValidationError(
                "funnel evidence attestation failed verification"
            )
        verified = True
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


def _reject_window_overlaps(admitted: list[GrowthFunnelEvidence]) -> None:
    by_source: dict[tuple[str, str], list[GrowthFunnelEvidence]] = {}
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
            # Windows are half-open [start, end); a zero-width window is the
            # closed instant {start}. Two windows double count when they share
            # any instant: strict interior overlap, or a zero-width earlier
            # window sitting exactly on the later window's start (which also
            # rejects two identical zero-width instants).
            if later_start < earlier_end or (
                earlier_start == earlier_end and earlier_start == later_start
            ):
                raise GrowthFunnelValidationError(
                    "admitted evidence windows overlap for one account and "
                    "capability; aggregate windows upstream to avoid double "
                    "counting"
                )


def _metric_unit(metric: str) -> Literal["count", "money"]:
    return "money" if metric == "revenue" else "count"


def _aggregate_stage_totals(
    admitted: list[GrowthFunnelEvidence],
) -> tuple[
    dict[tuple[str, str], Decimal],
    dict[tuple[str, str], set[str]],
    dict[tuple[str, str], int],
    dict[str, set[str]],
]:
    totals: dict[tuple[str, str], Decimal] = {}
    accounts: dict[tuple[str, str], set[str]] = {}
    counts: dict[tuple[str, str], int] = {}
    stage_accounts: dict[str, set[str]] = {stage: set() for stage in _FUNNEL_STAGES}
    for evidence in admitted:
        basis = evidence.basis
        metric_values = evidence.metrics.model_dump(mode="python")
        for metric, value in metric_values.items():
            if value is None or metric in _PRECOMPUTED_RATE_METRICS:
                continue
            amount = value if isinstance(value, Decimal) else Decimal(int(value))
            key = (metric, basis)
            totals[key] = totals.get(key, Decimal("0")) + amount
            accounts.setdefault(key, set()).add(evidence.connector_account_ref)
            counts[key] = counts.get(key, 0) + 1
            stage_accounts[_METRIC_STAGE[metric]].add(evidence.connector_account_ref)
    return totals, accounts, counts, stage_accounts


def _pick_metric_total(
    metric: str,
    totals: Mapping[tuple[str, str], Decimal],
) -> tuple[FunnelBasis, Decimal] | None:
    priority = _METRIC_BASIS_PRIORITY.get(metric, _DEFAULT_BASIS_PRIORITY)
    for basis in priority:
        value = totals.get((metric, basis))
        if value is not None:
            return basis, value
    return None


def _quantized_rate(numerator: Decimal, denominator: Decimal) -> Decimal:
    return (numerator / denominator).quantize(_RATE_QUANTUM, rounding=ROUND_HALF_UP)


def build_growth_funnel_snapshot(
    inputs: BuildGrowthFunnelSnapshotInput | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any] | None = None,
    scope_keyring: ExactScopeDigestProvider | None = None,
    scope_key_id: str | None = None,
) -> GrowthFunnelSnapshot:
    """Compute one sealed funnel snapshot from admissible evidence.

    With ``scope`` and ``scope_keyring`` the snapshot verifies every attested
    envelope, reports ``host_hmac_verified`` only when all admitted evidence
    verified, and seals the snapshot itself. Without them the snapshot is
    honest-but-unverified: it carries no attestation and reports
    ``caller_supplied_unverified``.
    """

    parsed = (
        inputs
        if isinstance(inputs, BuildGrowthFunnelSnapshotInput)
        else BuildGrowthFunnelSnapshotInput.model_validate(inputs)
    )
    if (scope is None) != (scope_keyring is None):
        raise GrowthFunnelValidationError(
            "verified snapshots require both scope and scope_keyring"
        )
    workflow_scope: DynamicWorkflowScope | None = None
    if scope is not None:
        workflow_scope = (
            scope
            if isinstance(scope, DynamicWorkflowScope)
            else DynamicWorkflowScope.model_validate(scope)
        )
    analysis_at = _parse_timestamp(parsed.analysis_as_of)

    admitted: list[GrowthFunnelEvidence] = []
    admitted_verified: dict[str, bool] = {}
    excluded: list[ExcludedFunnelEvidence] = []
    for evidence in parsed.evidence:
        verified, reason = _classify_evidence(
            evidence,
            analysis_at=analysis_at,
            policy=parsed.staleness_policy,
            scope=workflow_scope,
            scope_keyring=scope_keyring,
        )
        if reason is not None:
            excluded.append(
                ExcludedFunnelEvidence(
                    observation_ref=evidence.observation_ref,
                    evidence_digest=evidence.evidence_digest,
                    reason=reason,
                )
            )
            continue
        admitted.append(evidence)
        admitted_verified[evidence.observation_ref] = verified
    _reject_window_overlaps(admitted)

    revenue_currencies = {
        evidence.currency
        for evidence in admitted
        if evidence.metrics.revenue is not None
    }
    if len(revenue_currencies) > 1:
        raise GrowthFunnelValidationError(
            "admitted revenue evidence spans multiple currencies; partition "
            "the snapshot or convert upstream with governed FX evidence"
        )
    snapshot_currency = next(iter(revenue_currencies), None)

    totals, accounts, counts, stage_accounts = _aggregate_stage_totals(admitted)

    expected_by_stage: dict[str, list[str]] = {}
    for expectation in parsed.expected_contributions:
        expected_by_stage.setdefault(expectation.stage, []).append(
            expectation.connector_account_ref
        )

    stage_aggregates: list[StageAggregate] = []
    for stage in _FUNNEL_STAGES:
        stage_totals = [
            StageMetricTotal(
                metric=metric,
                basis=basis,
                unit=_metric_unit(metric),
                value=(
                    value.quantize(_MONEY_QUANTUM)
                    if _metric_unit(metric) == "money"
                    else value.quantize(_COUNT_QUANTUM)
                ),
                evidence_count=counts[(metric, basis)],
                account_count=len(accounts[(metric, basis)]),
            )
            for (metric, basis), value in sorted(totals.items())
            if _METRIC_STAGE[metric] == stage
        ]
        missing = tuple(
            sorted(
                account
                for account in expected_by_stage.get(stage, [])
                if account not in stage_accounts[stage]
            )
        )
        if not stage_totals:
            completeness: Literal["present", "partial", "unknown"] = "unknown"
        elif missing:
            completeness = "partial"
        else:
            completeness = "present"
        stage_aggregates.append(
            StageAggregate(
                stage=stage,
                completeness=completeness,
                totals=tuple(stage_totals),
                missing_expected_accounts=missing,
            )
        )

    rates: list[FunnelRate] = []
    for rate_name, numerator_metric, denominator_metric in _RATE_DEFINITIONS:
        numerator_pick = _pick_metric_total(numerator_metric, totals)
        denominator_pick = _pick_metric_total(denominator_metric, totals)
        if numerator_pick is None or denominator_pick is None:
            continue
        denominator_basis, denominator_value = denominator_pick
        if denominator_value <= 0:
            continue
        numerator_basis, numerator_value = numerator_pick
        value = _quantized_rate(numerator_value, denominator_value)
        rates.append(
            FunnelRate(
                rate_name=rate_name,
                value=value,
                numerator=FunnelRateSide(
                    metric=numerator_metric,
                    stage=_METRIC_STAGE[numerator_metric],
                    basis=numerator_basis,
                    value=numerator_value,
                ),
                denominator=FunnelRateSide(
                    metric=denominator_metric,
                    stage=_METRIC_STAGE[denominator_metric],
                    basis=denominator_basis,
                    value=denominator_value,
                ),
                cross_basis=numerator_basis != denominator_basis,
                anomalous=value > 1,
            )
        )

    derived_values: list[DerivedFunnelValue] = []
    revenue_pick = _pick_metric_total("revenue", totals)
    sessions_pick = _pick_metric_total("sessions", totals)
    orders_pick = _pick_metric_total("orders", totals)
    if revenue_pick is not None and sessions_pick is not None:
        sessions_basis, sessions_value = sessions_pick
        if sessions_value > 0:
            revenue_basis, revenue_value = revenue_pick
            derived_values.append(
                DerivedFunnelValue(
                    name="revenue_per_session",
                    value=(revenue_value / sessions_value).quantize(
                        _MONEY_QUANTUM, rounding=ROUND_HALF_UP
                    ),
                    numerator=FunnelRateSide(
                        metric="revenue",
                        stage="revenue",
                        basis=revenue_basis,
                        value=revenue_value,
                    ),
                    denominator=FunnelRateSide(
                        metric="sessions",
                        stage="traffic",
                        basis=sessions_basis,
                        value=sessions_value,
                    ),
                )
            )
    if revenue_pick is not None and orders_pick is not None:
        orders_basis, orders_value = orders_pick
        if orders_value > 0:
            revenue_basis, revenue_value = revenue_pick
            derived_values.append(
                DerivedFunnelValue(
                    name="average_order_value",
                    value=(revenue_value / orders_value).quantize(
                        _MONEY_QUANTUM, rounding=ROUND_HALF_UP
                    ),
                    numerator=FunnelRateSide(
                        metric="revenue",
                        stage="revenue",
                        basis=revenue_basis,
                        value=revenue_value,
                    ),
                    denominator=FunnelRateSide(
                        metric="orders",
                        stage="conversion",
                        basis=orders_basis,
                        value=orders_value,
                    ),
                )
            )

    effective_references: dict[str, FunnelReferenceRate] = {
        reference.rate_name: reference for reference in DEFAULT_FUNNEL_REFERENCE_RATES
    }
    for reference in parsed.reference_rates:
        effective_references[reference.rate_name] = reference
    reference_echo = tuple(
        effective_references[name]
        for name in _RATE_ORDER
        if name in effective_references
    )

    bottleneck: FunnelBottleneck | None = None
    bottleneck_reason: str | None = None
    candidates: list[tuple[Decimal, int, FunnelRate, FunnelReferenceRate]] = []
    for rate in rates:
        if rate.anomalous:
            continue
        reference = effective_references.get(rate.rate_name)
        if reference is None:
            continue
        shortfall = (rate.value / reference.value).quantize(
            _RATE_QUANTUM, rounding=ROUND_HALF_UP
        )
        if shortfall < 1:
            candidates.append(
                (shortfall, _RATE_ORDER.index(rate.rate_name), rate, reference)
            )
    if candidates:
        shortfall, _, rate, reference = min(candidates, key=lambda item: item[:2])
        bottleneck = FunnelBottleneck(
            rate_name=rate.rate_name,
            observed=rate.value,
            reference=reference,
            shortfall=shortfall,
        )
    elif rates:
        bottleneck_reason = "no computable funnel rate falls below its reference"
    else:
        bottleneck_reason = (
            "insufficient admitted evidence to compute any referenced funnel rate"
        )

    all_verified = bool(admitted) and all(
        admitted_verified[evidence.observation_ref] for evidence in admitted
    )
    evidence_scope_status: EvidenceScopeStatus = (
        "host_hmac_verified"
        if scope_keyring is not None and all_verified
        else "caller_supplied_unverified"
    )

    snapshot_kwargs: dict[str, Any] = {
        "snapshot_ref": parsed.snapshot_ref,
        "analysis_as_of": parsed.analysis_as_of,
        "currency": snapshot_currency,
        "evidence_scope_status": evidence_scope_status,
        "staleness_policy": parsed.staleness_policy,
        "stages": tuple(stage_aggregates),
        "rates": tuple(rates),
        "derived_values": tuple(derived_values),
        "bottleneck": bottleneck,
        "bottleneck_reason": bottleneck_reason,
        "reference_rates": reference_echo,
        "admitted_evidence": tuple(
            AdmittedFunnelEvidence(
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
        return GrowthFunnelSnapshot(**snapshot_kwargs)

    key_id = scope_key_id or str(scope_keyring.active_key_id).strip()
    exact_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=key_id,
        scope=workflow_scope,
    )
    draft = GrowthFunnelSnapshot(
        **snapshot_kwargs,
        receipt_key_id=key_id,
        exact_scope_digest=exact_scope_digest,
        funnel_hmac="0" * 64,
    )
    signature = _keyring_signature(
        scope_keyring,
        key_id=key_id,
        domain=_GROWTH_FUNNEL_SNAPSHOT_HMAC_DOMAIN,
        payload=draft.hmac_payload(),
    )
    sealed = draft.model_dump(
        mode="python",
        by_alias=True,
        exclude={"funnel_digest"},
        exclude_none=True,
    )
    sealed["funnel_hmac"] = signature
    return GrowthFunnelSnapshot.model_validate(sealed)


def verify_growth_funnel_snapshot(
    value: GrowthFunnelSnapshot | Mapping[str, Any],
    *,
    scope: DynamicWorkflowScope | Mapping[str, Any],
    scope_keyring: ExactScopeDigestProvider,
) -> GrowthFunnelSnapshot:
    """Re-validate and verify one sealed funnel snapshot; raise on failure."""

    snapshot = GrowthFunnelSnapshot.model_validate(
        value.model_dump(mode="python", by_alias=True, exclude_none=True)
        if isinstance(value, GrowthFunnelSnapshot)
        else value
    )
    if (
        snapshot.receipt_key_id is None
        or snapshot.exact_scope_digest is None
        or snapshot.funnel_hmac is None
    ):
        raise GrowthFunnelValidationError("funnel snapshot carries no host attestation")
    workflow_scope = (
        scope
        if isinstance(scope, DynamicWorkflowScope)
        else DynamicWorkflowScope.model_validate(scope)
    )
    expected_scope_digest = _keyring_scope_digest(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        scope=workflow_scope,
    )
    if not hmac.compare_digest(snapshot.exact_scope_digest, expected_scope_digest):
        raise GrowthFunnelValidationError(
            "funnel snapshot attestation failed verification"
        )
    expected_hmac = _keyring_signature(
        scope_keyring,
        key_id=snapshot.receipt_key_id,
        domain=_GROWTH_FUNNEL_SNAPSHOT_HMAC_DOMAIN,
        payload=snapshot.hmac_payload(),
    )
    if not hmac.compare_digest(snapshot.funnel_hmac, expected_hmac):
        raise GrowthFunnelValidationError(
            "funnel snapshot attestation failed verification"
        )
    return snapshot


__all__ = [
    "GROWTH_FUNNEL_EVIDENCE_SCHEMA",
    "GROWTH_FUNNEL_SNAPSHOT_SCHEMA",
    "DEFAULT_FUNNEL_REFERENCE_RATES",
    "AdmittedFunnelEvidence",
    "BuildGrowthFunnelSnapshotInput",
    "CurrencyCode",
    "DerivedFunnelValue",
    "ExcludedFunnelEvidence",
    "ExpectedFunnelContribution",
    "FunnelBottleneck",
    "FunnelRate",
    "FunnelRateSide",
    "FunnelReferenceRate",
    "FunnelStalenessPolicy",
    "GrowthFunnelEvidence",
    "GrowthFunnelSnapshot",
    "GrowthFunnelValidationError",
    "GrowthMetrics",
    "StageAggregate",
    "StageMetricTotal",
    "build_growth_funnel_snapshot",
    "mint_growth_funnel_evidence",
    "verify_growth_funnel_evidence",
    "verify_growth_funnel_snapshot",
]
